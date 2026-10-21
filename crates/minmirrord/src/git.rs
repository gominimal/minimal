//! Repository copies (O2): a bare mirror clone per slug, cloned on the first
//! request, refreshed when stale, and bundled for the guest.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::mirror::RepoSlug;
use sha2::Digest;
use tokio::process::Command;

use crate::status::{Failure, Head, RepoStatus};
use crate::store::Store;

/// How old a copy may be before a request refreshes it first (MIR-012).
const REFRESH_AFTER: Duration = Duration::from_secs(5 * 60);
/// How long a request waits for that refresh before it takes the held copy.
const REFRESH_BOUND: Duration = Duration::from_secs(10);

/// What the mirror answers for a repository.
#[derive(Debug)]
pub enum Copy {
    /// The copy's bare clone and its bundle.
    Ready { repo: PathBuf, bundle: PathBuf },
    /// No copy, and the body of the 502 that says why (MIR-010).
    NoCopy(String),
}

#[derive(Default)]
struct RepoMeta {
    last_refresh: Option<Instant>,
    refreshed_at: Option<u64>,
    last_failure: Option<Failure>,
}

struct Entry {
    writer: Arc<tokio::sync::Mutex<()>>,
    meta: Arc<Mutex<RepoMeta>>,
}

/// Every repository copy the mirror holds or is making.
pub struct Repos {
    store: Store,
    /// What a slug is appended to for its clone URL: `https://`, or a local
    /// base in tests.
    origin_base: String,
    entries: Mutex<HashMap<RepoSlug, Arc<Entry>>>,
}

impl Repos {
    pub fn new(store: Store) -> Self {
        Self::with_origin_base(store, "https://".to_string())
    }

    /// Repositories cloned from `<origin_base><slug>`: for tests against
    /// local repositories only.
    pub fn with_origin_base(store: Store, origin_base: String) -> Self {
        Self {
            store,
            origin_base,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn clone_url(&self, slug: &RepoSlug) -> String {
        format!("{}{}", self.origin_base, slug.as_str())
    }

    fn entry(&self, slug: &RepoSlug) -> Arc<Entry> {
        self.entries
            .lock()
            .expect("lock")
            .entry(slug.clone())
            .or_insert_with(|| {
                Arc::new(Entry {
                    writer: Arc::new(tokio::sync::Mutex::new(())),
                    meta: Arc::new(Mutex::new(RepoMeta::default())),
                })
            })
            .clone()
    }

    /// Answers a request for a repository copy: clones it when absent,
    /// refreshes it when older than five minutes, bounded (MIR-010, MIR-012).
    pub async fn copy(&self, slug: &RepoSlug) -> Copy {
        let entry = self.entry(slug);
        let repo = self.store.repo_git(slug);
        let bundle = self.store.bundle_path(slug);
        let held = repo.join("HEAD").is_file() && bundle.is_file();
        if !held {
            // The first request waits for the whole clone, as it waited for
            // its own clone from the origin before.
            let _writer = entry.writer.lock().await;
            if !(repo.join("HEAD").is_file() && bundle.is_file()) {
                match clone(&self.store, slug, &self.clone_url(slug)).await {
                    Ok(()) => {
                        let mut meta = entry.meta.lock().expect("lock");
                        meta.last_refresh = Some(Instant::now());
                        meta.refreshed_at = Some(crate::status::now_secs());
                        meta.last_failure = None;
                        tracing::info!(slug = %slug, "copied");
                    }
                    Err(cause) => {
                        entry.meta.lock().expect("lock").last_failure = Some(Failure::now(&cause));
                        return Copy::NoCopy(format!(
                            "the mirror could not copy {}: {cause}",
                            slug.https_url()
                        ));
                    }
                }
            }
            return Copy::Ready { repo, bundle };
        }
        let stale = {
            let meta = entry.meta.lock().expect("lock");
            meta.last_refresh
                .is_none_or(|t| t.elapsed() > REFRESH_AFTER)
        };
        if stale {
            let store = self.store.clone();
            let slug_owned = slug.clone();
            let entry_owned = entry.clone();
            let handle = tokio::spawn(async move {
                let _writer = entry_owned.writer.lock().await;
                let result = refresh(&store, &slug_owned).await;
                let mut meta = entry_owned.meta.lock().expect("lock");
                match result {
                    Ok(()) => {
                        meta.last_refresh = Some(Instant::now());
                        meta.refreshed_at = Some(crate::status::now_secs());
                    }
                    Err(cause) => {
                        tracing::info!(slug = %slug_owned, cause, "refresh failed; the held copy stands");
                        // A failed refresh is not retried on every request.
                        meta.last_refresh = Some(Instant::now());
                        meta.last_failure = Some(Failure::now(&cause));
                    }
                }
            });
            if tokio::time::timeout(REFRESH_BOUND, handle).await.is_err() {
                tracing::info!(slug = %slug, "refresh exceeds its bound; answering with the held copy");
            }
        }
        Copy::Ready { repo, bundle }
    }

    /// Every copy's row for `min mirror status`.
    pub async fn status(&self) -> Vec<RepoStatus> {
        let mut rows = Vec::new();
        for slug in self.store.repo_slugs() {
            let entry = self.entry(&slug);
            let (refreshed_at, last_failure) = {
                let meta = entry.meta.lock().expect("lock");
                (meta.refreshed_at, meta.last_failure.clone())
            };
            let heads = heads(&self.store.repo_git(&slug)).await;
            rows.push(RepoStatus {
                slug: slug.as_str().to_string(),
                heads,
                refreshed_at,
                last_failure,
            });
        }
        rows.sort_by(|a, b| a.slug.cmp(&b.slug));
        rows
    }
}

/// A git command the mirror runs: the user's and the system's configuration
/// ignored, prompts disabled (MIR-014).
fn git() -> Command {
    let mut cmd = Command::new("git");
    cmd.env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .arg("--no-optional-locks")
        .arg("-c")
        .arg("core.hooksPath=/dev/null")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(false);
    cmd
}

async fn run(mut cmd: Command) -> Result<String, String> {
    let output = cmd.output().await.map_err(|e| format!("git: {e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let line = stderr
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("git failed")
            .trim()
            .to_string();
        Err(line)
    }
}

async fn clone(store: &Store, slug: &RepoSlug, url: &str) -> Result<(), String> {
    let dir = store.repo_dir(slug);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let repo = store.repo_git(slug);
    let tmp = dir.join("repo.git.tmp");
    if tmp.exists() {
        std::fs::remove_dir_all(&tmp).map_err(|e| e.to_string())?;
    }
    let mut cmd = git();
    cmd.arg("clone")
        .arg("--quiet")
        .arg("--mirror")
        .arg(url)
        .arg(&tmp);
    run(cmd).await?;
    std::fs::rename(&tmp, &repo).map_err(|e| e.to_string())?;
    write_bundle(store, slug).await
}

async fn refresh(store: &Store, slug: &RepoSlug) -> Result<(), String> {
    let repo = store.repo_git(slug);
    let before = refs_digest(&repo).await?;
    let mut cmd = git();
    cmd.arg("-C")
        .arg(&repo)
        .arg("fetch")
        .arg("--quiet")
        .arg("--prune")
        .arg("origin");
    run(cmd).await?;
    let after = refs_digest(&repo).await?;
    if before != after || !store.bundle_path(slug).is_file() {
        write_bundle(store, slug).await?;
    }
    Ok(())
}

/// Writes the bundle of every ref and replaces the served one by one rename
/// (MIR-011).
async fn write_bundle(store: &Store, slug: &RepoSlug) -> Result<(), String> {
    let repo = store.repo_git(slug);
    let bundle = store.bundle_path(slug);
    let tmp = store.repo_dir(slug).join("bundle.tmp");
    let mut cmd = git();
    cmd.arg("-C")
        .arg(&repo)
        .arg("bundle")
        .arg("create")
        .arg("--quiet")
        .arg(&tmp)
        .arg("--all");
    run(cmd).await?;
    std::fs::rename(&tmp, &bundle).map_err(|e| e.to_string())
}

async fn refs_digest(repo: &std::path::Path) -> Result<String, String> {
    let mut cmd = git();
    cmd.arg("-C")
        .arg(repo)
        .arg("for-each-ref")
        .arg("--format=%(objectname) %(refname)");
    let listing = run(cmd).await?;
    Ok(hex::encode(sha2::Sha256::digest(listing.as_bytes())))
}

async fn heads(repo: &std::path::Path) -> Vec<Head> {
    let mut cmd = git();
    cmd.arg("-C")
        .arg(repo)
        .arg("for-each-ref")
        .arg("--format=%(objectname) %(refname:short)")
        .arg("refs/heads");
    let Ok(listing) = run(cmd).await else {
        return Vec::new();
    };
    listing
        .lines()
        .filter_map(|line| {
            let (commit, name) = line.split_once(' ')?;
            Some(Head {
                name: name.to_string(),
                commit: commit.to_string(),
            })
        })
        .take(8)
        .collect()
}
