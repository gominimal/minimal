//! Git repository checkout management for source operations.
//!
//! This crate provides abstractions for creating and maintaining checkouts of git repositories
//! at specific versions.

use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    collections::HashMap,
    fs::{self, File, OpenOptions, TryLockError},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tempfile::tempdir_in;
use tracing::{trace, warn};

mod error;
pub use error::Error;
mod repo;
pub use repo::Repo;

/// Reference to a specific version in a git repository.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GitRef {
    /// A branch name (e.g., "main", "develop")
    Branch(String),
    /// A tag (e.g., "v1.0.0")
    Tag(String),
    /// A specific commit hash (full or abbreviated)
    Commit(String),
}

impl GitRef {
    /// Returns the string representation suitable for git commands.
    pub fn as_str(&self) -> &str {
        match self {
            GitRef::Branch(s) | GitRef::Tag(s) | GitRef::Commit(s) => s,
        }
    }

    /// Returns the [common::repo_spec::Repo] representation.
    pub fn as_repo<U: Into<String>, H: Into<String>>(
        &self,
        url: U,
        checkout_git_hash: H,
    ) -> common::repo_spec::Repo {
        common::repo_spec::Repo::Git {
            url: url.into(),
            rev: checkout_git_hash.into(),
            tracking: match self {
                GitRef::Branch(b) => Some(common::repo_spec::GitRef::Branch(b.clone())),
                GitRef::Tag(t) => Some(common::repo_spec::GitRef::Tag(t.clone())),
                GitRef::Commit(_) => None,
            },
        }
    }
}

/// Converts from an (Upstream)[mfile::Upstream] stanza in the minimal-file
/// to a [GitRef].
impl TryFrom<&mfile::LinkConfig> for GitRef {
    type Error = ();
    fn try_from(upstream: &mfile::LinkConfig) -> Result<Self, Self::Error> {
        match upstream {
            mfile::LinkConfig::Git {
                repo: _,
                branch,
                locked_commit,
            } => Ok(match (&locked_commit, &branch) {
                (Some(hash), _) => GitRef::Commit(hash.clone()),
                (None, Some(branch)) => GitRef::Branch(branch.clone()),
                (None, None) => GitRef::Branch("main".to_string()),
            }),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for GitRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitRef::Branch(b) => write!(f, "branch:{}", b),
            GitRef::Tag(t) => write!(f, "tag:{}", t),
            GitRef::Commit(c) => write!(f, "commit:{}", c),
        }
    }
}

/// Describes the version of a worktree.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Checkout {
    pub version: GitRef,
    pub rev: String,
}

/// State of a specific git repo thats being managed.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RepoState {
    remote: String,
    // Maps subdirs to specific checkouts.
    checkouts: HashMap<String, Checkout>,
}

/// State of the manager serialized to disk.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ManagerState {
    // Maps a remote string to an ID.
    pub git_remotes: HashMap<String, String>,
    // Maps IDs to the corresponding Repo.
    pub repos: HashMap<String, RepoState>,
}

impl ManagerState {
    /// attempts to read the state file if it exists, otherwise initializes an empty state.
    fn in_dir_or_default(dir: &Path) -> Result<Self, Error> {
        let path = dir.join("state.json");
        if path.exists() {
            let f = fs::File::open(path)?;
            Ok(serde_json_lenient::from_reader(f).map_err(Error::StatefileInvalid)?)
        } else {
            Ok(Default::default())
        }
    }

    /// The recorded checkout of `remote` that already serves `at`, as its dir
    /// under the checkouts root and its commit.
    fn existing_checkout(&self, remote: &str, at: &GitRef) -> Option<(String, String)> {
        let id = self.git_remotes.get(remote)?;
        for (dir, checkout) in self.repos.get(id)?.checkouts.iter() {
            if &checkout.version == at {
                return Some((dir.clone(), checkout.rev.clone()));
            }
            // Its possible to have a checkout thats tracking a branch, but right now it points
            // to a commit which was requested. We can just use that checkout rather than making
            // one that points to just a commit in this case.
            if let GitRef::Commit(rev) = at
                && &checkout.rev == rev
            {
                return Some((dir.clone(), rev.clone()));
            }
        }
        None
    }

    /// serializes the state to the statefile in the given base directory.
    ///
    /// The file is written beside `state.json` and renamed over it, so a
    /// reader that does not hold the cache lock (the [`Manager`] constructor)
    /// sees either the old registry or the new one, never a torn write.
    fn write_to(&self, dir: &Path) -> Result<(), Error> {
        let path = dir.join("state.json");
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        if let Err(e) = serde_json_lenient::to_writer(&mut tmp, self) {
            if e.is_io() {
                return Err(std::io::Error::new(
                    e.io_error_kind().unwrap(),
                    format!("writing state: {}", path.display()),
                )
                .into());
            } else {
                todo!("serde error: {:?}", e)
            }
        }
        tmp.as_file().sync_all()?;
        tmp.persist(&path).map_err(|e| e.error)?;
        Ok(())
    }
}

/// How long [`lock_cache`] waits for another holder before giving up. A
/// holder keeps the lock for a whole clone or fetch; a stuck one (a hung
/// `git fetch`) must fail the waiter with a diagnostic, not hang it forever.
/// `MINIMAL_VCS_LOCK_TIMEOUT_SECS` overrides the default for slow remotes.
fn lock_timeout() -> Duration {
    std::env::var("MINIMAL_VCS_LOCK_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(600))
}

/// Takes `<base_dir>/.lock` exclusively, the lock serializing every manager
/// over one cache dir, and returns the open file holding it; dropping the
/// file releases the lock. The file is opened fresh on every call so two
/// managers in a single process also exclude each other: `flock` is per open
/// file description, not per inode.
///
/// A holder can sit on the lock for a whole network fetch, so a contended
/// lock is reported before the wait starts, and a wait that outlasts
/// `timeout` fails naming the lock file rather than hanging behind a stuck
/// holder.
fn lock_cache(base_dir: &Path, timeout: Duration) -> Result<File, Error> {
    let lock_path = base_dir.join(".lock");
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;
    let deadline = Instant::now() + timeout;
    let mut backoff = Duration::from_millis(10);
    let mut warned = false;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(TryLockError::WouldBlock) => {}
            Err(TryLockError::Error(e)) => return Err(e.into()),
        }
        if !warned {
            warn!(
                "waiting for the checkouts cache lock at {} (held by another process or manager)",
                lock_path.display()
            );
            warned = true;
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(Error::Other(format!(
                "timed out after {}s waiting for the checkouts cache lock at {}; another \
                 process or manager still holds it. If that holder is stuck (for example on \
                 a hung git fetch), stop it and re-run; if it is only slow, set \
                 MINIMAL_VCS_LOCK_TIMEOUT_SECS to wait longer",
                timeout.as_secs(),
                lock_path.display()
            )));
        }
        std::thread::sleep(backoff.min(deadline - now));
        backoff = (backoff * 2).min(Duration::from_secs(1));
    }
}

fn create_unique_id_and_dir(base_dir: &Path, prefix: String) -> std::io::Result<(String, PathBuf)> {
    let candidate = base_dir.join(&prefix);
    if !candidate.exists() {
        fs::create_dir(&candidate)?;
        return Ok((prefix, candidate));
    }

    // If prefix exists, try adding random suffixes
    use rand::RngExt;
    let mut rng = rand::rng();
    const MAX_ATTEMPTS: u32 = 1000;

    for _ in 0..MAX_ATTEMPTS {
        // Generate a random suffix (8 alphanumeric characters)
        let suffix: String = (0..8)
            .map(|_| {
                let idx = rng.random_range(0..36);
                if idx < 10 {
                    (b'0' + idx) as char
                } else {
                    (b'a' + idx - 10) as char
                }
            })
            .collect();

        let dir_name = format!("{}-{}", prefix, suffix);
        let candidate = base_dir.join(&dir_name);
        if !candidate.exists() {
            fs::create_dir(&candidate)?;
            return Ok((dir_name, candidate));
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!(
            "Could not create unique directory with prefix '{}' after {} attempts",
            prefix, MAX_ATTEMPTS
        ),
    ))
}

/// Runs [`Repo::new_worktree`] into `dir`, removing the directory again when
/// git refuses: the add is not recorded in the state file, so a leftover would
/// sit under the checkouts dir unrecorded.
fn new_worktree_or_cleanup(repo: &mut Repo, dir: &Path, at: GitRef) -> Result<Checkout, Error> {
    repo.new_worktree(dir.to_path_buf(), at).inspect_err(|_| {
        let _ = fs::remove_dir_all(dir);
    })
}

/// A handle to the manager for source-code checkouts.
#[derive(Debug, Clone)]
pub struct ManagerHandle(Arc<Mutex<Manager>>);

impl ManagerHandle {
    /// Updates all repos to latest - does nothing for refs which arent symbolic (i.e. commits).
    pub fn update(&mut self) -> Result<(), Error> {
        self.0.lock().unwrap().update()
    }

    /// Fetches and re-checks-out a single known remote. See [`Manager::update_remote`].
    pub fn update_remote(&mut self, remote: &str) -> Result<(), Error> {
        self.0.lock().unwrap().update_remote(remote)
    }

    /// Returns the path to a checkout described by the given parameters, as well as the
    /// commit hash at the given ref.
    pub fn checkout_of(&mut self, remote: &str, at: GitRef) -> Result<(PathBuf, String), Error> {
        self.0.lock().unwrap().checkout_of(remote, at)
    }
}

/// Manages source-code checkouts.
#[derive(Debug)]
pub struct Manager {
    base_dir: PathBuf,
    state: ManagerState,
    repos: HashMap<String, Repo>,
    /// When true, [Manager::checkout_of] / [Manager::update] return
    /// [Error::OfflineCacheMiss] for any remote that would require a clone or fetch
    /// rather than performing the network operation. Mirrors the value of
    /// `mctx::Config::is_offline` (i.e. `--offline`).
    offline: bool,
}

impl Manager {
    /// Initializes the checkouts manager in the given directory, returning a
    /// thread-safe, cloneable handle to the manager instance.
    pub fn new_in_dir<P: Into<PathBuf>>(base_dir: P) -> Result<ManagerHandle, Error> {
        Self::new_in_dir_with_offline(base_dir, false)
    }

    /// Same as [Self::new_in_dir], but with an `offline` flag. When `offline=true`,
    /// any operation that would require a clone or fetch (new remote, or refresh of
    /// a known remote) surfaces as [Error::OfflineCacheMiss] rather than performing
    /// the network operation.
    pub fn new_in_dir_with_offline<P: Into<PathBuf>>(
        base_dir: P,
        offline: bool,
    ) -> Result<ManagerHandle, Error> {
        let base_dir = base_dir.into();
        let db_path = base_dir.join("git").join("db");
        fs::create_dir_all(&db_path)?;
        fs::create_dir_all(base_dir.join("git").join("checkouts"))?;

        // Read without the cache lock: a holder can keep it for a whole
        // network fetch, and this constructor runs on async workers in the
        // daemon. `write_to` replaces `state.json` atomically, so this read
        // never sees it half written, and every mutating path re-reads the
        // registry under the lock before writing it back.
        let state = ManagerState::in_dir_or_default(&base_dir)?;
        let mut repos = HashMap::new();
        for (remote, id) in state.git_remotes.iter() {
            repos.insert(id.clone(), Repo::new(remote, db_path.join(id))?);
        }

        // For now we depend on the git command line tool. Shelling out when git doesn't exist
        // gives an incomprehensible NotFound error, so lets explicitly check that git is in PATH
        // and give a reasonable error if it is not.
        if !common::command_exists("git")? {
            return Err(Error::Other(
                "The git command was not found in path - is it installed?".into(),
            ));
        }

        let manager = Manager {
            base_dir,
            state,
            repos,
            offline,
        };
        Ok(ManagerHandle(Arc::new(Mutex::new(manager))))
    }

    fn git_checkouts_dir(&self) -> PathBuf {
        self.base_dir.join("git").join("checkouts")
    }
    fn git_bares_dir(&self) -> PathBuf {
        self.base_dir.join("git").join("db")
    }

    /// Re-reads the registry, keeping every repo already opened. Called with
    /// the cache lock held: the snapshot taken at construction goes stale as
    /// soon as another manager over the same dir records a remote or a
    /// checkout, and writing it back would drop that manager's entries.
    fn reload_state(&mut self) -> Result<(), Error> {
        self.state = ManagerState::in_dir_or_default(&self.base_dir)?;
        let db_path = self.git_bares_dir();
        for (remote, id) in self.state.git_remotes.iter() {
            if !self.repos.contains_key(id) {
                self.repos
                    .insert(id.clone(), Repo::new(remote, db_path.join(id))?);
            }
        }
        Ok(())
    }

    /// Updates all repos to latest - does nothing for refs which arent symbolic (i.e. commits).
    /// In offline mode, returns [Error::OfflineCacheMiss] — `update` is fundamentally
    /// a network operation, and silently lameducking it would mask hard-to-debug bugs
    /// for callers like `minimal update` that explicitly want fresh state.
    #[tracing::instrument(level = "info", name = "checkouts.update", skip_all)]
    pub fn update(&mut self) -> Result<(), Error> {
        // Serialize against every other manager over the same cache dir. Git
        // itself is only per-repository; a second `min session activate`
        // against the same bare repo would otherwise race this fetch/checkout
        // inside the shared worktree (`index.lock: File exists`).
        if self.offline {
            // Offline touches nothing, so answer from an unlocked read
            // (`state.json` is replaced atomically) rather than wait behind
            // another manager's fetch. Pick the first known remote for the
            // error message; if there are no known remotes there's nothing to
            // update, so a synthetic placeholder is clearer than a misleading
            // Ok.
            let state = ManagerState::in_dir_or_default(&self.base_dir)?;
            let remote = state
                .git_remotes
                .keys()
                .next()
                .map(|remote| scrubbed_remote(remote).into_owned())
                .unwrap_or_else(|| "<no remotes>".to_string());
            return Err(Error::OfflineCacheMiss { remote });
        }
        let _lock = lock_cache(&self.base_dir, lock_timeout())?;
        self.reload_state()?;
        let checkouts_dir = self.git_checkouts_dir();
        for id in self.state.git_remotes.values_mut() {
            let repo = self.repos.get_mut(id).unwrap();
            trace!("updating repo {}", scrubbed_remote(repo.url()));
            repo.fetch()?;
            for (dir, checkout) in self.state.repos.get_mut(id).unwrap().checkouts.iter_mut() {
                checkout.rev =
                    repo.worktree_checkout(&checkouts_dir.join(dir), &checkout.version)?;
            }
        }
        self.state.write_to(&self.base_dir)?;
        Ok(())
    }

    /// Fetches a single known `remote` and re-checks-out its tracked worktrees,
    /// mirroring the per-repo body of [`Self::update`] for just that remote.
    ///
    /// Unlike [`Self::update`], the remaining registered remotes are left
    /// untouched, so one unreachable remote cannot gate an operation that only
    /// needs `remote` fresh. A remote not yet registered is a no-op: a
    /// subsequent [`Self::checkout_of`] clones it on first use.
    #[tracing::instrument(
        level = "info",
        name = "checkouts.update_remote",
        skip_all,
        fields(remote = %scrubbed_remote(remote))
    )]
    pub fn update_remote(&mut self, remote: &str) -> Result<(), Error> {
        if self.offline {
            // As in `update`: offline touches nothing, so it never waits on
            // the lock. An unregistered remote is still a no-op.
            let state = ManagerState::in_dir_or_default(&self.base_dir)?;
            if !state.git_remotes.contains_key(remote) {
                return Ok(());
            }
            return Err(Error::OfflineCacheMiss {
                remote: scrubbed_remote(remote).into_owned(),
            });
        }
        let _lock = lock_cache(&self.base_dir, lock_timeout())?;
        self.reload_state()?;
        let Some(id) = self.state.git_remotes.get(remote).cloned() else {
            return Ok(());
        };
        let checkouts_dir = self.git_checkouts_dir();
        let repo = self.repos.get_mut(&id).unwrap();
        trace!("updating repo {}", scrubbed_remote(repo.url()));
        repo.fetch()?;
        for (dir, checkout) in self.state.repos.get_mut(&id).unwrap().checkouts.iter_mut() {
            checkout.rev = repo.worktree_checkout(&checkouts_dir.join(dir), &checkout.version)?;
        }
        self.state.write_to(&self.base_dir)?;
        Ok(())
    }

    /// Returns the path to a checkout described by the given parameters, as well as the
    /// commit hash at the given ref.
    #[tracing::instrument(
        level = "info",
        name = "checkouts.checkout_of",
        skip_all,
        fields(remote = %scrubbed_remote(remote))
    )]
    pub fn checkout_of(&mut self, remote: &str, at: GitRef) -> Result<(PathBuf, String), Error> {
        trace!("checkout_of {} at {:?}", scrubbed_remote(remote), at);

        // A ref already checked out, and an offline miss on an unknown
        // remote, are answered from an unlocked read (`state.json` is
        // replaced atomically): neither touches the cache, so neither waits
        // behind another manager's fetch.
        let fresh = ManagerState::in_dir_or_default(&self.base_dir)?;
        if let Some((dir, rev)) = fresh.existing_checkout(remote, &at) {
            return Ok((self.git_checkouts_dir().join(dir), rev));
        }
        if self.offline && !fresh.git_remotes.contains_key(remote) {
            return Err(Error::OfflineCacheMiss {
                remote: scrubbed_remote(remote).into_owned(),
            });
        }

        // Same serialization rationale as `update`: the fetch and worktree
        // checkout below mutate shared git state across managers.
        let _lock = lock_cache(&self.base_dir, lock_timeout())?;
        self.reload_state()?;

        let out = match self.state.git_remotes.get(remote) {
            // This remote is already managed
            Some(id) => {
                // See if theres already a checkout of this ref (another
                // manager may have made it while this one waited).
                if let Some((dir, rev)) = self.state.existing_checkout(remote, &at) {
                    return Ok((self.git_checkouts_dir().join(dir), rev));
                }
                // There's not a checkout of this ref, lets create it.
                let checkout_dir = tempdir_in(self.git_checkouts_dir())?.keep();
                let relative_dir = checkout_dir.strip_prefix(self.git_checkouts_dir()).unwrap();
                let repo = self.repos.get_mut(id).unwrap();
                // Offline: skip the fetch and try the worktree checkout against
                // what's already in the bare repo. If the requested ref isn't
                // there, `new_worktree` will surface a git error from below
                // — which is the right outcome (caller gets to know the ref
                // wasn't pre-populated).
                if !self.offline {
                    repo.fetch()?;
                }
                let checkout = new_worktree_or_cleanup(repo, &checkout_dir, at.clone())?;
                let git_hash = checkout.rev.clone();

                self.state.repos.get_mut(id).unwrap().checkouts.insert(
                    relative_dir.to_str().ok_or(Error::InvalidPath)?.to_string(),
                    checkout,
                );

                Ok((checkout_dir, git_hash))
            }
            // New remote, need to create
            None => {
                if self.offline {
                    // Offline: cannot clone an unknown remote. Surface as cache miss
                    // so the caller sees a clean error (not a git "could not connect").
                    return Err(Error::OfflineCacheMiss {
                        remote: scrubbed_remote(remote).into_owned(),
                    });
                }
                // Make id/directory for bare repository
                let prefix = match remote.to_lowercase().rsplit_once("/") {
                    None => "checkout".to_string(),
                    Some((_before, after)) => after.trim_end_matches(".git").to_string(),
                };
                // Make repo
                let (id, dir) = create_unique_id_and_dir(&self.git_bares_dir(), prefix)?;
                let mut repo = Repo::new(remote, dir.clone())?;
                // Make checkout
                let checkout_dir = tempdir_in(self.git_checkouts_dir())?.keep();
                let relative_dir = checkout_dir.strip_prefix(self.git_checkouts_dir()).unwrap();
                // Nothing about this remote is recorded until the checkout
                // succeeds, so a refused ref must also take the bare clone with
                // it: left in place, the next request for the same remote would
                // find the directory taken and clone again under a suffixed id.
                let checkout = match new_worktree_or_cleanup(&mut repo, &checkout_dir, at.clone()) {
                    Ok(checkout) => checkout,
                    Err(err) => {
                        drop(repo);
                        let _ = fs::remove_dir_all(&dir);
                        return Err(err);
                    }
                };
                let git_hash = checkout.rev.clone();

                self.state
                    .git_remotes
                    .insert(remote.to_string(), id.clone());
                self.state.repos.insert(
                    id.clone(),
                    RepoState {
                        remote: remote.to_string(),
                        checkouts: [(
                            relative_dir.to_str().ok_or(Error::InvalidPath)?.to_string(),
                            checkout,
                        )]
                        .into(),
                    },
                );
                self.repos.insert(id, repo);

                Ok((checkout_dir, git_hash))
            }
        };
        self.state.write_to(&self.base_dir)?;
        out
    }
}

/// `remote` as the `checkouts.*` spans record it: without userinfo, query or
/// fragment, so a credential in a remote URL (`https://user:token@host/…`,
/// `?private_token=…`) never reaches a log or an exported span. The host and
/// path are kept; they are what makes the span useful. scp-like remotes
/// (`git@host:org/repo.git`) lose their user the same way; a local path is
/// returned as given.
pub(crate) fn scrubbed_remote(remote: &str) -> Cow<'_, str> {
    let base = remote
        .find(['?', '#'])
        .map_or(remote, |at| remote.split_at(at).0);
    if let Some((scheme, rest)) = base.split_once("://") {
        let (authority, path) = rest.find('/').map_or((rest, ""), |at| rest.split_at(at));
        if let Some((_, host)) = authority.rsplit_once('@') {
            return Cow::Owned(format!("{scheme}://{host}{path}"));
        }
    } else if let Some((authority, path)) = base.split_once(':')
        && !authority.contains('/')
        && let Some((_, host)) = authority.rsplit_once('@')
    {
        return Cow::Owned(format!("{host}:{path}"));
    }
    Cow::Borrowed(base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn gitref_as_str() {
        assert_eq!(GitRef::Branch("main".to_string()).as_str(), "main");
        assert_eq!(GitRef::Tag("v1.0.0".to_string()).as_str(), "v1.0.0");
        assert_eq!(GitRef::Commit("abc123".to_string()).as_str(), "abc123");
    }

    #[test]
    fn spans_record_a_remote_without_credentials() {
        for (remote, recorded) in [
            (
                "https://github.com/octocat/Spoon-Knife",
                "https://github.com/octocat/Spoon-Knife",
            ),
            (
                "https://user:ghp_token@github.com/org/private.git",
                "https://github.com/org/private.git",
            ),
            (
                "https://oauth2:glpat-x@gitlab.internal:8443/team/repo",
                "https://gitlab.internal:8443/team/repo",
            ),
            (
                "https://git.example/repo.git?private_token=abc#frag",
                "https://git.example/repo.git",
            ),
            ("https://tok@git.example", "https://git.example"),
            (
                "ssh://git@git.example:2222/org/repo",
                "ssh://git.example:2222/org/repo",
            ),
            ("git@github.com:org/repo.git", "github.com:org/repo.git"),
            ("github.com:org/repo.git", "github.com:org/repo.git"),
            ("/srv/git/repo@v1", "/srv/git/repo@v1"),
            ("./a@b:c/repo", "./a@b:c/repo"),
        ] {
            assert_eq!(scrubbed_remote(remote), recorded, "{remote}");
        }
    }

    /// A subscriber that keeps the `remote` field of every span it is
    /// given, and every event rendered as `name=value` fields.
    struct Remotes(std::sync::Mutex<Vec<String>>, std::sync::Mutex<Vec<String>>);

    impl tracing::Subscriber for Remotes {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            struct Remote<'a>(&'a std::sync::Mutex<Vec<String>>);
            impl tracing::field::Visit for Remote<'_> {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "remote" {
                        self.0.lock().unwrap().push(format!("{value:?}"));
                    }
                }
            }
            span.record(&mut Remote(&self.0));
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            struct Fields(String);
            impl tracing::field::Visit for Fields {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    self.0.push_str(&format!("{}={value:?} ", field.name()));
                }
            }
            let mut fields = Fields(String::new());
            event.record(&mut fields);
            self.1.lock().unwrap().push(fields.0);
        }

        fn enter(&self, _: &tracing::span::Id) {}

        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// Spec 25 TEL-041: the `checkouts.*` spans carry the remote
    /// without its userinfo or query, and so do the trace-level events
    /// inside them, so a token in a remote URL never reaches the log, the
    /// spool or a collector. Offline, so nothing is
    /// fetched: the spans open, record and fail fast.
    #[test]
    fn a_checkout_span_never_carries_userinfo() {
        let remote = "https://u:ghp_t0ken@git.example/org/repo.git?private_token=q";
        let base_dir = tempdir().unwrap();
        let handle = Manager::new_in_dir_with_offline(base_dir.path(), true).unwrap();
        let seen = std::sync::Arc::new(Remotes(
            std::sync::Mutex::default(),
            std::sync::Mutex::default(),
        ));
        tracing::subscriber::with_default(seen.clone(), || {
            let mut manager = handle.0.lock().unwrap();
            manager.update_remote(remote).unwrap();
            assert!(
                manager
                    .checkout_of(remote, GitRef::Branch("main".to_string()))
                    .is_err(),
                "offline: no fetch"
            );
        });
        let events = seen.1.lock().unwrap();
        assert!(
            events
                .iter()
                .any(|e| e.contains("checkout_of https://git.example/org/repo.git")),
            "checkout_of's trace event names the scrubbed remote: {events:?}"
        );
        for event in events.iter() {
            for secret in ["ghp_t0ken", "private_token", "//u:"] {
                assert!(!event.contains(secret), "{secret} in an event: {event}");
            }
        }
        let seen = seen.0.lock().unwrap();
        assert_eq!(
            *seen,
            [
                "https://git.example/org/repo.git",
                "https://git.example/org/repo.git"
            ],
            "update_remote's and checkout_of's spans"
        );
    }

    /// Spec 25 TEL-041: an error names the remote without its userinfo or
    /// query, so a token in a remote URL never reaches an error message: the
    /// offline miss, and a failed clone whose git stderr echoes the URL.
    #[test]
    fn an_error_never_carries_userinfo() {
        let remote = "https://u:ghp_t0ken@127.0.0.1:1/org/repo.git?private_token=q";
        let base_dir = tempdir().unwrap();
        let handle = Manager::new_in_dir_with_offline(base_dir.path(), true).unwrap();
        let err = handle
            .0
            .lock()
            .unwrap()
            .checkout_of(remote, GitRef::Branch("main".to_string()))
            .expect_err("offline: no fetch");
        assert!(matches!(err, Error::OfflineCacheMiss { .. }), "{err:?}");
        let Err(clone) = repo::Repo::new(remote, base_dir.path().join("bare")) else {
            panic!("nothing listens on port 1");
        };
        for text in [
            err.to_string(),
            format!("{err:?}"),
            clone.to_string(),
            format!("{clone:?}"),
        ] {
            for secret in ["ghp_t0ken", "private_token", "//u:"] {
                assert!(!text.contains(secret), "{secret} in an error: {text}");
            }
        }
        assert!(
            err.to_string().contains("https://127.0.0.1:1/org/repo.git"),
            "the miss names the scrubbed remote: {err}"
        );
    }

    #[test]
    #[ignore]
    fn manager() {
        let remote = "https://github.com/octocat/Spoon-Knife";
        let base_dir = tempdir().unwrap();
        let mut manager = Manager::new_in_dir(base_dir.path()).unwrap();

        let (checkout, hash) = manager
            .checkout_of(remote, GitRef::Branch("main".to_string()))
            .unwrap();

        // Expect bare checkout to be at db/spoon-knife
        assert!(
            base_dir
                .path()
                .join("git")
                .join("db")
                .join("spoon-knife")
                .exists()
        );
        assert_eq!(hash, "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9".to_string());
        // Expect the README.md to exist from the checkout
        assert!(checkout.join("README.md").exists());
        // Expect runtime to be updated
        assert!(
            manager
                .0
                .as_ref()
                .lock()
                .unwrap()
                .repos
                .contains_key("spoon-knife")
        );
        // Expect serialized state to be updated
        assert_eq!(
            manager
                .0
                .as_ref()
                .lock()
                .unwrap()
                .state
                .git_remotes
                .get(remote)
                .unwrap(),
            "spoon-knife"
        );
        assert_eq!(
            manager
                .0
                .as_ref()
                .lock()
                .unwrap()
                .state
                .repos
                .get("spoon-knife")
                .unwrap()
                .remote,
            remote,
        );
        assert_eq!(
            manager
                .0
                .as_ref()
                .lock()
                .unwrap()
                .state
                .repos
                .get("spoon-knife")
                .unwrap()
                .checkouts
                .values()
                .next()
                .unwrap(),
            &Checkout {
                version: GitRef::Branch("main".to_string()),
                rev: "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9".to_string(),
            },
        );
        // Make sure state-file was written to disk
        assert!(base_dir.path().join("state.json").exists());
        // Make sure a fresh checkout request points to the same path.
        let (checkout2, hash2) = manager
            .checkout_of(remote, GitRef::Branch("main".to_string()))
            .unwrap();
        assert_eq!(&checkout, &checkout2);
        assert_eq!(
            hash2,
            "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9".to_string()
        );
        // Make sure even a freshly-initialized manager does the same
        let (checkout3, hash3) = Manager::new_in_dir(base_dir.path())
            .unwrap()
            .checkout_of(remote, GitRef::Branch("main".to_string()))
            .unwrap();
        assert_eq!(&checkout, &checkout3);
        assert_eq!(
            hash3,
            "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9".to_string()
        );
    }

    /// In offline mode, asking for an unknown remote must surface as
    /// OfflineCacheMiss without attempting any git operation.
    #[test]
    fn offline_unknown_remote_errors() {
        let base_dir = tempdir().unwrap();
        let mut manager = Manager::new_in_dir_with_offline(base_dir.path(), true).unwrap();

        let result = manager.checkout_of(
            "https://example.invalid/never-cloned",
            GitRef::Branch("main".to_string()),
        );
        match result {
            Err(Error::OfflineCacheMiss { remote }) => {
                assert_eq!(remote, "https://example.invalid/never-cloned");
            }
            other => panic!("expected OfflineCacheMiss, got: {:?}", other),
        }
    }

    /// Helper: initialise a local git repo with one commit on `branch` and
    /// return (TempDir, commit-hash).  The TempDir must be kept alive for the
    /// duration of the test so the path stays valid.
    fn make_local_repo(branch: &str) -> (tempfile::TempDir, String) {
        use std::process::Command;
        let src = tempfile::tempdir().unwrap();
        // Init with an explicit branch name so the test is git-version agnostic.
        let init = Command::new("git")
            .args(["init", "-b", branch, src.path().to_str().unwrap()])
            .output()
            .unwrap();
        assert!(init.status.success(), "git init failed");

        for (k, v) in [("user.email", "test@example.com"), ("user.name", "Test")] {
            Command::new("git")
                .args(["config", k, v])
                .current_dir(src.path())
                .output()
                .unwrap();
        }

        std::fs::write(src.path().join("hello.txt"), b"hello").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(src.path())
            .output()
            .unwrap();
        let commit = Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(src.path())
            .output()
            .unwrap();
        assert!(commit.status.success(), "git commit failed");

        let rev_out = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(src.path())
            .output()
            .unwrap();
        let hash = String::from_utf8_lossy(&rev_out.stdout).trim().to_string();
        (src, hash)
    }

    /// checkout_of with a previously-unseen local repo URL returns a valid
    /// directory containing the committed file and the correct rev SHA.
    #[test]
    fn checkout_of_new_remote_returns_valid_path_and_rev() {
        let (src, expected_hash) = make_local_repo("main");
        let remote = src.path().to_str().unwrap().to_string();

        let base = tempfile::tempdir().unwrap();
        let mut handle = Manager::new_in_dir(base.path()).unwrap();

        let (checkout_path, rev) = handle
            .checkout_of(&remote, GitRef::Branch("main".to_string()))
            .unwrap();

        assert!(checkout_path.exists(), "checkout directory must exist");
        assert!(
            checkout_path.join("hello.txt").exists(),
            "checked-out file must be present"
        );
        assert_eq!(rev, expected_hash, "returned rev must match HEAD");
    }

    /// A second checkout_of call for the same ref returns the cached path and
    /// rev without creating a new worktree.
    #[test]
    fn checkout_of_same_branch_twice_uses_cache() {
        let (src, _) = make_local_repo("main");
        let remote = src.path().to_str().unwrap().to_string();

        let base = tempfile::tempdir().unwrap();
        let mut handle = Manager::new_in_dir(base.path()).unwrap();

        let (path1, hash1) = handle
            .checkout_of(&remote, GitRef::Branch("main".to_string()))
            .unwrap();
        let (path2, hash2) = handle
            .checkout_of(&remote, GitRef::Branch("main".to_string()))
            .unwrap();

        assert_eq!(path1, path2, "second call must return the cached path");
        assert_eq!(hash1, hash2, "both calls must return the same rev");
    }

    /// When a commit hash matching an existing branch checkout is requested,
    /// checkout_of returns the same worktree instead of creating a second one.
    #[test]
    fn checkout_of_commit_ref_reuses_branch_worktree() {
        let (src, hash) = make_local_repo("main");
        let remote = src.path().to_str().unwrap().to_string();

        let base = tempfile::tempdir().unwrap();
        let mut handle = Manager::new_in_dir(base.path()).unwrap();

        // First: checkout via branch.
        let (branch_path, branch_rev) = handle
            .checkout_of(&remote, GitRef::Branch("main".to_string()))
            .unwrap();
        assert_eq!(branch_rev, hash);

        // Second: request the exact commit — must reuse the existing worktree.
        let (commit_path, commit_rev) = handle
            .checkout_of(&remote, GitRef::Commit(hash.clone()))
            .unwrap();

        assert_eq!(
            branch_path, commit_path,
            "commit ref must reuse the branch worktree"
        );
        assert_eq!(commit_rev, hash);
    }

    /// Two managers over one cache dir, the second holding a registry snapshot
    /// that predates the first's branch checkout — the shape of two daemon
    /// contexts scaffolding against the same cache. Each must get a usable
    /// checkout of `main`: a worktree *on* the branch would make git refuse
    /// the second one (`cannot force update the branch 'main' used by
    /// worktree at ...`).
    #[test]
    fn checkout_of_branch_from_a_stale_manager_does_not_collide() {
        let (src, hash) = make_local_repo("main");
        let remote = src.path().to_str().unwrap().to_string();
        let base = tempfile::tempdir().unwrap();

        // Register the remote through a commit checkout, so a manager created
        // now knows the repo but has no checkout of the branch to reuse.
        let mut first = Manager::new_in_dir(base.path()).unwrap();
        first
            .checkout_of(&remote, GitRef::Commit(hash.clone()))
            .unwrap();
        let mut stale = Manager::new_in_dir(base.path()).unwrap();

        let (path1, rev1) = first
            .checkout_of(&remote, GitRef::Branch("main".to_string()))
            .unwrap();
        let (path2, rev2) = stale
            .checkout_of(&remote, GitRef::Branch("main".to_string()))
            .unwrap();

        assert_eq!(rev1, hash);
        assert_eq!(rev2, hash);
        assert_eq!(
            path1, path2,
            "the stale manager re-reads the registry under the lock and reuses the first's checkout"
        );
        assert!(path2.join("hello.txt").exists());
    }

    /// A refused worktree add leaves nothing behind under the checkouts dir.
    #[test]
    fn checkout_of_unknown_ref_leaves_no_checkout_dir() {
        let (src, _) = make_local_repo("main");
        let remote = src.path().to_str().unwrap().to_string();
        let base = tempfile::tempdir().unwrap();
        let mut handle = Manager::new_in_dir(base.path()).unwrap();

        // Registers the remote; the next call takes the known-remote path.
        handle
            .checkout_of(&remote, GitRef::Branch("main".to_string()))
            .unwrap();
        let before = std::fs::read_dir(base.path().join("git").join("checkouts"))
            .unwrap()
            .count();

        assert!(
            handle
                .checkout_of(&remote, GitRef::Tag("no-such-tag".to_string()))
                .is_err()
        );

        let after = std::fs::read_dir(base.path().join("git").join("checkouts"))
            .unwrap()
            .count();
        assert_eq!(before, after, "the refused add must not leak a directory");
    }

    /// A fresh branch checkout lands on the fetched tip, not the bare
    /// clone's clone-time copy of the branch, and a branch that upstream
    /// created after the clone resolves at all.
    #[test]
    fn checkout_of_branch_lands_on_the_fetched_tip() {
        use std::process::Command;
        let (src, first_hash) = make_local_repo("main");
        let remote = src.path().to_str().unwrap().to_string();
        let base = tempfile::tempdir().unwrap();
        let mut handle = Manager::new_in_dir(base.path()).unwrap();

        // Clone the bare repo at the first commit.
        let (_, rev) = handle
            .checkout_of(&remote, GitRef::Commit(first_hash.clone()))
            .unwrap();
        assert_eq!(rev, first_hash);

        // Move `main` upstream and add a branch that postdates the clone.
        let git = |args: &[&str]| {
            let out = Command::new("git")
                .args(args)
                .current_dir(src.path())
                .output()
                .unwrap();
            assert!(out.status.success(), "git {args:?} failed");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        std::fs::write(src.path().join("hello.txt"), b"hello again").unwrap();
        git(&["commit", "-am", "second"]);
        let second_hash = git(&["rev-parse", "HEAD"]);
        git(&["branch", "dev"]);

        let (path, rev) = handle
            .checkout_of(&remote, GitRef::Branch("main".to_string()))
            .unwrap();
        assert_eq!(
            rev, second_hash,
            "a branch checkout must land on the fetched tip"
        );
        assert_eq!(
            std::fs::read(path.join("hello.txt")).unwrap(),
            b"hello again"
        );

        let (_, rev) = handle
            .checkout_of(&remote, GitRef::Branch("dev".to_string()))
            .unwrap();
        assert_eq!(
            rev, second_hash,
            "a branch created after the clone must resolve"
        );
    }

    /// A cache whose bare clone carries only `refs/heads/<branch>` (cloned
    /// before remote-tracking refs were fetched at clone time, never updated
    /// since) still serves a branch checkout offline.
    #[test]
    fn offline_checkout_of_branch_from_a_legacy_cache_uses_the_local_ref() {
        use std::process::Command;
        let (src, hash) = make_local_repo("main");
        let remote = src.path().to_str().unwrap().to_string();
        let base = tempfile::tempdir().unwrap();

        // Register the remote online, then strip the remote-tracking refs the
        // clone-time fetch wrote, leaving the legacy shape.
        let mut online = Manager::new_in_dir(base.path()).unwrap();
        online
            .checkout_of(&remote, GitRef::Commit(hash.clone()))
            .unwrap();
        let bare = std::fs::read_dir(base.path().join("git").join("db"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let out = Command::new("git")
            .args(["update-ref", "-d", "refs/remotes/origin/main"])
            .current_dir(&bare)
            // Match Repo::run_git_bare: explicit GIT_DIR keeps git operating
            // on the bare repo even when `safe.bareRepository = explicit` is
            // configured (planned as the default in Git 3.0).
            .env("GIT_DIR", &bare)
            .output()
            .unwrap();
        assert!(out.status.success());

        let mut offline = Manager::new_in_dir_with_offline(base.path(), true).unwrap();
        let (path, rev) = offline
            .checkout_of(&remote, GitRef::Branch("main".to_string()))
            .unwrap();
        assert_eq!(rev, hash);
        assert!(path.join("hello.txt").exists());
    }

    /// A refused ref on a remote the manager has never seen leaves no bare
    /// clone behind either: the remote is not recorded, so a leftover
    /// `git/db/<id>` would make the next request clone again under a
    /// suffixed id.
    #[test]
    fn checkout_of_unknown_ref_on_new_remote_leaves_no_bare_repo() {
        let (src, hash) = make_local_repo("main");
        let remote = src.path().to_str().unwrap().to_string();
        let base = tempfile::tempdir().unwrap();
        let mut handle = Manager::new_in_dir(base.path()).unwrap();

        assert!(
            handle
                .checkout_of(&remote, GitRef::Tag("no-such-tag".to_string()))
                .is_err()
        );
        let bares = base.path().join("git").join("db");
        let leftover = std::fs::read_dir(&bares).map(|d| d.count()).unwrap_or(0);
        assert_eq!(leftover, 0, "the refused add must not leak the bare clone");

        // The remote is still unknown, so a good ref clones once, unsuffixed.
        let (_, rev) = handle
            .checkout_of(&remote, GitRef::Commit(hash.clone()))
            .unwrap();
        assert_eq!(rev, hash);
        assert_eq!(std::fs::read_dir(&bares).unwrap().count(), 1);
    }

    /// A single unreachable remote must not gate `update_remote` for a
    /// different, reachable remote — even though the global `update` errors on
    /// the same registry.
    #[test]
    fn update_remote_ignores_other_unreachable_remotes() {
        let (reachable_src, _) = make_local_repo("main");
        let reachable = reachable_src.path().to_str().unwrap().to_string();
        let (unreachable_src, _) = make_local_repo("main");
        let unreachable = unreachable_src.path().to_str().unwrap().to_string();

        let base = tempfile::tempdir().unwrap();
        let mut handle = Manager::new_in_dir(base.path()).unwrap();

        // Register both remotes by checking each out once.
        handle
            .checkout_of(&reachable, GitRef::Branch("main".to_string()))
            .unwrap();
        handle
            .checkout_of(&unreachable, GitRef::Branch("main".to_string()))
            .unwrap();

        // Make the second remote unreachable by dropping its source directory.
        drop(unreachable_src);

        // The global refresh touches every remote, so it fails on the dead one.
        assert!(handle.update().is_err());

        // A targeted refresh of the reachable remote is unaffected.
        handle.update_remote(&reachable).unwrap();
    }

    /// In offline mode, `update()` returns OfflineCacheMiss rather than
    /// silently no-op'ing. Callers like `minimal update` ask explicitly for
    /// fresh state, so noop-ing would mask hard-to-debug bugs (per review
    /// from @twitchyliquid64).
    #[test]
    fn offline_update_errors() {
        let base_dir = tempdir().unwrap();
        let mut manager = Manager::new_in_dir_with_offline(base_dir.path(), true).unwrap();
        match manager.update() {
            Err(Error::OfflineCacheMiss { .. }) => {}
            other => panic!("expected OfflineCacheMiss, got: {:?}", other),
        }
    }

    /// Default (online) Manager keeps its existing behavior — `offline` is
    /// false unless explicitly requested.
    #[test]
    fn default_manager_is_online() {
        let base_dir = tempdir().unwrap();
        let manager = Manager::new_in_dir(base_dir.path()).unwrap();
        assert!(!manager.0.lock().unwrap().offline);
    }

    /// Many managers converging on one cache dir — the exact shape of
    /// concurrent `min session activate` invocations, each building its own
    /// manager against the shared vcs cache — must not race each other's
    /// git operations into `index.lock` and must all land a usable checkout.
    #[test]
    fn concurrent_checkout_of_managers_share_one_cache_dir() {
        let (src, hash) = make_local_repo("main");
        let remote = src.path().to_str().unwrap().to_string();
        let base = tempfile::tempdir().unwrap();

        // The intended failure mode: every manager holds its own directory
        // snapshot at construction. Two managers constructed together see the
        // same (empty) state, so each tries an independent clone + worktree
        // add for the same ref unless the lock serializes them.
        let n_threads = 8;
        let results: Vec<_> = (0..n_threads)
            .map(|_| {
                let (remote, base) = (remote.clone(), base.path().to_path_buf());
                std::thread::spawn(move || {
                    let mut mgr = Manager::new_in_dir(base).unwrap();
                    let (path, rev) = mgr
                        .checkout_of(&remote, GitRef::Branch("main".to_string()))
                        .map_err(|e| e.to_string())?;
                    assert!(path.join("hello.txt").exists());
                    Ok::<_, String>(rev)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>();

        // Every thread must succeed rather than trip over `index.lock`.
        for result in results {
            assert_eq!(result.unwrap(), hash, "manager checkout failed");
        }

        // Each manager re-reads the registry under the lock, so the first
        // clone is reused rather than duplicated under a suffixed id.
        let state = ManagerState::in_dir_or_default(base.path()).unwrap();
        assert_eq!(state.git_remotes.len(), 1, "one remote: {state:?}");
        let id = &state.git_remotes[&remote];
        assert_eq!(
            state.repos[id].checkouts.len(),
            1,
            "one checkout: {state:?}"
        );

        // No `index.lock` may be left stranded in any worktree. A linked
        // worktree's `.git` is a file pointing at its gitdir under the bare
        // repo, which is where the index (and its lock) lives.
        let checkouts = base.path().join("git").join("checkouts");
        for entry in std::fs::read_dir(checkouts).unwrap().flatten() {
            let pointer = std::fs::read_to_string(entry.path().join(".git")).unwrap();
            let gitdir = PathBuf::from(pointer.trim().strip_prefix("gitdir: ").unwrap());
            assert!(gitdir.is_dir(), "worktree gitdir {}", gitdir.display());
            assert!(
                !gitdir.join("index.lock").exists(),
                "stranded index.lock for {}",
                entry.path().display()
            );
        }
    }

    /// Concurrency over the same remote through separate `update_remote`
    /// managers: one manager's worktree refresh must not see another's git
    /// state mid-flux (the other half of the reported `index.lock` race).
    #[test]
    fn concurrent_update_remote_does_not_race() {
        let (src, _) = make_local_repo("main");
        let remote = src.path().to_str().unwrap().to_string();
        let base = tempfile::tempdir().unwrap();

        // One manager registers the remote, so the others see it in state.json.
        let mut first = Manager::new_in_dir(base.path()).unwrap();
        first
            .checkout_of(&remote, GitRef::Branch("main".to_string()))
            .unwrap();

        let n_threads = 8;
        let handles: Vec<_> = (0..n_threads)
            .map(|_| {
                let base = base.path().to_path_buf();
                let remote = remote.clone();
                std::thread::spawn(move || {
                    let mut mgr = Manager::new_in_dir(base).unwrap();
                    mgr.update_remote(&remote).map_err(|e| e.to_string())
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap().unwrap();
        }
    }

    /// Two managers built before either records anything both register
    /// their remote: the second re-reads `state.json` under the lock instead
    /// of writing back its empty construction-time snapshot over the first.
    #[test]
    fn stale_manager_keeps_another_managers_remote() {
        let (src_a, _) = make_local_repo("main");
        let (src_b, _) = make_local_repo("main");
        let remote_a = src_a.path().to_str().unwrap().to_string();
        let remote_b = src_b.path().to_str().unwrap().to_string();
        let base = tempfile::tempdir().unwrap();

        let mut first = Manager::new_in_dir(base.path()).unwrap();
        let mut second = Manager::new_in_dir(base.path()).unwrap();
        first
            .checkout_of(&remote_a, GitRef::Branch("main".to_string()))
            .unwrap();
        second
            .checkout_of(&remote_b, GitRef::Branch("main".to_string()))
            .unwrap();

        let state = ManagerState::in_dir_or_default(base.path()).unwrap();
        assert!(state.git_remotes.contains_key(&remote_a), "{state:?}");
        assert!(state.git_remotes.contains_key(&remote_b), "{state:?}");
    }

    /// A holder of `<base>/.lock` outside any manager (another process, in
    /// the field) keeps `checkout_of` waiting until it lets go, and the
    /// waiter then completes rather than failing.
    #[test]
    fn checkout_of_waits_for_an_external_lock_holder() {
        let (src, hash) = make_local_repo("main");
        let remote = src.path().to_str().unwrap().to_string();
        let base = tempfile::tempdir().unwrap();
        let mut mgr = Manager::new_in_dir(base.path()).unwrap();

        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(base.path().join(".lock"))
            .unwrap();
        file.lock().unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let out = mgr.checkout_of(&remote, GitRef::Branch("main".to_string()));
            tx.send(out.map(|(_, rev)| rev).map_err(|e| e.to_string()))
                .unwrap();
        });

        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(500))
                .is_err(),
            "checkout_of must not proceed while another holder has the lock"
        );
        drop(file);
        let rev = rx
            .recv_timeout(std::time::Duration::from_secs(60))
            .expect("checkout_of completes once the lock is released")
            .unwrap();
        assert_eq!(rev, hash);
        waiter.join().unwrap();
    }

    /// A holder that never lets go fails the waiter once the bound passes,
    /// naming the lock file, instead of hanging it forever.
    #[test]
    fn lock_cache_times_out_on_a_stuck_holder() {
        let base = tempfile::tempdir().unwrap();
        let held = lock_cache(base.path(), Duration::from_secs(1)).unwrap();
        let err = lock_cache(base.path(), Duration::from_millis(200)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("timed out"), "{msg}");
        assert!(
            msg.contains(&base.path().join(".lock").display().to_string()),
            "the error names the lock file: {msg}"
        );
        drop(held);
        lock_cache(base.path(), Duration::from_millis(200)).expect("free once released");
    }

    /// The constructor reads `state.json` without the cache lock, so it
    /// must not wait behind a holder.
    #[test]
    fn constructor_does_not_wait_for_the_cache_lock() {
        let base = tempfile::tempdir().unwrap();
        let _held = lock_cache(base.path(), Duration::from_secs(1)).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let dir = base.path().to_path_buf();
        std::thread::spawn(move || tx.send(Manager::new_in_dir(dir).is_ok()).unwrap());
        assert!(
            rx.recv_timeout(Duration::from_secs(30))
                .expect("constructor returns while the lock is held")
        );
    }

    #[test]
    #[ignore]
    fn repo_integration_smoketest() {
        // Fresh clone
        let clone_dir = tempdir().unwrap();
        let mut repo =
            Repo::new("https://github.com/octocat/Spoon-Knife", clone_dir.path()).unwrap();
        assert_eq!(
            "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9".to_string(),
            repo.bare_revision().unwrap()
        );
        repo.list_remote_branches().unwrap();
        repo.list_tags().unwrap();

        let checkout_dir = tempdir().unwrap();
        repo.new_worktree(
            checkout_dir.path().to_path_buf(),
            GitRef::Branch("main".to_string()),
        )
        .unwrap();

        // Not fresh clone
        let mut repo =
            Repo::new("https://github.com/octocat/Spoon-Knife", clone_dir.path()).unwrap();
        repo.fetch().unwrap();
        assert_eq!(
            "d0dd1f61b33d64e29d8bc1372a94ef6a2fee76a9".to_string(),
            repo.worktree_checkout(checkout_dir.path(), &GitRef::Branch("main".to_string()))
                .unwrap()
        );
    }

    /// Writes `url.<base>.insteadOf = <instead_of>` into the bare clone's own
    /// config. The rewrite can come from any config level; the clone's own
    /// config is used so the test never touches the process environment.
    fn add_insteadof(cache: &std::path::Path, base: &str, instead_of: &str) {
        let output = std::process::Command::new("git")
            .arg("config")
            .arg("--file")
            .arg(cache.join("config"))
            .arg(format!("url.{base}.insteadOf"))
            .arg(instead_of)
            .output()
            .unwrap();
        assert!(output.status.success(), "git config insteadOf failed");
    }

    /// A `url.<base>.insteadOf` rewrite, at any config level, used to break
    /// the cache validation in `Repo::new`: `git remote get-url` applies
    /// rewrites, the clone stores the un-rewritten `remote.origin.url`, so
    /// the second open of the same cache dir failed with
    /// `Error::InvalidPath`.
    #[test]
    fn accepts_a_cached_clone_whose_origin_is_rewritten_by_insteadof() {
        let (src, _) = make_local_repo("main");
        let src = src.path().to_string_lossy().into_owned();
        let cache = tempfile::tempdir().unwrap();

        Repo::new(&src, cache.path()).expect("first open clones");
        // Rewrite the plain path to a `file://` URL, as a user's config might.
        add_insteadof(cache.path(), &format!("file://{src}"), &src);

        // Second open revalidates the cached clone instead of cloning, and
        // fetches still go through the rewrite.
        let mut repo = Repo::new(&src, cache.path()).expect("rewritten cache reopens");
        repo.fetch().expect("fetch through the rewrite succeeds");
    }

    /// The cache identity check compares the url the caller asked for with
    /// the url the cache was cloned from, both un-rewritten: an `insteadOf`
    /// mapping the requested url onto the cached one does not make a cache
    /// of another remote pass. The pre-fix code refused this too; the test
    /// pins that refusal so a later loosening (for example comparing
    /// rewritten urls on both sides) cannot slip through.
    #[test]
    fn refuses_a_cached_clone_of_another_remote_even_under_insteadof() {
        let (cached, _) = make_local_repo("main");
        let cached = cached.path().to_string_lossy().into_owned();
        let (requested, _) = make_local_repo("main");
        let requested = requested.path().to_string_lossy().into_owned();
        let cache = tempfile::tempdir().unwrap();

        Repo::new(&cached, cache.path()).expect("first open clones");
        add_insteadof(cache.path(), &cached, &requested);
        let result = Repo::new(&requested, cache.path()).map(|_| ());

        assert!(
            matches!(result, Err(crate::Error::InvalidPath)),
            "a cache of another remote is refused"
        );
    }
}
