use crate::{Checkout, Error, GitRef, scrubbed_remote};
use common::fetchers::MirrorEndpoint;
use common::mirror::{MirrorPath, RepoSlug};
use mirror_client::blocking;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tracing::{info, trace};

const GIT_SEC_ARGS: [&str; 3] = ["--no-optional-locks", "-c", "core.hooksPath=/dev/null"];

/// The refspec every fetch uses: the source's branch heads land under
/// `refs/remotes/origin/*`, whichever source they come from.
const FETCH_REFSPEC: &str = "+refs/heads/*:refs/remotes/origin/*";

/// The mirror a repository's copy is read from, in the form the endpoint
/// serves it (spec MIR, O2): the host socket names the copy's path in the
/// store, which git reads as a local repository; a guest door serves a
/// bundle, which the guest downloads to a file and git reads from there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepoMirror {
    /// The host socket: the mirror answers `path` with the copy's store path.
    Path(MirrorEndpoint),
    /// A guest door: the mirror answers `bundle`, downloaded to `file`.
    Bundle {
        endpoint: MirrorEndpoint,
        file: PathBuf,
    },
}

impl RepoMirror {
    /// The form `endpoint` serves: a path over a Unix socket, a bundle over a
    /// vsock door, which lands in `bundle_file`.
    // On a platform without vsock no endpoint serves a bundle, so the file
    // goes unused there.
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    pub fn for_endpoint(endpoint: MirrorEndpoint, bundle_file: PathBuf) -> Self {
        match endpoint {
            MirrorEndpoint::Unix(_) => RepoMirror::Path(endpoint),
            #[cfg(target_os = "linux")]
            MirrorEndpoint::Vsock { .. } => RepoMirror::Bundle {
                endpoint,
                file: bundle_file,
            },
        }
    }
}

/// Why the mirror gave no copy; the caller then fetches from the origin.
#[derive(Debug, thiserror::Error)]
enum NoCopy {
    #[error(transparent)]
    Request(#[from] blocking::Error),
    #[error("the mirror answered {status}: {body}")]
    Refused { status: u16, body: String },
    #[error("the mirror answered a path that is not absolute: {0:?}")]
    RelativePath(String),
    #[error("the bundle could not be written: {0}")]
    Write(#[from] std::io::Error),
}

/// The mirror's copy of one repository: set when a mirror is given and the
/// repository URL is in the slug grammar (MIR-013).
#[derive(Debug)]
struct MirrorCopy {
    mirror: RepoMirror,
    slug: RepoSlug,
}

impl MirrorCopy {
    /// Asks the mirror for the copy and returns what git fetches from: the
    /// store path, or the bundle file once downloaded (MIR-010).
    fn source(&self) -> Result<PathBuf, NoCopy> {
        match &self.mirror {
            RepoMirror::Path(endpoint) => {
                let path = MirrorPath::GitPath {
                    slug: self.slug.clone(),
                }
                .render();
                let reply = blocking::get(endpoint, &path)?;
                let body = reply.text();
                if !(200..300).contains(&reply.status) {
                    return Err(NoCopy::Refused {
                        status: reply.status,
                        body,
                    });
                }
                let copy = PathBuf::from(&body);
                if !copy.is_absolute() {
                    return Err(NoCopy::RelativePath(body));
                }
                Ok(copy)
            }
            RepoMirror::Bundle { endpoint, file } => {
                let path = MirrorPath::GitBundle {
                    slug: self.slug.clone(),
                }
                .render();
                if let Some(parent) = file.parent() {
                    fs::create_dir_all(parent)?;
                }
                let reply = blocking::get_to_file(endpoint, &path, file)?;
                if !(200..300).contains(&reply.status) {
                    return Err(NoCopy::Refused {
                        status: reply.status,
                        body: reply.text(),
                    });
                }
                Ok(file.clone())
            }
        }
    }
}

/// A git repository of some remote.
pub struct Repo {
    /// The path to the bare repository.
    bare: PathBuf,
    /// The remote URL of the repository.
    url: String,
    /// The mirror's copy to fetch from, when a mirror is set and the URL is
    /// in its grammar; the remote stays `url` either way (MIR-013).
    copy: Option<MirrorCopy>,
}

impl Repo {
    /// Creates a new repository for the given URL and bare repository. The
    /// given path with be re-used if it is already initialized.
    pub fn new<S: Into<String>, P: Into<PathBuf>>(url: S, base: P) -> Result<Self, Error> {
        Self::new_with_mirror(url, base, None)
    }

    /// As [`Self::new`], fetching through `mirror` when one is given and the
    /// URL has the scheme `https`, no user information and no port (MIR-013).
    /// Any other URL, and a mirror that holds no copy or does not answer,
    /// fetches from the origin as [`Self::new`] does.
    pub fn new_with_mirror<S: Into<String>, P: Into<PathBuf>>(
        url: S,
        base: P,
        mirror: Option<RepoMirror>,
    ) -> Result<Self, Error> {
        let url = url.into();
        let copy = mirror.and_then(|mirror| match RepoSlug::from_repo_url(&url) {
            Ok(slug) => Some(MirrorCopy { mirror, slug }),
            Err(reason) => {
                trace!(
                    remote = %scrubbed_remote(&url),
                    %reason,
                    "repository is outside the mirror's grammar; fetching from its origin"
                );
                None
            }
        });
        // Absolute, because every git call below pairs `current_dir(base)`
        // with `GIT_DIR=base`, and git resolves a relative `GIT_DIR` against
        // that new working directory.
        let base = std::path::absolute(base.into())?;

        if base.join("HEAD").exists() {
            // Double-check its the right remote. Read the clone's stored value,
            // not `git remote get-url`: the latter applies `url.<base>.insteadOf`
            // rewrites from any config level, so a rewritten clone would never
            // match and every cache open would fail with InvalidPath.
            // `--local` so a `remote.origin.url` in global or system config
            // cannot stand in for a cache whose own config lacks one.
            let output = Command::new("git")
                .args(["config", "--local", "--get", "remote.origin.url"])
                .current_dir(&base)
                // Explicit GIT_DIR so git recognises the bare repo as
                // intentional even when `safe.bareRepository = explicit` is
                // configured (planned as the default in Git 3.0). Under that
                // setting, missing it makes this command fail and fall
                // through to a clone into the already-populated directory,
                // which can surface as `clone ... already exists`.
                .env("GIT_DIR", &base)
                .output()?;

            if output.status.success() {
                let remote = String::from_utf8_lossy(&output.stdout).trim().to_string();
                return if remote != url {
                    Err(Error::InvalidPath)
                } else {
                    Ok(Self {
                        url,
                        bare: base,
                        copy,
                    })
                };
            }
        }

        // Create parent directory if it doesn't exist
        if let Some(parent) = base.parent() {
            fs::create_dir_all(parent)?;
        }

        let repo = Self {
            url,
            bare: base,
            copy,
        };
        let cloned_from = repo.clone_bare()?;

        // A bare clone writes only `refs/heads/*`; every branch lookup in this
        // crate goes through `refs/remotes/origin/*`, so populate those now
        // rather than leaving the first branch checkout to fail on a ref the
        // clone never wrote. The source the clone came from serves the fetch
        // too, so a guest does not download its bundle twice. A clone that
        // cannot be fetched is not a usable cache entry: take the directory
        // with the error.
        if let Err(err) = repo.fetch_via(cloned_from.as_deref()) {
            // The directory goes with the error; its own failure to go would
            // add nothing to that error.
            let _ = fs::remove_dir_all(&repo.bare);
            return Err(err);
        }
        Ok(repo)
    }

    /// Asks the mirror for its copy. `None`, logged, when there is no mirror
    /// for this URL, when the mirror holds no copy, or when it does not
    /// answer: the caller then uses the origin, so the mirror never fails a
    /// fetch (MIR-013).
    fn copy_source(&self) -> Option<PathBuf> {
        let copy = self.copy.as_ref()?;
        match copy.source() {
            Ok(source) => Some(source),
            Err(reason) => {
                info!(
                    remote = %scrubbed_remote(&self.url),
                    %reason,
                    "the mirror gave no copy; fetching from the origin"
                );
                None
            }
        }
    }

    /// Clones the bare repository from the mirror's copy when it has one, and
    /// from the origin otherwise. Returns the copy the clone came from, so
    /// the caller can fetch from it too. A clone from the copy keeps the
    /// original URL as the remote: the copy is where the bytes come from,
    /// never the repository's identity (MIR-013).
    fn clone_bare(&self) -> Result<Option<PathBuf>, Error> {
        let dest = self.bare.to_str().ok_or(Error::InvalidPath)?;
        if let Some(copy) = self.copy_source() {
            let from_copy = copy
                .to_str()
                .ok_or(Error::InvalidPath)
                .and_then(|source| self.run_clone(source, dest))
                .and_then(|()| self.run_git_bare(vec!["remote", "set-url", "origin", &self.url]));
            match from_copy {
                Ok(_) => return Ok(Some(copy)),
                Err(reason) => {
                    info!(
                        remote = %scrubbed_remote(&self.url),
                        %reason,
                        "clone from the mirror's copy failed; cloning from the origin"
                    );
                    // Whatever the failed clone left would make the origin
                    // clone refuse the directory; a directory that is already
                    // gone is the wanted state.
                    let _ = fs::remove_dir_all(&self.bare);
                }
            }
        }
        self.run_clone(&self.url, dest).map(|()| None)
    }

    /// `git clone --quiet --bare <source> <dest>`.
    fn run_clone(&self, source: &str, dest: &str) -> Result<(), Error> {
        let output = Command::new("git")
            .args(
                GIT_SEC_ARGS
                    .into_iter()
                    .chain(["clone", "--quiet", "--bare"])
                    .chain([source, dest])
                    .collect::<Vec<_>>(),
            )
            .output()?;
        if !output.status.success() {
            return Err(Error::GitCommandFailed {
                command: "clone".to_string(),
                stderr: scrub_stderr(&self.url, &output.stderr),
                status: output.status.to_string(),
            });
        }
        Ok(())
    }

    /// Returns the path to the bare git repository.
    pub fn bare_repo_path(&self) -> &Path {
        &self.bare
    }

    /// Returns the remote URL of the repository.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Fetches updates from the remote repository.
    ///
    /// This updates the remote-tracking branches but does not modify any
    /// checkouts. With a mirror, the update comes from its copy, asked for
    /// afresh each time so a guest reads the newest bundle; the origin serves
    /// when the mirror gives none (MIR-013).
    pub fn fetch(&mut self) -> Result<(), Error> {
        self.fetch_via(self.copy_source().as_deref())
    }

    /// Fetches from `copy` when there is one, and from the origin when there
    /// is none or the copy cannot be fetched.
    fn fetch_via(&self, copy: Option<&Path>) -> Result<(), Error> {
        if let Some(copy) = copy {
            let from_copy = copy
                .to_str()
                .ok_or(Error::InvalidPath)
                .and_then(|source| self.fetch_from(source));
            match from_copy {
                Ok(()) => return Ok(()),
                Err(reason) => info!(
                    remote = %scrubbed_remote(&self.url),
                    %reason,
                    "fetch from the mirror's copy failed; fetching from the origin"
                ),
            }
        }
        self.fetch_from("origin")
    }

    /// `git fetch --quiet <source> <refspec>`: `source` is the remote
    /// `origin`, a copy's path or a bundle file.
    fn fetch_from(&self, source: &str) -> Result<(), Error> {
        self.run_git_bare(
            GIT_SEC_ARGS
                .into_iter()
                .chain(["fetch", "--quiet"])
                .chain([source, FETCH_REFSPEC])
                .collect::<Vec<_>>(),
        )?;
        Ok(())
    }

    /// Returns the current commit hash of the repositories' default branch.
    pub fn bare_revision(&self) -> Result<String, Error> {
        let output = self.run_git_bare(["rev-parse", "HEAD"].into())?;
        let commit = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(commit)
    }

    /// Checks out the given ref in the given worktree, returning the git hash.
    pub fn worktree_checkout(
        &self,
        worktree_path: &Path,
        git_ref: &GitRef,
    ) -> Result<String, Error> {
        match git_ref {
            GitRef::Branch(b) => self.run_git_checkout(
                worktree_path,
                GIT_SEC_ARGS
                    .into_iter()
                    .chain(["checkout", format!("origin/{}", b).as_str()])
                    .collect(),
            ),
            GitRef::Commit(s) | GitRef::Tag(s) => self.run_git_checkout(
                worktree_path,
                GIT_SEC_ARGS
                    .into_iter()
                    .chain(["checkout", s])
                    .collect::<Vec<_>>(),
            ),
        }?;

        let output = self.run_git_checkout(worktree_path, ["rev-parse", "HEAD"].into())?;
        let commit = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(commit)
    }

    /// Creates a new worktree at the given path, checked-out to the given ref.
    ///
    /// Every worktree is a detached checkout, a branch included. Git lets a
    /// branch be checked out by at most one worktree of a repository, so a
    /// worktree *on* `main` makes the next `new_worktree` for `main` fail
    /// (`cannot force update the branch 'main' used by worktree at ...`) —
    /// and that next request is routine, because every [`crate::Manager`]
    /// over a shared cache dir carries its own snapshot of the checkout
    /// registry, and one that predates another's checkout asks for its own.
    /// Detached, the worktrees are independent; a branch checkout is
    /// refreshed by [`Self::worktree_checkout`] via `origin/<branch>`
    /// regardless, which detaches too.
    ///
    /// A branch is added at `origin/<branch>`, the ref [`Self::fetch`]
    /// updates, not at the bare name: that resolves to the bare clone's own
    /// `refs/heads/<branch>`, which nothing refreshes after the clone, so the
    /// worktree would land on the clone-time tip and a branch created
    /// upstream since would not resolve at all.
    pub fn new_worktree(&mut self, path: PathBuf, git_ref: GitRef) -> Result<Checkout, Error> {
        // Drop registrations whose directories are gone first, so a stale
        // entry cannot claim the path this add is about to use.
        self.run_git_bare(
            GIT_SEC_ARGS
                .into_iter()
                .chain(["worktree", "prune"])
                .collect::<Vec<_>>(),
        )?;
        let target = match &git_ref {
            // A cache cloned before remote-tracking refs were fetched at clone
            // time, and never updated since, carries only `refs/heads/<b>`;
            // offline that is the only copy of the branch there is.
            GitRef::Branch(b) => {
                let tracking = format!("refs/remotes/origin/{b}");
                if self.ref_exists(&tracking) {
                    tracking
                } else {
                    format!("refs/heads/{b}")
                }
            }
            GitRef::Commit(s) | GitRef::Tag(s) => s.clone(),
        };
        self.run_git_bare(
            GIT_SEC_ARGS
                .into_iter()
                .chain([
                    "worktree",
                    "add",
                    "-f",
                    "--detach",
                    path.to_str().unwrap(),
                    target.as_str(),
                ])
                .collect::<Vec<_>>(),
        )?;

        let output = self.run_git_checkout(&path, ["rev-parse", "HEAD"].into())?;
        Ok(Checkout {
            version: git_ref,
            rev: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        })
    }

    /// Whether the bare repository has the given fully-qualified ref.
    fn ref_exists(&self, full_ref: &str) -> bool {
        self.run_git_bare(["show-ref", "--verify", "--quiet", full_ref].into())
            .is_ok()
    }

    /// Returns a list of all tags in the repository.
    pub fn list_tags(&self) -> Result<Vec<String>, Error> {
        let output = self.run_git_bare(["tag", "--list"].into())?;
        let tags = String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|s| s.to_string())
            .collect();
        Ok(tags)
    }

    /// Returns a list of all remote branches.
    pub fn list_remote_branches(&self) -> Result<Vec<String>, Error> {
        let output = self.run_git_bare(["branch", "--remote", "--list"].into())?;
        let branches = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|s| {
                let trimmed = s.trim();
                // Skip HEAD pointer
                if trimmed.starts_with("origin/HEAD") {
                    None
                } else {
                    // Remove "origin/" prefix
                    trimmed.strip_prefix("origin/").map(|b| b.to_string())
                }
            })
            .collect();
        Ok(branches)
    }

    /// Runs a git command in the bare repository directory.
    fn run_git_bare(&self, args: Vec<&str>) -> Result<Output, Error> {
        trace!("Running bare git command: git {:?}", &args.join(" "));

        let output = Command::new("git")
            .current_dir(self.bare_repo_path())
            // Explicitly set GIT_DIR so git recognises the bare repo as
            // intentional even when `safe.bareRepository = explicit` is set
            // in the system or global config (planned as the default in
            // Git 3.0).
            .env("GIT_DIR", self.bare_repo_path())
            .args(&args)
            .output()?;

        if !output.status.success() {
            let stderr = scrub_stderr(&self.url, &output.stderr);
            return Err(Error::GitCommandFailed {
                command: args.join(" "),
                stderr,
                status: output.status.to_string(),
            });
        }
        Ok(output)
    }

    /// Runs a git command in a specific checkout directory.
    fn run_git_checkout<P: AsRef<Path>>(
        &self,
        checkout: P,
        args: Vec<&str>,
    ) -> Result<Output, Error> {
        trace!("Running worktree git command: git {}", args.join(" "));

        let output = Command::new("git")
            .current_dir(checkout)
            .args(&args)
            .output()?;

        if !output.status.success() {
            let stderr = scrub_stderr(&self.url, &output.stderr);
            return Err(Error::GitCommandFailed {
                command: args.join(" "),
                stderr,
                status: output.status.to_string(),
            });
        }
        Ok(output)
    }
}

impl std::fmt::Debug for Repo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Repo")
            .field("url", &self.url)
            .field("bare", &self.bare)
            .field("copy", &self.copy)
            .finish()
    }
}

/// Git's stderr, with the secret parts of `url` taken out: the whole URL is
/// replaced by the scrubbed remote, and then any userinfo or query/fragment
/// left is removed on its own, because git echoes the URL it was given
/// ("unable to access '…'"), sometimes with its own userinfo already gone.
/// A token in the URL must not reach an error message (spec 25 TEL-041).
fn scrub_stderr(url: &str, stderr: &[u8]) -> String {
    let mut stderr = String::from_utf8_lossy(stderr).into_owned();
    let scrubbed = crate::scrubbed_remote(url);
    if scrubbed == url {
        return stderr;
    }
    stderr = stderr.replace(url, &scrubbed);
    let (base, tail) = url
        .find(['?', '#'])
        .map_or((url, ""), |at| url.split_at(at));
    if !tail.is_empty() {
        stderr = stderr.replace(tail, "");
    }
    let authority = base.split_once("://").map_or(base, |(_, rest)| rest);
    let authority = authority.split('/').next().unwrap_or(authority);
    if let Some((userinfo, _)) = authority.rsplit_once('@') {
        stderr = stderr.replace(&format!("{userinfo}@"), "");
    }
    stderr
}
