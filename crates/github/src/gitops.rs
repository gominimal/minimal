//! Daemon-side authenticated git for working-tree session repositories (spec R2,
//! R3, R6).
//!
//! This module runs real `git` against a session's working tree on the daemon
//! host, on the token's behalf, and returns the result. It is modelled on the
//! hardening in `crates/checkouts` (the `GIT_SEC_ARGS` prefix:
//! `--no-optional-locks` and `core.hooksPath=/dev/null`) but adds the property
//! the GitHub flow needs above everything else: **the token never touches argv,
//! the remote URL, or any on-disk git config.**
//!
//! # Why env-only credential injection (a deliberate deviation from the spec)
//!
//! The PRD sketches the transport as an `https://x-access-token:<token>@…` URL.
//! That is illustrative only. Baking the token into the URL would persist it in
//! `.git/config` (`origin.url`) and echo it in process argv — both of which are
//! **sandbox-visible**, because the session's working tree lives on the host the
//! sandbox can read (R6.1). So this module fails closed instead:
//!
//! * `origin` always carries the **clean** `https://…` URL — no userinfo.
//! * Credentials are injected **only through the environment** of each `git`
//!   child, via `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_n` / `GIT_CONFIG_VALUE_n`
//!   which install an inline, one-shot `credential.helper`. The helper is a
//!   short shell snippet that prints `username`/`password` on the `get`
//!   operation; the **password is read from a per-child env var**
//!   ([`SECRET_ENV`]), so the token appears in neither the config *value* nor
//!   anywhere git can write to disk.
//! * The helper list is **reset to empty first** (`credential.helper=`), then
//!   ours is appended. This is load-bearing on a real developer host: without
//!   the reset, an inherited helper (e.g. `credential.https://github.com.helper
//!   = !gh auth git-credential` in the operator's `~/.gitconfig`) would answer
//!   first and splice in the *wrong* user's real token — a silent
//!   misattribution and credential-leak bug. The reset clears every inherited
//!   (generic and URL-scoped) helper so only ours can fire.
//! * `GIT_TERMINAL_PROMPT=0` turns a missing/failed credential into a clean
//!   failure instead of an interactive hang, and `protocol.allow` is pinned to
//!   the exact scheme of the configured remote so a malicious redirect cannot
//!   switch git onto `file://`/`ext::` transports.
//! * The operator's **global and system git config are denied** to every child
//!   (`GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM` → `/dev/null`): a git spawned
//!   here reads only the repo-local config of the directory it runs in, so the
//!   "credentialed git reads only daemon-authored config" invariant holds by
//!   construction, not merely because the inherited environment happens to be
//!   clean of `insteadOf` rewrites or stray credential helpers.
//!
//! Finally, `git` is chatty, so all child stdout/stderr is streamed line-by-line
//! through a [`scrub`]ber that masks the live token bytes with
//! [`crate::secret::REDACTED`] before a line ever reaches a callback, a captured
//! buffer, or an error message — belt-and-suspenders against a remote that
//! echoes what it was sent.

use std::borrow::Cow;
use std::fmt;
use std::fs;
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::secret::{REDACTED, SecretString};

/// Non-secret hardening flags applied to every `git` invocation, mirroring
/// `crates/checkouts`: no optional index locks, and hooks disabled so a
/// repository can never run attacker-controlled hook scripts on the daemon.
const GIT_SEC_ARGS: [&str; 3] = ["--no-optional-locks", "-c", "core.hooksPath=/dev/null"];

/// The per-child environment variable the inline credential helper reads the
/// token from. Named distinctively so it is greppable and unlikely to collide.
const SECRET_ENV: &str = "MINIMALD_GH_CRED_TOKEN";

/// The HTTP Basic username presented alongside the token. For a GitHub App
/// user-to-server token any username works; `x-access-token` is conventional.
const CRED_USERNAME: &str = "x-access-token";

/// Which of a child's two output streams a line arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStream {
    /// The child's standard output.
    Stdout,
    /// The child's standard error (where `git` writes progress).
    Stderr,
}

/// Errors from daemon-side git operations.
///
/// Every variant is safe to surface: `stderr` embedded in [`GitError::Failed`]
/// has already passed through the token [`scrub`]ber, and no variant carries
/// credential material.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GitError {
    /// The `git` process could not be started or waited on.
    #[error("failed to run git for `{operation}`: {source}")]
    Spawn {
        /// The logical operation being attempted (e.g. `clone`, `push`).
        operation: String,
        /// The underlying spawn/wait error.
        #[source]
        source: io::Error,
    },

    /// `git` ran but exited non-zero. `stderr` is scrubbed of token bytes.
    #[error("git {operation} failed ({status}): {stderr}")]
    Failed {
        /// The logical operation that failed.
        operation: String,
        /// A human description of how it exited.
        status: String,
        /// The (scrubbed) tail of the child's stderr.
        stderr: String,
    },

    /// The requested base branch does not exist on the remote, so a working
    /// branch cannot be created from it (spec R2.6).
    #[error("base branch `{branch}` not found on the remote")]
    BaseBranchNotFound {
        /// The base branch that could not be resolved.
        branch: String,
    },

    /// A filesystem step around a git operation failed (temp dir, rename, …).
    #[error("filesystem error during git {operation}: {source}")]
    Io {
        /// The logical operation whose filesystem step failed.
        operation: String,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// Expected information could not be parsed out of git's output.
    #[error("could not determine {what} from git output")]
    Unparsable {
        /// What was being parsed (e.g. `remote default branch`).
        what: String,
    },

    /// The clone destination already exists; cloning would not be atomic.
    #[error("clone destination `{path}` already exists")]
    DestinationExists {
        /// The destination path that was already present.
        path: String,
    },

    /// A path could not be expressed as UTF-8 for a git argument.
    #[error("path is not valid UTF-8: {path}")]
    NonUtf8Path {
        /// The offending path, rendered lossily.
        path: String,
    },
}

/// The result of [`Repo::checkout_or_create`] (spec R2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CheckoutOutcome {
    /// The branch already existed on the remote and was checked out.
    Checkout,
    /// The branch was absent on the remote and was created locally from the
    /// base branch. It is **not** pushed (spec R2.5).
    CreatedFromBase,
}

/// How the current branch relates to its upstream — the signal that feeds the
/// "is there PR-able work?" decision (spec R4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ahead {
    /// No upstream is configured: a freshly created branch that has never been
    /// pushed. Everything on it is unpushed.
    NoUpstream,
    /// The branch tracks `origin/<branch>`; it is `ahead` commits ahead and
    /// `behind` commits behind that upstream.
    Tracking {
        /// Commits on the local branch not yet on its upstream.
        ahead: usize,
        /// Commits on the upstream not yet merged locally.
        behind: usize,
    },
}

impl Ahead {
    /// Whether this branch has work that could be turned into a pull request:
    /// either it has no upstream yet, or it is strictly ahead of one.
    #[must_use]
    pub fn is_pr_able(&self) -> bool {
        match self {
            Ahead::NoUpstream => true,
            Ahead::Tracking { ahead, .. } => *ahead > 0,
        }
    }
}

/// Replaces every occurrence of the live token in `line` with the redaction
/// marker. A no-op when there is no token or it does not appear.
fn scrub<'a>(line: &'a str, token: Option<&str>) -> Cow<'a, str> {
    match token {
        Some(secret) if !secret.is_empty() && line.contains(secret) => {
            Cow::Owned(line.replace(secret, REDACTED))
        }
        _ => Cow::Borrowed(line),
    }
}

/// The inline `credential.helper` shell snippet. It responds only to the `get`
/// operation and reads the token from [`SECRET_ENV`] — the token itself is never
/// part of this string, only the name of the env var that carries it.
fn credential_helper_script() -> String {
    format!(
        "!f() {{ test \"$1\" = get && printf 'username=%s\\npassword=%s\\n' \
         '{CRED_USERNAME}' \"${{{SECRET_ENV}-}}\"; }}; f"
    )
}

/// The transport scheme of a remote (`https`, `http`, `file`). Local paths with
/// no `scheme://` prefix are treated as `file`.
fn url_scheme(remote: &str) -> &str {
    remote.split_once("://").map(|(s, _)| s).unwrap_or("file")
}

/// A fully-built `git` invocation: the argv (after `git`) and the environment
/// overrides. Kept separate from spawning so it can be asserted on in tests
/// (the token must appear only in the [`SECRET_ENV`] value, nowhere else).
struct GitCommand {
    args: Vec<String>,
    /// `(key, value)` env overrides. Exactly one value — the [`SECRET_ENV`]
    /// entry — may carry token bytes; everything else is non-secret.
    envs: Vec<(String, String)>,
}

impl fmt::Debug for GitCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redact the one secret-bearing env value so a stray debug print is safe.
        let envs: Vec<(&str, &str)> = self
            .envs
            .iter()
            .map(|(k, v)| {
                if k == SECRET_ENV {
                    (k.as_str(), REDACTED)
                } else {
                    (k.as_str(), v.as_str())
                }
            })
            .collect();
        f.debug_struct("GitCommand")
            .field("args", &self.args)
            .field("envs", &envs)
            .finish()
    }
}

/// Builds the hardened argv + environment for one git call. When `token` is
/// `Some`, installs the env-only credential helper (with a leading reset of any
/// inherited helper) and places the token in the [`SECRET_ENV`] value only.
fn build_git(scheme: &str, subargs: &[&str], token: Option<&str>) -> GitCommand {
    let mut args: Vec<String> = GIT_SEC_ARGS.iter().map(|s| (*s).to_string()).collect();
    args.extend(subargs.iter().map(|s| (*s).to_string()));

    // Runtime-only config (never written to any repo's config file).
    let mut config: Vec<(String, String)> = vec![
        // Pin transport: deny everything, then re-allow exactly the remote's
        // scheme so a redirect cannot switch git onto a dangerous transport.
        ("protocol.allow".to_string(), "never".to_string()),
        (format!("protocol.{scheme}.allow"), "always".to_string()),
    ];

    let mut envs: Vec<(String, String)> = vec![
        ("GIT_TERMINAL_PROMPT".to_string(), "0".to_string()),
        // Deny the operator's global/system config: the child reads only the
        // repo-local config of the daemon-controlled directory it runs in
        // (see the module docs — this makes the isolation hold by
        // construction).
        ("GIT_CONFIG_GLOBAL".to_string(), "/dev/null".to_string()),
        ("GIT_CONFIG_SYSTEM".to_string(), "/dev/null".to_string()),
    ];

    if let Some(secret) = token {
        // Reset the accumulated helper list (clears inherited helpers such as a
        // host `gh auth git-credential`), then install ours as the only helper.
        config.push(("credential.helper".to_string(), String::new()));
        config.push(("credential.helper".to_string(), credential_helper_script()));
        // The plaintext lives only here, only for this child's lifetime.
        envs.push((SECRET_ENV.to_string(), secret.to_string()));
    }

    envs.push(("GIT_CONFIG_COUNT".to_string(), config.len().to_string()));
    for (i, (key, value)) in config.into_iter().enumerate() {
        envs.push((format!("GIT_CONFIG_KEY_{i}"), key));
        envs.push((format!("GIT_CONFIG_VALUE_{i}"), value));
    }

    GitCommand { args, envs }
}

/// The captured, already-scrubbed result of a git child.
#[derive(Debug)]
struct GitOutput {
    success: bool,
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Drains one child stream line-by-line, forwarding each line to `tx`. Reading
/// on a dedicated thread per stream avoids the classic pipe-buffer deadlock when
/// git writes a lot to both stdout and stderr.
fn read_lines<R: Read>(reader: R, stream: OutputStream, tx: mpsc::Sender<(OutputStream, String)>) {
    let mut buffered = BufReader::new(reader);
    let mut raw = Vec::new();
    loop {
        raw.clear();
        match buffered.read_until(b'\n', &mut raw) {
            Ok(0) => break,
            Ok(_) => {
                while matches!(raw.last(), Some(b'\n') | Some(b'\r')) {
                    raw.pop();
                }
                let line = String::from_utf8_lossy(&raw).into_owned();
                if tx.send((stream, line)).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

/// Runs one hardened git command in `cwd`, streaming each output line (scrubbed)
/// to `on_line` and returning the captured, scrubbed output. `remote` is used
/// only to derive the transport scheme to pin; `token`, when present, is
/// injected env-only.
///
/// A non-zero exit is **not** an error here — the caller decides via [`require`]
/// — so callers that want to inspect a failure (e.g. probing for an upstream)
/// can do so.
fn run_git(
    cwd: &Path,
    remote: &str,
    operation: &str,
    subargs: &[&str],
    token: Option<&SecretString>,
    mut on_line: impl FnMut(OutputStream, &str),
) -> Result<GitOutput, GitError> {
    let exposed: Option<&str> = token.map(SecretString::expose_secret);
    let spec = build_git(url_scheme(remote), subargs, exposed);

    let mut command = Command::new("git");
    command
        .args(&spec.args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in &spec.envs {
        command.env(key, value);
    }

    let mut child = command.spawn().map_err(|source| GitError::Spawn {
        operation: operation.to_string(),
        source,
    })?;
    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");

    let (tx, rx) = mpsc::channel::<(OutputStream, String)>();
    let mut out_buf = String::new();
    let mut err_buf = String::new();

    std::thread::scope(|scope| {
        let tx_out = tx.clone();
        scope.spawn(move || read_lines(stdout, OutputStream::Stdout, tx_out));
        let tx_err = tx.clone();
        scope.spawn(move || read_lines(stderr, OutputStream::Stderr, tx_err));
        // Drop the original sender so `rx` ends once both readers finish.
        drop(tx);

        for (stream, line) in rx {
            let scrubbed = scrub(&line, exposed);
            on_line(stream, scrubbed.as_ref());
            let buf = match stream {
                OutputStream::Stdout => &mut out_buf,
                OutputStream::Stderr => &mut err_buf,
            };
            buf.push_str(scrubbed.as_ref());
            buf.push('\n');
        }
    });

    let status = child.wait().map_err(|source| GitError::Spawn {
        operation: operation.to_string(),
        source,
    })?;

    Ok(GitOutput {
        success: status.success(),
        code: status.code(),
        stdout: out_buf,
        stderr: err_buf,
    })
}

/// Turns a non-zero git exit into a [`GitError::Failed`]; passes success
/// through. The embedded stderr is already token-scrubbed.
fn require(out: GitOutput, operation: &str) -> Result<GitOutput, GitError> {
    if out.success {
        return Ok(out);
    }
    let stderr = {
        let trimmed = out.stderr.trim();
        if trimmed.is_empty() {
            "(no stderr)".to_string()
        } else {
            trimmed.to_string()
        }
    };
    Err(GitError::Failed {
        operation: operation.to_string(),
        status: match out.code {
            Some(code) => format!("exit status {code}"),
            None => "terminated by signal".to_string(),
        },
        stderr,
    })
}

/// Parses a `git ls-remote --symref origin HEAD` line of the form
/// `ref: refs/heads/<name>\tHEAD` into `<name>`.
fn parse_symref(line: &str) -> Option<String> {
    let rest = line.strip_prefix("ref:")?.trim_start();
    let refname = rest.split_whitespace().next()?;
    refname.strip_prefix("refs/heads/").map(str::to_string)
}

/// A unique temp sibling of `dest` inside `parent`, on the same filesystem so
/// the finalizing rename is atomic.
fn unique_temp(parent: &Path, dest: &Path) -> PathBuf {
    let name = dest.file_name().and_then(|n| n.to_str()).unwrap_or("repo");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    parent.join(format!(".{name}.gitops-{}-{nanos}.tmp", std::process::id()))
}

/// An authenticated git working tree for a session repository.
///
/// `remote` is always the **clean** URL (no credentials); authentication is
/// supplied per operation as an [`Option<&SecretString>`] and injected env-only.
/// Passing `None` runs an unauthenticated operation (local-only, or against a
/// transport that needs no credentials, e.g. `file://` fixtures).
#[derive(Debug)]
#[must_use]
pub struct Repo {
    work: PathBuf,
    remote: String,
}

impl Repo {
    /// Clones `remote` into `dest` atomically: the clone lands in a temp sibling
    /// of `dest` and is renamed into place only on success, so a failure leaves
    /// **no** half-primed directory behind (spec R2.6). `dest` must not already
    /// exist. Progress lines are streamed (scrubbed) to `on_line`.
    pub fn clone(
        remote: impl Into<String>,
        dest: impl AsRef<Path>,
        token: Option<&SecretString>,
        on_line: impl FnMut(OutputStream, &str),
    ) -> Result<Repo, GitError> {
        let remote = remote.into();
        let dest = dest.as_ref();

        if dest.exists() {
            return Err(GitError::DestinationExists {
                path: dest.display().to_string(),
            });
        }

        let parent = dest
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|source| GitError::Io {
            operation: "clone".to_string(),
            source,
        })?;

        let temp = unique_temp(parent, dest);
        let temp_str = temp.to_str().ok_or_else(|| GitError::NonUtf8Path {
            path: temp.display().to_string(),
        })?;

        let outcome = run_git(
            parent,
            &remote,
            "clone",
            &["clone", "--origin", "origin", &remote, temp_str],
            token,
            on_line,
        )
        .and_then(|out| require(out, "clone"));

        match outcome {
            Ok(_) => {
                fs::rename(&temp, dest).map_err(|source| {
                    let _ = fs::remove_dir_all(&temp);
                    GitError::Io {
                        operation: "clone (finalize rename)".to_string(),
                        source,
                    }
                })?;
                Ok(Repo {
                    work: dest.to_path_buf(),
                    remote,
                })
            }
            Err(err) => {
                // Leave nothing behind on failure (R2.6).
                let _ = fs::remove_dir_all(&temp);
                Err(err)
            }
        }
    }

    /// Wraps an already-cloned working tree at `work` whose `origin` points at
    /// the clean URL `remote`. Does no I/O; use for adopt-local flows and to
    /// operate on a tree produced elsewhere.
    pub fn open(work: impl Into<PathBuf>, remote: impl Into<String>) -> Repo {
        Repo {
            work: work.into(),
            remote: remote.into(),
        }
    }

    /// The working-tree path.
    #[must_use]
    pub fn work_dir(&self) -> &Path {
        &self.work
    }

    /// The clean remote URL bound to `origin`.
    #[must_use]
    pub fn remote(&self) -> &str {
        &self.remote
    }

    /// Fetches from `origin`, pruning deleted remote branches. Streams progress.
    pub fn fetch(
        &self,
        token: Option<&SecretString>,
        on_line: impl FnMut(OutputStream, &str),
    ) -> Result<(), GitError> {
        require(
            self.git("fetch", &["fetch", "--prune", "origin"], token, on_line)?,
            "fetch",
        )?;
        Ok(())
    }

    /// Fast-forwards the current branch from its upstream. Streams progress.
    pub fn pull(
        &self,
        token: Option<&SecretString>,
        on_line: impl FnMut(OutputStream, &str),
    ) -> Result<(), GitError> {
        require(
            self.git("pull", &["pull", "--ff-only"], token, on_line)?,
            "pull",
        )?;
        Ok(())
    }

    /// Pushes `branch` to `origin`, setting it as the upstream. Pushing is always
    /// explicit (spec R3.4); nothing here is called implicitly on branch
    /// creation. Streams progress.
    pub fn push(
        &self,
        token: Option<&SecretString>,
        branch: &str,
        on_line: impl FnMut(OutputStream, &str),
    ) -> Result<(), GitError> {
        require(
            self.git(
                "push",
                &["push", "--set-upstream", "origin", branch],
                token,
                on_line,
            )?,
            "push",
        )?;
        Ok(())
    }

    /// Puts the working tree on `branch`, checkout-or-create (spec R2.2):
    ///
    /// * if `branch` exists on the remote, fetch and check it out as a tracking
    ///   branch;
    /// * otherwise create it locally from `base` (defaulting to the remote's
    ///   default branch) **without pushing** (spec R2.5). If the base is absent
    ///   on the remote, fails with [`GitError::BaseBranchNotFound`] (R2.6).
    pub fn checkout_or_create(
        &self,
        token: Option<&SecretString>,
        branch: &str,
        base: Option<&str>,
        mut on_line: impl FnMut(OutputStream, &str),
    ) -> Result<CheckoutOutcome, GitError> {
        if self.remote_has_branch(token, branch)? {
            let refspec = format!("+refs/heads/{branch}:refs/remotes/origin/{branch}");
            require(
                self.git(
                    "fetch",
                    &["fetch", "--no-tags", "origin", &refspec],
                    token,
                    &mut on_line,
                )?,
                "fetch",
            )?;
            let origin_ref = format!("origin/{branch}");
            require(
                self.git(
                    "checkout",
                    &["checkout", "-B", branch, "--track", &origin_ref],
                    None,
                    &mut on_line,
                )?,
                "checkout",
            )?;
            return Ok(CheckoutOutcome::Checkout);
        }

        let base = match base {
            Some(base) => base.to_string(),
            None => self.default_branch(token)?,
        };
        if !self.remote_has_branch(token, &base)? {
            return Err(GitError::BaseBranchNotFound { branch: base });
        }
        let refspec = format!("+refs/heads/{base}:refs/remotes/origin/{base}");
        require(
            self.git(
                "fetch",
                &["fetch", "--no-tags", "origin", &refspec],
                token,
                &mut on_line,
            )?,
            "fetch",
        )?;
        let origin_base = format!("origin/{base}");
        // `--no-track`: a created branch has no upstream until it is explicitly
        // pushed, which is exactly what feeds the PR-able signal.
        require(
            self.git(
                "checkout",
                &["checkout", "-b", branch, "--no-track", &origin_base],
                None,
                &mut on_line,
            )?,
            "checkout",
        )?;
        Ok(CheckoutOutcome::CreatedFromBase)
    }

    /// The name of the currently checked-out branch. Fails on a detached HEAD.
    pub fn current_branch(&self) -> Result<String, GitError> {
        let out = require(
            self.git_quiet("rev-parse", &["rev-parse", "--abbrev-ref", "HEAD"], None)?,
            "rev-parse",
        )?;
        let branch = out.stdout.trim();
        if branch.is_empty() || branch == "HEAD" {
            return Err(GitError::Unparsable {
                what: "current branch (detached HEAD?)".to_string(),
            });
        }
        Ok(branch.to_string())
    }

    /// The remote's default branch, via `ls-remote --symref origin HEAD`.
    /// Authenticated (private repos need the token to answer).
    pub fn default_branch(&self, token: Option<&SecretString>) -> Result<String, GitError> {
        let out = require(
            self.git_quiet(
                "ls-remote",
                &["ls-remote", "--symref", "origin", "HEAD"],
                token,
            )?,
            "ls-remote",
        )?;
        out.stdout
            .lines()
            .find_map(parse_symref)
            .ok_or_else(|| GitError::Unparsable {
                what: "remote default branch".to_string(),
            })
    }

    /// How the current branch relates to its upstream (spec R4.6). Returns
    /// [`Ahead::NoUpstream`] when the branch has never been pushed.
    pub fn ahead_of_upstream(&self) -> Result<Ahead, GitError> {
        let upstream = self.git_quiet(
            "rev-parse",
            &[
                "rev-parse",
                "--abbrev-ref",
                "--symbolic-full-name",
                "@{upstream}",
            ],
            None,
        )?;
        if !upstream.success {
            return Ok(Ahead::NoUpstream);
        }
        let out = require(
            self.git_quiet(
                "rev-list",
                &["rev-list", "--left-right", "--count", "@{upstream}...HEAD"],
                None,
            )?,
            "rev-list",
        )?;
        // Output is "<behind>\t<ahead>" (left = upstream side, right = HEAD).
        let mut counts = out.stdout.split_whitespace();
        let behind = counts.next().and_then(|n| n.parse().ok());
        let ahead = counts.next().and_then(|n| n.parse().ok());
        match (behind, ahead) {
            (Some(behind), Some(ahead)) => Ok(Ahead::Tracking { ahead, behind }),
            _ => Err(GitError::Unparsable {
                what: "ahead/behind commit counts".to_string(),
            }),
        }
    }

    /// Whether `origin` advertises a head named `branch`.
    fn remote_has_branch(
        &self,
        token: Option<&SecretString>,
        branch: &str,
    ) -> Result<bool, GitError> {
        let out = require(
            self.git_quiet(
                "ls-remote",
                &["ls-remote", "--heads", "origin", branch],
                token,
            )?,
            "ls-remote",
        )?;
        Ok(!out.stdout.trim().is_empty())
    }

    /// Runs a git command in the working tree, streaming output to `on_line`.
    fn git(
        &self,
        operation: &str,
        subargs: &[&str],
        token: Option<&SecretString>,
        on_line: impl FnMut(OutputStream, &str),
    ) -> Result<GitOutput, GitError> {
        run_git(&self.work, &self.remote, operation, subargs, token, on_line)
    }

    /// Runs a git command in the working tree, discarding streamed output (used
    /// for value-returning probes like `rev-parse`/`ls-remote`).
    fn git_quiet(
        &self,
        operation: &str,
        subargs: &[&str],
        token: Option<&SecretString>,
    ) -> Result<GitOutput, GitError> {
        self.git(operation, subargs, token, |_, _| {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::{REDACTED, SecretString};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    /// Runs `git` with a fixed identity, asserting success — for building
    /// fixtures and making commits in tests.
    fn git_run(args: &[&str], cwd: &Path) {
        let status = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env("GIT_AUTHOR_NAME", "tester")
            .env("GIT_AUTHOR_EMAIL", "tester@example.com")
            .env("GIT_COMMITTER_NAME", "tester")
            .env("GIT_COMMITTER_EMAIL", "tester@example.com")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawn git");
        assert!(status.success(), "git {args:?} failed in {cwd:?}");
    }

    /// Creates a bare `file://` remote under `root` with a single commit on
    /// `default_branch`; returns `(bare_path, file_url)`.
    fn make_bare_remote(root: &Path, default_branch: &str) -> (PathBuf, String) {
        let seed = root.join("seed");
        fs::create_dir_all(&seed).expect("seed dir");
        git_run(&["init", "-q", "-b", default_branch, "."], &seed);
        fs::write(seed.join("README.md"), b"seed\n").expect("write readme");
        git_run(&["add", "README.md"], &seed);
        git_run(&["commit", "-q", "-m", "initial"], &seed);

        let bare = root.join("remote.git");
        git_run(
            &[
                "clone",
                "-q",
                "--bare",
                seed.to_str().expect("utf-8"),
                bare.to_str().expect("utf-8"),
            ],
            root,
        );
        let url = format!("file://{}", bare.display());
        (bare, url)
    }

    /// Recursively asserts no file under `dir` (including `.git/config`) contains
    /// the token bytes.
    fn assert_no_token_on_disk(dir: &Path, token: &str) {
        fn contains(hay: &[u8], needle: &[u8]) -> bool {
            !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
        }
        let needle = token.as_bytes();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(path) = stack.pop() {
            let meta = fs::symlink_metadata(&path).expect("stat");
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                for entry in fs::read_dir(&path).expect("read_dir") {
                    stack.push(entry.expect("dir entry").path());
                }
            } else if meta.is_file() {
                let bytes = fs::read(&path).unwrap_or_default();
                assert!(
                    !contains(&bytes, needle),
                    "token bytes found on disk in {}",
                    path.display()
                );
            }
        }
    }

    #[test]
    fn scrub_masks_only_the_current_token() {
        assert_eq!(
            scrub("password=ghs_secret trailing", Some("ghs_secret")).as_ref(),
            "password=[REDACTED:gh] trailing"
        );
        assert_eq!(
            scrub("nothing to see", Some("ghs_secret")).as_ref(),
            "nothing to see"
        );
        assert_eq!(scrub("ghs_secret", None).as_ref(), "ghs_secret");
        assert_eq!(scrub("unchanged", Some("")).as_ref(), "unchanged");
    }

    #[test]
    fn build_git_keeps_the_token_out_of_argv_and_config() {
        let token = "ghs_super_secret_TOKEN_value_0xDEAD";
        let cmd = build_git(
            "https",
            &["clone", "https://github.com/octo/hello.git", "/dest"],
            Some(token),
        );

        // The argv is entirely non-secret.
        for arg in &cmd.args {
            assert!(!arg.contains(token), "token leaked into argv: {arg}");
        }

        // Exactly one env value carries the token, and it is the dedicated var.
        let secret_bearing: Vec<_> = cmd.envs.iter().filter(|(_, v)| v.contains(token)).collect();
        assert_eq!(
            secret_bearing.len(),
            1,
            "token appears in more than one place"
        );
        assert_eq!(secret_bearing[0].0, SECRET_ENV);
        assert_eq!(secret_bearing[0].1, token);

        // Reconstruct the injected config and assert its shape.
        let count: usize = cmd
            .envs
            .iter()
            .find_map(|(k, v)| (k == "GIT_CONFIG_COUNT").then(|| v.parse().expect("count")))
            .expect("GIT_CONFIG_COUNT present");
        let value_of = |name: &str| {
            cmd.envs
                .iter()
                .find_map(|(k, v)| (k == name).then(|| v.clone()))
        };
        let config: Vec<(String, String)> = (0..count)
            .map(|i| {
                (
                    value_of(&format!("GIT_CONFIG_KEY_{i}")).expect("key"),
                    value_of(&format!("GIT_CONFIG_VALUE_{i}")).expect("value"),
                )
            })
            .collect();

        // Protocol pinned to https; no config value carries the token.
        assert!(
            config
                .iter()
                .any(|(k, v)| k == "protocol.allow" && v == "never")
        );
        assert!(
            config
                .iter()
                .any(|(k, v)| k == "protocol.https.allow" && v == "always")
        );
        for (_, v) in &config {
            assert!(!v.contains(token), "token leaked into git config value");
        }

        // Two credential.helper entries: a reset (empty) then our helper, which
        // references the env var by NAME, not the token.
        let helpers: Vec<&String> = config
            .iter()
            .filter(|(k, _)| k == "credential.helper")
            .map(|(_, v)| v)
            .collect();
        assert_eq!(helpers.len(), 2, "expected reset + helper");
        assert!(
            helpers[0].is_empty(),
            "first helper entry must reset the list"
        );
        assert!(helpers[1].contains(SECRET_ENV));
        assert!(!helpers[1].contains(token));

        // The operator's global/system config is denied to the child, so the
        // credentialed leg reads only the repo-local config of the directory
        // it runs in (regression: this must hold by construction, not by the
        // host environment happening to be clean).
        for var in ["GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"] {
            assert_eq!(
                value_of(var).as_deref(),
                Some("/dev/null"),
                "{var} must be pinned to /dev/null"
            );
        }

        // Debug is redaction-safe.
        let dbg = format!("{cmd:?}");
        assert!(!dbg.contains(token), "token leaked in Debug: {dbg}");
        assert!(dbg.contains(REDACTED));
    }

    #[test]
    fn clone_then_checkout_or_create_over_file_url() {
        let tmp = tempfile::tempdir().expect("tmp");
        let (bare, url) = make_bare_remote(tmp.path(), "main");
        // An existing remote branch to check out.
        git_run(&["branch", "feat/exists", "main"], &bare);

        let dest = tmp.path().join("work");
        let repo = Repo::clone(url, &dest, None, |_, _| {}).expect("clone");
        assert_eq!(repo.current_branch().expect("branch"), "main");
        assert_eq!(repo.default_branch(None).expect("default"), "main");

        // Existing remote branch -> checkout.
        let outcome = repo
            .checkout_or_create(None, "feat/exists", None, |_, _| {})
            .expect("checkout existing");
        assert_eq!(outcome, CheckoutOutcome::Checkout);
        assert_eq!(repo.current_branch().unwrap(), "feat/exists");

        // Absent remote branch -> created from base, no upstream, PR-able.
        let outcome = repo
            .checkout_or_create(None, "feat/new", Some("main"), |_, _| {})
            .expect("create new");
        assert_eq!(outcome, CheckoutOutcome::CreatedFromBase);
        assert_eq!(repo.current_branch().unwrap(), "feat/new");
        assert_eq!(repo.ahead_of_upstream().unwrap(), Ahead::NoUpstream);
        assert!(repo.ahead_of_upstream().unwrap().is_pr_able());
    }

    #[test]
    fn absent_base_branch_is_a_clean_error() {
        let tmp = tempfile::tempdir().expect("tmp");
        let (_bare, url) = make_bare_remote(tmp.path(), "main");
        let dest = tmp.path().join("work");
        let repo = Repo::clone(url, &dest, None, |_, _| {}).expect("clone");

        let err = repo
            .checkout_or_create(None, "feat/x", Some("no-such-base"), |_, _| {})
            .expect_err("missing base must fail");
        assert!(
            matches!(err, GitError::BaseBranchNotFound { ref branch } if branch == "no-such-base"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn ahead_detection_counts_local_commits() {
        let tmp = tempfile::tempdir().expect("tmp");
        let (bare, url) = make_bare_remote(tmp.path(), "main");
        git_run(&["branch", "feat/x", "main"], &bare);

        let dest = tmp.path().join("work");
        let repo = Repo::clone(url, &dest, None, |_, _| {}).expect("clone");
        repo.checkout_or_create(None, "feat/x", None, |_, _| {})
            .expect("checkout");
        assert_eq!(
            repo.ahead_of_upstream().unwrap(),
            Ahead::Tracking {
                ahead: 0,
                behind: 0
            }
        );

        fs::write(dest.join("local.txt"), b"local\n").expect("write");
        git_run(&["add", "local.txt"], &dest);
        git_run(&["commit", "-q", "-m", "local work"], &dest);
        assert_eq!(
            repo.ahead_of_upstream().unwrap(),
            Ahead::Tracking {
                ahead: 1,
                behind: 0
            }
        );
        assert!(repo.ahead_of_upstream().unwrap().is_pr_able());
    }

    #[test]
    fn failed_clone_leaves_no_directory() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dest = tmp.path().join("work");
        let bogus = format!("file://{}/does-not-exist.git", tmp.path().display());

        let err = Repo::clone(bogus, &dest, None, |_, _| {}).expect_err("clone must fail");
        assert!(
            matches!(err, GitError::Failed { .. }),
            "unexpected: {err:?}"
        );
        assert!(!dest.exists(), "failed clone left a directory behind");
        // No leftover temp sibling either.
        let leftovers: Vec<String> = fs::read_dir(tmp.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            !leftovers.iter().any(|n| n.contains("gitops-")),
            "temp sibling not cleaned up: {leftovers:?}"
        );
    }

    #[test]
    fn scrubber_masks_a_token_echoed_by_a_scripted_command() {
        let tmp = tempfile::tempdir().expect("tmp");
        let work = tmp.path();
        git_run(&["init", "-q", "-b", "main", "."], work);

        let token = "ghs_echoed_secret_VALUE_zzz";
        // A scripted git alias echoes whatever the credential env var holds — the
        // injected token — proving the stream scrubber masks it before anyone
        // sees it.
        let alias = format!("alias.leak=!printf 'the token is %s end\\n' \"${{{SECRET_ENV}-}}\"");
        let secret = SecretString::new(token);

        let mut streamed = String::new();
        let out = run_git(
            work,
            "file:///unused",
            "leak",
            &["-c", &alias, "leak"],
            Some(&secret),
            |_, line| {
                streamed.push_str(line);
                streamed.push('\n');
            },
        )
        .expect("run scripted alias");

        assert!(out.success, "alias should run; stderr: {}", out.stderr);
        assert!(
            streamed.contains(REDACTED),
            "expected redaction marker in stream: {streamed}"
        );
        assert!(
            !streamed.contains(token),
            "token leaked to the stream callback: {streamed}"
        );
        assert!(
            !out.stdout.contains(token),
            "token leaked into captured stdout"
        );
        assert!(out.stdout.contains(REDACTED));
    }

    // Tests that exercise the auth-enforcing smart-HTTP mock. They prove the
    // env-only credential helper actually fires: the mock rejects any request
    // that does not present the exact injected token.
    #[cfg(feature = "test-support")]
    mod mock {
        use super::{assert_no_token_on_disk, git_run};
        use crate::gitops::{CheckoutOutcome, GitError, Repo};
        use crate::secret::SecretString;
        use crate::testing::{GitAuth, MockGithub};

        fn repo_url(mock: &MockGithub, owner: &str, repo: &str) -> String {
            // base_url() ends with '/'.
            format!("{}{owner}/{repo}.git", mock.base_url())
        }

        #[tokio::test]
        async fn clone_checkout_and_push_succeed_with_the_injected_token() {
            let mock = MockGithub::start().await.expect("start mock");
            mock.create_bare_repo("octo", "hello", "main")
                .expect("bare repo");
            let token = "ghs_injected_secret_0xABC123";
            // Only the exact injected credentials are accepted -> success proves
            // the helper fired and carried our token.
            mock.set_git_auth(GitAuth::Exact {
                username: "x-access-token".to_string(),
                password: token.to_string(),
            });

            let url = repo_url(&mock, "octo", "hello");
            let root = tempfile::tempdir().expect("tmp");
            let dest = root.path().join("hello");
            let git_root = mock.git_root().to_path_buf();

            let dest_for_work = dest.clone();
            // Run the blocking git work off the async runtime so the mock keeps
            // serving its own connections.
            let repo = tokio::task::spawn_blocking(move || -> Result<Repo, GitError> {
                let secret = SecretString::new(token);
                let repo = Repo::clone(url, &dest_for_work, Some(&secret), |_, _| {})?;
                let outcome =
                    repo.checkout_or_create(Some(&secret), "feat/x", Some("main"), |_, _| {})?;
                assert_eq!(outcome, CheckoutOutcome::CreatedFromBase);

                std::fs::write(dest_for_work.join("new.txt"), b"work\n").expect("write");
                git_run(&["add", "new.txt"], &dest_for_work);
                git_run(&["commit", "-q", "-m", "session work"], &dest_for_work);

                repo.push(Some(&secret), "feat/x", |_, _| {})?;
                Ok(repo)
            })
            .await
            .expect("join")
            .expect("git ops succeed with the helper");

            // The branch is now on the remote (push really landed).
            let bare = git_root.join("octo").join("hello.git");
            let show = std::process::Command::new("git")
                .args([
                    "--git-dir",
                    bare.to_str().expect("utf-8"),
                    "show-ref",
                    "refs/heads/feat/x",
                ])
                .output()
                .expect("show-ref");
            assert!(show.status.success(), "pushed branch missing on the remote");

            // Nothing on disk — including .git/config — holds token bytes.
            assert_no_token_on_disk(repo.work_dir(), token);
        }

        #[tokio::test]
        async fn wrong_token_is_rejected_and_leaves_no_directory() {
            let mock = MockGithub::start().await.expect("start mock");
            mock.create_bare_repo("octo", "hello", "main")
                .expect("bare repo");
            mock.set_git_auth(GitAuth::Exact {
                username: "x-access-token".to_string(),
                password: "the-correct-token".to_string(),
            });

            let url = repo_url(&mock, "octo", "hello");
            let root = tempfile::tempdir().expect("tmp");
            let dest = root.path().join("hello");

            let dest_for_clone = dest.clone();
            let result = tokio::task::spawn_blocking(move || {
                let wrong = SecretString::new("a-wrong-token");
                Repo::clone(url, &dest_for_clone, Some(&wrong), |_, _| {})
            })
            .await
            .expect("join");

            assert!(result.is_err(), "clone with a wrong token must fail");
            assert!(!dest.exists(), "failed clone must leave no directory");
        }

        #[tokio::test]
        async fn unauthenticated_clone_is_rejected() {
            let mock = MockGithub::start().await.expect("start mock");
            mock.create_bare_repo("octo", "hello", "main")
                .expect("bare repo");
            mock.set_git_auth(GitAuth::Exact {
                username: "x-access-token".to_string(),
                password: "the-correct-token".to_string(),
            });

            let url = repo_url(&mock, "octo", "hello");
            let root = tempfile::tempdir().expect("tmp");
            let dest = root.path().join("hello");

            let dest_for_clone = dest.clone();
            let result = tokio::task::spawn_blocking(move || {
                // No token at all -> no credential helper wired -> 401 at the gate.
                Repo::clone(url, &dest_for_clone, None, |_, _| {})
            })
            .await
            .expect("join");

            assert!(result.is_err(), "unauthenticated clone must fail");
            assert!(!dest.exists(), "failed clone must leave no directory");
        }
    }
}
