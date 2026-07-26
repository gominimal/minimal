//! The in-sandbox mediated-access facade (spec R3): the `git%` verb behind
//! `min git`, dispatched from the session channel in `crate::env`.
//!
//! The sandbox has no GitHub credential (spec G5/R6.1); instead the in-sandbox
//! `min` helper forwards `min git <args>` as a `git%<args>` request line over
//! the per-session UDS, and this module performs the real, authenticated git
//! operation on the daemon side, streaming scrubbed output back as `msg:`
//! lines. Access is bound to the sandbox lifetime by construction: the
//! dispatch lives on the channel actor that `crate::env::Env` aborts when the
//! sandbox is torn down, and every request re-reads the session record from the
//! live store (a destroyed session's record is gone), so nothing authorizes
//! after destroy (spec R3.5/R6.3).
//!
//! # The argv gate is a security boundary
//!
//! [`parse_git_argv`] is a **fail-closed allowlist**, not a git argv parser:
//! only the exact shapes below are accepted, and everything else — every
//! option, every extra argument, every unknown subcommand — is rejected.
//! The sandbox must never be able to steer a token-bearing `git` process:
//! `-c`/`--config-env` would let it inject arbitrary config (credential
//! helpers, `core.sshCommand`), `--upload-pack`/`--receive-pack` name a
//! program for git to execute, `--exec-path` redirects git's own helper
//! binaries, and `-C`/`--git-dir`/`--work-tree` or a path argument would move
//! the operation out of the session's declared workspace. None of those can
//! reach the daemon-side `git` because no token starting with `-` (other than
//! the literal `remote -v` form) and no free-form path is accepted at all.
//! Widening this grammar is a security change and needs review plus negative
//! tests.
//!
//! Accepted shapes (`[owner/repo]` selects among the session's declared
//! repos and is required only when more than one is declared):
//!
//! ```text
//! push   [owner/repo]      # push the current branch to the declared remote
//! pull   [owner/repo]      # fast-forward the current branch from the remote
//! fetch  [owner/repo]      # update remote-tracking refs from the remote
//! status [owner/repo]      # current branch + ahead/behind of upstream
//! remote [-v] [owner/repo] # show the declared origin URL
//! clone  owner/repo        # clone a declared repo into the workspace
//! ```
//!
//! # Authorization and token flow
//!
//! Every request resolves the **live** session record and passes
//! [`super::authz::authorize`] for the concrete permission the operation
//! needs (`contents:write` for push, `contents:read` otherwise) before any
//! token is fetched or any process runs. The token comes from the daemon's
//! single [`GrantManager`](github::GrantManager) and is handed straight to
//! `github::gitops`, which injects it env-only and scrubs it from all output;
//! it never appears in this module's errors, spans, or `msg:` lines.
//!
//! # Isolating the credentialed leg (the security core)
//!
//! The session workspace is sandbox-visible: in-sandbox code can rewrite a
//! primed repo's `.git/config` at will, and `git` honours a large, open-ended
//! set of config directives that redirect where a connection goes or splice
//! material into it — `[include]`/`[includeIf]` (which pull in arbitrary
//! attacker-authored config from any path), `credential.helper`,
//! `http.<url>.extraHeader`, `url.<base>.insteadOf`/`pushInsteadOf`, and
//! `remote.origin.url`/`pushurl`. Any one of these can point a token-bearing
//! `git` at an attacker host or splice the token into a header. There is **no**
//! way to make this safe by inspecting the config text first: an `[includeIf]`
//! alone (path resolved and read only at git runtime) defeats any parser, and
//! a check-then-use scan races the sandbox rewriting the file underneath it.
//!
//! So the token-bearing operation never runs in — and never reads the config
//! of — the sandbox working tree. Every push/pull/fetch is split into a
//! token-free **local** leg and a credentialed **network** leg run against a
//! **daemon-authored clean mirror** the sandbox cannot reach:
//!
//! * The mirror is a bare repo under the session's daemon-side state
//!   ([`mirror_root`] → `<workspace-parent>/.gh-mirror/<owner>__<repo>.git`), a
//!   sibling of the sandbox-mounted workspace/home/state dirs that is itself
//!   mounted nowhere into the sandbox. Its config is written only by the daemon
//!   ([`ensure_mirror`] sets `remote.origin.url` to the canonical URL derived
//!   daemon-side by [`remote_url`], never from sandbox input) — no `[include]`,
//!   no `insteadOf`, no on-disk credential helper.
//! * **Push:** the requested branch is transferred worktree → mirror over the
//!   local, network-incapable leg ([`run_local_git`]: protocol pinned to
//!   `file`, global/system config disabled, no token), then pushed mirror →
//!   canonical URL by [`github::gitops`], which injects the token env-only and,
//!   running in the mirror, reads only the daemon-authored mirror config.
//! * **Fetch/pull:** [`github::gitops`] fetches canonical → mirror with the
//!   token (again reading only the mirror config), then the worktree is
//!   updated from the mirror over the local, token-free leg.
//!
//! Net invariant: **no `git` process that holds the token ever reads a config
//! file the sandbox can write or reach via `include`.** The canonical URL is
//! always the daemon's own derivation; a rewritten worktree
//! `origin`/`pushurl`/`insteadOf`/`include` is simply never consulted on the
//! token leg, so it cannot redirect it or leak the token. `clone` is exempt
//! from the mirror dance: it targets a fresh, not-yet-existing directory, so
//! there is no pre-existing sandbox-controlled config for it to read.
//!
//! Every span here is `github.facade` with fields limited to `repo` and
//! `grant_id` (see the conventions in `super::state`).

use std::fs;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use github::attrs::GithubAttrs;
use github::gitops::Repo;
use github::{GrantId, RepoSpec, SecretString};
use paths::DaemonAbsPath;
use tracing::Instrument;
use url::Url;

use super::authz::{self, AuthzError, Permission};
use super::state::{DaemonGrantManager, GithubService};
use crate::store::SessionRecordHandle;

/// The exact deny message for a session that has no GitHub authentication
/// wired at all (no facade plumbed, or no grant bound). Shared with the
/// dispatch arm in `crate::env` so both paths answer identically.
pub(crate) const NO_GITHUB_AUTH: &str = "this session has no GitHub authentication";

/// One line summarizing the accepted grammar, appended to every allowlist
/// rejection so the error is actionable without widening what it accepts.
const SUPPORTED: &str = "supported: `min git push|pull|fetch|status [owner/repo]`, \
     `min git remote -v [owner/repo]`, `min git clone owner/repo`";

/// Name of the daemon-only directory (a sibling of the sandbox-mounted
/// workspace) that holds the clean per-repo mirrors. Hidden and prefixed so it
/// cannot collide with a repo directory named after a declared repo.
const MIRROR_DIR: &str = ".gh-mirror";

/// Errors surfaced to the in-sandbox client as a single `error:` line (or
/// `msg:` lines plus a terminator when multi-line). Every variant is
/// actionable and secret-free: repo names, scope names and grant ids only,
/// never token material (spec R8.1, R6.2).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum FacadeError {
    /// The request failed the fail-closed argv allowlist (see the module
    /// docs: this gate is a security boundary).
    #[error("{reason}; {SUPPORTED}")]
    NotPermitted {
        /// Why the argv was rejected (names the offending token or shape).
        reason: String,
    },

    /// The authorization choke point denied the operation (no grant bound,
    /// repo not declared, or missing scope — spec R5.4).
    #[error(transparent)]
    Denied(#[from] AuthzError),

    /// The live session record could not be read. A destroyed session's
    /// record is deleted, so this is also how facade access ends at destroy
    /// (spec R3.5/R6.3).
    #[error("session record unavailable: {source}")]
    SessionUnavailable {
        /// The store-read failure.
        #[source]
        source: std::io::Error,
    },

    /// Obtaining a live access token for the bound grant failed.
    #[error(transparent)]
    Auth(#[from] github::RefreshError),

    /// A GitHub-domain failure (e.g. the daemon has no GitHub App configured).
    #[error(transparent)]
    Github(#[from] github::Error),

    /// The daemon-side credentialed git operation failed. `gitops` errors
    /// embed only token-scrubbed output.
    #[error(transparent)]
    Git(#[from] github::gitops::GitError),

    /// A daemon-side, token-free **local** git step (mirror setup, the local
    /// ref transfer, or a worktree update) failed. These legs never hold a
    /// token and never contact the network; the detail is a short, non-secret
    /// summary.
    #[error("local git step `{operation}` failed: {detail}")]
    LocalGit {
        /// The logical local step that failed.
        operation: String,
        /// A short, non-secret description of the failure.
        detail: String,
    },

    /// The selected repo has no primed working tree in this session's
    /// workspace.
    #[error(
        "repo {owner}/{name} is not primed in this session's workspace; \
         run `min git clone {owner}/{name}` first"
    )]
    NotPrimed {
        /// The repository owner.
        owner: String,
        /// The repository name.
        name: String,
    },

    /// The session declares several repos, so the operation must name one.
    #[error(
        "multiple repos are declared for this session; name one explicitly, \
         e.g. `min git {subcommand} owner/repo`"
    )]
    AmbiguousRepo {
        /// The subcommand the user ran, echoed into the suggested fix.
        subcommand: String,
    },

    /// A grant is bound but the session declares no repos to operate on.
    #[error("no repos are declared for this session")]
    NoDeclaredRepos,

    /// The working tree's current branch name begins with `-`, so handing it
    /// to `git push` risks having it parsed as an option rather than a branch
    /// (argv injection). Refuse rather than run a token-bearing push on it
    /// (defense-in-depth; the branch name is not secret).
    #[error(
        "current branch `{branch}` has an unsafe name (leading `-`); \
         rename it before pushing"
    )]
    UnsafeBranchName {
        /// The offending branch name.
        branch: String,
    },

    /// The daemon could not derive a mirror location outside the
    /// sandbox-visible workspace (the workspace has no parent directory). Fail
    /// closed rather than risk running the token leg near sandbox-writable
    /// config.
    #[error("could not derive a daemon-private mirror location for the session workspace")]
    NoMirrorRoot,

    /// Streaming plumbing failed (connection clone / blocking-task join).
    #[error("internal error while streaming git output: {source}")]
    Stream {
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
}

/// A request that passed the [`parse_git_argv`] allowlist. `repo` is the
/// optional `owner/repo` selector naming which declared repo to operate on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GitVerbCmd {
    /// `push [owner/repo]` — push the current branch to the declared remote.
    Push {
        /// Which declared repo to push, when more than one is declared.
        repo: Option<RepoSpec>,
    },
    /// `pull [owner/repo]` — fast-forward the current branch.
    Pull {
        /// Which declared repo to pull.
        repo: Option<RepoSpec>,
    },
    /// `fetch [owner/repo]` — update remote-tracking refs from the remote.
    Fetch {
        /// Which declared repo to fetch.
        repo: Option<RepoSpec>,
    },
    /// `status [owner/repo]` — current branch and ahead/behind of upstream.
    Status {
        /// Which declared repo to inspect.
        repo: Option<RepoSpec>,
    },
    /// `remote [-v] [owner/repo]` — show the declared origin URL.
    RemoteShow {
        /// Which declared repo to show.
        repo: Option<RepoSpec>,
    },
    /// `clone owner/repo` — clone a declared repo into the workspace.
    Clone {
        /// The declared repo to clone (mandatory).
        repo: RepoSpec,
    },
}

impl GitVerbCmd {
    /// The repo selector, if the request named one.
    fn selector(&self) -> Option<&RepoSpec> {
        match self {
            Self::Push { repo }
            | Self::Pull { repo }
            | Self::Fetch { repo }
            | Self::Status { repo }
            | Self::RemoteShow { repo } => repo.as_ref(),
            Self::Clone { repo } => Some(repo),
        }
    }

    /// The subcommand keyword, for error messages.
    fn subcommand(&self) -> &'static str {
        match self {
            Self::Push { .. } => "push",
            Self::Pull { .. } => "pull",
            Self::Fetch { .. } => "fetch",
            Self::Status { .. } => "status",
            Self::RemoteShow { .. } => "remote",
            Self::Clone { .. } => "clone",
        }
    }

    /// The permission this operation must be authorized for (spec R5.4):
    /// `contents:write` to push, `contents:read` for everything else.
    fn permission(&self) -> Permission {
        match self {
            Self::Push { .. } => Permission::push(),
            _ => Permission::read_contents(),
        }
    }

    /// Whether the operation contacts the remote and therefore needs a live
    /// access token. `status` and `remote` are local-only.
    fn needs_token(&self) -> bool {
        matches!(
            self,
            Self::Push { .. } | Self::Pull { .. } | Self::Fetch { .. } | Self::Clone { .. }
        )
    }
}

/// Builds a [`FacadeError::NotPermitted`] with the given reason.
fn not_permitted(reason: impl Into<String>) -> FacadeError {
    FacadeError::NotPermitted {
        reason: reason.into(),
    }
}

/// Parses one `owner/repo` selector token. Branch selectors and anything
/// option- or path-shaped are rejected: the selector's only job is to pick
/// one of the session's declared repos; branches come from the declaration.
fn parse_selector(token: &str) -> Result<RepoSpec, FacadeError> {
    if token.starts_with('-') {
        return Err(not_permitted(format!(
            "git option `{token}` is not permitted through `min git`"
        )));
    }
    if token.contains('@') || token.contains(':') {
        return Err(not_permitted(format!(
            "`{token}`: branch selectors are not accepted here; the branch \
             comes from the session's repo declaration"
        )));
    }
    token
        .parse::<RepoSpec>()
        .map_err(|e| not_permitted(format!("`{token}` is not an `owner/repo` name ({e})")))
}

/// Parses the optional trailing `[owner/repo]` selector: nothing, or exactly
/// one selector token. Options and extra arguments are rejected.
fn optional_selector(rest: &[&str]) -> Result<Option<RepoSpec>, FacadeError> {
    match rest {
        [] => Ok(None),
        [one] => Ok(Some(parse_selector(one)?)),
        [first, ..] if first.starts_with('-') => Err(not_permitted(format!(
            "git option `{first}` is not permitted through `min git`"
        ))),
        _ => Err(not_permitted("too many arguments")),
    }
}

/// The fail-closed argv allowlist (see the module docs — this is a security
/// boundary, not a convenience parser). Only the exact accepted shapes parse;
/// every option (`-c`, `-C`, `--upload-pack`, `--exec-path`, `--git-dir`,
/// `--work-tree`, `--config-env`, `--`, …), every path argument, and every
/// unknown subcommand is rejected with an actionable error.
pub(crate) fn parse_git_argv(argv: &str) -> Result<GitVerbCmd, FacadeError> {
    let tokens: Vec<&str> = argv.split_whitespace().collect();
    let Some((&sub, rest)) = tokens.split_first() else {
        return Err(not_permitted("missing git subcommand"));
    };
    if sub.starts_with('-') {
        // Blocks every pre-subcommand option: `-c`, `-C`, `--exec-path`,
        // `--git-dir`, `--work-tree`, `--config-env`, `--namespace`, ….
        return Err(not_permitted(format!(
            "git option `{sub}` is not permitted through `min git`"
        )));
    }
    match sub {
        "push" => Ok(GitVerbCmd::Push {
            repo: optional_selector(rest)?,
        }),
        "pull" => Ok(GitVerbCmd::Pull {
            repo: optional_selector(rest)?,
        }),
        "fetch" => Ok(GitVerbCmd::Fetch {
            repo: optional_selector(rest)?,
        }),
        "status" => Ok(GitVerbCmd::Status {
            repo: optional_selector(rest)?,
        }),
        "remote" => {
            // `-v` is the single permitted flag anywhere in the grammar, and
            // only in this position; it changes nothing (the output is
            // already verbose).
            let rest = match rest.split_first() {
                Some((&"-v", others)) => others,
                _ => rest,
            };
            Ok(GitVerbCmd::RemoteShow {
                repo: optional_selector(rest)?,
            })
        }
        "clone" => match rest {
            [one] => Ok(GitVerbCmd::Clone {
                repo: parse_selector(one)?,
            }),
            [] => Err(not_permitted(
                "clone needs a declared repo, e.g. `min git clone owner/repo`",
            )),
            [first, ..] if first.starts_with('-') => Err(not_permitted(format!(
                "git option `{first}` is not permitted through `min git`"
            ))),
            _ => Err(not_permitted("too many arguments")),
        },
        other => Err(not_permitted(format!(
            "git subcommand `{other}` is not available through `min git`"
        ))),
    }
}

/// Derives the clean (credential-free) canonical remote URL for a declared
/// repo from the daemon's configured git base: `<git_base>/<owner>/<repo>.git`.
///
/// This is the single source of truth for where the credentialed leg connects
/// (spec R5.4): it comes from the session's declared repo, daemon-side, and is
/// supplied explicitly to `git` — the sandbox's own `origin` is never used.
fn remote_url(git_base: &Url, repo: &RepoSpec) -> Result<Url, FacadeError> {
    // `Url::join` resolves relative to the last `/`; guarantee the base is
    // treated as a directory so a slash-less override can't eat a path
    // segment.
    let mut base = git_base.clone();
    if !base.path().ends_with('/') {
        base.set_path(&format!("{}/", base.path()));
    }
    base.join(&format!("{}/{}.git", repo.owner(), repo.repo()))
        .map_err(|e| {
            FacadeError::Github(github::Error::InvalidConfig {
                var: "MINIMALD_GITHUB_GIT_BASE_URL".to_string(),
                reason: e.to_string(),
            })
        })
}

/// Where an operation's token may come from. Production always goes through
/// the daemon's one shared [`DaemonGrantManager`]; channel-level tests use a
/// fixed token so they can exercise the full dispatch against fixture remotes
/// without a seeded grant store (the refresh machinery has its own exhaustive
/// tests in the `github` crate).
#[derive(Debug, Clone)]
enum TokenSource {
    /// The shared daemon grant manager (the only production variant).
    Grants(DaemonGrantManager),
    /// A fixed token, compiled only into this crate's unit tests.
    #[cfg(test)]
    Fixed(SecretString),
}

/// The per-session GitHub facade state carried by the session channel actor:
/// the daemon-held pieces needed to authorize and run `git%` requests. Dies
/// with the channel actor, which dies with the sandbox (spec R3.5).
#[derive(Debug, Clone)]
pub(crate) struct SessionGithub {
    tokens: TokenSource,
    /// Whether a GitHub App client id is configured; token-requiring
    /// operations fail closed with [`github::Error::NotConfigured`] when not
    /// (the mandatory pre-I/O check from `super::state`'s module docs).
    configured: bool,
    git_base: Url,
    /// Live handle to this session's record: re-read per request so attrs
    /// updates are seen and a destroyed session (deleted record) authorizes
    /// nothing.
    record: SessionRecordHandle,
}

impl SessionGithub {
    /// Builds the facade state for one session from the daemon's shared
    /// [`GithubService`] and the session's record handle.
    // Not yet reached from the production launcher: the `EnvArgs::with_github`
    // wiring through `session_host` lands with the activation tasks of this
    // spec's DAG. The channel-level tests in `crate::env` are the usage proof
    // in the meantime (mirrors the `super::authz` precedent).
    #[allow(dead_code)]
    pub(crate) fn new(service: &GithubService, record: SessionRecordHandle) -> Self {
        Self {
            tokens: TokenSource::Grants(service.grants().clone()),
            configured: service.config().is_configured(),
            git_base: service.config().git_base().clone(),
            record,
        }
    }

    /// Test constructor: a fixed token and an explicit git base, so channel
    /// tests can drive the full dispatch against `file://` fixture remotes.
    #[cfg(test)]
    pub(crate) fn for_tests(
        token: impl Into<String>,
        git_base: Url,
        record: SessionRecordHandle,
    ) -> Self {
        Self {
            tokens: TokenSource::Fixed(SecretString::new(token)),
            configured: true,
            git_base,
            record,
        }
    }

    /// A clone of the live record handle, so channel tests can mutate or
    /// delete the record out from under the facade.
    #[cfg(test)]
    pub(crate) fn record_handle_for_tests(&self) -> SessionRecordHandle {
        self.record.clone()
    }

    /// Handles one `git%<argv>` request line: parse → authorize → run,
    /// streaming scrubbed output as `msg:` lines and terminating with an
    /// `error:` line on failure.
    pub(crate) async fn handle_git(
        &self,
        argv: &str,
        working: &DaemonAbsPath,
        stream: &mut UnixStream,
    ) {
        if let Err(err) = self.run_git(argv, working, stream).await {
            write_facade_error(&err, stream);
        }
    }

    /// The fallible body of [`SessionGithub::handle_git`].
    async fn run_git(
        &self,
        argv: &str,
        working: &DaemonAbsPath,
        stream: &mut UnixStream,
    ) -> Result<(), FacadeError> {
        // 1. The allowlist gate — before anything else runs or is read.
        let cmd = parse_git_argv(argv)?;

        // 2. A fresh, live read of the session record: a destroyed session's
        //    record is deleted, so this is where post-destroy access dies.
        let record = self
            .record
            .record()
            .await
            .map_err(|source| FacadeError::SessionUnavailable { source })?;

        // 3. Resolve the target repo among the declared set and authorize the
        //    concrete permission through the single choke point (spec R5.4).
        let attrs = authz::read_github_attrs(&record)?;
        if attrs.grant_id.is_none() {
            return Err(AuthzError::NoGrantBound.into());
        }
        let repo = resolve_repo(&attrs, &cmd)?;
        let grant_id = authz::authorize(&record, &repo, cmd.permission())?;

        let span = tracing::info_span!("github.facade", repo = %repo, grant_id = %grant_id);
        async {
            // 4. Only now touch a token, and only for remote-contacting ops.
            let token = if cmd.needs_token() {
                Some(self.token(&grant_id).await?)
            } else {
                None
            };

            // 5. Run the git work on the blocking pool, streaming `msg:`
            //    lines straight onto a clone of the connection. The actor
            //    awaits the join handle, so output cannot interleave with
            //    other requests.
            let remote = remote_url(&self.git_base, &repo)?;
            let out = stream
                .try_clone()
                .map_err(|source| FacadeError::Stream { source })?;
            let working = working.clone();
            let declared_repos = attrs.repos.len();
            tokio::task::spawn_blocking(move || {
                execute(
                    &cmd,
                    &repo,
                    &remote,
                    token.as_ref(),
                    &working,
                    declared_repos,
                    out,
                )
            })
            .await
            .map_err(|e| FacadeError::Stream {
                source: std::io::Error::other(e),
            })?
        }
        .instrument(span)
        .await
    }

    /// Obtains a live access token for the bound grant, refreshing through
    /// the shared manager as needed. Fails closed with
    /// [`github::Error::NotConfigured`] when the daemon has no GitHub App
    /// configured (see `super::state`'s module docs).
    async fn token(&self, grant_id: &GrantId) -> Result<SecretString, FacadeError> {
        if !self.configured {
            return Err(github::Error::NotConfigured.into());
        }
        match &self.tokens {
            TokenSource::Grants(grants) => Ok(grants.token_for(grant_id).await?),
            #[cfg(test)]
            TokenSource::Fixed(token) => Ok(token.clone()),
        }
    }
}

/// Writes a facade failure to the client. Single-line errors go out as one
/// `error:` line; multi-line ones (scrubbed git stderr) go out as `msg:`
/// lines with an `error:` terminator, mirroring the channel's existing
/// multi-line error convention.
fn write_facade_error(err: &FacadeError, stream: &mut UnixStream) {
    let text = err.to_string();
    if text.contains('\n') {
        for line in text.lines() {
            let _ = writeln!(stream, "msg:{line}");
        }
        let _ = writeln!(stream, "error: git operation failed");
    } else {
        let _ = writeln!(stream, "error: {text}");
    }
}

/// Resolves which declared repo the request targets. An explicit selector
/// picks the matching declaration (falling through to the selector itself
/// when undeclared, so [`authz::authorize`] produces its canonical
/// `RepoNotDeclared` denial); with no selector the session must declare
/// exactly one repo.
fn resolve_repo(attrs: &GithubAttrs, cmd: &GitVerbCmd) -> Result<RepoSpec, FacadeError> {
    match cmd.selector() {
        Some(sel) => Ok(attrs
            .repos
            .iter()
            .find(|declared| declared.owner() == sel.owner() && declared.repo() == sel.repo())
            .unwrap_or(sel)
            .clone()),
        None => match attrs.repos.as_slice() {
            [] => Err(FacadeError::NoDeclaredRepos),
            [one] => Ok(one.clone()),
            _ => Err(FacadeError::AmbiguousRepo {
                subcommand: cmd.subcommand().to_string(),
            }),
        },
    }
}

/// Locates the primed working tree for `repo`: `<working>/<repo-name>`
/// (multi-repo layout), or the workspace root itself when it is the single
/// declared repo (single-repo prime / adopt-local layout). The path is always
/// derived daemon-side from the validated repo name — never from sandbox
/// input — and a validated repo name is a single, non-`..` path component, so
/// it cannot escape the workspace.
fn primed_dir(
    working: &DaemonAbsPath,
    declared_repos: usize,
    repo: &RepoSpec,
) -> Result<PathBuf, FacadeError> {
    let root = working.as_utf8_path().as_std_path();
    let sub = root.join(repo.repo());
    if sub.join(".git").exists() {
        return Ok(sub);
    }
    if declared_repos == 1 && root.join(".git").exists() {
        return Ok(root.to_path_buf());
    }
    Err(FacadeError::NotPrimed {
        owner: repo.owner().to_string(),
        name: repo.repo().to_string(),
    })
}

/// The daemon-private directory that holds this session's clean mirrors: a
/// sibling of the sandbox-mounted workspace (`<workspace-parent>/.gh-mirror`).
///
/// In production `working` is `<session-dir>/tree`, so the parent is the
/// session's own daemon-side state directory — unique per session, mounted
/// nowhere into the sandbox, and removed when the session is destroyed. Fails
/// closed with [`FacadeError::NoMirrorRoot`] if the workspace somehow has no
/// parent, rather than fall back to any sandbox-reachable location.
fn mirror_root(working: &DaemonAbsPath) -> Result<PathBuf, FacadeError> {
    working
        .as_utf8_path()
        .as_std_path()
        .parent()
        .map(|parent| parent.join(MIRROR_DIR))
        .ok_or(FacadeError::NoMirrorRoot)
}

/// Renders a path as `&str` for a git argument, failing closed on non-UTF-8
/// (all daemon-side session paths are UTF-8 `DaemonAbsPath`s in practice).
fn path_arg(path: &Path) -> Result<&str, FacadeError> {
    path.to_str().ok_or_else(|| FacadeError::LocalGit {
        operation: "resolve path".to_string(),
        detail: format!("path is not valid UTF-8: {}", path.display()),
    })
}

/// Runs one **token-free, local-only** git step and streams its output as
/// `msg:` lines. This is the isolation-critical counterpart to
/// `github::gitops` (which holds the token): it carries no credential and
/// cannot reach the network — transport is pinned to `file`, and the
/// operator's global/system git config is disabled — so even when it must read
/// a sandbox-writable working-tree config (the worktree-update legs) there is
/// nothing for a hostile config to exfiltrate and nowhere off-host for it to
/// redirect to. Hooks are disabled and optional locks skipped, mirroring
/// `gitops`'s non-secret hardening.
fn run_local_git(
    cwd: &Path,
    operation: &str,
    subargs: &[&str],
    out: &mut UnixStream,
) -> Result<(), FacadeError> {
    let output = Command::new("git")
        .arg("--no-optional-locks")
        // Pin transport to local files only and disable hooks. `-c` config is
        // propagated to any subprocess (e.g. the source repo's `upload-pack`)
        // via `GIT_CONFIG_PARAMETERS`.
        .args([
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.file.allow=always",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .args(subargs)
        .current_dir(cwd)
        // No token here, ever. Disable the operator's global/system config so
        // an inherited credential helper or `insteadOf` cannot fire, and never
        // block on a credential prompt.
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .output()
        .map_err(|source| FacadeError::LocalGit {
            operation: operation.to_string(),
            detail: format!("could not run git: {source}"),
        })?;

    for line in String::from_utf8_lossy(&output.stderr).lines() {
        let _ = writeln!(out, "msg:{line}");
    }
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = {
        let trimmed = stderr.trim();
        if trimmed.is_empty() {
            match output.status.code() {
                Some(code) => format!("git exited with status {code}"),
                None => "git terminated by signal".to_string(),
            }
        } else {
            // The last stderr line is the most useful and carries no token
            // (these legs never hold one).
            trimmed.lines().next_back().unwrap_or(trimmed).to_string()
        }
    };
    Err(FacadeError::LocalGit {
        operation: operation.to_string(),
        detail,
    })
}

/// Ensures a clean, daemon-authored bare mirror exists for `repo` under
/// `root`, and returns its path. The mirror's `origin` is (re-)pointed at the
/// `canonical` URL on every call so the config the token leg later reads is
/// always the daemon's, never anything a prior sandbox action could have
/// influenced. Created bare and empty; objects arrive only via explicit,
/// daemon-issued transfers.
fn ensure_mirror(
    root: &Path,
    repo: &RepoSpec,
    canonical: &Url,
    out: &mut UnixStream,
) -> Result<PathBuf, FacadeError> {
    fs::create_dir_all(root).map_err(|source| FacadeError::LocalGit {
        operation: "create mirror root".to_string(),
        detail: format!("{source}"),
    })?;
    // `owner`/`repo` are validated single path components (no `/`, no `..`),
    // so this name cannot escape `root`.
    let dir = root.join(format!("{}__{}.git", repo.owner(), repo.repo()));

    if !dir.join("HEAD").exists() {
        let dir_arg = path_arg(&dir)?;
        run_local_git(
            root,
            "init mirror",
            &["init", "--bare", "--quiet", dir_arg],
            out,
        )?;
    }
    // `config` (not `remote add`/`set-url`) is idempotent and daemon-authored:
    // it sets the value whether or not it already existed, so a partially
    // initialised mirror still converges to the canonical origin.
    run_local_git(
        &dir,
        "configure mirror origin",
        &["config", "remote.origin.url", canonical.as_str()],
        out,
    )?;
    run_local_git(
        &dir,
        "configure mirror fetch",
        &[
            "config",
            "remote.origin.fetch",
            "+refs/heads/*:refs/heads/*",
        ],
        out,
    )?;
    Ok(dir)
}

/// Runs the authorized operation (on the blocking pool), writing scrubbed
/// output as `msg:` lines directly onto the connection clone. The credentialed
/// legs go through `github::gitops` against the daemon-owned clean mirror; the
/// token never touches the sandbox working tree's config (see the module docs).
fn execute(
    cmd: &GitVerbCmd,
    repo: &RepoSpec,
    remote: &Url,
    token: Option<&SecretString>,
    working: &DaemonAbsPath,
    declared_repos: usize,
    mut out: UnixStream,
) -> Result<(), FacadeError> {
    let owner_repo = format!("{}/{}", repo.owner(), repo.repo());
    match cmd {
        GitVerbCmd::Push { .. } => {
            let work = primed_dir(working, declared_repos, repo)?;
            let branch = Repo::open(&work, remote.as_str()).current_branch()?;
            // A leading-dash branch name would be parsed as a git option once
            // it reaches `git push … <branch>`; refuse before any token-bearing
            // process runs.
            if branch.starts_with('-') {
                return Err(FacadeError::UnsafeBranchName { branch });
            }

            let mirror = ensure_mirror(&mirror_root(working)?, repo, remote, &mut out)?;
            let work_arg = path_arg(&work)?;
            let refspec = format!("+refs/heads/{branch}:refs/heads/{branch}");
            // Local, token-free leg: copy the branch worktree → mirror. Runs in
            // the mirror (clean config); the worktree is only a fetch *source*.
            run_local_git(
                &mirror,
                "stage push",
                &["fetch", "--no-tags", work_arg, refspec.as_str()],
                &mut out,
            )?;

            // Credentialed leg: push mirror → canonical. `gitops` runs in the
            // mirror and reads only the daemon-authored mirror config.
            Repo::open(mirror.clone(), remote.as_str()).push(token, &branch, |_, line| {
                let _ = writeln!(out, "msg:{line}");
            })?;

            // Best-effort: reflect the push in the worktree's remote-tracking
            // so the sandbox's own `git status` is sane. Purely local and
            // token-free; failure here does not undo the successful push.
            if let Ok(mirror_arg) = path_arg(&mirror) {
                let track = format!("+refs/heads/{branch}:refs/remotes/origin/{branch}");
                let _ = run_local_git(
                    &work,
                    "update tracking",
                    &["fetch", mirror_arg, track.as_str()],
                    &mut out,
                );
                let upstream = format!("origin/{branch}");
                let _ = run_local_git(
                    &work,
                    "set upstream",
                    &[
                        "branch",
                        "--set-upstream-to",
                        upstream.as_str(),
                        branch.as_str(),
                    ],
                    &mut out,
                );
            }
            let _ = writeln!(out, "msg:pushed `{branch}` to origin ({owner_repo})");
        }
        GitVerbCmd::Fetch { .. } => {
            let work = primed_dir(working, declared_repos, repo)?;
            let mirror = ensure_mirror(&mirror_root(working)?, repo, remote, &mut out)?;
            // Credentialed leg: canonical → mirror (mirror config only).
            Repo::open(mirror.clone(), remote.as_str()).fetch(token, |_, line| {
                let _ = writeln!(out, "msg:{line}");
            })?;
            // Local, token-free leg: mirror → worktree remote-tracking refs.
            let mirror_arg = path_arg(&mirror)?;
            run_local_git(
                &work,
                "fetch",
                &[
                    "fetch",
                    "--prune",
                    mirror_arg,
                    "+refs/heads/*:refs/remotes/origin/*",
                ],
                &mut out,
            )?;
            let _ = writeln!(out, "msg:fetched origin ({owner_repo})");
        }
        GitVerbCmd::Pull { .. } => {
            let work = primed_dir(working, declared_repos, repo)?;
            let branch = Repo::open(&work, remote.as_str()).current_branch()?;
            let mirror = ensure_mirror(&mirror_root(working)?, repo, remote, &mut out)?;
            // Credentialed leg: canonical → mirror (mirror config only).
            Repo::open(mirror.clone(), remote.as_str()).fetch(token, |_, line| {
                let _ = writeln!(out, "msg:{line}");
            })?;
            // Local, token-free legs: update the worktree's tracking ref from
            // the mirror, then fast-forward the current branch onto it.
            let mirror_arg = path_arg(&mirror)?;
            let track = format!("+refs/heads/{branch}:refs/remotes/origin/{branch}");
            run_local_git(
                &work,
                "pull (fetch)",
                &["fetch", mirror_arg, track.as_str()],
                &mut out,
            )?;
            let upstream = format!("refs/remotes/origin/{branch}");
            run_local_git(
                &work,
                "pull (fast-forward)",
                &["merge", "--ff-only", upstream.as_str()],
                &mut out,
            )?;
            let _ = writeln!(
                out,
                "msg:pulled origin into the current branch ({owner_repo})"
            );
        }
        GitVerbCmd::Status { .. } => {
            // Local-only probes: no token, no remote contact.
            let dir = primed_dir(working, declared_repos, repo)?;
            let tree = Repo::open(dir, remote.as_str());
            let branch = tree.current_branch()?;
            let _ = writeln!(out, "msg:{owner_repo}: on branch `{branch}`");
            match tree.ahead_of_upstream()? {
                github::gitops::Ahead::NoUpstream => {
                    let _ = writeln!(
                        out,
                        "msg:no upstream: the branch has never been pushed \
                         (`min git push` publishes it)"
                    );
                }
                github::gitops::Ahead::Tracking { ahead, behind } => {
                    let _ = writeln!(
                        out,
                        "msg:ahead of origin/{branch} by {ahead} commit(s), behind by {behind}"
                    );
                }
                // `Ahead` is non-exhaustive; report rather than guess.
                _ => {
                    let _ = writeln!(out, "msg:upstream relationship not recognized");
                }
            }
        }
        GitVerbCmd::RemoteShow { .. } => {
            // Reported from the daemon's own derivation — the session's one
            // legitimate origin — rather than by running git in a
            // sandbox-writable tree.
            let _ = writeln!(out, "msg:origin\t{remote} (fetch)");
            let _ = writeln!(out, "msg:origin\t{remote} (push)");
        }
        GitVerbCmd::Clone { .. } => {
            // Always into `<working>/<repo-name>`; the root-prime layout is
            // the activation flow's business, not the facade's. Clone targets a
            // fresh directory, so there is no pre-existing sandbox-controlled
            // config to read — no mirror indirection is needed.
            let dest = working.as_utf8_path().as_std_path().join(repo.repo());
            let tree = Repo::clone(remote.as_str(), &dest, token, |_, line| {
                let _ = writeln!(out, "msg:{line}");
            })?;
            let _ = writeln!(out, "msg:cloned {owner_repo} into `{}`", repo.repo());
            if let Some(branch) = repo.branch() {
                let outcome = tree.checkout_or_create(token, branch, repo.base(), |_, line| {
                    let _ = writeln!(out, "msg:{line}");
                })?;
                let what = match outcome {
                    github::gitops::CheckoutOutcome::Checkout => "checked out",
                    github::gitops::CheckoutOutcome::CreatedFromBase => "created",
                    // `CheckoutOutcome` is non-exhaustive.
                    _ => "prepared",
                };
                let _ = writeln!(out, "msg:{what} branch `{branch}`");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Asserts that `argv` is rejected by the allowlist and that the denial
    /// mentions `expect_in_reason`.
    fn assert_rejected(argv: &str, expect_in_reason: &str) {
        let err = parse_git_argv(argv)
            .expect_err(&format!("argv must be rejected fail-closed: {argv:?}"));
        assert!(
            matches!(err, FacadeError::NotPermitted { .. }),
            "expected NotPermitted for {argv:?}, got {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains(expect_in_reason),
            "denial for {argv:?} should mention {expect_in_reason:?}: {msg}"
        );
    }

    // ---- the security-boundary negatives (see the module docs) ----

    #[test]
    fn rejects_config_injection_options() {
        assert_rejected("-c core.hooksPath=/tmp/x push", "-c");
        assert_rejected("--config-env=core.askpass=X push", "--config-env");
        assert_rejected("push --config-env=core.askpass=X", "--config-env");
    }

    #[test]
    fn rejects_program_steering_options() {
        assert_rejected("--upload-pack=/tmp/evil fetch", "--upload-pack");
        assert_rejected("fetch --upload-pack=/tmp/evil", "--upload-pack");
        assert_rejected("push --receive-pack=/tmp/evil", "--receive-pack");
        assert_rejected("--exec-path=/tmp/evil push", "--exec-path");
    }

    #[test]
    fn rejects_repository_relocation_options() {
        assert_rejected("-C /tmp push", "-C");
        assert_rejected("--git-dir=/tmp/other/.git push", "--git-dir");
        assert_rejected("--work-tree=/ push", "--work-tree");
    }

    #[test]
    fn rejects_double_dash_and_everything_after_it() {
        assert_rejected("push -- main", "--");
        assert_rejected("-- push", "--");
    }

    #[test]
    fn rejects_path_escapes_as_clone_targets() {
        assert_rejected("clone ../outside", "owner/repo");
        assert_rejected("clone /etc/passwd", "owner/repo");
        assert_rejected("clone ../../root/x", "owner/repo");
        assert_rejected("clone owner/repo/extra", "owner/repo");
    }

    #[test]
    fn rejects_urls_as_clone_targets() {
        assert_rejected("clone https://github.com/a/b.git", "branch selectors");
        assert_rejected("clone ssh://git@host/a/b", "branch selectors");
        assert_rejected("clone git@github.com:a/b.git", "branch selectors");
    }

    #[test]
    fn rejects_branch_selectors_on_selectors() {
        assert_rejected("push octo/hello@feat/x", "branch selectors");
        assert_rejected("clone octo/hello@feat/x", "branch selectors");
    }

    #[test]
    fn rejects_unknown_subcommands() {
        for argv in [
            "rev-parse HEAD",
            "config user.name evil",
            "checkout main",
            "daemon",
            "gc",
            "submodule update --init",
            "PUSH", // case-sensitive: only the exact keyword passes
        ] {
            assert_rejected(argv, "not available");
        }
    }

    #[test]
    fn rejects_remote_mutations() {
        assert_rejected("remote add evil https://evil.example/x.git", "too many");
        assert_rejected(
            "remote set-url origin https://evil.example/x.git",
            "too many",
        );
        assert_rejected("remote -v -v", "-v");
    }

    #[test]
    fn rejects_extra_arguments() {
        assert_rejected("push origin main", "too many");
        assert_rejected("clone octo/hello extra", "too many");
        assert_rejected("clone", "clone needs a declared repo");
        assert_rejected("", "missing git subcommand");
    }

    #[test]
    fn rejects_flags_in_selector_position() {
        assert_rejected("push --force", "--force");
        assert_rejected("push -f", "-f");
        assert_rejected("fetch --all", "--all");
        assert_rejected("pull --rebase", "--rebase");
    }

    // ---- the accepted grammar ----

    #[test]
    fn accepts_the_allowlisted_shapes() {
        let repo: RepoSpec = "octo/hello".parse().unwrap();
        assert_eq!(
            parse_git_argv("push").unwrap(),
            GitVerbCmd::Push { repo: None }
        );
        assert_eq!(
            parse_git_argv("push octo/hello").unwrap(),
            GitVerbCmd::Push {
                repo: Some(repo.clone())
            }
        );
        assert_eq!(
            parse_git_argv("pull").unwrap(),
            GitVerbCmd::Pull { repo: None }
        );
        assert_eq!(
            parse_git_argv("fetch").unwrap(),
            GitVerbCmd::Fetch { repo: None }
        );
        assert_eq!(
            parse_git_argv("status").unwrap(),
            GitVerbCmd::Status { repo: None }
        );
        assert_eq!(
            parse_git_argv("remote").unwrap(),
            GitVerbCmd::RemoteShow { repo: None }
        );
        assert_eq!(
            parse_git_argv("remote -v").unwrap(),
            GitVerbCmd::RemoteShow { repo: None }
        );
        assert_eq!(
            parse_git_argv("remote -v octo/hello").unwrap(),
            GitVerbCmd::RemoteShow {
                repo: Some(repo.clone())
            }
        );
        assert_eq!(
            parse_git_argv("clone octo/hello").unwrap(),
            GitVerbCmd::Clone { repo }
        );
        // Surrounding whitespace is insignificant.
        assert_eq!(
            parse_git_argv("  push   ").unwrap(),
            GitVerbCmd::Push { repo: None }
        );
    }

    #[test]
    fn permissions_map_write_for_push_read_otherwise() {
        assert_eq!(
            parse_git_argv("push").unwrap().permission(),
            Permission::push()
        );
        for argv in ["pull", "fetch", "status", "remote -v", "clone o/r"] {
            assert_eq!(
                parse_git_argv(argv).unwrap().permission(),
                Permission::read_contents(),
                "{argv} must require only contents:read"
            );
        }
    }

    #[test]
    fn local_only_ops_need_no_token() {
        assert!(!parse_git_argv("status").unwrap().needs_token());
        assert!(!parse_git_argv("remote -v").unwrap().needs_token());
        for argv in ["push", "pull", "fetch", "clone o/r"] {
            assert!(parse_git_argv(argv).unwrap().needs_token(), "{argv}");
        }
    }

    // ---- URL derivation & mirror-root isolation ----

    #[test]
    fn remote_url_joins_base_owner_repo() {
        let repo: RepoSpec = "octo/hello".parse().unwrap();
        let base = Url::parse("https://github.com/").unwrap();
        assert_eq!(
            remote_url(&base, &repo).unwrap().as_str(),
            "https://github.com/octo/hello.git"
        );
        // A base missing its trailing slash still resolves as a directory.
        let base = Url::parse("http://127.0.0.1:9999/git").unwrap();
        assert_eq!(
            remote_url(&base, &repo).unwrap().as_str(),
            "http://127.0.0.1:9999/git/octo/hello.git"
        );
    }

    #[test]
    fn mirror_root_is_a_sibling_of_the_workspace() {
        let working =
            DaemonAbsPath::try_new("/var/lib/minimald/sessions/abcd/tree").expect("abs path");
        let root = mirror_root(&working).expect("workspace has a parent");
        assert_eq!(
            root,
            std::path::Path::new("/var/lib/minimald/sessions/abcd").join(MIRROR_DIR),
            "the mirror must live outside the sandbox-mounted workspace tree"
        );
    }

    #[test]
    fn facade_error_messages_are_actionable_and_secret_free() {
        let messages = [
            not_permitted("git option `--upload-pack=/x` is not permitted through `min git`")
                .to_string(),
            FacadeError::NotPrimed {
                owner: "octo".into(),
                name: "hello".into(),
            }
            .to_string(),
            FacadeError::LocalGit {
                operation: "stage push".into(),
                detail: "fatal: could not read from remote repository".into(),
            }
            .to_string(),
            FacadeError::AmbiguousRepo {
                subcommand: "push".into(),
            }
            .to_string(),
            FacadeError::NoDeclaredRepos.to_string(),
            FacadeError::NoMirrorRoot.to_string(),
            FacadeError::UnsafeBranchName {
                branch: "-oProxyCommand=evil".into(),
            }
            .to_string(),
        ];
        for message in messages {
            assert!(!message.is_empty());
            for needle in ["ghu_", "gho_", "ghp_", "access_token", "refresh_token"] {
                assert!(
                    !message.contains(needle),
                    "message must not contain {needle:?}: {message}"
                );
            }
        }
    }
}
