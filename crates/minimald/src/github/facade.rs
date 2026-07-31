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
//! # The isolation invariant (the security core)
//!
//! **No privileged (daemon-run) `git` process may read sandbox-writable git
//! config.** The session workspace is sandbox-visible: in-sandbox code can
//! rewrite a primed repo's `.git/config` at will, and `git` executes a large,
//! open-ended set of config directives *as the process that reads them* —
//! `core.fsmonitor`, `core.sshCommand`, `core.pager`, `filter.<n>.process`,
//! `diff.external`, hooks, and `[include]`/`[includeIf]` (which splice in
//! arbitrary attacker-authored files, resolved only at git runtime). If the
//! daemon ran `git` in the worktree — or made a daemon git open
//! `upload-pack`/`receive-pack` *against* the worktree — any one of those would
//! run attacker code **as the daemon**, which then reads the token from the
//! mirror. This is the residual the earlier "token-free local leg" design
//! still had: even without a token in the working tree, a daemon
//! `git fetch <worktree-path>` spawns `upload-pack` there and executes its
//! config. A `.git/config` text scanner cannot close it (git honours includes
//! at file precedence, and a check-then-use scan races the sandbox rewriting
//! the file).
//!
//! So the daemon runs `git` in exactly one place: the daemon-private, bare,
//! daemon-authored **mirror** ([`mirror_root`] →
//! `<workspace-parent>/.gh-mirror/<owner>__<repo>.git`), a sibling of the
//! sandbox-mounted workspace that is mounted nowhere into the sandbox, with
//! `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`, its
//! `remote.origin.url` set to the canonical URL [`remote_url`] derives
//! daemon-side (never the string `"origin"`, never anything the sandbox
//! authored), and the token injected env-only by [`github::gitops`]. Object and
//! ref movement between the worktree and the mirror never exposes worktree
//! config to a daemon git:
//!
//! * **Objects are inert.** Git objects are content-addressed blobs; reading
//!   them executes nothing. Worktree → mirror transfer uses
//!   `objects/info/alternates` ([`link_worktree_objects`]): the mirror is given
//!   read-only object access to `<worktree>/.git/objects`. No `git upload-pack`
//!   ever runs in the worktree (that would read its config), and an alternate
//!   is an object *source* only — git never reads the alternate parent's config.
//! * **Refs are read and written as plain files.** The daemon parses the
//!   worktree's `HEAD`/`refs/*`/`packed-refs` itself ([`read_head_branch`],
//!   [`read_ref_oid`]) and writes tracking / branch tips back with
//!   [`write_loose_ref`] — never `git -C <worktree> …`. Every OID is validated
//!   as a hex sha ([`valid_oid`]) and every branch name is
//!   [`check_safe_branch`]-validated before it is used as a path component or a
//!   git argument, so a planted `refs/heads/x` holding `--evil` cannot become
//!   option-injection.
//! * **Mirror → worktree** object transfer builds a self-contained pack *in the
//!   mirror* ([`import_objects_into_worktree`], daemon-authored config) and
//!   drops the resulting `.pack`/`.idx` into the worktree object store as plain
//!   files.
//!
//! Per operation:
//!
//! * **Push:** read the worktree branch tip (plain file) → give the mirror
//!   object access to the worktree (alternate) and write the tip as a mirror
//!   ref (plain file) → [`github::gitops`] pushes mirror → canonical (token,
//!   mirror config only). The worktree's `origin`/`pushurl`/`insteadOf`/
//!   `include`/hooks are never read.
//! * **Fetch:** [`github::gitops`] fetches canonical → mirror (token, mirror
//!   config) → the objects are packed *in the mirror* and copied into the
//!   worktree, and each `refs/remotes/origin/*` is written as a plain file.
//! * **Pull:** fetch as above, verify a fast-forward *in the mirror*
//!   (`merge-base --is-ancestor`, the worktree tip resolved via the alternate),
//!   then advance the checked-out branch and its tracking ref as plain files.
//!   The daemon never runs a checkout in the sandbox-writable tree, so the
//!   working-tree files re-materialize on the sandbox's own next checkout.
//! * **Status:** branch from `HEAD`; ahead/behind from a mirror-side
//!   `rev-list` over the alternate — again no git in the worktree.
//! * **Clone:** the worktree does not exist yet, so the whole clone is built in
//!   a daemon-private temp under the mirror root (credentialed fetch → mirror,
//!   worktree assembled from the mirror over local legs) and renamed into the
//!   workspace only once complete — nothing token-bearing or config-reading
//!   ever runs in the sandbox-reachable destination, and a pre-existing
//!   destination is refused outright rather than adopted.
//!
//! Net invariant: **no `git` process the daemon runs ever reads — or resolves a
//! remote name from — a directory the sandbox can write.** The canonical URL is
//! always the daemon's own derivation; a rewritten worktree
//! `origin`/`pushurl`/`insteadOf`/`include`, and any `core.fsmonitor`/
//! `core.sshCommand`/`filter.*.process`/hook planted in the worktree config, is
//! simply never consulted by a daemon git, so it can neither redirect the token
//! leg nor execute code as the daemon.
//!
//! The mirror-location half of the invariant — `<workspace-parent>/.gh-mirror`
//! is writable by the daemon only — is owed by the launcher: the activation
//! wiring that mounts the workspace into the sandbox MUST NOT bind the
//! workspace's host *parent* (the session state dir) into the sandbox
//! namespace. That wiring has not landed yet ([`SessionGithub::new`] is not
//! reached from the production launcher); re-verify this property when it
//! does.
//!
//! Every span here is `github.facade` with fields limited to `repo` and
//! `grant_id` (see the conventions in `super::state`).

use std::fs;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

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

    /// A branch name is unsafe to use as a git argument or a ref-file path
    /// component: it begins with `-` (git would parse it as an option), or
    /// contains a `..`/empty path component or a git-special character (a
    /// planted `HEAD`/ref could try to escape the refs tree). Covers the
    /// worktree's current branch on push/pull/status and the declared/derived
    /// branch on clone. Refuse rather than run any git or touch any path on it
    /// (the branch name is not secret).
    #[error("branch `{branch}` has an unsafe name; rename it")]
    UnsafeBranchName {
        /// The offending branch name.
        branch: String,
    },

    /// A `pull` targeted a branch that has no counterpart on the remote (there
    /// is nothing to fast-forward onto).
    #[error("branch `{branch}` does not exist on the remote")]
    NoRemoteBranch {
        /// The branch that was not found on the remote.
        branch: String,
    },

    /// A `pull` would not be a fast-forward: the checked-out branch has
    /// diverged from the remote. The facade never merges or rebases in the
    /// sandbox-writable tree, so it refuses (mirrors `git pull --ff-only`).
    #[error("`{branch}` has diverged from the remote; `min git pull` is fast-forward only")]
    NotFastForward {
        /// The branch that could not be fast-forwarded.
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

/// Builds the hardened, **token-free, local-only** git command shared by
/// [`run_local_git`] and [`local_branch_exists`]: transport pinned to `file`,
/// hooks disabled, the operator's global/system config denied, and no
/// credential anywhere in its environment.
fn local_git_command(cwd: &Path, subargs: &[&str]) -> Command {
    let mut command = Command::new("git");
    command
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
        .stdin(Stdio::null());
    command
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
    let output =
        local_git_command(cwd, subargs)
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

/// The maximum symbolic-ref chase depth when resolving a worktree ref by hand.
const MAX_SYMREF_DEPTH: usize = 8;

/// Whether `s` is a git object id: 40 (SHA-1) or 64 (SHA-256) hex digits.
/// Everything read out of a sandbox-writable ref file is validated with this
/// before it is used as a git argument, so a planted `refs/heads/x` holding
/// `--upload-pack=evil` can never become option-injection on the mirror side.
fn valid_oid(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Validates a branch name that will become both a ref-file **path component**
/// and a **git argument**. A conservative subset of `git check-ref-format`:
/// non-empty, no leading `-`, no trailing `/`, no `.lock` suffix, no `..`/`//`,
/// no `.`/`..`/empty path component, and none of git's special characters or
/// control characters. Fail-closed — an unlisted shape is rejected — so a
/// hostile `HEAD`/ref cannot escape the refs tree or smuggle an option.
fn check_safe_branch(branch: &str) -> Result<(), FacadeError> {
    let unsafe_name = branch.is_empty()
        || branch.starts_with('-')
        || branch.ends_with('/')
        || branch.ends_with(".lock")
        || branch.contains("..")
        || branch.contains("//")
        || branch.contains(|c: char| c.is_ascii_control() || " \t\\~^:?*[".contains(c))
        || branch
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..");
    if unsafe_name {
        return Err(FacadeError::UnsafeBranchName {
            branch: branch.to_string(),
        });
    }
    Ok(())
}

/// The `.git` directory of a primed worktree. Only a real directory is
/// accepted (never a `.git` *file*: a gitfile could redirect the git dir
/// elsewhere), failing closed otherwise.
fn worktree_git_dir(work: &Path) -> Result<PathBuf, FacadeError> {
    let git_dir = work.join(".git");
    if git_dir.is_dir() {
        Ok(git_dir)
    } else {
        Err(FacadeError::LocalGit {
            operation: "open worktree".to_string(),
            detail: format!("{} has no .git directory", work.display()),
        })
    }
}

/// A short, non-secret local-git error for a ref read/write step.
fn ref_step_error(operation: impl Into<String>, detail: impl Into<String>) -> FacadeError {
    FacadeError::LocalGit {
        operation: operation.into(),
        detail: detail.into(),
    }
}

/// Validates a ref-file value as an OID, erroring with a non-secret message.
fn validated_oid(refname: &str, value: &str) -> Result<String, FacadeError> {
    if valid_oid(value) {
        Ok(value.to_string())
    } else {
        Err(ref_step_error(
            format!("read ref {refname}"),
            "ref does not contain a valid object id",
        ))
    }
}

/// Resolves a ref's target OID by parsing the loose ref file then `packed-refs`
/// as plain files — never by running git in the (sandbox-writable) tree. Chases
/// symbolic refs up to [`MAX_SYMREF_DEPTH`]. `Ok(None)` when the ref is absent.
/// Works on any git dir, worktree or bare mirror.
fn read_ref_oid(git_dir: &Path, refname: &str) -> Result<Option<String>, FacadeError> {
    read_ref_oid_depth(git_dir, refname, 0)
}

fn read_ref_oid_depth(
    git_dir: &Path,
    refname: &str,
    depth: usize,
) -> Result<Option<String>, FacadeError> {
    if depth > MAX_SYMREF_DEPTH {
        return Err(ref_step_error(
            format!("read ref {refname}"),
            "symbolic ref chain too deep",
        ));
    }
    // A loose ref file takes precedence over any packed-refs entry.
    let loose = git_dir.join(refname);
    if let Ok(contents) = fs::read_to_string(&loose) {
        let line = contents.trim();
        if let Some(target) = line.strip_prefix("ref:") {
            return read_ref_oid_depth(git_dir, target.trim(), depth + 1);
        }
        return validated_oid(refname, line).map(Some);
    }
    let packed = git_dir.join("packed-refs");
    if let Ok(contents) = fs::read_to_string(&packed) {
        for entry in contents.lines() {
            if entry.starts_with('#') || entry.starts_with('^') {
                continue;
            }
            if let Some((oid, name)) = entry.split_once(' ')
                && name.trim() == refname
            {
                return validated_oid(refname, oid.trim()).map(Some);
            }
        }
    }
    Ok(None)
}

/// Reads the branch a worktree's `HEAD` points at, as a plain file. Errors on a
/// detached HEAD (nothing to push/pull) and validates the branch name.
fn read_head_branch(git_dir: &Path) -> Result<String, FacadeError> {
    let head = fs::read_to_string(git_dir.join("HEAD"))
        .map_err(|source| ref_step_error("read HEAD", format!("{source}")))?;
    let branch = head
        .trim()
        .strip_prefix("ref: refs/heads/")
        .ok_or_else(|| ref_step_error("read HEAD", "HEAD is detached; check out a branch first"))?;
    check_safe_branch(branch)?;
    Ok(branch.to_string())
}

/// Writes a ref as a loose plain file (creating the ref subdirectory),
/// atomically via a temp file + rename. The daemon moves a worktree ref this
/// way — never with `git -C <worktree> …` — so no worktree config is read. The
/// caller has [`check_safe_branch`]-validated the branch component of
/// `refname`, so this join cannot escape the refs tree.
fn write_loose_ref(git_dir: &Path, refname: &str, oid: &str) -> Result<(), FacadeError> {
    let path = git_dir.join(refname);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| {
            ref_step_error(format!("write ref {refname}"), format!("{source}"))
        })?;
    }
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("ref")
        .to_string();
    let tmp = path.with_file_name(format!(".{file_name}.min-{}.tmp", std::process::id()));
    fs::write(&tmp, format!("{oid}\n"))
        .map_err(|source| ref_step_error(format!("write ref {refname}"), format!("{source}")))?;
    fs::rename(&tmp, &path).map_err(|source| {
        let _ = fs::remove_file(&tmp);
        ref_step_error(format!("write ref {refname}"), format!("{source}"))
    })
}

/// Grants the daemon-private mirror read-only access to the worktree's object
/// store via `objects/info/alternates`. Objects are content-addressed and
/// inert, so this exposes **no** worktree config to the mirror's git — the
/// mechanism that lets the daemon pack/read worktree commits without ever
/// running `git upload-pack` (which would read worktree config) in the tree.
fn link_worktree_objects(mirror: &Path, worktree_git_dir: &Path) -> Result<(), FacadeError> {
    let objects = worktree_git_dir.join("objects");
    let objects = path_arg(&objects)?;
    let info = mirror.join("objects").join("info");
    fs::create_dir_all(&info)
        .map_err(|source| ref_step_error("link worktree objects", format!("{source}")))?;
    fs::write(info.join("alternates"), format!("{objects}\n"))
        .map_err(|source| ref_step_error("link worktree objects", format!("{source}")))
}

/// Runs one hardened, token-free git command in a **daemon-private** directory
/// (the mirror — never the sandbox worktree), capturing stdout. Shares
/// [`local_git_command`]'s hardening (global/system config denied, hooks off,
/// no credential prompt). `stdin` is fed when present (for `pack-objects
/// --revs`). The `detail` on failure is the last non-secret stderr line.
fn mirror_git_capture(
    cwd: &Path,
    operation: &str,
    subargs: &[&str],
    stdin: Option<&str>,
) -> Result<String, FacadeError> {
    let mut command = local_git_command(cwd, subargs);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command
        .spawn()
        .map_err(|source| ref_step_error(operation, format!("could not run git: {source}")))?;
    if let Some(input) = stdin
        && let Some(mut sink) = child.stdin.take()
    {
        let _ = sink.write_all(input.as_bytes());
    }
    let output = child
        .wait_with_output()
        .map_err(|source| ref_step_error(operation, format!("{source}")))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = stderr
        .trim()
        .lines()
        .next_back()
        .unwrap_or("git failed")
        .to_string();
    Err(ref_step_error(operation, detail))
}

/// The `(branch, oid)` heads of the daemon-private mirror. Read with a
/// mirror-side `for-each-ref` (daemon-authored config), never from the
/// worktree. Unsafe branch names / invalid OIDs are skipped defensively.
fn mirror_heads(mirror: &Path) -> Result<Vec<(String, String)>, FacadeError> {
    let out = mirror_git_capture(
        mirror,
        "list mirror heads",
        &[
            "for-each-ref",
            "--format=%(objectname) %(refname)",
            "refs/heads",
        ],
        None,
    )?;
    Ok(out
        .lines()
        .filter_map(|line| line.split_once(' '))
        .filter_map(|(oid, refname)| {
            let branch = refname.strip_prefix("refs/heads/")?;
            (valid_oid(oid) && check_safe_branch(branch).is_ok())
                .then(|| (branch.to_string(), oid.to_string()))
        })
        .collect())
}

/// Copies the objects reachable from `tips` out of the mirror and into the
/// worktree's object store **without running git in the worktree**.
/// `pack-objects` runs *in the mirror* (daemon-authored config) and writes a
/// self-contained pack to a daemon-private temp; the resulting `.pack`/`.idx`
/// are copied into `<worktree>/.git/objects/pack` as plain, inert files. A
/// no-op when there are no valid tips.
fn import_objects_into_worktree(
    mirror: &Path,
    worktree_git_dir: &Path,
    tips: &[String],
) -> Result<(), FacadeError> {
    let stdin: String = tips
        .iter()
        .filter(|t| valid_oid(t))
        .map(|t| format!("{t}\n"))
        .collect();
    if stdin.is_empty() {
        return Ok(());
    }
    let staging = mirror.join(format!(".pack-import-{}.tmp", std::process::id()));
    fs::create_dir_all(&staging)
        .map_err(|source| ref_step_error("import objects", format!("{source}")))?;
    let result = import_objects_inner(mirror, worktree_git_dir, &staging, &stdin);
    let _ = fs::remove_dir_all(&staging);
    result
}

fn import_objects_inner(
    mirror: &Path,
    worktree_git_dir: &Path,
    staging: &Path,
    stdin: &str,
) -> Result<(), FacadeError> {
    let base = staging.join("pack");
    let base_arg = path_arg(&base)?;
    // A full pack reachable from the tips: self-contained (no `--thin`), so the
    // `.pack`/`.idx` are valid in the worktree object store on their own.
    mirror_git_capture(
        mirror,
        "pack objects",
        &["pack-objects", "--revs", "--delta-base-offset", base_arg],
        Some(stdin),
    )?;
    let dest = worktree_git_dir.join("objects").join("pack");
    fs::create_dir_all(&dest)
        .map_err(|source| ref_step_error("import objects", format!("{source}")))?;
    // Copy the `.pack` before the `.idx`: a reader that sees an `.idx` treats
    // the pack as usable, so the data file must already be in place.
    for extension in ["pack", "idx"] {
        for entry in fs::read_dir(staging)
            .map_err(|source| ref_step_error("import objects", format!("{source}")))?
        {
            let path = entry
                .map_err(|source| ref_step_error("import objects", format!("{source}")))?
                .path();
            let matches = path.extension().and_then(|e| e.to_str()) == Some(extension);
            if let (true, Some(name)) = (matches, path.file_name()) {
                fs::copy(&path, dest.join(name))
                    .map_err(|source| ref_step_error("import objects", format!("{source}")))?;
            }
        }
    }
    Ok(())
}

/// Whether `new` is a descendant of (or equal to) `old`, decided in the mirror
/// with `merge-base --is-ancestor` (worktree-only commits resolved via the
/// object alternate). A non-zero exit — not-an-ancestor or a bad object — is a
/// non-fast-forward.
fn is_fast_forward(mirror: &Path, old: &str, new: &str) -> Result<bool, FacadeError> {
    if old == new {
        return Ok(true);
    }
    let status = local_git_command(mirror, &["merge-base", "--is-ancestor", old, new])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|source| {
            ref_step_error("check fast-forward", format!("could not run git: {source}"))
        })?;
    Ok(status.success())
}

/// `(ahead, behind)` of `local` relative to `upstream`, computed in the mirror
/// over the worktree object alternate (`rev-list --left-right --count
/// upstream...local` prints `<behind>\t<ahead>`).
fn count_ahead_behind(
    mirror: &Path,
    upstream: &str,
    local: &str,
) -> Result<(usize, usize), FacadeError> {
    let range = format!("{upstream}...{local}");
    let out = mirror_git_capture(
        mirror,
        "count ahead/behind",
        &["rev-list", "--left-right", "--count", range.as_str()],
        None,
    )?;
    let mut counts = out.split_whitespace();
    let behind = counts.next().and_then(|n| n.parse().ok());
    let ahead = counts.next().and_then(|n| n.parse().ok());
    match (behind, ahead) {
        (Some(behind), Some(ahead)) => Ok((ahead, behind)),
        _ => Err(ref_step_error(
            "count ahead/behind",
            "could not parse ahead/behind counts",
        )),
    }
}

/// Ahead/behind of the checked-out branch versus its `origin/<branch>` tracking
/// ref, computed in a mirror over the worktree objects (alternate). Extracted
/// from [`execute`]'s `status` arm so it has no immediately-invoked closure.
fn worktree_ahead_behind(
    mirror_root: &Path,
    repo: &RepoSpec,
    remote: &Url,
    git_dir: &Path,
    upstream: &str,
    local: &str,
    out: &mut UnixStream,
) -> Result<(usize, usize), FacadeError> {
    let mirror = ensure_mirror(mirror_root, repo, remote, out)?;
    link_worktree_objects(&mirror, git_dir)?;
    count_ahead_behind(&mirror, upstream, local)
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

/// Whether the daemon-private repo at `dir` has a local branch named `branch`.
/// A quiet, token-free, local-only probe with the same hardening as
/// [`run_local_git`]. Used only against the mirror, whose heads (after a
/// fetch) are exactly the canonical remote's — so this doubles as the
/// "does the branch exist on the remote?" check without another network op.
fn local_branch_exists(dir: &Path, branch: &str) -> Result<bool, FacadeError> {
    // Always probed as a fully-qualified ref, so a `-`-leading branch name can
    // never be parsed as an option here.
    let refname = format!("refs/heads/{branch}");
    local_git_command(dir, &["rev-parse", "--verify", "--quiet", &refname])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .map_err(|source| FacadeError::LocalGit {
            operation: "probe mirror branch".to_string(),
            detail: format!("could not run git: {source}"),
        })
}

/// The branch a fresh clone's worktree starts on (spec R2.2), decided
/// daemon-side against the already-fetched mirror.
#[derive(Debug)]
enum CloneTarget {
    /// The branch exists on the remote (present in the mirror after the
    /// fetch); check it out tracking `origin/<branch>`.
    Existing {
        /// The remote branch to check out.
        branch: String,
    },
    /// The branch is absent on the remote; create it locally from `base`,
    /// with no upstream — it is never pushed implicitly (spec R2.5).
    CreateFromBase {
        /// The new local branch.
        branch: String,
        /// The remote branch it starts from.
        base: String,
    },
}

impl CloneTarget {
    /// The branch the finished worktree ends up on.
    fn branch(&self) -> &str {
        match self {
            Self::Existing { branch } | Self::CreateFromBase { branch, .. } => branch,
        }
    }
}

/// Resolves the [`CloneTarget`] for a declared repo: its declared branch if it
/// exists on the remote; otherwise created from the declared base (or the
/// remote's default branch); with no declared branch, the remote's default.
///
/// `mirror_tree` must be the **mirror**, already fetched: branch existence is
/// a local probe against the mirror's heads, and the one network op — the
/// default-branch `ls-remote` — runs in the mirror too, reading only its
/// daemon-authored config (never the workspace's).
fn clone_target(
    mirror_tree: &Repo,
    repo: &RepoSpec,
    token: Option<&SecretString>,
) -> Result<CloneTarget, FacadeError> {
    let mirror = mirror_tree.work_dir();
    let target = match repo.branch() {
        Some(branch) if local_branch_exists(mirror, branch)? => CloneTarget::Existing {
            branch: branch.to_string(),
        },
        Some(branch) => {
            let base = match repo.base() {
                Some(base) => base.to_string(),
                None => mirror_tree.default_branch(token)?,
            };
            if !local_branch_exists(mirror, &base)? {
                return Err(github::gitops::GitError::BaseBranchNotFound { branch: base }.into());
            }
            CloneTarget::CreateFromBase {
                branch: branch.to_string(),
                base,
            }
        }
        None => CloneTarget::Existing {
            branch: mirror_tree.default_branch(token)?,
        },
    };
    // The branch name becomes a bare `git checkout` argument on the local leg;
    // a leading dash would parse as an option (argv injection). The declared
    // spec's ref validation is strict but does not exclude a leading `-`.
    if target.branch().starts_with('-') {
        return Err(FacadeError::UnsafeBranchName {
            branch: target.branch().to_string(),
        });
    }
    Ok(target)
}

/// A unique temp directory under the daemon-private mirror root for staging a
/// clone's worktree — same filesystem as the workspace in production (both
/// live under the session dir), so the finalizing rename is atomic.
fn unique_clone_temp(root: &Path, repo: &RepoSpec) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    root.join(format!(
        ".clone-{}__{}-{}-{nanos}.tmp",
        repo.owner(),
        repo.repo(),
        std::process::id()
    ))
}

/// Builds the sandbox-facing worktree for a fresh clone entirely inside a temp
/// directory under the daemon-private mirror `root`, then renames it to `dest`
/// in one step. Every git process here is local-only and token-free; the tree
/// the sandbox eventually sees is complete — `origin` at the canonical URL,
/// `target` checked out — *before* it becomes sandbox-reachable, so no later
/// git step (least of all a token-bearing one) ever runs inside it. Failure at
/// any step removes the temp and leaves the workspace untouched (spec R2.6).
fn materialize_worktree(
    root: &Path,
    mirror: &Path,
    canonical: &Url,
    target: &CloneTarget,
    dest: &Path,
    repo: &RepoSpec,
    out: &mut UnixStream,
) -> Result<(), FacadeError> {
    let temp = unique_clone_temp(root, repo);
    if let Err(err) = build_worktree(&temp, mirror, canonical, target, out) {
        let _ = fs::remove_dir_all(&temp);
        return Err(err);
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|source| {
            let _ = fs::remove_dir_all(&temp);
            FacadeError::LocalGit {
                operation: "prepare workspace".to_string(),
                detail: format!("could not create the workspace directory: {source}"),
            }
        })?;
    }
    fs::rename(&temp, dest).map_err(|source| {
        let _ = fs::remove_dir_all(&temp);
        FacadeError::LocalGit {
            operation: "finalize clone".to_string(),
            detail: format!("could not move the clone into the workspace: {source}"),
        }
    })
}

/// The fallible steps of [`materialize_worktree`], separated so a failure at
/// any point cleans up the temp directory exactly once.
fn build_worktree(
    temp: &Path,
    mirror: &Path,
    canonical: &Url,
    target: &CloneTarget,
    out: &mut UnixStream,
) -> Result<(), FacadeError> {
    let mirror_arg = path_arg(mirror)?;
    let temp_arg = path_arg(temp)?;
    // `--no-checkout`: the branch decision is already made in `target`.
    // `--no-hardlinks`: never share object inodes between the daemon-private
    // mirror and the soon-to-be-sandbox-writable tree.
    run_local_git(
        mirror,
        "clone from mirror",
        &[
            "clone",
            "--quiet",
            "--no-checkout",
            "--no-hardlinks",
            "--origin",
            "origin",
            mirror_arg,
            temp_arg,
        ],
        out,
    )?;
    // The finished tree presents the clean canonical URL as `origin` (R6.1:
    // no credential material), exactly as a direct clone would — but no
    // token-bearing git will ever read it back (see the module docs).
    run_local_git(
        temp,
        "set clone origin",
        &["remote", "set-url", "origin", canonical.as_str()],
        out,
    )?;
    match target {
        CloneTarget::Existing { branch } => {
            let origin_ref = format!("origin/{branch}");
            run_local_git(
                temp,
                "checkout",
                &["checkout", "--quiet", "-B", branch, "--track", &origin_ref],
                out,
            )
        }
        CloneTarget::CreateFromBase { branch, base } => {
            let origin_base = format!("origin/{base}");
            // `--no-track`: a created branch has no upstream until explicitly
            // pushed (spec R2.5) — the PR-able signal depends on it.
            run_local_git(
                temp,
                "checkout",
                &[
                    "checkout",
                    "--quiet",
                    "-b",
                    branch,
                    "--no-track",
                    &origin_base,
                ],
                out,
            )
        }
    }
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
            let git_dir = worktree_git_dir(&work)?;
            // Branch + tip read as plain files: no git runs in the worktree, so
            // no worktree config is executed. `read_head_branch` validates the
            // name (rejects a leading-dash / escaping branch) and rejects a
            // detached HEAD.
            let branch = read_head_branch(&git_dir)?;
            let branch_ref = format!("refs/heads/{branch}");
            let tip = read_ref_oid(&git_dir, &branch_ref)?.ok_or_else(|| {
                ref_step_error(
                    "read branch tip",
                    format!("branch `{branch}` has no commits"),
                )
            })?;

            let mirror = ensure_mirror(&mirror_root(working)?, repo, remote, &mut out)?;
            // The only bridge from the sandbox tree to the credentialed leg:
            // read-only object access (inert) + the tip written as a mirror ref
            // (plain file). No `git upload-pack` ever runs in the worktree.
            link_worktree_objects(&mirror, &git_dir)?;
            write_loose_ref(&mirror, &branch_ref, &tip)?;

            // Credentialed leg: push mirror → canonical. `gitops` runs in the
            // mirror and reads only the daemon-authored mirror config; the tip's
            // objects are reachable via the alternate.
            Repo::open(mirror.clone(), remote.as_str()).push(token, &branch, |_, line| {
                let _ = writeln!(out, "msg:{line}");
            })?;

            // Reflect the push in the worktree's remote-tracking ref (plain
            // file; the pushed objects already live in the worktree). Purely
            // local; failure here does not undo the successful push.
            let _ = write_loose_ref(&git_dir, &format!("refs/remotes/origin/{branch}"), &tip);
            let _ = writeln!(out, "msg:pushed `{branch}` to origin ({owner_repo})");
        }
        GitVerbCmd::Fetch { .. } => {
            let work = primed_dir(working, declared_repos, repo)?;
            let git_dir = worktree_git_dir(&work)?;
            let mirror = ensure_mirror(&mirror_root(working)?, repo, remote, &mut out)?;
            // Credentialed leg: canonical → mirror (mirror config only). Objects
            // accumulate in the mirror across fetches, so this stays incremental
            // without ever touching the worktree.
            Repo::open(mirror.clone(), remote.as_str()).fetch(token, |_, line| {
                let _ = writeln!(out, "msg:{line}");
            })?;
            // Reflect every canonical head into the worktree with plain-file
            // ops: import the objects (packed in the mirror) then write
            // `refs/remotes/origin/*`. No git runs in the worktree.
            let heads = mirror_heads(&mirror)?;
            let tips: Vec<String> = heads.iter().map(|(_, oid)| oid.clone()).collect();
            import_objects_into_worktree(&mirror, &git_dir, &tips)?;
            for (branch, oid) in &heads {
                write_loose_ref(&git_dir, &format!("refs/remotes/origin/{branch}"), oid)?;
            }
            let _ = writeln!(out, "msg:fetched origin ({owner_repo})");
        }
        GitVerbCmd::Pull { .. } => {
            let work = primed_dir(working, declared_repos, repo)?;
            let git_dir = worktree_git_dir(&work)?;
            let branch = read_head_branch(&git_dir)?;
            let branch_ref = format!("refs/heads/{branch}");
            let local_tip = read_ref_oid(&git_dir, &branch_ref)?.ok_or_else(|| {
                ref_step_error(
                    "read branch tip",
                    format!("branch `{branch}` has no commits"),
                )
            })?;

            let mirror = ensure_mirror(&mirror_root(working)?, repo, remote, &mut out)?;
            // Credentialed leg: canonical → mirror (mirror config only).
            Repo::open(mirror.clone(), remote.as_str()).fetch(token, |_, line| {
                let _ = writeln!(out, "msg:{line}");
            })?;
            let new_tip =
                read_ref_oid(&mirror, &branch_ref)?.ok_or_else(|| FacadeError::NoRemoteBranch {
                    branch: branch.clone(),
                })?;

            if new_tip == local_tip {
                let _ = writeln!(out, "msg:already up to date ({owner_repo})");
            } else {
                // Fast-forward only, decided in the mirror over the worktree
                // objects (alternate) — the facade never merges/rebases in the
                // sandbox-writable tree.
                link_worktree_objects(&mirror, &git_dir)?;
                if !is_fast_forward(&mirror, &local_tip, &new_tip)? {
                    return Err(FacadeError::NotFastForward { branch });
                }
                import_objects_into_worktree(&mirror, &git_dir, std::slice::from_ref(&new_tip))?;
                // Advance the checked-out branch and its tracking ref as plain
                // files. The working-tree files re-materialize on the sandbox's
                // own next checkout; no daemon git touches the tree.
                write_loose_ref(&git_dir, &branch_ref, &new_tip)?;
                write_loose_ref(&git_dir, &format!("refs/remotes/origin/{branch}"), &new_tip)?;
                let _ = writeln!(
                    out,
                    "msg:fast-forwarded `{branch}` to origin ({owner_repo})"
                );
            }
        }
        GitVerbCmd::Status { .. } => {
            // Local-only, no token, no remote contact — and no git in the
            // worktree: branch from `HEAD`, tips from the ref files.
            let dir = primed_dir(working, declared_repos, repo)?;
            let git_dir = worktree_git_dir(&dir)?;
            let Ok(branch) = read_head_branch(&git_dir) else {
                let _ = writeln!(out, "msg:{owner_repo}: HEAD is detached");
                return Ok(());
            };
            let _ = writeln!(out, "msg:{owner_repo}: on branch `{branch}`");
            let local_tip = read_ref_oid(&git_dir, &format!("refs/heads/{branch}"))?;
            let upstream = read_ref_oid(&git_dir, &format!("refs/remotes/origin/{branch}"))?;
            match (local_tip, upstream) {
                (Some(local), Some(up)) => {
                    // Ahead/behind computed in the mirror over the worktree
                    // objects (alternate). Degrade gracefully rather than fail
                    // the whole status if the comparison cannot be made.
                    let counts = worktree_ahead_behind(
                        &mirror_root(working)?,
                        repo,
                        remote,
                        &git_dir,
                        &up,
                        &local,
                        &mut out,
                    );
                    match counts {
                        Ok((ahead, behind)) => {
                            let _ = writeln!(
                                out,
                                "msg:ahead of origin/{branch} by {ahead} commit(s), behind by {behind}"
                            );
                        }
                        Err(_) => {
                            let _ = writeln!(out, "msg:upstream relationship not recognized");
                        }
                    }
                }
                _ => {
                    let _ = writeln!(
                        out,
                        "msg:no upstream: the branch has never been pushed \
                         (`min git push` publishes it)"
                    );
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
            // the activation flow's business, not the facade's. The clone runs
            // the full mirror discipline: the moment a clone lands in the
            // workspace its `.git/config` is sandbox-writable, so every
            // token-bearing step (fetch, default-branch probe) happens in the
            // daemon-private mirror *first*, and the worktree is materialized
            // from the mirror over token-free local legs, appearing in the
            // workspace fully formed (see the module docs).
            let dest = working.as_utf8_path().as_std_path().join(repo.repo());
            if dest.exists() {
                // Fail closed: whatever is here, the sandbox may have planted
                // it (hostile config included). Never adopt or touch it.
                return Err(github::gitops::GitError::DestinationExists {
                    path: dest.display().to_string(),
                }
                .into());
            }
            let root = mirror_root(working)?;
            let mirror = ensure_mirror(&root, repo, remote, &mut out)?;
            let mirror_tree = Repo::open(mirror.clone(), remote.as_str());
            // Credentialed leg: every canonical head → mirror. Runs in the
            // mirror; reads only its daemon-authored config.
            mirror_tree.fetch(token, |_, line| {
                let _ = writeln!(out, "msg:{line}");
            })?;
            let target = clone_target(&mirror_tree, repo, token)?;
            materialize_worktree(&root, &mirror, remote, &target, &dest, repo, &mut out)?;
            let _ = writeln!(out, "msg:cloned {owner_repo} into `{}`", repo.repo());
            if repo.branch().is_some() {
                let what = match &target {
                    CloneTarget::Existing { .. } => "checked out",
                    CloneTarget::CreateFromBase { .. } => "created",
                };
                let _ = writeln!(out, "msg:{what} branch `{}`", target.branch());
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
            FacadeError::NoRemoteBranch {
                branch: "feat/x".into(),
            }
            .to_string(),
            FacadeError::NotFastForward {
                branch: "feat/x".into(),
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

    // ---- plain-file ref reading/writing & OID/branch validation ----

    #[test]
    fn valid_oid_accepts_shas_and_rejects_everything_else() {
        assert!(valid_oid(&"a".repeat(40)));
        assert!(valid_oid(&"0".repeat(64)));
        assert!(valid_oid("9dbd6e01f4657f834203ed1b4da152d704ddeaec"));
        assert!(!valid_oid(&"a".repeat(39)));
        assert!(!valid_oid(&"a".repeat(41)));
        // An option-shaped or path-shaped ref-file value is never an OID, so it
        // can never reach a git argument via `read_ref_oid`.
        assert!(!valid_oid("--upload-pack=/tmp/evil"));
        assert!(!valid_oid("ref: refs/heads/main"));
        assert!(!valid_oid(&format!("{}z", "a".repeat(39))));
    }

    #[test]
    fn check_safe_branch_accepts_normal_and_rejects_dangerous() {
        for ok in ["main", "feat/x", "release/1.2.x", "user.name/topic"] {
            check_safe_branch(ok).unwrap_or_else(|_| panic!("{ok} must be accepted"));
        }
        for bad in [
            "",
            "-oProxyCommand=evil",
            "..",
            "a/../b",
            "a//b",
            "feat/",
            "has space",
            "ctrl\tchar",
            "weird~ref",
            "x.lock",
            "back\\slash",
        ] {
            assert!(
                matches!(
                    check_safe_branch(bad),
                    Err(FacadeError::UnsafeBranchName { .. })
                ),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn reads_head_and_refs_as_plain_files() {
        let dir = tempfile::tempdir().expect("tmp");
        let git_dir = dir.path();
        let oid = "9dbd6e01f4657f834203ed1b4da152d704ddeaec";

        fs::write(git_dir.join("HEAD"), "ref: refs/heads/feat/x\n").unwrap();
        fs::create_dir_all(git_dir.join("refs").join("heads").join("feat")).unwrap();
        fs::write(git_dir.join("refs/heads/feat/x"), format!("{oid}\n")).unwrap();

        assert_eq!(read_head_branch(git_dir).unwrap(), "feat/x");
        assert_eq!(
            read_ref_oid(git_dir, "refs/heads/feat/x")
                .unwrap()
                .as_deref(),
            Some(oid)
        );
        // A missing ref is `None`, not an error.
        assert!(
            read_ref_oid(git_dir, "refs/remotes/origin/feat/x")
                .unwrap()
                .is_none()
        );

        // packed-refs fallback for a ref with no loose file.
        let packed_oid = "0000000000000000000000000000000000000abc";
        fs::write(
            git_dir.join("packed-refs"),
            format!("# pack-refs with: peeled\n{packed_oid} refs/heads/main\n"),
        )
        .unwrap();
        assert_eq!(
            read_ref_oid(git_dir, "refs/heads/main").unwrap().as_deref(),
            Some(packed_oid)
        );
    }

    #[test]
    fn detached_and_unsafe_head_are_refused() {
        let dir = tempfile::tempdir().expect("tmp");
        let git_dir = dir.path();

        fs::write(
            git_dir.join("HEAD"),
            "9dbd6e01f4657f834203ed1b4da152d704ddeaec\n",
        )
        .unwrap();
        assert!(
            read_head_branch(git_dir).is_err(),
            "detached HEAD must fail"
        );

        fs::write(git_dir.join("HEAD"), "ref: refs/heads/-oEvil\n").unwrap();
        assert!(
            matches!(
                read_head_branch(git_dir),
                Err(FacadeError::UnsafeBranchName { .. })
            ),
            "a dash-leading HEAD branch must be refused"
        );
    }

    #[test]
    fn write_loose_ref_roundtrips_and_creates_subdirs() {
        let dir = tempfile::tempdir().expect("tmp");
        let git_dir = dir.path();
        let oid = "9dbd6e01f4657f834203ed1b4da152d704ddeaec";

        write_loose_ref(git_dir, "refs/remotes/origin/feat/x", oid).unwrap();
        assert_eq!(
            read_ref_oid(git_dir, "refs/remotes/origin/feat/x")
                .unwrap()
                .as_deref(),
            Some(oid)
        );
        // No stray temp file is left behind next to the ref.
        let leftovers: Vec<_> = fs::read_dir(git_dir.join("refs/remotes/origin/feat"))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp ref file not cleaned up");
    }

    #[test]
    fn read_ref_oid_rejects_a_planted_option_shaped_value() {
        let dir = tempfile::tempdir().expect("tmp");
        let git_dir = dir.path();
        fs::create_dir_all(git_dir.join("refs").join("heads")).unwrap();
        // A hostile worktree plants an option string where an OID belongs; the
        // reader refuses it rather than let it flow into a git argument.
        fs::write(git_dir.join("refs/heads/main"), "--upload-pack=/tmp/evil\n").unwrap();
        assert!(
            read_ref_oid(git_dir, "refs/heads/main").is_err(),
            "a non-OID ref value must be rejected"
        );
    }
}
