//! A session-owned runtime environment.
//!
//! [`Env`] is the minimald-specific counterpart to [`mctx::Env`]. The crucial
//! difference is ownership: this `Env` *owns* the [`mctx::Context`] and
//! [`graph::Graph`] (they are moved into the in-sandbox command actor) instead
//! of borrowing them like `mctx::Env<'a>` does. That makes it `Send + 'static`,
//! so the long-lived session host can hold it directly — no self-referential
//! lifetimes, no leaking the context/graph to fabricate `'static` borrows.
//!
//! ## The in-sandbox `min` command channel
//!
//! Packages, tasks and checks can be driven from *inside* a running session via
//! the `min` helper, which talks to `/run/minenv_sock`. [`sandbox`]'s listener
//! is synchronous — a blocking `accept()` loop on its own OS thread — which is
//! why the equivalent handler in `mctx` has to spin up a fresh tokio runtime per
//! command. Here we bridge that synchronous world to the daemon's async runtime
//! with an actor:
//!
//! - [`BridgeChannel`] is the trivial synchronous [`sandbox::Channel`]. For each
//!   request it clones the connection and forwards it (with the request line)
//!   down an mpsc to the actor, then returns immediately.
//! - [`BoxChannel`] is the actor: it owns the context and graph and processes
//!   requests one at a time on the runtime, so every handler is a plain
//!   `async fn` that `.await`s — no nested runtimes, no sync/async bridge writers.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::Permissions;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;

use crate::traced::spawn_blocking;
use camino::{Utf8Path, Utf8PathBuf};
use graph::{BuildSpecRef, Graph, SetupForPackages, Transitives};
use mctx::{AddDepMode, Context, Error};
use mfile::{EnvPatches, EnvVarValue};
use op::Runnable;
use ot::OpTracker;
use paths::{DaemonAbsPath, DaemonRelPath, SandboxAbsPath};
use sandbox::config::{ClassifierLeaf, Config, SandboxMapped};
use sandbox::{Container, Sandbox};
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// The min helper script installed at `/usr/bin/min` inside the sandbox.
const MIN_SCRIPT: &str = include_str!("env_min_helper.sh");

/// Marks a hook file as ours, so a rootfs that already carries one (zsh's
/// global rc is a file its own package may ship) is appended to once rather
/// than repeatedly.
const ATTACH_ENV_HOOK_MARKER: &str = "minimal: per-attach environment";

/// Directory and file name of the bash rc the session shell is started with
/// (`--rcfile`). Not a shell-owned integration point like the others — this
/// build of bash has no `/etc/bash.bashrc` — so the daemon names it on the
/// shell's own argv; see [`install_attach_env_hooks`]. Because it is the
/// *only* file a session bash reads, it does both jobs the other shells split
/// between a system rc and a user one: the attach-env hook, then the user's
/// own startup file ([`ATTACH_ENV_BASH_USER_RC`]).
const ATTACH_ENV_BASH_RC_DIR: &str = "usr/share/minimal";
const ATTACH_ENV_BASH_RC_NAME: &str = "attach-env.bash";

/// In-sandbox absolute path of that rc, for the shell's argv.
///
/// Read only by the real launcher (`cfg(not(test))`); the mock launcher runs
/// its own program, so tolerate it being unread under `test`.
#[cfg_attr(test, allow(dead_code))]
pub(crate) const ATTACH_ENV_BASH_RC: &str =
    constcat::concat!("/", ATTACH_ENV_BASH_RC_DIR, "/", ATTACH_ENV_BASH_RC_NAME);

/// File name of the POSIX fallback, installed beside the bash rc.
const ATTACH_ENV_POSIX_NAME: &str = "attach-env-posix.sh";

/// In-sandbox absolute path of the POSIX fallback, named by `$ENV`.
///
/// `$ENV` is the one hook POSIX defines: an interactive shell expands it and
/// sources that file at startup. dash, the BusyBox and BSD ashes, ksh, and
/// mksh all honour it (bash only in POSIX mode, which is why bash has its own
/// rc instead).
///
/// It buys startup, not refresh: POSIX has no per-prompt or per-command hook,
/// and none can be synthesized — `PS1` expansion cannot mutate the shell's own
/// environment, since a command substitution runs in a subshell and
/// `${var:=word}` assigns only when the variable is unset. So a POSIX shell
/// gets the terminal that was current when it started, and a long-lived one
/// re-syncs by sourcing `$MINIMAL_ATTACH_ENV` itself. Documented in
/// `docs/reference/loadouts.md`.
pub(crate) const ATTACH_ENV_POSIX: &str =
    constcat::concat!("/", ATTACH_ENV_BASH_RC_DIR, "/", ATTACH_ENV_POSIX_NAME);

/// POSIX shells: no function, no hook, no trap — just read the published
/// file, if it is there. Sourced once, at shell startup, via `$ENV`.
///
/// Deliberately silent and side-effect free: `$ENV` is read by every
/// interactive POSIX shell in the session (and by some ksh builds for
/// non-interactive ones too), so anything that printed or failed here would
/// surface in places that have nothing to do with a terminal.
const ATTACH_ENV_HOOK_POSIX: &str = constcat::concat!(
    "# ",
    ATTACH_ENV_HOOK_MARKER,
    "\n[ -r ",
    crate::box_runtime::ATTACH_ENV_SH,
    " ] && . ",
    crate::box_runtime::ATTACH_ENV_SH,
    "\n: \n",
);

/// bash: a `DEBUG` trap rather than `PROMPT_COMMAND`.
///
/// `PROMPT_COMMAND` is an environment variable, so a composed one replaces
/// ours and the MOTD recipe this project documented for years ends in
/// `unset PROMPT_COMMAND` — either would silently stop the refresh. A trap is
/// shell state, not environment, so nothing a loadout sets can reach it.
const ATTACH_ENV_HOOK_BASH: &str = constcat::concat!(
    "# ",
    ATTACH_ENV_HOOK_MARKER,
    "\n__minimal_attach_env() {\n    [ -r ",
    crate::box_runtime::ATTACH_ENV_SH,
    " ] && . ",
    crate::box_runtime::ATTACH_ENV_SH,
    "\n    return 0\n}\ntrap '__minimal_attach_env' DEBUG\n",
);

/// The second half of the bash rc: the user's own startup file.
///
/// A session bash is started `--noprofile --rcfile <this file>`, so this is
/// the only place a `~/.bashrc` patched into the session home can be reached
/// from. Without it bash is the one shell whose startup file a loadout patch
/// cannot reach — zsh, fish, and nushell all read theirs out of the session
/// home, which is where patches land, on their own.
///
/// Sourced *after* the hook above, which is the ordering every other shell
/// gets from its own vendor integration point (`/etc/zsh/zshrc` runs before
/// `~/.zshrc`, `vendor_conf.d` before `config.fish`): the refresh is in place
/// before anything a loadout wrote can run, and a `DEBUG` trap set by the
/// user's file is free to take over from there.
///
/// `~/.bashrc` and nothing else, because that is the file bash itself would
/// have read here. The session shell is an interactive *non-login* bash —
/// no `-l`, and an `argv[0]` of `/usr/bin/bash` with no leading `-`, which
/// are the only two ways bash becomes a login shell — and `~/.bashrc` is
/// what such a shell reads. `--rcfile` displaced it; this puts it back.
///
/// The login chain (`~/.bash_profile`, `~/.bash_login`, `~/.profile`) is
/// deliberately NOT read. bash consults those only for a login shell, and it
/// would consult exactly one of them; a shell that reports `shopt
/// login_shell` as off has no business running files whose whole purpose is
/// once-per-login setup (agent startup, unguarded `PATH` prepends). A
/// dotfiles tree that keeps its bash setup in `~/.bash_profile` reaches this
/// shell by naming the patch `dest = ".bashrc"` — the destination is the
/// user's to choose, unlike the layout of a real home directory.
const ATTACH_ENV_BASH_USER_RC: &str = r#"# minimal: user startup file
if [ -n "${HOME:-}" ] && [ -r "$HOME/.bashrc" ]; then
    . "$HOME/.bashrc"
fi
"#;

/// The whole bash rc: the attach-env hook, then the user's startup file.
const ATTACH_ENV_BASH_RC_BODY: &str =
    constcat::concat!(ATTACH_ENV_HOOK_BASH, ATTACH_ENV_BASH_USER_RC);

/// zsh: `precmd`, its per-prompt hook. Installed into the global rc, so it
/// runs before any user `~/.zshrc`, which cannot unset a hook it never saw.
const ATTACH_ENV_HOOK_ZSH: &str = constcat::concat!(
    "# ",
    ATTACH_ENV_HOOK_MARKER,
    "\nautoload -Uz add-zsh-hook\n__minimal_attach_env() {\n    [ -r ",
    crate::box_runtime::ATTACH_ENV_SH,
    " ] && . ",
    crate::box_runtime::ATTACH_ENV_SH,
    "\n}\nadd-zsh-hook precmd __minimal_attach_env\nadd-zsh-hook preexec __minimal_attach_env\n",
);

/// fish: its own syntax, from `vendor_conf.d` — the directory fish reserves
/// for exactly this kind of integration.
const ATTACH_ENV_HOOK_FISH: &str = constcat::concat!(
    "# ",
    ATTACH_ENV_HOOK_MARKER,
    "\nfunction __minimal_attach_env --on-event fish_prompt\n    test -r ",
    crate::box_runtime::ATTACH_ENV_FISH,
    "\n    and source ",
    crate::box_runtime::ATTACH_ENV_FISH,
    "\nend\nfunction __minimal_attach_env_preexec --on-event fish_preexec\n    test -r ",
    crate::box_runtime::ATTACH_ENV_FISH,
    "\n    and source ",
    crate::box_runtime::ATTACH_ENV_FISH,
    "\nend\n",
);

/// nushell: the JSON form, from a vendor autoload dir. Nu cannot `source` a
/// path it does not know at parse time, and a literal path that is missing is
/// a parse error rather than a skipped file, so it reads data instead.
const ATTACH_ENV_HOOK_NU: &str = constcat::concat!(
    "# ",
    ATTACH_ENV_HOOK_MARKER,
    "\n$env.config.hooks.pre_prompt ++= [{||\n    let p = \"",
    crate::box_runtime::ATTACH_ENV_JSON,
    "\"\n    if ($p | path exists) { load-env (open $p) }\n}]\n$env.config.hooks.pre_execution ++= [{||\n    let p = \"",
    crate::box_runtime::ATTACH_ENV_JSON,
    "\"\n    if ($p | path exists) { load-env (open $p) }\n}]\n",
);

/// Where the session's workspace appears *inside* the sandbox. The daemon sees
/// the same directory at [`BoxChannel::working`], so this is the prefix
/// that translates a path typed in the sandbox into one the daemon can write.
pub(crate) const WORKSPACE_ROOT: &str = constcat::concat!("/", sandbox::SESSION_DEFAULT_WD);

/// Where the session's home directory appears inside the sandbox, backed by
/// [`BoxChannel::home`]. The second of the two directories a sandbox path
/// can name on the daemon's side.
pub(crate) const HOME_ROOT: &str = constcat::concat!("/", sandbox::SESSION_HOME);

/// The file name of the per-box identity socket that a host with an
/// identity plane puts in a box. No host this daemon runs on has an
/// identity plane, so the daemon puts no file of this name in any box
/// (BOX-140). Only the tests that check the box for it read the name.
#[cfg(test)]
pub(crate) const IDENTITY_SOCKET_NAME: &str = "identity.sock";

/// The first file named [`IDENTITY_SOCKET_NAME`] under any of `roots`, or
/// `None` when no root holds one. A root that does not exist holds none.
/// Symbolic links are not followed.
#[cfg(test)]
pub(crate) fn find_identity_socket(roots: &[&Path]) -> Option<PathBuf> {
    let mut pending: Vec<PathBuf> = roots.iter().map(|root| root.to_path_buf()).collect();
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if entry.file_name() == IDENTITY_SOCKET_NAME {
                return Some(path);
            }
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                pending.push(path);
            }
        }
    }
    None
}

/// The parameters used to construct an [`Env`].
///
/// Built with [`EnvArgs::new`] plus the `with_*` setters. `state_base_dir` is the
/// host directory backing the session's `/state`; the caller is responsible for
/// its lifetime (e.g. a persistent state dir or a `TempDir` handed to
/// [`Env::with_temp_dirs`]).
#[derive(Debug, Clone)]
pub struct EnvArgs {
    name: String,
    username: Option<String>,

    cwd: DaemonAbsPath,
    home: DaemonAbsPath,
    state_base_dir: DaemonAbsPath,

    packages: Vec<String>,
    patches: Option<EnvPatches>,
    env_vars: Option<BTreeMap<String, EnvVarValue>>,
    ot: Option<OpTracker>,
    network: sandbox::NetPlan,
    /// Weak handle to the owning session actor, wired into the command channel
    /// so in-sandbox `min` commands can drive session side-ops (e.g. builds).
    /// Every session env has one — this `Env` is always session-scoped.
    session: crate::box_actor::WeakBoxHandle,
    /// The owning session's id, for the helper channel's request spans
    /// (`session.id`), beside the box id: host-side facts about who is
    /// asking, never read from the request.
    session_id: Option<boxes::SessionId>,
    /// When true (default), [`Env::build`] consumes package
    /// [`SetupForPackages`] output for `env_vars`/`fs_mappings`.
    /// When false, the caller supplies both via `env_vars` /
    /// `patches` and `state_dirs` is derived from resolved values
    /// shaped `/state/<prefix>`.
    ///
    /// [`SetupForPackages`]: graph::SetupForPackages
    include_package_attr_wiring: bool,

    /// The box's classifier leaf (NET-079): the cgroup its egress verdict is
    /// decided on, and the one every process of the box is placed in.
    /// `None` on a host that places no box — the tree the privileged step
    /// installs is absent — whose environments launch exactly as they did
    /// before the classifier existed, never refused on that ground.
    classifier_leaf: Option<ClassifierLeaf>,

    /// The proxy's root certificate, PEM-encoded, that [`Env::build`] adds
    /// to the box's own trust store (BEP-011). `None` for a box that gets
    /// no root: its trust store is the packages' own.
    root_certificate: Option<String>,
}

impl EnvArgs {
    /// Creates args for an environment named `name`, with working directory
    /// `cwd` and `/state` backed by `state_base_dir`. `session` is a weak
    /// handle to the owning session actor.
    pub fn new(
        name: impl Into<String>,
        cwd: impl Into<DaemonAbsPath>,
        home: impl Into<DaemonAbsPath>,
        state_base_dir: impl Into<DaemonAbsPath>,
        session: crate::box_actor::WeakBoxHandle,
    ) -> Self {
        Self {
            name: name.into(),
            username: None,
            cwd: cwd.into(),
            home: home.into(),
            state_base_dir: state_base_dir.into(),
            packages: Vec::new(),
            patches: None,
            env_vars: None,
            ot: None,
            network: sandbox::NetPlan::host(),
            session,
            session_id: None,
            include_package_attr_wiring: true,
            classifier_leaf: None,
            root_certificate: None,
        }
    }

    /// Names the owning session, so every helper request the box sends is
    /// served in a span that carries `session.id` (the host's knowledge of
    /// the asker, beside `box.id`).
    #[must_use]
    pub fn with_session_id(mut self, session_id: boxes::SessionId) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Opts out of consuming `env_vars` / `fs_mappings` from
    /// `SetupForPackages`. Callers on this path must funnel package
    /// contributions through `.with_resolved_env_vars` /
    /// `.with_patches` themselves.
    #[must_use]
    pub fn without_package_attr_wiring(mut self) -> Self {
        self.include_package_attr_wiring = false;
        self
    }

    /// Sets the packages (by name) that should be available in the environment.
    #[must_use]
    pub fn with_packages<I, S>(mut self, packages: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.packages = packages.into_iter().map(Into::into).collect();
        self
    }

    /// Adds caller-supplied filesystem patches (pinhole mounts) on top of the
    /// ones contributed by packages.
    #[must_use]
    pub fn with_patches(mut self, patches: EnvPatches) -> Self {
        self.patches = Some(patches);
        self
    }

    /// Sets environment variables to apply on top of the package-derived ones.
    #[must_use]
    pub fn with_env_vars(mut self, env_vars: BTreeMap<String, EnvVarValue>) -> Self {
        self.env_vars = Some(env_vars);
        self
    }

    /// Set environment variables from already-resolved values,
    /// wrapping each as [`EnvVarValue::Value`]. Ergonomic shortcut
    /// over `.with_env_vars` for callers with post-gate values.
    #[must_use]
    pub fn with_resolved_env_vars(mut self, env_vars: HashMap<String, String>) -> Self {
        self.env_vars = Some(
            env_vars
                .into_iter()
                .map(|(k, v)| (k, EnvVarValue::Value(v)))
                .collect(),
        );
        self
    }

    /// Sets the operation tracker propagated to downstream operations.
    #[must_use]
    pub fn with_op_tracker(mut self, ot: OpTracker) -> Self {
        self.ot = Some(ot);
        self
    }

    /// Sets the username.
    #[must_use]
    pub fn with_username(mut self, username: String) -> Self {
        self.username = Some(username);
        self
    }

    /// Sets what the session sandbox's network looks like when no provider
    /// decides it — a plan, because that is what the sandbox layer acts on.
    #[must_use]
    pub fn with_network(mut self, plan: sandbox::NetPlan) -> Self {
        self.network = plan;
        self
    }

    /// Places this environment's box in `leaf`, its own classifier leaf
    /// (NET-079) — the cgroup its egress verdict is decided on and the one
    /// every process of the box is placed in. The leaf must already exist:
    /// the launcher creates it before the spawn.
    #[must_use]
    pub fn with_classifier_leaf(mut self, leaf: ClassifierLeaf) -> Self {
        self.classifier_leaf = Some(leaf);
        self
    }

    /// Adds the proxy's root certificate, PEM-encoded, to the box's trust
    /// store (BEP-011): appended to the box's own copy of the CA bundle and
    /// linked in the hashed certificate directory under its subject hash.
    #[must_use]
    pub fn with_root_certificate(mut self, pem: String) -> Self {
        self.root_certificate = Some(pem);
        self
    }
}

/// A fully-owned, session-scoped runtime environment.
///
/// Owns the sandbox and the command-channel actor (which in turn owns the
/// context and graph), so the whole environment can be moved and held for the
/// life of a session. Dropping it tears down the actor and the sandbox (and
/// thus the sandbox's backing files).
pub struct Env {
    sandbox: Sandbox<BridgeChannel>,
    /// The working directory commands in this session start in, resolved from
    /// the sandbox config once at build time. Fixed for the sandbox's lifetime,
    /// so resolving it here keeps the [`command_environment`] accessor total.
    ///
    /// [`command_environment`]: Self::command_environment
    command_cwd: String,
    /// The command-channel actor task. `Some` until [`Drop`] aborts it.
    actor: Option<JoinHandle<()>>,
    /// Variables the channel actor has added since launch; see
    /// [`BoxChannel::runtime_env`].
    runtime_env: RuntimeEnv,
    /// Extra directories kept alive for the environment's lifetime (e.g. a
    /// temporary `/state` directory). Dropped after the sandbox.
    _temp_dirs: Vec<TempDir>,
}

/// Environment variables a *running* session has acquired, on top of the ones
/// it was launched with. Usually happens due to `min add`.
///
/// Shared between [`Env`] and the [`BoxChannel`] actor that learns of them.
#[derive(Clone, Default)]
pub(crate) struct RuntimeEnv(Arc<Mutex<BTreeMap<String, String>>>);

impl RuntimeEnv {
    /// Records a variable the session has just acquired. Last write wins, as it
    /// does in the shell, where a later `export` overrides an earlier one.
    fn record(&self, key: &str, value: &str) {
        self.0
            .lock()
            .expect("runtime env lock is never held across a panic")
            .insert(key.to_string(), value.to_string());
    }

    /// Everything recorded so far.
    fn snapshot(&self) -> BTreeMap<String, String> {
        self.0
            .lock()
            .expect("runtime env lock is never held across a panic")
            .clone()
    }
}

/// Derive the composition-path state-dir set by picking up any
/// resolved env-var value shaped `/state/<single-component>`.
/// Multi-component and empty prefixes are dropped — they can't be
/// distinguished from coincidental `/state/`-prefixed values.
fn state_dirs_from_env_vars(env_vars: &BTreeMap<String, String>) -> BTreeSet<String> {
    env_vars
        .values()
        .filter_map(|v| v.strip_prefix("/state/"))
        .filter(|p| !p.is_empty() && !p.contains('/'))
        .map(str::to_owned)
        .collect()
}

/// Looks up a session package by name in `graph`.
///
/// The lookup [`Env::build`] uses at launch. Session activation's finalize
/// check judges the same names against the same graph's names, and both
/// word an unknown name through [`unknown_package`].
pub(crate) fn session_package(graph: &Graph, name: &str) -> std::io::Result<BuildSpecRef> {
    graph
        .by_name(name)
        .copied()
        .ok_or_else(|| unknown_package(name))
}

/// The error for a session package `name` the graph does not declare,
/// shared by the launch ([`session_package`]) and the finalize check, so
/// both report an unknown name in the same words.
pub(crate) fn unknown_package(name: &str) -> std::io::Error {
    std::io::Error::other(format!("no such package: {name}"))
}

/// The project's `[upstream]` pin: the repo the session's packages come
/// from and the `locked_commit` they are read at. Captured so a refusal
/// for an unknown package can say which commit it judged against, since a
/// package newer than the pin is unknown until `min update` moves it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UpstreamPin {
    /// The `[upstream]` `repo`, as `minimal.toml` writes it.
    pub(crate) repo: String,
    /// The full `locked_commit`.
    pub(crate) locked_commit: String,
}

impl UpstreamPin {
    /// The pin `file` declares. `None` for a `dir` upstream, a git
    /// upstream with no `locked_commit`, or no `[upstream]` at all: none
    /// of those has a commit that `min update` can move.
    pub(crate) fn of(file: &mfile::File) -> Option<Self> {
        match &file.upstream.as_ref()?.link {
            mfile::LinkConfig::Git {
                repo,
                locked_commit: Some(commit),
                ..
            } => Some(Self {
                repo: repo.clone(),
                locked_commit: commit.clone(),
            }),
            _ => None,
        }
    }

    /// The pin in the short form `git log --oneline` prints.
    pub(crate) fn short_commit(&self) -> &str {
        self.locked_commit
            .get(..7)
            .unwrap_or(self.locked_commit.as_str())
    }

    /// The note added once to an unknown-package refusal: where the names
    /// were looked up, and the command that moves the pin.
    pub(crate) fn hint(&self) -> String {
        format!(
            "Packages come from {} at commit {}, the [upstream] pin in minimal.toml. \
             If a package is newer than that commit, run `min update` to move the pin \
             to the head of its branch.",
            self.repo,
            self.short_commit()
        )
    }
}

/// `err` (an unknown-package refusal) with `pin`'s [`UpstreamPin::hint`]
/// appended, or `err` unchanged when the project has no pin.
pub(crate) fn with_upstream_pin(err: std::io::Error, pin: Option<&UpstreamPin>) -> std::io::Error {
    match pin {
        Some(pin) => std::io::Error::new(err.kind(), format!("{err}. {}", pin.hint())),
        None => err,
    }
}

impl Env {
    /// Build a runtime environment. Resolves and locally builds the
    /// requested packages (plus `bash`/`socat` for the `min`
    /// helper), assembles the rootfs, and spawns the command
    /// channel actor.
    pub async fn build(mut ctx: Context, mut graph: Graph, args: EnvArgs) -> std::io::Result<Self> {
        // NET-155: the leaf the launcher created for this box places every
        // package build this env starts — the missing packages below and the
        // in-box installs later — so the box's egress verdict decides what
        // they reach. It replaces any leaf the context carried, because the
        // launch's leaf is the one the box runs in now.
        if let Some(leaf) = args.classifier_leaf.clone() {
            ctx = ctx.with_classifier_leaf(leaf);
        }
        // Resolve the requested package names to top-levels, then ensure the
        // helper's dependencies (`bash`, `socat`) are present.
        graph.top_levels = args
            .packages
            .iter()
            .map(|n| session_package(&graph, n))
            .collect::<Result<_, _>>()
            .map_err(|e| with_upstream_pin(e, UpstreamPin::of(ctx.minimal_file()).as_ref()))?;
        for helper_dep in ["bash", "socat"] {
            if let Some(bsr) = graph.by_name(helper_dep).copied()
                && !graph.top_levels.contains(&bsr)
            {
                graph.top_levels.push(bsr);
            }
        }

        // Ensure all transitive runtime deps are built and present locally.
        let cache = ctx.local_cache();
        let transitives = Transitives::for_toplevels(&graph, graph.top_levels.clone(), false);
        let all_built = transitives
            .keys()
            .all(|bsr| cache.read_dir(&graph.spec_hash(bsr)).is_ok());
        if !all_built {
            tracing::trace!("missing local packages, building session env");
            match ctx.classifier_leaf() {
                Some(leaf) => tracing::info!(
                    box_name = %args.name,
                    leaf = %leaf.dir().display(),
                    "starting the box's missing package builds in the box's classifier leaf",
                ),
                None if ctx.box_network().is_some() => tracing::info!(
                    box_name = %args.name,
                    "starting the box's missing package builds on the box's own network, \
                     under the box's egress rules",
                ),
                None => tracing::info!(
                    box_name = %args.name,
                    "starting the box's missing package builds in the daemon's own cgroup, \
                     with no per-box egress enforcement, because the box has none",
                ),
            }
            // NET-155: a build the box's egress rules refused names the
            // destination and the box before the build's own error, as the
            // build side operation's does. The launch knows the box's name.
            let placement = crate::box_ops::BuildPlacement {
                box_name: args.name.clone(),
                leaf: ctx.classifier_leaf().cloned(),
                network: ctx.box_network().cloned(),
            };
            let (log_tx, log_rx) = futures::channel::mpsc::unbounded();
            // Reduce the `!Send` error (`mctx::Error` holds nickel `Rc`s) to
            // a string in the same poll it appears, so `join!` never holds it.
            let build = async {
                match ctx.build_graph(&graph, false, Some(log_tx)).await {
                    Ok(()) => None,
                    Err(e) => Some(e.to_string()),
                }
            };
            // The tap names the box for a refused source, and the package
            // and the host for one it could not connect to
            // (`BuildTap::failure`); the error is taken as it hands it back.
            tapped_build(build, log_rx, &placement)
                .await
                .map_err(std::io::Error::other)?;
        }

        // Collect the package-derived wiring and merge caller-supplied
        // overrides. On the composition path the caller funnels
        // `env_state_wiring` and fs mappings through their own args,
        // so we skip `SetupForPackages`'s output for those fields.
        // `needs_dns` / `needs_internet` are ignored on either
        // branch — they aren't user-gate-able, so if we add a new
        // `SetupForPackages` field make sure to route it through
        // the same branch as `env_vars`/`fs_mappings`, not with these.
        let (legacy_state_dirs, mut pkg_env_vars) = if args.include_package_attr_wiring {
            let SetupForPackages {
                fs_mappings: _,
                fs_mapping_packages: _,
                needs_dns: _,
                needs_internet: _,
                state_dirs,
                env_vars,
            } = SetupForPackages::build(&graph, transitives.keys())
                .map_err(std::io::Error::other)?;
            (state_dirs, env_vars)
        } else {
            (BTreeSet::<String>::new(), BTreeMap::new())
        };

        if let Some(vars) = &args.env_vars {
            for (k, v) in vars {
                let value = match v {
                    EnvVarValue::Value(v) => v.clone(),
                    EnvVarValue::Inherit => std::env::var(k).map_err(|e| {
                        std::io::Error::other(format!("inheriting environment variable '{k}': {e}"))
                    })?,
                };
                pkg_env_vars.insert(k.clone(), value);
            }
        }

        // Composition path: state_dirs come from the resolved
        // env-var values shaped `/state/<prefix>`. Matches what
        // `SetupForPackages` produces for `env_state_wiring` and
        // means a session that has been correctly gated (e.g. a
        // `deny` policy on some GOCACHE env var) also skips creating
        // its state dir — no orphaned `/state` slot for a var the
        // session doesn't actually have.
        let state_dirs: BTreeSet<String> = if args.include_package_attr_wiring {
            legacy_state_dirs
        } else {
            state_dirs_from_env_vars(&pkg_env_vars)
        };

        let rootfs_dirs = transitives
            .keys()
            .map(|bsr| cache.read_dir(&graph.spec_hash(bsr)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| std::io::Error::other(format!("loading dependency: {e}")))?;
        // BEP-011: the trust variables of a box with the proxy's root, below
        // every variable the caller set, so a box spec keeps its own value.
        // The bundle variables follow whether the packages ship a bundle,
        // because the box's variables are fixed before its rootfs exists.
        let ships_bundle = args.root_certificate.is_some()
            && layers_ship_ca_bundle(rootfs_dirs.iter().map(|ce| ce.path()));
        crate::box_runtime::layer_trust_env(
            &mut pkg_env_vars,
            args.root_certificate.is_some(),
            ships_bundle,
        );

        let config = Config::new(args.name.clone())
            .with_session_dirs(
                args.home.as_utf8_path().as_std_path().to_path_buf(),
                args.cwd.as_utf8_path().as_std_path().to_path_buf(),
            )
            //.with_wd(args.cwd.as_utf8_path(), false, patch.into())
            .with_rootfs(
                rootfs_dirs
                    .into_iter()
                    .map(|ce| SandboxMapped::Dir(ce.path().to_path_buf())),
            )
            .with_state_dir(args.state_base_dir.as_utf8_path())
            .with_env_vars(pkg_env_vars.into_iter())
            .with_plan(args.network)
            .with_hostname(args.name.clone())
            .with_daemon_id(ctx.daemon_id().unwrap()) // Always set under minimald
            .with_username(args.username.unwrap_or_else(|| "user".to_string()));
        // NET-080: the box's own id, for the fetch records its installs
        // produce — the leaf's name, the same id the tree's rules match,
        // when the host placed it in one; else the session's name. Read
        // before the leaf is moved into the sandbox config below.
        let box_id = args
            .classifier_leaf
            .as_ref()
            .and_then(|leaf| {
                leaf.dir()
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
            })
            .unwrap_or_else(|| args.name.clone());
        // NET-079: the leaf the launcher created before this build, so the
        // sandbox keeps the host's cgroup mounts out of a leaf-bearing box and
        // names the leaf it entered on its launch log line. `None` on a host
        // that places no box: the config above is the whole story, exactly as
        // it was before the classifier existed.
        let classifier_leaf = args.classifier_leaf.clone();
        let config = match args.classifier_leaf {
            Some(leaf) => config.with_classifier_leaf(leaf),
            None => config,
        };

        // Wire up the channel actor and build the sandbox around the bridge.
        let (tx, rx) = mpsc::channel(8);
        let base_dir = ctx.tasks_base_dir();
        let mut sandbox = config
            .build(base_dir, BridgeChannel { tx })
            .await
            .map_err(sandbox_err_to_io)?;

        for want_dir in &state_dirs {
            std::fs::create_dir_all(args.state_base_dir.as_utf8_path().join(want_dir))
                .map_err(std::io::Error::other)?;
        }
        install_min_helpers(&sandbox.rootfs()).map_err(std::io::Error::other)?;
        // BEP-011: the root goes into this box's own trust store, or the box
        // keeps the packages' store unchanged.
        match &args.root_certificate {
            Some(pem) => {
                let installed = install_root_certificate(&sandbox.rootfs(), pem)?;
                if installed.bundle {
                    tracing::debug!(
                        session_id = ?args.session_id,
                        box_name = %args.name,
                        link = %installed.link,
                        bundle_variables = ships_bundle,
                        "injected the proxy's root certificate into the box's trust store"
                    );
                } else {
                    tracing::debug!(
                        session_id = ?args.session_id,
                        box_name = %args.name,
                        link = %installed.link,
                        bundle_variables = ships_bundle,
                        "injected the proxy's root certificate into the box's trust store; \
                         the packages ship no CA bundle, so the box has no bundle and \
                         only NODE_EXTRA_CA_CERTS names the root"
                    );
                }
            }
            None => tracing::debug!(
                session_id = ?args.session_id,
                box_name = %args.name,
                "injected no proxy root certificate into the box's trust store"
            ),
        }
        sandbox.keep_dir(false);
        let command_cwd = sandbox.command_cwd().map_err(sandbox_err_to_io)?;

        let runtime_env = RuntimeEnv::default();
        let channel = BoxChannel {
            rootfs: DaemonAbsPath::try_new(
                Utf8PathBuf::try_from(sandbox.rootfs().to_path_buf()).unwrap(),
            )
            .unwrap(),
            name: args.name.clone(),
            runtime_env: runtime_env.clone(),
            state_dir: args.state_base_dir.clone(),
            working: args.cwd.clone(),
            home: args.home.clone(),
            has_packages: transitives.keys().copied().collect(),
            box_id,
            classifier_leaf,
            session_id: args.session_id,
            ot: args.ot.clone(),
            session: args.session.clone(),
            ctx,
            graph,
            rx,
        };
        // The actor serves the box's in-session `min` for the env's life, past
        // the launch that built it: a root of its own, linked to the launch.
        let actor = crate::traced::spawn_detached(
            tracing::info_span!(parent: None, "session.env"),
            channel.run(),
        );

        Ok(Self {
            sandbox,
            command_cwd,
            actor: Some(actor),
            runtime_env,
            _temp_dirs: Vec::new(),
        })
    }

    /// Gives ownership of additional temporary directories to this environment,
    /// so they are cleaned up when the environment is dropped (e.g. a temporary
    /// `/state` directory).
    pub fn with_temp_dirs<I: IntoIterator<Item = TempDir>>(mut self, dirs: I) -> Self {
        self._temp_dirs.extend(dirs);
        self
    }

    /// Creates a fresh container in this environment's sandbox.
    pub fn container(&mut self, plan: &sandbox::NetPlan) -> std::io::Result<Container> {
        self.sandbox.new_container(plan).map_err(sandbox_err_to_io)
    }

    /// The host-side twin of the report file a leaf-bearing box's pre-exec
    /// closure writes into its `/run`: the same file, through the sandbox's
    /// read-write `/run` bind, named by the leaf. For the launch to read
    /// after the spawn — which cover the box took over its classifier tree,
    /// or the errno that killed the closure before the program ran — so it
    /// is forwarded from the sandbox, which owns the directory the box's
    /// `/run` is bound from and cannot have its path precomputed by a caller
    /// (the base directory is named by [`Env::build`], per launch).
    ///
    /// [`Env::build`]: crate::env::Env::build
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn closure_report_path(
        &self,
        leaf: &sandbox::config::ClassifierLeaf,
    ) -> std::path::PathBuf {
        self.sandbox.closure_report_path(leaf)
    }

    /// Holds the program of every command `container` spawns at a start gate
    /// until the returned gate is released; see [`sandbox::Sandbox::hold_start`].
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn hold_start(
        &self,
        container: &mut Container,
    ) -> std::io::Result<sandbox::StartGate> {
        self.sandbox
            .hold_start(container)
            .map_err(sandbox_err_to_io)
    }

    /// The assembled session rootfs on the daemon's filesystem.
    ///
    /// Exposed so the launcher can answer "is this shell installed in
    /// this session" before it spawns one
    /// ([`crate::attach_shell::resolve`]) — the same question
    /// [`install_min_helpers`] answers about directories it writes into.
    /// Only meaningful once [`Env::build`] has returned: the rootfs is
    /// what that assembles.
    ///
    /// Read only by the real `SandboxLauncher` (`cfg(not(test))`), which
    /// the mock launcher stands in for under test.
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn rootfs(&self) -> std::path::PathBuf {
        self.sandbox.rootfs()
    }

    /// Builds a command to run `program` inside the given container.
    pub fn command<I, S>(
        &mut self,
        container: &Container,
        program: &str,
        args: I,
    ) -> std::io::Result<hakoniwa::Command>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.sandbox
            .command(container, program, args, [("", ""); 0])
            .map_err(sandbox_err_to_io)
    }

    /// The working directory and environment a command should run with in this
    /// session **as it stands now** — `/workbench`, the composed session
    /// variables, and anything `min add` has installed since launch.
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn command_environment(&self) -> crate::box_runtime::BoxEnvironment {
        let mut vars = self.sandbox.command_env();
        vars.extend(self.runtime_env.snapshot());
        crate::box_runtime::BoxEnvironment {
            cwd: self.command_cwd.clone(),
            vars,
        }
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        // Abort the actor first: any in-flight handler is cancelled and the
        // owned context/graph dropped, so nothing keeps reading from the sandbox
        // files that the sandbox's own `Drop` (run when `sandbox` is dropped
        // after this) is about to remove.
        if let Some(actor) = self.actor.take() {
            actor.abort();
        }
    }
}

/// Converts an [`mctx::Error`] into an [`std::io::Error`], preserving its
/// (richly-formatted) `Display` message.
fn err_to_io(e: Error) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// Converts a [`sandbox::Error`] into an [`std::io::Error`].
fn sandbox_err_to_io(e: sandbox::Error) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// Installs the `min` helper script and the `etc` directory into a rootfs,
/// along with the per-attach environment hooks ([`install_attach_env_hooks`]).
fn install_min_helpers(rootfs: &Path) -> std::io::Result<()> {
    let usr_bin = rootfs.join("usr").join("bin");
    std::fs::create_dir_all(&usr_bin)?;
    std::fs::write(usr_bin.join("min"), MIN_SCRIPT)?;
    std::fs::set_permissions(usr_bin.join("min"), Permissions::from_mode(0o0755))?;
    std::fs::create_dir_all(rootfs.join("etc"))?;
    install_attach_env_hooks(rootfs)?;
    Ok(())
}

/// Installs the shell hooks that re-read the per-attach environment (`TERM`)
/// into a rootfs.
///
/// These live in the *rootfs*, at each shell's own vendor/system integration
/// point, for two reasons. They are outside the session home, which is where
/// loadout patches land — so nothing a loadout does can collide with them or
/// remove them. And they are installed by the daemon for every session, so no
/// loadout or project author has to know the mechanism exists, which a
/// composed `PROMPT_COMMAND` recipe would have required.
///
/// One file per shell because there is no shell-agnostic hook: each names its
/// own events. Each installs *two* — one at the prompt and one before a
/// command runs — because they answer different questions. The prompt hook
/// keeps a shell that is sitting idle current; the pre-execution hook is what
/// makes the very first command typed at a prompt drawn *before* the attach
/// see the new terminal, rather than the value that was in force when that
/// prompt was drawn. bash needs only the `DEBUG` trap, which already fires
/// before every command.
///
/// bash's file is the odd one: this build has no `/etc/bash.bashrc`, so there
/// is no integration point bash reads by itself and the session shell is
/// pointed at [`ATTACH_ENV_BASH_RC`] with `--rcfile` instead. That makes it
/// the only startup file a session bash reads, so it carries the user's own
/// too ([`ATTACH_ENV_BASH_USER_RC`]) — the file the *shell's* rc would have
/// sourced, had bash been reading one.
///
/// Every hook hard-codes the file path rather than reading
/// `$MINIMAL_ATTACH_ENV`: the variable is a convenience for anyone scripting
/// against this, and a session whose composition happened to set it must not
/// be able to break the refresh.
fn install_attach_env_hooks(rootfs: &Path) -> std::io::Result<()> {
    // (integration dir, file name, contents)
    let hooks: [(&Path, &str, &str); 5] = [
        (
            Path::new(ATTACH_ENV_BASH_RC_DIR),
            ATTACH_ENV_BASH_RC_NAME,
            ATTACH_ENV_BASH_RC_BODY,
        ),
        (
            Path::new(ATTACH_ENV_BASH_RC_DIR),
            ATTACH_ENV_POSIX_NAME,
            ATTACH_ENV_HOOK_POSIX,
        ),
        (Path::new("etc/zsh"), "zshrc", ATTACH_ENV_HOOK_ZSH),
        (
            Path::new("usr/share/fish/vendor_conf.d"),
            "00-minimal-attach-env.fish",
            ATTACH_ENV_HOOK_FISH,
        ),
        (
            Path::new("usr/share/nushell/vendor/autoload"),
            "00-minimal-attach-env.nu",
            ATTACH_ENV_HOOK_NU,
        ),
    ];

    for (dir, name, body) in hooks {
        let dir = rootfs.join(dir);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(name);
        // zsh's global rc is a file its own package may ship, so append rather
        // than overwrite; the others are namespaced files nothing else owns.
        // Appending is safe on a fresh rootfs and idempotent per launch, since
        // each session composes its rootfs anew.
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        if existing.contains(ATTACH_ENV_HOOK_MARKER) {
            continue;
        }
        std::fs::write(&path, format!("{existing}{body}"))?;
    }
    Ok(())
}

/// Adds the proxy's root certificate `pem` to the trust store of the box
/// whose rootfs is `rootfs` (BEP-011), in both standard forms, beside the
/// system roots the box's packages ship:
///
/// - the root alone, at [`BOX_ROOT_CERTIFICATE`];
/// - the box's own copy of the CA bundle at [`BOX_CA_BUNDLE`]: the bundle
///   the packages ship, with the root appended. When the packages ship no
///   bundle, no bundle is written: a bundle with the root alone would
///   replace the public roots for a tool that reads it;
/// - a link `<subject hash>.<n>` to the root in [`BOX_CA_DIR`], the name
///   OpenSSL looks a certificate up by in a hashed directory.
///
/// The rootfs is hardlinked from the package store, so a file it holds can
/// be the store's own. Each file is written as a new file in place of the
/// one it replaces, and never through it, so no other box built from the
/// same packages sees the root. A link in the rootfs resolves inside the
/// rootfs, never on the daemon's side. Returns the link's name, and
/// whether the box has a bundle.
///
/// [`BOX_ROOT_CERTIFICATE`]: crate::box_runtime::BOX_ROOT_CERTIFICATE
/// [`BOX_CA_BUNDLE`]: crate::box_runtime::BOX_CA_BUNDLE
/// [`BOX_CA_DIR`]: crate::box_runtime::BOX_CA_DIR
pub(crate) fn install_root_certificate(rootfs: &Path, pem: &str) -> std::io::Result<RootInstall> {
    use crate::box_runtime::{BOX_CA_BUNDLE, BOX_CA_DIR, BOX_ROOT_CERTIFICATE};
    let unusable = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the Box Egress Proxy's root certificate is not a valid certificate",
        )
    };
    // Only the one certificate block reaches the store: text around it,
    // or a second block, would add trust the checks below never read.
    let block = certificate_block(pem).ok_or_else(unusable)?;
    let der = certificate_der(block).ok_or_else(unusable)?;
    let hash = trust_store::subject_hash(&der).ok_or_else(unusable)?;
    let mut text = block.to_string();
    text.push('\n');

    let dir = resolve_in_rootfs(rootfs, Path::new(BOX_CA_DIR), true)?
        .expect("a created directory resolves");
    let file_name = |box_path: &str| {
        Path::new(box_path)
            .file_name()
            .expect("a trust-store path names a file")
            .to_owned()
    };
    let root_name = file_name(BOX_ROOT_CERTIFICATE);
    replace_file(&dir.join(&root_name), text.as_bytes())?;

    let bundle_name = file_name(BOX_CA_BUNDLE);
    let bundle = match resolve_in_rootfs(rootfs, Path::new(BOX_CA_BUNDLE), false)? {
        Some(path) if path.is_file() => {
            let mut bundle = std::fs::read(path)?;
            if !bundle.is_empty() && !bundle.ends_with(b"\n") {
                bundle.push(b'\n');
            }
            bundle.extend_from_slice(text.as_bytes());
            replace_file(&dir.join(&bundle_name), &bundle)?;
            true
        }
        _ => false,
    };

    // A system root can hold the same subject hash: the first free suffix
    // is the root's, as `c_rehash` numbers a collision.
    for n in 0u32.. {
        let name = format!("{hash:08x}.{n}");
        let link = dir.join(&name);
        match std::fs::symlink_metadata(&link) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::os::unix::fs::symlink(&root_name, &link)?;
                return Ok(RootInstall { link: name, bundle });
            }
            Err(e) => return Err(e),
            Ok(_) if std::fs::read_link(&link).is_ok_and(|to| to == Path::new(&root_name)) => {
                return Ok(RootInstall { link: name, bundle });
            }
            Ok(_) => {}
        }
    }
    unreachable!("a directory cannot hold a link for every suffix")
}

/// What [`install_root_certificate`] wrote into a box's trust store.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RootInstall {
    /// The name of the root's link in the hashed directory.
    pub(crate) link: String,
    /// Whether the box has its own CA bundle with the root appended. False
    /// when the packages ship no bundle, so the box has none.
    pub(crate) bundle: bool,
}

/// Whether the packages in `layers`, the directories a box's rootfs is
/// built from, ship a CA bundle at [`BOX_CA_BUNDLE`]. Read before the
/// rootfs exists, because the box's variables are fixed when it is built.
/// A link resolves inside the layer that holds it.
///
/// [`BOX_CA_BUNDLE`]: crate::box_runtime::BOX_CA_BUNDLE
fn layers_ship_ca_bundle<'a>(layers: impl IntoIterator<Item = &'a Path>) -> bool {
    let bundle = Path::new(crate::box_runtime::BOX_CA_BUNDLE);
    layers.into_iter().any(|layer| {
        resolve_in_rootfs(layer, bundle, false)
            .ok()
            .flatten()
            .is_some_and(|path| path.is_file())
    })
}

/// Writes `bytes` to `path` as a new file, after it removes what `path`
/// held. A hardlink to the package store, or a link to another file, loses
/// only its name in this rootfs, and its target stays unchanged.
fn replace_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    std::fs::write(path, bytes)
}

/// Resolves the box path `box_path` to its file on the daemon's side of
/// `rootfs`, as the box sees it: every link resolves inside `rootfs`, and a
/// `..` stops at its root. A missing component is created as a directory
/// when `create` is true. Otherwise the path resolves to `None`.
fn resolve_in_rootfs(
    rootfs: &Path,
    box_path: &Path,
    create: bool,
) -> std::io::Result<Option<PathBuf>> {
    use std::path::Component;
    fn push_components(stack: &mut Vec<std::ffi::OsString>, path: &Path) {
        for component in path.components().rev() {
            match component {
                Component::Normal(name) => stack.push(name.to_owned()),
                Component::ParentDir => stack.push("..".into()),
                Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
            }
        }
    }
    let mut stack = Vec::new();
    push_components(&mut stack, box_path);
    let mut current = rootfs.to_path_buf();
    let mut hops = 0u32;
    while let Some(name) = stack.pop() {
        if name == ".." {
            if current != rootfs {
                current.pop();
            }
            continue;
        }
        let next = current.join(&name);
        match std::fs::symlink_metadata(&next) {
            Ok(meta) if meta.file_type().is_symlink() => {
                hops += 1;
                if hops > 40 {
                    return Err(std::io::Error::other(format!(
                        "too many links in {} inside the box",
                        box_path.display()
                    )));
                }
                let target = std::fs::read_link(&next)?;
                if target.is_absolute() {
                    current = rootfs.to_path_buf();
                }
                push_components(&mut stack, &target);
            }
            Ok(_) => current = next,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && create => {
                std::fs::create_dir(&next)?;
                current = next;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        }
    }
    Ok(Some(current))
}

/// The text of the one certificate block in `pem`, from its `BEGIN` line
/// through its `END` line, or `None` when `pem` holds no block or more
/// than one.
fn certificate_block(pem: &str) -> Option<&str> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    if pem.matches(BEGIN).count() != 1 {
        return None;
    }
    let start = pem.find(BEGIN)?;
    let end = start + pem[start..].find(END)? + END.len();
    Some(&pem[start..end])
}

/// Whether `pem` holds exactly one certificate block with a base64 body
/// that is not empty. The create gate of a brokered secret reads this
/// (BOX-081), so an empty or malformed value does not count as the
/// proxy's root certificate.
pub(crate) fn is_one_certificate(pem: &str) -> bool {
    certificate_block(pem)
        .and_then(certificate_der)
        .is_some_and(|der| !der.is_empty())
}

/// The DER bytes of the first certificate in `pem`, or `None` when `pem`
/// holds no certificate block or its body is not base64.
fn certificate_der(pem: &str) -> Option<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let body = pem.split_once(BEGIN)?.1.split_once(END)?.0;
    trust_store::base64_decode(body)
}

/// The pieces of OpenSSL's hashed-directory lookup that [`install_root_certificate`]
/// needs: the subject hash of a certificate, as `openssl x509 -subject_hash`
/// prints it. `minimald` holds no X.509 or SHA-1 library, and a hashed
/// directory needs only this one value, so the reading is local and small.
mod trust_store {
    /// One DER element: its tag, its content, and the bytes after it.
    fn element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
        let (&tag, rest) = input.split_first()?;
        if tag & 0x1f == 0x1f {
            return None;
        }
        let (&first, rest) = rest.split_first()?;
        let (len, rest) = if first < 0x80 {
            (usize::from(first), rest)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 4 || rest.len() < count {
                return None;
            }
            let (bytes, rest) = rest.split_at(count);
            (
                bytes
                    .iter()
                    .fold(0usize, |len, &b| (len << 8) | usize::from(b)),
                rest,
            )
        };
        if rest.len() < len {
            return None;
        }
        let (content, rest) = rest.split_at(len);
        Some((tag, content, rest))
    }

    /// The DER encoding of one element with `tag` and `content`.
    fn encode(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 0x80 {
            out.push(u8::try_from(len).expect("checked above"));
        } else {
            let bytes: Vec<u8> = len
                .to_be_bytes()
                .into_iter()
                .skip_while(|&b| b == 0)
                .collect();
            out.push(0x80 | u8::try_from(bytes.len()).expect("a length has at most 8 bytes"));
            out.extend(bytes);
        }
        out.extend_from_slice(content);
        out
    }

    /// The content of the certificate's subject `Name`.
    fn subject(der: &[u8]) -> Option<&[u8]> {
        const SEQUENCE: u8 = 0x30;
        let (SEQUENCE, certificate, _) = element(der)? else {
            return None;
        };
        let (SEQUENCE, tbs, _) = element(certificate)? else {
            return None;
        };
        let mut rest = tbs;
        // The explicit version is optional; then the serial, the signature
        // algorithm, the issuer and the validity come before the subject.
        if rest.first() == Some(&0xa0) {
            rest = element(rest)?.2;
        }
        for _ in 0..4 {
            rest = element(rest)?.2;
        }
        let (SEQUENCE, subject, _) = element(rest)? else {
            return None;
        };
        Some(subject)
    }

    /// An attribute value in OpenSSL's canonical form: a string type is
    /// re-encoded as a `UTF8String` with ASCII letters lowercased, leading
    /// and trailing whitespace removed and each inner run of whitespace
    /// made one space. Any other type keeps its encoding.
    fn canonical_value(tag: u8, content: &[u8], whole: &[u8]) -> Option<Vec<u8>> {
        let text: String = match tag {
            // UTF8String
            0x0c => std::str::from_utf8(content).ok()?.to_string(),
            // BMPString
            0x1e => content
                .chunks(2)
                .map(|c| match c {
                    [hi, lo] => char::from_u32(u32::from(u16::from_be_bytes([*hi, *lo]))),
                    _ => None,
                })
                .collect::<Option<String>>()?,
            // UniversalString
            0x1c => content
                .chunks(4)
                .map(|c| {
                    <[u8; 4]>::try_from(c)
                        .ok()
                        .and_then(|b| char::from_u32(u32::from_be_bytes(b)))
                })
                .collect::<Option<String>>()?,
            // PrintableString, T61String, IA5String, VisibleString: one
            // byte for one character.
            0x13 | 0x14 | 0x16 | 0x1a => content.iter().map(|&b| char::from(b)).collect(),
            _ => return Some(whole.to_vec()),
        };
        let space = |b: &u8| matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r');
        let bytes = text.as_bytes();
        let start = bytes.iter().position(|b| !space(b)).unwrap_or(bytes.len());
        let end = bytes
            .iter()
            .rposition(|b| !space(b))
            .map_or(start, |i| i + 1);
        let mut out = Vec::with_capacity(end - start);
        let mut in_space = false;
        for b in &bytes[start..end] {
            if space(b) {
                if !in_space {
                    out.push(b' ');
                }
                in_space = true;
            } else {
                out.push(b.to_ascii_lowercase());
                in_space = false;
            }
        }
        Some(encode(0x0c, &out))
    }

    /// The canonical encoding of a subject's content, as OpenSSL hashes it:
    /// each relative distinguished name as a DER `SET` of canonical
    /// attributes, in order, with no outer `SEQUENCE`.
    fn canonical_name(mut name: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        while !name.is_empty() {
            let (0x31, mut set, rest) = element(name)? else {
                return None;
            };
            name = rest;
            let mut attributes = Vec::new();
            while !set.is_empty() {
                let (0x30, attribute, rest) = element(set)? else {
                    return None;
                };
                set = rest;
                let (0x06, _, value) = element(attribute)? else {
                    return None;
                };
                let oid = &attribute[..attribute.len() - value.len()];
                let (tag, content, tail) = element(value)?;
                if !tail.is_empty() {
                    return None;
                }
                let mut encoded = oid.to_vec();
                encoded.extend(canonical_value(tag, content, value)?);
                attributes.push(encode(0x30, &encoded));
            }
            // DER orders a SET OF by its members' encodings.
            attributes.sort();
            out.extend(encode(0x31, &attributes.concat()));
        }
        Some(out)
    }

    /// The subject hash of the DER certificate `der`: the first four bytes
    /// of the SHA-1 of its canonical subject, read little-endian. `None`
    /// when `der` is not a certificate this can read.
    pub(super) fn subject_hash(der: &[u8]) -> Option<u32> {
        let digest = sha1(&canonical_name(subject(der)?)?);
        Some(u32::from_le_bytes([
            digest[0], digest[1], digest[2], digest[3],
        ]))
    }

    /// SHA-1 (FIPS 180-4). Used only to name a link, never to check one.
    fn sha1(data: &[u8]) -> [u8; 20] {
        let mut h: [u32; 5] = [
            0x6745_2301,
            0xefcd_ab89,
            0x98ba_dcfe,
            0x1032_5476,
            0xc3d2_e1f0,
        ];
        let mut message = data.to_vec();
        let bits = u64::try_from(data.len()).expect("a length fits in 64 bits") * 8;
        message.push(0x80);
        while message.len() % 64 != 56 {
            message.push(0);
        }
        message.extend(bits.to_be_bytes());
        for block in message.chunks(64) {
            let mut w = [0u32; 80];
            for (i, word) in block.chunks(4).enumerate() {
                w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
            }
            for i in 16..80 {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            }
            let [mut a, mut b, mut c, mut d, mut e] = h;
            for (i, word) in w.iter().enumerate() {
                let (f, k) = match i {
                    0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
                    20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                    40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                    _ => (b ^ c ^ d, 0xca62_c1d6),
                };
                let t = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(*word);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = t;
            }
            for (state, value) in h.iter_mut().zip([a, b, c, d, e]) {
                *state = state.wrapping_add(value);
            }
        }
        let mut out = [0u8; 20];
        for (chunk, word) in out.chunks_mut(4).zip(h) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Standard base64, padding optional, whitespace ignored. `None` for
    /// any other character.
    pub(super) fn base64_decode(text: &str) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut acc = 0u32;
        let mut bits = 0u32;
        for b in text.bytes() {
            let value = match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => break,
                b' ' | b'\t' | b'\r' | b'\n' => continue,
                _ => return None,
            };
            acc = (acc << 6) | u32::from(value);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push(u8::try_from((acc >> bits) & 0xff).expect("masked to a byte"));
            }
        }
        Some(out)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn sha1_matches_the_standard_vectors() {
            assert_eq!(
                hex::encode(sha1(b"abc")),
                "a9993e364706816aba3e25717850c26c9cd0d89d"
            );
            assert_eq!(
                hex::encode(sha1(b"")),
                "da39a3ee5e6b4b0d3255bfef95601890afd80709"
            );
            assert_eq!(
                hex::encode(sha1(
                    b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
                )),
                "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
            );
        }
    }
}

/// A request forwarded from the synchronous listener to the async actor.
struct ChannelRequest {
    /// The single request line read by the listener (`method%data`).
    line: String,
    /// The line as the box sent it, when it was not valid UTF-8 and `line`
    /// is its lossy decode. `None` for a valid line.
    raw: Option<Vec<u8>>,
    /// An owned clone of the client connection, written to by the handler.
    stream: UnixStream,
}

/// The synchronous [`sandbox::Channel`] that bridges the listener thread to the
/// async [`BoxChannel`] actor. It does no work itself beyond handing each
/// request off; the connection clone stays open in the actor until the handler
/// finishes, at which point dropping it closes the connection and the client's
/// `socat` sees EOF.
struct BridgeChannel {
    tx: mpsc::Sender<ChannelRequest>,
}

impl sandbox::Channel for BridgeChannel {
    fn handle(&mut self, stream: &mut UnixStream, line: &str, _rootfs: &Path) {
        self.forward(stream, line, None);
    }

    fn handle_lossy(&mut self, stream: &mut UnixStream, line: &str, raw: &[u8], _rootfs: &Path) {
        self.forward(stream, line, Some(raw.to_vec()));
    }
}

impl BridgeChannel {
    fn forward(&mut self, stream: &mut UnixStream, line: &str, raw: Option<Vec<u8>>) {
        let stream = match stream.try_clone() {
            Ok(s) => s,
            Err(e) => {
                let _ = writeln!(stream, "error: internal: cloning connection failed: {e}");
                return;
            }
        };
        // `blocking_send` is correct here: the listener runs on its own OS
        // thread, not a runtime worker. It only blocks if the actor is many
        // commands behind, which doesn't happen for interactive `min` use.
        if let Err(e) = self.tx.blocking_send(ChannelRequest {
            line: line.to_string(),
            raw,
            stream,
        }) {
            let mut stream = e.0.stream;
            let _ = writeln!(stream, "error: session command handler unavailable");
        }
    }
}

/// The async command-channel actor.
///
/// Owns the session's [`Context`] and [`Graph`] and processes one request at a
/// time, so all of its handlers can be plain `async fn`s.
struct BoxChannel {
    ctx: Context,
    graph: Graph,
    /// The box's name, as the environment was built with it — the one fact
    /// about the box that outlives its record, so the paths the record read
    /// fails on can still say whose request they were in the one line every
    /// expose request owes the log.
    name: String,
    /// The sandbox rootfs, into which freshly-installed packages are hardlinked.
    rootfs: DaemonAbsPath,
    /// The host directory backing `/state`.
    state_dir: DaemonAbsPath,
    /// The host directory backing `/workbench`.
    working: DaemonAbsPath,
    /// The host directory backing `/home`.
    home: DaemonAbsPath,

    /// Packages already materialized into the rootfs.
    has_packages: HashSet<BuildSpecRef>,
    /// NET-080: the box this channel's installs are made for, named the way
    /// the classifier tree names it — the box's leaf when the host placed it
    /// in one, else the session's name — so the daemon's own fetches are
    /// recorded with the box that asked for them.
    box_id: String,
    /// The box's classifier leaf (NET-155): the in-box patched build runs in
    /// it, so the box's egress verdict decides what the build can reach.
    /// `None` on a host that places no box.
    classifier_leaf: Option<ClassifierLeaf>,
    /// The owning session's id ([`EnvArgs::with_session_id`]); `None` for
    /// an env built without one (tests).
    session_id: Option<boxes::SessionId>,
    ot: Option<OpTracker>,
    /// Weak handle to the owning session actor, used by session-scoped commands
    /// (e.g. `min build`) to drive side-ops.
    session: crate::box_actor::WeakBoxHandle,
    /// Accumulates env vars of newly-installed packages, shared with the owning [`Env`].
    runtime_env: RuntimeEnv,
    rx: mpsc::Receiver<ChannelRequest>,
}

/// What a helper request's trace hands a task the request runs (TEL-023,
/// TEL-045), as [`channel_request_span`] decides it from the request's
/// prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TaskTrace {
    /// The helper opted out (the `otel%off%` prefix): the request's span is
    /// recorded nowhere, and the task gets `MINIMAL_OTEL=off` and no
    /// `TRACEPARENT`.
    OptedOut,
    /// The `TRACEPARENT` the task may be given: the request span's own
    /// context, only when the helper sent a context for the span to join and
    /// the span is recorded ([`crate::exec::box_traceparent`], TEL-024).
    Parent(Option<String>),
}

/// The prefix name of a request whose helper opted out of telemetry:
/// `otel%off%<method>%<data>`. Its one meaningful value is
/// [`minimald_rpc::trace::OTEL_OFF`]; any other is ignored, as
/// [`minimald_rpc::trace::opted_out`] ignores it.
const OTEL_PREFIX: &str = "otel";

/// The span one helper request is handled in, the request with its prefix
/// removed, and what the request's trace hands a task it runs
/// ([`TaskTrace`]).
///
/// The helper (`env_min_helper.sh`, `__min_rpc`) sends
/// `otel%off%<method>%<data>` when the box has `MINIMAL_OTEL=off` (the
/// marker [`crate::exec`] hands the box of a request that opted out,
/// TEL-045), else `traceparent%<w3c traceparent>%<method>%<data>` when the
/// box has a `TRACEPARENT` — the exec span's context, handed to the box by
/// [`crate::exec`] — and the bare `<method>%<data>` otherwise. The actor runs
/// for the env's life under its own `session.env` root, so without this a
/// request's mailbox messages (`StartMaterialize`, `ExposeDynamic`) and the
/// spans they open were children of that root, in a trace of their own
/// (scenarios 717b and 770). Here the request gets a root of its own that
/// adopts the forwarded context ([`crate::exec::adopt_trace`] records the
/// ids and `remember`s them for [`crate::traced::caller_context`]), so the
/// messages sent while handling it join the exec that ran the helper. An
/// opted-out request's root is made non-recording instead
/// ([`crate::exec::adopt_opt_out`]): it parents nothing, is exported and
/// spooled nowhere, and neither is anything under it.
///
/// A task gets a `TRACEPARENT` only from a request that carried one: a bare
/// request (an older helper's, or one from a box handed no `TRACEPARENT`)
/// mints a root for the daemon's own work, and handing a task that root
/// would start a trace the caller never asked for.
///
/// `box_id` and `session_id` are the host's own knowledge of who is asking
/// (the channel was built for that box, by that session): they go on the
/// span as `box.id` and `session.id`, and nothing the box sends can set
/// them. The box-supplied part of the line (the prefix) only parents or
/// opts out the span, and the method is recorded as one of
/// [`CHANNEL_METHODS`] or `other` ([`channel_method`]), never as the text
/// the box sent.
fn channel_request_span<'a>(
    line: &'a str,
    box_id: &str,
    session_id: Option<boxes::SessionId>,
) -> (tracing::Span, &'a str, TaskTrace) {
    let (traceparent, opted_out, request) = match line.split_once('%') {
        Some(("traceparent", rest)) => match rest.split_once('%') {
            Some((tp, request)) => (Some(tp), false, request),
            None => (None, false, rest),
        },
        Some((OTEL_PREFIX, rest)) => match rest.split_once('%') {
            Some((value, request)) => (None, value == minimald_rpc::trace::OTEL_OFF, request),
            None => (None, false, rest),
        },
        _ => (None, false, line),
    };
    let method = channel_method(request);
    let span = tracing::info_span!(
        parent: None,
        "session.channel",
        method,
        box.id = box_id,
        session.id = session_id.as_ref().map(tracing::field::display),
        telemetry = tracing::field::Empty,
        trace_id = tracing::field::Empty,
        span_id = tracing::field::Empty,
        parent_span_id = tracing::field::Empty,
    );
    if opted_out {
        crate::exec::adopt_opt_out(&span);
        return (span, request, TaskTrace::OptedOut);
    }
    let client_ctx = traceparent.and_then(minimald_rpc::trace::TraceContext::parse_traceparent);
    let sent = client_ctx.is_some();
    let adopted = crate::exec::adopt_trace(&span, client_ctx);
    let traceparent = task_traceparent(sent, crate::exec::box_traceparent(&adopted));
    (span, request, TaskTrace::Parent(traceparent))
}

/// The `TRACEPARENT` the task of a request that did not opt out is given:
/// the request span's context when that span is recorded (`recorded`), and
/// only when the helper `sent` a context for the span to join. A bare
/// request's span is a root the daemon minted for its own work; the box
/// that sent it was handed no `TRACEPARENT` (TEL-024), or its helper
/// predates the prefix, and its task gets none either.
fn task_traceparent(sent: bool, recorded: Option<String>) -> Option<String> {
    recorded.filter(|_| sent)
}

/// The methods [`BoxChannel::handle`] dispatches: the only values the
/// `session.channel` span's `method` takes besides `other`. Keep it in step
/// with the arms of `handle`.
const CHANNEL_METHODS: &[&str] = &[
    "add-transient",
    "add-build",
    "add-runtime",
    "add-session",
    "search",
    "check",
    "patched-pkg",
    "run",
    "build",
    "materialize",
    "net-expose",
    "net-expose-public",
];

/// The `method` a helper request is recorded under: the text before its
/// first `%` when that is a method [`BoxChannel::handle`] dispatches,
/// else `other` (a line with no `%` is never dispatched, so it is `other`
/// too). The line comes from inside the box and the span is exported and
/// spooled, so no box-chosen text, of any length, reaches the host's
/// telemetry through this field.
fn channel_method(request: &str) -> &'static str {
    request
        .split_once('%')
        .and_then(|(method, _)| CHANNEL_METHODS.iter().find(|known| **known == method))
        .copied()
        .unwrap_or("other")
}

/// A request line safe to log: a `run` request carries the caller's
/// exported environment, secrets included, as its last group, so that group
/// is cut.
fn loggable_request(line: &str) -> std::borrow::Cow<'_, str> {
    match line.match_indices(RUN_GROUP_SEP).nth(1) {
        Some((at, _)) => format!("{}<environment redacted>", &line[..=at]).into(),
        None => line.into(),
    }
}

impl BoxChannel {
    /// Drives the actor until the bridge (and thus all senders) is dropped.
    async fn run(mut self) {
        while let Some(ChannelRequest {
            line,
            raw,
            mut stream,
        }) = self.rx.recv().await
        {
            let (span, request, trace) = channel_request_span(&line, &self.box_id, self.session_id);
            // An opted-out request keeps its command line out of the records
            // (TEL-045), the file log's included.
            if trace != TaskTrace::OptedOut {
                tracing::trace!("session channel handling: {}", loggable_request(&line));
            }
            // Boxed: the handler's future is large (every subcommand's state in
            // one `async fn`) and it is awaited once per request, not per byte.
            let handled = self.handle_raw(request, raw.as_deref(), trace, &mut stream);
            tracing::Instrument::instrument(Box::pin(handled), span).await;
            // `stream` is dropped here, closing the connection so the client's
            // `socat` reads EOF and the `min` helper's read loop terminates.
        }
    }

    /// Dispatches a single valid `method%data` request line.
    #[cfg(test)]
    async fn handle(&mut self, line: &str, stream: &mut UnixStream) {
        self.handle_raw(line, None, TaskTrace::Parent(None), stream)
            .await;
    }

    /// Dispatches a single `method%data` request line. `raw` is the line as
    /// the box sent it when `line` is its lossy decode. `trace` is what the
    /// request's trace hands a task the request runs
    /// ([`channel_request_span`]).
    async fn handle_raw(
        &mut self,
        line: &str,
        raw: Option<&[u8]>,
        trace: TaskTrace,
        stream: &mut UnixStream,
    ) {
        let add_dep = match line.split_once('%') {
            Some(("add-transient", pkgs)) => match self.parse_pkgs_line(pkgs) {
                Err(n) => {
                    let _ = writeln!(stream, "error: no such package '{n}'");
                    None
                }
                Ok(pkgs) => {
                    self.install(&pkgs, stream).await;
                    None
                }
            },
            Some(("add-build", pkgs)) => match self.parse_pkgs_line(pkgs) {
                Err(n) => {
                    let _ = writeln!(stream, "error: no such package '{n}'");
                    None
                }
                Ok(pkgs) => {
                    self.install(&pkgs, stream).await;
                    Some((AddDepMode::BuildPackages, pkgs))
                }
            },
            Some(("add-runtime", pkgs)) => match self.parse_pkgs_line(pkgs) {
                Err(n) => {
                    let _ = writeln!(stream, "error: no such package '{n}'");
                    None
                }
                Ok(pkgs) => {
                    self.install(&pkgs, stream).await;
                    Some((AddDepMode::RuntimePackages, pkgs))
                }
            },
            Some(("add-session", pkgs)) => match self.parse_pkgs_line(pkgs) {
                Err(n) => {
                    let _ = writeln!(stream, "error: no such package '{n}'");
                    None
                }
                Ok(pkgs) => {
                    self.install(&pkgs, stream).await;
                    Some((AddDepMode::SessionPackages, pkgs))
                }
            },
            Some(("search", term)) => {
                self.search(term, stream);
                None
            }
            Some(("check", args)) => {
                self.run_check(stream, args).await;
                None
            }
            Some(("patched-pkg", name)) => {
                self.run_patched_pkg(stream, name).await;
                None
            }
            Some(("run", request)) => {
                let mut request = TaskRunRequest::parse(request);
                if let Some(data) = raw.and_then(run_data_bytes) {
                    request.mark_invalid_bytes(data);
                }
                self.run_task(stream, request, trace).await;
                None
            }
            Some(("build", args)) => {
                self.run_build(stream, args).await;
                None
            }
            // `<cwd>%<args>`: the helper's sandbox working directory, so a
            // relative `--output` resolves where the user typed it.
            Some(("materialize", request)) => {
                self.run_materialize(stream, request).await;
                None
            }
            // `<port>`: the box's own `min net expose <port>` (NET-043) — the
            // port a process inside the box asks to publish, decided and
            // published by the session that owns it.
            Some(("net-expose", port)) => {
                self.expose_port(stream, port).await;
                None
            }
            // `<port>` or nothing: the box's own `min net expose --public
            // [<port>]` (NET-145). No public surface exists on this host, so
            // the request is refused and nothing is published.
            Some(("net-expose-public", port)) => {
                self.refuse_public_expose(stream, port);
                None
            }
            // A new arm above also goes in `CHANNEL_METHODS`, or its span
            // records `other`.
            _ => {
                let _ = writeln!(stream, "error: unhandled input '{line}'");
                None
            }
        };

        if let Some((mode, pkgs)) = add_dep {
            let bsrs: Vec<BuildSpecRef> = pkgs.into_iter().map(|(_n, bsr)| bsr).collect();
            if let Err(e) = self.ctx.add_deps(&self.graph, bsrs, mode) {
                let _ = writeln!(stream, "error: {e}");
            }
        }
    }

    /// Record and transmit a newly-acquired variable to the session shell.
    fn announce_env(&self, stream: &mut UnixStream, key: &str, value: &str) {
        self.runtime_env.record(key, value);
        let _ = writeln!(stream, "set_env:{key}:{value}");
    }

    /// Resolves a space-separated list of package names to `(name, ref)` pairs,
    /// returning the first unknown name as `Err`.
    fn parse_pkgs_line<'a>(&self, pkgs: &'a str) -> Result<Vec<(&'a str, BuildSpecRef)>, &'a str> {
        pkgs.split(' ')
            .map(|n| match self.graph.by_name(n) {
                None => Err(n),
                Some(bsr) => Ok((n, *bsr)),
            })
            .collect()
    }

    /// Installs packages into the running environment, building them if needed
    /// and hardlinking their files into the live rootfs.
    async fn install(&mut self, pkgs: &[(&str, BuildSpecRef)], stream: &mut UnixStream) {
        if pkgs
            .iter()
            .all(|(_n, bsr)| self.graph.top_levels.contains(bsr))
        {
            // Already installed. Say so rather than returning silently: this
            // path is indistinguishable from a successful injection on the
            // wire, so a stale `top_levels` would otherwise read as success.
            let _ = writeln!(
                stream,
                "msg:Already installed: {}",
                pkgs.iter().map(|t| t.0).collect::<Vec<_>>().join(", ")
            );
            return;
        }

        let mut new_graph = self.graph.clone();
        for (_n, bsr) in pkgs {
            if !new_graph.top_levels.contains(bsr) {
                new_graph.top_levels.push(*bsr);
            }
        }
        // Stream build progress back to the client while the graph builds: a
        // first-time `min add` fetches and extracts its packages right here.
        // `msg:` lines (`fetching go`, `building go`) name what started. The
        // byte meter those fetches already track is painted as `bar:` lines
        // on the next row; the in-sandbox helper redraws each one in place. A
        // fully-cached add emits neither and stays quiet.
        //
        // Built before the two futures: `build` needs `&mut self.ctx` and
        // `render` must not borrow it as well. NET-080: the scope is the
        // record's as much as the meter's — every package this install may
        // fetch is recorded as the daemon's own node-plane fetch, made for
        // the box that asked — so the one walk feeds both.
        let scope = install_scope(&new_graph, pkgs);
        // NET-155: `Env::build` placed this context in the box's leaf, so
        // the builds this install starts follow the box's egress verdict.
        match self.ctx.classifier_leaf() {
            Some(leaf) => tracing::info!(
                box_name = %self.name,
                leaf = %leaf.dir().display(),
                "starting an in-box install's package builds in the box's classifier leaf",
            ),
            None if self.ctx.box_network().is_some() => tracing::info!(
                box_name = %self.name,
                "starting an in-box install's package builds on the box's own network, \
                 under the box's egress rules",
            ),
            None => tracing::info!(
                box_name = %self.name,
                "starting an in-box install's package builds in the daemon's own cgroup, \
                 with no per-box egress enforcement, because the box has none",
            ),
        }
        let progress = crate::sandbox_progress::SandboxProgress::new(
            self.ctx.op_tracker(),
            Some(scope.clone()),
        )
        .with_fetch_record(self.fetch_record(&new_graph, &scope));
        let (log_tx, log_rx) = futures::channel::mpsc::unbounded();
        let build = async {
            // Reduce the `!Send` error (`mctx::Error` holds nickel `Rc`s) to a
            // string in the same poll it appears, so `join!` never buffers it
            // across the render side's awaits — this future runs on the
            // spawned (`Send`) channel actor.
            match self.ctx.build_graph(&new_graph, false, Some(log_tx)).await {
                Ok(()) => None,
                Err(e) => Some(e.to_string()),
            }
        };
        let mut renderer = orchestrator::BuildRenderer::new(false);
        let render =
            crate::sandbox_progress::relay(stream, progress, log_rx, |event, progress, stream| {
                if let Some(line) = renderer.render(event) {
                    progress.message(stream, &line.text);
                }
            });
        let (build_err, ()) = tokio::join!(build, render);
        if let Some(e) = build_err {
            let e = unreachable_source(&e, &self.name).unwrap_or(e);
            let _ = writeln!(stream, "error: {e}");
            return;
        }

        let transitives = Transitives::for_toplevels(
            &new_graph,
            pkgs.iter().map(|(_n, bsr)| *bsr).collect(),
            false,
        );
        match SetupForPackages::build(
            &new_graph,
            transitives
                .keys()
                .filter(|bsr| !self.has_packages.contains(bsr)),
        ) {
            Ok(setup) => {
                for want_dir in setup.state_dirs {
                    if let Err(e) =
                        std::fs::create_dir_all(self.state_dir.as_utf8_path().join(want_dir))
                    {
                        let _ = writeln!(stream, "error: {e}");
                        return;
                    }
                }
                for (k, v) in &setup.env_vars {
                    self.announce_env(stream, k, v);
                }
            }
            Err(e) => {
                let _ = writeln!(stream, "error: {e}");
                return;
            }
        }

        let cache = self.ctx.local_cache();

        // Resolve the newly-needed packages to their cache directories,
        // then hardlink them in within a blocking thread.
        let mut pkg_dirs = Vec::new();
        for bsr in transitives.keys() {
            if self.has_packages.insert(*bsr) {
                match cache.read_dir(&new_graph.spec_hash(bsr)) {
                    Ok(entry) => pkg_dirs.push(entry.path().to_path_buf()),
                    Err(e) => {
                        let _ = writeln!(stream, "error: {e}");
                        return;
                    }
                }
            }
        }
        let rootfs = self.rootfs.as_utf8_path().as_std_path().to_path_buf();
        let hardlink = spawn_blocking(move || {
            pkg_dirs
                .iter()
                .try_for_each(|src| common::hardlink_dir_contents(src, &rootfs))
        })
        .await;
        match hardlink {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = writeln!(stream, "error: hardlinking: {e}");
                return;
            }
            Err(e) => {
                let _ = writeln!(stream, "error: spawn: {e}");
                return;
            }
        }

        let _ = writeln!(
            stream,
            "msg:Installed {}",
            pkgs.iter().map(|t| t.0).collect::<Vec<_>>().join(", ")
        );
        self.graph = new_graph;
    }

    /// NET-080: the context this install's fetches are recorded under — the
    /// box the install was made for, the leaf this daemon's own fetches
    /// leave from (where it stands in one), the host the daemon fetches the
    /// configured remote cache from, and each package in the install's scope
    /// spelled the way `min search` spells it, with its upstream version
    /// when the graph knows one. A source a package declares is a package
    /// build's traffic (NET-155), never the node plane's, so the record
    /// does not list it.
    fn fetch_record(
        &self,
        graph: &Graph,
        scope: &HashSet<String>,
    ) -> crate::sandbox_progress::FetchRecord {
        let objects = scope
            .iter()
            .map(|name| {
                let spelled = graph
                    .by_name(name)
                    .and_then(|bsr| graph.get(bsr))
                    .and_then(|build| build.upstream_version())
                    .map_or_else(
                        || name.clone(),
                        |version| format!("{name} (version {version})"),
                    );
                (name.clone(), spelled)
            })
            .collect();
        crate::sandbox_progress::FetchRecord {
            box_id: self.box_id.clone(),
            leaf: crate::net::classifier::daemon_fetch_leaf(Path::new(
                sandbox::classifier::TREE_ROOT,
            )),
            cache_host: crate::net::classifier::cache_host(
                &self.ctx.daemon_context().config().remote_cache_url(),
            ),
            objects,
        }
    }

    /// Implements `min search <term>`.
    fn search(&self, term: &str, stream: &mut UnixStream) {
        for (bsr, m) in self.graph.fuzzy_name_search(term, 8).iter() {
            let b = self.graph.get(bsr).unwrap();
            let name = &b.name;
            if name.ends_with(" (prebuilt)") {
                continue;
            }

            let _ = write!(stream, "msg: * {name}");
            if let Some(v) = b.upstream_version() {
                let _ = write!(stream, " (version {v})");
            }
            if !m.outputs.is_empty() {
                let _ = write!(
                    stream,
                    " [provides {}]",
                    m.outputs.keys().cloned().collect::<Vec<_>>().join(",")
                );
            }
            let _ = writeln!(stream);
        }
    }

    /// Implements `min check [--packages] [--stacks] [--profiles] [--fix] [names...]`:
    /// kicks off a session side-op check run and streams each object's results
    /// back to the client until the run completes.
    async fn run_check(&mut self, stream: &mut UnixStream, args: &str) {
        use crate::box_ops::{CheckOpts, CheckOutcome, CheckUpdate};

        let Some(session) = self.session.upgrade() else {
            let _ = writeln!(stream, "error: session is gone");
            return;
        };

        let opts = match CheckOpts::from_args(args) {
            Ok(opts) => opts,
            Err(msg) => {
                let _ = writeln!(stream, "error: {msg}");
                return;
            }
        };

        let mut updates = match session.start_check(opts).await {
            Ok(rx) => rx,
            Err(e) => {
                let _ = writeln!(stream, "error: {e}");
                return;
            }
        };

        let mut outcome = None;
        while let Some(update) = updates.recv().await {
            if let CheckUpdate::Finished(o) = &update {
                outcome = Some(o.clone());
            }
            for line in update.render() {
                let _ = writeln!(stream, "msg:{line}");
            }
        }

        // Report the propagated outcome; only a clean run claims success.
        let (status, message) = CheckOutcome::summarize(outcome.as_ref());
        if status == 0 {
            let _ = writeln!(stream, "msg:{message}");
        } else {
            let _ = writeln!(stream, "error: {message}");
        }
    }

    /// Implements `min patched-pkg <pkgname>`.
    async fn run_patched_pkg(&mut self, stream: &mut UnixStream, pkg_name: &str) {
        let (ctx, graph, new_has_packages) = if let Ok(v) = self.refresh(stream).await {
            v
        } else {
            return;
        };

        let bsr = match graph.by_name(pkg_name) {
            None => {
                Self::write_error(
                    &Error::Graph(Box::new(graph::Error::NoSuchPkg {
                        name: pkg_name.to_string(),
                    })),
                    stream,
                );
                return;
            }
            Some(bsr) => *bsr,
        };

        // Scope the build to the requested package on a throwaway clone. The
        // session graph's own `top_levels` is its record of what is installed;
        // narrowing that to `[bsr]` would make the next `min add <pkg>` take
        // `install`'s already-installed path and silently inject nothing.
        let mut build_graph = graph.clone();
        build_graph.top_levels = vec![bsr];

        let tapped = Arc::new(Mutex::new(std::collections::VecDeque::new()));
        // NET-155: an own-address box has no leaf. Its build attaches to the
        // box's own network, which the box's context carries.
        let box_network = ctx.box_network().cloned();
        let result: std::io::Result<()> = async {
            let remote_storage = ctx.remote_storage().await.map_err(err_to_io)?;
            let remote_cache = if ctx.use_remote_cache() {
                // No flag to name: the daemon's context never sets no_fetch
                // and the in-sandbox `min` helper takes no flags. `{:#}`
                // keeps the cause.
                Some(ctx.remote_cache(false, false).await.map_err(|e| {
                    std::io::Error::other(format!("{:#}", mctx::remote_cache_setup_error(e, None)))
                })?)
            } else {
                None
            };
            let output_base = ctx.builds_base_dir();
            let _ = std::fs::create_dir_all(&output_base);

            let cache = ctx.local_cache();
            let (stdout_writer, stderr_writer) = StreamWriter::pair(stream)?;
            // NET-155: the build runs in the box's own leaf, or on the own-
            // address box's network, so the box's egress verdict decides what
            // it can reach. A box with neither has no per-box enforcement,
            // and its build runs in the daemon's own cgroup.
            match &self.classifier_leaf {
                Some(leaf) => tracing::info!(
                    box_name = %self.name,
                    package = %pkg_name,
                    leaf = %leaf.dir().display(),
                    "starting a package build for a box in the box's classifier leaf",
                ),
                None if box_network.is_some() => tracing::info!(
                    box_name = %self.name,
                    package = %pkg_name,
                    leaf = "none",
                    "starting a package build for a box on the box's own network, \
                     under the box's egress rules",
                ),
                None => tracing::info!(
                    box_name = %self.name,
                    package = %pkg_name,
                    leaf = "none",
                    "starting a package build for a box in the daemon's own cgroup, \
                     with no per-box egress enforcement, because the box has none",
                ),
            }
            let res = op::PatchedBuild {
                spec: &bsr,
                remote_fetcher: &remote_storage,
                stdout_writer: Some(Box::new(LineTap::new(stdout_writer, tapped.clone()))),
                stderr_writer: Some(Box::new(LineTap::new(stderr_writer, tapped.clone()))),
                remote_cache: remote_cache.as_ref(),
                classifier_leaf: self.classifier_leaf.clone(),
                box_network: match &self.classifier_leaf {
                    Some(_) => None,
                    None => box_network.clone(),
                },
            }
            .run(&op::Options {
                cache,
                graph: &build_graph,
                exec_base: output_base,
                ot: self.ot.clone(),
                daemon_id: ctx.daemon_id(),
            })
            .await
            .map_err(std::io::Error::other)?;

            res.outputs
                .finalize(res.meta)
                .map_err(std::io::Error::other)?;
            Ok(())
        }
        .await;

        if let Err(e) = result {
            // NET-155: a build the box's rules refused names the destination
            // and the box before the build's own error.
            let lines = tapped
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let failure = e.to_string();
            let refusal = patched_build_refusal(
                build_denies_all(self.classifier_leaf.as_ref(), box_network.as_ref()),
                pkg_name,
                &self.name,
                &failure,
                lines.iter().map(String::as_str),
            )
            .or_else(|| {
                let text = failure.strip_prefix("other: ")?;
                source_failure(pkg_name, &self.name, text)
            });
            if let Some(refusal) = refusal {
                let _ = writeln!(stream, "error: {refusal}");
            }
            let _ = writeln!(stream, "error: {e}");
            return;
        }
        let _ = writeln!(
            stream,
            "msg:Written to cache with hash {}",
            graph.spec_hash(&bsr).0
        );

        self.ctx = ctx;
        self.graph = graph;
        self.has_packages = new_has_packages;
    }

    /// Implements `min task run <task> [args...]`: runs the task and, for a
    /// helper that sends its argv, relays the task's exit code as `exit:<n>`
    /// so the helper exits with it. A task box's entrypoint is that helper.
    /// `trace` is what the request's trace hands the task
    /// ([`run_task_trace`]).
    async fn run_task(
        &mut self,
        stream: &mut UnixStream,
        request: TaskRunRequest,
        trace: TaskTrace,
    ) {
        let task_name = request.task.as_str();
        let relays = request.relays_exit();
        // BCLI-010 (T62): a relaying helper prints `err:` lines on stderr,
        // and an older one prints only `msg:` lines.
        let note_tag = if relays { "err" } else { "msg" };
        let (mut ctx, graph, _) = match self.refresh_tagged(stream, note_tag).await {
            Ok(v) => v,
            Err(e) => {
                return relay_refusal_exit(stream, relays, task_name, refusal_exit_code(&e));
            }
        };

        let (mut task, mut graph) = match ctx.task(graph, task_name) {
            Err(e) => {
                Self::write_error_tagged(&e, stream, note_tag);
                return relay_refusal_exit(stream, relays, task_name, refusal_exit_code(&e));
            }
            Ok(None) => {
                let _ = writeln!(stream, "error: no such task '{}'", one_line(task_name));
                return relay_refusal_exit(stream, relays, task_name, EXIT_NOT_FOUND);
            }
            Ok(Some(v)) => v,
        };

        // BCLI-010 (T62): the laptop refuses an argument that is not valid
        // UTF-8 before the task runs, so the in-box run does as well.
        if relays && request.invalid_arg {
            let _ = writeln!(stream, "{}", invalid_arg_refusal(task_name));
            return relay_refusal_exit(stream, relays, task_name, EXIT_USAGE);
        }

        let parsed_args = if !task.args.is_empty() {
            let parsed = match &request.args {
                TaskRunArgs::Line(line) => task.args.parse(line),
                TaskRunArgs::Argv(argv) => task
                    .args
                    .parse_argv_named(&format!("min task run {task_name}"), argv.iter()),
            };
            match parsed {
                Err(e) => {
                    for line in format!("{}", e.render().ansi()).lines() {
                        let _ = writeln!(stream, "{note_tag}:{line}");
                    }
                    let _ = writeln!(stream, "error: failed parsing arguments for task");
                    return relay_refusal_exit(stream, relays, task_name, EXIT_USAGE);
                }
                Ok(args) => Some(args),
            }
        } else {
            None
        };

        // The caller's own values for the task's `inherit` variables, after
        // the names the client's `[vars] ignore` matched are gone. The
        // daemon's environment is not the caller's, so it never fills one.
        // A variable the caller does not set, or sets to a value that is not
        // valid UTF-8, refuses the run with the text the laptop's `min task
        // run` prints for both.
        if let Err(name) = run_task_vars(&mut task.vars, self.session_id.as_ref(), relays, &request)
        {
            let _ = writeln!(stream, "{}", inherit_refusal(task_name, &name));
            return relay_refusal_exit(stream, relays, task_name, EXIT_USAGE);
        }
        run_task_trace(&mut task.vars, mlog::otel::exporting(), trace, &request.env);
        let start_dir = match start_dir_in_box(
            task.inherit_cwd,
            request.cwd.as_deref(),
            self.working.as_utf8_path().as_std_path(),
        ) {
            Ok(dir) => dir,
            Err(notice) => {
                let _ = writeln!(stream, "{note_tag}:{notice}");
                None
            }
        };

        let Some(session) = self.session.upgrade() else {
            let _ = writeln!(stream, "error: session is gone");
            return relay_refusal_exit(stream, relays, task_name, EXIT_MIN_FAILURE);
        };

        // T123: a helper whose stdin is a pipe or a file forwards it. The
        // task gets it on its stdin pipe, through `run_invocations_in`.
        let forward_stdin = relays && request.stdin;
        tracing::info!(
            task = %task_name,
            stdin_forwarded = forward_stdin,
            "in-box task run starts",
        );
        let mut forwarded: Option<crate::exec::ForwardedStdin> = None;

        // `Ok(false)`: the run was refused and the refusal, with its exit
        // code for a relaying helper, is already sent.
        let result: Result<bool, Error> = async {
            // A task started from inside the session is a PTask of that
            // session's mode too (017-005).
            let gone = |e: std::io::Error| Error::IO("reading the session", Default::default(), e);
            // Two statements: `mctx::Error` is not `Send`, and one expression
            // would hold it across the second await in a spawned future.
            let record = session.record().await.map_err(gone)?;
            let switch = session.net_switch().await.map_err(gone)?;
            let opt_out = session.deny_all_opt_out().await.map_err(gone)?;
            let network =
                crate::exec::task_network(&record, &switch, boxes::EGRESS_DEFAULT_PHASE, opt_out);
            let mut env = ctx
                .make_env_with_network(
                    task_name,
                    &mut graph,
                    // The session layout ignores this. `start_dir` places
                    // an `inherit_cwd` task.
                    None,
                    task.state_key.as_ref(),
                    Some(&task.patch),
                    Some(&task.vars),
                    task.packages.clone(),
                    network,
                    // The session's own home, not the daemon's. `minimald` is
                    // pid 1 with `HOME=/` inside the guest, so the ambient
                    // home would expand a package's `~/.claude.json` onto the
                    // read-only rootfs (#1204); the session has a real,
                    // writable home and this channel already holds it.
                    mctx::PatchHome::Session(self.home.clone()),
                    mctx::WdLayout::Session {
                        home: self.home.as_utf8_path().to_path_buf().into(),
                        working: self.working.as_utf8_path().to_path_buf().into(),
                    },
                )
                .await?;

            let (interactive, invocations) =
                env.task_invocations(&task, parsed_args.as_ref()).await?;
            if interactive {
                let _ = writeln!(
                    stream,
                    "error: cannot run interactive tasks from within an environment"
                );
                relay_refusal_exit(stream, relays, task_name, EXIT_USAGE);
                return Ok(false);
            }

            match &start_dir {
                dir if dir.is_some() || forward_stdin => {
                    run_invocations_in(
                        &mut env,
                        invocations,
                        dir.as_deref(),
                        stream,
                        note_tag,
                        forward_stdin.then_some(&mut forwarded),
                    )
                    .await?
                }
                _ => {
                    let (stdout_writer, stderr_writer) =
                        StreamWriter::pair_tagged(stream, note_tag)
                            .map_err(|e| Error::IO("creating writers", Default::default(), e))?;
                    env.run(invocations, Some(stdout_writer), Some(stderr_writer))
                        .await?
                }
            }
            Ok(true)
        }
        .await;

        Self::end_task_run(
            stream,
            relays,
            note_tag,
            task_name,
            result,
            forwarded.as_mut(),
        );
        if let Some(forwarded) = forwarded {
            let _ = spawn_blocking(move || forwarded.finish(FORWARDED_STDIN_CLOSE_WAIT)).await;
        }
    }

    /// Sends the end of a task run: its exit code for a relaying helper,
    /// or the error that ended it. `Ok(false)` is a run whose refusal is
    /// already sent.
    fn end_task_run(
        stream: &mut UnixStream,
        relays: bool,
        note_tag: &str,
        task_name: &str,
        result: Result<bool, Error>,
        forwarded: Option<&mut crate::exec::ForwardedStdin>,
    ) {
        if matches!(result, Ok(false)) {
            return;
        }
        let mut result = result.map(|_| ());
        // A stdin that stopped before its end, while the task read it, fails
        // a run that passed: the task did not get all of its input. A run
        // that failed keeps its own error, so the task's exit code stays.
        if let Some(error) = forwarded.and_then(|f| f.failure()) {
            tracing::warn!(task = %task_name, %error, "the forwarded stdin stopped before its end");
            if result.is_ok() {
                result = Err(forwarded_stdin_error(&error));
            }
        }
        if relays && let Some(code) = relayed_exit_code(&result) {
            // BCLI-010 (T62): the helper exits with this code, so a task
            // box's entrypoint ends with the task's own status.
            tracing::info!(
                task = %task_name,
                exit_code = code,
                "relaying a task's exit code to the in-box min helper",
            );
            let _ = writeln!(stream, "exit:{code}");
            return;
        }
        if let Err(e) = result {
            Self::write_error_tagged(&e, stream, note_tag);
            relay_refusal_exit(stream, relays, task_name, refusal_exit_code(&e));
        }
    }

    /// Implements `min build [--verbose] [--rebuild] pkgs...`: kicks off
    /// a session side-op build and streams its progress back to the client
    /// until the build completes.
    async fn run_build(&mut self, stream: &mut UnixStream, args: &str) {
        let mut flag_verbose = false;
        let mut flag_rebuild = false;
        let mut pkgs: Vec<String> = Vec::new();

        for token in args.split_whitespace() {
            match token {
                "--verbose" => flag_verbose = true,
                "--rebuild" => flag_rebuild = true,
                _ => pkgs.push(token.to_string()),
            }
        }

        let Some(session) = self.session.upgrade() else {
            let _ = writeln!(stream, "error: session is gone");
            return;
        };

        let mut events = match session.start_build(flag_rebuild, pkgs).await {
            Ok(rx) => rx,
            Err(e) => {
                let _ = writeln!(stream, "error: {e}");
                return;
            }
        };

        use crate::box_ops::{BuildOutcome, BuildUpdate};
        let mut renderer = orchestrator::BuildRenderer::new(flag_verbose);
        let mut outcome = None;
        // The same meter as `min add`. Unscoped: this build runs on the
        // session's own side-op, so every package row on the tree is its.
        let progress = crate::sandbox_progress::SandboxProgress::new(self.ctx.op_tracker(), None);
        let updates = futures::stream::poll_fn(|cx| events.poll_recv(cx));
        crate::sandbox_progress::relay(stream, progress, updates, |update, progress, stream| {
            match update {
                BuildUpdate::Event(event) => {
                    if let Some(line) = renderer.render(event) {
                        progress.message(stream, &line.text);
                    }
                }
                BuildUpdate::Finished(o) => outcome = Some(o),
            }
        })
        .await;

        // Report the propagated outcome; only success claims completion.
        match outcome {
            Some(BuildOutcome::Success) => {
                let _ = writeln!(stream, "msg:build finished");
            }
            Some(BuildOutcome::Failed(e)) => {
                let _ = writeln!(stream, "error: build failed: {e}");
            }
            Some(BuildOutcome::Cancelled) => {
                let _ = writeln!(stream, "error: build cancelled");
            }
            // The channel closed without a terminal update — the side-op died
            // before reporting (e.g. the actor was torn down mid-build).
            None => {
                let _ = writeln!(stream, "error: build ended without reporting an outcome");
            }
        }
    }

    /// Implements `min materialize --output <path> [--arch <arch>] <name>`.
    ///
    /// The side-op streams the artifact's bytes rather than writing a file, so
    /// landing it is this transport's job. `request` carries the helper's
    /// sandbox working directory ahead of the arguments, so `--output` resolves
    /// where the user typed it and stays inside the workspace — the one
    /// directory the daemon and the sandbox share.
    async fn run_materialize(&mut self, stream: &mut UnixStream, request: &str) {
        use crate::box_ops::{MaterializeOutcome, MaterializeUpdate};
        use tokio::io::AsyncWriteExt as _;

        let prepared: Result<_, String> = async {
            let MaterializeArgs { opts, output } = MaterializeArgs::from_request(request)?;
            let session = self.session.upgrade().ok_or("session is gone")?;
            let file = create_artifact(&self.working, &self.home, &output)
                .await
                .map_err(|e| format!("creating {output}: {e}"))?;
            let updates = session
                .start_materialize(opts)
                .await
                .map_err(|e| e.to_string())?;
            Ok((output, file, updates))
        }
        .await;
        let (output, mut file, mut updates) = match prepared {
            Ok(prepared) => prepared,
            Err(msg) => {
                let _ = writeln!(stream, "error: {msg}");
                return;
            }
        };

        let mut outcome = None;
        let mut write_err = None;
        while let Some(update) = updates.recv().await {
            match &update {
                MaterializeUpdate::Chunk(bytes) => {
                    if let Err(e) = file.write_all(bytes).await {
                        // Returning drops the receiver, which poisons the
                        // assembly's writer — no point building the rest of an
                        // artifact that has nowhere to land.
                        write_err = Some(e.to_string());
                        break;
                    }
                }
                MaterializeUpdate::Finished(o) => outcome = Some(o.clone()),
                MaterializeUpdate::Event(_) => {}
            }
            for line in update.render() {
                let _ = writeln!(stream, "msg:{line}");
            }
        }

        if let Some(msg) = write_err {
            let _ = writeln!(stream, "error: writing {output}: {msg}");
            return;
        }
        let (status, message) = MaterializeOutcome::summarize(outcome.as_ref());
        if status != 0 {
            let _ = writeln!(stream, "error: {message}");
            return;
        }

        // A `tokio::fs::File` completes its writes in the background; dropping
        // one unflushed truncates the artifact silently.
        if let Err(e) = file.flush().await {
            let _ = writeln!(stream, "error: writing {output}: {e}");
            return;
        }
        // The byte stream carries no mode, so a raw-file output needs the
        // source's back or an extracted binary arrives without its executable
        // bit. On the fd, so it cannot land on a path swapped underneath us.
        if let Some(MaterializeOutcome::Completed {
            mode: Some(mode), ..
        }) = outcome
            && let Err(e) = file
                .set_permissions(Permissions::from_mode(mode & 0o777))
                .await
        {
            let _ = writeln!(stream, "error: setting mode on {output}: {e}");
            return;
        }

        let _ = writeln!(stream, "msg:{message} to {output}");
    }

    /// Handles the box's own `min net expose <port>` (NET-043): the request a
    /// process inside the box sends to publish one of its ports. The session
    /// that owns this channel decides it against the box's `dynamic_ingress`
    /// setting and publishes when it allows (NET-044); the reply carries the
    /// address the port was published on and, said honestly, whether a
    /// connection to it is answered by the box yet — bound on the host, but
    /// a port the box did not declare waits for its relay gate to admit it,
    /// and until then the relay answers, not the box — or the typed
    /// refusal's own reason.
    ///
    /// A box decided `ask` makes this wait (NET-045): the session routes the
    /// ask to whoever is attached — this peer's own terminal, when it is the
    /// client the human answered from — and the reply that lands here is the
    /// applied answer: the mapping the human allowed, or the typed refusal
    /// for a deny and for nobody being attached to answer.
    ///
    /// One info line per request on every path (NET-044's observability): the
    /// actor logs each request it sees, and this channel logs the ones no
    /// actor can — a port that is not a number, a session that is gone, an
    /// actor that dropped a request's reply channel before answering, and
    /// the record the actor could not read, whose line the actor cannot
    /// write because the box's name lives in that record and this channel
    /// holds its own copy. Every line names the box, the port as given, and
    /// the outcome.
    async fn expose_port(&self, stream: &mut UnixStream, port: &str) {
        let port_number = match port.parse::<u16>() {
            Ok(number) => number,
            Err(_) => {
                tracing::info!(
                    name = %self.name,
                    port = %port,
                    outcome = "refused",
                    reason = %format_args!("'{port}' is not a port number"),
                    "dynamic ingress expose"
                );
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "the reply channel is best-effort: a peer that sent no port \
                              number may be gone before the reply lands, and there is \
                              nowhere to report that to"
                )]
                let _ = writeln!(stream, "error: '{port}' is not a port number");
                return;
            }
        };
        let session = match self.session.upgrade() {
            Some(session) => session,
            None => {
                tracing::info!(
                    name = %self.name,
                    port = %port,
                    outcome = "refused",
                    // `%format_args!` keeps the reason unquoted, the shape the
                    // other expose lines print.
                    reason = %format_args!("the session is gone"),
                    "dynamic ingress expose"
                );
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "the reply channel is best-effort: a peer may be gone before \
                              the reply lands, and there is nowhere to report that to"
                )]
                let _ = writeln!(stream, "error: session is gone");
                return;
            }
        };
        match session.expose_dynamic(port_number).await {
            Ok(mapping) => {
                // The publish admitted the port at the box's relay gate
                // before it answered (NET-044), so the port is reachable
                // now; nothing listening on it yet is answered by the box's
                // own kernel, not by the gate.
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "the reply channel is best-effort: a peer may be gone before \
                              the reply lands, and there is nowhere to report that to"
                )]
                let _ = writeln!(
                    stream,
                    "msg:published port {} at {}",
                    mapping.internal_port, mapping.local
                );
            }
            Err(failure) => {
                // The failures no actor could name, so this channel writes
                // their lines itself: the record-read failure reached the
                // actor but its line cannot be written there — the box's
                // name lives in the record it could not read — and the
                // dead-actor failure never reached one at all. Every other
                // failure already left its line in the actor, which saw the
                // record; logging here too would make two lines for one
                // request.
                let line = match &failure {
                    crate::net::policy::ExposeFailure::RecordUnreadable { .. }
                    | crate::net::policy::ExposeFailure::ActorGone { .. } => {
                        tracing::info!(
                            name = %self.name,
                            port = %port,
                            outcome = "refused",
                            reason = %failure,
                            "dynamic ingress expose"
                        );
                        format!("error: {failure}")
                    }
                    // A refusal names its way forward with the box's name
                    // and the port asked for. The name is the record's, read
                    // now: this channel's own copy is the creation-time one,
                    // and `min session rename` has moved on from it by the
                    // time a later request lands. The record's network mode
                    // decides which way forward is open. A host-address
                    // box's port needs no exposing at all, and a port the
                    // box's own listening process has published already is
                    // published: each is the goal met rather than an error,
                    // so it is a plain message and the helper exits 0.
                    crate::net::policy::ExposeFailure::Refused(refusal) => {
                        let (box_name, network) = match session.record().await {
                            Ok(record) => (
                                record.name.unwrap_or_else(|| self.name.clone()),
                                record.network,
                            ),
                            Err(_) => (self.name.clone(), boxes::NetworkMode::OwnIp),
                        };
                        let text = refusal.for_caller(&box_name, network, port_number);
                        if matches!(
                            refusal,
                            crate::net::policy::ExposeRefusal::NeedsNoExposing { .. }
                                | crate::net::policy::ExposeRefusal::ListenPublished { .. }
                        ) {
                            format!("msg:{text}")
                        } else {
                            format!("error: {text}")
                        }
                    }
                    crate::net::policy::ExposeFailure::Publish { .. } => {
                        format!("error: {failure}")
                    }
                };
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "the reply channel is best-effort: a peer may be gone before \
                              the reply lands, and there is nowhere to report that to"
                )]
                let _ = writeln!(stream, "{line}");
            }
        }
    }

    /// Refuses the box's `min net expose --public [<port>]` (NET-145): this
    /// host has no public surface, so nothing is published, neither locally
    /// nor publicly. The request is never handed to the session, so no
    /// mapping can result from it. One info line names the box, the port as
    /// given (empty when none was given), the outcome and the reason.
    fn refuse_public_expose(&self, stream: &mut UnixStream, port: &str) {
        tracing::info!(
            name = %self.name,
            port = %port,
            outcome = "refused: public exposure",
            reason = %format_args!("public exposure is not available on this host"),
            "dynamic ingress expose"
        );
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the reply channel is best-effort: a peer may be gone before the reply \
                      lands, and there is nowhere to report that to"
        )]
        let _ = writeln!(
            stream,
            "error: public exposure is not available on this host. Nothing was published."
        );
    }

    /// Writes an [`mctx::Error`] to the client as `msg:` lines (preserving its
    /// multi-line, richly-formatted report) followed by an `error:` terminator.
    fn write_error(e: &Error, stream: &mut UnixStream) {
        Self::write_error_tagged(e, stream, "msg");
    }

    /// [`Self::write_error`] with its report lines sent under `tag`: `err:`
    /// for a helper that prints them on stderr.
    fn write_error_tagged(e: &Error, stream: &mut UnixStream, tag: &str) {
        for line in e.to_string().split('\n') {
            let _ = writeln!(stream, "{tag}:{line}");
        }
        let _ = writeln!(stream, "error: sandbox command failed.");
    }

    /// Refreshes and returns internals by re-reading the minimal.toml.
    ///
    /// The returned graph carries the session's own top-levels, not the ones a
    /// fresh parse hands out: [`Self::install`] reads `top_levels` as the set
    /// of packages already injected into the live rootfs, so a refresh that
    /// reset it would either re-inject everything or (worse) claim packages are
    /// present that never were.
    async fn refresh(
        &mut self,
        stream: &mut UnixStream,
    ) -> Result<(Context, Graph, HashSet<BuildSpecRef>), ()> {
        self.refresh_tagged(stream, "msg").await.map_err(|_| ())
    }

    /// [`Self::refresh`] with a failure's report lines sent under `tag`. A
    /// failure comes back as the `Error` it reported.
    async fn refresh_tagged(
        &mut self,
        stream: &mut UnixStream,
        tag: &str,
    ) -> Result<(Context, Graph, HashSet<BuildSpecRef>), Error> {
        let error = |e: Error, stream: &mut UnixStream| {
            Self::write_error_tagged(&e, stream, tag);
            Err(e)
        };

        let mut ctx = match self.ctx.cloned_reinit() {
            Err(e) => return error(e, stream),
            Ok(ctx) => ctx,
        };
        let mut graph = match ctx.graph_from_all_packages() {
            Err(e) => return error(e, stream),
            Ok(g) => g,
        };

        // Recompute BuildSpecRefs for the new graph.
        let no_such = |name: String| Error::Graph(Box::new(graph::Error::NoSuchPkg { name }));
        let new_top_levels: Vec<BuildSpecRef> =
            match Self::remap_refs(&self.graph, &graph, &self.graph.top_levels) {
                Err(name) => return error(no_such(name), stream),
                Ok(v) => v,
            };
        let new_has_packages: HashSet<BuildSpecRef> =
            match Self::remap_refs(&self.graph, &graph, &self.has_packages) {
                Err(name) => return error(no_such(name), stream),
                Ok(v) => v,
            };
        graph.top_levels = new_top_levels;

        Ok((ctx, graph, new_has_packages))
    }

    /// Re-resolves refs taken against `from` into refs against `to`. Refs are
    /// graph-local, so the only identity that survives a re-parse is the
    /// package name; a name `to` no longer declares comes back as `Err`.
    fn remap_refs<'a, C: FromIterator<BuildSpecRef>>(
        from: &Graph,
        to: &Graph,
        bsrs: impl IntoIterator<Item = &'a BuildSpecRef>,
    ) -> Result<C, String> {
        bsrs.into_iter()
            .map(|bsr| {
                let name = &from.get(bsr).expect("bsrs always exist").name;
                to.by_name(name).copied().ok_or_else(|| name.clone())
            })
            .collect()
    }
}

/// Names of `pkgs` and of everything building or running them needs: the
/// packages an install's progress meter reports on.
fn install_scope(graph: &Graph, pkgs: &[(&str, BuildSpecRef)]) -> HashSet<String> {
    let top_levels: Vec<BuildSpecRef> = pkgs.iter().map(|(_n, bsr)| *bsr).collect();
    let deps = Transitives::for_toplevels(graph, top_levels.clone(), true);
    top_levels
        .iter()
        .chain(deps.keys())
        .filter_map(|bsr| graph.get(bsr).map(|b| b.name.clone()))
        .collect()
}

/// A parsed `min materialize` invocation: what to materialize, plus where in
/// the session to put it.
#[derive(Debug, PartialEq)]
struct MaterializeArgs {
    opts: crate::box_ops::MaterializeOpts,
    /// Where the artifact lands, as an absolute path in the *sandbox* —
    /// resolved against the sandbox cwd, and not yet tied to a daemon
    /// directory. [`sandbox_to_daemon`] decides which one it names.
    output: SandboxAbsPath,
}

impl MaterializeArgs {
    /// Parses a `materialize%<cwd>%<args>` request line. The cwd is its own
    /// field rather than a flag so no user argument can be mistaken for it.
    fn from_request(request: &str) -> Result<Self, String> {
        let Some((cwd, args)) = request.split_once('%') else {
            return Err("malformed materialize request: no working directory".to_string());
        };
        Self::from_args(Utf8Path::new(cwd), args)
    }

    /// Mirrors the clap interface of `mip materialize`: a required
    /// `-o`/`--output <PATH>`, an optional `--arch <ARCH>`, and exactly one
    /// bare `<OUTPUT_NAME>`, with both `--flag value` and `--flag=value`
    /// accepted. `--output` departs from `mip`'s: it resolves against `cwd`
    /// and must land in the workspace (see [`resolve_output`]).
    fn from_args(cwd: &Utf8Path, args: &str) -> Result<Self, String> {
        let mut output: Option<String> = None;
        let mut arch: Option<String> = None;
        let mut names: Vec<String> = Vec::new();

        let mut tokens = args.split_whitespace();
        while let Some(token) = tokens.next() {
            let (flag, inline) = match token.split_once('=') {
                Some((flag, value)) => (flag, Some(value)),
                None => (token, None),
            };
            // Takes the flag's value from `=` when it was attached, otherwise
            // from the next token.
            let mut value = |flag: &str| match inline {
                Some(v) => Ok(v.to_string()),
                None => tokens
                    .next()
                    .map(str::to_string)
                    .ok_or_else(|| format!("`{flag}` requires a value")),
            };

            match flag {
                "-o" | "--output" => output = Some(value(flag)?),
                "--arch" => arch = Some(value(flag)?),
                // Any leading dash, as `min check` does. A typo falling
                // through to the positional would read as a second output
                // name, and the error has to name the typo, not the count.
                flag if flag.starts_with('-') => {
                    return Err(format!(
                        "unknown flag `{flag}` (expected --output or --arch)"
                    ));
                }
                _ => names.push(token.to_string()),
            }
        }

        let output = output.ok_or("`min materialize` requires --output <PATH>")?;
        let output = resolve_output(cwd, Utf8Path::new(output.as_str()))?;

        let output_name = match names.len() {
            1 => names.remove(0),
            0 => return Err("`min materialize` requires the name of an output".to_string()),
            _ => {
                return Err(format!(
                    "expected one output name, got {}",
                    names.join(", ")
                ));
            }
        };

        Ok(Self {
            opts: crate::box_ops::MaterializeOpts { output_name, arch },
            output,
        })
    }
}

/// Resolves a `--output` path typed inside the sandbox — absolute, or relative
/// to `cwd`, the directory the user typed it in — to an absolute path in the
/// sandbox's mount namespace.
///
/// Which daemon directory it lands in is [`sandbox_to_daemon`]'s decision, so
/// nothing is stripped here.
fn resolve_output(cwd: &Utf8Path, output: &Utf8Path) -> Result<SandboxAbsPath, String> {
    let absolute = if output.is_absolute() {
        output.to_path_buf()
    } else {
        if output.as_str().is_empty() {
            return Err("`--output` is empty".to_string());
        }
        if !cwd.is_absolute() {
            return Err(format!(
                "cannot resolve `--output {output}`: \
                 the working directory `{cwd}` is not an absolute path"
            ));
        }
        cwd.join(output)
    };
    // Normalize here so `sandbox_to_daemon`'s prefix match is sound:
    // `/workbench/../etc/passwd` must not pass on its first component.
    // Lexical, not `canonicalize` — this is a sandbox path, and the artifact
    // does not exist yet. `create_under` makes the on-disk check.
    SandboxAbsPath::try_new(normalize_absolute(&absolute))
        .map_err(|e| format!("`--output` is not a usable path: {e}"))
}

/// Resolves `.` and `..` textually. A `..` at the root stays there, so an
/// escape can only show up as a path failing the workspace prefix check.
pub(crate) fn normalize_absolute(path: &Utf8Path) -> Utf8PathBuf {
    let mut out = Utf8PathBuf::new();
    for component in path.components() {
        match component {
            camino::Utf8Component::CurDir => {}
            camino::Utf8Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_str()),
        }
    }
    out
}

/// Creates the file an artifact named by `path` should be written to.
///
/// Picks the session directory `path` falls under — [`WORKSPACE_ROOT`] maps to
/// `working`, [`HOME_ROOT`] to `home` — and creates the directories leading to
/// the destination. These two are the only directories a sandbox path and the
/// daemon share, so anything else is refused rather than redirected:
/// `/tmp/x.tar` names a file in the *sandbox*, which the daemon cannot write.
///
/// This is the one realm crossing a destination makes, and it is where the
/// result is checked to really be inside the directory it named.
/// [`resolve_output`] rules out escapes spelled with `..`, but it reasons about
/// the sandbox's namespace and cannot see symlinks: the parent is canonicalized
/// and checked, and the file opened `O_NOFOLLOW` so a link at the destination
/// itself is refused at open time. The daemon is not confined to the sandbox,
/// so either would otherwise have it writing wherever the link leads.
///
/// The bytes are written straight into the returned file: it is the artifact,
/// not a staging copy, so a run that fails partway leaves a partial file.
async fn create_artifact(
    working: &DaemonAbsPath,
    home: &DaemonAbsPath,
    path: &SandboxAbsPath,
) -> std::io::Result<tokio::fs::File> {
    let invalid = |msg: String| std::io::Error::new(std::io::ErrorKind::InvalidInput, msg);

    let (base, rel) = [(WORKSPACE_ROOT, working), (HOME_ROOT, home)]
        .into_iter()
        .find_map(|(root, base)| Some((base, path.as_utf8_path().strip_prefix(root).ok()?)))
        .ok_or_else(|| {
            invalid(format!(
                "`{path}` is outside the session's {WORKSPACE_ROOT} and {HOME_ROOT}"
            ))
        })?;
    // Stripping a root off itself leaves nothing to name a file with.
    if rel.as_str().is_empty() {
        return Err(invalid(format!(
            "`{path}` is a session directory, not a file"
        )));
    }
    // The typed join keeps the destination anchored: `DaemonAbsPath::join`
    // takes a `DaemonRelPath`, where joining a raw string could replace the
    // root outright. `try_new` re-checks that the remainder is relative and
    // `..`-free — `resolve_output` normalized it, and this is the proof.
    let rel = DaemonRelPath::try_new(rel)
        .map_err(|e| invalid(format!("`{path}` cannot be resolved on the daemon: {e}")))?;
    let dest = base.join(&rel);

    let (parent, file_name) = match (
        dest.as_utf8_path().parent(),
        dest.as_utf8_path().file_name(),
    ) {
        (Some(parent), Some(file_name)) => (parent, file_name),
        _ => return Err(invalid(format!("`{path}` does not name a file"))),
    };
    // `base` is canonicalized too: it may itself be reached through a symlink
    // (`/var` -> `/private/var`), which would fail a textual comparison.
    let real_base = canonicalize_utf8(base.as_utf8_path())?;
    let contained = |dir: &Utf8Path| -> std::io::Result<Utf8PathBuf> {
        let real = canonicalize_utf8(dir)?;
        if !real.starts_with(&real_base) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("`{path}` resolves to `{real}`, outside `{base}`"),
            ));
        }
        Ok(real)
    };

    // Check the deepest directory that already exists *before* creating
    // anything: `create_dir_all` through a symlinked parent would otherwise
    // materialize directories outside the session before the check refused.
    let existing = parent
        .ancestors()
        .find(|dir| dir.exists())
        .ok_or_else(|| invalid(format!("`{path}` has no existing parent directory")))?;
    contained(existing)?;

    tokio::fs::create_dir_all(parent).await?;
    // Re-checked after creating: `create_dir_all` only makes real directories,
    // but the check above and this are not one atomic step.
    let real_parent = contained(parent)?;

    tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(real_parent.join(file_name))
        .await
}

/// [`std::fs::canonicalize`] keeping the path UTF-8.
fn canonicalize_utf8(path: &Utf8Path) -> std::io::Result<Utf8PathBuf> {
    let canonical = std::fs::canonicalize(path.as_std_path())?;
    Utf8PathBuf::from_path_buf(canonical)
        .map_err(|p| std::io::Error::other(format!("path is not utf-8: {}", p.display())))
}

/// Separates the groups of a `run` request: the caller's directory, the
/// task with its argv, and the caller's environment. `env_min_helper.sh`
/// (`__min_run_request`) writes it.
const RUN_GROUP_SEP: char = '\u{1e}';
/// Separates the items inside one group of a `run` request.
const RUN_ITEM_SEP: char = '\u{1f}';
/// The flag in a `run` request's fourth group that says the helper
/// forwards its stdin to the task (T123).
const RUN_STDIN_FLAG: &str = "stdin";
/// How long a run that forwarded its stdin waits, after its last line,
/// for the helper to close the connection. The channel answers one request
/// at a time, so a helper that never closes must not hold it.
const FORWARDED_STDIN_CLOSE_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// The task arguments of a `run` request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TaskRunArgs {
    /// A helper from before the argv form: the rest of the line after the
    /// task name, split by shell rules. Such a helper reads no `exit:` line.
    Line(String),
    /// The caller's argv after the task name, one item per argument.
    Argv(Vec<String>),
}

/// What the in-box `min task run` asks of the channel.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TaskRunRequest {
    task: String,
    args: TaskRunArgs,
    /// The caller's `$PWD` inside the box. `None` from an older helper.
    cwd: Option<String>,
    /// The caller's exported environment.
    env: BTreeMap<String, String>,
    /// The names in `env` whose value held a byte that is not valid UTF-8.
    invalid_env: BTreeSet<String>,
    /// Whether an argument after the task name held such a byte.
    invalid_arg: bool,
    /// Whether the helper forwards its stdin to the task: a fourth group
    /// that names `stdin` (T123). It sends that stdin on the connection
    /// after the channel's `stdin:` line, up to its EOF.
    stdin: bool,
}

impl TaskRunRequest {
    /// Parses the data after `run%`. A request with no group separator is
    /// the older `<task> <args>` form.
    fn parse(request: &str) -> Self {
        let Some((cwd, rest)) = request.split_once(RUN_GROUP_SEP) else {
            let (task, args) = request.split_once(' ').unwrap_or((request, ""));
            return Self {
                task: task.to_string(),
                args: TaskRunArgs::Line(args.to_string()),
                cwd: None,
                env: BTreeMap::new(),
                invalid_env: BTreeSet::new(),
                invalid_arg: false,
                stdin: false,
            };
        };
        let (argv, env) = rest.split_once(RUN_GROUP_SEP).unwrap_or((rest, ""));
        let (env, flags) = env.split_once(RUN_GROUP_SEP).unwrap_or((env, ""));
        let stdin = flags.split(RUN_ITEM_SEP).any(|flag| flag == RUN_STDIN_FLAG);
        let mut argv = argv.split(RUN_ITEM_SEP).map(unescape_run_item);
        let task = argv.next().unwrap_or_default();
        let env = env
            .split(RUN_ITEM_SEP)
            .filter(|item| !item.is_empty())
            .filter_map(|item| {
                let item = unescape_run_item(item);
                let (name, value) = item.split_once('=')?;
                Some((name.to_string(), value.to_string()))
            })
            .collect();
        Self {
            task,
            args: TaskRunArgs::Argv(argv.collect()),
            cwd: Some(unescape_run_item(cwd)),
            env,
            invalid_env: BTreeSet::new(),
            invalid_arg: false,
            stdin,
        }
    }

    /// Records which args and env values held a byte that is not valid
    /// UTF-8. `data` is the raw form of the data [`TaskRunRequest::parse`]
    /// read. The separators and escapes are ASCII, so an item is invalid
    /// exactly when its raw bytes are.
    fn mark_invalid_bytes(&mut self, data: &[u8]) {
        if !self.relays_exit() {
            return;
        }
        let group_sep = RUN_GROUP_SEP as u8;
        let item_sep = RUN_ITEM_SEP as u8;
        let mut groups = data.splitn(4, |b| *b == group_sep);
        let _cwd = groups.next();
        let argv = groups.next().unwrap_or_default();
        let env = groups.next().unwrap_or_default();
        self.invalid_arg = argv
            .split(|b| *b == item_sep)
            .skip(1)
            .any(|item| std::str::from_utf8(item).is_err());
        for item in env.split(|b| *b == item_sep) {
            if std::str::from_utf8(item).is_ok() {
                continue;
            }
            let item = unescape_run_item(&String::from_utf8_lossy(item));
            if let Some((name, _)) = item.split_once('=') {
                self.invalid_env.insert(name.to_string());
            }
        }
    }

    /// Whether the helper that sent this reads an `exit:` line.
    fn relays_exit(&self) -> bool {
        matches!(self.args, TaskRunArgs::Argv(_))
    }
}

/// The data after `run%` in a raw request line, past an optional
/// `traceparent%<id>%` or `otel%<value>%` prefix ([`channel_request_span`]).
/// `None` when the line is not a `run` request.
fn run_data_bytes(raw: &[u8]) -> Option<&[u8]> {
    fn split_pct(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
        let at = bytes.iter().position(|b| *b == b'%')?;
        Some((&bytes[..at], &bytes[at + 1..]))
    }
    let (mut method, mut rest) = split_pct(raw)?;
    if method == b"traceparent" || method == OTEL_PREFIX.as_bytes() {
        (_, rest) = split_pct(rest)?;
        (method, rest) = split_pct(rest)?;
    }
    (method == b"run").then_some(rest)
}

/// The refusal for an `inherit` variable the caller does not set, or sets
/// to a value that is not valid UTF-8. The laptop's `min task run` prints
/// the same text for both (`crates/minimal/src/task.rs`).
fn inherit_refusal(task: &str, name: &str) -> String {
    let task = one_line(task);
    let name = one_line(name);
    format!(
        "error: task '{task}' declares `env_vars.{name} = {{ inherit = true }}`, \
         but {name} is not set in this shell; export it before running the task"
    )
}

/// The refusal for an argument that is not valid UTF-8.
fn invalid_arg_refusal(task: &str) -> String {
    format!(
        "error: an argument for task '{}' is not valid UTF-8, so the task did not run",
        one_line(task)
    )
}

/// Reverses the helper's escapes: `\\`, `\n` (newline), `\c` (carriage
/// return), `\u` and `\r` (the two separators).
fn unescape_run_item(item: &str) -> String {
    let mut out = String::with_capacity(item.len());
    let mut chars = item.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('c') => out.push('\r'),
            Some('u') => out.push(RUN_ITEM_SEP),
            Some('r') => out.push(RUN_GROUP_SEP),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// `text` with each control character escaped (`\n`, `\r`, `\u{1b}`), for
/// a name or a path that the channel echoes. A newline in it would start a
/// protocol line of its own, such as `exit:0`.
pub(crate) fn one_line(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.chars().any(char::is_control) {
        return text.into();
    }
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        if c.is_control() {
            out.extend(c.escape_debug());
        } else {
            out.push(c);
        }
    }
    out.into()
}

/// Settles an in-box run's task variables. First each name the client's
/// `[vars] ignore` matched for box `box_id`'s entrypoint run goes (see
/// [`crate::box_actor::entrypoint_env`]), so a dropped name never reaches
/// the task, whatever the uploaded `minimal.toml` declares for it. Then a
/// relaying helper's caller fills the `inherit` ones
/// ([`inherit_from_caller`]).
fn run_task_vars(
    vars: &mut BTreeMap<String, EnvVarValue>,
    box_id: Option<&boxes::SessionId>,
    relays: bool,
    request: &TaskRunRequest,
) -> Result<(), String> {
    if let Some(id) = box_id {
        let drops = crate::box_actor::entrypoint_env::drops(id);
        vars.retain(|name, _| !drops.contains(name));
    }
    if relays {
        inherit_from_caller(vars, &request.env, &request.invalid_env)?;
    }
    Ok(())
}

/// Adds the trace variables to an in-box run's task variables (TEL-023), as
/// the sandboxed task path adds them (`minimald_rpc::taskenv::with_trace`).
/// Since T43 a task box's entrypoint is the in-box `min task run`: the
/// exec's `TRACEPARENT` reaches that helper, and the helper hands it on as
/// the request's trace prefix, but the task runs in a sandbox of its own
/// whose variables are the task's alone. Without this the task got no
/// `TRACEPARENT`, and a `min` it ran started a trace of its own.
///
/// `trace` is what the request's trace hands the task
/// ([`channel_request_span`]): the request span's context, so the task's
/// work is a child of the span that served it, or the opt-out. A helper
/// that opted out (`MINIMAL_OTEL=off`, TEL-045) sends the opt-out on the
/// request itself, so its task gets the marker and no `TRACEPARENT`.
/// `caller` is the helper's exported environment; its marker opts the task
/// out too. With `telemetry_on` false nothing but the marker is added, as
/// [`minimald_rpc::taskenv::trace_env`] decides on the exec path.
fn run_task_trace(
    vars: &mut BTreeMap<String, EnvVarValue>,
    telemetry_on: bool,
    trace: TaskTrace,
    caller: &BTreeMap<String, String>,
) {
    let (traceparent, opted_out) = match trace {
        TaskTrace::OptedOut => (None, true),
        TaskTrace::Parent(traceparent) => (traceparent, minimald_rpc::trace::opted_out(caller)),
    };
    let trace = minimald_rpc::taskenv::trace_env(telemetry_on, traceparent, opted_out);
    for (name, value) in trace {
        vars.insert(name, EnvVarValue::Value(value));
    }
}

/// Gives each `inherit` variable of a task the caller's value. The daemon's
/// own environment never fills one (#585). `Err(name)` names the first
/// `inherit` variable the caller does not set, or sets to a value in
/// `invalid` (one that held a byte that is not valid UTF-8), as the laptop
/// refuses both. A name in `invalid` that the task does not declare is
/// ignored.
fn inherit_from_caller(
    vars: &mut BTreeMap<String, EnvVarValue>,
    caller: &BTreeMap<String, String>,
    invalid: &BTreeSet<String>,
) -> Result<(), String> {
    for (name, value) in vars.iter_mut() {
        if !matches!(value, EnvVarValue::Inherit) {
            continue;
        }
        match caller.get(name) {
            Some(caller_value) if !invalid.contains(name) => {
                *value = EnvVarValue::Value(caller_value.clone());
            }
            _ => return Err(name.clone()),
        }
    }
    Ok(())
}

/// Where an `inherit_cwd` task starts in its sandbox: the caller's `$PWD`
/// when it is a directory under `/workbench` in the session's tree at
/// `working`.
///
/// `Ok(None)` keeps the default `/workbench`. `Err(notice)` also keeps it,
/// with a line for the caller that says why.
fn start_dir_in_box(
    inherit_cwd: bool,
    cwd: Option<&str>,
    working: &Path,
) -> Result<Option<String>, String> {
    let root = format!("/{}", sandbox::SESSION_DEFAULT_WD);
    let Some(cwd) = cwd.filter(|_| inherit_cwd) else {
        return Ok(None);
    };
    let cwd_trimmed = cwd.trim_end_matches('/');
    if cwd_trimmed == root {
        return Ok(None);
    }
    let notice = || {
        format!(
            "{} is not a directory under {root}, so the task runs in {root}.",
            one_line(cwd)
        )
    };
    let Some(rel) = cwd_trimmed.strip_prefix(&format!("{root}/")) else {
        return Err(notice());
    };
    let rel_path = Path::new(rel);
    let plain = rel_path
        .components()
        .all(|c| matches!(c, std::path::Component::Normal(_)));
    if !plain {
        return Err(notice());
    }
    // A symlink the box made can point out of its tree, so resolve it and
    // accept only a directory under the resolved tree.
    let inside = match (
        working.canonicalize(),
        working.join(rel_path).canonicalize(),
    ) {
        (Ok(root_dir), Ok(dir)) => dir.starts_with(&root_dir) && dir.is_dir(),
        _ => false,
    };
    if !inside {
        return Err(notice());
    }
    Ok(Some(format!("{root}/{rel}")))
}

/// The code `min task run` exits with when the task does not exist.
const EXIT_NOT_FOUND: u8 = 4;
/// The code `min task run` exits with when it refuses the task's arguments
/// or an interactive task.
const EXIT_USAGE: u8 = 2;
/// The code `min task run` exits with when `min` itself fails, before or
/// around the task.
const EXIT_MIN_FAILURE: u8 = 125;
/// The code `min task run` exits with when the project configuration
/// (`minimal.toml` or a package file) is not valid.
const EXIT_CONFIG: u8 = 3;

/// The code a refused run exits with for the error that refused it: a
/// configuration error (a package layer included) is [`EXIT_CONFIG`], a
/// missing package, profile or stack is [`EXIT_NOT_FOUND`], and any other
/// error is a failure of `min` itself.
fn refusal_exit_code(e: &Error) -> u8 {
    match e {
        Error::Config(_) | Error::Format(_) | Error::MFile(_) => EXIT_CONFIG,
        Error::Graph(g) => match **g {
            graph::Error::Decode(_)
            | graph::Error::ConflictingPackage { .. }
            | graph::Error::ConflictingProfile { .. }
            | graph::Error::ConflictingStack { .. }
            | graph::Error::ConflictingContainer { .. }
            | graph::Error::UpstreamNotPinned { .. }
            | graph::Error::NoSuchOutput { .. } => EXIT_CONFIG,
            graph::Error::NoSuchPkg { .. }
            | graph::Error::NoSuchProfile { .. }
            | graph::Error::NoSuchStack { .. } => EXIT_NOT_FOUND,
            graph::Error::Fetch(_) => EXIT_MIN_FAILURE,
        },
        _ => EXIT_MIN_FAILURE,
    }
}

/// Ends a refused run with `exit:<code>` for a helper that relays exit
/// codes. An older helper stops at the `error:` line and gets nothing more.
fn relay_refusal_exit(stream: &mut UnixStream, relays: bool, task: &str, code: u8) {
    if relays {
        tracing::info!(
            task = %task,
            exit_code = code,
            "relaying a refused task run's exit code to the in-box min helper",
        );
        let _ = writeln!(stream, "exit:{code}");
    }
}

/// The code `min task run` exits with for a run's result: 0 for a run that
/// passed, and the failing invocation's code for one that failed. A code
/// outside 1 to 255 becomes 1. `None` for an error that is not the task's
/// own exit, which the channel reports as an error.
fn relayed_exit_code(result: &Result<(), Error>) -> Option<u8> {
    match result {
        Ok(()) => Some(0),
        Err(Error::Execution { code, .. }) => {
            Some(u8::try_from(*code).ok().filter(|c| *c != 0).unwrap_or(1))
        }
        Err(_) => None,
    }
}

/// Runs each invocation in `dir`, streams its stdout to `stream` as `msg:`
/// lines and its stderr as `err_tag` lines, and stops at the first one that fails, as `Env::run` does.
/// `Env::run` has no working directory of its own, so an `inherit_cwd` task
/// runs here.
///
/// `Env::run` gives a task no stdin either, so a run whose helper forwards
/// its stdin runs here too (T123). With `stdin`, the first invocation gets
/// a stdin pipe, the channel sends the helper `stdin:`, and the copy of the
/// forwarded stdin to the pipe goes into `stdin`. Only the first invocation
/// of a multi-invocation task gets the forwarded stdin. The later
/// invocations get none. https://github.com/gominimal/minimal/issues/3094
/// tracks this gap.
async fn run_invocations_in(
    env: &mut mctx::Env<'_>,
    invocations: Vec<sandbox::config::Invocation>,
    dir: Option<&str>,
    stream: &UnixStream,
    err_tag: &'static str,
    mut stdin: Option<&mut Option<crate::exec::ForwardedStdin>>,
) -> Result<(), Error> {
    let io = |what: &'static str| move |e: std::io::Error| Error::IO(what, Default::default(), e);
    let shared = Arc::new(Mutex::new(
        stream.try_clone().map_err(io("creating writers"))?,
    ));
    for (idx, invocation) in invocations.iter().enumerate() {
        // One plan, container and attach per invocation: hakoniwa unshares
        // per spawn, so each one needs its own network.
        let planned = env.plan_launch().await?;
        let container = env.container(planned.plan())?;
        let mut cmd = env.invocation_command(&container, invocation)?;
        if let Some(dir) = dir {
            cmd.current_dir(dir);
        }
        let mut stdin = stdin.as_deref_mut().filter(|_| idx == 0);
        if stdin.is_some() {
            cmd.stdin(hakoniwa::Stdio::piped());
        }
        cmd.stdout(hakoniwa::Stdio::MakePipe);
        cmd.stderr(hakoniwa::Stdio::MakePipe);
        let mut child = sandbox::forker::on_fork_thread(move || cmd.spawn())
            .map_err(|e| Error::Other(anyhow::anyhow!("spawn failed: {e}")))?;
        let guard = match planned.attach_child(&mut child).await {
            Ok(guard) => guard,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e.into());
            }
        };
        if let Some(slot) = stdin.as_deref_mut() {
            let started = match child.stdin.take() {
                Some(pipe) => crate::exec::ForwardedStdin::start(
                    stream,
                    std::fs::File::from(std::os::fd::OwnedFd::from(pipe)),
                ),
                None => Err(std::io::Error::other("the task has no stdin pipe")),
            };
            match started {
                Ok(forwarded) => {
                    *slot = Some(forwarded);
                    // The helper sends its stdin only after this line, so
                    // the request line the listener read is all it read.
                    let mut stream = shared
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let _ = writeln!(stream, "stdin:");
                }
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    if let Some(guard) = guard {
                        guard.teardown().await;
                    }
                    return Err(forwarded_stdin_error(&e));
                }
            }
        }
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let (out, err) = (shared.clone(), shared.clone());
        let status = crate::traced::spawn_blocking(move || {
            let out = std::thread::spawn(move || stdout.map(|p| forward_lines(p, &out, "msg")));
            let err = std::thread::spawn(move || stderr.map(|p| forward_lines(p, &err, err_tag)));
            let _ = out.join();
            let _ = err.join();
            child.wait()
        })
        .await;
        // The task ended, so a read of the forwarded stdin that fails now
        // does not fail the run.
        if let Some(Some(forwarded)) = stdin.as_deref() {
            forwarded.task_ended();
        }
        if let Some(guard) = guard {
            guard.teardown().await;
        }
        drop(container);
        let status = status
            .map_err(|e| Error::Other(anyhow::anyhow!("waiting for the task failed: {e}")))?
            .map_err(|e| Error::Other(anyhow::anyhow!("waiting for the task failed: {e}")))?;
        if !status.success() {
            return Err(Error::Execution {
                idx,
                code: status.code,
                reason: status.reason.clone(),
                stderr: String::new(),
                stdout: String::new(),
            });
        }
    }
    Ok(())
}

/// The failure of a run whose stdin could not reach its task.
fn forwarded_stdin_error(e: &std::io::Error) -> Error {
    Error::Other(anyhow::anyhow!(
        "min task run could not pass its stdin to the task: {e}"
    ))
}

/// Copies `pipe` to `stream` as one `<tag>:` line per line, until EOF.
fn forward_lines(pipe: impl std::io::Read, stream: &Mutex<UnixStream>, tag: &str) {
    use std::io::BufRead as _;
    let mut reader = std::io::BufReader::new(pipe);
    let mut line = Vec::new();
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let text = String::from_utf8_lossy(&line);
                let text = text.strip_suffix('\n').unwrap_or(&text);
                let mut stream = stream
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let _ = writeln!(stream, "{tag}:{text}");
            }
        }
    }
}

/// An [`tokio::io::AsyncWrite`] that frames whatever is written to it into
/// newline-delimited `<tag>:` lines on a shared [`UnixStream`], `msg:` by
/// default.
///
/// Used to stream a sandboxed build's stdout/stderr back to the `min` client.
/// Two writers can share one connection (via `Arc<Mutex<_>>`) so stdout and
/// stderr don't interleave mid-line.
struct StreamWriter {
    stream: Arc<Mutex<UnixStream>>,
    buf: Vec<u8>,
    tag: &'static str,
}

impl StreamWriter {
    fn pair(stream: &UnixStream) -> Result<(Self, Self), std::io::Error> {
        Self::pair_tagged(stream, "msg")
    }

    /// A stdout writer that emits `msg:` and a stderr writer that emits
    /// `err_tag`.
    fn pair_tagged(
        stream: &UnixStream,
        err_tag: &'static str,
    ) -> Result<(Self, Self), std::io::Error> {
        let shared = Arc::new(Mutex::new(stream.try_clone()?));
        Ok((
            Self {
                stream: shared.clone(),
                buf: Vec::new(),
                tag: "msg",
            },
            Self {
                stream: shared,
                buf: Vec::new(),
                tag: err_tag,
            },
        ))
    }

    fn emit_lines(&mut self) {
        while let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
            let line = String::from_utf8_lossy(&self.buf[..pos]);
            let _ = writeln!(self.stream.lock().unwrap(), "{}:{line}", self.tag);
            self.buf.drain(..=pos);
        }
    }
}

impl tokio::io::AsyncWrite for StreamWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.buf.extend_from_slice(buf);
        self.emit_lines();
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

/// How many output lines of one build [`LineTap`] keeps.
const TAPPED_LINES: usize = 64;

/// The most bytes of one unfinished line [`LineTap`] holds. Past this bound
/// it keeps only the tail, so output that never ends a line stays bounded.
const TAPPED_LINE_BYTES: usize = 4096;

/// A writer that passes every byte to `inner` and keeps the last
/// [`TAPPED_LINES`] lines in `lines` (NET-155), so a build that fails can say
/// what it could not reach. A `\n` or a `\r` ends a line, so a progress meter
/// that redraws with `\r` gives lines too. The text after the last line end
/// is kept as a line when the tap shuts down or is dropped.
pub(crate) struct LineTap<W> {
    inner: W,
    buf: Vec<u8>,
    lines: Arc<Mutex<std::collections::VecDeque<String>>>,
}

impl<W> LineTap<W> {
    pub(crate) fn new(inner: W, lines: Arc<Mutex<std::collections::VecDeque<String>>>) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            lines,
        }
    }

    /// How many bytes of an unfinished line the tap holds.
    #[cfg(test)]
    pub(crate) fn pending(&self) -> usize {
        self.buf.len()
    }

    fn keep(&self, line: &[u8]) {
        if line.is_empty() {
            return;
        }
        let line = String::from_utf8_lossy(line).into_owned();
        let mut lines = self
            .lines
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if lines.len() == TAPPED_LINES {
            lines.pop_front();
        }
        lines.push_back(line);
    }

    /// Keeps the text after the last line end as a line.
    fn flush_line(&mut self) {
        let rest = std::mem::take(&mut self.buf);
        self.keep(&rest);
    }
}

impl<W> Drop for LineTap<W> {
    fn drop(&mut self) {
        self.flush_line();
    }
}

impl<W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for LineTap<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let this = &mut *self;
        let written = match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => n,
            other => return other,
        };
        this.buf.extend_from_slice(&buf[..written]);
        if let Some(last) = this.buf.iter().rposition(|&b| b == b'\n' || b == b'\r') {
            let done: Vec<u8> = this.buf.drain(..=last).collect();
            for line in done.split(|&b| b == b'\n' || b == b'\r') {
                this.keep(line);
            }
        }
        if this.buf.len() > TAPPED_LINE_BYTES {
            let cut = this.buf.len() - TAPPED_LINE_BYTES;
            this.buf.drain(..cut);
        }
        Poll::Ready(Ok(written))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.flush_line();
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The destination a failed build's output says it could not reach
/// (NET-155), read from the last lines the build printed, newest first, so
/// the failure that ended the build wins over an earlier tolerated one. It
/// knows the failure lines of `curl` and `wget`, which also cover `git` over
/// HTTPS: a host it could not resolve, or a host and port it could not
/// connect to. It also knows the line a build writes when it could not
/// fetch a web source it declares, and names the host the download could
/// not connect to, or the source's host when the line names none.
/// `None` when no line names a destination.
pub(crate) fn refused_destination<'a>(lines: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let word = |rest: &str| -> Option<String> {
        let host: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
            .collect();
        let host = host.trim_end_matches(['.', ':']);
        (!host.is_empty()).then(|| host.to_string())
    };
    let lines: Vec<&str> = lines.into_iter().collect();
    lines.into_iter().rev().find_map(|line| {
        // A web source the build declares, fetched in the box's leaf:
        // `could not fetch the source https://example.com/a.tar.gz: ...`
        // Only a connection the download could not open names a
        // destination. A bad hash or a failed extract is no refusal.
        // The download names the host it could not connect to, which is
        // the host a redirect sent it to. The source's own host stands in
        // only when that text names no host.
        if let Some(rest) = line.strip_prefix(WEB_SOURCE_FAILURE) {
            let (_, connect) = rest.split_once(WEB_SOURCE_CONNECT_FAILURE)?;
            return connect_host(connect).or_else(|| source_host(rest));
        }
        // curl: `Could not resolve host: example.com`
        if let Some((_, rest)) = line.split_once("Could not resolve host: ") {
            return word(rest);
        }
        // curl: `Failed to connect to example.com port 443 after 3 ms: ...`
        if let Some((_, rest)) = line.split_once("Failed to connect to ") {
            let host = word(rest)?;
            let port = rest
                .split_once(" port ")
                .map(|(_, p)| {
                    p.chars()
                        .take_while(char::is_ascii_digit)
                        .collect::<String>()
                })
                .filter(|p| !p.is_empty());
            return Some(match port {
                Some(port) => format!("{host}:{port}"),
                None => host,
            });
        }
        // wget: `Resolving example.com (example.com)... failed: ...`
        if let Some(rest) = line.strip_prefix("Resolving ")
            && line.contains("... failed")
        {
            return word(rest);
        }
        // wget: `Connecting to example.com (example.com)|1.2.3.4|:443... failed: ...`
        if let Some(rest) = line.strip_prefix("Connecting to ")
            && line.contains("... failed")
        {
            let host = word(rest)?;
            let port = rest
                .rsplit_once("|:")
                .map(|(_, p)| {
                    p.chars()
                        .take_while(char::is_ascii_digit)
                        .collect::<String>()
                })
                .filter(|p| !p.is_empty());
            return Some(match port {
                Some(port) if !host.ends_with(&format!(":{port}")) => format!("{host}:{port}"),
                _ => host,
            });
        }
        None
    })
}

/// How the line starts that a package build writes when it could not fetch
/// a web source it declares (NET-155). `op`'s spec build writes it, followed
/// by the source's URL.
const WEB_SOURCE_FAILURE: &str = "could not fetch the source ";

/// What the error of a web-source fetch says when the download could not
/// open a connection to the source. `common`'s placed download writes it,
/// followed by the host and the port.
const WEB_SOURCE_CONNECT_FAILURE: &str = "could not connect to ";

/// The error line for a package build of the box `box_name` that could not
/// connect to a source, or that needs a network the box does not have
/// (NET-155), or `None` for any other failure. `failure` is the build's own
/// error: its package, then the download's text, whose reason the line keeps.
pub(crate) fn unreachable_source(failure: &str, box_name: &str) -> Option<String> {
    let (head, rest) = failure.split_once("` failed to build: ")?;
    let (_, package) = head.rsplit_once('`')?;
    source_failure(package, box_name, rest.strip_prefix("other: ")?)
}

/// [`unreachable_source`], for a package already named. `text` is the error
/// of the build, after its kind. A refusal by the box's rules, or by its
/// having no network, gives the next step. Any other reason is the
/// download's own.
pub(crate) fn source_failure(package: &str, box_name: &str, text: &str) -> Option<String> {
    if text.lines().next() == Some(op::NEEDS_NETWORK) {
        return Some(format!(
            "the build of {package} needs the network, and box {box_name} has none. \
             To build it, activate a new session with --network host_ip"
        ));
    }
    let connect = text.strip_prefix(WEB_SOURCE_CONNECT_FAILURE)?;
    let host = connect_host(connect)?;
    let (_, why) = connect.lines().next()?.split_once(": ")?;
    let why = match why {
        common::RULES_REFUSE => egress_rules_refuse(box_name, Some(&host)),
        common::NO_NETWORK => match egress_remedy(&host) {
            Some(remedy) => format!("box {box_name} has no network. {remedy}"),
            None => format!("box {box_name} has no network"),
        },
        why => why.to_string(),
    };
    Some(format!(
        "the build of {package} could not reach {host}: {why}"
    ))
}

/// The host in the `<host>:<port>: <error>` text that follows
/// [`WEB_SOURCE_CONNECT_FAILURE`], without the port. `None` when the text
/// names no host and port.
fn connect_host(rest: &str) -> Option<String> {
    let addr = rest.split_once(": ").map_or(rest, |(a, _)| a);
    let addr = addr.split_whitespace().next()?;
    let (host, port) = addr.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    (!host.is_empty() && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()))
        .then(|| host.to_ascii_lowercase())
}

/// The host of the URL `rest` starts with: the authority after the scheme,
/// without a user name or a port. `None` when `rest` starts with no URL.
fn source_host(rest: &str) -> Option<String> {
    let (_, after) = rest.split_once("://")?;
    let authority = after.split(['/', '?', '#', ' ']).next()?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split_once(']').map(|(h, _)| h)?,
        None => authority.split(':').next()?,
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Whether the egress rules a box's package build runs under admit no
/// destination (NET-155): the build runs in the deny subtree of the
/// classifier tree, or on the network of an own-address box whose rules
/// admit nothing. A build with neither runs under no rules of the box.
pub(crate) fn build_denies_all(
    leaf: Option<&ClassifierLeaf>,
    network: Option<&op::BuildNetwork>,
) -> bool {
    match leaf {
        Some(leaf) => leaf.is_deny(),
        None => network.is_some_and(op::BuildNetwork::denies_all),
    }
}

/// The error line for an in-box patched build that the egress rules of its
/// box refused (NET-155), or `None` when the refusal is not the rules'.
/// `failure` is the build's own error. The error of a patched build names no
/// package, so the refusal holds only when that error itself carries the
/// destination [`refused_destination`] reads from `lines`. A build that
/// tolerated a failed download and then failed for another reason is left
/// with its own error.
pub(crate) fn patched_build_refusal<'a>(
    denies_all: bool,
    package: &str,
    box_name: &str,
    failure: &str,
    lines: impl IntoIterator<Item = &'a str>,
) -> Option<String> {
    let lines: Vec<&str> = lines.into_iter().collect();
    let destination = refused_destination(lines.iter().copied())?;
    if !failure.contains(destination_host(&destination)) {
        return None;
    }
    egress_refusal(denies_all, package, box_name, lines)
}

/// A destination [`refused_destination`] read, without its port.
fn destination_host(destination: &str) -> &str {
    destination
        .rsplit_once(':')
        .filter(|(h, p)| !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        .map_or(destination, |(h, _)| h)
}

/// The next step that lets a box's builds reach `host`, or `None` when `host`
/// is no name `--allow-dns-hosts` can admit. The step names `--network
/// own_ip` because a box on the default network refuses that flag at create
/// (`classifier::unenforceable_rules`). It also names the `minimal.toml` key
/// that does what the flag does: `min` reads `network.egress` under
/// `[defaults]` into a new session's rules (NET-060). The file sets no
/// network mode, so that step still names `--network own_ip`.
fn egress_remedy(host: &str) -> Option<String> {
    (boxes::is_valid_dns_host(host) && host.parse::<std::net::Ipv4Addr>().is_err()).then(|| {
        format!(
            "To allow it, activate a new session with --network own_ip --allow-dns-hosts {host}. \
             Or add {host} to network.egress.allow_dns_hosts under [defaults] in minimal.toml, \
             then activate a new session with --network own_ip"
        )
    })
}

/// Why a box's egress rules refused a build, with the next step when `host`
/// has one.
fn egress_rules_refuse(box_name: &str, host: Option<&str>) -> String {
    let refused = format!("the egress rules of box {box_name} do not allow it");
    match host.and_then(egress_remedy) {
        Some(remedy) => format!("{refused}. {remedy}"),
        None => refused,
    }
}

/// The error line for a package build that the egress rules of its box
/// refused (NET-155), or `None` when the refusal is not the rules'.
/// `denies_all` is [`build_denies_all`]'s answer for the build. A box whose
/// rules admit no destination is refused every one, so any destination
/// outside the box zone that its build could not reach was refused by the
/// box's rules. Any other box's failures are left as the build reported them.
pub(crate) fn egress_refusal<'a>(
    denies_all: bool,
    package: &str,
    box_name: &str,
    lines: impl IntoIterator<Item = &'a str>,
) -> Option<String> {
    if !denies_all {
        return None;
    }
    let lines: Vec<&str> = lines.into_iter().collect();
    let line = lines
        .into_iter()
        .rev()
        .find(|line| refused_destination([*line]).is_some())?;
    let destination = refused_destination([line])?;
    // Box-zone names are not subject to egress rules, so a failure to
    // resolve or reach one is not a refusal by the box's rules.
    let host = destination
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let zone_apex = boxes::core::zone_answer::ZONE_APEX;
    if host == zone_apex || host.ends_with(&format!(".{zone_apex}")) {
        return None;
    }
    let reason = egress_rules_refuse(box_name, Some(destination_host(&destination)));
    Some(format!(
        "the build of {package} could not reach {destination}: {reason}"
    ))
}

/// Runs `build`, a box's package builds, while it reads the events they
/// send on `log_rx`, and returns the error to report when they fail
/// (NET-155). A build the box's egress rules refused names the destination
/// and the box before the build's own error. Any other failure is the
/// build's own error, unchanged. `build` resolves to the build's error, if
/// any, and drops the events' sender when it ends.
pub(crate) async fn tapped_build(
    build: impl std::future::Future<Output = Option<String>>,
    mut log_rx: futures::channel::mpsc::UnboundedReceiver<orchestrator::BuildEvent>,
    placement: &crate::box_ops::BuildPlacement,
) -> Result<(), String> {
    use futures::StreamExt as _;
    let tap = async {
        let mut tap = crate::box_ops::BuildTap::default();
        while let Some(event) = log_rx.next().await {
            tap.observe(&event, placement);
        }
        tap
    };
    let (failure, tap) = tokio::join!(build, tap);
    match failure {
        None => Ok(()),
        Some(failure) => Err(tap.failure(placement, failure)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NET-155: a build whose source download could not connect reports the
    /// package, the host and the reason, in the words of the user-facing
    /// line. Any other failure is left as the build reported it.
    #[test]
    fn unreachable_source_names_the_package_and_the_host() {
        assert_eq!(
            unreachable_source(
                "session spawn: `claude-code` failed to build: other: could not connect to \
                     storage.googleapis.com:443: no answer after 15s",
                "x"
            )
            .as_deref(),
            Some(
                "the build of claude-code could not reach storage.googleapis.com: no answer after 15s"
            )
        );
        assert_eq!(
            unreachable_source(
                "`zsh` failed to build: other: could not connect to objects.example.net:443: \
                     Connection refused (os error 111)\nsecond line",
                "x"
            )
            .as_deref(),
            Some(
                "the build of zsh could not reach objects.example.net: \
                     Connection refused (os error 111)"
            )
        );
        assert_eq!(
            unreachable_source(
                "`foo` failed to build: other: could not connect to sources.example.com:443: \
                     the egress rules do not allow this host",
                "x"
            )
            .as_deref(),
            Some(
                "the build of foo could not reach sources.example.com: \
                     the egress rules of box x do not allow it. \
                     To allow it, activate a new session with \
                     --network own_ip --allow-dns-hosts sources.example.com. \
                     Or add sources.example.com to network.egress.allow_dns_hosts under [defaults] in minimal.toml, \
                     then activate a new session with --network own_ip"
            )
        );
        assert_eq!(
            unreachable_source(
                "`foo` failed to build: other: could not connect to sources.example.com:443: \
                     the box has no network",
                "x"
            )
            .as_deref(),
            Some(
                "the build of foo could not reach sources.example.com: \
                     box x has no network. \
                     To allow it, activate a new session with \
                     --network own_ip --allow-dns-hosts sources.example.com. \
                     Or add sources.example.com to network.egress.allow_dns_hosts under [defaults] in minimal.toml, \
                     then activate a new session with --network own_ip"
            )
        );
        assert_eq!(
            unreachable_source(
                "`foo` failed to build: other: the build needs the network and the box has none",
                "x"
            )
            .as_deref(),
            Some(
                "the build of foo needs the network, and box x has none. \
                     To build it, activate a new session with --network host_ip"
            )
        );
        for other in [
            "`foo` failed to build: other: hash mismatch",
            "`foo` failed to build: exit status 1: could not connect to a.example:443: no",
            "could not connect to a.example:443: no",
        ] {
            assert_eq!(unreachable_source(other, "x"), None, "{other}");
        }
    }

    /// A refusal gives a next step only where the step would work: a host
    /// name that a build's own connection or its source fetch named, without
    /// its port, and not a literal address.
    #[test]
    fn a_refusal_gives_a_next_step_only_where_it_works() {
        let refused = |line: &str| egress_refusal(true, "foo", "x", [line]).unwrap();
        let with_step = |destination: &str, host: &str| {
            format!(
                "the build of foo could not reach {destination}: \
                 the egress rules of box x do not allow it. \
                 To allow it, activate a new session with \
                 --network own_ip --allow-dns-hosts {host}. \
                 Or add {host} to network.egress.allow_dns_hosts under [defaults] in minimal.toml, \
                 then activate a new session with --network own_ip"
            )
        };
        let without_step = |destination: &str| {
            format!(
                "the build of foo could not reach {destination}: \
                 the egress rules of box x do not allow it"
            )
        };
        for (line, want) in [
            (
                "curl: (6) Could not resolve host: example.com",
                with_step("example.com", "example.com"),
            ),
            (
                "curl: (7) Failed to connect to example.com port 8080 after 2 ms: refused",
                with_step("example.com:8080", "example.com"),
            ),
            (
                "Connecting to 93.184.215.14:80... failed: No route to host.",
                without_step("93.184.215.14:80"),
            ),
            (
                "curl: (7) Failed to connect to [2001:db8::1] port 443 after 2 ms: refused",
                without_step("[2001:db8::1]:443"),
            ),
            (
                "could not fetch the source https://example.com/a.tar.gz: \
                 could not connect to example.com:443: refused",
                with_step("example.com", "example.com"),
            ),
            (
                "could not fetch the source gs://a-bucket/a.tar.gz: \
                 could not connect to storage.googleapis.com:443: refused",
                with_step("storage.googleapis.com", "storage.googleapis.com"),
            ),
        ] {
            assert_eq!(refused(line), want, "{line}");
        }
    }

    /// A helper request arrives as `traceparent%<tp>%<method>%<data>` when
    /// the box has a `TRACEPARENT`, and bare otherwise; the prefix is taken
    /// off before dispatch and the request's span is named for the method.
    /// Without a subscriber the adopted ids are not observable here; the
    /// shape of the request is.
    #[test]
    fn channel_request_span_strips_the_traceparent_prefix() {
        let tp = "00-af79b928d8ae574b659f1fbf40208758-ed105930ec67df47-01";
        let expose = format!("traceparent%{tp}%net-expose%8770");
        let (_, request, _) = super::channel_request_span(&expose, "b", None);
        assert_eq!(request, "net-expose%8770");
        let materialize = format!("traceparent%{tp}%materialize%/workbench%--output o o717b");
        let (_, request, _) = super::channel_request_span(&materialize, "b", None);
        assert_eq!(request, "materialize%/workbench%--output o o717b");
        let (_, request, _) = super::channel_request_span("net-expose%8770", "b", None);
        assert_eq!(request, "net-expose%8770");
        // A prefix with no request after it is handed on as-is, to be refused
        // by the dispatcher as unhandled input rather than guessed at.
        let (_, request, _) = super::channel_request_span("traceparent%garbage", "b", None);
        assert_eq!(request, "garbage");
    }

    /// A request from inside a box is served in a span that
    /// names the box and the session it belongs to, as the host knows them
    /// (the channel was built for that box by that session), whatever the
    /// line says: the box-supplied traceparent parents the span and sets
    /// nothing else.
    #[test]
    fn a_box_request_span_carries_the_host_side_box_identity() {
        use tracing_subscriber::layer::SubscriberExt as _;
        let log = crate::test_harness::SpanLog::default();
        let _g = tracing::subscriber::set_default(tracing_subscriber::registry().with(log.clone()));
        let session_id =
            boxes::SessionId::parse_str("7b3e1f2a-9c4d-4e5f-8a6b-1c2d3e4f5a6b").unwrap();
        let tp = "00-af79b928d8ae574b659f1fbf40208758-ed105930ec67df47-01";
        let line = format!("traceparent%{tp}%net-expose%8770");
        let (span, request, _) = super::channel_request_span(&line, "leaf-7", Some(session_id));
        assert_eq!(request, "net-expose%8770");
        drop(span);
        let served = log.one("session.channel", "method", "net-expose");
        assert_eq!(served.field("box.id"), Some("leaf-7"), "{served:?}");
        assert_eq!(
            served.field("session.id"),
            Some(session_id.to_string().as_str()),
            "{served:?}"
        );
        assert_eq!(
            served.field("trace_id"),
            Some("af79b928d8ae574b659f1fbf40208758"),
            "the line's traceparent parents the span"
        );

        // Without a session id the field is simply absent; the box id stays.
        let (span, _, _) = super::channel_request_span("net-expose%8770", "solo", None);
        drop(span);
        let bare = log.find("session.channel", "box.id", "solo");
        assert_eq!(bare.len(), 1);
        assert_eq!(bare[0].field("session.id"), None);
    }

    /// The span's `method` is one of the methods the channel
    /// dispatches, or `other`: a line with no `%`, an unknown method, or a
    /// long one never puts box-chosen text on the host's span.
    #[test]
    fn a_box_request_span_names_only_a_dispatched_method() {
        use tracing_subscriber::layer::SubscriberExt as _;
        let log = crate::test_harness::SpanLog::default();
        let _g = tracing::subscriber::set_default(tracing_subscriber::registry().with(log.clone()));
        let long = "x".repeat(64 * 1024);
        let tp = "00-af79b928d8ae574b659f1fbf40208758-ed105930ec67df47-01";
        for (line, method) in [
            ("net-expose%8770".to_string(), "net-expose"),
            (format!("traceparent%{tp}%materialize%/w%o"), "materialize"),
            ("add-session%jq".to_string(), "add-session"),
            ("net-expose".to_string(), "other"),
            ("no percent sign at all".to_string(), "other"),
            ("rm-rf%/".to_string(), "other"),
            (format!("{long}%x"), "other"),
            (long.clone(), "other"),
            (format!("traceparent%{tp}%{long}"), "other"),
        ] {
            let (span, _, _) = super::channel_request_span(&line, "m", None);
            drop(span);
            let served = log.find("session.channel", "box.id", "m");
            let last = served.last().expect("a session.channel span");
            assert_eq!(last.field("method"), Some(method), "{:.40}", line);
        }
        for method in super::CHANNEL_METHODS {
            assert_eq!(super::channel_method(&format!("{method}%")), *method);
        }
    }

    /// TEL-025: a `min` inside a box (the shipped helper, `__min_rpc`)
    /// hands the box's inherited `TRACEPARENT` to the daemon as the request
    /// line's `traceparent%` prefix, and the daemon serves the request in a
    /// span that adopts it, so the daemon's work for it joins the outer
    /// trace. The inner `min` is a shell function: it has no exporter and
    /// exports nothing. The helper runs under bash with a `socat` stand-in
    /// that records the line it would send; the span is the one the channel
    /// actor serves that line in. A value that is not the 55-character W3C
    /// form is not forwarded at all, so a `%` in it cannot shift the split.
    /// A box handed the opt-out (`MINIMAL_OTEL=off`, TEL-045) sends the
    /// `otel%off%` prefix instead, and never its `TRACEPARENT`.
    #[cfg(unix)]
    #[test]
    fn a_min_in_a_box_joins_the_outer_trace_through_the_helper_prefix() {
        use std::os::unix::fs::PermissionsExt as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let helper = tmp.path().join("min_helper.sh");
        std::fs::write(&helper, MIN_SCRIPT).unwrap();
        let sent_line = tmp.path().join("line");
        let bin = tmp.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let socat = bin.join("socat");
        std::fs::write(
            &socat,
            format!("#!/bin/sh\ncat > '{}'\necho done:\n", sent_line.display()),
        )
        .unwrap();
        std::fs::set_permissions(&socat, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let send_with = |traceparent: Option<&str>, otel: Option<&str>| -> String {
            let mut cmd = std::process::Command::new("bash");
            cmd.arg("-c")
                .arg(format!(
                    ". '{}'; __min_rpc net-expose 8770",
                    helper.display()
                ))
                .env("PATH", &path)
                .env_remove("TRACEPARENT")
                .env_remove(minimald_rpc::trace::OTEL_ENV);
            if let Some(tp) = traceparent {
                cmd.env("TRACEPARENT", tp);
            }
            if let Some(otel) = otel {
                cmd.env(minimald_rpc::trace::OTEL_ENV, otel);
            }
            let out = cmd.output().expect("run bash");
            assert!(out.status.success(), "{out:?}");
            std::fs::read_to_string(&sent_line)
                .unwrap()
                .trim_end_matches('\n')
                .to_string()
        };
        let send = |traceparent: Option<&str>| send_with(traceparent, None);

        let tp = "00-af79b928d8ae574b659f1fbf40208758-ed105930ec67df47-01";
        let line = send(Some(tp));
        assert_eq!(line, format!("traceparent%{tp}%net-expose%8770"));

        let log = crate::test_harness::SpanLog::default();
        let _g = tracing::subscriber::set_default(tracing_subscriber::registry().with(log.clone()));
        let (span, request, _) = super::channel_request_span(&line, "inner", None);
        assert_eq!(request, "net-expose%8770");
        drop(span);
        let served = log.one("session.channel", "box.id", "inner");
        assert_eq!(
            served.field("trace_id"),
            Some("af79b928d8ae574b659f1fbf40208758"),
            "the daemon's span joins the outer trace: {served:?}"
        );
        assert_eq!(
            served.field("parent_span_id"),
            Some("ed105930ec67df47"),
            "{served:?}"
        );

        // Not the W3C form: the request goes bare, and the daemon mints.
        for bad in [
            "",
            "garbage",
            "00-af79b928d8ae574b659f1fbf40208758-ed105930ec67df47-0",
            "00-af79b928d8ae574b659f1fbf40208758%ed105930ec67df4-01",
            "00-AF79B928D8AE574B659F1FBF40208758-ED105930EC67DF47-01",
            "00-af79b928d8ae574b659f1fbf40208758-ed105930ec67df47-01%x",
            "00-af79b928d8ae574b659f1fbf40208758-ed105930ec67df47-01 x",
        ] {
            assert_eq!(send(Some(bad)), "net-expose%8770", "{bad:?}");
        }
        assert_eq!(send(None), "net-expose%8770");

        // TEL-045: a box handed the opt-out sends it, and never its
        // TRACEPARENT; only `off` opts out, as the daemon reads the marker.
        let off = minimald_rpc::trace::OTEL_OFF;
        assert_eq!(send_with(Some(tp), Some(off)), "otel%off%net-expose%8770");
        assert_eq!(send_with(None, Some(off)), "otel%off%net-expose%8770");
        assert_eq!(
            send_with(Some(tp), Some("on")),
            format!("traceparent%{tp}%net-expose%8770")
        );
    }

    /// Every session rootfs carries the per-attach environment hook for every
    /// shell we support, at that shell's own vendor/system integration point
    /// — installed by the daemon, so no loadout or project author has to know
    /// the mechanism exists, and outside the session home, so no loadout
    /// patch can collide with one.
    #[test]
    fn every_session_rootfs_carries_the_attach_env_hooks() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        install_min_helpers(rootfs).unwrap();

        // (path in the rootfs, a fragment only that shell's hook contains)
        // Two hooks per shell, and the pre-execution one is the load-bearing
        // half: the first command typed at a prompt drawn *before* the attach
        // must already see the new terminal, which a prompt-only hook cannot
        // do (that prompt already fired). bash's `DEBUG` trap covers both.
        let expected = [
            (
                "usr/share/minimal/attach-env.bash",
                "trap '__minimal_attach_env' DEBUG",
            ),
            ("etc/zsh/zshrc", "add-zsh-hook precmd __minimal_attach_env"),
            ("etc/zsh/zshrc", "add-zsh-hook preexec __minimal_attach_env"),
            (
                "usr/share/fish/vendor_conf.d/00-minimal-attach-env.fish",
                "--on-event fish_prompt",
            ),
            (
                "usr/share/fish/vendor_conf.d/00-minimal-attach-env.fish",
                "--on-event fish_preexec",
            ),
            (
                "usr/share/nushell/vendor/autoload/00-minimal-attach-env.nu",
                "$env.config.hooks.pre_prompt",
            ),
            (
                "usr/share/nushell/vendor/autoload/00-minimal-attach-env.nu",
                "$env.config.hooks.pre_execution",
            ),
            // The POSIX tier sources the file outright: `$ENV` fires once, at
            // startup, and POSIX has no hook to refresh from afterwards.
            (
                "usr/share/minimal/attach-env-posix.sh",
                "/home/.local/state/minimal/attach-env.sh",
            ),
        ];
        for (rel, fragment) in expected {
            let body = std::fs::read_to_string(rootfs.join(rel))
                .unwrap_or_else(|e| panic!("{rel} should be installed: {e}"));
            assert!(body.contains(fragment), "{rel} is missing its hook: {body}");
            // Each reads the published file by absolute path rather than
            // through `$MINIMAL_ATTACH_ENV`, so a composed variable of that
            // name cannot redirect or break the refresh.
            assert!(
                body.contains(crate::box_runtime::ATTACH_ENV_SH)
                    || body.contains(crate::box_runtime::ATTACH_ENV_FISH)
                    || body.contains(crate::box_runtime::ATTACH_ENV_JSON),
                "{rel} should hard-code the published path: {body}"
            );
            assert!(
                !body.contains("$MINIMAL_ATTACH_ENV"),
                "{rel} must not depend on a composed variable: {body}"
            );
        }
    }

    /// The bash rc carries both halves, hook first. A session bash reads
    /// nothing else, so if the user's startup file were sourced before the
    /// trap were set, a `~/.bashrc` could see a session without a `TERM`
    /// refresh — the one ordering rule this file has.
    #[test]
    fn the_bash_rc_installs_the_hook_before_the_users_startup_file() {
        let tmp = tempfile::tempdir().unwrap();
        install_min_helpers(tmp.path()).unwrap();

        let body =
            std::fs::read_to_string(tmp.path().join("usr/share/minimal/attach-env.bash")).unwrap();
        let hook = body
            .find("trap '__minimal_attach_env' DEBUG")
            .expect("the rc must install the hook");
        let user_rc = body
            .find("$HOME/.bashrc")
            .expect("the rc must reach the user's startup file");
        assert!(hook < user_rc, "the hook must be installed first: {body}");
    }

    /// Runs a rootfs's bash rc the way an attach does — the argv
    /// `crate::attach_shell`'s table gives bash — with `home` standing in
    /// for the session home, and returns the shell's stdout.
    ///
    /// `None` when the host has no bash to run it with: the caller skips,
    /// matching the repo's self-skip-locally convention
    /// (`crates/common/tests/shell_lint.rs`). The Linux lanes have bash, so
    /// these run for real in CI.
    fn run_session_bash(rootfs: &Path, home: &Path, command: &str) -> Option<String> {
        let rc = rootfs
            .join(ATTACH_ENV_BASH_RC_DIR)
            .join(ATTACH_ENV_BASH_RC_NAME);
        let out = std::process::Command::new("bash")
            .args(["--noprofile", "--rcfile"])
            .arg(&rc)
            // `-i` is what makes bash read an `--rcfile` at all, and it is
            // what a session bash is started with. Without a tty it warns
            // about job control on stderr, which is why only stdout is read.
            .args(["-i", "-c", command])
            .env("HOME", home)
            // The rc under test is the only startup file that may run: the
            // developer's own environment must not reach it.
            .env_remove("BASH_ENV")
            .env_remove("ENV")
            .output()
            .map_err(|e| eprintln!("no bash to run the session rc with — skipping: {e}"))
            .ok()?;
        assert!(
            out.status.success(),
            "the session rc should leave a usable shell: {}",
            String::from_utf8_lossy(&out.stderr),
        );
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// A rootfs plus an empty session home, ready for [`run_session_bash`].
    fn rootfs_and_home() -> (TempDir, std::path::PathBuf, std::path::PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs");
        let home = tmp.path().join("home");
        std::fs::create_dir_all(&rootfs).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        install_min_helpers(&rootfs).unwrap();
        (tmp, rootfs, home)
    }

    /// The point of the whole file: a `~/.bashrc` patched into the session
    /// home runs, and runs *after* the daemon's hook is in place — so the
    /// same `dest = ".bashrc"` patch that works for `.zshrc` and
    /// `config.fish` works for bash.
    #[test]
    fn a_patched_bashrc_is_sourced_after_the_hook() {
        let (_tmp, rootfs, home) = rootfs_and_home();
        std::fs::write(
            home.join(".bashrc"),
            // `declare -F` asks whether the hook's function is defined yet,
            // which is only true if the first half of the rc has run.
            "echo bashrc-ran\ndeclare -F __minimal_attach_env >/dev/null && echo hook-first\n",
        )
        .unwrap();

        let Some(out) = run_session_bash(&rootfs, &home, "echo prompt-ready") else {
            return;
        };
        assert!(out.contains("bashrc-ran"), "got: {out}");
        assert!(out.contains("hook-first"), "got: {out}");
        assert!(out.contains("prompt-ready"), "got: {out}");
    }

    /// The login chain stays unread, which is what bash does: those files
    /// belong to a *login* shell, and this one is not one. A home carrying
    /// all four gets `~/.bashrc` alone — sourcing a `~/.bash_profile` here
    /// would run once-per-login setup in a shell reporting `login_shell` as
    /// off, which happens nowhere else a bash user has been.
    #[test]
    fn the_login_chain_is_not_sourced() {
        let (_tmp, rootfs, home) = rootfs_and_home();
        std::fs::write(home.join(".bashrc"), "echo bashrc-ran\n").unwrap();
        for file in [".bash_profile", ".bash_login", ".profile"] {
            std::fs::write(home.join(file), format!("echo {file}-ran\n")).unwrap();
        }

        let Some(out) = run_session_bash(&rootfs, &home, "echo prompt-ready") else {
            return;
        };
        assert_eq!(
            out.matches("bashrc-ran").count(),
            1,
            "the rc should be sourced exactly once, got: {out}"
        );
        for file in [".bash_profile", ".bash_login", ".profile"] {
            assert!(
                !out.contains(&format!("{file}-ran")),
                "{file} is a login shell's file and must stay unread, got: {out}"
            );
        }
    }

    /// And a home carrying *only* a login-chain file gets nothing — the same
    /// silence `docker exec -it … bash` or a Linux terminal emulator gives
    /// it. The fix is the patch's `dest`, which is the user's to name.
    #[test]
    fn a_login_chain_file_alone_is_not_a_bashrc() {
        for file in [".bash_profile", ".bash_login", ".profile"] {
            let (_tmp, rootfs, home) = rootfs_and_home();
            std::fs::write(home.join(file), format!("echo {file}-ran\n")).unwrap();

            let Some(out) = run_session_bash(&rootfs, &home, "echo prompt-ready") else {
                return;
            };
            assert!(
                !out.contains(&format!("{file}-ran")),
                "{file} must not stand in for ~/.bashrc, got: {out}"
            );
            assert!(out.contains("prompt-ready"), "got: {out}");
        }
    }

    /// The common case — a session home with no dotfiles at all — starts a
    /// shell that is quiet and whose first command sees a zero status, not
    /// the failed `-r` test of a file that was never there.
    #[test]
    fn a_home_with_no_startup_file_starts_cleanly() {
        let (_tmp, rootfs, home) = rootfs_and_home();

        let Some(out) = run_session_bash(&rootfs, &home, r"echo status=$?") else {
            return;
        };
        assert_eq!(out.trim(), "status=0", "got: {out}");
    }

    /// A rootfs whose own packages ship a global zsh rc keeps it: the hook is
    /// appended, and appending is idempotent across launches.
    #[test]
    fn installing_hooks_appends_to_a_shipped_zshrc_once() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        std::fs::create_dir_all(rootfs.join("etc/zsh")).unwrap();
        std::fs::write(
            rootfs.join("etc/zsh/zshrc"),
            "# shipped by the zsh package\n",
        )
        .unwrap();

        install_min_helpers(rootfs).unwrap();
        install_min_helpers(rootfs).unwrap();

        let body = std::fs::read_to_string(rootfs.join("etc/zsh/zshrc")).unwrap();
        assert!(body.contains("# shipped by the zsh package"), "{body}");
        assert_eq!(
            body.matches("add-zsh-hook precmd __minimal_attach_env")
                .count(),
            1,
            "the hook should be appended exactly once: {body}"
        );
    }

    /// Runs the installed `min` helper with `__min_rpc` stubbed out, so a
    /// `patched-build` invocation can be checked without a daemon socket.
    /// Returns `None` when the host has no bash, matching the repo's
    /// self-skip-locally convention.
    fn run_min_helper(rootfs: &Path, args: &str) -> Option<(String, String, i32)> {
        let script = rootfs.join("usr/bin/min");
        let out = std::process::Command::new("bash")
            .args([
                "-c",
                r#"
source "$1"
__min_rpc() { echo "RPC-CALLED:$*" >&2; return 1; }
min_patched_pkg $2
rc=$?
echo "rc=$rc"
exit $rc
"#,
                "_",
                script.to_str().unwrap(),
                args,
            ])
            .output()
            .map_err(|e| eprintln!("no bash to run the min helper with — skipping: {e}"))
            .ok()?;
        Some((
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
            out.status.code().unwrap_or(-1),
        ))
    }

    /// `min package patched-build --help` prints usage, exits 0, and makes no
    /// RPC — `--help` must not be forwarded to the daemon as a package name.
    #[test]
    fn patched_build_help_prints_usage_without_rpc() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        install_min_helpers(rootfs).unwrap();

        let Some((stdout, stderr, code)) = run_min_helper(rootfs, "--help") else {
            return;
        };
        assert_eq!(code, 0, "help should exit 0, got: {stdout} {stderr}");
        assert!(
            stdout.contains("Usage: min package patched-build <package name>"),
            "help should print usage on stdout, got: {stdout}"
        );
        assert!(
            !stderr.contains("RPC-CALLED"),
            "help must not reach the daemon, got: {stderr}"
        );
        assert!(stdout.contains("rc=0"), "got: {stdout}");
    }

    /// A missing name or a `-`-prefixed argument prints usage, exits 1, and
    /// makes no RPC — it is a usage error, not a package name.
    #[test]
    fn patched_build_rejects_missing_or_flag_like_names() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        install_min_helpers(rootfs).unwrap();

        for args in ["", "--bogus"] {
            let Some((stdout, stderr, code)) = run_min_helper(rootfs, args) else {
                return;
            };
            assert_eq!(code, 1, "`{args}` should exit 1, got: {stdout} {stderr}");
            assert!(
                stderr.contains("Usage: min package patched-build <package name>"),
                "`{args}` should print usage, got: {stderr}"
            );
            assert!(
                !stderr.contains("RPC-CALLED"),
                "`{args}` must not reach the daemon, got: {stderr}"
            );
        }
    }

    /// Runs the installed `min` helper as a script, with `PATH` prefixed by
    /// a directory holding a `socat` stand-in that announces itself on
    /// stderr — loud RPC detection for the main dispatch path, which runs
    /// only when the file is executed rather than sourced. Returns `None`
    /// when the host has no bash, matching the repo's self-skip-locally
    /// convention.
    fn run_min_command(rootfs: &Path, args: &str) -> Option<(String, String, i32)> {
        use std::os::unix::fs::PermissionsExt as _;

        let bin = rootfs.join("fakebin");
        std::fs::create_dir_all(&bin).unwrap();
        let socat = bin.join("socat");
        // The helper sends socat's stderr to /dev/null, so the fake marks
        // the call in a file, and the marker is added to stderr below.
        let marker = rootfs.join("rpc-called");
        let _ = std::fs::remove_file(&marker);
        std::fs::write(
            &socat,
            format!("#!/bin/sh\necho RPC-CALLED > '{}'\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&socat, std::fs::Permissions::from_mode(0o755)).unwrap();
        let script = rootfs.join("usr/bin/min");
        let out = std::process::Command::new("bash")
            .arg(script.to_str().unwrap())
            .args(args.split_whitespace())
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .output()
            .map_err(|e| eprintln!("no bash to run the min helper with — skipping: {e}"))
            .ok()?;
        let mut stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        stderr.push_str(&std::fs::read_to_string(&marker).unwrap_or_default());
        Some((
            String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr,
            out.status.code().unwrap_or(-1),
        ))
    }

    /// `-h`, `--help`, and `help` at every dispatch level of the in-session
    /// `min` helper print that level's own usage and exit 0 without
    /// contacting the daemon, as does a help flag after other arguments to
    /// a command that takes no task arguments; a bare `min package`/`min task`/`min net` and an unknown
    /// subcommand print usage on stderr and exit 1.
    #[test]
    fn help_spellings_print_usage_without_rpc() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        install_min_helpers(rootfs).unwrap();

        for (args, code, stream, usage) in [
            ("--help", 0, "stdout", "Usage: min <subcommand>"),
            ("-h", 0, "stdout", "Usage: min <subcommand>"),
            ("help", 0, "stdout", "Usage: min <subcommand>"),
            (
                "package --help",
                0,
                "stdout",
                "Usage: min package <subcommand>",
            ),
            ("package -h", 0, "stdout", "Usage: min package <subcommand>"),
            (
                "package help",
                0,
                "stdout",
                "Usage: min package <subcommand>",
            ),
            ("pkg --help", 0, "stdout", "Usage: min package <subcommand>"),
            (
                "task --help",
                0,
                "stdout",
                "Usage: min task run <task name>",
            ),
            ("net --help", 0, "stdout", "Usage: min net expose <port>"),
            (
                "add --help",
                0,
                "stdout",
                "Usage: min add [--session|--build|--runtime] <packages>",
            ),
            (
                "add -h",
                0,
                "stdout",
                "Usage: min add [--session|--build|--runtime] <packages>",
            ),
            (
                "add --build --help",
                0,
                "stdout",
                "Usage: min add [--session|--build|--runtime] <packages>",
            ),
            (
                "add jq --help",
                0,
                "stdout",
                "Usage: min add [--session|--build|--runtime] <packages>",
            ),
            ("run --help", 0, "stdout", "Usage: min task run <task name>"),
            (
                "task run --help",
                0,
                "stdout",
                "Usage: min task run <task name>",
            ),
            (
                "search --help",
                0,
                "stdout",
                "Usage: min package search <query>",
            ),
            (
                "package search --help",
                0,
                "stdout",
                "Usage: min package search <query>",
            ),
            (
                "package build --help",
                0,
                "stdout",
                "Usage: min package build <packages>",
            ),
            (
                "package build foo --help",
                0,
                "stdout",
                "Usage: min package build <packages>",
            ),
            (
                "package patched-build --help",
                0,
                "stdout",
                "Usage: min package patched-build <package name>",
            ),
            ("check --help", 0, "stdout", "Usage: min check"),
            ("check foo --help", 0, "stdout", "Usage: min check"),
            (
                "materialize --help",
                0,
                "stdout",
                "Usage: min materialize --output <path> [--arch <arch>] <output name>",
            ),
            (
                "materialize --output x --help",
                0,
                "stdout",
                "Usage: min materialize --output <path> [--arch <arch>] <output name>",
            ),
            (
                "materialize --arch x86_64 --help",
                0,
                "stdout",
                "Usage: min materialize --output <path> [--arch <arch>] <output name>",
            ),
            (
                "net expose --help",
                0,
                "stdout",
                "Usage: min net expose <port>",
            ),
            ("package", 1, "stderr", "Usage: min package <subcommand>"),
            ("task", 1, "stderr", "Usage: min task run <task name>"),
            ("net", 1, "stderr", "Usage: min net expose <port>"),
            ("bogus", 1, "stderr", "Usage: min <subcommand>"),
            (
                "package bogus",
                1,
                "stderr",
                "Usage: min package <subcommand>",
            ),
            ("task bogus", 1, "stderr", "Usage: min task run <task name>"),
            ("net bogus", 1, "stderr", "Usage: min net expose <port>"),
        ] {
            let Some((stdout, stderr, exit)) = run_min_command(rootfs, args) else {
                return;
            };
            assert_eq!(
                exit, code,
                "`{args}` should exit {code}, got: {stdout} {stderr}"
            );
            let (out, other) = if stream == "stdout" {
                (&stdout, &stderr)
            } else {
                (&stderr, &stdout)
            };
            assert!(
                out.contains(usage),
                "`{args}` should print `{usage}` on {stream}, got: {stdout} {stderr}"
            );
            assert!(
                other.is_empty(),
                "`{args}` should print only on {stream}, got: {stdout} {stderr}"
            );
            assert!(
                !stdout.contains("RPC-CALLED") && !stderr.contains("RPC-CALLED"),
                "`{args}` must not reach the daemon, got: {stdout} {stderr}"
            );
        }
    }

    /// Runs the installed `min` helper as a script in `cwd`, with a `socat`
    /// stand-in that saves the request it reads to a file and answers with
    /// `reply`. Returns stdout, stderr, the exit code and the saved request,
    /// or `None` when the host has no bash.
    fn run_min_against(
        rootfs: &Path,
        cwd: &Path,
        args: &[&str],
        envs: &[(&str, &str)],
        reply: &str,
    ) -> Option<(String, String, i32, String)> {
        use std::os::unix::fs::PermissionsExt as _;

        let bin = rootfs.join("replybin");
        std::fs::create_dir_all(&bin).unwrap();
        let socat = bin.join("socat");
        let capture = rootfs.join("request");
        std::fs::write(
            &socat,
            format!(
                // One line: a `run` helper keeps its side open until the
                // channel answers, as the channel answers before EOF.
                "#!/bin/sh\nIFS= read -r line\nprintf '%s\\n' \"$line\" > '{}'\nprintf '%s' '{reply}'\n",
                capture.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&socat, std::fs::Permissions::from_mode(0o755)).unwrap();
        let script = rootfs.join("usr/bin/min");
        let out = std::process::Command::new("bash")
            .arg(script.to_str().unwrap())
            .args(args)
            .current_dir(cwd)
            .env_remove("TRACEPARENT")
            .env("PWD", cwd)
            .envs(envs.iter().copied())
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .output()
            .map_err(|e| eprintln!("no bash to run the min helper with — skipping: {e}"))
            .ok()?;
        Some((
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
            out.status.code().unwrap_or(-1),
            std::fs::read_to_string(&capture).unwrap_or_default(),
        ))
    }

    // T48, BCLI-010, BCLI-014: a run whose socat a signal ends, as Ctrl-C
    // or the run's timeout does, prints neither socat's warning nor the
    // broken-stream line, and exits 125 as before.
    #[test]
    fn min_helper_run_ended_by_signal_prints_no_connection_line() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        install_min_helpers(rootfs).unwrap();
        let bin = rootfs.join("signalbin");
        std::fs::create_dir_all(&bin).unwrap();
        let socat = bin.join("socat");
        std::fs::write(
            &socat,
            "#!/bin/sh\nIFS= read -r line\nprintf 'msg:task output\\n'\n\
             echo 'socat[1] W exiting on signal 15' >&2\nkill -TERM $$\n",
        )
        .unwrap();
        std::fs::set_permissions(&socat, std::fs::Permissions::from_mode(0o755)).unwrap();
        let Ok(out) = std::process::Command::new("bash")
            .arg(rootfs.join("usr/bin/min"))
            .args(["task", "run", "lint"])
            .current_dir(rootfs)
            .env_remove("TRACEPARENT")
            .env("PWD", rootfs)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .output()
        else {
            eprintln!("no bash to run the min helper with — skipping");
            return;
        };
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(125), "{stderr}");
        assert!(stdout.contains("task output"), "{stdout}");
        assert!(!stderr.contains("exiting on signal"), "{stderr}");
        assert!(!stderr.contains("the connection closed"), "{stderr}");

        // The same stream with no signal still prints the line.
        let Some((_, stderr, got, _)) = run_min_against(
            rootfs,
            rootfs,
            &["task", "run", "lint"],
            &[],
            "msg:task output\n",
        ) else {
            return;
        };
        assert_eq!(got, 125, "{stderr}");
        assert!(
            stderr.contains("the connection closed before the task reported its exit status"),
            "{stderr}"
        );
    }

    /// The real `socat` on this host's `PATH`, or `None` when it has none.
    fn host_socat() -> Option<PathBuf> {
        std::env::var_os("PATH")
            .into_iter()
            .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
            .map(|dir| dir.join("socat"))
            .find(|candidate| candidate.is_file())
    }

    /// Runs the installed `min` helper with `args` and `stdin` on its
    /// stdin, through the host's real `socat`, against a socket that
    /// `serve` answers in place of `/run/minenv_sock`. The listener reads
    /// the request line as the session listener does, with a buffered read
    /// that it then drops. Returns stdout, stderr and the exit code, or
    /// `None` when the host has no bash or no socat.
    fn run_min_against_channel(
        rootfs: &Path,
        args: &[&str],
        stdin: Vec<u8>,
        serve: impl FnOnce(UnixStream, String) + Send + 'static,
    ) -> Option<(String, String, i32)> {
        use std::io::{BufRead as _, BufReader};
        use std::os::unix::fs::PermissionsExt as _;

        let Some(socat) = host_socat() else {
            eprintln!("no socat to run the min helper with — skipping");
            return None;
        };
        let sock = rootfs.join("minenv_sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let bin = rootfs.join("channelbin");
        std::fs::create_dir_all(&bin).unwrap();
        let wrapper = bin.join("socat");
        std::fs::write(
            &wrapper,
            format!(
                "#!/bin/bash\nargs=()\nfor a in \"$@\"; do args+=(\"${{a/UNIX-CONNECT:\\/run\\/minenv_sock/UNIX-CONNECT:{}}}\"); done\nexec '{}' \"${{args[@]}}\"\n",
                sock.display(),
                socat.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            // Bytes that arrive before the channel asks for them would sit
            // in the kernel buffer now, and the buffered read below would
            // take them with the line.
            std::thread::sleep(std::time::Duration::from_millis(200));
            let mut raw = Vec::new();
            BufReader::new(&stream).read_until(b'\n', &mut raw).unwrap();
            let line = String::from_utf8(raw).unwrap();
            serve(stream, line.trim_end_matches('\n').to_string());
        });

        let script = rootfs.join("usr/bin/min");
        let mut child = std::process::Command::new("bash")
            .arg(script.to_str().unwrap())
            .args(args)
            .current_dir(rootfs)
            .env_remove("TRACEPARENT")
            .env("PWD", rootfs)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| eprintln!("no bash to run the min helper with — skipping: {e}"))
            .ok()?;
        let mut pipe = child.stdin.take().unwrap();
        let feeder = std::thread::spawn(move || {
            // A task that ends before it reads all of its stdin closes the
            // pipe, so this write can fail.
            let _ = pipe.write_all(&stdin);
        });
        let out = child.wait_with_output().unwrap();
        let _ = feeder.join();
        server.join().expect("the channel side passes its checks");
        Some((
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
            out.status.code().unwrap_or(-1),
        ))
    }

    /// The data of a `run` request line, past `run%`.
    fn run_request_data(line: &str) -> TaskRunRequest {
        let data = line
            .strip_prefix("run%")
            .unwrap_or_else(|| panic!("not a run request: {line:?}"));
        TaskRunRequest::parse(data)
    }

    // T123, BOX-038: the in-box `min task run` is a task box's entrypoint,
    // so the run's stdin is its stdin. It says in the request that it
    // forwards that stdin, sends it only after the channel's `stdin:` line,
    // and closes it at its EOF. A run the channel refuses never sends it.
    #[test]
    fn minenv_run_forwards_stdin_to_the_task() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        install_min_helpers(rootfs).unwrap();

        let input = b"select 1;\nselect 2;\n".to_vec();
        let expected = input.clone();
        let Some((stdout, stderr, code)) = run_min_against_channel(
            rootfs,
            &["task", "run", "query", "--limit", "5"],
            input,
            move |mut stream, line| {
                use std::io::Read as _;
                let request = run_request_data(&line);
                assert!(
                    request.stdin,
                    "the request says it forwards stdin: {line:?}"
                );
                assert_eq!(request.task, "query");
                assert_eq!(
                    request.args,
                    TaskRunArgs::Argv(vec!["--limit".to_string(), "5".to_string()])
                );
                writeln!(stream, "stdin:").unwrap();
                let mut got = Vec::new();
                stream.read_to_end(&mut got).unwrap();
                assert_eq!(got, expected, "all of the stdin, after the line, then EOF");
                writeln!(stream, "msg:read {} bytes", got.len()).unwrap();
                writeln!(stream, "exit:0").unwrap();
            },
        ) else {
            return;
        };
        assert_eq!(code, 0, "{stdout} {stderr}");
        assert_eq!(stdout, "read 20 bytes\n");

        // A refusal sends no `stdin:` line, so the helper sends none of
        // its stdin, and it exits with the refusal's code.
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        install_min_helpers(rootfs).unwrap();
        let Some((stdout, stderr, code)) = run_min_against_channel(
            rootfs,
            &["task", "run", "nope"],
            b"never sent\n".to_vec(),
            |mut stream, line| {
                use std::io::Read as _;
                assert!(run_request_data(&line).stdin);
                write!(stream, "error: no such task 'nope'\nexit:4\n").unwrap();
                let mut got = Vec::new();
                stream.read_to_end(&mut got).unwrap();
                assert!(got.is_empty(), "no stdin without `stdin:`: {got:?}");
            },
        ) else {
            return;
        };
        assert_eq!(code, 4, "{stdout} {stderr}");
        assert!(stdout.is_empty(), "{stdout}");
        assert!(stderr.contains("no such task 'nope'"), "{stderr}");

        // The flag is a fourth group, after the environment, and an older
        // request without it forwards nothing.
        let parsed = TaskRunRequest::parse("/w\u{1e}lint\u{1e}A=1\u{1f}B=2\u{1e}stdin");
        assert!(parsed.stdin);
        assert_eq!(parsed.env.get("B").map(String::as_str), Some("2"));
        let parsed = TaskRunRequest::parse("/w\u{1e}lint\u{1e}A=1");
        assert!(!parsed.stdin);
        let mut marked = TaskRunRequest::parse("/w\u{1e}lint\u{1e}A=1\u{1e}stdin");
        marked.mark_invalid_bytes(b"/w\x1elint\x1eA=\xff\x1estdin");
        assert!(marked.invalid_env.contains("A"));
    }

    /// The channel side of a forwarded `run`, built from the pieces the
    /// channel's `run_task` uses: a `stdin:` line, the task's stdin fed by
    /// [`crate::exec::ForwardedStdin`], its stdout as `msg:` lines and its
    /// stderr as `err:` lines, then its exit code and the close.
    fn serve_task(script: &'static str) -> impl FnOnce(UnixStream, String) + Send + 'static {
        move |stream, line| {
            assert!(run_request_data(&line).stdin, "{line:?}");
            let mut task = std::process::Command::new("/bin/sh")
                .args(["-c", script])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let mut forwarded =
                crate::exec::ForwardedStdin::start(&stream, task.stdin.take().unwrap()).unwrap();
            let shared = Arc::new(Mutex::new(stream.try_clone().unwrap()));
            writeln!(shared.lock().unwrap(), "stdin:").unwrap();
            let (stdout, stderr) = (task.stdout.take().unwrap(), task.stderr.take().unwrap());
            let (out, err) = (shared.clone(), shared.clone());
            let out = std::thread::spawn(move || forward_lines(stdout, &out, "msg"));
            let err = std::thread::spawn(move || forward_lines(stderr, &err, "err"));
            out.join().unwrap();
            err.join().unwrap();
            let status = task.wait().unwrap();
            forwarded.task_ended();
            let result = match status.code() {
                Some(0) => Ok(true),
                code => Err(Error::Execution {
                    idx: 0,
                    code: code.unwrap_or(1),
                    reason: String::new(),
                    stderr: String::new(),
                    stdout: String::new(),
                }),
            };
            let mut stream = stream;
            BoxChannel::end_task_run(
                &mut stream,
                true,
                "err",
                "query",
                result,
                Some(&mut forwarded),
            );
            forwarded.finish(std::time::Duration::from_secs(10));
        }
    }

    // T123, BOX-038: `cat q.sql | min task run query > out.csv` in a task
    // box. The run's stdin goes through the in-box helper to the task's
    // stdin pipe and closes at its end. The helper's stdout is the task's
    // stdout alone, and it exits with the task's code. A task that ends
    // before it reads all of its stdin still reports its code.
    #[test]
    fn task_run_pipes_stdin_through_the_in_box_helper() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        install_min_helpers(rootfs).unwrap();
        let Some((stdout, stderr, code)) = run_min_against_channel(
            rootfs,
            &["task", "run", "query"],
            b"select 1;\nselect 2;\n".to_vec(),
            serve_task("read first; echo \"first:$first\"; echo diag >&2; cat; exit 7"),
        ) else {
            return;
        };
        assert_eq!(code, 7, "{stdout} {stderr}");
        assert_eq!(stdout, "first:select 1;\nselect 2;\n");
        assert_eq!(stderr, "diag\n");

        // Far more input than any pipe holds, and a task that reads one
        // byte: the channel drops the rest, and the run still ends with
        // the task's code.
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        install_min_helpers(rootfs).unwrap();
        let Some((stdout, stderr, code)) = run_min_against_channel(
            rootfs,
            &["task", "run", "query"],
            vec![b'y'; 4 * 1024 * 1024],
            serve_task("head -c 1; echo; exit 0"),
        ) else {
            return;
        };
        assert_eq!(code, 0, "{stdout} {stderr}");
        assert_eq!(stdout, "y\n");
        assert!(stderr.is_empty(), "{stderr}");
    }

    /// Ends a run with `result` while its forwarded stdin fails with a
    /// reset connection, before or after the task ended, and returns what
    /// the channel sends the helper.
    fn end_run_after_a_stdin_reset(result: Result<bool, Error>, after_task_ended: bool) -> String {
        use std::io::Read as _;
        let (connection, helper) = UnixStream::pair().unwrap();
        let mut forwarded =
            crate::exec::ForwardedStdin::start(&connection, std::io::sink()).unwrap();
        if after_task_ended {
            forwarded.task_ended();
        }
        // A peer that closes with unread data resets the connection, so the
        // copy's next read fails.
        (&connection).write_all(b"unread").unwrap();
        drop(helper);
        forwarded.wait_for_copy_end();
        let (mut ours, mut theirs) = UnixStream::pair().unwrap();
        BoxChannel::end_task_run(
            &mut ours,
            true,
            "err",
            "query",
            result,
            Some(&mut forwarded),
        );
        drop(ours);
        let mut sent = String::new();
        theirs.read_to_string(&mut sent).unwrap();
        sent
    }

    // T123, BOX-038: a task that fails with its own code while its
    // forwarded stdin fails still ends with its own code.
    #[test]
    fn task_run_pipes_stdin_through_the_in_box_helper_keeps_a_failed_task_code() {
        let failed = Err(Error::Execution {
            idx: 0,
            code: 4,
            reason: String::new(),
            stderr: String::new(),
            stdout: String::new(),
        });
        let sent = end_run_after_a_stdin_reset(failed, false);
        assert!(sent.ends_with("exit:4\n"), "{sent:?}");
        // The same reset while the task read its stdin fails a run that
        // passed, so the reset above did reach the run.
        let sent = end_run_after_a_stdin_reset(Ok(true), false);
        assert!(!sent.contains("exit:0"), "{sent:?}");
        assert!(sent.contains("could not pass its stdin"), "{sent:?}");
    }

    // T123, BOX-038: a forwarded stdin that fails after the task ended
    // with 0 leaves the run's code 0.
    #[test]
    fn task_run_pipes_stdin_through_the_in_box_helper_keeps_a_pass_after_the_task_ended() {
        let sent = end_run_after_a_stdin_reset(Ok(true), true);
        assert_eq!(sent, "exit:0\n");
    }

    /// BCLI-010 (T62): a refusal for a project configuration error exits 3,
    /// a missing package exits 4, and any other refusal exits 125.
    #[test]
    fn refusal_exit_code_gives_a_config_error_exit_3() {
        let config = Error::Config(mctx::ConfigError::InvalidRemoteCacheUrl(String::new()));
        assert_eq!(refusal_exit_code(&config), 3);
        let other = Error::Other(anyhow::anyhow!("no sandbox"));
        assert_eq!(refusal_exit_code(&other), 125);
        let conflict = Error::Graph(Box::new(graph::Error::ConflictingStack {
            name: "dev".into(),
        }));
        assert_eq!(refusal_exit_code(&conflict), 3);
        let missing = Error::Graph(Box::new(graph::Error::NoSuchPkg {
            name: "nope".into(),
        }));
        assert_eq!(refusal_exit_code(&missing), 4);
        let fetch = Error::Graph(Box::new(graph::Error::Fetch("offline".into())));
        assert_eq!(refusal_exit_code(&fetch), 125);
    }

    /// The channel's trace log never carries a `run` request's environment.
    #[test]
    fn loggable_request_cuts_the_run_environment() {
        let line = "run%/w\u{1e}lint\u{1f}a\u{1e}TOKEN=secret\u{1f}HOME=/h";
        let logged = loggable_request(line);
        assert_eq!(
            logged,
            "run%/w\u{1e}lint\u{1f}a\u{1e}<environment redacted>"
        );
        assert_eq!(loggable_request("run%lint a b"), "run%lint a b");
    }

    /// BCLI-010 (T62): `min task run`, a task box's entrypoint, exits with
    /// the code the channel relays for the task, and the channel relays the
    /// task's own code.
    #[test]
    fn task_entrypoint_relays_the_task_exit_code() {
        // The channel side: the code that ends a run.
        let failed = |code| {
            Err(Error::Execution {
                idx: 0,
                code,
                reason: String::new(),
                stderr: String::new(),
                stdout: String::new(),
            })
        };
        assert_eq!(relayed_exit_code(&Ok(())), Some(0));
        assert_eq!(relayed_exit_code(&failed(3)), Some(3));
        assert_eq!(relayed_exit_code(&failed(137)), Some(137));
        assert_eq!(relayed_exit_code(&failed(0)), Some(1));
        assert_eq!(relayed_exit_code(&failed(300)), Some(1));
        assert_eq!(relayed_exit_code(&failed(-1)), Some(1));
        assert_eq!(
            relayed_exit_code(&Err(Error::Other(anyhow::anyhow!("no sandbox")))),
            None
        );

        // The helper side: it exits with the relayed code, after the
        // task's output.
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        install_min_helpers(rootfs).unwrap();
        for (args, code) in [
            (&["task", "run", "lint"][..], 3),
            (&["task", "run", "lint"][..], 0),
            (&["run", "lint"][..], 42),
            (&["task", "run", "lint"][..], 137),
        ] {
            let reply = format!("msg:task output\nexit:{code}\n");
            let Some((stdout, stderr, got, _)) = run_min_against(rootfs, rootfs, args, &[], &reply)
            else {
                return;
            };
            assert_eq!(got, code, "{args:?}: {stdout} {stderr}");
            assert!(stdout.contains("task output"), "{args:?}: {stdout}");
        }

        // A refusal exits with the code the channel sends after it.
        for (reply, code) in [
            ("error: no such task nope\nexit:4\n", 4),
            (
                "err:usage line\nerror: failed parsing arguments for task\nexit:2\n",
                2,
            ),
            (
                "err:report\nerror: sandbox command failed.\nexit:125\n",
                125,
            ),
            ("err:report\nerror: sandbox command failed.\nexit:3\n", 3),
            // A refusal with no `exit:` line, as an older daemon sends.
            ("error: no such task nope\n", 125),
        ] {
            let Some((stdout, stderr, got, _)) =
                run_min_against(rootfs, rootfs, &["task", "run", "nope"], &[], reply)
            else {
                return;
            };
            assert_eq!(got, code, "{reply:?}: {stderr}");
            assert!(stderr.contains("error:"), "{reply:?}: {stderr}");
            assert!(stdout.is_empty(), "{reply:?}: {stdout}");
            assert!(
                !stderr.contains("the connection closed"),
                "{reply:?}: {stderr}"
            );
        }

        // A stream that ends with no `exit:` line, as when the connection
        // drops mid-task, is a failure of min, not a success.
        for reply in ["msg:task output\n", "msg:task output\ndone:\n", ""] {
            let Some((_, stderr, got, _)) =
                run_min_against(rootfs, rootfs, &["task", "run", "lint"], &[], reply)
            else {
                return;
            };
            assert_eq!(got, 125, "{reply:?}: {stderr}");
            assert!(
                stderr.contains("the connection closed before the task reported its exit status"),
                "{reply:?}: {stderr}"
            );
        }

        // A line that `echo` reads as a flag prints as it is.
        let Some((stdout, stderr, got, _)) = run_min_against(
            rootfs,
            rootfs,
            &["task", "run", "lint"],
            &[],
            "msg:-n\nerr:-E\nexit:0\n",
        ) else {
            return;
        };
        assert_eq!(got, 0, "{stderr}");
        assert_eq!(stdout, "-n\n");
        assert_eq!(stderr, "-E\n");

        // A name the channel echoes stays on one line, so a newline in it
        // cannot end the run with an `exit:` line of its own.
        assert_eq!(one_line("nope\nexit:0"), "nope\\nexit:0");
        assert_eq!(one_line("nope\r\x1b"), "nope\\r\\u{1b}");
        assert_eq!(one_line("lint"), "lint");

        // A task that writes only to stderr leaves the helper's stdout empty.
        let Some((stdout, stderr, got, _)) = run_min_against(
            rootfs,
            rootfs,
            &["task", "run", "lint"],
            &[],
            "err:task stderr\nexit:1\n",
        ) else {
            return;
        };
        assert_eq!(got, 1, "{stderr}");
        assert!(stdout.is_empty(), "{stdout}");
        assert!(stderr.contains("task stderr"), "{stderr}");

        // The channel side of a refusal and of the task's stderr.
        use std::io::Read as _;
        let read_all = |mut rx: UnixStream| {
            let mut got = String::new();
            rx.read_to_string(&mut got).unwrap();
            got
        };
        let (mut tx, rx) = UnixStream::pair().unwrap();
        relay_refusal_exit(&mut tx, true, "nope", EXIT_NOT_FOUND);
        relay_refusal_exit(&mut tx, false, "nope", EXIT_NOT_FOUND);
        drop(tx);
        assert_eq!(read_all(rx), "exit:4\n");

        let (tx, rx) = UnixStream::pair().unwrap();
        forward_lines(&b"one\ntwo\n"[..], &Mutex::new(tx), "err");
        assert_eq!(read_all(rx), "err:one\nerr:two\n");

        let (tx, rx) = UnixStream::pair().unwrap();
        let (mut out, mut err) = StreamWriter::pair_tagged(&tx, "err").unwrap();
        drop(tx);
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            use tokio::io::AsyncWriteExt as _;
            out.write_all(b"to stdout\n").await.unwrap();
            err.write_all(b"to stderr\n").await.unwrap();
        });
        drop((out, err));
        assert_eq!(read_all(rx), "msg:to stdout\nerr:to stderr\n");
    }

    /// T43: a name the client's `[vars] ignore` matched never reaches the
    /// task on the entrypoint path. The run stages it, the launch takes it,
    /// and the in-box run drops it before it fills `inherit` variables. That
    /// holds for a name the uploaded `minimal.toml` gives a value, and for
    /// an `inherit` one whose value the helper's caller still has.
    #[test]
    fn task_entrypoint_drops_ignored_vars() {
        use crate::box_actor::entrypoint_env;

        let id = boxes::SessionId::mint();
        entrypoint_env::stage(
            id,
            vec![
                ("KEPT".to_string(), "k".to_string()),
                ("IGNORED_TOKEN".to_string(), "leak".to_string()),
            ],
            None,
            BTreeSet::from(["IGNORED_TOKEN".to_string(), "IGNORED_FIXED".to_string()]),
        );
        // The launch: the dropped name is not among its variables, and the
        // launch records the names for the in-box run.
        let (launch_vars, dropped) = entrypoint_env::take(&id).expect("the run staged");
        assert_eq!(launch_vars, vec![("KEPT".to_string(), "k".to_string())]);
        entrypoint_env::record(id, dropped);

        // The in-box run, as the helper sends it with the caller's value.
        let request = TaskRunRequest::parse(&format!(
            "/workbench{RUN_GROUP_SEP}lint{RUN_GROUP_SEP}IGNORED_TOKEN=caller{RUN_ITEM_SEP}KEPT=k"
        ));
        let mut vars = BTreeMap::from([
            ("IGNORED_TOKEN".to_string(), EnvVarValue::Inherit),
            (
                "IGNORED_FIXED".to_string(),
                EnvVarValue::Value("from-toml".to_string()),
            ),
            ("KEPT".to_string(), EnvVarValue::Inherit),
        ]);
        assert_eq!(run_task_vars(&mut vars, Some(&id), true, &request), Ok(()));
        assert_eq!(
            vars,
            BTreeMap::from([("KEPT".to_string(), EnvVarValue::Value("k".to_string()))]),
            "only the kept variable reaches the task"
        );

        // A box no task run launched drops nothing.
        let mut vars = BTreeMap::from([(
            "IGNORED_FIXED".to_string(),
            EnvVarValue::Value("v".to_string()),
        )]);
        let other = boxes::SessionId::mint();
        assert_eq!(
            run_task_vars(&mut vars, Some(&other), false, &request),
            Ok(())
        );
        assert_eq!(vars.len(), 1);
    }

    /// TEL-023 on a task box (T43): the task an in-box `min task run` runs
    /// gets the request span's `TRACEPARENT` on opt-in, over whatever the
    /// task declares, and keeps its other variables. The helper's exported
    /// `TRACEPARENT` is not what it gets: that names the exec, and the task's
    /// work is a child of the span that served the request. A helper that
    /// opted out hands the task the marker and no `TRACEPARENT`; with
    /// telemetry off, or no recorded span, nothing is added. Scenario 712b.
    #[test]
    fn an_in_box_task_run_gives_the_task_the_request_traceparent() {
        let exec_tp = "00-af79b928d8ae574b659f1fbf40208758-ed105930ec67df47-01";
        let span_tp = "00-af79b928d8ae574b659f1fbf40208758-1111111111111111-01";
        let declared = || {
            BTreeMap::from([
                ("KEPT".to_string(), EnvVarValue::Value("k".to_string())),
                (
                    "TRACEPARENT".to_string(),
                    EnvVarValue::Value("from-toml".to_string()),
                ),
            ])
        };
        let on = TaskRunRequest::parse(&format!(
            "/workbench{RUN_GROUP_SEP}t{RUN_GROUP_SEP}TRACEPARENT={exec_tp}"
        ));

        let mut vars = declared();
        let joined = TaskTrace::Parent(Some(span_tp.to_string()));
        run_task_trace(&mut vars, true, joined.clone(), &on.env);
        assert_eq!(
            vars,
            BTreeMap::from([
                ("KEPT".to_string(), EnvVarValue::Value("k".to_string())),
                (
                    "TRACEPARENT".to_string(),
                    EnvVarValue::Value(span_tp.to_string()),
                ),
            ]),
            "the task gets the request span's TRACEPARENT and keeps the rest"
        );

        // Telemetry off, or a request span no export records: nothing added.
        for (telemetry_on, traceparent) in [(false, Some(span_tp.to_string())), (true, None)] {
            let mut vars = declared();
            run_task_trace(
                &mut vars,
                telemetry_on,
                TaskTrace::Parent(traceparent),
                &on.env,
            );
            assert_eq!(vars, declared());
        }

        // TEL-045: a helper whose exported environment carries the opt-out
        // marker opts its task out, even with a TRACEPARENT for the request.
        let off = TaskRunRequest::parse(&format!(
            "/workbench{RUN_GROUP_SEP}t{RUN_GROUP_SEP}{}={}",
            minimald_rpc::trace::OTEL_ENV,
            minimald_rpc::trace::OTEL_OFF,
        ));
        let mut vars = BTreeMap::new();
        run_task_trace(&mut vars, true, joined, &off.env);
        assert_eq!(
            vars,
            BTreeMap::from([(
                minimald_rpc::trace::OTEL_ENV.to_string(),
                EnvVarValue::Value(minimald_rpc::trace::OTEL_OFF.to_string()),
            )])
        );
    }

    /// TEL-024 on the in-box path: with no exporter the request span is not
    /// recorded, so a `run` request yields no `TRACEPARENT` for its task,
    /// even when the helper sent one.
    #[test]
    fn an_unrecorded_request_span_gives_the_task_no_traceparent() {
        let tp = "00-af79b928d8ae574b659f1fbf40208758-ed105930ec67df47-01";
        let line = format!("traceparent%{tp}%run%/workbench{RUN_GROUP_SEP}t");
        let (_, request, trace) = super::channel_request_span(&line, "b", None);
        assert_eq!(request, format!("run%/workbench{RUN_GROUP_SEP}t"));
        assert_eq!(trace, TaskTrace::Parent(None));
    }

    /// TEL-045 on the in-box path: a helper that opted out sends the
    /// opt-out on the request itself (`otel%off%`). The daemon's span for
    /// the request is marked `telemetry=opt-out`, parents nothing, and is
    /// exported nowhere, nor is a span under it; the same request without
    /// the prefix is exported. The task gets `MINIMAL_OTEL=off` and no
    /// `TRACEPARENT`, from the request alone: a Line-form request has no
    /// environment to carry the marker in. Scenario 712e.
    #[test]
    fn an_opted_out_helper_request_records_no_span_and_opts_its_task_out() {
        use opentelemetry::trace::TracerProvider as _;
        use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let log = crate::test_harness::SpanLog::default();
        let _g = tracing::subscriber::set_default(
            tracing_subscriber::registry()
                .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("t")))
                .with(log.clone()),
        );
        let exported = || -> Vec<String> {
            exporter
                .get_finished_spans()
                .unwrap()
                .iter()
                .map(|s| s.name.to_string())
                .collect()
        };

        let run = format!("run%/workbench{RUN_GROUP_SEP}t");
        let line = format!("otel%off%{run}");
        let (span, request, trace) = super::channel_request_span(&line, "off", None);
        assert_eq!(request, run);
        assert_eq!(trace, TaskTrace::OptedOut);
        span.in_scope(|| drop(tracing::info_span!("under").entered()));
        drop(span);
        let served = log.one("session.channel", "box.id", "off");
        assert_eq!(served.field("telemetry"), Some(crate::exec::OPT_OUT));
        assert_eq!(served.field("parent_span_id"), None, "{served:?}");
        assert!(served.field("trace_id").is_some(), "ids for the file log");
        assert_eq!(exported(), Vec::<String>::new(), "nothing exported");

        let (span, request, trace) = super::channel_request_span(&run, "on", None);
        assert_eq!(request, run);
        assert_eq!(trace, TaskTrace::Parent(None));
        drop(span);
        assert_eq!(exported(), vec!["session.channel".to_string()]);

        // Only `off` opts out; another value is stripped and ignored.
        let (_, request, trace) = super::channel_request_span("otel%on%net-expose%8770", "b", None);
        assert_eq!(request, "net-expose%8770");
        assert_eq!(trace, TaskTrace::Parent(None));

        let off = BTreeMap::from([(
            minimald_rpc::trace::OTEL_ENV.to_string(),
            EnvVarValue::Value(minimald_rpc::trace::OTEL_OFF.to_string()),
        )]);
        for telemetry_on in [true, false] {
            let line_form = TaskRunRequest::parse("t");
            assert!(line_form.env.is_empty());
            let mut vars = BTreeMap::new();
            run_task_trace(&mut vars, telemetry_on, TaskTrace::OptedOut, &line_form.env);
            assert_eq!(vars, off, "telemetry_on={telemetry_on}");
        }
    }

    /// The Line form an older helper sends (`run%<task> <args>`: no prefix,
    /// no environment) hands its task nothing, as before T43's fix: its
    /// request span is a root the daemon minted, and a recorded root is no
    /// trace the caller asked to join. A prefixed request's recorded span
    /// is handed on; an unrecorded one never is (TEL-024).
    #[test]
    fn a_bare_request_hands_its_task_no_traceparent() {
        let span_tp = "00-af79b928d8ae574b659f1fbf40208758-1111111111111111-01";
        assert_eq!(task_traceparent(false, Some(span_tp.to_string())), None);
        assert_eq!(task_traceparent(false, None), None);
        assert_eq!(task_traceparent(true, None), None);
        assert_eq!(
            task_traceparent(true, Some(span_tp.to_string())),
            Some(span_tp.to_string())
        );

        let (_, request, trace) = super::channel_request_span("run%lint a b", "old", None);
        assert_eq!(request, "run%lint a b");
        assert_eq!(trace, TaskTrace::Parent(None));
        let line_form = TaskRunRequest::parse("lint a b");
        assert_eq!(line_form.args, TaskRunArgs::Line("a b".to_string()));
        let mut vars = BTreeMap::new();
        run_task_trace(&mut vars, true, trace, &line_form.env);
        assert_eq!(vars, BTreeMap::new());
    }

    /// BCLI-010 (T62): the request `min task run` sends carries the caller's
    /// args with their spaces, its `$PWD` and its exported variables. The
    /// channel fills the task's `inherit` variables from them and starts an
    /// `inherit_cwd` task in that directory.
    #[test]
    fn task_entrypoint_carries_env_cwd_and_args() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        install_min_helpers(rootfs).unwrap();
        let cwd = rootfs.join("some dir");
        std::fs::create_dir_all(&cwd).unwrap();

        let Some((stdout, stderr, code, request)) = run_min_against(
            rootfs,
            &cwd,
            &[
                "task",
                "run",
                "lint",
                "--name",
                "two words",
                "back\\slash",
                "",
            ],
            &[("CALLER_TOKEN", "a=b\nline two\x1fx\\y")],
            "exit:0\n",
        ) else {
            return;
        };
        assert_eq!(code, 0, "{stdout} {stderr}");
        let data = request
            .trim_end_matches('\n')
            .strip_prefix("run%")
            .unwrap_or_else(|| panic!("not a run request: {request:?}"));
        let parsed = TaskRunRequest::parse(data);
        assert!(parsed.relays_exit());
        assert_eq!(parsed.task, "lint");
        assert_eq!(
            parsed.args,
            TaskRunArgs::Argv(vec![
                "--name".to_string(),
                "two words".to_string(),
                "back\\slash".to_string(),
                String::new(),
            ])
        );
        assert_eq!(parsed.cwd.as_deref(), cwd.to_str());
        assert_eq!(
            parsed.env.get("CALLER_TOKEN").map(String::as_str),
            Some("a=b\nline two\x1fx\\y")
        );

        // An older helper's `<task> <args>` line still parses, and reads
        // no `exit:` line.
        let legacy = TaskRunRequest::parse("lint --name x");
        assert_eq!(legacy.task, "lint");
        assert_eq!(legacy.args, TaskRunArgs::Line("--name x".to_string()));
        assert!(!legacy.relays_exit());

        // Env: the caller's value fills an `inherit` variable, and one the
        // caller does not set refuses the run, not read from the daemon.
        let mut vars = BTreeMap::from([
            ("CALLER_TOKEN".to_string(), EnvVarValue::Inherit),
            ("NOT_SET_BY_CALLER".to_string(), EnvVarValue::Inherit),
        ]);
        assert_eq!(
            inherit_from_caller(&mut vars, &parsed.env, &parsed.invalid_env),
            Err("NOT_SET_BY_CALLER".to_string())
        );
        let mut vars = BTreeMap::from([
            ("CALLER_TOKEN".to_string(), EnvVarValue::Inherit),
            ("FIXED".to_string(), EnvVarValue::Value("v".to_string())),
        ]);
        assert_eq!(
            inherit_from_caller(&mut vars, &parsed.env, &parsed.invalid_env),
            Ok(())
        );
        assert_eq!(
            vars,
            BTreeMap::from([
                (
                    "CALLER_TOKEN".to_string(),
                    EnvVarValue::Value("a=b\nline two\x1fx\\y".to_string())
                ),
                ("FIXED".to_string(), EnvVarValue::Value("v".to_string())),
            ])
        );

        // Cwd: an `inherit_cwd` task starts in the caller's directory under
        // `/workbench` when the session's tree has it.
        let working = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(working.path().join("sub/deeper")).unwrap();
        let w = working.path();
        assert_eq!(
            start_dir_in_box(true, Some("/workbench/sub/deeper"), w),
            Ok(Some("/workbench/sub/deeper".to_string()))
        );
        assert_eq!(start_dir_in_box(true, Some("/workbench"), w), Ok(None));
        assert_eq!(start_dir_in_box(false, Some("/workbench/sub"), w), Ok(None));
        assert_eq!(start_dir_in_box(true, None, w), Ok(None));
        // A symlink in the box's tree that points out of it is not a
        // directory under `/workbench`.
        let elsewhere = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), w.join("escape")).unwrap();
        for outside in [
            "/workbench/missing",
            "/home",
            "/workbench/../etc",
            "/workbench/escape",
        ] {
            let notice = start_dir_in_box(true, Some(outside), w).unwrap_err();
            assert_eq!(
                notice,
                format!(
                    "{outside} is not a directory under /workbench, so the task runs in /workbench."
                )
            );
        }
        // A `$PWD` with a newline in it stays on one line in the notice.
        let notice = start_dir_in_box(true, Some("/home\nexit:0"), w).unwrap_err();
        assert!(!notice.contains('\n'), "{notice:?}");
        assert!(notice.starts_with("/home\\nexit:0 is not"), "{notice:?}");

        // Bytes that are not valid UTF-8: a declared `inherit` value that
        // held one refuses the run with the laptop's text, as does an
        // argument. An undeclared variable that held one is ignored.
        let raw = b"traceparent%00-ab-cd-01%run%/workbench\x1elint\x1fok\x1fbad\xff\x1e\
                    TOKEN=caf\xe9\x1fOTHER=\xfe\x1fFINE=v";
        let data = run_data_bytes(raw).unwrap();
        let mut parsed = TaskRunRequest::parse(&String::from_utf8_lossy(data));
        parsed.mark_invalid_bytes(data);
        assert!(parsed.invalid_arg);
        assert_eq!(
            parsed.invalid_env,
            BTreeSet::from(["TOKEN".to_string(), "OTHER".to_string()])
        );
        assert_eq!(run_data_bytes(b"search%x\xff"), None);
        // The opt-out prefix is skipped the same way (TEL-045).
        assert_eq!(
            run_data_bytes(b"otel%off%run%/w\x1et\xff"),
            Some(&b"/w\x1et\xff"[..])
        );
        assert_eq!(run_data_bytes(b"otel%off%search%x"), None);
        let mut vars = BTreeMap::from([
            ("TOKEN".to_string(), EnvVarValue::Inherit),
            ("FINE".to_string(), EnvVarValue::Inherit),
        ]);
        assert_eq!(
            inherit_from_caller(&mut vars, &parsed.env, &parsed.invalid_env),
            Err("TOKEN".to_string())
        );
        let mut vars = BTreeMap::from([("FINE".to_string(), EnvVarValue::Inherit)]);
        assert_eq!(
            inherit_from_caller(&mut vars, &parsed.env, &parsed.invalid_env),
            Ok(())
        );
        assert_eq!(
            inherit_refusal("lint", "TOKEN"),
            "error: task 'lint' declares `env_vars.TOKEN = { inherit = true }`, \
             but TOKEN is not set in this shell; export it before running the task"
        );
        assert_eq!(
            invalid_arg_refusal("lint"),
            "error: an argument for task 'lint' is not valid UTF-8, so the task did not run"
        );
        let mut valid_args = TaskRunRequest::parse("/workbench\x1elint\x1fok\x1eFINE=v");
        valid_args.mark_invalid_bytes(b"/workbench\x1elint\x1fok\x1eFINE=v");
        assert!(!valid_args.invalid_arg);
        assert!(valid_args.invalid_env.is_empty());
    }

    /// A project whose `needs-token` task inherits `TOKEN` from the caller.
    fn inherit_task_repo() -> TempDir {
        let repo = tempdir().unwrap();
        let pkgs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../mctx/testdata/fakepkgs");
        std::fs::write(
            repo.path().join("minimal.toml"),
            format!(
                "[upstream]\ndir = {:?}\n\n\
                 [tasks.needs-token]\npackages = [\"uroot\"]\nexec = \"/bbin/true\"\n\
                 env_vars.TOKEN = {{ inherit = true }}\n",
                pkgs.to_str().unwrap()
            ),
        )
        .unwrap();
        repo
    }

    /// Hands `raw` to a channel over the project at `repo`, as the listener
    /// does for a line that was not valid UTF-8, and returns its reply.
    async fn handle_lossy_line(repo: &Path, raw: &[u8]) -> String {
        let (_state, _rootfs, _cwd, mut chan, _sender) =
            setup_channel_in(crate::box_actor::WeakBoxHandle::dangling(), "web", repo);
        let (mut ours, mut theirs) = UnixStream::pair().unwrap();
        let line = String::from_utf8_lossy(raw).into_owned();
        chan.handle_raw(&line, Some(raw), TaskTrace::Parent(None), &mut ours)
            .await;
        drop(ours);
        let mut reply = String::new();
        std::io::Read::read_to_string(&mut theirs, &mut reply).unwrap();
        reply
    }

    // BCLI-010 (T62): a declared `inherit` value with a byte that is not
    // valid UTF-8 refuses the run with exit 2, as the laptop does.
    #[tokio::test]
    async fn task_run_refuses_an_inherit_value_that_is_not_utf8() {
        let repo = inherit_task_repo();
        let reply = handle_lossy_line(
            repo.path(),
            b"run%/workbench\x1eneeds-token\x1eTOKEN=caf\xe9",
        )
        .await;
        assert_eq!(
            reply,
            "error: task 'needs-token' declares `env_vars.TOKEN = { inherit = true }`, \
             but TOKEN is not set in this shell; export it before running the task\nexit:2\n"
        );
    }

    // BCLI-010 (T62): an argument with a byte that is not valid UTF-8
    // refuses the run with exit 2.
    #[tokio::test]
    async fn task_run_refuses_an_argument_that_is_not_utf8() {
        let repo = inherit_task_repo();
        let reply = handle_lossy_line(
            repo.path(),
            b"run%/workbench\x1eneeds-token\x1fcaf\xe9\x1eTOKEN=v",
        )
        .await;
        assert_eq!(
            reply,
            "error: an argument for task 'needs-token' is not valid UTF-8, \
             so the task did not run\nexit:2\n"
        );
    }

    // BCLI-010 (T62): an exported variable that the task does not declare
    // neither refuses nor drops the run, whatever bytes it holds.
    #[tokio::test]
    async fn task_run_ignores_an_undeclared_value_that_is_not_utf8() {
        let repo = inherit_task_repo();
        let reply = handle_lossy_line(
            repo.path(),
            b"run%/workbench\x1eneeds-token\x1eTOKEN=v\x1fOTHER=caf\xe9",
        )
        .await;
        assert!(!reply.contains("not valid UTF-8"), "{reply}");
        assert!(!reply.contains("is not set in this shell"), "{reply}");
        // The run reaches the box: the test's box is gone, so it ends there.
        assert_eq!(reply, "error: session is gone\nexit:125\n");
    }

    /// In an argument slot a bare `help` is a package name, search term, or
    /// task name, not a help request, so it still reaches the daemon. So
    /// does a help flag after a task name: it is the task's argument. So
    /// does a help flag in a materialize value slot: it is the path.
    #[test]
    fn help_word_in_argument_slot_reaches_rpc() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        install_min_helpers(rootfs).unwrap();

        for args in [
            "search help",
            "add help",
            "package build help",
            "task run help",
            "run mytask --help",
            "materialize --output --help x",
            "materialize -o -h x",
        ] {
            let Some((stdout, stderr, _)) = run_min_command(rootfs, args) else {
                return;
            };
            assert!(
                stderr.contains("RPC-CALLED"),
                "`{args}` should reach the daemon, got: {stdout} {stderr}"
            );
        }
    }

    use camino::Utf8PathBuf;
    use mctx::ConfigBuilder;
    use std::io::{BufRead, BufReader};
    use tempfile::tempdir;

    /// Builds a `Context` and `Graph` from mctx's fakerepo fixture, plus a
    /// `BoxChannel` wired to them with a dummy receiver so handlers can be
    /// driven directly.
    fn setup_channel() -> (TempDir, TempDir, TempDir, BoxChannel) {
        setup_channel_with(crate::box_actor::WeakBoxHandle::dangling(), "web")
    }

    /// [`setup_channel`] for a channel bound to the session that owns it: the
    /// session's weak handle and the box's name, so the paths that reach into
    /// the session — the expose hop — can be driven against a live one.
    fn setup_channel_with(
        session: crate::box_actor::WeakBoxHandle,
        name: &str,
    ) -> (TempDir, TempDir, TempDir, BoxChannel) {
        let (state, rootfs, cwd, channel, _sender) = setup_channel_sender(session, name);
        (state, rootfs, cwd, channel)
    }

    /// [`setup_channel_with`] keeping the request sender too, for a test
    /// that drives the actor's own loop ([`BoxChannel::run`]) rather than a
    /// handler: the loop ends when the sender is dropped.
    fn setup_channel_sender(
        session: crate::box_actor::WeakBoxHandle,
        name: &str,
    ) -> (
        TempDir,
        TempDir,
        TempDir,
        BoxChannel,
        mpsc::Sender<ChannelRequest>,
    ) {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        setup_channel_in(
            session,
            name,
            &manifest_dir.join("../mctx/testdata/fakerepo"),
        )
    }

    /// [`setup_channel_sender`] for the project at `repo`.
    fn setup_channel_in(
        session: crate::box_actor::WeakBoxHandle,
        name: &str,
        repo: &Path,
    ) -> (
        TempDir,
        TempDir,
        TempDir,
        BoxChannel,
        mpsc::Sender<ChannelRequest>,
    ) {
        let cwd = tempdir().unwrap();
        let state = tempdir().unwrap();
        let home = tempdir().unwrap();
        let rootfs = tempdir().unwrap();
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let config = ConfigBuilder::new()
            .with_state_dir(state.path().to_path_buf())
            .with_repo_dir(repo.to_path_buf())
            .with_stdlib_dir(manifest_dir.join("../stdlib/minimal-ncl"))
            .with_no_fetch(true)
            .build()
            .unwrap();

        let mut ctx = Context::new(config).unwrap();
        let mut graph = ctx.graph_from_all_packages().unwrap();
        graph.top_levels = vec![];

        let (tx, rx) = mpsc::channel(4);
        let channel = BoxChannel {
            name: name.to_string(),
            rootfs: DaemonAbsPath::try_new(
                Utf8PathBuf::try_from(rootfs.path().to_path_buf()).unwrap(),
            )
            .unwrap(),
            state_dir: DaemonAbsPath::try_new(
                Utf8PathBuf::try_from(state.path().to_path_buf()).unwrap(),
            )
            .unwrap(),
            working: DaemonAbsPath::try_new(
                Utf8PathBuf::try_from(cwd.path().to_path_buf()).unwrap(),
            )
            .unwrap(),
            home: DaemonAbsPath::try_new(Utf8PathBuf::try_from(home.path().to_path_buf()).unwrap())
                .unwrap(),
            has_packages: HashSet::new(),
            box_id: "a session in a test".to_string(),
            classifier_leaf: None,
            session_id: None,
            ot: None,
            session,
            runtime_env: RuntimeEnv::default(),
            ctx,
            graph,
            rx,
        };
        (state, rootfs, cwd, channel, tx)
    }

    /// TEL-045 at the channel's own loop: an opted-out helper request
    /// (`otel%off%`) leaves no command line in the daemon's records, the
    /// trace-level "session channel handling" record included, while the
    /// same request without the prefix leaves its line. The loop is driven
    /// through the request sender, so the guard at the record is what is
    /// under test, not the span alone. A thread-local subscriber at TRACE
    /// reads the record: the shared capture sits above it.
    #[tokio::test]
    async fn an_opted_out_helper_request_keeps_its_line_out_of_the_log() {
        let capture = crate::test_harness::CaptureWriter::default();
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_writer(capture.clone())
                .with_ansi(false)
                .finish(),
        );
        let (_state, _rootfs, _cwd, chan, tx) =
            setup_channel_sender(crate::box_actor::WeakBoxHandle::dangling(), "optout");
        // Two public-exposure requests, refused without a session so the
        // handler is quick: the plain one and the opted-out one. The ports
        // tell their lines apart in the log.
        let mut replies = Vec::new();
        for line in ["net-expose-public%3131", "otel%off%net-expose-public%3232"] {
            let (ours, theirs) = UnixStream::pair().unwrap();
            replies.push(ours);
            tx.send(ChannelRequest {
                line: line.to_string(),
                raw: None,
                stream: theirs,
            })
            .await
            .unwrap();
        }
        drop(tx);
        chan.run().await;
        for reply in &replies {
            assert_eq!(
                read_lines(reply),
                vec![
                    "error: public exposure is not available on this host. Nothing was published."
                ],
                "both requests were handled"
            );
        }
        // The channel's own line, the one that names the request as it
        // arrived, is written for the plain request and withheld for the
        // opted-out one. The handler's lines under the opted-out request
        // carry the span's `telemetry="opt-out"` mark, which the export
        // layer honours (TEL-045); a plain local sink like this one shows
        // them, and that is not what the opt-out is for.
        let logged = capture.contents();
        assert!(
            logged.contains("session channel handling: net-expose-public%3131"),
            "the plain request leaves its line: {logged}"
        );
        assert!(
            !logged.contains("session channel handling: otel%off%net-expose-public%3232")
                && !logged.contains("session channel handling: net-expose-public%3232"),
            "the opted-out request's own line is withheld: {logged}"
        );
        let opted_out_lines: Vec<&str> =
            logged.lines().filter(|l| l.contains("port=3232")).collect();
        assert!(
            !opted_out_lines.is_empty()
                && opted_out_lines
                    .iter()
                    .all(|l| l.contains("telemetry=\"opt-out\"")),
            "every line under the opted-out request carries the opt-out mark: {opted_out_lines:?}"
        );
        assert!(
            logged
                .lines()
                .filter(|l| l.contains("port=3131"))
                .all(|l| !l.contains("telemetry=\"opt-out\"")),
            "the plain request's lines carry no opt-out mark: {logged}"
        );
    }

    /// Reads all currently-available lines from a `UnixStream`.
    fn read_lines(stream: &UnixStream) -> Vec<String> {
        stream.set_nonblocking(true).unwrap();
        BufReader::new(stream)
            .lines()
            .map_while(Result::ok)
            .collect()
    }

    #[tokio::test]
    async fn errs_on_unknown_command() {
        let (_state, _rootfs, _cwd, mut chan) = setup_channel();
        let (mut ours, theirs) = UnixStream::pair().unwrap();

        chan.handle("garbage-input", &mut ours).await;
        drop(ours);

        let lines = read_lines(&theirs);
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("error: unhandled input 'garbage-input'"),
            "unexpected output: {lines:?}"
        );
    }

    /// The box's `min net expose <port>` reaches the channel as
    /// `net-expose%<port>` (NET-043) — the request shape the helper sends —
    /// and the channel answers it rather than treating it as unknown input:
    /// a non-numeric port is refused as one, and a numeric one is routed to
    /// the session that owns the channel (here a dangling handle, so the
    /// routing is what the reply names). The decision itself — against the
    /// box's `dynamic_ingress` — is the session actor's, proven where it
    /// lives.
    #[tokio::test]
    async fn net_expose_reaches_the_session_channel() {
        let (_state, _rootfs, _cwd, mut chan) = setup_channel();
        let (mut ours, theirs) = UnixStream::pair().unwrap();

        #[expect(
            clippy::large_futures,
            reason = "the handle future carries the harness's whole channel; the test awaits \
                      it to completion"
        )]
        chan.handle("net-expose%http", &mut ours).await;
        drop(ours);
        assert_eq!(
            read_lines(&theirs),
            vec!["error: 'http' is not a port number"],
            "a non-numeric port is refused as one"
        );

        let (mut ours, theirs) = UnixStream::pair().unwrap();
        #[expect(
            clippy::large_futures,
            reason = "the handle future carries the harness's whole channel; the test awaits \
                      it to completion"
        )]
        chan.handle("net-expose%3000", &mut ours).await;
        drop(ours);
        assert_eq!(
            read_lines(&theirs),
            vec!["error: session is gone"],
            "a numeric port is routed to the session that owns the channel"
        );
    }

    /// NET-145: the box's `min net expose --public [<port>]` arrives as its
    /// own request, with or without a port, and is refused with the plain
    /// line the helper prints before it exits 1. The session is never asked,
    /// so nothing is published: the dangling session handle here would
    /// answer `session is gone` if it were. The info line names the box, the
    /// port as given and the outcome.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expose_public_refused_without_public_surface() {
        let capture = crate::test_harness::captured_log();
        let (_state, _rootfs, _cwd, mut chan) = setup_channel();
        for request in ["net-expose-public%3000", "net-expose-public%"] {
            let (mut ours, theirs) = UnixStream::pair().unwrap();
            #[expect(
                clippy::large_futures,
                reason = "the handle future carries the harness's whole channel; the test \
                          awaits it to completion"
            )]
            chan.handle(request, &mut ours).await;
            drop(ours);
            assert_eq!(
                read_lines(&theirs),
                vec![
                    "error: public exposure is not available on this host. Nothing was published."
                ],
                "{request}: the public request is refused, and the session is not asked"
            );
        }
        assert_eq!(
            super::channel_method("net-expose-public%3000"),
            "net-expose-public"
        );
        let logged = capture.contents();
        let lines: Vec<&str> = logged
            .lines()
            .filter(|line| {
                line.contains("dynamic ingress expose")
                    && line.contains("outcome=\"refused: public exposure\"")
            })
            .collect();
        assert_eq!(lines.len(), 2, "one line per request, got: {logged}");
        assert!(lines[0].contains("port=3000"), "{}", lines[0]);
    }

    /// NET-044's observability for the paths no session actor ever saw — the
    /// ones a `min net expose` request can take without one deciding it: a
    /// port that is not a number, a session that is gone, a reply channel an
    /// actor dropped before answering, and a record the actor could not
    /// read, whose line the actor cannot write because the box's name lives
    /// in the record it could not read. This channel holds its own copy of
    /// the name, so it writes those lines; each request leaves exactly one,
    /// naming the box, the port as given, and the outcome. Every path the
    /// actor did see — including a publish that failed, whatever the source
    /// — leaves its own line there, pinned by the expose tests in `box_actor`,
    /// so the channel writes none for it: one request, one line, on every
    /// path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expose_logs_every_path_from_the_channel() {
        let capture = crate::test_harness::captured_log();

        // A port that is not a number, and a session that is gone: two
        // requests a dangling channel answers on its own. Under this test's
        // own box name — the shared capture holds every test's lines, so
        // each request's line below is found and counted by the box it
        // names.
        let (_state, _rootfs, _cwd, mut chan) =
            setup_channel_with(crate::box_actor::WeakBoxHandle::dangling(), "chanweb");
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        #[expect(
            clippy::large_futures,
            reason = "the handle future carries the harness's whole channel; the test awaits \
                      it to completion"
        )]
        chan.handle("net-expose%http", &mut ours).await;
        drop(ours);
        assert_eq!(
            read_lines(&theirs),
            vec!["error: 'http' is not a port number"],
            "a non-numeric port is refused as one"
        );

        let (mut ours, theirs) = UnixStream::pair().unwrap();
        #[expect(
            clippy::large_futures,
            reason = "the handle future carries the harness's whole channel; the test awaits \
                      it to completion"
        )]
        chan.handle("net-expose%3000", &mut ours).await;
        drop(ours);
        assert_eq!(
            read_lines(&theirs),
            vec!["error: session is gone"],
            "a numeric port is routed to the session that owns the channel"
        );

        // A session whose record cannot be read: the actor returns its own
        // typed failure — it cannot name the box — and the line is this
        // channel's, which knows the name without the record.
        let server = crate::test_harness::TestServer::new().await;
        let mut client = server.connect().await;
        let id =
            crate::test_harness::create_configured_session(&mut client, "recweb", "/tmp").await;
        let manager = server.state.sessions_manager().await;
        let handle = manager
            .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .expect("the session resolves");
        // The record, made unreadable on disk: the read every expose request
        // does now fails, before any decision exists to log.
        let sessions_dir = server
            .state
            .minimal_state_dir()
            .await
            .as_utf8_path()
            .as_std_path()
            .join("sessions");
        let records: Vec<std::path::PathBuf> = std::fs::read_dir(&sessions_dir)
            .expect("the state root holds the sessions dir")
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_ok_and(|file_type| file_type.is_dir()))
            .map(|entry| entry.path().join("record.json"))
            .filter(|record| record.is_file())
            .collect();
        assert_eq!(records.len(), 1, "one session, one record: {records:?}");
        std::fs::write(&records[0], "not a record").expect("the record is made unreadable");

        let (_state, _rootfs, _cwd, mut chan) = setup_channel_with(handle.downgrade(), "recweb");
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        #[expect(
            clippy::large_futures,
            reason = "the handle future carries the harness's whole channel; the test awaits \
                      it to completion"
        )]
        chan.handle("net-expose%3000", &mut ours).await;
        drop(ours);
        let lines = read_lines(&theirs);
        assert_eq!(lines.len(), 1, "one reply: {lines:?}");
        assert!(
            lines[0].starts_with(
                "error: port 3000 was not opened: the session's saved state could not be read:"
            ),
            "the reply is the typed record-read failure: {lines:?}"
        );

        // A publish that failed with `ENOTCONN` out of a bind the actor did
        // attempt: the actor saw the request, so its line is the actor's and
        // this channel must not add one — a real `ENOTCONN` there is a
        // `Publish` failure, not the dead-actor failure it must not be
        // conflated with. A stand-in actor answers it, then drops the reply
        // channel of the next request, which no actor saw: that one is the
        // `ActorGone` failure, and its line is this channel's.
        let (_state, _rootfs, _cwd, mut chan) = setup_channel_with(
            crate::box_actor::WeakBoxHandle::answering(vec![Err(
                crate::net::policy::ExposeFailure::Publish {
                    port: 3000,
                    source: std::io::Error::new(
                        std::io::ErrorKind::NotConnected,
                        "a bind answered ENOTCONN",
                    ),
                },
            )]),
            "bindweb",
        );
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        #[expect(
            clippy::large_futures,
            reason = "the handle future carries the harness's whole channel; the test awaits \
                      it to completion"
        )]
        chan.handle("net-expose%3000", &mut ours).await;
        drop(ours);
        let lines = read_lines(&theirs);
        assert_eq!(lines.len(), 1, "one reply: {lines:?}");
        assert!(
            lines[0].starts_with("error: publishing port 3000 failed:")
                && lines[0].contains("a bind answered ENOTCONN"),
            "the reply is the typed publish failure, source intact: {lines:?}"
        );

        let (mut ours, theirs) = UnixStream::pair().unwrap();
        #[expect(
            clippy::large_futures,
            reason = "the handle future carries the harness's whole channel; the test awaits \
                      it to completion"
        )]
        chan.handle("net-expose%3000", &mut ours).await;
        drop(ours);
        let lines = read_lines(&theirs);
        assert_eq!(lines.len(), 1, "one reply: {lines:?}");
        assert!(
            lines[0].starts_with("error: port 3000 was not opened: the box is stopping or stopped"),
            "a reply channel the actor dropped is its own typed failure: {lines:?}"
        );

        // One line per request — four wrote one, and the ENOTCONN publish
        // wrote none — each naming the box and the port as given. Counted
        // and taken per box name: under the shared capture every test's
        // lines ride one buffer, so a request's line is found by the box
        // it names.
        let logged = capture.contents();
        let lines_for = |name: &str| -> Vec<&str> {
            logged
                .lines()
                .filter(|line| {
                    line.contains("dynamic ingress expose")
                        && line.contains(&format!("name={name}"))
                })
                .collect()
        };
        assert_eq!(
            lines_for("chanweb").len(),
            2,
            "one line per request the dangling channel answered on its own: {logged}"
        );
        assert_eq!(
            lines_for("recweb").len(),
            1,
            "the record the actor could not read says its one line: {logged}"
        );
        assert_eq!(
            lines_for("bindweb").len(),
            1,
            "the dropped reply channel says its one line: {logged}"
        );
        assert!(
            !logged
                .lines()
                .any(|line| line.contains("publishing port 3000 failed")),
            "a publish the actor attempted is the actor's line to write, and \
             this channel must not add one for the same request: {logged}"
        );
        assert!(
            lines_for("chanweb")[0].contains("port=http")
                && lines_for("chanweb")[0].contains("outcome=\"refused\"")
                && lines_for("chanweb")[0].contains("reason='http' is not a port number"),
            "the non-numeric port's line names the port as given: {}",
            lines_for("chanweb")[0]
        );
        assert!(
            lines_for("chanweb")[1].contains("port=3000")
                && lines_for("chanweb")[1].contains("outcome=\"refused\"")
                && lines_for("chanweb")[1].contains("reason=the session is gone"),
            "the gone session's line says so: {}",
            lines_for("chanweb")[1]
        );
        assert!(
            lines_for("recweb")[0].contains("port=3000")
                && lines_for("recweb")[0].contains("outcome=\"refused\"")
                && lines_for("recweb")[0].contains(
                    "reason=port 3000 was not opened: the session's saved state could not be read"
                ),
            "the record-read failure's line names the box, whose name the \
             unreadable record could not: {}",
            lines_for("recweb")[0]
        );
        assert!(
            lines_for("bindweb")[0].contains("port=3000")
                && lines_for("bindweb")[0].contains("outcome=\"refused\"")
                && lines_for("bindweb")[0]
                    .contains("reason=port 3000 was not opened: the box is stopping or stopped"),
            "the dropped reply channel's line is this channel's, naming the \
             box: {}",
            lines_for("bindweb")[0]
        );
    }

    /// The publish reply is a plain fact for every port (NET-044): a port
    /// the box declared was admitted when it attached, and a runtime-only
    /// port in the same range is admitted by the publish itself, so neither
    /// reply carries a "not yet reachable" caveat. One box, one flow.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expose_reply_is_a_plain_publish_for_declared_and_runtime_ports() {
        let server = crate::test_harness::TestServer::new().await;
        let mut client = server.connect().await;
        // The hand vouched for, so the registry publishes it: both publishes
        // below bind at the box's own address.
        let manager = server.state.sessions_manager().await;
        manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
        let web = crate::box_actor::tests::finalize_declared_dynamic_ingress_session(
            &mut client,
            "web",
            std::net::Ipv4Addr::new(100, 64, 128, 51),
            std::net::Ipv4Addr::new(127, 0, 64, 51),
        )
        .await;
        let handle = manager
            .get_session(crate::box_manager::BoxKeyPredicate::Id(web))
            .await
            .unwrap()
            .expect("the box resolves");
        handle
            .ensure_host("tester".to_string())
            .await
            .expect("the box launches its host");
        let sock = handle
            .net_switch()
            .await
            .unwrap()
            .lock()
            .await
            .control_socket();
        let (forwarder, served) = crate::box_actor::tests::fake_forwarder(sock, 200).await;
        let (_state, _rootfs, _cwd, mut chan) = setup_channel_with(handle.downgrade(), "web");

        // The declared port: the gate admitted it when the box attached, so
        // the reply is a fact — reachable now, no caveat.
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        #[expect(
            clippy::large_futures,
            reason = "the handle future carries the harness's whole channel; the test awaits \
                      it to completion"
        )]
        chan.handle("net-expose%3000", &mut ours).await;
        drop(ours);
        assert_eq!(
            read_lines(&theirs),
            vec!["msg:published port 3000 at 127.0.64.51:3000"],
            "a declared port's reply carries no reachability caveat"
        );

        // A runtime-only port in the same range: the publish admitted it at
        // the box's gate, so its reply is the same plain fact.
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        #[expect(
            clippy::large_futures,
            reason = "the handle future carries the harness's whole channel; the test awaits \
                      it to completion"
        )]
        chan.handle("net-expose%3200", &mut ours).await;
        drop(ours);
        assert_eq!(
            read_lines(&theirs),
            vec!["msg:published port 3200 at 127.0.64.51:3200"],
            "a runtime-only port's reply carries no reachability caveat"
        );
        forwarder.abort();
        assert_eq!(
            served.lock().expect("served lock").len(),
            2,
            "one mapping is one request, and both publishes reached the switch"
        );
    }

    /// Drives one in-box `min net expose <port>` against the session that
    /// owns the channel and returns the reply lines, for the refusal tests
    /// below: each pins the line the box's caller reads, which is where a
    /// refusal names its way forward.
    async fn expose_reply(
        handle: &crate::box_actor::BoxHandle,
        name: &str,
        port: u16,
    ) -> Vec<String> {
        let (_state, _rootfs, _cwd, mut chan) = setup_channel_with(handle.downgrade(), name);
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        #[expect(
            clippy::large_futures,
            reason = "the handle future carries the harness's whole channel; the test awaits \
                      it to completion"
        )]
        chan.handle(&format!("net-expose%{port}"), &mut ours).await;
        drop(ours);
        read_lines(&theirs)
    }

    /// The deny refusal names the way forward: the setting that allows a
    /// publish, and the host-side forward that needs no policy change, with
    /// the box's name and the port asked for filled in by the daemon. Still
    /// an `error:` line, so the helper exits 1.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expose_deny_reply_names_the_way_forward() {
        let server = crate::test_harness::TestServer::new().await;
        let mut client = server.connect().await;
        let id = crate::box_actor::tests::finalize_dynamic_ingress_session(
            &mut client,
            "web",
            std::net::Ipv4Addr::new(100, 64, 128, 52),
            std::net::Ipv4Addr::new(127, 0, 64, 52),
            None,
            None,
        )
        .await;
        let manager = server.state.sessions_manager().await;
        let handle = manager
            .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .expect("the box resolves");
        assert_eq!(
            expose_reply(&handle, "web", 3001).await,
            vec![
                "error: dynamic ingress is denied for this box. Re-activate with --network \
                 own_ip and --dynamic-ingress allow --dynamic-range <lo>-<hi> (or \
                 --dynamic-ingress ask) to allow it, or forward it from the host now: min \
                 net forward web <local>:3001"
            ],
        );
    }

    /// The way forward names the box as it is called now, not as it was
    /// created: the channel's own copy of the name is the creation-time one,
    /// so a box renamed since would otherwise be pointed at a name no
    /// command resolves. The line is built from the record the request is
    /// decided against.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expose_reply_names_the_renamed_box() {
        let server = crate::test_harness::TestServer::new().await;
        let mut client = server.connect().await;
        let id = crate::box_actor::tests::finalize_dynamic_ingress_session(
            &mut client,
            "web",
            std::net::Ipv4Addr::new(100, 64, 128, 54),
            std::net::Ipv4Addr::new(127, 0, 64, 54),
            None,
            None,
        )
        .await;
        let manager = server.state.sessions_manager().await;
        let handle = manager
            .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .expect("the box resolves");
        handle
            .rename("api".to_string())
            .await
            .expect("the box renames");
        // The channel still carries the name the environment was built with.
        let lines = expose_reply(&handle, "web", 3001).await;
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].ends_with("min net forward api <local>:3001"),
            "the way forward names the box as it is called now: {}",
            lines[0]
        );
        assert!(
            !lines[0].contains("web"),
            "the creation-time name is not the one offered: {}",
            lines[0]
        );
    }

    /// A `--network none` box cannot carry dynamic ingress — the activation
    /// refuses the flags off `own_ip` — so re-activating with them is no way
    /// forward for it. The host-side forward is: it dials inside the box's
    /// own namespace, so it reaches a port a `none` box listens on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expose_deny_reply_on_a_none_box_offers_only_the_forward() {
        use minimald_rpc::{
            ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, FinalizeSession,
            FinalizeSessionRequest,
        };
        let server = crate::test_harness::TestServer::new().await;
        let mut client = server.connect().await;
        let mut request = crate::test_harness::create_session_req("web", "/uwu");
        request.config.network = boxes::NetworkMode::NoNet;
        let id = client.call::<CreateSession>(&request).await.unwrap().id;
        crate::test_harness::unwrap_ready(
            client
                .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
                    session_id: id,
                    contribution: Default::default(),
                })
                .await
                .unwrap(),
        );
        client
            .call::<FinalizeSession>(&FinalizeSessionRequest {
                session_id: id,
                report_shared_port_collisions: false,
            })
            .await
            .unwrap();
        let manager = server.state.sessions_manager().await;
        let handle = manager
            .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .expect("the box resolves");
        assert_eq!(
            expose_reply(&handle, "web", 3001).await,
            vec![
                "error: dynamic ingress is denied for this box: a --network none box has no \
                 address to publish at. Forward it from the host instead: min net forward \
                 web <local>:3001"
            ],
        );
    }

    /// An `ask` with nobody attached names the two ways forward: attach a
    /// terminal and retry, or have the host forward the port. Still an
    /// `error:` line, so the helper exits 1.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expose_ask_unattended_reply_names_the_way_forward() {
        let server = crate::test_harness::TestServer::new().await;
        let mut client = server.connect().await;
        let id = crate::box_actor::tests::finalize_dynamic_ingress_session(
            &mut client,
            "web",
            std::net::Ipv4Addr::new(100, 64, 128, 53),
            std::net::Ipv4Addr::new(127, 0, 64, 53),
            Some(boxes::DynamicIngress::Ask),
            Some((3000, 3999)),
        )
        .await;
        let manager = server.state.sessions_manager().await;
        let handle = manager
            .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .expect("the box resolves");
        // No host is running, so nobody is attached to answer.
        assert_eq!(
            expose_reply(&handle, "web", 3001).await,
            vec![
                "error: dynamic ingress is set to ask and nobody is attached to answer: \
                 attach a terminal (min session attach web) and retry, or have the host \
                 forward it (min net forward web <local>:3001)"
            ],
        );
    }

    /// A host-address box's port needs no exposing: the reply says where it
    /// already answers, as a plain `msg:` line, so the helper exits 0 — the
    /// goal is met, and an error would read as a failure. The harness daemon
    /// is native, so the host's loopback is named beside the name; the
    /// VM-backed rendering, without it, is pinned in `net::policy`'s tests.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expose_host_address_reply_is_a_plain_message() {
        let server = crate::test_harness::TestServer::new().await;
        let mut client = server.connect().await;
        let id = crate::test_harness::create_configured_session(&mut client, "web", "/uwu").await;
        let manager = server.state.sessions_manager().await;
        let handle = manager
            .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .expect("the box resolves");
        assert_eq!(
            expose_reply(&handle, "web", 3001).await,
            vec![
                "msg:port 3001 needs no exposing: this box shares the host's network, so it \
                 already answers at web.min.internal:3001 (and localhost:3001)"
            ],
        );
    }

    /// A port the box's own listening process published already is the goal
    /// met, not a refusal: the reply says where the port answers and that
    /// the publication lasts while the process listens, as a plain `msg:`
    /// line, so the helper exits 0.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expose_reply_on_a_listen_published_port_is_a_plain_message() {
        let server = crate::test_harness::TestServer::new().await;
        let mut client = server.connect().await;
        let manager = server.state.sessions_manager().await;
        let listener = crate::box_actor::tests::listening_socket();
        let port = crate::box_actor::tests::port_of(&listener);
        let loopback = std::net::Ipv4Addr::new(127, 0, 64, 86);
        let (handle, gate, _served) = crate::box_actor::tests::box_with_listen_plan(
            &mut client,
            &manager,
            "web",
            std::net::Ipv4Addr::new(100, 64, 128, 86),
            loopback,
            (port, port),
        )
        .await;
        crate::box_actor::tests::soon(|| gate.admits_tcp(port)).await;
        assert_eq!(
            expose_reply(&handle, "web", port).await,
            vec![format!(
                "msg:port {port} is published already at {loopback}:{port}, because a \
                 process in this box is listening on it. It is unpublished when that \
                 process stops listening on it."
            )],
        );
        handle.stop().await;
        drop(listener);
    }

    /// NET-043's host-side-only boundary: the dynamic ingress stance and
    /// range are create inputs, and nothing a process inside the box can
    /// send sets or widens them. The in-box expose request carries a port
    /// and no policy field — a request spelling anything more than the
    /// port is not a port number and is refused as one — so a publish,
    /// allowed or refused, is decided against the stance the box was
    /// created with and leaves the record's policy bit-identical. There is
    /// no in-box verb that writes `IngressPolicy` at all; this pins the
    /// boundary from the box's side: the only reachable request cannot
    /// carry a stance, and the record the daemon holds after a successful
    /// publish is the one the create stored.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn in_box_expose_cannot_change_ingress_policy() {
        let server = crate::test_harness::TestServer::new().await;
        let mut client = server.connect().await;
        // The hand vouched for, so the registry publishes it: the allowed
        // publish below binds at the box's own address.
        let manager = server.state.sessions_manager().await;
        manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
        let web = crate::box_actor::tests::finalize_dynamic_ingress_session(
            &mut client,
            "web",
            std::net::Ipv4Addr::new(100, 64, 128, 61),
            std::net::Ipv4Addr::new(127, 0, 64, 61),
            Some(boxes::DynamicIngress::Allow),
            Some((3000, 3999)),
        )
        .await;
        let handle = manager
            .get_session(crate::box_manager::BoxKeyPredicate::Id(web))
            .await
            .unwrap()
            .expect("the box resolves");
        handle
            .ensure_host("tester".to_string())
            .await
            .expect("the box launches its host");
        let sock = handle
            .net_switch()
            .await
            .unwrap()
            .lock()
            .await
            .control_socket();
        let (forwarder, served) = crate::box_actor::tests::fake_forwarder(sock, 200).await;
        let (_state, _rootfs, _cwd, mut chan) = setup_channel_with(handle.downgrade(), "web");

        // The stance the create stored — the fixed point every request below
        // must leave bit-identical, including the range an in-box request
        // would most want to widen.
        let policy_at_create = client
            .call::<minimald_rpc::GetSessionRecord>(&minimald_rpc::GetSessionRecordRequest::Id(web))
            .await
            .record
            .expect("the create left a record")
            .policy;
        assert_eq!(
            policy_at_create.ingress,
            Some(boxes::IngressPolicy {
                port_mappings: vec![],
                dynamic_allowed_range: Some((3000, 3999)),
                dynamic_ingress: Some(boxes::DynamicIngress::Allow),
            }),
            "the harness box is the one this test's stance describes"
        );

        // A publish the stance allows — the request that would have the
        // best claim on the stance if any did.
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        #[expect(
            clippy::large_futures,
            reason = "the handle future carries the harness's whole channel; the test awaits \
                      it to completion"
        )]
        chan.handle("net-expose%3000", &mut ours).await;
        drop(ours);
        assert_eq!(
            read_lines(&theirs),
            vec!["msg:published port 3000 at 127.0.64.61:3000"],
            "the allowed publish is a fact, admitted at the gate (NET-044)"
        );

        // The refusal the range gives a port outside it — decided against
        // the stored stance, typed as its own error.
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        #[expect(
            clippy::large_futures,
            reason = "the handle future carries the harness's whole channel; the test awaits \
                      it to completion"
        )]
        chan.handle("net-expose%4200", &mut ours).await;
        drop(ours);
        assert_eq!(
            read_lines(&theirs),
            vec![
                "error: port 4200 is outside this box's --dynamic-range 3000-3999. Nothing \
                 was published."
                    .to_string()
            ],
            "the out-of-range request is refused with its own typed error"
        );

        // A request trying to smuggle a stance in the port field: the
        // request carries a port and no policy field, so this is not a port
        // number — refused as one, not parsed as an in-box policy write.
        for smuggle in [
            "net-expose%3000:dynamic_ingress=allow",
            "net-expose%3000-3999",
        ] {
            let (mut ours, theirs) = UnixStream::pair().unwrap();
            #[expect(
                clippy::large_futures,
                reason = "the handle future carries the harness's whole channel; the test awaits \
                          it to completion"
            )]
            chan.handle(smuggle, &mut ours).await;
            drop(ours);
            let lines = read_lines(&theirs);
            assert!(
                lines
                    == vec![format!(
                        "error: '{}' is not a port number",
                        smuggle
                            .split_once('%')
                            .expect("the request names its verb")
                            .1
                    )],
                "{smuggle}: the request carries a port and no policy field, so \
                 anything more is not a port number, got: {lines:?}"
            );
        }
        forwarder.abort();
        assert_eq!(
            served.lock().expect("served lock").len(),
            1,
            "only the allowed publish reached the switch: the refusals asked \
             it nothing"
        );

        // The record after it all: the stance and the range the create
        // stored, unchanged by a publish and by every refusal — no in-box
        // path rewrote the policy the box runs under.
        let policy_after = client
            .call::<minimald_rpc::GetSessionRecord>(&minimald_rpc::GetSessionRecordRequest::Id(web))
            .await
            .record
            .expect("the record still reads")
            .policy;
        assert_eq!(
            policy_after, policy_at_create,
            "no in-box request can set or rewrite the ingress policy"
        );
    }

    /// A variable a running session acquires has to reach two places: the shell,
    /// which exports it, and the daemon, which hands it to anything injected
    /// into the session later. `min add` is the source in production; this
    /// drives the announcement directly, since installing a package would mean
    /// building one.
    #[tokio::test]
    async fn an_acquired_var_reaches_both_the_shell_and_the_daemon() {
        let (_state, _rootfs, _cwd, chan) = setup_channel();
        let (mut ours, theirs) = UnixStream::pair().unwrap();

        chan.announce_env(&mut ours, "GOCACHE", "/state/gocache");
        drop(ours);

        assert_eq!(read_lines(&theirs), vec!["set_env:GOCACHE:/state/gocache"]);
        assert_eq!(
            chan.runtime_env
                .snapshot()
                .get("GOCACHE")
                .map(String::as_str),
            Some("/state/gocache"),
            "the daemon's view is missing a variable the shell was given"
        );
    }

    /// Installing over an earlier install replaces the value, as the shell's
    /// second `export` does.
    #[tokio::test]
    async fn a_reannounced_var_takes_the_newer_value() {
        let (_state, _rootfs, _cwd, chan) = setup_channel();
        let (mut ours, _theirs) = UnixStream::pair().unwrap();

        chan.announce_env(&mut ours, "PYTHONPATH", "/first");
        chan.announce_env(&mut ours, "PYTHONPATH", "/second");

        assert_eq!(
            chan.runtime_env
                .snapshot()
                .get("PYTHONPATH")
                .map(String::as_str),
            Some("/second")
        );
    }

    #[tokio::test]
    async fn search_finds_known_package() {
        let (_state, _rootfs, _cwd, mut chan) = setup_channel();
        let (mut ours, theirs) = UnixStream::pair().unwrap();

        // "uroot" is a known package in the fakerepo fixture.
        chan.handle("search%uroot", &mut ours).await;
        drop(ours);

        let lines = read_lines(&theirs);
        assert!(
            lines.iter().any(|l| l.contains("uroot")),
            "expected 'uroot' in search results, got: {lines:?}"
        );
    }

    /// Names the packages `bsrs` refers to, sorted, for comparing sets across
    /// two parses of the same repo (refs are graph-local; names are not).
    fn names<'a>(graph: &Graph, bsrs: impl IntoIterator<Item = &'a BuildSpecRef>) -> Vec<String> {
        let mut out: Vec<String> = bsrs
            .into_iter()
            .map(|bsr| graph.get(bsr).expect("bsr in graph").name.clone())
            .collect();
        out.sort();
        out
    }

    /// A refresh re-parses the mfile, so its graph's `top_levels` are the
    /// packages the *repo* declares. The session means something else by that
    /// field — the packages it has injected into its rootfs — and `install`
    /// reads it to decide whether `min add` has any work to do. A refresh that
    /// let the repo's answer through would make `min add <declared-pkg>` take
    /// the already-installed path and inject nothing.
    #[tokio::test]
    async fn refresh_does_not_adopt_the_repos_top_levels() {
        let (_state, _rootfs, _cwd, mut chan) = setup_channel();
        let (mut ours, _theirs) = UnixStream::pair().unwrap();

        // The fixture declares `uroot`; this session has installed nothing.
        assert!(
            chan.graph.by_name("uroot").is_some(),
            "fixture no longer declares uroot"
        );
        chan.graph.top_levels = vec![];
        chan.has_packages = HashSet::new();

        let (_ctx, graph, has_packages) = chan
            .refresh(&mut ours)
            .await
            .expect("refresh should succeed");

        assert!(
            graph.top_levels.is_empty(),
            "refresh adopted the repo's top-levels as the installed set: {:?}",
            names(&graph, &graph.top_levels)
        );
        assert!(has_packages.is_empty());
    }

    /// The other half: refs are graph-local, so what the session *has*
    /// installed has to be re-resolved by name onto the reparsed graph rather
    /// than carried over or dropped.
    #[tokio::test]
    async fn refresh_remaps_the_installed_set_onto_the_new_graph() {
        let (_state, _rootfs, _cwd, mut chan) = setup_channel();
        let (mut ours, _theirs) = UnixStream::pair().unwrap();

        let uroot = *chan.graph.by_name("uroot").expect("fakerepo has uroot");
        chan.graph.top_levels = vec![uroot];
        chan.has_packages = HashSet::from([uroot]);

        let (_ctx, graph, has_packages) = chan
            .refresh(&mut ours)
            .await
            .expect("refresh should succeed");

        assert_eq!(
            names(&graph, &graph.top_levels),
            vec!["uroot".to_string()],
            "refresh dropped the session's top-levels"
        );
        assert_eq!(names(&graph, &has_packages), vec!["uroot".to_string()]);
        for bsr in graph.top_levels.iter().chain(has_packages.iter()) {
            assert!(
                graph.get(bsr).is_some(),
                "a ref from the old graph leaked into the new one"
            );
        }
    }

    /// Adding a package the session already has is a no-op, but it must be a
    /// *visible* one: the wire carries no other signal, so a silent return is
    /// indistinguishable from a successful injection.
    #[tokio::test]
    async fn installing_an_already_installed_package_reports_it() {
        let (_state, _rootfs, _cwd, mut chan) = setup_channel();
        let (mut ours, theirs) = UnixStream::pair().unwrap();

        let uroot = *chan.graph.by_name("uroot").expect("fakerepo has uroot");
        chan.graph.top_levels = vec![uroot];

        // Driven directly rather than through `handle`, which would also
        // record the dependency in the fixture's checked-in minimal.toml.
        chan.install(&[("uroot", uroot)], &mut ours).await;
        drop(ours);

        let lines = read_lines(&theirs);
        assert_eq!(
            lines,
            vec!["msg:Already installed: uroot".to_string()],
            "unexpected output: {lines:?}"
        );
    }

    /// A resolved env var shaped `/state/<prefix>` seeds a state
    /// dir named `<prefix>`; non-`/state/` values are ignored. This
    /// is the isolated composition-branch derivation the parity
    /// test does not exercise via `Env::build` (which requires a
    /// full graph + built packages), pulled out into a helper so
    /// it can be unit-tested directly.
    #[test]
    fn state_dirs_from_env_vars_extracts_single_component_prefixes() {
        let env = BTreeMap::from([
            ("GOCACHE".to_string(), "/state/gocache".to_string()),
            ("GOMODCACHE".to_string(), "/state/gomodcache".to_string()),
            ("HOME".to_string(), "/home/user".to_string()),
            ("PS1".to_string(), r"\u@\h $ ".to_string()),
        ]);
        let out = state_dirs_from_env_vars(&env);
        assert_eq!(out.len(), 2);
        assert!(out.contains("gocache"));
        assert!(out.contains("gomodcache"));
    }

    /// A value that's literally `/state/` (no prefix component) is
    /// ignored — creating `state_base_dir/` itself is nonsense.
    #[test]
    fn state_dirs_from_env_vars_ignores_bare_state() {
        let env = BTreeMap::from([("WEIRD".to_string(), "/state/".to_string())]);
        assert!(state_dirs_from_env_vars(&env).is_empty());
    }

    /// The sandbox working directory the helper sends, for tests that don't
    /// care which subdirectory of the workspace the command was typed in.
    fn wd(sub: &str) -> Utf8PathBuf {
        Utf8Path::new(WORKSPACE_ROOT).join(sub)
    }

    /// A session's two daemon directories, `work` and `home`, under `dir`.
    fn session_dirs(dir: &TempDir) -> (DaemonAbsPath, DaemonAbsPath) {
        let root = Utf8PathBuf::try_from(dir.path().to_path_buf()).unwrap();
        let dirs = (root.join("work"), root.join("home"));
        std::fs::create_dir_all(&dirs.0).unwrap();
        std::fs::create_dir_all(&dirs.1).unwrap();
        (
            DaemonAbsPath::try_new(dirs.0).unwrap(),
            DaemonAbsPath::try_new(dirs.1).unwrap(),
        )
    }

    /// An absolute sandbox path, as `resolve_output` produces.
    fn sbx(path: &str) -> SandboxAbsPath {
        SandboxAbsPath::try_new(path).unwrap()
    }

    /// The parse mirrors `mip materialize`'s clap interface, including the
    /// `--flag=value` form clap accepts alongside `--flag value`.
    #[test]
    fn materialize_args_parse_both_flag_forms() {
        let expected = MaterializeArgs {
            opts: crate::box_ops::MaterializeOpts {
                output_name: "image".to_string(),
                arch: Some("arm64".to_string()),
            },
            output: SandboxAbsPath::try_new("/workbench/dist/image.tar").unwrap(),
        };

        let cwd = wd("");
        assert_eq!(
            MaterializeArgs::from_args(&cwd, "--output dist/image.tar --arch arm64 image").unwrap(),
            expected
        );
        assert_eq!(
            MaterializeArgs::from_args(&cwd, "-o=dist/image.tar --arch=arm64 image").unwrap(),
            expected
        );
        // The positional is recognised wherever it lands.
        assert_eq!(
            MaterializeArgs::from_args(&cwd, "image -o dist/image.tar --arch arm64").unwrap(),
            expected
        );
    }

    /// The request line carries the helper's working directory ahead of the
    /// arguments; without it there is nothing to resolve `--output` against,
    /// which must be an error rather than a guess at the workspace root.
    #[test]
    fn materialize_request_carries_the_working_directory() {
        let args = MaterializeArgs::from_request(&format!("{}%-o out.tar image", wd("sub")))
            .expect("a well-formed request");
        assert_eq!(args.output.as_str(), "/workbench/sub/out.tar");

        let err = MaterializeArgs::from_request("-o out.tar image")
            .expect_err("a request without a working directory is malformed");
        assert!(
            err.contains("working directory"),
            "the error must say what is missing, got {err:?}",
        );
    }

    /// The point of sending the cwd: `min materialize -o out.tar` run from a
    /// subdirectory resolves *there*, not at the workspace root. Resolution
    /// stops at an absolute sandbox path — which session directory it names is
    /// `sandbox_to_daemon`'s decision, so `/home` resolves as readily as
    /// `/workbench` and neither is checked here.
    #[test]
    fn materialize_output_resolves_against_the_working_directory() {
        for (cwd, output, want) in [
            // A bare name lands beside the user, wherever they are.
            (
                "/workbench/sub/deep",
                "out.tar",
                "/workbench/sub/deep/out.tar",
            ),
            ("/workbench", "out.tar", "/workbench/out.tar"),
            ("/home/nested", "out.tar", "/home/nested/out.tar"),
            // `..` and `.` are resolved away.
            (
                "/workbench/sub/deep",
                "../out.tar",
                "/workbench/sub/out.tar",
            ),
            (
                "/workbench/sub",
                "./dist/out.tar",
                "/workbench/sub/dist/out.tar",
            ),
            // An absolute path is already a sandbox path: the cwd doesn't
            // enter into it, so it resolves the same way from anywhere.
            (
                "/workbench/sub",
                "/workbench/dist/out.tar",
                "/workbench/dist/out.tar",
            ),
            ("/workbench", "/home/somefile", "/home/somefile"),
            ("/home", "/workbench/somefile", "/workbench/somefile"),
        ] {
            let resolved = resolve_output(Utf8Path::new(cwd), Utf8Path::new(output))
                .unwrap_or_else(|e| panic!("resolving {output:?} from {cwd:?}: {e}"));
            assert_eq!(resolved.as_str(), want, "`-o {output}` from {cwd}");
        }
    }

    /// Each of the two directories a sandbox path can name maps to its own
    /// daemon directory — `/workbench` to the workspace, `/home` to the home.
    #[tokio::test]
    async fn sandbox_paths_land_in_the_session_directory_they_name() {
        let tmp = tempdir().unwrap();
        let (working, home) = session_dirs(&tmp);

        for (path, want) in [
            (
                "/workbench/dist/out.tar",
                working.as_utf8_path().join("dist/out.tar"),
            ),
            (
                "/home/.cache/out.tar",
                home.as_utf8_path().join(".cache/out.tar"),
            ),
        ] {
            create_artifact(&working, &home, &sbx(path))
                .await
                .unwrap_or_else(|e| panic!("creating {path}: {e}"));
            assert!(want.is_file(), "`{path}` should have landed at {want}");
        }
    }

    /// Anything under neither directory is refused rather than redirected:
    /// `/tmp/x.tar` names a file in the *sandbox*, which the daemon cannot
    /// write, and a root names a directory, not an artifact.
    #[tokio::test]
    async fn sandbox_paths_outside_the_session_directories_are_refused() {
        let tmp = tempdir().unwrap();
        let (working, home) = session_dirs(&tmp);

        for (path, want) in [
            ("/tmp/x.tar", "outside the session's"),
            ("/etc/passwd", "outside the session's"),
            ("/", "outside the session's"),
            // A prefix match must be by component, or this would resolve.
            ("/workbenchx/out.tar", "outside the session's"),
            ("/workbench", "is a session directory"),
            ("/home", "is a session directory"),
        ] {
            let err = create_artifact(&working, &home, &sbx(path))
                .await
                .expect_err("a path outside the session directories");
            assert!(
                err.to_string().contains(want),
                "expected {want:?} for {path}, got {err}",
            );
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        }
    }

    /// A `..` that climbs out shows up as a path under neither directory —
    /// `resolve_output` normalizes first precisely so the prefix match cannot
    /// be fooled by a leading component.
    #[tokio::test]
    async fn traversals_out_of_the_session_directories_are_refused() {
        let tmp = tempdir().unwrap();
        let (working, home) = session_dirs(&tmp);

        for (cwd, output) in [
            ("/workbench", "/etc/passwd"),
            ("/workbench", "../out.tar"),
            ("/workbench/sub", "../../out.tar"),
            ("/home", "../../../../etc/passwd"),
            ("/workbench", "/workbench/../etc/passwd"),
        ] {
            let resolved = resolve_output(Utf8Path::new(cwd), Utf8Path::new(output))
                .expect("resolution itself does not judge the destination");
            let err = create_artifact(&working, &home, &resolved)
                .await
                .expect_err("a path leaving the session directories must be refused");
            assert!(
                err.to_string().contains("outside the session's"),
                "expected a containment error for `-o {output}` from {cwd}, got {err}",
            );
        }
    }

    /// The directories leading to the artifact are created, and the bytes go
    /// straight into it — there is no staging copy to publish.
    #[tokio::test]
    async fn create_artifact_creates_the_file_and_its_parents() {
        use tokio::io::AsyncWriteExt as _;

        let tmp = tempdir().unwrap();
        let (working, home) = session_dirs(&tmp);

        let mut file = create_artifact(&working, &home, &sbx("/workbench/dist/image.tar"))
            .await
            .expect("the parent directories are created");
        file.write_all(b"tarball").await.unwrap();
        file.flush().await.unwrap();
        drop(file);

        let dest = working.as_utf8_path().join("dist/image.tar");
        assert_eq!(std::fs::read(&dest).unwrap(), b"tarball");
    }

    /// `resolve_output` reasons about a path in the sandbox's namespace, so it
    /// cannot see a symlink in the workspace pointing out of it. The daemon is
    /// not confined to the sandbox, so the check has to happen on disk or
    /// `-o escape/x.tar` writes wherever the link leads.
    #[tokio::test]
    async fn create_artifact_refuses_a_parent_symlinked_out_of_the_session() {
        let tmp = tempdir().unwrap();
        let (working, home) = session_dirs(&tmp);
        let outside = Utf8PathBuf::try_from(tmp.path().join("outside")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, working.as_utf8_path().join("escape")).unwrap();

        let err = create_artifact(&working, &home, &sbx("/workbench/escape/x.tar"))
            .await
            .expect_err("a symlinked parent leaving the session must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            !outside.join("x.tar").exists(),
            "nothing may be created outside the session directory"
        );
    }

    /// The parent check cannot catch a symlink at the *destination itself*, so
    /// the open refuses to follow one. Otherwise `-o out.tar`, with `out.tar`
    /// linked to `/etc/passwd`, would have the daemon write through it.
    #[tokio::test]
    async fn create_artifact_refuses_a_symlinked_destination() {
        let tmp = tempdir().unwrap();
        let (working, home) = session_dirs(&tmp);
        let outside = Utf8PathBuf::try_from(tmp.path().join("outside.tar")).unwrap();
        std::os::unix::fs::symlink(&outside, working.as_utf8_path().join("out.tar")).unwrap();

        create_artifact(&working, &home, &sbx("/workbench/out.tar"))
            .await
            .expect_err("a symlinked destination must not be followed");
        assert!(
            !outside.exists(),
            "the link's target must not be created, let alone written"
        );
    }

    /// The containment check has to run *before* any directory is created, or
    /// `create_dir_all` walks through the link and materializes directories
    /// outside the session on its way to a destination that is then refused.
    #[tokio::test]
    async fn create_artifact_creates_nothing_through_a_symlinked_parent() {
        let tmp = tempdir().unwrap();
        let (working, home) = session_dirs(&tmp);
        let outside = Utf8PathBuf::try_from(tmp.path().join("outside")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, working.as_utf8_path().join("escape")).unwrap();

        let err = create_artifact(&working, &home, &sbx("/workbench/escape/deep/x.tar"))
            .await
            .expect_err("a destination below a symlinked parent must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            !outside.join("deep").exists(),
            "no directory may be created outside the session"
        );
    }

    /// A symlinked *directory* that stays inside the session directory is
    /// ordinary content and keeps working — the check is containment, not a
    /// ban on links.
    #[tokio::test]
    async fn create_artifact_allows_a_symlink_within_the_session() {
        let tmp = tempdir().unwrap();
        let (working, home) = session_dirs(&tmp);
        std::fs::create_dir_all(working.as_utf8_path().join("real")).unwrap();
        std::os::unix::fs::symlink(
            working.as_utf8_path().join("real"),
            working.as_utf8_path().join("link"),
        )
        .unwrap();

        create_artifact(&working, &home, &sbx("/workbench/link/x.tar"))
            .await
            .expect("a link inside the session directory is fine");
        assert!(
            working.as_utf8_path().join("real/x.tar").exists(),
            "the file lands in the directory the link points at"
        );
    }

    /// `--arch` is optional (the output's own arch, else the host's, applies);
    /// `--output` and the name are not.
    #[test]
    fn materialize_args_require_an_output_path_and_a_name() {
        let cwd = wd("");
        let args = MaterializeArgs::from_args(&cwd, "-o image.tar image").unwrap();
        assert_eq!(args.opts.arch, None);

        for (args, want) in [
            ("image", "--output"),
            ("-o image.tar", "requires the name"),
            ("-o", "requires a value"),
            ("-o image.tar image other", "expected one output name"),
        ] {
            let err = MaterializeArgs::from_args(&cwd, args).expect_err("incomplete invocation");
            assert!(
                err.contains(want),
                "expected {want:?} in the error for {args:?}, got {err:?}",
            );
        }
    }

    /// A mistyped flag must be an error, never a positional: read as one it
    /// would be a second output name, and the report would complain about the
    /// count instead of naming the typo.
    #[test]
    fn materialize_args_reject_unknown_flags() {
        let err = MaterializeArgs::from_args(&wd(""), "--ouput image.tar image")
            .expect_err("a mistyped flag must not parse as an output name");
        assert!(
            err.contains("unknown flag") && err.contains("--ouput"),
            "the error must name the offending flag, got {err:?}",
        );
    }

    /// A multi-component prefix that leaked past the extractor
    /// (which should have already rejected it) is silently dropped
    /// here — the extractor is the layer that surfaces the error
    /// to the client. This helper is the last line of defense but
    /// its concern is producing a valid single-component set, not
    /// diagnosing bad ones.
    #[test]
    fn state_dirs_from_env_vars_silently_drops_multi_component() {
        let env = BTreeMap::from([("WEIRD".to_string(), "/state/foo/bar".to_string())]);
        assert!(state_dirs_from_env_vars(&env).is_empty());
    }

    // BEP-011: two roots `openssl req` issued, with the subject hash
    // `openssl x509 -subject_hash` prints for each. The first has the
    // proxy's subject with a doubled space and capitals. The second has a
    // PrintableString, padding whitespace and a two-valued name.
    const ROOT_FIXTURE: &str = "-----BEGIN CERTIFICATE-----
MIIB6TCCAY+gAwIBAgIUKEyk5XE1f8EVhMjyqFOVAARndXswCgYIKoZIzj0EAwIw
OzEQMA4GA1UECgwHTWluaW1hbDEnMCUGA1UEAwweTWluaW1hbCBCb3ggRWdyZXNz
IFByb3h5ICBSb290MB4XDTI2MTAyMjIzNDU1NFoXDTM2MTAxOTIzNDU1NFowOzEQ
MA4GA1UECgwHTWluaW1hbDEnMCUGA1UEAwweTWluaW1hbCBCb3ggRWdyZXNzIFBy
b3h5ICBSb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExUC2b3xiCEX0LCqy
sX0SMiHE0w+BRLrWRcgXH3TYrLnnvIODSgyYXivXAf938svi3if2u9dz4vLa2xFe
7A9aLKNxMG8wHQYDVR0OBBYEFIgMZA34w+lLInVQsCRYuhrFh28UMB8GA1UdIwQY
MBaAFIgMZA34w+lLInVQsCRYuhrFh28UMA8GA1UdEwEB/wQFMAMBAf8wHAYDVR0e
AQH/BBIwEKAOMAyCCmdpdGh1Yi5jb20wCgYIKoZIzj0EAwIDSAAwRQIgHh0/64gR
ThgYRM6y+810FiKt1tE5xHpfzExZsodENtECIQD0rmeyrbOA0ieA96kOppfKC0hK
HXlvsoVB14bgb2892g==
-----END CERTIFICATE-----\n";
    const ROOT_FIXTURE_HASH: u32 = 0x75ba_e43c;
    const ROOT_FIXTURE_MIXED: &str = "-----BEGIN CERTIFICATE-----
MIIB3jCCAYWgAwIBAgIUJTs63lHvmaKP6+0zeiJcEqmcMEcwCgYIKoZIzj0EAwIw
RTELMAkGA1UEBhMCVVMxGDAWBgNVBAoMDyAgTWluaW1hbHRDb3JwIDEcMAsGA1UE
AwwEUm9vdDANBgNVBAsMBkVncmVzczAeFw0yNjEwMjIyMzQ2MDFaFw0zNjEwMTky
MzQ2MDFaMEUxCzAJBgNVBAYTAlVTMRgwFgYDVQQKDA8gIE1pbmltYWx0Q29ycCAx
HDALBgNVBAMMBFJvb3QwDQYDVQQLDAZFZ3Jlc3MwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAT2BZlyD4iot8ZEN8nWDeFUrSTPNjWVnwvTKXVQ9pSNBooOKADDTelx
i3DPaOjeBqN4rbdyBsezCfBTN0Zbq7Vno1MwUTAdBgNVHQ4EFgQU1qntUuFHdvTi
EaXbONzaxV3n8VQwHwYDVR0jBBgwFoAU1qntUuFHdvTiEaXbONzaxV3n8VQwDwYD
VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiAdxfdz9bZjCvywfPZdGrNy
5AtB0aBLEzU4X+WJQNBCOQIgHA2qJyucOi4ZJc3KkPluYSaqzqvgMfalICgLj9mo
06M=
-----END CERTIFICATE-----\n";
    const ROOT_FIXTURE_MIXED_HASH: u32 = 0x1313_be68;

    #[test]
    fn subject_hash_matches_openssl() {
        for (pem, hash) in [
            (ROOT_FIXTURE, ROOT_FIXTURE_HASH),
            (ROOT_FIXTURE_MIXED, ROOT_FIXTURE_MIXED_HASH),
        ] {
            let der = certificate_der(pem).expect("a PEM certificate");
            assert_eq!(trust_store::subject_hash(&der), Some(hash), "{pem}");
        }
        assert_eq!(certificate_der("not a certificate"), None);
    }

    /// BEP-011: the root lands in the box's own bundle copy and hashed
    /// directory, and the package store's bundle keeps its bytes.
    #[test]
    fn root_certificate_goes_into_the_box_copy_never_the_store() {
        let store = tempfile::tempdir().unwrap();
        let store_bundle = store.path().join("ca-certificates.crt");
        let system_roots = "-----BEGIN CERTIFICATE-----\nU1lTVEVN\n-----END CERTIFICATE-----";
        std::fs::write(&store_bundle, system_roots).unwrap();
        let rootfs = tempfile::tempdir().unwrap();
        let certs = rootfs.path().join("etc/ssl/certs");
        std::fs::create_dir_all(&certs).unwrap();
        std::fs::hard_link(&store_bundle, certs.join("ca-certificates.crt")).unwrap();
        // A system root that holds the same subject hash keeps its link.
        std::fs::write(certs.join("other.pem"), "other").unwrap();
        std::os::unix::fs::symlink("other.pem", certs.join("75bae43c.0")).unwrap();

        let installed = install_root_certificate(rootfs.path(), ROOT_FIXTURE).unwrap();

        assert_eq!(
            installed,
            RootInstall {
                link: "75bae43c.1".to_string(),
                bundle: true
            }
        );
        assert!(layers_ship_ca_bundle([store.path(), rootfs.path()]));
        assert_eq!(
            std::fs::read_to_string(&store_bundle).unwrap(),
            system_roots
        );
        let bundle = std::fs::read_to_string(certs.join("ca-certificates.crt")).unwrap();
        assert_eq!(bundle, format!("{system_roots}\n{ROOT_FIXTURE}"));
        assert_eq!(
            std::fs::read_to_string(certs.join("minimal-box-egress-proxy-root.pem")).unwrap(),
            ROOT_FIXTURE
        );
        assert_eq!(
            std::fs::read_link(certs.join("75bae43c.1")).unwrap(),
            Path::new("minimal-box-egress-proxy-root.pem")
        );
        assert_eq!(
            std::fs::read_link(certs.join("75bae43c.0")).unwrap(),
            Path::new("other.pem")
        );
    }

    /// BEP-011: a link in the rootfs resolves inside the rootfs, so an
    /// absolute link never sends a write to the daemon's own `/etc`.
    #[test]
    fn root_certificate_follows_links_inside_the_rootfs() {
        let rootfs = tempfile::tempdir().unwrap();
        let real = rootfs.path().join("etc/pki/tls/certs");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink("/etc/pki/tls", rootfs.path().join("etc/ssl")).unwrap();

        assert!(!layers_ship_ca_bundle([rootfs.path()]));

        let installed = install_root_certificate(rootfs.path(), ROOT_FIXTURE).unwrap();

        assert_eq!(
            installed,
            RootInstall {
                link: "75bae43c.0".to_string(),
                bundle: false
            }
        );
        assert!(
            !real.join("ca-certificates.crt").exists(),
            "with no system bundle the box gets no bundle"
        );
        assert_eq!(
            std::fs::read_to_string(real.join("minimal-box-egress-proxy-root.pem")).unwrap(),
            ROOT_FIXTURE
        );
        assert!(real.join("75bae43c.0").is_symlink());
    }

    #[test]
    fn root_certificate_that_is_not_a_certificate_is_refused() {
        let rootfs = tempfile::tempdir().unwrap();
        let error = install_root_certificate(rootfs.path(), "garbage").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(!rootfs.path().join("etc/ssl/certs").exists());
    }

    /// BEP-011: a PEM with a second certificate block is refused, so no
    /// trust anchor beyond the proxy's root reaches the box.
    #[test]
    fn root_certificate_with_two_blocks_is_refused() {
        let rootfs = tempfile::tempdir().unwrap();
        let two = format!("{ROOT_FIXTURE}{ROOT_FIXTURE_MIXED}");
        let error = install_root_certificate(rootfs.path(), &two).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(!rootfs.path().join("etc/ssl/certs").exists());
    }

    /// BEP-011: text around the one block never reaches the store.
    #[test]
    fn root_certificate_text_outside_the_block_is_dropped() {
        let rootfs = tempfile::tempdir().unwrap();
        let pem = format!("note before\n{ROOT_FIXTURE}trailing text\n");
        install_root_certificate(rootfs.path(), &pem).unwrap();
        assert_eq!(
            std::fs::read_to_string(
                rootfs
                    .path()
                    .join("etc/ssl/certs/minimal-box-egress-proxy-root.pem")
            )
            .unwrap(),
            ROOT_FIXTURE
        );
    }
}
