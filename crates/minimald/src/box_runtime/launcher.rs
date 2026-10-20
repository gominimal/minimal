//! The launchers: what starts a box's process, and the environment it
//! starts in.

use super::*;

/// Emit one `tracing::info!` per item the launcher folds into the
/// session — packages, vars, and patches — tagging each with its
/// provenance so an operator can trace "where did `EDITOR=hx` come
/// from?" back to the loadout / project / package that contributed
/// it.
///
/// Baseline packages (the launcher-defaults `base`, `coreutils`,
/// `socat`) log with `source = "launcher-baseline"` so they can be
/// distinguished from composition contributions. Patches and hooks
/// still log even though the launcher can't act on them yet — an
/// operator inspecting a session should see the intent even when
/// the plumbing is deferred.
///
/// Var values are logged at `debug` (separate call) rather than
/// `info` so an accidentally-inherited secret doesn't sit in the
/// default log stream.
pub(super) fn log_session_contents(
    session_name: &str,
    baseline_packages: &[&str],
    composition: Option<&boxes::core::compose::Composition>,
) {
    for p in baseline_packages {
        tracing::info!(
            session = session_name,
            domain = "package",
            name = p,
            source = "launcher-baseline",
            "session content",
        );
    }
    let Some(comp) = composition else {
        return;
    };
    for p in comp.packages() {
        tracing::info!(
            session = session_name,
            domain = "package",
            name = %p.package(),
            source = ?boxes::core::source::Provenanced::source(p),
            "session content",
        );
    }
    for v in comp.vars() {
        let var = v.var();
        tracing::info!(
            session = session_name,
            domain = "var",
            name = %var.name(),
            source = ?boxes::core::source::Provenanced::source(v),
            "session content",
        );
        tracing::debug!(
            session = session_name,
            name = %var.name(),
            value = %var.value(),
            "session var value",
        );
    }
    for sp in comp.patches() {
        let patch = sp.patch();
        tracing::info!(
            session = session_name,
            domain = "patch",
            host_source = %patch.host_path(),
            sandbox_dest = %patch.destination(),
            source = ?boxes::core::source::Provenanced::source(sp),
            "session content (patch: materialized into session home at FinalizeSession)",
        );
    }
    // Hooks are logged in setup order (project first, then loadouts —
    // see `Composition::lifecycle_hooks`), so the log reads in the
    // order the transitions will fire. Execution is still deferred, so
    // this records intent rather than an outcome; an operator
    // inspecting a session should be able to see which scripts it
    // carries and where each came from before any of them runs.
    for h in comp.lifecycle_hooks() {
        let src = boxes::core::source::Provenanced::source(h);
        let hook = h.hook();
        [
            ("on_activate", hook.on_activate()),
            ("on_destroy", hook.on_destroy()),
            ("on_attach", hook.on_attach()),
            ("on_detach", hook.on_detach()),
        ]
        .into_iter()
        .filter_map(|(event, script)| script.map(|s| (event, s)))
        .for_each(|(event, script)| {
            let kind = match script.body() {
                boxes::core::lifecyclehook::HookScriptBody::Inline(_) => "inline",
                boxes::core::lifecyclehook::HookScriptBody::External(_) => "external",
            };
            tracing::info!(
                session = session_name,
                domain = "lifecycle_hook",
                event,
                kind,
                timeout_secs = script.timeout().as_secs(),
                description = hook.description().unwrap_or_default(),
                source = ?src,
                "session content (lifecycle hook: composed, not yet executed)",
            );
        });
    }
}

/// Opens a PTY of the requested size, launches the session process
/// wired to the slave side, and yields the master side plus a
/// handle to the process. The seam between the generic [`Host`]
/// runtime and the process-creation backend.
pub(crate) trait BoxLauncher {
    /// The running-process handle this launcher produces.
    type Process: BoxProcess;
    /// A value held for the session's lifetime, for its `Drop` (it owns the
    /// sandbox files backing the running process's rootfs) and as the live view
    /// of the session's environment. Dropped after [`Self::Process`].
    type Guard: BoxGuard;

    /// Launches the session's shell, placing its host-address box in a
    /// classifier leaf named by `session_id` when this host has one.
    ///
    /// `guest` is the daemon's own posture — whether this daemon is a
    /// microVM's pid 1 — handed in per launch rather than read from
    /// [`crate::guest`] inside, because the launch decision it scopes (a
    /// guest refuses a host-address box it cannot place; a native host runs
    /// it unenforced) is exactly what a launcher test has to be able to pose.
    fn launch(
        self,
        guest: bool,
        session_id: boxes::SessionId,
        name: String,
        username: String,
        paths: BoxPaths,
        sz: WinSize,
    ) -> impl Future<Output = io::Result<Launched<Self::Process, Self::Guard>>> + Send;
}

/// Where a command should start in a session, and with what environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BoxEnvironment {
    /// Absolute path inside the sandbox: `/workbench` for a session.
    pub(crate) cwd: String,
    /// The composed session variables, layout defaults included, plus anything
    /// installed into the session since it launched.
    pub(crate) vars: BTreeMap<String, String>,
}

/// The launcher-owned value a [`Host`] holds for its session's lifetime.
///
/// Primarily a `Drop` guard — it owns the sandbox files backing the running
/// process's rootfs — but it is also the live handle to the session's
/// environment.
pub(crate) trait BoxGuard: Send + 'static {
    /// The working directory and environment a command should run with in this
    /// session, as of now.
    fn command_environment(&self) -> BoxEnvironment;
}

/// The mock launcher has no sandbox, so there is nothing to describe.
#[cfg(test)]
impl BoxGuard for () {
    fn command_environment(&self) -> BoxEnvironment {
        BoxEnvironment::default()
    }
}

impl BoxGuard for crate::env::Env {
    fn command_environment(&self) -> BoxEnvironment {
        crate::env::Env::command_environment(self)
    }
}

/// The product of [`BoxLauncher::launch`].
pub(crate) struct Launched<P, G> {
    /// Master side of the launched process's PTY; the slave is wired to the
    /// process. The [`Host`] reads its stdout and writes its stdin here.
    pub(super) master: OwnedFd,
    /// Handle used to wait on / signal the launched process.
    pub(super) process: P,
    /// Kept alive for the session; see [`BoxLauncher::Guard`].
    pub(super) guard: G,
    /// The per-sandbox network attachment (own-IP switch wiring), if any. Torn
    /// down explicitly via [`sandbox::NetGuard::teardown`] at session end.
    /// `None` for `HostNet`/`NoNet` and for the plain mock.
    pub(super) net_guard: Option<Box<dyn sandbox::NetGuard>>,
    /// Path of the session PTY's slave side, so hooks can open the
    /// terminal briefly rather than the host retaining a descriptor.
    pub(super) tty_path: std::path::PathBuf,
    /// Whether processes injected into this session are entering a none box,
    /// so the shim must reinstall the none plan's full socket-family seal;
    /// every other box's injected processes reinstall the confined-families
    /// seal the shim defaults to.  Every injection is sealed, since the
    /// filter is inherited only by children of the filtered process.
    pub(super) seal_injection: bool,
    /// The box's classifier leaf (NET-079): the cgroup its egress verdict is
    /// decided on, and the one every process of the session — injected ones
    /// included — is placed in. `None` on a host that places no box: the tree
    /// is absent, and while a native session then runs unenforced rather than
    /// refused on that ground, a guest's host-address launch is refused
    /// instead (design §7.1).
    pub(super) leaf: Option<sandbox::config::ClassifierLeaf>,
    /// What the launch decided about this box's egress verdict: enforced on
    /// a leaf of its own, or unenforced on a host that could not decide per
    /// box. Carried to the host's attributes so a session can say which it
    /// runs under — the launch's own decision, not a re-derivation.
    pub(super) host_ip_enforcement: Option<HostIpEnforcement>,
    /// The listen plan the launch gathered for the box it launched: the
    /// lease, the published address, the switch control channel, the gate
    /// and the publication set its watcher publishes through. `None` when
    /// the launch could build no plan — no lease, no published address or no
    /// live gate — and a mock launch that builds none starts no watcher at
    /// all. The plan rides here rather than a table between the two, so it
    /// is this launch's own from the moment it is built: it never survives
    /// to a spawn that did not gather it.
    pub(super) listen_plan: Option<crate::net::listeners::ListenPlan>,
    /// The gate holding the launched shell before it execs, on a launch
    /// minted only for lifecycle hooks (see [`SandboxLauncher::for_hooks`]):
    /// the box exists for the hooks to run in, while the shell — whose
    /// startup files are the user's — waits for the first attach. `None` on
    /// every other launch, whose shell starts at once.
    pub(super) start_gate: Option<sandbox::StartGate>,
}

/// Packages every session sandbox gets unconditionally, regardless of
/// the client's contribution: `base` for the shell, `coreutils` for
/// `ls`/`cat`/etc, and `socat` for the `min` command bridge (the
/// helper installed at `/usr/bin/min` speaks to `/run/minenv_sock`
/// via `socat`).
pub(super) const BASELINE_PACKAGES: &[&str] = &["base", "coreutils", "socat"];

/// Environment folded into a session shell at the launching attach, over and
/// above the composition. Both halves are captured from the SSH channel the
/// attach arrives on (see [`crate::box_actor::Session::attach`]).
///
/// The two halves sit on opposite sides of the composition in precedence:
/// `inherited` are defaults the composition may override, `connection` are
/// authoritative facts that override the composition.
///
/// `inherited` is a launch-time fact: it describes the client that *created*
/// the shell and cannot be revised without respawning it. `connection` is a
/// per-attach fact — see [`ConnectionEnv`] — carried on every attach, not just
/// the one that mints the host.
///
/// The fields are read only by the real [`SandboxLauncher`]; the mock launcher
/// ignores them, so tolerate them being unread under `test`.
#[derive(Debug, Default, Clone)]
#[cfg_attr(test, allow(dead_code))]
pub(crate) struct AttachEnv {
    /// Locale/timezone vars the client forwarded from its shell (`LANG`,
    /// `LC_*`, `TZ`) — OpenSSH's `AcceptEnv` set. Applied as defaults *below*
    /// the composition, so a loadout's explicit locale still wins.
    pub(crate) inherited: Vec<(String, String)>,
    /// Per-connection facts — `TERM` from the PTY request, plus the banner's
    /// detach hint the daemon derives from the channel's session keys. Applied
    /// *above* the composition, the way sshd sets `TERM`
    /// authoritatively regardless of shell dotfiles. (`SSH_TTY` and
    /// `SSH_CONNECTION`/`SSH_CLIENT` are deliberately not set: the session
    /// sandbox has no host `/dev/pts` and the Unix-socket transport has no peer
    /// address, so any value would name something that doesn't exist in-session.)
    pub(crate) connection: Vec<(String, String)>,
}

impl AttachEnv {
    /// The connection half as a map, for merging into a session environment.
    pub(crate) fn connection_env(&self) -> ConnectionEnv {
        self.connection.iter().cloned().collect()
    }

    /// Whether this attach declares a terminal (`TERM` from the PTY
    /// request). The detach hint the daemon seeds every attach with is not a
    /// terminal fact, so an empty-vs-non-empty map no longer answers this.
    pub(crate) fn declares_terminal(&self) -> bool {
        self.connection.iter().any(|(k, _)| k == "TERM")
    }
}

/// The facts that describe *the terminal currently attached*, as opposed to
/// the session's own composed environment: `TERM` from the PTY request, plus
/// the banner's detach hint derived from the channel's session keys, and
/// `MINIMAL_SESSION_NAME` when the session is renamed — republished so the
/// already-running shell picks up the new name at its next prompt.
///
/// Kept apart from [`AttachEnv`] because its lifetime is different. A session
/// shell is spawned once and lives across many attaches, so its `environ` is
/// frozen at launch — but `TERM` describes whichever terminal is on the other
/// end *now*, and a client attaching from a different terminal than the one
/// that minted the shell brings a different one. The host therefore keeps the
/// latest and republishes it on every attach ([`Host::publish_connection_env`])
/// rather than treating it as a launch-time constant.
pub(crate) type ConnectionEnv = std::collections::BTreeMap<String, String>;

/// Where the session home lives inside the sandbox.
///
/// Derived from the same `sandbox` constant the sandbox mounts it from
/// (`crate::env::HOME_ROOT` is the same value; this module cannot use that one
/// because `env` is `cfg(not(test))` and these paths are asserted under test).
pub(super) const SESSION_HOME_ROOT: &str = constcat::concat!("/", sandbox::SESSION_HOME);

/// Session-home-relative directory holding the per-attach environment files.
pub(super) const ATTACH_ENV_DIR_REL: &str = ".local/state/minimal";

/// POSIX-shell form of the per-attach environment, sourced by the baseline
/// [`BASELINE_PROMPT_COMMAND`] at every prompt.
pub(super) const ATTACH_ENV_SH_REL: &str = constcat::concat!(ATTACH_ENV_DIR_REL, "/attach-env.sh");

/// fish form of the same file, read by the fish hook the daemon installs into
/// the rootfs (`crate::env`). Written alongside the POSIX form because a
/// session's shell is whatever the user runs, not only the bash the daemon
/// spawns.
pub(super) const ATTACH_ENV_FISH_REL: &str =
    constcat::concat!(ATTACH_ENV_DIR_REL, "/attach-env.fish");

/// The same facts as data rather than as a script, for a shell that would
/// rather read them than evaluate them — nushell, today.
///
/// Nu cannot use either script form. `source` takes a *parse-time constant*
/// path, so it can't be pointed at `$env.MINIMAL_ATTACH_ENV_JSON`; and a
/// literal path that doesn't exist yet is a hard parse error, which would
/// break the shell outright on a session that has published nothing. Its
/// `load-env (open …)` reads this file instead, under a `path exists` guard.
/// JSON also sidesteps a third set of quoting rules — the escaping is the
/// serializer's problem, not this module's.
///
/// Every key here becomes an environment variable, so the file carries no
/// metadata (not even the "generated" banner the script forms have).
pub(super) const ATTACH_ENV_JSON_REL: &str =
    constcat::concat!(ATTACH_ENV_DIR_REL, "/attach-env.json");

/// In-sandbox absolute path of the POSIX per-attach environment file.
pub(crate) const ATTACH_ENV_SH: &str = constcat::concat!(SESSION_HOME_ROOT, "/", ATTACH_ENV_SH_REL);

/// In-sandbox absolute path of the fish per-attach environment file.
pub(crate) const ATTACH_ENV_FISH: &str =
    constcat::concat!(SESSION_HOME_ROOT, "/", ATTACH_ENV_FISH_REL);

/// In-sandbox absolute path of the JSON per-attach environment file.
pub(crate) const ATTACH_ENV_JSON: &str =
    constcat::concat!(SESSION_HOME_ROOT, "/", ATTACH_ENV_JSON_REL);

/// The baseline shell's per-prompt wiring, in two halves.
///
/// Trigger half of the launcher-baseline orientation banner: evaluates the
/// [`BASELINE_MOTD`] payload at the first interactive prompt, then unsets
/// both vars so the banner prints exactly once and never for
/// non-interactive commands. Identical to the MOTD recipe the built-in
/// `default` loadout ships and `docs/reference/loadouts.md` ("Vars in the
/// attach shell") documents.
///
/// It carries nothing but the banner. The per-attach environment is refreshed
/// by the shell hooks the daemon installs into the rootfs (`crate::env`),
/// deliberately not from here: this variable is composed, so a loadout
/// setting its own `PROMPT_COMMAND` would replace the refresh, and the MOTD
/// recipe above would `unset` it — neither of which a session's `TERM` may
/// depend on.
pub(super) const BASELINE_PROMPT_COMMAND: &str =
    r#"eval "$MINIMAL_MOTD"; unset PROMPT_COMMAND MINIMAL_MOTD"#;

/// Absolute workspace root inside a session sandbox, `/workbench` by
/// convention. Derived from the same [`sandbox::SESSION_DEFAULT_WD`] the
/// sandbox uses as the shell's initial cwd (sessions never set a
/// `working_name_override`), so [`BASELINE_MOTD`]'s blueprint test cannot
/// drift from where the workspace actually lives.
pub(super) const SESSION_WORKSPACE_ROOT: &str = constcat::concat!("/", sandbox::SESSION_DEFAULT_WD);

/// Payload half of the launcher-baseline orientation banner: a STATIC
/// template. The dynamic parts resolve in-shell at print time: the
/// template interpolates `$MINIMAL_SESSION_NAME` and `$MINIMAL_LOADOUTS`
/// (both seeded by [`session_baseline_env`] — the loadout list arrives
/// from the client as the composition's first-class orientation field,
/// never as a user var); each carries a `${VAR:-fallback}` so a missing
/// var still renders sanely. Whether the workspace holds a blueprint is a
/// SESSION-filesystem fact, so it is not interpolated from anywhere — the
/// template tests [`SESSION_WORKSPACE_ROOT`] directly (both mfile
/// layouts, `minimal.toml` and `.minimal/minimal.toml`) when it prints,
/// which stays correct across skipped uploads, an in-session `min init`,
/// and attaches from unrelated host directories. TTY-gated, plain text —
/// `NO_COLOR`-safe, no box drawing.
pub(super) const BASELINE_MOTD: &str = constcat::concat!(
    r#"[ -t 1 ] && { printf 'minimal · session %s · loadout %s\ndetach: %s' "${MINIMAL_SESSION_NAME:-unnamed}" "${MINIMAL_LOADOUTS:-none}" "${MINIMAL_DETACH_HINT:-ctrl-] then d}"; [ -f "#,
    SESSION_WORKSPACE_ROOT,
    r#"/minimal.toml ] || [ -f "#,
    SESSION_WORKSPACE_ROOT,
    r#"/.minimal/minimal.toml ] || printf ' · no minimal.toml here — min init to add one'; printf '\n'; }"#,
);

/// The launcher-baseline environment seeded beneath every other layer of
/// [`layer_session_env`]: the session's identity (`MINIMAL_SESSION_NAME`,
/// plus `MINIMAL_LOADOUTS` when the composition's first-class orientation
/// field carries a display list) and the once-only orientation banner
/// pair. ALL orientation env is seeded here, daemon-side, from typed
/// data — none of it rides the user var lane, so user vars and policy
/// can never collide with it. Sitting on the lowest layer means any
/// composed `PROMPT_COMMAND` — a user loadout's, or the built-in
/// default's — overrides the baseline banner cleanly, while the identity
/// vars stay available for that override to interpolate.
///
/// `loadouts_display` is `None` when the composition carries no display
/// list (a client that predates the orientation field, or no
/// composition at all): the var is then left unset so each template's
/// own `${MINIMAL_LOADOUTS:-…}` fallback renders — the baseline banner
/// falls back to `none`, the built-in default loadout's MOTD to
/// `default (built-in)`, each correct for the context it prints in.
pub(super) fn session_baseline_env(
    session_name: &str,
    loadouts_display: Option<&str>,
) -> Vec<(String, String)> {
    let mut env = vec![
        ("MINIMAL_SESSION_NAME".to_string(), session_name.to_string()),
        (
            "PROMPT_COMMAND".to_string(),
            BASELINE_PROMPT_COMMAND.to_string(),
        ),
        ("MINIMAL_MOTD".to_string(), BASELINE_MOTD.to_string()),
        // Where the host republishes the attached terminal's facts. Named
        // rather than hard-coded into the prompt command so a loadout that
        // replaces `PROMPT_COMMAND` (or starts another shell) can still find
        // the file; the fish form is offered for the same reason.
        ("MINIMAL_ATTACH_ENV".to_string(), ATTACH_ENV_SH.to_string()),
        (
            "MINIMAL_ATTACH_ENV_FISH".to_string(),
            ATTACH_ENV_FISH.to_string(),
        ),
        (
            "MINIMAL_ATTACH_ENV_JSON".to_string(),
            ATTACH_ENV_JSON.to_string(),
        ),
        // The POSIX fallback tier. `$ENV` is the only startup hook a plain
        // `sh`, dash, ash, or ksh offers, and unlike the other four shells
        // there is nothing in the rootfs they read on their own — so this one
        // has to travel as a variable. It names a daemon-owned file; the file
        // is what does the work.
        ("ENV".to_string(), crate::env::ATTACH_ENV_POSIX.to_string()),
    ];
    if let Some(display) = loadouts_display {
        env.push(("MINIMAL_LOADOUTS".to_string(), display.to_string()));
    }
    env
}

/// Layers a session shell's environment by precedence, lowest first: the
/// launcher `baseline` (session identity + orientation banner), the
/// client-forwarded `inherited` locale/timezone, then the `composition` vars
/// (which may override both lower layers), then the `connection` facts
/// (which override everything — sshd-style). Later inserts win on a shared key.
pub(super) fn layer_session_env(
    baseline: Vec<(String, String)>,
    inherited: Vec<(String, String)>,
    composition: Vec<(String, String)>,
    connection: Vec<(String, String)>,
) -> std::collections::HashMap<String, String> {
    let mut env = std::collections::HashMap::new();
    for (k, v) in baseline
        .into_iter()
        .chain(inherited)
        .chain(composition)
        .chain(connection)
    {
        env.insert(k, v);
    }
    env
}

/// The real [`BoxLauncher`]: evaluates a minimal context into a graph,
/// builds a sandboxed `/bin/bash`, and wires it to a freshly opened PTY.
pub(crate) struct SandboxLauncher {
    pub(crate) ctx: mctx::Context,
    /// Env captured from the SSH channel that mints this shell; see
    /// [`AttachEnv`].
    pub(crate) attach_env: AttachEnv,
    pub(crate) network_mode: NetworkMode,
    /// Shared per-host gvproxy switch. Used only for
    /// [`NetworkMode::OwnIp`] launches.
    pub(crate) net_switch: std::sync::Arc<tokio::sync::Mutex<crate::net::SwitchClient>>,
    /// The session's whole network policy — declared egress enforced by the
    /// switch relay's outbound leg (NET-062/063/064), static ingress port
    /// mappings applied on the switch once this `OwnIp` PTask attaches and
    /// inbound ports gated on its other leg, removed on exit. Unused by other
    /// network modes.
    pub(crate) policy: boxes::BoxPolicy,
    /// The proxy-routing-table handle the `OwnIp` lease is reported through
    /// on attach, so the box's `<name>.min.internal` route exists exactly
    /// while the box does (NET-001). Ignored by every other network mode.
    pub(crate) own_address: Option<crate::net::provider::OwnAddressReporter>,
    /// The addresses the VM host daemon handed this box's registration
    /// (T66), when it was registered: the switch address this `OwnIp` PTask
    /// attaches with instead of drawing one, and the published loopback
    /// address the host side names the box by. Ignored by every other
    /// network mode; `None` for a session the activating client did not
    /// register, which self-allocates on a native host and is refused on a
    /// VM host, where the in-VM daemon draws nothing (NET-138).
    pub(crate) box_addresses: Option<boxes::BoxAddresses>,
    /// Composition to merge into the launcher's baseline packages and
    /// vars. Patches and lifecycle hooks are ignored today.
    pub(crate) composition: Option<std::sync::Arc<boxes::core::compose::Composition>>,
    /// Weak handle back to the owning session actor, for  `min` commands
    /// (e.g. `min build`) to drive session side-ops.
    pub(crate) session: crate::box_actor::WeakBoxHandle,
    /// Whether this launch exists to run lifecycle hooks rather than to serve
    /// a person: minted by the session's hook path — activation at finalize,
    /// teardown at detach or destroy — headless, its pty read by nobody.
    ///
    /// The unenforced-placement advisory is a session surface, and a hook run
    /// is not a session start: its daemon-log record would count one hook run
    /// as one session start, and its banner would be written into a hook pty
    /// no one reads. So a hook launch emits neither form. This is *not* the
    /// launch phase (`LaunchPhase`): the destroy path's hook launch is
    /// `Attached` exactly like an attach's, and finalize's activation launch
    /// is `Activating` — only the caller that mints the launch knows what it
    /// is for, which is why it travels on the launcher.
    pub(crate) for_hooks: bool,
    /// The classifier tree this daemon places host-address boxes in: the
    /// one the privileged step installs natively, and the guest's own boot
    /// mounts for itself. A field of the launcher so the launch reads one
    /// root for its leaf, its probe and its reclaim — and so the
    /// unenforced-launch test can drive that whole path over a stand-in
    /// tree it built, which the real tree's kernel-only facts would
    /// otherwise make undrivable; production sets it from the same
    /// constant every path reads.
    pub(crate) classifier_root: std::path::PathBuf,
    /// The mount table this launch reads the classifier tree's facts over,
    /// as `/proc/self/mountinfo` spells it: `None` — every production path
    /// and the start-up check alike — reads the daemon's own, live. A field
    /// for the same reason [`Self::classifier_root`] is one: the two facts
    /// of one launch answer over one tree and one mount table, and a
    /// host's own mount table covers no stand-in tree, so a launch driven
    /// over one would read every fact as unconfined and never reach the
    /// placement it was driven to test. The field names which table
    /// answers, it never fabricates one — no client or box input reaches
    /// it, and production passes `None`.
    pub(crate) classifier_mountinfo: Option<String>,
    /// The box's runtime publications, built fresh for the spawn this
    /// launcher is about to run: the one set this launch's listen plan and
    /// the session actor's runtime expose path both read, so a port the
    /// one published is never bound by the other (NET-047's never-contend
    /// half, and the answer `min net expose` gets when the listener
    /// watcher published its port first).
    pub(crate) publications: crate::net::listeners::BoxPublications,
    /// The daemon's state directory, handed to this launch's listen plan:
    /// its watcher appends each listen it publishes to the audit log under
    /// it, the one the session's runtime expose path audits in (NET-046).
    pub(crate) state_dir: std::path::PathBuf,
}

/// Reaps a freshly-spawned sandbox process if the launch is abandoned
/// before the process is handed off to a [`Launched`].
///
/// A [`hakoniwa::Child`] does not terminate when dropped, so anything
/// that lets one go without killing it orphans the sandbox — a process
/// still holding the session's rootfs after the session it belonged to
/// is gone. The `Err` arms between the spawn and the handoff reap
/// explicitly; this is what catches the third way out, a **cancelled**
/// launch future. There is a real caller: a teardown transition bounds
/// its launch with a timeout (`box_actor::HOOK_LAUNCH_TIMEOUT`) and drops
/// this future when it expires, which without the guard would strand a
/// sandbox the destroy then tries to delete out from under.
///
/// Reaping is synchronous (`kill` + `wait` are not async), so unlike
/// [`sandbox::PlannedLaunch`] — which has to give a lease back, and spawns
/// that release — this needs no runtime to do its work in `Drop`.
pub(super) struct SpawnedProcessGuard {
    /// `None` once the process has been handed off — see
    /// [`Self::release`].
    process: Option<hakoniwa::Child>,
}

impl SpawnedProcessGuard {
    fn new(process: hakoniwa::Child) -> Self {
        Self {
            process: Some(process),
        }
    }

    /// Borrow the guarded process, for the post-spawn wiring that still
    /// needs it while the guard stays responsible for it.
    fn get_mut(&mut self) -> &mut hakoniwa::Child {
        self.process
            .as_mut()
            .expect("the process is taken only by `release`, which consumes the guard")
    }

    /// Hand the process off, disarming the guard.
    fn release(mut self) -> hakoniwa::Child {
        self.process
            .take()
            .expect("the process is taken only here, and this consumes the guard")
    }
}

impl Drop for SpawnedProcessGuard {
    fn drop(&mut self) {
        let Some(mut process) = self.process.take() else {
            return;
        };
        // `kill` and `wait` are independent: a process that already
        // exited fails the kill with `ESRCH` but still needs reaping.
        if let Err(e) = process.kill() {
            tracing::warn!(error = %e, "killing sandbox process after an abandoned launch");
        }
        if let Err(e) = process.wait() {
            tracing::warn!(error = %e, "reaping sandbox process after an abandoned launch");
        }
    }
}

/// The box's classifier leaf during its launch, removed if the launch is
/// abandoned before the leaf is handed off (NET-079).
///
/// The leaf is created before the spawn — the sandbox layer needs it to bind
/// the tree into the box and root the box's cgroup namespace at the leaf — so
/// every way out of [`SandboxLauncher::launch`] between that and the handoff
/// into [`Launched`] has to account for a leaf with no box in it: an `Err`
/// return
/// for a build that failed, and — the one no `return` covers — the future's
/// own `Drop`, which is what a teardown transition bounding its launch with
/// a timeout (`box_actor::HOOK_LAUNCH_TIMEOUT`) takes. This guard owns the
/// leaf until `release` hands it to the [`SandboxBackend`] that keeps it for
/// the session's lifetime.
///
/// Declared *before* the [`SpawnedProcessGuard`] it shares the launch with,
/// so an abandoned launch drops in the opposite order: the process is reaped
/// first and the leaf removed after, because a cgroup that still holds a
/// process refuses its removal.
pub(super) struct BoxLeafGuard {
    leaf: Option<sandbox::config::ClassifierLeaf>,
}

impl BoxLeafGuard {
    fn new(leaf: sandbox::config::ClassifierLeaf) -> Self {
        Self { leaf: Some(leaf) }
    }

    /// The leaf this guard owns, for the placement between the spawn and the
    /// handoff.
    fn get(&self) -> Option<&sandbox::config::ClassifierLeaf> {
        self.leaf.as_ref()
    }

    /// Hand the leaf off, disarming the guard.
    fn release(mut self) -> sandbox::config::ClassifierLeaf {
        self.leaf
            .take()
            .expect("the leaf is taken only here, and this consumes the guard")
    }
}

impl Drop for BoxLeafGuard {
    fn drop(&mut self) {
        let Some(leaf) = self.leaf.take() else {
            return;
        };
        // The same shape the session-end teardown's `Drop` uses: this leaf's
        // box was SIGKILLed and reaped by the [`SpawnedProcessGuard`] dropped
        // just before it (the guard is declared after this one, so the launch's
        // own drop order runs the process first), and a just-reaped box's
        // cgroup can refuse its `rmdir` (`EBUSY`) for a few milliseconds while
        // the kernel empties it. A single refusal would leak the leaf of an
        // abandoned launch — a hook launch that timed out past its spawn, most
        // notably — until the next same-id launch reclaimed it or the daemon
        // restarted, so the removal is retried briefly before it is warned
        // about.
        if let Err(e) = remove_box_leaf_patiently(leaf.dir(), DROP_LEAF_REMOVAL_ATTEMPTS, |_| {
            std::thread::sleep(DROP_LEAF_REMOVAL_PAUSE)
        }) {
            tracing::warn!(
                leaf = %leaf.dir().display(),
                error = %e,
                "removing the classifier leaf of an abandoned launch"
            );
        }
    }
}

/// The mount table a host-address launch answers over: the knob's when one
/// was set, the daemon's own, read live, when none was — the knob's `None`
/// is every production path ([`SandboxLauncher::classifier_mountinfo`]).
///
/// The distinction is not cosmetic. `None` handed through as "no table at
/// all" makes [`sandbox::classifier::tree_is_real`] say a real tree is not
/// real — it answers from the table — so a guest, whose own boot mounted the
/// `nsdelegate` cgroup2 the tree sits on, would refuse every host-address
/// box it launched as a broken image, while a native host without a tree
/// kept running boxes unenforced: the one table read here is what both
/// halves of the launch — the decision and the placement — answer over.
pub(super) fn launch_mountinfo(knob: Option<String>) -> Option<String> {
    knob.or_else(sandbox::classifier::own_mountinfo)
}

/// Reads the one line the box's pre-exec closure reported into the
/// sandbox's `/run`, and says what it means: which cover the box took over
/// the classifier tree the launch bound for its join, or the errno that
/// killed the closure before the program ran — the `127` the spawn then
/// reports, whose stderr is the session's own terminal and reaches no
/// daemon log without this file.
///
/// Polled rather than awaited, and the file is taken away only once the
/// box's fate is known: a `failed` line is written by the closure's own
/// exit path, so nothing follows it and the removal is owed then; a `cover`
/// line is written while the closure is still heading for its exec, and a
/// closure that covered and then died past that point replaces its line —
/// the removal before that would have dropped the `failed` line carrying
/// the `127`'s diagnosis into a file nobody reads, so the watch goes on
/// until the deadline even after a line was read. A report that never
/// appears is itself a finding — a box that could not say what it did still
/// ran — and it is warned, not debugged: a leaf-bearing box whose closure
/// could not write `/run` is exactly the state this channel exists to
/// catch. Runs off the launch's critical path (`crate::traced::spawn`ed), so
/// a session is never held up by what its box did in its first
/// milliseconds.
///
/// `watch` is how long the launch's own watch waits; [`CLOSURE_REPORT_WATCH`]
/// is the production one, and a test drives the same code with a shorter
/// one.
pub(super) async fn report_box_closure(
    report: std::path::PathBuf,
    session: String,
    watch: std::time::Duration,
) {
    let deadline = std::time::Instant::now() + watch;
    // The lines this closure has left so far, so a replacement or an
    // appended line is logged as the new finding it is rather than skipped
    // as a repeat — and a line already said is not said twice.
    let mut seen: Vec<String> = Vec::new();
    loop {
        match tokio::fs::read_to_string(&report).await {
            Ok(content) => {
                for line in content.lines().map(str::trim).filter(|l| !l.is_empty()) {
                    if seen.iter().any(|s| s == line) {
                        continue;
                    }
                    seen.push(line.to_string());
                    if say_closure_line(line, &session) {
                        // The box's fate is known: the closure died, and it
                        // died having said so. The daemon owes the tree one
                        // line per launch, not a file per session.
                        let _ = tokio::fs::remove_file(&report).await;
                        return;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(
                    session = %session,
                    error = %e,
                    "reading the box's closure report",
                );
                return;
            }
        }
        if std::time::Instant::now() > deadline {
            if seen.is_empty() {
                tracing::warn!(
                    session = %session,
                    report = %report.display(),
                    "the box's pre-exec closure wrote no report into its /run \
                     before the watch gave up: a leaf-bearing box that could not \
                     say what it did over its classifier tree is exactly the \
                     state this channel exists to catch — no line below names \
                     its cover or its errno",
                );
            }
            // The box's fate is known by the deadline either way: the closure
            // writes within its first milliseconds, so the watch's whole
            // window without a new line is a closure that execed — or one
            // that never got to write, which the warn above just said. The
            // removal is owed now, and the box's fate is the only thing that
            // ever owed it.
            let _ = tokio::fs::remove_file(&report).await;
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

/// How long a launch watches its box's closure report: the closure writes
/// within its first milliseconds, so three seconds without a line it has not
/// already read is a closure that has nothing more to say.
pub(super) const CLOSURE_REPORT_WATCH: std::time::Duration = std::time::Duration::from_secs(3);

/// Says what one line of the box's closure report means, and returns whether
/// the line settles the box's fate: `true` for a `failed` line, which the
/// closure writes on its way to `_exit(127)` and nothing follows; `false`
/// for a `cover` line, which it writes while still heading for its exec.
/// A cover line may carry a refused devpts remount after a `; `, since the
/// report holds one line; each part is said on its own.
pub(super) fn say_closure_line(line: &str, session: &str) -> bool {
    if let Some((cover, devpts)) = line.split_once("; ") {
        let settled = say_closure_line(cover, session);
        return say_closure_line(devpts, session) || settled;
    }
    if line == "cover cgroup2" {
        tracing::info!(
            session = %session,
            cover = "cgroup2",
            "the box covered its bound classifier tree with the design's \
             own cover: a read-only cgroup2 mount of its namespace root, \
             so its own limit is readable where a runtime looks and no \
             other cgroup is reachable",
        );
    } else if let Some(errno) = line.strip_prefix("cover tmpfs-fallback errno ") {
        tracing::warn!(
            session = %session,
            cover = "tmpfs-fallback",
            mount_errno = errno,
            "the box's classifier cover fell back to an empty read-only \
             tmpfs: the kernel refused the design's cgroup2 mount of the \
             box's namespace root in its user namespace, so the box has \
             no cgroup path to write a migration to, but none to read a \
             limit from either — a recorded fallback, never the design's \
             cover",
        );
    } else if line == "cover tmpfs-fallback forced" {
        tracing::warn!(
            session = %session,
            cover = "tmpfs-fallback",
            "the box's classifier cover was forced onto its recorded \
             fallback — a launch in a test posture, never a production one",
        );
    } else if let Some(rest) = line.strip_prefix("devpts max=") {
        let (max, errno) = rest.rsplit_once(" errno ").unwrap_or((rest, "unreported"));
        tracing::warn!(
            session = %session,
            max,
            errno,
            "remounting the box's /dev/pts with a per-instance max failed; \
             the box runs on the shared PTY pool",
        );
    } else if let Some(errno) = line.strip_prefix("lo-down errno ") {
        tracing::warn!(
            session = %session,
            errno = errno,
            "the box could not bring up the loopback interface of its own \
             network namespace: it runs, but nothing in it can reach \
             127.0.0.1 or ::1",
        );
    } else if let Some(failed) = line.strip_prefix("failed ") {
        let (step, errno) = failed
            .rsplit_once(" errno ")
            .unwrap_or((failed, "unreported"));
        tracing::error!(
            session = %session,
            step = %step,
            errno = %errno,
            "the box's pre-exec closure died before its program ran: the \
             spawn reports this as exit 127, and this line is the only \
             place a daemon log ever sees which step and which errno",
        );
        return true;
    } else {
        tracing::warn!(
            session = %session,
            report = %line,
            "the box's pre-exec closure reported a line this daemon does \
             not read",
        );
    }
    false
}

impl BoxLauncher for SandboxLauncher {
    type Process = SandboxProcess;
    // The session env, kept alive for the session's lifetime (it owns the
    // sandbox files backing the running process's rootfs). The own-IP switch
    // attachment, when present, travels separately as `Launched::net_guard` and
    // is torn down explicitly at session end.
    type Guard = crate::env::Env;

    async fn launch(
        self,
        guest: bool,
        session_id: boxes::SessionId,
        name: String,
        username: String,
        paths: BoxPaths,
        sz: WinSize,
    ) -> io::Result<Launched<SandboxProcess, Self::Guard>> {
        let ctx = self.ctx;
        // Move the session policy out of `self` up front so it can be applied
        // after the switch attach below (the rest of `self` is consumed first).
        let policy = self.policy;
        // NET-079: the cohort subtree this box's declaration places its leaf
        // in, decided from the declaration before anything is reserved and
        // before its first process exists — the same verdict the plan below
        // resolves a deny-all box through, and the one the placement's own
        // leaf is named by. The declaration is fixed at create, so a launch
        // decides it once and a box is never re-verdicted mid-flight.
        let classifier_verdict = crate::net::classifier::verdict_of(policy.egress.as_ref());
        // Whether the declaration lets a listen publish at all (NET-016):
        // `allow` with a range. Read now, before the policy moves into the
        // network plan, for the missing-listen-plan line below.
        let listens_can_publish = policy.ingress.as_ref().is_some_and(|ingress| {
            ingress.dynamic_ingress == Some(boxes::DynamicIngress::Allow)
                && ingress.dynamic_allowed_range.is_some()
        });
        let network_mode = self.network_mode;
        // The classifier tree this daemon places boxes in, moved out before
        // the rest of `self` is consumed (see the field's doc).
        let classifier_root = self.classifier_root;
        // The mount table the launch's classifier facts answer over, moved
        // out with it (see the field's doc).
        let classifier_mountinfo = self.classifier_mountinfo;
        let net_switch = self.net_switch;
        let own_address = self.own_address;
        let box_addresses = self.box_addresses;
        // The session name, registered as this PTask's `*.min.internal` hostname on
        // an own-IP attach (finding #3 / UC6); cloned because `name` is consumed by
        // the sandbox env below.
        let session_name = name.clone();
        let composition = self.composition;
        let attach_env = self.attach_env;
        let session = self.session;
        // What this launch is for, decided by the caller that minted it (see
        // [`SandboxLauncher::for_hooks`]): it gates the advisory below, never
        // the placement itself — a hook launch's box is placed like any
        // other's, or runs unenforced like any other's; only the advice is
        // for the session's audience.
        let for_hooks = self.for_hooks;
        // `graph_from_all_packages` is CPU-heavy (nickel evaluation,
        // graph construction) — run it on the blocking pool so it
        // doesn't stall the async executor.
        let (ctx, graph_result) = crate::traced::spawn_blocking(move || {
            let mut ctx = ctx;
            let r = ctx.graph_from_all_packages().map_err(|e| e.to_string());
            (ctx, r)
        })
        .await
        .map_err(io::Error::other)?;
        let graph = graph_result.map_err(io::Error::other)?;

        // NET-079: the classifier leaf this host-address box's egress verdict
        // is decided on, decided *before anything is reserved* and before its
        // first process exists. Scoped to the host-address box, the one that
        // speaks with an address it did not lease: a none box has no traffic
        // to decide and an own-IP box's verdict is its own, on the address
        // it holds. The decision fails closed for the launch — a tree that
        // is absent, or a daemon that cannot place a process in it, leaves
        // the box unenforced rather than refused natively — and never reaches
        // the box's own pre-exec closure, which is where an unplaceable join
        // would die taking the leaf it cannot take. The guard owns the leaf
        // until the handoff into `Launched`, so a launch abandoned anywhere
        // in between leaves no leaf behind, and it drops after the process
        // guard below so the box's processes are gone before their leaf is
        // removed.
        //
        // Whether this host can decide per box is read fresh, per launch,
        // from the table's *effect* (design §7.4) — the start reading is not
        // kept, because a marker survives whatever emptied the table and the
        // refusal does not, and a start reading would survive it the same
        // way. The probe binds a listener, forks a child, and waits, so it
        // runs on the blocking pool, and only a host-address launch reads
        // one: no other mode has a verdict the cgroup decides, and the one
        // over the same `classifier_root` the box is placed into, so both
        // halves of this launch answer over one tree and one mount table.
        // The whole decision is kept, not only its verdict bit: the refusal
        // and the advice below say which box they are for out of the cause
        // that produced it, so the launch's words and the start-up line
        // name the same ground. The read itself is the one shared fact
        // every host-address path answers over — [`re_read_classifier_fact`],
        // the same read the create response answers over — and the knob's
        // `None` — every production path — is the daemon's own mount table
        // read live inside it, never "no table at all": a launch that
        // answered over no table would read even a guest's `nsdelegate`
        // cgroup2 as not real and refuse every host-address box in it as a
        // broken image, so the live read and the decision share that one
        // blocking hop, and the same one table is what the placement below
        // answers over too.
        let (leaf, decision) = if matches!(network_mode, NetworkMode::HostNet) {
            let (mountinfo, decision) = re_read_classifier_fact(
                classifier_root.clone(),
                classifier_mountinfo.clone(),
                guest,
            )
            .await?;
            // NET-079: the other half of what a host that decides per box
            // refuses — the declaration's own rules. The create path refuses
            // the same declaration over the same predicate while the fact
            // says the host decides, but a box created before that was true —
            // a create the fact read `none` on, or a record persisted before
            // this gate existed — still lands here, and the launch is the
            // last place that can refuse it before the box runs placed and
            // looking decided while its rules go unenforced. Gated on the
            // decision this launch has just re-read, not the node fact: the
            // fact is what a display shows, the launch's own fresh read is
            // what refuses a box. Refused *before* the leaf below is
            // allocated — a box this launch refuses to run never lands in
            // `boxes/allow` — and whatever the launch is for: a hook run of
            // the same box would run the same rules unenforced, so it is
            // refused on the same ground as any other launch. On a host that
            // cannot decide per box the gate answers nothing — NET-079's
            // exception is that host's to keep, and the refusal below is the
            // other one's.
            if let Some(rules) = crate::net::classifier::refuses_unenforceable_declaration(
                network_mode,
                decision.can_decide_per_box(),
                policy.egress.as_ref(),
            ) {
                // The one typed error the create returns over the same
                // rules: `InvalidInput`, not an `other` failure, so the
                // refusal is the same machine-mode failure wherever a
                // client meets it — the create's RPC arm keys on this
                // kind, and the kind is what an `io::Error` carries to
                // whatever downstream reads it. A launch hits the boxes
                // the create's gate never saw — created before the host
                // could decide per box, persisted from before the gate
                // existed — so the two refusals must not read as two
                // different failures of the same declaration.
                let refusal = crate::net::classifier::unenforceable_declaration_refusal(&rules);
                tracing::info!(
                    session = %session_name,
                    network_mode = %network_mode.word(),
                    host_ip_enforcement = %HostIpEnforcement::PerBox.machine_str(),
                    refusal = %refusal,
                    "refusing a host-address box whose declaration names rules \
                     this host's classifier cannot enforce"
                );
                return Err(refusal);
            }
            let leaf = create_session_leaf(
                &classifier_root,
                mountinfo.as_deref(),
                guest,
                &session_id,
                &session_name,
                classifier_verdict,
                decision.can_decide_per_box(),
            )
            .await?;
            (leaf, Some(decision))
        } else {
            (None, None)
        };
        let mut leaf_guard = leaf.clone().map(BoxLeafGuard::new);

        // What this launch's placement means for the box's egress record:
        // the leaf itself, never the node fact re-read beside it — the
        // record is this box's own launch outcome, and the reads lower it by
        // the fact (`displayed_host_ip_enforcement`), so a leaf placed over
        // a table that is not refusing shows `none` while the host cannot
        // decide and `per_box` once it can again, without a relaunch. The
        // declaration is the placement's other half: a box whose rules the
        // classifier cannot enforce is recorded `none` even placed, so the
        // record never promises `per_box` for rules no verdict enforces.
        // The refusal and the advice below read the one decision.
        let enforcement = host_ip_enforcement(network_mode, leaf.as_ref(), policy.egress.as_ref());

        // A host-address box this host cannot give a verdict of its own is
        // refused where the box's own declaration is the thing that cannot
        // be honoured — never for a state a person could still fix from the
        // host itself. In the guest that is every state: the tree and the
        // table were the image's own boot's work, and there is no installer
        // to run inside a microVM (design §7.1) — a box that cannot be
        // placed has no leaf to decide on at all, and a deny-all box whose
        // table is not loaded would run placed while nothing refuses its
        // connections, a verdict that looks decided and is not. The first
        // refusal names the broken image it is; the second names the
        // interim, guest-side classifier enforcement not being available
        // yet. Natively the same states keep NET-079's exception — the box
        // runs unenforced and the log says so — except the one state where
        // the step's own install is standing behind a refusal that is not
        // in force: a deny-all box placed on either probe cause, refused
        // rather than run on a refusal nothing here is making. A refused
        // box never reaches the advisory below — the refusal is the only
        // thing that launch says; the advisory is for the host-address
        // boxes that run, the ones a verdict has nothing to enforce in
        // yet.
        if let Some(refusal) = refused_unenforced_host_address_box(
            guest,
            network_mode,
            classifier_verdict,
            leaf.is_some(),
            decision.as_ref(),
        ) {
            tracing::error!(
                session = %session_name,
                network_mode = %network_mode.word(),
                tree = %classifier_root.display(),
                placed = leaf.is_some(),
                refusal = %refusal,
                "refusing a host-address box this host cannot decide an \
                 egress verdict for"
            );
            return Err(io::Error::other(refusal));
        }

        // The advisory for that same state, on either kind of host, as a
        // diagnostic record per launch — on the daemon's log stream, and
        // nowhere else. This is not the session's stderr channel and not a
        // field any client reads: the session reply and the CLI's start
        // output are untouched by it, so a scripted `min session start`
        // never sees this line. What a person in a session gets is the
        // banner below, written onto the session's own pty — that banner is
        // the in-session surface, and this record is its daemon-log twin,
        // attributed to the session and carrying the decision in the
        // machine spelling a reader greps for (`host_ip_enforcement`).
        // Carrying the field out to a client — over the session reply, and
        // surfaced by `min doctor` — is issue #1773, outside this task's
        // layers.
        //
        // At the placement decision, not after the build: a launch that goes
        // no further than this (a tree-less host, an env that fails to
        // build) has still been told apart, and every launch is — the
        // resolver-hook advisory this is modelled on (NET-122, design §7.1)
        // advises on every session start, the install hint it carries is the
        // answer to a host without the tree, and silencing every launch
        // after the first takes the notice away from exactly the session a
        // person is about to work in. In the guest the hint is not what the
        // state means — there is no installer to run there — so the notice
        // is the interim's own words, and the session that just started is
        // told at its own start, both here in the daemon's log and in the
        // pty banner below, never per daemon and never for a hook run.
        //
        // A launch minted for lifecycle hooks advises on neither surface: a
        // hook run is not a session start, and its record would count one
        // hook run as one. The placement itself is not gated with it.
        let advise = advises_unenforced_placement(network_mode, leaf.as_ref(), decision.as_ref())
            && !for_hooks;
        if advise {
            let notice = unenforced_placement_notice(guest, leaf.as_ref());
            tracing::info!(
                session = %session_name,
                host_ip_enforcement = %HostIpEnforcement::None.machine_str(),
                notice = %notice,
                "the session's host-address box runs unenforced on this host",
            );
        }
        // The banner is the advisory's in-box surface, and follows the
        // advisory's rule (NET-079): a native daemon only — per-box
        // enforcement is a native-host fact, and the guest's state is the
        // interim's, said in the record above — only while the box declares
        // egress, because a box that declared nothing asked for no
        // enforcement, and only over a decision that names a cause: a box
        // nothing placed on a host that decides per box runs unenforced for
        // a reason the record above names (the placement's own failure),
        // not one an install or an own-address start ends, so the advisory
        // would hand out a command that changes nothing. Its text is the
        // create reply's own, which carries none without a cause either, so
        // the terminal the start printed into and the shell it opens say the
        // same thing.
        let banner = match (
            advise && !guest,
            policy.egress.as_ref(),
            decision
                .as_ref()
                .and_then(crate::net::classifier::Decision::cause),
        ) {
            (true, Some(egress), Some(cause)) => {
                Some(crate::net::classifier::advisory_text(cause, egress))
            }
            _ => None,
        };

        // Step 1 (pre-spawn): the provider for this PTask's mode reserves what
        // the sandbox needs — for own-IP, a lease and a running gvproxy — and
        // says what it is. The decision this launch itself read above goes in
        // with them, carried rather than memoized, so the plan below follows
        // this launch's verdict fact and never a concurrent launch's.
        // `PlannedLaunch` owns the release from here: an early `Err` return
        // or a cancelled launch gives the lease back.
        let planned = sandbox::PlannedLaunch::begin(crate::net::provider::network_for(
            network_mode,
            &net_switch,
            &session_name,
            Some(policy),
            own_address.clone(),
            box_addresses,
            decision,
        ))
        .await
        .map_err(|e| io::Error::other(format!("planning the session network: {e}")))?;

        // The none plan's full seal is the one an injected process has to be
        // told about explicitly (`--seal-none-box`); every other box's
        // confined-families seal is the shim's default. Derived from the plan
        // itself — the same data `new_container` seals the box from — so
        // launch and injection agree by construction.
        let seal_injection = planned.plan().seal() == sandbox::SocketSeal::Full;

        // Package + env-var union of the launcher baseline and every
        // contribution the composer collected. Packages: baseline set
        // (required for a usable interactive shell) unioned with
        // everything the composition asks for, dedup-preserving-order
        // so the base packages install first. Env vars: the
        // composition's over a small launcher baseline — the session's
        // identity (`MINIMAL_SESSION_NAME`) and the once-only
        // orientation banner pair (see [`session_baseline_env`]) —
        // while `sandbox` sets the session defaults (`PS1`, `PATH`,
        // `HOME`, `LANG`, …) which these vars then override on a
        // shared key.
        //
        // Baseline is intentionally minimal: `base` for the shell,
        // `coreutils` for `ls`/`cat`/etc, and `socat` for the
        // in-sandbox `min` helper's UDS relay to the daemon. `bash`
        // is unconditionally added as a helper dep by
        // `crate::env::Env::build`, so listing it here would just
        // duplicate the entry — `socat` is added there too but is
        // named explicitly so the baseline reads as self-contained.
        //
        // Both maps carry only resolved values, so the composition-
        // vars merge doesn't need `EnvVarValue::Value(...)` at
        // each insert: `EnvArgs::with_resolved_env_vars` wraps once
        // at the boundary. Composition patches and lifecycle hooks
        // are not applied yet (the file-upload path and in-sandbox
        // exec plumbing that they need aren't wired), so they pass
        // through this stage untouched.
        // A shadow set tracks membership so the composition-union
        // pass below stays O(n) instead of the naive
        // `Vec::contains` per iteration (see clippy's O(n²) hint).
        // Two `String` allocs per baseline entry (one for the vec,
        // one for the set) — intrinsic given both need owned
        // strings and `String::clone` is a deep copy. Trivial cost
        // for a three-element baseline.
        let mut packages: Vec<String> =
            BASELINE_PACKAGES.iter().map(|s| (*s).to_string()).collect();
        let mut package_set: std::collections::HashSet<String> =
            BASELINE_PACKAGES.iter().map(|s| (*s).to_string()).collect();
        if let Some(comp) = &composition {
            for p in comp.packages() {
                let name = p.package();
                if package_set.insert(name.to_string()) {
                    packages.push(name.to_string());
                }
            }
        }
        // Env vars, layered by precedence (see [`layer_session_env`]): the
        // launcher baseline and the client-forwarded locale/timezone sit
        // below the composition, and the per-connection facts (`TERM`) sit
        // above it.
        let composition_vars: Vec<(String, String)> = composition
            .as_ref()
            .map(|c| {
                c.vars()
                    .iter()
                    .map(|v| (v.var().name().to_string(), v.var().value().to_string()))
                    .collect()
            })
            .unwrap_or_default();
        // The banner's loadout list arrives as the composition's
        // first-class orientation field; empty means "unknown" (an old
        // client) and seeds nothing — the template's `${…:-}` fallback
        // renders instead.
        let loadouts_display = composition
            .as_ref()
            .map(|c| c.orientation().loadouts_display.as_str())
            .filter(|d| !d.is_empty());
        let env_vars = layer_session_env(
            session_baseline_env(&name, loadouts_display),
            attach_env.inherited,
            composition_vars,
            attach_env.connection,
        );
        // Which shell this attach starts is decided from the composed
        // `SHELL` (see `crate::attach_shell`). Read before `env_vars`
        // moves into the env build; the rootfs it has to be checked
        // against doesn't exist until that build has run.
        let requested_shell = env_vars.get("SHELL").cloned();
        // Whether anything composed a prompt. `sandbox` sets a
        // bash-syntax `PS1` as the session default, which a shell that
        // doesn't speak those escapes prints literally — so a non-bash
        // shell gets its own (see `ShellChoice::prompt`), but only when
        // the user hasn't asked for a specific prompt themselves.
        let composed_prompt = env_vars.contains_key("PS1");
        // For the log line on the fallback path, which fires after
        // `name` has moved into `EnvArgs`.
        let session_label = name.clone();
        // Log every item that will (or would) end up in the session,
        // tagged with its provenance. Patches and lifecycle hooks are
        // included even though the launcher can't act on them yet —
        // an operator inspecting logs should see the intent.
        log_session_contents(&name, BASELINE_PACKAGES, composition.as_deref());

        // Build the env + container and spawn the process. Any failure here
        // leaves no process to reap; `planned` releases its lease on the `Err`
        // return. `planned` outlives the block, so the plan is cloned out.
        let plan = planned.plan().clone();
        let build_and_spawn = async {
            // The env owns the context, graph and the sandbox files backing the
            // running process's rootfs, so it is `Send + 'static` and can be moved
            // into the host as the guard that keeps those files alive.
            // Boxed: inlined, this reaches the cache fetchers' client stack and
            // the launch future's layout overruns rustc's query depth (128).
            let mut env_args =
                crate::env::EnvArgs::new(name, paths.working, paths.home, paths.cache, session)
                    .with_session_id(session_id)
                    .with_packages(packages)
                    .with_resolved_env_vars(env_vars)
                    // Session envs source package attrs (env_state_wiring,
                    // env_dir/file_mappings) exclusively through the
                    // composer so they're subject to user policy. Task-run
                    // uses a different `Env::build` (mctx::env::Env) and
                    // keeps the legacy un-gated wiring for now.
                    .without_package_attr_wiring()
                    .with_network(plan.clone())
                    .with_username(username);
            // NET-079: the leaf created before this build, so the sandbox
            // binds the tree into the box, joins the box's own first process
            // to the leaf in its pre-exec closure, and names the leaf it
            // entered on its launch log line. The guard keeps the leaf for the
            // launch's duration; this copy travels into the config.
            if let Some(leaf) = leaf_guard.as_ref().and_then(BoxLeafGuard::get).cloned() {
                env_args = env_args.with_classifier_leaf(leaf);
            }
            let mut env = Box::pin(crate::env::Env::build(ctx, graph, env_args)).await?;

            let mut container = env
                .container(&plan)
                .map_err(|e| io::Error::other(format!("container build: {e}")))?;
            container.set_session_leader();
            // A launch minted only for hooks holds its shell at the gate: the
            // hooks need the box, not the shell, and the shell's startup —
            // the user's rc files and prompt commands — must not run ahead of
            // the activate hooks it may depend on. The first attach releases
            // it (see [`Host::attach`]).
            let start_gate = if for_hooks {
                Some(
                    env.hold_start(&mut container)
                        .map_err(|e| io::Error::other(format!("start gate: {e}")))?,
                )
            } else {
                None
            };

            let pty = Pty::open(sz).map_err(|e| io::Error::other(format!("pty open: {e}")))?;

            // NET-079: a host-address box this launch runs unenforced gets
            // the advisory in the terminal itself — this banner is the
            // in-session surface, the prose a person at the terminal reads;
            // the record for that same decision went to the daemon's log at
            // the placement decision, which no client reads (issue #1773
            // tracks carrying it out). The person about to type in this
            // session is the one whose egress is not being decided, and the
            // state is the deployment's, not the session's, so the notice
            // says what would change it. A guest's *refused* box never gets
            // this far, its launch being refused (design §7.1) — but the
            // guest's other host-address boxes do, and say the interim's
            // words: a session started in a VM host that does not enforce
            // per box yet is told so at its own start, like any host's.
            // And never on a hook launch: its
            // pty is read by nobody, and a hook run is not a session start.
            if let Some(notice) = &banner {
                // The same write the shell fallback notice uses, for the
                // same reasons: onto the pty's slave, best-effort, CRLF on
                // each of the advisory's two lines — see the comment there.
                let text = notice
                    .lines()
                    .map(|line| format!("minimal: {line}\r\n"))
                    .collect::<String>();
                let written = pty.dup_slave_fd().and_then(|fd| {
                    use std::io::Write as _;
                    std::fs::File::from(fd).write_all(text.as_bytes())
                });
                if let Err(e) = written {
                    tracing::debug!(
                        error = %e,
                        "could not print the placement notice to the terminal"
                    );
                }
            }
            // The shell, and the argv it needs to reach the daemon's
            // per-attach environment hook. Every program path here is
            // absolute (`/usr/bin/<shell>`): packages install with
            // `--prefix=/usr` and the generic rootfs has no `/bin`, so a
            // bare name or a `/bin/…` path would fail with ENOENT.
            let shell = crate::attach_shell::resolve(requested_shell.as_deref(), &env.rootfs());
            if let Some(notice) = &shell.fallback {
                tracing::warn!(
                    session = %session_label,
                    requested = requested_shell.as_deref().unwrap_or_default(),
                    "{notice}",
                );
                // Onto the pty's *slave* — that is the shell's stdout, so
                // the line reaches the attached terminal ahead of the
                // first prompt. Writing to the master would feed it to
                // the shell as input instead. Best-effort: a session that
                // comes up must not fail over a notice, and the log above
                // has already recorded it. CRLF because this is a raw
                // terminal write, not a line through the shell.
                let written = pty.dup_slave_fd().and_then(|fd| {
                    use std::io::Write as _;
                    std::fs::File::from(fd).write_all(format!("minimal: {notice}\r\n").as_bytes())
                });
                if let Err(e) = written {
                    tracing::debug!(error = %e, "could not print the shell notice to the terminal");
                }
            }
            let mut command = env
                .command(&container, &shell.program, shell.args.iter().copied())
                .map_err(|e| io::Error::other(format!("build command: {e}")))?;
            // Name the shell that is actually running. The composed
            // value is a path on the machine the loadout was authored on
            // (`/opt/homebrew/bin/fish`), which resolves to nothing
            // in-session, and on the fallback path it names a shell that
            // isn't the one at this prompt.
            command.env("SHELL", &shell.program);
            // The session default `PS1` is bash's, so a shell with its
            // own prompt grammar needs the equivalent in that grammar —
            // handed the bash one, zsh renders `\[\033[…\]\u@\h` as
            // literal text. Skipped when the composition set `PS1`: that
            // is the user's own prompt, in whatever syntax they meant.
            if let Some(prompt) = shell.prompt
                && !composed_prompt
            {
                command.env("PS1", prompt);
            }
            command.stdin(hakoniwa::Stdio::from(pty.dup_slave_fd()?));
            command.stdout(hakoniwa::Stdio::from(pty.dup_slave_fd()?));
            let tty_path = pty.slave_path().to_path_buf();
            // Kept for one notice written after the switch attach below (an
            // own-address box the hostname proxy stranded), so it is said in
            // the terminal, not only in the daemon's log. Never for a hook
            // launch: its pty is read by nobody. Dropped before the launch
            // returns, so it never outlives the shell's own slave fds.
            let late_notice_fd = (matches!(network_mode, NetworkMode::OwnIp) && !for_hooks)
                .then(|| pty.dup_slave_fd().ok())
                .flatten();
            let (master, slave) = pty.into_fds();
            command.stderr(hakoniwa::Stdio::from(slave));

            // On the fork thread, never this one: the container dies with
            // the thread that forked it (see `sandbox::forker`).
            let process = sandbox::forker::on_fork_thread(move || command.spawn())
                .map_err(|e| io::Error::other(format!("exec failed: {e}")))?;
            // `command`/`container` no longer borrow `env`, so it can be moved
            // into the host to keep its backing files alive.
            drop(container);
            Ok::<_, io::Error>((env, master, process, tty_path, late_notice_fd, start_gate))
        }
        .await;

        let (env, master, process, tty_path, late_notice_fd, start_gate) = match build_and_spawn {
            Ok(parts) => parts,
            Err(e) => return Err(e),
        };

        // From here the process exists, so every way out of this function
        // has to account for it — including the one no `return` covers, a
        // cancelled future. `SpawnedProcessGuard` owns it until the
        // handoff at the bottom; an `Err` return or a drop reaps it.
        let mut process = SpawnedProcessGuard::new(process);

        // The box's closure report, read off the launch's critical path: the
        // cover it took over its bound classifier tree — the design's
        // read-only cgroup2 mount of its namespace root, or the recorded
        // tmpfs fallback with the errno that forced it — or the errno that
        // killed the pre-exec closure before the program ran, which is the
        // one place a `127` ever reaches a daemon log. Nothing in the session
        // waits on it; the session is up while this reads.
        if let Some(leaf) = leaf.as_ref() {
            let report = env.closure_report_path(leaf);
            let session = session_label.clone();
            crate::traced::spawn(async move {
                report_box_closure(report, session, CLOSURE_REPORT_WATCH).await
            });
        }

        // NET-079: the box's supervisor is moved into its leaf right after the
        // spawn, from the daemon's own namespaces where the leaf is
        // reachable — the same place the shim later writes an injected
        // process. The program placed itself already, in the pre-exec closure
        // it ran inside the box, before it unshared the cgroup namespace onto
        // the leaf; the supervisor is the one process that never ran that
        // closure. Never fatal: a supervisor the host could not place runs in
        // the daemon's leaf, at the cost of being classified as the daemon
        // rather than its box.
        if let Some(leaf) = leaf_guard.as_ref().and_then(BoxLeafGuard::get) {
            let supervisor = process.get_mut().id();
            match place_box_processes(leaf, supervisor) {
                Ok(()) => tracing::info!(
                    session = %session_label,
                    leaf = %leaf.dir().display(),
                    supervisor,
                    "placed the session's box in its classifier leaf: the \
                     supervisor here, the program in its own pre-exec closure",
                ),
                Err(e) => tracing::warn!(
                    session = %session_label,
                    leaf = %leaf.dir().display(),
                    error = %e,
                    "placing the session's supervisor in its classifier leaf",
                ),
            }
        }

        // Step 3 (post-spawn): hand the process to the provider, which wires its
        // namespace onto the switch; a tap the sandbox layer built travels here
        // inside `Spawned`.
        //
        // Until this returns, an own-IP PTask's egress isn't up yet, but a shell
        // PTask never probes the network in this window (the SSH layer dispatches
        // commands only after `Launched` is returned).
        let net_guard: Option<Box<dyn sandbox::NetGuard>> = {
            let spawned = sandbox::Spawned::from_child(process.get_mut());
            match planned.attach(spawned).await {
                // The guard owns the release now; it detaches at session end.
                Ok(guard) => Some(guard),
                // The release stays with `planned`, which drops on this return.
                Err(e) => return Err(io::Error::other(e)),
            }
        };

        // Step 4 (post-attach): gather the listen-publication plan (NET-016,
        // NET-017) — everything the box's listener watcher needs, from what
        // this launch alone holds: the box's lease on the switch, the gvproxy
        // control channel its forwarder verbs ride (built the way the
        // provider's own-IP plan builds it), the published address the
        // switch granted this session (NET-010), the ingress gate the
        // attach just registered for the relay, and the box's publication
        // set, shared with the runtime expose surface so neither binds a
        // port the other already holds. The plan rides [`Launched`] to the
        // host that runs the box, which starts the watcher when it builds
        // and stops it with the session — so a box with no lease, no
        // published address or no live gate carries no plan, and its ports
        // stay unpublishable by listening.
        //
        // Read here, after `planned.attach` above returned: a successful
        // attach has already reported this spawn's lease
        // (`complete_own_ip_attach` reports it before it returns `Ok`), and
        // every launch — a respawn included — runs this step afresh, so the
        // lease the plan carries is always this spawn's own.
        let lease = crate::net::provider::attached_lease(&plan, own_address.as_ref());
        let published = own_address
            .as_ref()
            .and_then(|reporter| reporter.published_address());
        let gate = lease.and_then(crate::net::switch::live_gate);
        // Design §7.1: a box that attached while the hostname proxy was not
        // serving past the settle was compiled with no node-address opening
        // (fail closed rather than at a port the proxy may not hold), so it
        // cannot reach the hostname proxy until it restarts. Said in the
        // session's own terminal — the person whose `HTTP(S)_PROXY` requests
        // will not route is told why and what clears it — beside the
        // daemon's warning. Best-effort, like the banner notices above.
        if let (Some(fd), Some(lease)) = (late_notice_fd, lease)
            && net_switch.lock().await.hostname_proxy_stranded(lease)
        {
            use std::io::Write as _;
            let written = std::fs::File::from(fd).write_all(
                b"minimal: the hostname proxy was not serving yet when this session's \
                  box attached, so the box cannot reach it (*.min.internal requests \
                  through HTTP(S)_PROXY will not route); restart the session once the \
                  daemon's hostname proxy serves\r\n",
            );
            if let Err(e) = written {
                tracing::debug!(
                    error = %e,
                    "could not print the hostname-proxy notice to the terminal"
                );
            }
        }
        if matches!(network_mode, NetworkMode::OwnIp)
            && (lease.is_none() || published.is_none() || gate.is_none())
        {
            // An own-address box whose listens will never publish: said once
            // per launch, naming the fact that is missing, so a listen that
            // never publishes is not silent (NET-016) — a warning where the
            // declaration allows listens to publish, since one it allows will
            // not.
            if listens_can_publish {
                tracing::warn!(
                    session = %session_label,
                    lease = ?lease,
                    published = ?published,
                    gate = gate.is_some(),
                    "the box carries no listen plan; its listens are not published"
                );
            } else {
                tracing::info!(
                    session = %session_label,
                    lease = ?lease,
                    published = ?published,
                    gate = gate.is_some(),
                    "the box carries no listen plan; its listens are not published"
                );
            }
        }
        let listen_plan = match (lease, published, gate) {
            (Some(lease), Some(published), Some(gate)) => {
                tracing::debug!(
                    session = %session_label,
                    %lease,
                    %published,
                    "built the box's listen plan"
                );
                let switch = net_switch.lock().await;
                let control = match switch.transport() {
                    crate::net::SwitchTransport::LocalSpawn => {
                        crate::net::policy::ControlChannel::Unix(switch.control_socket())
                    }
                    crate::net::SwitchTransport::HostShuttle { cid, port } => {
                        crate::net::policy::ControlChannel::Vsock { cid, port }
                    }
                };
                Some(crate::net::listeners::ListenPlan::new(
                    session_label,
                    lease,
                    published,
                    control,
                    gate,
                    self.publications,
                    self.state_dir,
                    own_address
                        .as_ref()
                        .map(crate::net::provider::OwnAddressReporter::registry),
                    session_id,
                ))
            }
            _ => None,
        };

        Ok(Launched {
            master,
            process: SandboxProcess::new(SandboxBackend {
                child: process.release(),
                // The backend owns the leaf from here: it is what the session
                // is placed in, and its removal at session end is the last
                // thing the box owes.
                leaf: leaf_guard.take().map(BoxLeafGuard::release),
            }),
            guard: env,
            net_guard,
            tty_path,
            seal_injection,
            // The launch's own placement outcome for this box, so the
            // session can record it without re-deriving it from things a
            // person never sees.
            host_ip_enforcement: enforcement,
            // The copy the host keeps, so every process injected into the
            // session can join the same leaf.
            leaf,
            // The box's listen plan, and with it the one handoff to the
            // host that runs the box: taken when the host builds, so a
            // cancelled launch's plan never reaches any host at all.
            listen_plan,
            start_gate,
        })
    }
}
