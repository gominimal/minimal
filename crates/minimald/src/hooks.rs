//! Running a session's lifecycle hooks.
//!
//! A hook is a script a loadout or a project asked to run at one
//! of a session's transitions. It executes **inside the running
//! session's sandbox**, by joining the session process's namespaces
//! (see [`crate::nsenter`]) — not in a freshly-built one. That
//! distinction matters: a new sandbox would share the rootfs and the
//! persistent home/workspace mounts, but get its own `/tmp`, its own
//! `/dev`, and its own network namespace. On an own-IP session the
//! fresh netns has no tap relayed to the switch, so a hook that fetches
//! anything would fail there and succeed on a host-net session — the
//! same declaration behaving differently for reasons nobody connected
//! to hooks. Joining the live session avoids all of it.
//!
//! # Delivering the script
//!
//! Scripts are piped to their interpreter on stdin rather than
//! referenced by path. The staged-scripts directory lives beside the
//! session's workspace on the *daemon* filesystem and is not mounted
//! into the sandbox, so a path would not resolve there; and reading the
//! bytes daemon-side collapses inline and external hooks onto one code
//! path. It also settles stdin: the script occupies it, so a hook cannot
//! read the user's keystrokes out of an attached terminal.
//!
//! Which interpreter is [`Interpreter`]'s decision: POSIX `sh` by
//! default, or whatever a leading shebang names. Because the script
//! arrives on stdin, no kernel ever sees that shebang — this module
//! reads it and runs what it names.
//!
//! # What this module does not do
//!
//! Decide *when* hooks fire. Wiring the four transitions is the
//! caller's job; this module runs a set of hooks for one event and
//! reports what happened.

use std::collections::BTreeMap;
use std::process::Stdio;
use std::time::Duration;

use paths::DaemonAbsPath;
use sessions::SessionId;
use sessions::core::compose::Composition;
use sessions::core::lifecyclehook::{HookScript, HookScriptBody, staged_script_path};
use sessions::core::source::{Provenanced, ProvenancedHook, Source};

/// The transition a hook is running for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HookEvent {
    Activate,
    Destroy,
    Attach,
    Detach,
}

impl HookEvent {
    /// The name as declared in configuration, and as reported to the
    /// hook in `MINIMAL_HOOK_EVENT`.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Activate => "on_activate",
            Self::Destroy => "on_destroy",
            Self::Attach => "on_attach",
            Self::Detach => "on_detach",
        }
    }

    /// Teardown events run in reverse composition order, so the project
    /// tears down after every loadout that layered on top of it. They are
    /// also the events that run under a total budget — see
    /// [`run_hooks`].
    pub(crate) fn is_teardown(self) -> bool {
        matches!(self, Self::Destroy | Self::Detach)
    }

    /// This event's script on `hook`, if it declares one.
    pub(crate) fn script_of(
        self,
        hook: &sessions::core::lifecyclehook::LifecycleHook,
    ) -> Option<&HookScript> {
        match self {
            Self::Activate => hook.on_activate(),
            Self::Destroy => hook.on_destroy(),
            Self::Attach => hook.on_attach(),
            Self::Detach => hook.on_detach(),
        }
    }
}

/// Builds commands that run inside a session's sandbox.
///
/// Exists so the runner can be exercised without a real sandbox: the
/// production implementation joins namespaces via the session host,
/// while tests substitute one that returns a plain host command. That
/// leaves only the `setns` step untested here — everything else (script
/// delivery, stdio, timeouts, ordering, metadata) runs against the same
/// code path either way.
pub(crate) trait SessionCommands {
    /// A command that will run `program` with `args` inside the
    /// session, with `extra_env` layered over the session's own
    /// variables.
    fn command(
        &self,
        program: &str,
        args: &[&str],
        extra_env: BTreeMap<String, String>,
    ) -> impl std::future::Future<Output = std::io::Result<std::process::Command>> + Send;
}

/// A [`SessionCommands`] owning everything needed to build an
/// injection, so it can outlive a borrow of the host.
///
/// The host uses this rather than its own handle: a hook run happens
/// inside the host's message loop, so a round-trip through the handle
/// would deadlock against itself. Owning the data also keeps a `&Host`
/// off the stack across an await — a `Host` holds a non-`Sync`
/// `dyn NetGuard`, which would make the whole session future non-`Send`.
pub(crate) struct InjectedCommands {
    pub(crate) leader_pid: u32,
    pub(crate) cwd: String,
    pub(crate) vars: BTreeMap<String, String>,
}

impl SessionCommands for InjectedCommands {
    async fn command(
        &self,
        program: &str,
        args: &[&str],
        extra_env: BTreeMap<String, String>,
    ) -> std::io::Result<std::process::Command> {
        let mut vars = self.vars.clone();
        vars.extend(extra_env);
        crate::nsenter::Injection::new(self.leader_pid, program, args)
            .with_cwd(self.cwd.clone())
            .with_env(vars)
            .command()
            .map_err(std::io::Error::other)
    }
}

impl SessionCommands for crate::session_host::HostHandle {
    fn command(
        &self,
        program: &str,
        args: &[&str],
        extra_env: BTreeMap<String, String>,
    ) -> impl std::future::Future<Output = std::io::Result<std::process::Command>> + Send {
        let args: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
        let program = program.to_string();
        async move { self.command_in_session_env(program, args, extra_env).await }
    }
}

/// How a hook's output is routed.
pub(crate) enum HookOutput {
    /// Open this terminal fresh for each hook and write to it, so the
    /// hook's stdout really is a tty (`[ -t 1 ]`, `tput`, size queries).
    ///
    /// A path rather than a retained descriptor: while any slave fd for
    /// a PTY stays open its master never sees EOF, so holding one for
    /// the session's lifetime would stop the host from ever observing
    /// the shell exit. Each descriptor opened here lives only as long
    /// as the hook that writes to it.
    Tty(std::path::PathBuf),
    /// Capture and return it. Activate and destroy hooks have no
    /// terminal to write to.
    Capture,
}

/// What a hook did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HookOutcome {
    /// The transition it ran for.
    pub(crate) event: &'static str,
    /// Human-readable source, e.g. ``user loadout `dev` `` (from `Source`'s `Display`).
    pub(crate) declared_by: String,
    /// The hook's own description, when it has one.
    pub(crate) description: Option<String>,
    pub(crate) status: HookStatus,
    /// Tail of captured output; always empty for
    /// [`HookOutput::Tty`], which wrote straight to the terminal.
    pub(crate) output: String,
}

impl HookOutcome {
    /// Whether this outcome should be treated as a failure by callers
    /// that gate on hooks (only `on_activate` does).
    pub(crate) fn failed(&self) -> bool {
        !matches!(self.status, HookStatus::Ok)
    }
}

/// The terminal state of one hook run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HookStatus {
    /// Exited zero.
    Ok,
    /// Exited non-zero, or was killed by a signal (`code` absent).
    Failed { code: Option<i32> },
    /// Exceeded the time it was given and was killed.
    ///
    /// `after` is what it actually got, which is not always what it
    /// asked for: on a budgeted run (teardown — see [`run_hooks`]) a
    /// hook is cut to whatever the budget has left. `budgeted` says
    /// which happened, because otherwise a hook declaring 60s and
    /// reported as timing out after 4s reads as a broken timeout rather
    /// than as a teardown that had already spent its time.
    TimedOut { after: Duration, budgeted: bool },
    /// Never ran: the command could not be built or spawned, or its
    /// script could not be read.
    NotRun { reason: String },
}

/// How long output tails are kept in an outcome. Enough to see a
/// compiler error or a stack trace without letting a chatty hook push
/// megabytes into a log line or an RPC response.
const OUTPUT_TAIL_BYTES: usize = 4096;

/// Run every hook in `composition` that declares a script for `event`.
///
/// Setup events run in composition order (project first, then loadouts
/// in selection order); teardown events run in reverse, so the project
/// tears down last. Hooks that declare nothing for this event are
/// skipped silently.
///
/// Never returns an error: a hook that could not run produces a
/// [`HookStatus::NotRun`] outcome rather than aborting the batch, so a
/// caller always gets one outcome per hook that declared a script and
/// decides for itself what is fatal. Only `on_activate` treats a
/// failure as fatal, and that decision belongs to its trigger, not
/// here.
/// `budget`, when set, is a deadline across the **whole** run rather
/// than per hook. Each script still gets at most its own timeout, but
/// never more than what is left; once the budget is spent the remaining
/// hooks are reported [`HookStatus::NotRun`] without being started.
///
/// Teardown passes one. A per-script cap alone bounds nothing in
/// aggregate — nothing limits how many hooks a composition may carry,
/// so N of them at [`MAX_HOOK_TIMEOUT`] each would hold a destroy open
/// for N×5 minutes, which is the exact failure that cap exists to
/// prevent. Setup passes `None`: `on_activate` and `on_attach` run
/// under a command the user is watching and can interrupt, and
/// truncating them would silently half-configure a session instead of
/// failing it.
///
/// [`MAX_HOOK_TIMEOUT`]: sessions::core::lifecyclehook::MAX_HOOK_TIMEOUT
pub(crate) async fn run_hooks<C: SessionCommands>(
    commands: &C,
    ctx: &HookContext<'_>,
    event: HookEvent,
    mut output: HookOutput,
    budget: Option<Duration>,
) -> Vec<HookOutcome> {
    let ordered: Vec<&ProvenancedHook> = if event.is_teardown() {
        ctx.composition.lifecycle_hooks_teardown().collect()
    } else {
        ctx.composition.lifecycle_hooks().iter().collect()
    };
    // Only hooks that declare something for this event are numbered, so
    // MINIMAL_HOOK_INDEX/COUNT describe the run that actually happens
    // rather than the whole composition.
    let running: Vec<&ProvenancedHook> = ordered
        .into_iter()
        .filter(|ph| event.script_of(ph.hook()).is_some())
        .collect();

    let deadline = budget.map(|b| tokio::time::Instant::now() + b);
    let mut outcomes = Vec::with_capacity(running.len());
    for (index, ph) in running.iter().enumerate() {
        let script = event
            .script_of(ph.hook())
            .expect("filtered to hooks with a script for this event");
        // A hook gets the smaller of its own timeout and what remains of
        // the run's budget, so the last hook cannot extend past it.
        let allowed = match deadline {
            None => script.timeout(),
            Some(d) => {
                let left = d.saturating_duration_since(tokio::time::Instant::now());
                if left.is_zero() {
                    outcomes.push(not_run_over_budget(event, ph, budget));
                    continue;
                }
                script.timeout().min(left)
            }
        };
        outcomes.push(
            run_one(
                commands,
                ctx,
                event,
                ph,
                script,
                allowed,
                index,
                running.len(),
                &mut output,
            )
            .await,
        );
    }
    outcomes
}

/// The outcome for a hook the run had no time left to start. Reported
/// rather than skipped silently: a hook that did not run is something
/// the operator has to be able to see, and it names the budget so the
/// reason is not mistaken for the hook's own failure.
fn not_run_over_budget(
    event: HookEvent,
    ph: &ProvenancedHook,
    budget: Option<Duration>,
) -> HookOutcome {
    HookOutcome {
        event: event.as_str(),
        declared_by: ph.source().to_string(),
        description: ph.hook().description().map(str::to_owned),
        status: HookStatus::NotRun {
            reason: format!(
                "the {} budget of {}s was spent by earlier hooks",
                event.as_str(),
                budget.unwrap_or_default().as_secs(),
            ),
        },
        output: String::new(),
    }
}

/// What a hook body is fed to, and with which arguments.
///
/// Hooks are POSIX shell by default: the contract is `sh`, not any one
/// shell's extensions, so a hook that works in one session keeps working in
/// a session whose `sh` is a leaner one. A script that wants something else
/// says so in a shebang, which is the spelling every hook author already
/// knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Interpreter {
    program: String,
    args: Vec<String>,
}

impl Interpreter {
    /// POSIX `sh` reading the script from standard input. `-s` is the POSIX
    /// spelling of "commands come from stdin"; passing no operands would
    /// mean the same thing, but saying it leaves nothing to infer.
    fn posix_shell() -> Self {
        Self {
            program: "sh".to_string(),
            args: vec!["-s".to_string()],
        }
    }

    /// The interpreter `body` asks for in a shebang, or POSIX `sh` when it
    /// asks for nothing.
    ///
    /// The body still reaches the interpreter on stdin rather than as a
    /// file, so this reads the shebang and runs what it names instead of
    /// letting the kernel do it — a hook has no path inside the session to
    /// be exec'd from. It is parsed exactly as the kernel would, so a hook
    /// behaves the same here as the same file would anywhere else:
    ///
    /// - The interpreter is the first whitespace-delimited word. A path
    ///   containing spaces therefore cannot be named — there is no quoting
    ///   in a shebang line, on any system. Point one at `env` instead.
    /// - Everything after it is **one** argument, not one per word
    ///   (`execve(2)`). This is why `#!/usr/bin/env -S python3 -u` works:
    ///   `env` receives `-S python3 -u` whole and splits it itself, which
    ///   is what `-S` is for. Splitting here instead would hand `env` a
    ///   `-S` with only `python3` attached and leave `-u` to be misread as
    ///   an option to `env`.
    ///
    /// The one thing the kernel does that this cannot: resolve a relative
    /// interpreter path, which it would take against the *daemon's* working
    /// directory rather than the session's. Name an absolute path, or a
    /// bare command for `env` to find on the session's `PATH`.
    ///
    /// The shebang line is left in the body. Every interpreter this can name
    /// treats `#` as a comment, and keeping it means a hook's line numbers
    /// match what its author wrote.
    fn for_script(body: &[u8]) -> Self {
        let Some(rest) = body.strip_prefix(b"#!") else {
            return Self::posix_shell();
        };
        let line = rest.split(|b| *b == b'\n').next().unwrap_or_default();
        // A shebang naming a non-UTF-8 path is not something to guess at.
        let Ok(line) = std::str::from_utf8(line) else {
            return Self::posix_shell();
        };
        // `trim` rather than `trim_start`: it also takes the `\r` a CRLF
        // checkout leaves on the line, which is otherwise part of the last
        // argument (or of the interpreter's own path, when it is alone).
        let line = line.trim();
        let (program, arg) = match line.split_once(char::is_whitespace) {
            Some((program, arg)) => (program, arg.trim()),
            None => (line, ""),
        };
        if program.is_empty() {
            // `#!` with nothing after it names no interpreter.
            return Self::posix_shell();
        }
        Self {
            program: program.to_string(),
            args: if arg.is_empty() {
                Vec::new()
            } else {
                vec![arg.to_string()]
            },
        }
    }

    /// The program to run.
    fn program(&self) -> &str {
        &self.program
    }

    /// Its arguments, in the shape [`SessionCommands::command`] takes.
    fn args(&self) -> Vec<&str> {
        self.args.iter().map(String::as_str).collect()
    }
}

/// Everything a hook run needs to know about the session it belongs to.
pub(crate) struct HookContext<'a> {
    pub(crate) session_id: SessionId,
    pub(crate) session_name: &'a str,
    pub(crate) composition: &'a Composition,
    /// Where the client's uploaded external scripts were staged.
    pub(crate) hooks_dir: DaemonAbsPath,
    /// The session's workspace, where a project's own scripts live when
    /// the project tree was uploaded.
    pub(crate) workspace: DaemonAbsPath,
}

#[allow(clippy::too_many_arguments)]
async fn run_one<C: SessionCommands>(
    commands: &C,
    ctx: &HookContext<'_>,
    event: HookEvent,
    ph: &ProvenancedHook,
    script: &HookScript,
    // How long this run may take — the script's own timeout, or less
    // when a budgeted run has less than that left. See `run_hooks`.
    timeout: Duration,
    index: usize,
    count: usize,
    output: &mut HookOutput,
) -> HookOutcome {
    let declared_by = ph.source().to_string();
    let description = ph.hook().description().map(str::to_owned);
    let outcome = |status| HookOutcome {
        event: event.as_str(),
        declared_by: declared_by.clone(),
        description: description.clone(),
        status,
        output: String::new(),
    };

    let body = match read_script(ctx, ph.source(), script) {
        Ok(b) => b,
        Err(reason) => return outcome(HookStatus::NotRun { reason }),
    };

    let env = metadata_env(ctx, event, ph.source(), index, count);
    // The interpreter reads the script from stdin. Nothing is passed as an
    // argument beyond what the shebang asked for, so a script's `$1..` are
    // empty rather than accidentally inheriting anything.
    let interpreter = Interpreter::for_script(&body);
    let built = match commands
        .command(interpreter.program(), &interpreter.args(), env)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            return outcome(HookStatus::NotRun {
                reason: format!("building the command for `{}`: {e}", interpreter.program()),
            });
        }
    };

    let mut cmd = tokio::process::Command::from(built);
    cmd.stdin(Stdio::piped());
    let capturing = match output {
        HookOutput::Capture => {
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
            true
        }
        HookOutput::Tty(path) => {
            // Opened per hook and dropped with the child, so no slave
            // descriptor outlives the run that needed it.
            let open = |p: &std::path::Path| std::fs::OpenOptions::new().write(true).open(p);
            let (out, err) = match (open(path), open(path)) {
                (Ok(o), Ok(e)) => (o, e),
                _ => {
                    return outcome(HookStatus::NotRun {
                        reason: format!("opening the session terminal `{}` failed", path.display()),
                    });
                }
            };
            cmd.stdout(Stdio::from(out)).stderr(Stdio::from(err));
            false
        }
    };
    cmd.kill_on_drop(true);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            // Naming the interpreter matters most here: a shebang for
            // something the session doesn't have is an ordinary mistake, and
            // a bare ENOENT would look like the hook itself was missing.
            return outcome(HookStatus::NotRun {
                reason: format!("spawning `{}`: {e}", interpreter.program()),
            });
        }
    };

    // Write the script, then close stdin — an interpreter reads to EOF
    // before it runs anything, so a hook that never terminates cannot be
    // blamed on a stdin left open.
    //
    // Bounded by the same deadline as the run itself: an interpreter that
    // never reads its stdin leaves this blocked once the body outgrows the
    // pipe buffer, and an unbounded block here would sit *before* the
    // timeout below and defeat it — including the teardown budget, whose
    // whole job is that a hook cannot hold a session open.
    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt as _;
        let written = tokio::time::timeout(timeout, stdin.write_all(&body)).await;
        let failed = match written {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(format!("writing the script to stdin: {e}")),
            Err(_elapsed) => Some(format!(
                "the interpreter did not read its script within {}s",
                timeout.as_secs(),
            )),
        };
        if let Some(reason) = failed {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return outcome(HookStatus::NotRun { reason });
        }
        drop(stdin);
    }

    let waited = if capturing {
        tokio::time::timeout(timeout, child.wait_with_output()).await
    } else {
        tokio::time::timeout(timeout, async {
            child.wait().await.map(|status| std::process::Output {
                status,
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        })
        .await
    };

    match waited {
        Ok(Ok(out)) => {
            let mut o = outcome(if out.status.success() {
                HookStatus::Ok
            } else {
                HookStatus::Failed {
                    code: out.status.code(),
                }
            });
            o.output = tail_of(&out.stdout, &out.stderr);
            o
        }
        Ok(Err(e)) => outcome(HookStatus::NotRun {
            reason: format!("waiting: {e}"),
        }),
        Err(_elapsed) => {
            // `wait_with_output`/`wait` took ownership, so the kill goes
            // through `kill_on_drop`: the child is dropped when the
            // timed-out future is, which signals it. That reaches the
            // interpreter — the shim relays it via `PR_SET_PDEATHSIG` —
            // but not anything the interpreter itself backgrounded: no
            // process group is set, so a `foo &` outlives the timeout.
            // Those are bounded by the session instead, whose PID
            // namespace takes them when its shell exits.
            outcome(HookStatus::TimedOut {
                after: timeout,
                // Cut short by the run's budget rather than by its own
                // declaration, when the two differ.
                budgeted: timeout < script.timeout(),
            })
        }
    }
}

/// Whether `p` stays inside the directory it is joined to: relative,
/// with no `..` component. The twin of `rpc::safe_relative_path`, which
/// guards the *write* side (unpacking an uploaded archive); this guards
/// the read.
fn contained_relative_path(p: &std::path::Path) -> bool {
    !p.is_absolute()
        && !p
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
}

/// The script bytes to feed the interpreter ([`Interpreter::for_script`]
/// reads its shebang out of these).
///
/// Inline hooks carry their body in the composition. External hooks are
/// read from the staged-scripts directory; a project's script may
/// instead be in the uploaded workspace tree, which is checked as a
/// fallback because that upload makes staging unnecessary.
fn read_script(
    ctx: &HookContext<'_>,
    source: &Source,
    script: &HookScript,
) -> Result<Vec<u8>, String> {
    match script.body() {
        HookScriptBody::Inline(body) => Ok(body.clone().into_bytes()),
        HookScriptBody::External(rel) => {
            let staged = staged_script_path(source, rel)
                .ok_or_else(|| "this source cannot declare hook scripts".to_string())?;
            // Both joins below are made with a path derived from wire
            // data, so neither is allowed to climb out of the directory
            // it is anchored to. `staged_script_path` and
            // `ConfigRelPath` each refuse the components that would let
            // it; this is the check at the point of use, where the
            // consequence actually lands — reading a file the session
            // was never given.
            if !contained_relative_path(staged.as_std_path())
                || !contained_relative_path(rel.as_utf8_path().as_std_path())
            {
                return Err(format!(
                    "hook script path `{staged}` escapes the session's staged-hooks directory"
                ));
            }
            let staged_path = ctx.hooks_dir.as_utf8_path().join(&staged);
            match std::fs::read(staged_path.as_std_path()) {
                Ok(b) => return Ok(b),
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err(format!("reading `{staged_path}`: {e}"));
                }
                Err(_) => {}
            }
            // Not staged. For a project, the script may have arrived
            // with the workspace tree instead.
            if matches!(source, Source::Project { .. }) {
                let in_tree = ctx.workspace.as_utf8_path().join(rel.as_utf8_path());
                return std::fs::read(in_tree.as_std_path()).map_err(|e| {
                    format!(
                        "script not staged, and reading `{in_tree}` from the workspace \
                         failed: {e}"
                    )
                });
            }
            Err(format!(
                "no staged script at `{staged_path}` (was the hook-script upload skipped?)"
            ))
        }
    }
}

/// The metadata a hook gets on top of the session's own environment.
fn metadata_env(
    ctx: &HookContext<'_>,
    event: HookEvent,
    source: &Source,
    index: usize,
    count: usize,
) -> BTreeMap<String, String> {
    // Split into kind and name because a hook author wants to branch on
    // one and print the other; `Source`'s `Display` gives a single
    // prose string, which is right for a log line but not for `[ "$K" =
    // project ]`. The catch-all exists because `Source` is
    // `#[non_exhaustive]`: a variant added later should degrade to a
    // usable value rather than fail to compile a crate that only needs
    // a label for it.
    let (kind, name) = match source {
        Source::UserLoadout { name } => ("loadout", name.clone()),
        Source::Project { path } => ("project", path.as_utf8_path().to_string()),
        Source::Package { name } => ("package", name.clone()),
        other => ("other", other.to_string()),
    };
    BTreeMap::from([
        ("MINIMAL_SESSION_ID".to_string(), ctx.session_id.to_string()),
        (
            "MINIMAL_SESSION_NAME".to_string(),
            ctx.session_name.to_string(),
        ),
        ("MINIMAL_HOOK_EVENT".to_string(), event.as_str().to_string()),
        ("MINIMAL_HOOK_SOURCE_KIND".to_string(), kind.to_string()),
        ("MINIMAL_HOOK_SOURCE_NAME".to_string(), name),
        // 1-based: these are for a human reading a log line, not an
        // array index.
        ("MINIMAL_HOOK_INDEX".to_string(), (index + 1).to_string()),
        ("MINIMAL_HOOK_COUNT".to_string(), count.to_string()),
    ])
}

/// Last [`OUTPUT_TAIL_BYTES`] of the two streams, stderr after stdout.
fn tail_of(stdout: &[u8], stderr: &[u8]) -> String {
    let mut joined = String::from_utf8_lossy(stdout).into_owned();
    if !stderr.is_empty() {
        if !joined.is_empty() && !joined.ends_with('\n') {
            joined.push('\n');
        }
        joined.push_str(&String::from_utf8_lossy(stderr));
    }
    if joined.len() <= OUTPUT_TAIL_BYTES {
        return joined;
    }
    // Cut on a char boundary so the tail stays valid UTF-8.
    let start = joined
        .char_indices()
        .rev()
        .map(|(i, _)| i)
        .find(|i| joined.len() - i >= OUTPUT_TAIL_BYTES)
        .unwrap_or(0);
    joined[start..].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sessions::core::lifecyclehook::LifecycleHook;

    /// A [`SessionCommands`] that runs the command on the host instead
    /// of inside a sandbox. Exercises everything but the namespace
    /// join.
    struct HostCommands;

    impl SessionCommands for HostCommands {
        fn command(
            &self,
            program: &str,
            args: &[&str],
            extra_env: BTreeMap<String, String>,
        ) -> impl std::future::Future<Output = std::io::Result<std::process::Command>> + Send
        {
            let mut cmd = std::process::Command::new(program);
            cmd.args(args);
            cmd.env_clear();
            cmd.envs(extra_env);
            async move { Ok(cmd) }
        }
    }

    /// A [`SessionCommands`] that always refuses, standing in for a
    /// session whose shell has exited.
    struct DeadSession;

    impl SessionCommands for DeadSession {
        async fn command(
            &self,
            _program: &str,
            _args: &[&str],
            _extra_env: BTreeMap<String, String>,
        ) -> std::io::Result<std::process::Command> {
            Err(std::io::Error::other("no session leader"))
        }
    }

    fn loadout(name: &str) -> Source {
        Source::UserLoadout {
            name: name.to_string(),
        }
    }

    fn project() -> Source {
        Source::Project {
            path: paths::HostPath::try_new("/repo").unwrap(),
        }
    }

    /// Compose `hooks` (in order) into a `Composition`.
    ///
    /// Built through the public snapshot conversion rather than a
    /// test-only constructor: `Composition`'s own builders are
    /// crate-private to `sessions`, and going through the wire form
    /// exercises the same path a daemon restart takes.
    fn composition_of(hooks: Vec<ProvenancedHook>) -> Composition {
        use sessions::wire::primitives::WireProvenancedHook;
        use sessions::wire::request::{COMPOSITION_SNAPSHOT_VERSION, WireComposition};
        let wire = WireComposition {
            version: COMPOSITION_SNAPSHOT_VERSION,
            vars: Vec::new(),
            patches: Vec::new(),
            packages: Vec::new(),
            lifecycle_hooks: hooks.into_iter().map(WireProvenancedHook::from).collect(),
            orientation: Default::default(),
        };
        Composition::try_from(wire).expect("hooks with at least one script convert back")
    }

    fn ctx<'a>(composition: &'a Composition, dir: &camino::Utf8Path) -> HookContext<'a> {
        HookContext {
            session_id: SessionId::nil(),
            session_name: "test",
            composition,
            hooks_dir: DaemonAbsPath::try_new(dir.join("hooks")).unwrap(),
            workspace: DaemonAbsPath::try_new(dir.join("tree")).unwrap(),
        }
    }

    fn inline_hook(event: HookEvent, body: &str, source: Source) -> ProvenancedHook {
        let script = HookScript::inline(body);
        let b = LifecycleHook::builder();
        let b = match event {
            HookEvent::Activate => b.with_on_activate(script),
            HookEvent::Destroy => b.with_on_destroy(script),
            HookEvent::Attach => b.with_on_attach(script),
            HookEvent::Detach => b.with_on_detach(script),
        };
        ProvenancedHook::new(b.build().unwrap(), source)
    }

    /// The last guard before the daemon reads a file for a hook.
    ///
    /// Currently unreachable: `staged_script_path` refuses a loadout
    /// name that isn't a plain path component, and `ConfigRelPath`
    /// refuses `..` in the script path, so nothing upstream can hand
    /// this an escaping path today. Tested directly for that reason —
    /// it is the backstop if either of those ever loosens, and a
    /// backstop nothing exercises is one nobody notices breaking.
    #[test]
    fn contained_relative_path_rejects_anything_that_could_climb_out() {
        use std::path::Path;
        for bad in [
            "/etc/shadow",
            "../etc/shadow",
            "loadout/../../../etc/shadow",
            "a/b/..",
            "..",
        ] {
            assert!(
                !contained_relative_path(Path::new(bad)),
                "{bad:?} should be refused",
            );
        }
        for good in [
            "loadout/dev/activate.sh",
            "project/scripts/setup.sh",
            "a",
            "./a/b",
        ] {
            assert!(
                contained_relative_path(Path::new(good)),
                "{good:?} should be allowed",
            );
        }
    }

    /// The default is POSIX `sh`, reading the script from stdin.
    #[test]
    fn a_script_without_a_shebang_runs_under_posix_sh() {
        let i = Interpreter::for_script(b"echo hello\n");
        assert_eq!(i.program(), "sh");
        assert_eq!(i.args(), vec!["-s"]);
        assert_eq!(i, Interpreter::for_script(b""));
    }

    /// A shebang names the interpreter, and everything after it is a
    /// single argument — `execve(2)`'s rule, not one-arg-per-word. The
    /// `env -S` case is the one that would break under word splitting:
    /// `env` needs `-S python3 -u` whole to split it itself.
    #[test]
    fn a_shebang_names_the_interpreter_and_one_argument() {
        let cases: [(&[u8], &str, Vec<&str>); 5] = [
            (b"#!/bin/fish\necho hi\n", "/bin/fish", vec![]),
            (
                b"#!/usr/bin/env python3\nprint(1)\n",
                "/usr/bin/env",
                vec!["python3"],
            ),
            (
                b"#!/usr/bin/env -S python3 -u\nprint(1)\n",
                "/usr/bin/env",
                vec!["-S python3 -u"],
            ),
            (b"#!/bin/sh -e\ntrue\n", "/bin/sh", vec!["-e"]),
            // No trailing newline: the shebang is the whole body.
            (b"#!/bin/fish", "/bin/fish", vec![]),
        ];
        for (body, program, args) in cases {
            let i = Interpreter::for_script(body);
            assert_eq!(
                i.program(),
                program,
                "body: {:?}",
                String::from_utf8_lossy(body)
            );
            assert_eq!(i.args(), args, "body: {:?}", String::from_utf8_lossy(body));
        }
    }

    /// Surrounding whitespace — including the `\r` a CRLF-checkout leaves on
    /// the line — is not part of the interpreter's path.
    #[test]
    fn a_shebang_tolerates_padding_and_crlf() {
        let i = Interpreter::for_script(b"#!  /usr/bin/env  fish  \r\nls\n");
        assert_eq!(i.program(), "/usr/bin/env");
        assert_eq!(i.args(), vec!["fish"]);
    }

    /// A `#!` that names nothing, or names something unreadable, falls back
    /// to the default rather than failing the hook: a script whose first
    /// line is odd is still a script.
    #[test]
    fn an_unusable_shebang_falls_back_to_posix_sh() {
        for body in [
            &b"#!\necho hi\n"[..],
            &b"#!   \n"[..],
            &b"#!/bin/\xff\n"[..],
        ] {
            assert_eq!(
                Interpreter::for_script(body),
                Interpreter::for_script(b"echo hi"),
                "body: {:?}",
                String::from_utf8_lossy(body),
            );
        }
    }

    /// A `#!` has to lead the file to be a shebang; one further down is just
    /// a comment.
    #[test]
    fn a_shebang_below_the_first_line_is_only_a_comment() {
        let i = Interpreter::for_script(b"echo hi\n#!/bin/fish\n");
        assert_eq!(i.program(), "sh");
    }

    /// End to end: a shebang'd script is really fed to the interpreter it
    /// names. `cat` copies stdin to stdout, so seeing the script's own text
    /// come back proves both halves — the program was chosen from the
    /// shebang, and the body reached it.
    #[tokio::test]
    async fn a_shebang_script_is_run_by_the_interpreter_it_names() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = camino::Utf8Path::from_path(tmp.path()).unwrap();
        // Not a shell script: under `sh` this would be a syntax error.
        let body = "#!/bin/cat\n<<< not shell >>>\n";
        let comp = composition_of(vec![inline_hook(HookEvent::Activate, body, loadout("dev"))]);

        let outcomes = run_hooks(
            &HostCommands,
            &ctx(&comp, dir),
            HookEvent::Activate,
            HookOutput::Capture,
            None,
        )
        .await;

        assert_eq!(outcomes[0].status, HookStatus::Ok, "{:?}", outcomes[0]);
        assert!(
            outcomes[0].output.contains("<<< not shell >>>"),
            "the script did not reach `cat`: {:?}",
            outcomes[0],
        );
        // The shebang rides along in the body, so `cat` echoes it too.
        assert!(
            outcomes[0].output.contains("#!/bin/cat"),
            "{:?}",
            outcomes[0]
        );
    }

    /// A shebang naming something the session doesn't have fails the hook
    /// with the interpreter in the message — the common mistake, and one a
    /// bare ENOENT would misattribute to the hook script itself.
    #[tokio::test]
    async fn a_missing_interpreter_is_reported_by_name() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = camino::Utf8Path::from_path(tmp.path()).unwrap();
        let comp = composition_of(vec![inline_hook(
            HookEvent::Activate,
            "#!/definitely/not/an/interpreter\ntrue\n",
            loadout("dev"),
        )]);

        let outcomes = run_hooks(
            &HostCommands,
            &ctx(&comp, dir),
            HookEvent::Activate,
            HookOutput::Capture,
            None,
        )
        .await;

        let HookStatus::NotRun { reason } = &outcomes[0].status else {
            panic!("expected NotRun, got {:?}", outcomes[0].status);
        };
        assert!(
            reason.contains("/definitely/not/an/interpreter"),
            "the failure should name the interpreter: {reason}"
        );
    }

    #[tokio::test]
    async fn inline_hook_runs_and_reports_success() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = camino::Utf8Path::from_path(tmp.path()).unwrap();
        let comp = composition_of(vec![inline_hook(
            HookEvent::Activate,
            "echo hello",
            loadout("dev"),
        )]);
        let outcomes = run_hooks(
            &HostCommands,
            &ctx(&comp, dir),
            HookEvent::Activate,
            HookOutput::Capture,
            None,
        )
        .await;

        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].status, HookStatus::Ok);
        assert!(!outcomes[0].failed());
        assert!(outcomes[0].output.contains("hello"), "{:?}", outcomes[0]);
        assert_eq!(outcomes[0].declared_by, "user loadout `dev`");
    }

    /// A non-zero exit is reported with its code rather than swallowed.
    #[tokio::test]
    async fn failing_hook_reports_its_exit_code() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = camino::Utf8Path::from_path(tmp.path()).unwrap();
        let comp = composition_of(vec![inline_hook(
            HookEvent::Activate,
            "echo oops >&2; exit 3",
            loadout("dev"),
        )]);
        let outcomes = run_hooks(
            &HostCommands,
            &ctx(&comp, dir),
            HookEvent::Activate,
            HookOutput::Capture,
            None,
        )
        .await;

        assert_eq!(outcomes[0].status, HookStatus::Failed { code: Some(3) });
        assert!(outcomes[0].failed());
        assert!(outcomes[0].output.contains("oops"));
    }

    /// A hook that outlives its timeout is killed and reported as timed
    /// out, not left running.
    #[tokio::test]
    async fn hook_exceeding_its_timeout_is_killed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = camino::Utf8Path::from_path(tmp.path()).unwrap();
        let script = HookScript::inline("sleep 30")
            .with_timeout(Duration::from_secs(1))
            .unwrap();
        let hook = LifecycleHook::builder()
            .with_on_activate(script)
            .build()
            .unwrap();
        let comp = composition_of(vec![ProvenancedHook::new(hook, loadout("dev"))]);

        let started = std::time::Instant::now();
        let outcomes = run_hooks(
            &HostCommands,
            &ctx(&comp, dir),
            HookEvent::Activate,
            HookOutput::Capture,
            None,
        )
        .await;

        // Its own declared timeout, on an unbudgeted run — so not
        // `budgeted`, which is what distinguishes this from a teardown
        // that ran out of time.
        assert!(
            matches!(
                outcomes[0].status,
                HookStatus::TimedOut {
                    budgeted: false,
                    ..
                }
            ),
            "{:?}",
            outcomes[0],
        );
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "the runner must not wait out the script it killed",
        );
    }

    /// Setup runs project-first; teardown runs the exact reverse.
    #[tokio::test]
    async fn teardown_runs_in_reverse_of_setup() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = camino::Utf8Path::from_path(tmp.path()).unwrap();

        let setup = composition_of(vec![
            inline_hook(HookEvent::Activate, "true", project()),
            inline_hook(HookEvent::Activate, "true", loadout("dev")),
        ]);
        let order: Vec<String> = run_hooks(
            &HostCommands,
            &ctx(&setup, dir),
            HookEvent::Activate,
            HookOutput::Capture,
            None,
        )
        .await
        .into_iter()
        .map(|o| o.declared_by)
        .collect();
        assert_eq!(order, vec!["project `/repo`", "user loadout `dev`"]);

        let teardown = composition_of(vec![
            inline_hook(HookEvent::Destroy, "true", project()),
            inline_hook(HookEvent::Destroy, "true", loadout("dev")),
        ]);
        let order: Vec<String> = run_hooks(
            &HostCommands,
            &ctx(&teardown, dir),
            HookEvent::Destroy,
            HookOutput::Capture,
            None,
        )
        .await
        .into_iter()
        .map(|o| o.declared_by)
        .collect();
        assert_eq!(order, vec!["user loadout `dev`", "project `/repo`"]);
    }

    /// Hooks that declare nothing for the event in flight are skipped,
    /// and the index/count reported to those that do run describes only
    /// the actual run.
    #[tokio::test]
    async fn only_hooks_declaring_this_event_run_and_are_numbered() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = camino::Utf8Path::from_path(tmp.path()).unwrap();
        let comp = composition_of(vec![
            inline_hook(HookEvent::Detach, "true", loadout("other")),
            inline_hook(
                HookEvent::Activate,
                "echo $MINIMAL_HOOK_INDEX/$MINIMAL_HOOK_COUNT",
                loadout("dev"),
            ),
        ]);
        let outcomes = run_hooks(
            &HostCommands,
            &ctx(&comp, dir),
            HookEvent::Activate,
            HookOutput::Capture,
            None,
        )
        .await;

        assert_eq!(outcomes.len(), 1, "the detach-only hook must not run");
        assert!(outcomes[0].output.contains("1/1"), "{:?}", outcomes[0]);
    }

    /// The metadata block reaches the script.
    #[tokio::test]
    async fn hook_receives_its_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = camino::Utf8Path::from_path(tmp.path()).unwrap();
        let comp = composition_of(vec![inline_hook(
            HookEvent::Attach,
            "echo $MINIMAL_HOOK_EVENT $MINIMAL_HOOK_SOURCE_KIND $MINIMAL_HOOK_SOURCE_NAME",
            loadout("dev"),
        )]);
        let outcomes = run_hooks(
            &HostCommands,
            &ctx(&comp, dir),
            HookEvent::Attach,
            HookOutput::Capture,
            None,
        )
        .await;

        assert!(
            outcomes[0].output.contains("on_attach loadout dev"),
            "{:?}",
            outcomes[0],
        );
    }

    /// An external script is read from the staged directory at the path
    /// the client derived.
    #[tokio::test]
    async fn external_script_is_read_from_the_staged_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = camino::Utf8Path::from_path(tmp.path()).unwrap();
        let staged = dir.join("hooks").join("loadout").join("dev");
        std::fs::create_dir_all(staged.as_std_path()).unwrap();
        std::fs::write(staged.join("a.sh").as_std_path(), "echo from-staged\n").unwrap();

        let hook = LifecycleHook::builder()
            .with_on_activate(HookScript::try_external("a.sh").unwrap())
            .build()
            .unwrap();
        let comp = composition_of(vec![ProvenancedHook::new(hook, loadout("dev"))]);
        let outcomes = run_hooks(
            &HostCommands,
            &ctx(&comp, dir),
            HookEvent::Activate,
            HookOutput::Capture,
            None,
        )
        .await;

        assert_eq!(outcomes[0].status, HookStatus::Ok, "{:?}", outcomes[0]);
        assert!(outcomes[0].output.contains("from-staged"));
    }

    /// A project's external script that was never staged falls back to
    /// the uploaded workspace tree.
    #[tokio::test]
    async fn project_script_falls_back_to_the_workspace_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = camino::Utf8Path::from_path(tmp.path()).unwrap();
        let tree = dir.join("tree").join("scripts");
        std::fs::create_dir_all(tree.as_std_path()).unwrap();
        std::fs::write(tree.join("s.sh").as_std_path(), "echo from-tree\n").unwrap();

        let hook = LifecycleHook::builder()
            .with_on_activate(HookScript::try_external("scripts/s.sh").unwrap())
            .build()
            .unwrap();
        let comp = composition_of(vec![ProvenancedHook::new(hook, project())]);
        let outcomes = run_hooks(
            &HostCommands,
            &ctx(&comp, dir),
            HookEvent::Activate,
            HookOutput::Capture,
            None,
        )
        .await;

        assert_eq!(outcomes[0].status, HookStatus::Ok, "{:?}", outcomes[0]);
        assert!(outcomes[0].output.contains("from-tree"));
    }

    /// A missing external script is reported as not-run, naming the
    /// path it looked for, rather than failing silently or panicking.
    #[tokio::test]
    async fn missing_external_script_reports_not_run() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = camino::Utf8Path::from_path(tmp.path()).unwrap();
        let hook = LifecycleHook::builder()
            .with_on_activate(HookScript::try_external("nope.sh").unwrap())
            .build()
            .unwrap();
        let comp = composition_of(vec![ProvenancedHook::new(hook, loadout("dev"))]);
        let outcomes = run_hooks(
            &HostCommands,
            &ctx(&comp, dir),
            HookEvent::Activate,
            HookOutput::Capture,
            None,
        )
        .await;

        assert!(
            matches!(&outcomes[0].status, HookStatus::NotRun { reason } if reason.contains("nope.sh")),
            "{:?}",
            outcomes[0],
        );
        assert!(outcomes[0].failed());
    }

    /// A session with no shell to join yields a not-run outcome per
    /// hook — the batch still reports, so a caller can say what was
    /// skipped instead of appearing to have run them.
    #[tokio::test]
    async fn dead_session_reports_not_run_per_hook() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = camino::Utf8Path::from_path(tmp.path()).unwrap();
        let comp = composition_of(vec![inline_hook(
            HookEvent::Destroy,
            "true",
            loadout("dev"),
        )]);
        let outcomes = run_hooks(
            &DeadSession,
            &ctx(&comp, dir),
            HookEvent::Destroy,
            HookOutput::Capture,
            None,
        )
        .await;

        assert_eq!(outcomes.len(), 1);
        assert!(matches!(outcomes[0].status, HookStatus::NotRun { .. }));
    }

    /// A teardown's hooks share one budget. Per-hook timeouts alone
    /// bound nothing in aggregate — nothing caps how many hooks a
    /// composition carries — so three hooks that would each burn their
    /// own timeout must still finish within the total, and the ones
    /// that never got to start must say so.
    #[tokio::test]
    async fn a_teardown_budget_is_shared_across_all_of_its_hooks() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = camino::Utf8Path::from_path(tmp.path()).unwrap();
        let slow = || {
            let script = HookScript::inline("sleep 30")
                .with_timeout(Duration::from_secs(10))
                .unwrap();
            ProvenancedHook::new(
                LifecycleHook::builder()
                    .with_on_destroy(script)
                    .build()
                    .unwrap(),
                loadout("dev"),
            )
        };
        let comp = composition_of(vec![slow(), slow(), slow()]);

        let started = std::time::Instant::now();
        let outcomes = run_hooks(
            &HostCommands,
            &ctx(&comp, dir),
            HookEvent::Destroy,
            HookOutput::Capture,
            Some(Duration::from_secs(2)),
        )
        .await;
        let elapsed = started.elapsed();

        assert_eq!(outcomes.len(), 3, "every hook is accounted for");
        // Unbudgeted this would be 3 × 10s; the budget caps the whole run.
        assert!(
            elapsed < Duration::from_secs(8),
            "the budget did not bound the run: took {elapsed:?}",
        );
        // The first burns the budget — and says the budget cut it
        // short, not its own 10s timeout, which it never reached.
        assert!(
            matches!(
                outcomes[0].status,
                HookStatus::TimedOut { budgeted: true, .. }
            ),
            "{:?}",
            outcomes[0],
        );
        let over_budget = outcomes[1..]
            .iter()
            .filter(
                |o| matches!(&o.status, HookStatus::NotRun { reason } if reason.contains("budget")),
            )
            .count();
        assert!(
            over_budget >= 1,
            "a hook the budget left no time for should report why: {:?}",
            &outcomes[1..],
        );
    }

    /// Without a budget the per-hook timeouts are the only bound, which
    /// is what setup transitions want: an `on_activate` that takes its
    /// full timeout is slow, not truncated.
    #[tokio::test]
    async fn an_unbudgeted_run_lets_every_hook_have_its_own_timeout() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = camino::Utf8Path::from_path(tmp.path()).unwrap();
        let quick = |body: &str| {
            ProvenancedHook::new(
                LifecycleHook::builder()
                    .with_on_activate(HookScript::inline(body))
                    .build()
                    .unwrap(),
                loadout("dev"),
            )
        };
        let comp = composition_of(vec![quick("echo one"), quick("echo two")]);

        let outcomes = run_hooks(
            &HostCommands,
            &ctx(&comp, dir),
            HookEvent::Activate,
            HookOutput::Capture,
            None,
        )
        .await;

        assert_eq!(outcomes.len(), 2);
        assert!(
            outcomes.iter().all(|o| o.status == HookStatus::Ok),
            "{outcomes:?}",
        );
    }

    /// A composition with no hooks for the event produces no outcomes
    /// and does nothing.
    #[tokio::test]
    async fn no_hooks_is_a_no_op() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = camino::Utf8Path::from_path(tmp.path()).unwrap();
        let comp = composition_of(Vec::new());
        assert!(
            run_hooks(
                &DeadSession,
                &ctx(&comp, dir),
                HookEvent::Activate,
                HookOutput::Capture,
                None,
            )
            .await
            .is_empty()
        );
    }

    #[test]
    fn output_tail_keeps_the_end_and_stays_utf8() {
        let long = "é".repeat(OUTPUT_TAIL_BYTES);
        let tail = tail_of(long.as_bytes(), b"");
        assert!(tail.len() <= OUTPUT_TAIL_BYTES + 2);
        assert!(long.ends_with(&tail));
    }
}
