//! The minimal CLI which pairs/talks-with minimald.

// The in-process daemon's async bodies are deep: rustc's default query depth (128)
// overflows computing their layout (`queries overflow the depth limit!`), as the
// daemon crates themselves already declare.
#![recursion_limit = "256"]
use std::io::IsTerminal as _;
use std::process::ExitCode;

use clap::{CommandFactory as _, Parser};
use minimal::{ExecArgs, PolicyArgs, PolicyOutputFormat};
use tracing_subscriber::fmt::format::{FormatEvent, Writer};
use tracing_subscriber::fmt::{FmtContext, FormatFields};
use tracing_subscriber::{
    EnvFilter, Layer, fmt, fmt::MakeWriter, prelude::*, registry::LookupSpan,
};

/// Custom main: handle shell completion requests before launching the async world.
fn main() -> ExitCode {
    clap_complete::CompleteEnv::with_factory(minimal::Cli::command)
        .var(minimal::COMPLETE_VAR)
        .complete();

    run()
}

#[tokio::main]
async fn run() -> ExitCode {
    // True only when RUST_LOG parsed: a malformed RUST_LOG falls back to the
    // default filter and keeps the plain user-facing format.
    let (filter, rust_log_set) = match EnvFilter::try_from_default_env() {
        Ok(filter) => (filter, true),
        Err(_) => (
            EnvFilter::new("warn")
                .add_directive("topiary=off".parse().unwrap())
                .add_directive("libcgroups=off".parse().unwrap()),
            false,
        ),
    };

    // Invoked as `git-remote-min` (a symlink or copy of this binary): speak
    // the git remote-helper protocol on stdout, so logs must go to stderr.
    if minimal::git_remote::invoked_as_remote_helper() {
        tracing_subscriber::registry()
            .with(fmt::layer().with_writer(std::io::stderr))
            .with(filter)
            .init();

        let args: Vec<String> = std::env::args().skip(1).collect();
        return match minimal::git_remote::run(&args).await {
            Ok(code) => code,
            Err(e) => {
                eprintln!("error: {e:#}");
                ExitCode::FAILURE
            }
        };
    }

    // Parse before installing the subscriber, so the shell completion handler can
    // be configured to log to stderr instead of stdout.
    let cli = minimal::Cli::try_parse()
        .unwrap_or_else(|err| minimal::with_retired_command_hint(err).exit());
    minimal::theme::install();

    // Publish `--vm` before any path resolution, so the socket, the state dir,
    // and any autospawn all name the same VM (NET-052).
    if let Err(e) = cli.global_args.publish_vm_name() {
        eprintln!("error: {e:#}");
        return ExitCode::FAILURE;
    }

    // OTel export (opt-in: MINIMAL_TELEMETRY=1 plus an OTLP endpoint; see
    // mlog::otel): the layers are None when off and carry their own
    // info-level filter when on; the console keeps its own filter, with the
    // OTel SDK's errors silenced.
    mlog::otel::init("minimal-cli");
    // A CLI lives for one command: its exit flush is short, so a collector
    // that is down or silent never shows in a command's wall time.
    mlog::otel::set_exit_flush(mlog::otel::CLI_EXIT_FLUSH);
    let filter = mlog::otel::quiet(filter);
    let registry = tracing_subscriber::registry()
        .with(mlog::otel::span_layer())
        .with(mlog::otel::log_layer());
    // `min dash` owns the terminal (alternate screen); a log line landing on
    // stdout/stderr would corrupt the frame. Log to <state>/dash.log
    // instead, discarding if the state dir can't be written.
    if matches!(cli.command, Some(minimal::Command::Dash)) {
        // Honor `--minimal-dir` so an isolated daemon's logs stay isolated.
        let base = cli
            .global_args
            .minimal_dir
            .clone()
            .unwrap_or_else(|| paths::minimal_state_dir().as_utf8_path().into());
        // Open the log file once; MakeWriter is per-write, so the closure
        // must not re-open it per log event.
        let file = {
            let path = base.join("dash.log");
            let _ = std::fs::create_dir_all(&base);
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map(std::sync::Arc::new)
                .ok()
        };
        let log = move || -> Box<dyn std::io::Write + Send> {
            match &file {
                Some(f) => Box::new(DashLog(f.clone())),
                None => Box::new(std::io::sink()),
            }
        };
        registry
            .with(
                fmt::layer()
                    .with_writer(log)
                    .with_ansi(false)
                    .with_filter(filter),
            )
            .init();
    } else if stdout_is_data_contract(&cli.command) {
        registry
            .with(
                console_layer(
                    std::io::stderr,
                    std::io::stderr().is_terminal(),
                    !rust_log_set,
                )
                .with_filter(filter),
            )
            .init();
    } else {
        registry
            .with(
                console_layer(
                    ot::StderrWriter::new,
                    std::io::stderr().is_terminal(),
                    !rust_log_set,
                )
                .with_filter(filter),
            )
            .init();
    }
    mlog::otel::report_init();

    // The output mode the run is under, read before the CLI is consumed:
    // the error path keys on it (below), so a machine-output run answers a
    // failure with its own contract rather than a plain-text line.
    let output_mode = machine_output_mode(&cli);

    // Only `version` writes its output through a fallible writer; a broken
    // pipe from any other command (e.g. a daemon socket) is a real failure.
    let quiet_on_closed_pipe = matches!(cli.command, Some(minimal::Command::Version));

    // The daily update check (inbox#589): reads its cache, spawns the
    // detached check when one is due, prints a notice once per new release.
    // Never waits, never fails the command.
    minimal::update_check::before_command(&cli.global_args, &cli.command);

    let result = minimal::run(cli).await;
    // Flush exported telemetry (bounded; a no-op when export is off). What
    // the bound cuts off is in the spool already.
    mlog::otel::shutdown(mlog::otel::CLI_EXIT_FLUSH);
    if let Err(e) = result {
        return answer_failure(
            &e,
            output_mode,
            quiet_on_closed_pipe,
            minimal::hosts::failed_run_alias_hint(),
            &mut std::io::stderr(),
        );
    }
    ExitCode::SUCCESS
}

/// How a failed run ends: the exit code, and what goes to `stderr`. The run's
/// stdout is not a parameter, so a failure writes nothing there.
#[expect(
    clippy::let_underscore_must_use,
    reason = "a closed stderr has no reader left to tell; the exit status is \
              the failure's answer either way"
)]
fn answer_failure(
    e: &anyhow::Error,
    machine_mode: bool,
    quiet_on_closed_pipe: bool,
    alias_hint: Option<&str>,
    stderr: &mut dyn std::io::Write,
) -> ExitCode {
    // A task's non-zero exit (`min task run`) is a status to relay, not
    // an error to print — the task's own output already streamed through
    // (the git-remote helper's ExitCode precedent).
    if let Some(&minimal::task::TaskExit(code)) = e.downcast_ref::<minimal::task::TaskExit>() {
        if let Some(hint) = alias_hint {
            let _ = writeln!(stderr, "{hint}");
        }
        return ExitCode::from(code);
    }
    // A machine-output run answers its failure with the one
    // `min/v1/error` object a client parses (BCLI-033), written by the
    // shared output writer, keyed on the output mode the run was under
    // rather than on the command. The object is the contract, so there is
    // no second, plain-text line to print for the same failure, only the
    // non-zero status.
    if machine_mode {
        return match machine_mode_answer(e) {
            MachineModeAnswer::Quiet => ExitCode::from(141),
            MachineModeAnswer::Object(failure) => {
                // BCLI-042: an old spelling's hint is the object's `hint`
                // field, with no separate line.
                let failure = match alias_hint {
                    Some(hint) => failure.with_alias_hint(hint),
                    None => failure,
                };
                emit_machine_mode_error(stderr, &failure);
                ExitCode::from(failure_exit_code(e))
            }
        };
    }
    // A reader that went away (`min version | head -1`) is not an error
    // worth reporting: exit quietly with the shell's SIGPIPE convention.
    if quiet_on_closed_pipe && is_broken_pipe(e) {
        return ExitCode::from(141);
    }
    let _ = writeln!(stderr, "error: {e:#}");
    if let Some(hint) = alias_hint {
        let _ = writeln!(stderr, "{hint}");
    }
    ExitCode::from(failure_exit_code(e))
}

/// The exit code a failed run ends with, from the architecture's reserved
/// codes ("Exit codes"): 2 when a running box holds the name a create
/// asked for (`minimald_rpc::HeldNameRefusal`) or a removal without
/// `--force` finds the box running (`minimal::BoxRunningRefusal`) or a run
/// names an entry with a terminal (`minimal::task::RunNeedsTerminal`), 3
/// when the activation refused the box spec
/// (`boxes::core::bep::ActivationRefused`) or found the project's
/// `minimal.toml` invalid (`minimal::ProjectFileInvalid`) or a GitHub
/// grant undeliverable (`minimal::GrantNotDelivered`), 7 when the VM host could not
/// be reached to register or resume an own-address box's row (provider/host
/// unreachable, #1790), 8 when the host refused the registration for want
/// of addresses (insufficient resources), the code a box address refusal
/// carries (`minimal::BoxAddressRefusal`: 2 when a name matches boxes on
/// more than one host, 4 when the address names no box, 7 when a host did
/// not answer the lookup), the code a `min box exec` refusal carries
/// (`minimal::BoxExecRefusal`: 2 for `-t` without a terminal or a box that
/// is not running, 5 when its spec turns exec off), the code a start
/// refusal carries (`minimal::StartEntryRefusal`: 4 when the start does not
/// find the entry, 2 when it cannot pick or start it), 2 when a start needs a terminal
/// it does not have (`minimal::StartNeedsTerminal`) or asks for a held name
/// (`minimal::StartNameHeld`), 124 when an exec ran past its own timeout
/// (`minimal::BoxExecTimedOut`), and 1, the unspecified error,
/// for everything else — a refusal the host answered included. Both
/// output modes end with the same code.
fn failure_exit_code(e: &anyhow::Error) -> u8 {
    // BEP-008/009/010/017/056: a box spec refused at activation.
    if let Some(refused) = e.downcast_ref::<boxes::core::bep::ActivationRefused>() {
        return refused.exit_code();
    }
    // BCLI-004: `min box rm` of a running box without `--force`.
    if e.downcast_ref::<minimal::BoxRunningRefusal>().is_some() {
        return minimal::BoxRunningRefusal::EXIT_CODE;
    }
    // BCLI-010: `min task run` or `min box run` of an entry with a terminal.
    if e.downcast_ref::<minimal::task::RunNeedsTerminal>()
        .is_some()
    {
        return minimal::task::RunNeedsTerminal::EXIT_CODE;
    }
    // BCLI-058: `min box rename` to a name BOX-010 refuses.
    if e.downcast_ref::<minimal::BoxRenameRefusal>().is_some() {
        return minimal::BoxRenameRefusal::EXIT_CODE;
    }
    // BCLI-005: `min box prune` off a terminal without `--yes`.
    if e.downcast_ref::<minimal::PruneNeedsYes>().is_some() {
        return minimal::PruneNeedsYes::EXIT_CODE;
    }
    // BCLI-029: a start off a terminal of an entry with a terminal.
    if e.downcast_ref::<minimal::StartNeedsTerminal>().is_some() {
        return minimal::StartNeedsTerminal::EXIT_CODE;
    }
    // BCLI-071, BCLI-072: a start that cannot pick or start its entry.
    if let Some(refusal) = e.downcast_ref::<minimal::StartEntryRefusal>() {
        return refusal.exit_code();
    }
    // BCLI-069: a start whose name a running box holds.
    if e.downcast_ref::<minimal::StartNameHeld>().is_some() {
        return minimal::StartNameHeld::EXIT_CODE;
    }
    // BOX-163: a create under a name a running box holds.
    if e.downcast_ref::<minimald_rpc::HeldNameRefusal>().is_some() {
        return minimald_rpc::HeldNameRefusal::EXIT_CODE;
    }
    // NET-060: a project `minimal.toml` whose session entry the start
    // cannot pick refuses the activation with exit 2.
    if e.downcast_ref::<minimal::SessionEntryUndecided>().is_some() {
        return minimal::SessionEntryUndecided::EXIT_CODE;
    }
    // An invalid project `minimal.toml` refuses the activation with exit 3.
    if e.downcast_ref::<minimal::ProjectFileInvalid>().is_some() {
        return 3;
    }
    // BEP-007: a GitHub grant the box cannot receive in its environment.
    if e.downcast_ref::<minimal::GrantNotDelivered>().is_some() {
        return 3;
    }
    if e.downcast_ref::<minimal_client::box_registration::HostUnreachable>()
        .is_some()
    {
        return 7;
    }
    if e.downcast_ref::<minimal_client::box_registration::HostAddressesExhausted>()
        .is_some()
    {
        return 8;
    }
    // BCLI-002, BCLI-064: a box address that names no single box.
    if let Some(refused) = e.downcast_ref::<minimal::BoxAddressRefusal>() {
        return refused.exit_code();
    }
    // BCLI-068: `min box attach` refused, or its connection failed.
    if let Some(refused) = e.downcast_ref::<minimal::BoxAttachRefusal>() {
        return refused.exit_code();
    }
    // BCLI-053: `min box exec -t` without a terminal, or into a box that is
    // not running (2), or whose spec turns exec off (5).
    if let Some(refused) = e.downcast_ref::<minimal::BoxExecRefusal>() {
        return refused.exit_code();
    }
    // BCLI-053: an exec that its own timeout ended.
    if e.downcast_ref::<minimal::BoxExecTimedOut>().is_some() {
        return minimal::BoxExecTimedOut::EXIT_CODE;
    }
    // BCLI-018: `min init` refused a request (2) or a type (3).
    if let Some(refusal) = e.downcast_ref::<minimal::InitRefusal>() {
        return refusal.code;
    }
    // BCLI-034, BCLI-062: `min box cp` of a file the box does not have, or
    // does not allow reading.
    if let Some(refused) = e.downcast_ref::<minimal::BoxFileRefusal>() {
        return refused.exit_code();
    }
    1
}

/// Whether the error's root cause is a broken pipe: the writer's reader
/// closed before all output was written. Rust ignores SIGPIPE by default, so
/// this surfaces as an `io::Error` of kind `BrokenPipe` instead of a signal.
fn is_broken_pipe(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe)
    })
}

/// How a machine-output run answers a failure.
#[derive(Debug, PartialEq, Eq)]
enum MachineModeAnswer {
    /// The reader of the document went away: exit 141 (the shell's SIGPIPE
    /// convention) with nothing on stderr, which nobody is reading either.
    Quiet,
    /// The one `min/v1/error` object, on stderr.
    Object(minimal::MachineModeFailure),
}

/// The machine-mode answer to a failed run, shared by every command that
/// takes `-o json`: in a machine mode every failure is the one error object
/// (or, for a reader that hung up, nothing). A walk's own failure is the
/// payload it already failed into. A broken pipe means the consumer hung
/// up, so the run exits quietly. A failure the command tagged as its own
/// document write ([`minimal::OutputWriteError`]) is `output_failed`, so a
/// script can tell it from a crash. A VM host that could not be reached is
/// `host_unreachable`, and one out of addresses `insufficient_resources`,
/// beside the exit codes [`failure_exit_code`] gives them. Anything else is
/// `unspecified`, the exit table's unspecified error, with the chain as its
/// message and no hint, because nothing about it is known to name a remedy.
fn machine_mode_answer(e: &anyhow::Error) -> MachineModeAnswer {
    if let Some(failure) = e.downcast_ref::<minimal::MachineModeFailure>() {
        return MachineModeAnswer::Object(failure.clone());
    }
    if is_broken_pipe(e) {
        return MachineModeAnswer::Quiet;
    }
    if e.downcast_ref::<minimal_client::box_registration::HostUnreachable>()
        .is_some()
    {
        return MachineModeAnswer::Object(minimal::MachineModeFailure::new(
            "host_unreachable",
            format!("{e:#}"),
            "the VM host daemon is not answering; check that it is running (`minvmd status`)"
                .to_string(),
        ));
    }
    if e.downcast_ref::<minimal_client::box_registration::HostAddressesExhausted>()
        .is_some()
    {
        return MachineModeAnswer::Object(minimal::MachineModeFailure::new(
            "insufficient_resources",
            format!("{e:#}"),
            "the VM host has no address left for another box; destroy a session you no \
             longer need and try again"
                .to_string(),
        ));
    }
    if let Some(refused) = e.downcast_ref::<minimal::AuditSelfUnsupportedUnenrolled>() {
        return MachineModeAnswer::Object(minimal::MachineModeFailure::new(
            refused.code(),
            format!("{e:#}"),
            "on the host, run `min box audit <box>`".to_string(),
        ));
    }
    // BEP-003, Gatehouse §6.2: a refused activation with a defined error
    // answers with that error and its next step.
    if let Some((code, hint)) = e
        .downcast_ref::<boxes::core::bep::ActivationRefused>()
        .and_then(|refused| {
            refused
                .refusals
                .iter()
                .find_map(|refusal| Some((refusal.code()?, refusal.next_step()?)))
        })
    {
        return MachineModeAnswer::Object(minimal::MachineModeFailure::new(
            code,
            format!("{e:#}"),
            hint,
        ));
    }
    // BCLI-053: an exec that its own timeout ended is `timeout`.
    if let Some(timed_out) = e.downcast_ref::<minimal::BoxExecTimedOut>() {
        return MachineModeAnswer::Object(minimal::MachineModeFailure::new(
            minimal::BoxExecTimedOut::CODE,
            format!("{e:#}"),
            timed_out.hint().to_string(),
        ));
    }
    if e.downcast_ref::<minimal::OutputWriteError>().is_some() {
        return MachineModeAnswer::Object(minimal::MachineModeFailure::new(
            "output_failed",
            format!("{e:#}"),
            "stdout could not be written; check the destination (a full disk, a closed \
             descriptor)"
                .to_string(),
        ));
    }
    MachineModeAnswer::Object(minimal::MachineModeFailure::new(
        "unspecified",
        format!("{e:#}"),
        String::new(),
    ))
}

/// A cheaply clonable writer over the dash log file: every clone writes
/// through the same opened file (append mode) instead of re-opening it.
struct DashLog(std::sync::Arc<std::fs::File>);

impl std::io::Write for DashLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (&*self.0).write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        (&*self.0).flush()
    }
}

/// Whether the command's stdout is a data contract that tracing must not
/// pollute, so its logs go to stderr instead. The `completions` handlers emit a
/// shell shim on stdout, `session exec` carries only the exec'd
/// command's output, `box exec` carries the command's output or its exec
/// id, and `task run` / `session run` stream the task's stdout —
/// a log line in any of them would be read as content. A bare `min` (no subcommand) is
/// one too: its non-TTY twin promises an empty stdout to pipelines, and its
/// interactive activate path prints only the session id there. So is
/// `session policy -o json`, whose stdout is one document a script parses.
fn stdout_is_data_contract(command: &Option<minimal::Command>) -> bool {
    matches!(
        command,
        None | Some(
            minimal::Command::CompleteSessionStr(_)
                | minimal::Command::Completions(_)
                | minimal::Command::Session(minimal::SessionArgs {
                    command: minimal::SessionCommand::Exec(ExecArgs { .. })
                        | minimal::SessionCommand::Run(_)
                        | minimal::SessionCommand::Policy(PolicyArgs {
                            output: Some(PolicyOutputFormat::Json),
                            ..
                        }),
                })
                | minimal::Command::Task(minimal::TaskArgs {
                    command: minimal::TaskCommand::Run(_),
                })
                | minimal::Command::Box(minimal::BoxArgs {
                    command: minimal::BoxCommand::Exec(_) | minimal::BoxCommand::Run(_),
                })
        )
    )
}

/// The console log layer. `plain` (no `RUST_LOG` in effect) renders through
/// [`PlainFormat`]: `warning:`/`error:` lines matching the rest of the CLI;
/// otherwise the full tracing format is kept for debugging.
fn console_layer<S, W>(writer: W, ansi: bool, plain: bool) -> Box<dyn Layer<S> + Send + Sync>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let layer = fmt::layer().with_writer(writer).with_ansi(ansi);
    if plain {
        layer.event_format(PlainFormat).boxed()
    } else {
        layer.boxed()
    }
}

/// The plain console format: `warning: <message>` for WARN, `error: <message>`
/// for ERROR, and the bare message for INFO and below. A message that already
/// starts with `help:` is written as a help line with no level prefix. Span
/// context is omitted on purpose: these lines are for a person, not debugging.
struct PlainFormat;

impl<S, N> FormatEvent<S, N> for PlainFormat
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        let mut message = MessageVisitor::default();
        event.record(&mut message);

        match *event.metadata().level() {
            tracing::Level::WARN => {
                if !message.0.as_deref().is_some_and(|m| m.starts_with("help:")) {
                    write!(writer, "warning: ")?;
                }
            }
            tracing::Level::ERROR => write!(writer, "error: ")?,
            _ => {}
        }

        ctx.format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

/// Captures the event's `message` field, so the formatter can decide whether
/// to prefix a level.
#[derive(Default)]
struct MessageVisitor(Option<String>);

impl tracing::field::Visit for MessageVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0 = Some(value.to_owned());
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = Some(format!("{value:?}"));
        }
    }
}

/// Whether a run is under the machine output mode: the command's `-o`, the
/// flag the architecture's machine-output contract hangs on — `json` for
/// `min session policy -o json` and `jsonl` for `min box audit -o jsonl`.
/// `false` for every text run, and for a command that has not taken a
/// machine `-o` yet, which is the same thing to the error path: its failure
/// is a plain-text line. The error path keys on this, so a command joins
/// the machine mode by growing an `output` flag, and nothing else about its
/// error path changes.
fn machine_output_mode(cli: &minimal::Cli) -> bool {
    match &cli.command {
        Some(minimal::Command::Session(minimal::SessionArgs {
            command: minimal::SessionCommand::Policy(PolicyArgs { output, .. }),
        })) => output.is_some(),
        // Architecture line 379: a `-o jsonl` failure is one `min/v1/error`
        // object too.
        Some(minimal::Command::Box(minimal::BoxArgs {
            command: minimal::BoxCommand::Audit(args),
        })) => args.output == Some(minimal::BoxAuditOutputFormat::Jsonl),
        // Architecture line 383: a `min box list -o json` failure is one
        // `min/v1/error` object (BCLI-001).
        Some(minimal::Command::Box(minimal::BoxArgs {
            command: minimal::BoxCommand::List(args),
        })) => args.output.is_some(),
        // BCLI-016: a `min box events -o jsonl` failure is one
        // `min/v1/error` object too.
        Some(minimal::Command::Box(minimal::BoxArgs {
            command: minimal::BoxCommand::Events(args),
        })) => args.output == Some(minimal::BoxEventsOutputFormat::Jsonl),
        _ => false,
    }
}

/// The machine-mode error object, encoded as one line by the shared output
/// writer: the `min/v1/error` stamp, the `code` a script branches on, the
/// message, and the hint — nothing else on the line, and no line beside it.
#[cfg(test)]
fn machine_mode_error_line(failure: &minimal::MachineModeFailure) -> anyhow::Result<String> {
    Ok(minimal::output::error_line(failure)?)
}

/// The machine-mode error emitter: writes the one `min/v1/error` object on
/// stderr, the only thing the mode puts there on any failure, so a client
/// parses a failure the same way it parses the document. A command that
/// takes `-o json` fails its walk into [`minimal::MachineModeFailure`] —
/// carried through the `anyhow` chain, the way [`minimal::task::TaskExit`]
/// is — and needs nothing else. `min ls --json` and its kin are untouched:
/// their failure stays the plain-text line it always was.
#[expect(
    clippy::let_underscore_must_use,
    reason = "a closed stderr has no reader left to tell; the exit status is \
              the failure's answer either way"
)]
fn emit_machine_mode_error(stderr: &mut dyn std::io::Write, failure: &minimal::MachineModeFailure) {
    // One object, one line. The exit code is non-zero either way.
    let _ = minimal::output::write_error(stderr, failure);
}

#[cfg(test)]
mod tests {
    use super::*;
    use minimal::Command;

    /// A bare `min` (no subcommand) keeps stdout clean: the non-TTY twin
    /// promises pipelines an empty stdout, so its tracing must go to stderr.
    #[test]
    fn bare_min_is_a_stdout_contract() {
        assert!(stdout_is_data_contract(&None));
    }

    /// `min session run` streams the task's stdout over the exec channel, so
    /// tracing must route to stderr like the other stdout contracts.
    #[test]
    fn session_run_is_a_stdout_contract() {
        let cmd = Some(Command::Session(minimal::SessionArgs {
            command: minimal::SessionCommand::Run(minimal::SessionRunArgs {
                session: "web".to_string(),
                task: "build".to_string(),
            }),
        }));
        assert!(stdout_is_data_contract(&cmd));
    }

    /// `min task run` streams the task's stdout, so tracing must route to
    /// stderr there like the other stdout contracts.
    #[test]
    fn task_run_is_a_stdout_contract() {
        let cmd = Some(Command::Task(minimal::TaskArgs {
            command: minimal::TaskCommand::Run(minimal::TaskRunArgs {
                task: "build".to_string(),
                path: None,
                detach: false,
                args: vec![],
            }),
        }));
        assert!(stdout_is_data_contract(&cmd));
    }

    /// A `MakeWriter` that appends to a shared buffer, so tests can assert on
    /// the exact rendered log line.
    struct BufferWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for BufferWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Without `RUST_LOG`, a warning renders as `warning: <message>` — no
    /// timestamp and no target.
    #[test]
    fn console_layer_renders_plain_warning() {
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = {
            let buf = buf.clone();
            move || BufferWriter(buf.clone())
        };
        let layer = console_layer(writer, false, true);
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(key = "value", "lifecycle_hooks is unknown");
        });
        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert_eq!(out, "warning: lifecycle_hooks is unknown key=\"value\"\n");
    }

    /// A WARN event whose message already starts with `help:` renders as a
    /// bare help line, with no level prefix.
    #[test]
    fn console_layer_renders_help_line_without_level() {
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = {
            let buf = buf.clone();
            move || BufferWriter(buf.clone())
        };
        let layer = console_layer(writer, false, true);
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!("help: do you need to update to a newer version of minimal?");
        });
        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert_eq!(
            out,
            "help: do you need to update to a newer version of minimal?\n"
        );
    }

    /// An ERROR event renders as `error: <message>`.
    #[test]
    fn console_layer_renders_plain_error() {
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = {
            let buf = buf.clone();
            move || BufferWriter(buf.clone())
        };
        let layer = console_layer(writer, false, true);
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(key = "value", "something failed");
        });
        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert_eq!(out, "error: something failed key=\"value\"\n");
    }

    /// With `RUST_LOG` set, the full tracing format (timestamp and target) is
    /// kept for debugging.
    #[test]
    fn console_layer_keeps_full_format_with_rust_log() {
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = {
            let buf = buf.clone();
            move || BufferWriter(buf.clone())
        };
        let layer = console_layer(writer, false, false);
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(key = "value", "lifecycle_hooks is unknown");
        });
        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(out.contains("min::tests:"), "target missing: {out:?}");
        assert!(out.contains(" WARN "), "level missing: {out:?}");
        assert!(
            out.contains("lifecycle_hooks is unknown"),
            "message missing: {out:?}"
        );
        assert!(
            out.as_bytes().first().is_some_and(u8::is_ascii_digit),
            "timestamp missing: {out:?}"
        );
    }

    /// `min session policy -o json` writes one document a script parses, so
    /// its tracing must route to stderr — and the text rendering, whose
    /// stdout is for a person, must not be caught by the same gate.
    #[test]
    fn session_policy_json_is_a_stdout_contract() {
        let cmd = Some(Command::Session(minimal::SessionArgs {
            command: minimal::SessionCommand::Policy(PolicyArgs {
                session: "web".to_string(),
                output: Some(PolicyOutputFormat::Json),
            }),
        }));
        assert!(stdout_is_data_contract(&cmd));
        let cmd = Some(Command::Session(minimal::SessionArgs {
            command: minimal::SessionCommand::Policy(PolicyArgs {
                session: "web".to_string(),
                output: None,
            }),
        }));
        assert!(!stdout_is_data_contract(&cmd));
    }

    /// The error path's key: a `-o json` run is a machine-output run, a text
    /// run is not, and a command that has not taken `-o json` yet is not
    /// either — the same three-way split the subscriber gate makes, read
    /// before the CLI is consumed so the failed run can still be asked what
    /// mode it was in.
    /// A walk's payload, a hung-up reader, a tagged document write and any
    /// other failure each get their own machine-mode answer.
    #[test]
    fn machine_mode_answers_write_failures() {
        let walk = minimal::MachineModeFailure::new(
            "not_found",
            "no session".to_string(),
            "hint".to_string(),
        );
        assert_eq!(
            machine_mode_answer(&anyhow::Error::new(walk.clone())),
            MachineModeAnswer::Object(walk)
        );

        let hung_up = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            .context(minimal::OutputWriteError);
        assert_eq!(machine_mode_answer(&hung_up), MachineModeAnswer::Quiet);

        let full = anyhow::Error::new(std::io::Error::other("no space left on device"))
            .context(minimal::OutputWriteError);
        match machine_mode_answer(&full) {
            MachineModeAnswer::Object(failure) => {
                assert_eq!(failure.code(), "output_failed");
                assert!(
                    failure.message().contains("no space left on device"),
                    "the message carries the io chain: {}",
                    failure.message()
                );
            }
            other => panic!("a failed document write answers output_failed, got {other:?}"),
        }

        // An io error the run met elsewhere (a config read, a socket) is
        // not the document's write: it must not claim stdout failed.
        let elsewhere = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::NotFound))
            .context("reading the config");
        for unrelated in [elsewhere, anyhow::anyhow!("something else")] {
            match machine_mode_answer(&unrelated) {
                MachineModeAnswer::Object(failure) => {
                    assert_eq!(failure.code(), "unspecified", "for {unrelated:#}");
                    assert!(failure.hint().is_empty(), "no remedy is known");
                }
                other => panic!("an unmapped failure is still an object, got {other:?}"),
            }
        }
    }

    // BEP-003, Gatehouse §6.2: a refused grant box reads as its defined
    // error under `-o json`, with the refusal's next step as the hint.
    #[test]
    fn machine_mode_names_the_grant_refusal_code() {
        use boxes::core::bep::{ActivationRefused, BepRefusal, ProxyAbsence};
        let answer = |refusal: BepRefusal| match machine_mode_answer(&anyhow::Error::new(
            ActivationRefused {
                refusals: vec![refusal],
            },
        )) {
            MachineModeAnswer::Object(failure) => failure,
            other => panic!("a refusal is an object, got {other:?}"),
        };
        let grants = vec!["GH_TOKEN".to_owned()];

        let failure = answer(BepRefusal::SignInRequired {
            grants: grants.clone(),
        });
        assert_eq!(failure.code(), "github_sign_in_required");
        assert_eq!(
            failure.hint(),
            "run `min auth login`, then create the box again"
        );
        assert!(failure.message().contains("Run `min auth login`"));

        let failure = answer(BepRefusal::UnenrolledNode {
            grants,
            stored: false,
            cause: ProxyAbsence::NotInstalled { path: None },
        });
        assert_eq!(failure.code(), "gatehouse_unenrolled_node");
        assert_eq!(
            failure.hint(),
            "to create the box without the grant, remove GH_TOKEN from [session.secrets] \
             in minimal.toml"
        );

        // A refusal with no defined error stays `unspecified`.
        let failure = answer(BepRefusal::SteeringOffWithProxyEnv);
        assert_eq!(failure.code(), "unspecified");
        assert!(failure.hint().is_empty());
    }

    /// An `unspecified` object still carries the `hint` key, empty, so
    /// every error object has `code`, `message` and `hint` (BCLI-033).
    #[test]
    fn machine_mode_error_line_keeps_an_empty_hint() {
        let line = machine_mode_error_line(&minimal::MachineModeFailure::new(
            "unspecified",
            "boom".to_string(),
            String::new(),
        ))
        .unwrap();
        assert!(line.contains(r#""hint":"""#), "got {line}");
        assert!(line.contains(r#""code":"unspecified""#), "got {line}");
    }

    /// BCLI-033: a failure under a machine output mode is one `min/v1/error`
    /// object on stderr with `code`, `message` and `hint`, and no
    /// plain-text line. The text mode keeps its `error:` line. Both end
    /// with the same exit code.
    #[test]
    fn machine_mode_error_object_on_stderr() {
        let failures = [
            anyhow::Error::new(minimal::MachineModeFailure::new(
                "not_found",
                "no box matches 'gone'".to_string(),
                "`min box list` lists the boxes there are".to_string(),
            )),
            anyhow::anyhow!("the daemon went away"),
        ];
        for e in &failures {
            let mut stderr = Vec::new();
            let code = answer_failure(e, true, false, None, &mut stderr);
            assert_eq!(code, ExitCode::from(1));
            let text = String::from_utf8(stderr).unwrap();
            assert_eq!(text.lines().count(), 1, "one object, one line: {text}");
            assert!(!text.contains("error:"), "no text line beside it: {text}");
            let object: serde_json_lenient::Value = serde_json_lenient::from_str(&text).unwrap();
            assert_eq!(object["schema"], "min/v1/error", "{text}");
            for key in ["code", "message", "hint"] {
                assert!(object[key].is_string(), "{key} is present: {text}");
            }

            let mut stderr = Vec::new();
            let code = answer_failure(e, false, false, None, &mut stderr);
            assert_eq!(code, ExitCode::from(1));
            let text = String::from_utf8(stderr).unwrap();
            assert!(
                text.starts_with("error: "),
                "text mode keeps its line: {text}"
            );
        }
        let object: serde_json_lenient::Value = {
            let mut stderr = Vec::new();
            answer_failure(&failures[0], true, false, None, &mut stderr);
            serde_json_lenient::from_slice(&stderr).unwrap()
        };
        assert_eq!(object["code"], "not_found");
        assert_eq!(object["message"], "no box matches 'gone'");
        assert_eq!(object["hint"], "`min box list` lists the boxes there are");
    }

    /// BCLI-042, BCLI-046: an old spelling's hint on a failed run is the
    /// error object's `hint` field in a machine output mode, with no
    /// separate line. The text mode prints it after its `error:` line.
    #[test]
    fn alias_hint_is_the_error_objects_hint() {
        let hint = "local-minimald is now called local.";
        let e = anyhow::anyhow!("the daemon went away");
        let mut stderr = Vec::new();
        answer_failure(&e, true, false, Some(hint), &mut stderr);
        let text = String::from_utf8(stderr).unwrap();
        assert_eq!(text.lines().count(), 1, "one object, one line: {text}");
        let object: serde_json_lenient::Value = serde_json_lenient::from_str(&text).unwrap();
        assert_eq!(object["hint"], hint);

        let mut stderr = Vec::new();
        answer_failure(&e, false, false, Some(hint), &mut stderr);
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            format!("error: the daemon went away\n{hint}\n")
        );
    }

    #[test]
    fn machine_output_mode_keys_on_the_output_flag() {
        let cli = minimal::Cli {
            global_args: minimal::GlobalArgs::default(),
            command: Some(Command::Session(minimal::SessionArgs {
                command: minimal::SessionCommand::Policy(PolicyArgs {
                    session: "web".to_string(),
                    output: Some(PolicyOutputFormat::Json),
                }),
            })),
        };
        assert!(machine_output_mode(&cli));

        let cli = minimal::Cli {
            global_args: minimal::GlobalArgs::default(),
            command: Some(Command::Session(minimal::SessionArgs {
                command: minimal::SessionCommand::Policy(PolicyArgs {
                    session: "web".to_string(),
                    output: None,
                }),
            })),
        };
        assert!(!machine_output_mode(&cli));

        let cli = minimal::Cli {
            global_args: minimal::GlobalArgs::default(),
            command: None,
        };
        assert!(!machine_output_mode(&cli));

        // `min box audit -o jsonl` is a machine mode, its text form is not.
        for (output, machine) in [
            (Some(minimal::BoxAuditOutputFormat::Jsonl), true),
            (None, false),
        ] {
            let cli = minimal::Cli {
                global_args: minimal::GlobalArgs::default(),
                command: Some(Command::Box(minimal::BoxArgs {
                    command: minimal::BoxCommand::Audit(minimal::BoxAuditArgs {
                        target: Some("self".to_string()),
                        parent: None,
                        output,
                        follow: false,
                    }),
                })),
            };
            assert_eq!(machine_output_mode(&cli), machine);
        }

        // `min box list -o json` is a machine mode, its table form is not.
        for (output, machine) in [
            (Some(minimal::BoxListOutputFormat::Json), true),
            (None, false),
        ] {
            let cli = minimal::Cli {
                global_args: minimal::GlobalArgs::default(),
                command: Some(Command::Box(minimal::BoxArgs {
                    command: minimal::BoxCommand::List(minimal::BoxListArgs { all: false, output }),
                })),
            };
            assert_eq!(machine_output_mode(&cli), machine);
        }

        // `min box events -o jsonl` is a machine mode, its text form is not.
        for (output, machine) in [
            (Some(minimal::BoxEventsOutputFormat::Jsonl), true),
            (None, false),
        ] {
            let cli = minimal::Cli {
                global_args: minimal::GlobalArgs::default(),
                command: Some(Command::Box(minimal::BoxArgs {
                    command: minimal::BoxCommand::Events(minimal::BoxEventsArgs {
                        target: Some("web".to_string()),
                        parent: None,
                        output,
                        follow: false,
                    }),
                })),
            };
            assert_eq!(machine_output_mode(&cli), machine);
        }

        // Its defined refusal answers with its own code.
        match machine_mode_answer(&anyhow::Error::new(minimal::AuditSelfUnsupportedUnenrolled)) {
            MachineModeAnswer::Object(failure) => {
                assert_eq!(failure.code(), "audit_self_unsupported_unenrolled");
            }
            other => panic!("the refusal answers with its code, got {other:?}"),
        }
    }

    /// The one object a machine-output failure answers with: a
    /// `min/v1/error` stamp, the `code` a script branches on, the message,
    /// and the hint — one line, nothing else, so a client parses a failure
    /// the same way it parses the document. Pinned here, beside the emitter
    /// that writes it.
    #[test]
    fn machine_mode_error_object_is_one_stamped_line() {
        let failure = minimal::MachineModeFailure::new(
            "not_found",
            "No session found matching 'gone'".to_string(),
            "no session by that name or id exists; `min ls` lists the \
             sessions there are"
                .to_string(),
        );
        let line = machine_mode_error_line(&failure).unwrap();
        let document: serde_json_lenient::Value =
            serde_json_lenient::from_str(line.trim_end()).unwrap();
        assert_eq!(
            document["schema"].as_str(),
            Some("min/v1/error"),
            "the failure object carries its own schema stamp: {line}"
        );
        assert_eq!(
            document["code"].as_str(),
            Some("not_found"),
            "the failure's kind is a name, not a message to parse: {line}"
        );
        assert_eq!(
            document["message"].as_str(),
            Some("No session found matching 'gone'"),
            "the message beside it, the kind of thing that was missing: {line}"
        );
        assert_eq!(
            document["hint"].as_str(),
            Some("no session by that name or id exists; `min ls` lists the sessions there are"),
            "the hint names the remedy, and the kind of thing that was missing: {line}"
        );
        assert_eq!(
            line.lines().count(),
            1,
            "one object, one line, nothing else: {line}"
        );
    }

    #[test]
    fn box_address_refusals_exit_with_their_codes() {
        let address = |s: &str| s.to_owned();
        for (refusal, code) in [
            (
                minimal::BoxAddressRefusal::NotFound {
                    address: address("web"),
                },
                4,
            ),
            (
                minimal::BoxAddressRefusal::Unreachable {
                    address: address("web"),
                    hosts: vec![address("beta.local-minvmd0")],
                },
                7,
            ),
            (
                minimal::BoxAddressRefusal::Ambiguous {
                    name: address("web"),
                    candidates: Vec::new(),
                },
                2,
            ),
        ] {
            let err = anyhow::Error::from(refusal).context("showing the box");
            assert_eq!(failure_exit_code(&err), code, "{err:#}");
        }
    }

    /// BCLI-071, BCLI-072: a start that does not find its entry exits 4,
    /// not found. Every other start refusal exits 2.
    #[test]
    fn start_entry_refusals_exit_with_their_codes() {
        use minimal::{StartEntryRefusal, StartVerb};
        let entry = || "build".to_owned();
        for (refusal, code) in [
            (
                StartEntryRefusal::Unknown {
                    verb: StartVerb::Box,
                    entry: entry(),
                    entries: Vec::new(),
                },
                4,
            ),
            (
                StartEntryRefusal::NotSession {
                    entry: entry(),
                    box_type: Some("task".to_owned()),
                },
                4,
            ),
            (
                StartEntryRefusal::Several {
                    verb: StartVerb::Session,
                    entries: Vec::new(),
                },
                2,
            ),
            (StartEntryRefusal::DefaultBlocked { box_type: None }, 2),
            (StartEntryRefusal::NameUnsupported { entry: entry() }, 2),
            (StartEntryRefusal::TaskNotInTasks { entry: entry() }, 2),
            (
                StartEntryRefusal::UnsupportedType {
                    entry: entry(),
                    box_type: Some("agent".to_owned()),
                },
                2,
            ),
            (
                StartEntryRefusal::NamedSessionUnsupported {
                    verb: StartVerb::Session,
                    entry: entry(),
                },
                2,
            ),
        ] {
            let err = anyhow::Error::new(refusal);
            assert_eq!(failure_exit_code(&err), code, "{err:#}");
        }
    }

    /// BCLI-053: an exec that its own timeout ended ends the run with 124
    /// in both output modes, and a machine-mode run answers it with the
    /// `timeout` object. The exec refusals end with 2 and 5.
    #[test]
    fn exec_timeout_returns_124_from_exec_and_wait_exec_in_machine_mode() {
        for timed_out in [
            minimal::BoxExecTimedOut::exec("web", 30),
            minimal::BoxExecTimedOut::waited("web", "0190a3c4-0000-7000-8000-000000000000"),
        ] {
            let e = anyhow::Error::new(timed_out.clone());
            assert_eq!(failure_exit_code(&e), 124);
            match machine_mode_answer(&e) {
                MachineModeAnswer::Object(failure) => {
                    assert_eq!(failure.code(), "timeout");
                    assert_eq!(failure.message(), timed_out.to_string());
                    assert_eq!(failure.hint(), timed_out.hint());
                }
                MachineModeAnswer::Quiet => panic!("a timeout is an error object"),
            }
            let mut stderr = Vec::new();
            assert_eq!(
                answer_failure(&e, true, false, None, &mut stderr),
                ExitCode::from(124)
            );
            let line = String::from_utf8(stderr).unwrap();
            assert!(line.contains(r#""code":"timeout""#), "{line}");
        }
        let target = "web".to_string();
        for (refusal, code) in [
            (
                minimal::BoxExecRefusal::NoTerminal {
                    target: target.clone(),
                },
                2,
            ),
            (
                minimal::BoxExecRefusal::NotRunning {
                    target: target.clone(),
                    state: "stopped".to_string(),
                },
                2,
            ),
            (
                minimal::BoxExecRefusal::ExecDisabled {
                    target: target.clone(),
                },
                5,
            ),
            (minimal::BoxExecRefusal::SpecUnreadable { target }, 5),
        ] {
            assert_eq!(failure_exit_code(&anyhow::Error::new(refusal)), code);
        }
    }

    /// BCLI-018: `min init` ends with 2 when it gets more than one type
    /// flag, and with 3 for a type this release refuses.
    #[test]
    fn init_refusals_exit_with_their_codes() {
        for (refusal, code) in [
            (
                minimal::InitRefusal {
                    code: 2,
                    message: minimal::INIT_ONE_TYPE_FLAG.to_owned(),
                },
                2,
            ),
            (
                minimal::InitRefusal {
                    code: 3,
                    message: "min init did not add the entry worker: type agent is not \
                              supported yet."
                        .to_owned(),
                },
                3,
            ),
        ] {
            assert_eq!(failure_exit_code(&anyhow::Error::new(refusal)), code);
        }
    }

    /// BCLI-034: `min box cp` ends with 4 for a file the box does not have,
    /// and 5 for a file the box does not allow reading.
    #[test]
    fn box_file_refusals_exit_with_their_codes() {
        for (refusal, code) in [
            (
                minimal::BoxFileRefusal::NotFound {
                    address: "web".to_owned(),
                    path: "out.txt".to_owned(),
                },
                4,
            ),
            (
                minimal::BoxFileRefusal::PermissionDenied {
                    address: "web".to_owned(),
                    path: "secret.txt".to_owned(),
                },
                5,
            ),
        ] {
            let err = anyhow::Error::new(refusal).context("copying the file");
            assert_eq!(failure_exit_code(&err), code, "{err:#}");
        }
    }

    /// #1790: a VM host that could not be reached ends the run with 7 —
    /// provider/host unreachable — found through every context the
    /// activation adds over it, and a machine-mode run answers it with the
    /// `host_unreachable` object and the same code. Any other failure stays
    /// the unspecified error, 1, in both modes.
    #[test]
    fn host_unreachable_exits_7_in_both_output_modes() {
        let unreachable = minimal_client::box_registration::HostUnreachable::over(
            std::io::Error::from(std::io::ErrorKind::NotFound),
            "connecting to the VM host daemon's box control socket at /x/control.sock",
        )
        .context("registering the box with the VM host daemon failed")
        .context("activating the session");
        assert_eq!(failure_exit_code(&unreachable), 7);
        match machine_mode_answer(&unreachable) {
            MachineModeAnswer::Object(failure) => {
                assert_eq!(failure.code(), "host_unreachable");
                assert!(
                    failure.message().contains("/x/control.sock"),
                    "the message is the chain the text mode prints: {}",
                    failure.message()
                );
            }
            MachineModeAnswer::Quiet => panic!("an unreachable host is an error object"),
        }

        let refused = anyhow::anyhow!("the VM host daemon refused the box registration: no");
        assert_eq!(failure_exit_code(&refused), 1);
        match machine_mode_answer(&refused) {
            MachineModeAnswer::Object(failure) => assert_eq!(failure.code(), "unspecified"),
            MachineModeAnswer::Quiet => panic!("a refusal is an error object"),
        }
    }

    /// BEP-008: a box spec the activation refused ends the run with exit 3,
    /// through the context the activation adds over it, and the message
    /// names each missing host. `cmd::session`'s test of the same name
    /// proves the refusal comes before the create.
    #[test]
    fn activation_refuses_grant_before_create_with_exit_3() {
        let refused = boxes::core::bep::ActivationRefused {
            refusals: vec![boxes::core::bep::BepRefusal::HostsOutsideEgress {
                missing: vec!["uploads.github.com".into(), "codeload.github.com".into()],
            }],
        };
        let e = anyhow::Error::new(refused).context("activating the session");
        assert_eq!(failure_exit_code(&e), 3);
        let text = format!("{:#}", e.root_cause());
        assert!(
            text.contains("does not allow: uploads.github.com, codeload.github.com."),
            "{text}"
        );
    }

    /// BEP-007: a GitHub grant the box cannot receive ends the run with
    /// exit 3, through the context the activation adds over it.
    #[test]
    fn an_undeliverable_grant_ends_with_exit_3() {
        let refused = minimal::GrantNotDelivered::NotSealed {
            grant: "GH_TOKEN".into(),
        };
        let e = anyhow::Error::new(refused).context("activating the session");
        assert_eq!(failure_exit_code(&e), 3);
    }

    /// BCLI-005: `min box prune` off a terminal without `--yes` ends with
    /// exit 2, and the text names `--yes`.
    #[test]
    fn prune_off_tty_needs_yes_exits_2() {
        let e = anyhow::Error::new(minimal::PruneNeedsYes);
        assert_eq!(failure_exit_code(&e), 2);
        let mut stderr = Vec::new();
        let code = answer_failure(&e, false, false, None, &mut stderr);
        assert_eq!(code, ExitCode::from(2));
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "error: Prune removes boxes. Pass --yes to confirm, \
             or --dry-run to see what it would remove.\n"
        );
    }

    /// BCLI-004: `min box rm` of a running box without `--force` ends with
    /// exit 2 in both output modes. The text mode prints the refusal, which
    /// names `--force`, on stderr.
    #[test]
    fn rm_running_box_refuses_naming_force_with_exit_2() {
        let e = anyhow::Error::new(minimal::BoxRunningRefusal::new("web"));
        assert_eq!(failure_exit_code(&e), 2);

        let mut stderr = Vec::new();
        let code = answer_failure(&e, false, false, None, &mut stderr);
        assert_eq!(code, ExitCode::from(2));
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "error: web is running. Stop it with min box stop web, \
             or remove it now with min box rm web --force.\n"
        );

        let mut stderr = Vec::new();
        let code = answer_failure(&e, true, false, None, &mut stderr);
        assert_eq!(code, ExitCode::from(2));
        let object: serde_json_lenient::Value = serde_json_lenient::from_slice(&stderr).unwrap();
        assert_eq!(object["schema"], "min/v1/error");
    }

    /// Exit codes: an invalid project `minimal.toml` ends the run with
    /// exit 3, through the context the activation adds over it.
    /// `cmd::session`'s test of the same name proves the refusal comes
    /// before the create and carries this type.
    #[test]
    fn activation_refuses_unloadable_project_file_before_create() {
        let invalid = minimal::ProjectFileInvalid {
            error: mfile::Error::HarnessTable(None),
        };
        let e = anyhow::Error::new(invalid).context("activating the session");
        assert_eq!(failure_exit_code(&e), 3);
    }

    /// A broken pipe anywhere in the error chain is classified as such, so
    /// `min version | head -1` can exit quietly instead of printing an error.
    #[test]
    fn broken_pipe_is_detected_through_the_chain() {
        let io = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "closed");
        let wrapped = anyhow::Error::new(io).context("writing version output");
        assert!(is_broken_pipe(&wrapped));

        let other = anyhow::anyhow!("something else");
        assert!(!is_broken_pipe(&other));
    }
}
