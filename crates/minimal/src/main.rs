//! The minimal CLI which pairs/talks-with minimald.

use std::io::IsTerminal as _;
use std::io::Write as _;
use std::process::ExitCode;

use anyhow::Context as _;
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
    let cli = minimal::Cli::parse();
    minimal::theme::install();

    // Publish `--vm` before any path resolution, so the socket, the state dir,
    // and any autospawn all name the same VM (NET-052).
    if let Err(e) = cli.global_args.publish_vm_name() {
        eprintln!("error: {e:#}");
        return ExitCode::FAILURE;
    }

    let registry = tracing_subscriber::registry().with(filter);
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
            .with(fmt::layer().with_writer(log).with_ansi(false))
            .init();
    } else if stdout_is_data_contract(&cli.command) {
        registry
            .with(console_layer(
                std::io::stderr,
                std::io::stderr().is_terminal(),
                !rust_log_set,
            ))
            .init();
    } else {
        registry
            .with(console_layer(
                ot::StdoutWriter::new,
                std::io::stdout().is_terminal(),
                !rust_log_set,
            ))
            .init();
    }

    // The output mode the run is under, read before the CLI is consumed:
    // the error path keys on it (below), so a machine-output run answers a
    // failure with its own contract rather than a plain-text line.
    let output_mode = machine_output_mode(&cli);

    // Only `version` writes its output through a fallible writer; a broken
    // pipe from any other command (e.g. a daemon socket) is a real failure.
    let quiet_on_closed_pipe = matches!(cli.command, Some(minimal::Command::Version));

    if let Err(e) = minimal::run(cli).await {
        // A task's non-zero exit (`min task run`) is a status to relay, not
        // an error to print — the task's own output already streamed through
        // (the git-remote helper's ExitCode precedent).
        if let Some(&minimal::task::TaskExit(code)) = e.downcast_ref::<minimal::task::TaskExit>() {
            return ExitCode::from(code);
        }
        // A machine-output run answers its failure with the one
        // `min/v1/error` object a client parses: the emitter below, keyed
        // on the output mode the run was under rather than on the command,
        // so the mechanism is one, shared by every command that takes
        // `-o json` — each fails its walk into the generic
        // [`minimal::MachineModeFailure`] payload, which is all this path
        // downcasts. The object is the contract, so there is no second,
        // plain-text line to print for the same failure, only the non-zero
        // status.
        if output_mode.is_some() {
            match machine_mode_answer(&e) {
                MachineModeAnswer::Quiet => return ExitCode::from(141),
                MachineModeAnswer::Object(failure) => {
                    emit_machine_mode_error(&failure);
                    return ExitCode::FAILURE;
                }
            }
        }
        // A reader that went away (`min version | head -1`) is not an error
        // worth reporting: exit quietly with the shell's SIGPIPE convention.
        if quiet_on_closed_pipe && is_broken_pipe(&e) {
            return ExitCode::from(141);
        }
        eprintln!("error: {e:#}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
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
/// script can tell it from a crash. Anything else is `unspecified`, the
/// exit table's unspecified error, with the chain as its message and no
/// hint, because nothing about it is known to name a remedy.
fn machine_mode_answer(e: &anyhow::Error) -> MachineModeAnswer {
    if let Some(failure) = e.downcast_ref::<minimal::MachineModeFailure>() {
        return MachineModeAnswer::Object(failure.clone());
    }
    if is_broken_pipe(e) {
        return MachineModeAnswer::Quiet;
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
/// command's output, and `task run` / `session run` stream the task's stdout —
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
        )
    )
}

/// The console log layer. `plain` (no `RUST_LOG` in effect) drops the
/// timestamp and target, so a warning reads as one message line; otherwise the
/// full tracing format is kept for debugging.
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
/// starts with `help:` is written as a help line with no level prefix.
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

/// The machine output mode a run is under: the command's `-o`, the flag the
/// architecture's machine-output contract hangs on — `json` for
/// `min session policy -o json`, the one command that takes it today.
/// `None` for every text run, and for a command that has not taken `-o
/// json` yet, which is the same thing to the error path: its failure is a
/// plain-text line. Both gates below key on this, so a command joins the
/// machine mode by growing an `output` flag, and nothing else about its
/// error path changes.
fn machine_output_mode(cli: &minimal::Cli) -> Option<PolicyOutputFormat> {
    match &cli.command {
        Some(minimal::Command::Session(minimal::SessionArgs {
            command: minimal::SessionCommand::Policy(PolicyArgs { output, .. }),
        })) => *output,
        _ => None,
    }
}

/// The schema stamp of the machine-mode error object — the same kind of
/// stamp a document carries, on the object a failure answers with.
const MACHINE_ERROR_SCHEMA: &str = "min/v1/error";

/// The shape of the one `min/v1/error` object.
#[derive(serde::Serialize)]
struct MachineModeErrorDoc<'a> {
    schema: &'static str,
    code: &'a str,
    message: &'a str,
    /// Omitted when nothing about the failure names a remedy (`unspecified`).
    #[serde(skip_serializing_if = "str::is_empty")]
    hint: &'a str,
}

/// The machine-mode error object, encoded: the schema stamp, the `code` a
/// script branches on, the message, and the hint — nothing else on the
/// line, and no line beside it.
fn machine_mode_error_line(failure: &minimal::MachineModeFailure) -> anyhow::Result<String> {
    let object = MachineModeErrorDoc {
        schema: MACHINE_ERROR_SCHEMA,
        code: failure.code(),
        message: failure.message(),
        hint: failure.hint(),
    };
    serde_json_lenient::to_string(&object).context("encoding the machine-mode error object")
}

/// The machine-mode error emitter: writes the one `min/v1/error` object on
/// stderr, the only thing the mode puts there on any failure, so a client
/// parses a failure the same way it parses the document. Keyed on the
/// output mode the failed run was under (the gate in the error path
/// above), and generic over the payload: a command that takes `-o json`
/// fails its walk into [`minimal::MachineModeFailure`] — carried through
/// the `anyhow` chain, the way [`minimal::task::TaskExit`] is — and needs
/// nothing else; the walk's own kinds name the code, message and hint, and
/// this turns them into the object. `min ls --json` and its kin are
/// untouched: their failure stays the plain-text line it always was.
#[expect(
    clippy::let_underscore_must_use,
    reason = "a closed stderr has no reader left to tell; the exit status is \
              the failure's answer either way"
)]
fn emit_machine_mode_error(failure: &minimal::MachineModeFailure) {
    let mut err = std::io::stderr();
    match machine_mode_error_line(failure) {
        // One object, one line — and a fallback the mode never wants, for
        // an encode that cannot happen: the exit code is non-zero either
        // way.
        Ok(line) => {
            let _ = writeln!(err, "{line}");
        }
        Err(error) => {
            let _ = writeln!(err, "error: {error:#}");
        }
    }
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
                keep: false,
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

    /// An `unspecified` object carries no hint key at all.
    #[test]
    fn machine_mode_error_line_omits_an_empty_hint() {
        let line = machine_mode_error_line(&minimal::MachineModeFailure::new(
            "unspecified",
            "boom".to_string(),
            String::new(),
        ))
        .unwrap();
        assert!(!line.contains("hint"), "got {line}");
        assert!(line.contains(r#""code":"unspecified""#), "got {line}");
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
        assert_eq!(machine_output_mode(&cli), Some(PolicyOutputFormat::Json));

        let cli = minimal::Cli {
            global_args: minimal::GlobalArgs::default(),
            command: Some(Command::Session(minimal::SessionArgs {
                command: minimal::SessionCommand::Policy(PolicyArgs {
                    session: "web".to_string(),
                    output: None,
                }),
            })),
        };
        assert_eq!(machine_output_mode(&cli), None);

        let cli = minimal::Cli {
            global_args: minimal::GlobalArgs::default(),
            command: None,
        };
        assert_eq!(machine_output_mode(&cli), None);
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
