//! The daemon's on-disk log in one place: appender creation, the reloadable
//! tracing layer, and the shutdown release. The native detached daemon and
//! the microVM pid-1 share this machinery unchanged — they differ only in
//! *when* the log directory is final (immediately for the native daemon,
//! after the state volume mounts for the microVM). A foreground run logs to
//! stdout only and never activates a file.
//!
//! [`DaemonLogger::install`] assembles the global subscriber;
//! [`DaemonLogger::activate`] points the file layer at a directory once it is
//! known and yields a [`DaemonLogRelease`](minimald::server::DaemonLogRelease)
//! for [`ServerState`](minimald::server::ServerState) to run at shutdown.
//!
//! The telemetry layer's init-time lines (`mlog::otel::report_init`: the
//! fixed-text endpoint refusals, the unsupported-exporter warning, an
//! exporter that could not be built, the "telemetry on" summary) go out once
//! the logger's durable sink is live: at install for a console-only run, at
//! `activate` for a file logger. A detached daemon's stdio is `/dev/null`, so
//! reported at install they reached nothing (OTEL-SPEC-EARS TEL-007: one
//! fixed-text warning per refusal, in the daemon's log).

use std::path::Path;

use minimald::server::DaemonLogRelease;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, Layer as _, fmt};

use crate::MainError;

/// Where a daemon's records go.
pub enum LogMode {
    /// Foreground: stdout only, no file.
    Console,
    /// Detached daemon or microVM pid-1: stdout (which the VM routes over the
    /// serial console into the host `boot.log`) plus a reloadable file layer,
    /// pointed at a directory by [`DaemonLogger::activate`].
    File,
}

type Activator = Box<dyn FnOnce(&Path) -> Result<DaemonLogRelease, MainError> + Send>;

/// The daemon's logging, once installed into the global tracing subscriber.
pub struct DaemonLogger {
    /// Present when [`install`](Self::install) set up a file layer (both file
    /// modes); `None` for a console-only foreground run.
    activate: Option<Activator>,
}

impl DaemonLogger {
    /// Assemble and install the global subscriber for `mode`. Call once,
    /// before any `tracing::*` whose output should be captured.
    pub fn install(mode: LogMode) -> Result<Self, MainError> {
        let (logger, ()) = Self::install_with(mode, ot::StdoutWriter::new, |subscriber| {
            subscriber.init();
        });
        Ok(logger)
    }

    /// [`install`](Self::install) with its two seams open: the console is
    /// written through `console`, and `set_default` makes the assembled
    /// subscriber the default (the process-global one in production; a test
    /// scopes it to its thread and keeps the guard it returns). Everything
    /// else is the production sequence, so a test of this exercises what the
    /// daemon runs.
    fn install_with<W, G>(
        mode: LogMode,
        console: W,
        set_default: impl FnOnce(tracing::Dispatch) -> G,
    ) -> (Self, G)
    where
        W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
    {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::new("info")
                .add_directive("topiary=off".parse().unwrap())
                .add_directive("libcgroups=off".parse().unwrap())
        });
        // The `RUST_LOG` filter is the console's and the file's, applied
        // per layer. Applied to the whole registry it would also gate the
        // OTel layers, so `RUST_LOG=warn` would silence the export and the
        // spool of every info-level span. The OTel layers keep their own
        // `MINIMAL_OTEL_FILTER` (default `info`).
        let filter = mlog::otel::quiet(filter);

        let LogMode::File = mode else {
            mlog::otel::init("minimald");
            let guard = set_default(tracing::Dispatch::new(
                tracing_subscriber::registry()
                    .with(fmt::layer().with_writer(console).with_filter(filter))
                    .with(mlog::otel::span_layer())
                    .with(mlog::otel::log_layer()),
            ));
            // The console is this logger's one sink, and it is live now.
            mlog::otel::report_init();
            return (Self { activate: None }, guard);
        };

        // The file layer starts `None` (inert — records still reach the
        // console). `reload` lets `activate` swap the appender in once the
        // log dir is known, and the shutdown release swap it back out, with
        // no deferred-writer hack or process-global hook.
        let (file_layer, reload) = tracing_subscriber::reload::Layer::new(None);
        mlog::otel::init("minimald");
        let guard = set_default(tracing::Dispatch::new(
            tracing_subscriber::registry()
                .with(
                    fmt::layer()
                        .with_writer(console)
                        .with_filter(filter.clone()),
                )
                .with(file_layer.with_filter(filter))
                .with(mlog::otel::span_layer())
                .with(mlog::otel::log_layer()),
        ));
        // No `report_init` here: the file layer is inert until `activate`,
        // and a detached daemon's console is `/dev/null`, so telemetry's
        // init-time warnings reported now reached nothing durable. `activate`
        // reports them once the file is open (or has failed to).
        let activate: Activator = Box::new(move |log_dir: &Path| {
            std::fs::create_dir_all(log_dir)
                .map_err(|e| MainError::IO(e, "creating minimald log directory"))?;
            let appender = build_appender(log_dir)?;
            // lossy(false): a diagnostic log that drops records under load
            // answers the wrong question. The cost is backpressure onto
            // logging threads if the sink wedges — accepted, because the
            // console layer stays independent and the volume fallback
            // collects without the daemon.
            let (writer, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
                .lossy(false)
                .finish(appender);
            reload
                .modify(|layer| {
                    *layer = Some(mlog::json_file_layer(writer, "minimald").boxed());
                })
                .map_err(|e| MainError::Other(format!("installing file log layer: {e}")))?;
            // The release: reload the file layer back off, then drop the guard
            // to flush pending records and close the file.
            Ok(DaemonLogRelease::new(move || {
                // Telemetry is flushed by `main` after the runtime has dropped
                // its in-flight tasks, so their spans are exported too.
                let _ = reload.modify(|layer| *layer = None);
                drop(guard);
            }))
        });
        (
            Self {
                activate: Some(activate),
            },
            guard,
        )
    }

    /// Point the file log at `log_dir`, returning the release to hand to
    /// `ServerState`. `Ok(None)` for a console-only (foreground) logger.
    ///
    /// A file logger reports telemetry's init here (`mlog::otel::report_init`),
    /// after the swap, so the refusal warnings and the "telemetry on" summary
    /// are the file's first lines; on a failed open they go to the console,
    /// the best sink left, just before `main` says the file could not be
    /// opened. A file logger that exits before this call never reports them,
    /// but nothing it has before this is durable either.
    pub fn activate(self, log_dir: &Path) -> Result<Option<DaemonLogRelease>, MainError> {
        let Some(activate) = self.activate else {
            return Ok(None);
        };
        let activated = activate(log_dir);
        mlog::otel::report_init();
        activated.map(Some)
    }
}

/// The daily-rotated, retention-bounded appender. Files carry a date suffix
/// (`minimald.log.<date>`); rotation and pruning are inline (no background
/// thread, no partial intermediates), so the release closes the file with a
/// plain guard drop — nothing to join.
fn build_appender(
    log_dir: &Path,
) -> Result<tracing_appender::rolling::RollingFileAppender, MainError> {
    tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("minimald.log")
        // Two weeks: comfortably past "what happened last week", bounded on disk.
        .max_log_files(14)
        .build(log_dir)
        .map_err(|e| MainError::IO(std::io::Error::other(e), "building rotating log appender"))
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex, PoisonError};

    use super::{DaemonLogger, LogMode};

    /// The console a test's logger writes to, readable afterwards.
    #[derive(Clone, Default)]
    struct Console(Arc<Mutex<Vec<u8>>>);

    impl Console {
        fn text(&self) -> String {
            let bytes = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            String::from_utf8_lossy(&bytes).into_owned()
        }
    }

    impl Write for Console {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The TEL-007 refusal `refusal_env` provokes, as `mlog::otel::init` words
    /// it: an endpoint from a `MINIMAL_` variable with plain `OTEL_` headers
    /// alongside. Fixed text, so a daemon's log can be grepped for it.
    const REFUSAL: &str = "telemetry: refusing to export traces: OTEL_EXPORTER_OTLP_HEADERS is set \
                           but the endpoint comes from MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT";

    /// `mlog::otel::init` reads the process environment and keeps its first
    /// reading, so both tests set the same one and serialise on this lock
    /// (`cargo test` runs them in one process; nextest in one each).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Set (`Some`) or clear (`None`) one environment variable.
    fn env(name: &str, value: Option<&str>) {
        match value {
            // SAFETY: called with `ENV_LOCK` held, so no other test of this
            // module mutates the environment concurrently, and the reads these
            // values feed (`mlog::otel::init`, `EnvFilter`) run on this thread
            // under the same lock; the module's other tests touch no
            // environment variable.
            Some(v) => unsafe { std::env::set_var(name, v) },
            // SAFETY: as above.
            None => unsafe { std::env::remove_var(name) },
        }
    }

    /// Telemetry opted in, an endpoint from `MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT`
    /// and plain `OTEL_EXPORTER_OTLP_HEADERS`: the TEL-007 refusal, for both
    /// signals, and no export or spool to build. The vetoes and the switches
    /// that would lift the refusal or turn traces off are cleared, as is
    /// `RUST_LOG`, so the console and file filters are the daemon's defaults.
    fn refusal_env() {
        env("MINIMAL_TELEMETRY", Some("1"));
        env(
            "MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT",
            Some("http://collector.invalid:4318"),
        );
        env("OTEL_EXPORTER_OTLP_HEADERS", Some("k=v"));
        env("MINIMAL_OTEL_SPOOL", Some("0"));
        for cleared in [
            "DO_NOT_TRACK",
            "OTEL_SDK_DISABLED",
            "MINIMAL_OTEL_EXPORTER_OTLP_HEADERS",
            "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
            "MINIMAL_OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
            "OTEL_TRACES_EXPORTER",
            "MINIMAL_OTEL_TRACES_EXPORTER",
            "RUST_LOG",
        ] {
            env(cleared, None);
        }
    }

    /// Everything the daily-rotated files under `dir` hold.
    fn log_files(dir: &std::path::Path) -> String {
        let mut text = String::new();
        for entry in std::fs::read_dir(dir).expect("reading the log dir") {
            let path = entry.expect("a log dir entry").path();
            if path
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("minimald.log"))
            {
                text.push_str(&std::fs::read_to_string(&path).expect("reading a log file"));
            }
        }
        text
    }

    /// TEL-007/TEL-004 for a detached daemon: its stdio is `/dev/null`, so the
    /// refusal is in its log only if it reaches the file, which opens after
    /// the subscriber is installed. The warning lands in the file once it
    /// opens, once, and the console (live throughout) has it once as well.
    #[test]
    fn a_file_logger_puts_telemetry_init_warnings_in_the_file_once_it_opens() {
        let _env = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        refusal_env();
        let console = Console::default();
        let sink = console.clone();
        let (logger, _default) = DaemonLogger::install_with(
            LogMode::File,
            move || sink.clone(),
            |dispatch| tracing::dispatcher::set_default(&dispatch),
        );
        assert!(
            !console.text().contains(REFUSAL),
            "reported before the file could carry it: {}",
            console.text()
        );
        let dir = tempfile::tempdir().expect("a temp log dir");
        let release = logger
            .activate(dir.path())
            .expect("activating the file log")
            .expect("a file logger yields a release");
        tracing::info!("after activation");
        release.run(); // the file layer off, the appender flushed and closed

        let file = log_files(dir.path());
        assert_eq!(
            file.matches(REFUSAL).count(),
            1,
            "the refusal in the file exactly once; the file holds:\n{file}"
        );
        assert!(
            file.contains("after activation"),
            "the file carries the daemon's later records too:\n{file}"
        );
        let console = console.text();
        assert_eq!(
            console.matches(REFUSAL).count(),
            1,
            "the refusal on the console exactly once; the console holds:\n{console}"
        );
    }

    /// A foreground daemon has the console only, and gets the refusal there
    /// once, at install, as before.
    #[test]
    fn a_console_logger_prints_telemetry_init_warnings_once() {
        let _env = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        refusal_env();
        let console = Console::default();
        let sink = console.clone();
        let (logger, _default) = DaemonLogger::install_with(
            LogMode::Console,
            move || sink.clone(),
            |dispatch| tracing::dispatcher::set_default(&dispatch),
        );
        assert_eq!(
            console.text().matches(REFUSAL).count(),
            1,
            "the refusal on the console exactly once, at install; it holds:\n{}",
            console.text()
        );
        let release = logger
            .activate(std::path::Path::new("/nonexistent/minimald-logs"))
            .expect("a console logger activates to nothing");
        assert!(release.is_none(), "a console logger has no file to release");
        assert_eq!(
            console.text().matches(REFUSAL).count(),
            1,
            "activation of a console logger reports nothing again; it holds:\n{}",
            console.text()
        );
    }
}
