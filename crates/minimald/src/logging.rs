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

use std::path::Path;

use minimald::server::DaemonLogRelease;
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
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::new("info")
                .add_directive("topiary=off".parse().unwrap())
                .add_directive("libcgroups=off".parse().unwrap())
        });

        let LogMode::File = mode else {
            tracing_subscriber::registry()
                .with(fmt::layer().with_writer(ot::StdoutWriter::new))
                .with(filter)
                .init();
            return Ok(Self { activate: None });
        };

        // The file layer starts `None` (inert — records still reach the
        // console). `reload` lets `activate` swap the appender in once the
        // log dir is known, and the shutdown release swap it back out, with
        // no deferred-writer hack or process-global hook.
        let (file_layer, reload) = tracing_subscriber::reload::Layer::new(None);
        tracing_subscriber::registry()
            .with(fmt::layer().with_writer(ot::StdoutWriter::new))
            .with(file_layer)
            .with(filter)
            .init();
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
                    *layer = Some(fmt::layer().with_ansi(false).with_writer(writer).boxed());
                })
                .map_err(|e| MainError::Other(format!("installing file log layer: {e}")))?;
            // The release: reload the file layer back off, then drop the guard
            // to flush pending records and close the file.
            Ok(DaemonLogRelease::new(move || {
                let _ = reload.modify(|layer| *layer = None);
                drop(guard);
            }))
        });
        Ok(Self {
            activate: Some(activate),
        })
    }

    /// Point the file log at `log_dir`, returning the release to hand to
    /// `ServerState`. `Ok(None)` for a console-only (foreground) logger.
    pub fn activate(self, log_dir: &Path) -> Result<Option<DaemonLogRelease>, MainError> {
        self.activate.map(|f| f(log_dir)).transpose()
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
