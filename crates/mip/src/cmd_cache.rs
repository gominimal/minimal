//! Command to maintain the local cache.

use std::time::Duration;

use anyhow::anyhow;
use futures::StreamExt;
use futures::channel::mpsc;
use op::{CleanCache, CleanEvent, StaleKind};

use crate::{Context, Error};

#[derive(Debug, clap::Subcommand)]
pub enum CacheArgs {
    /// Remove stale entries from the local cache
    ///
    /// Deletes cached build artifacts whose last recorded use is older than
    /// `--older-than`, or that have no recorded use at all. Packages needed
    /// by the current project's tasks and stack are always kept. Also removes
    /// sandbox, task, and temporary build directories whose owning process is
    /// no longer running.
    Clean {
        /// Only delete cache entries last used at least this long ago.
        /// Takes a whole number of days, hours, or minutes: e.g. `30d`,
        /// `12h`, `45m`
        #[arg(long, value_parser = parse_duration, default_value = "14d")]
        older_than: Duration,
    },
    /// Show the upstream attribution files captured from a source archive
    ///
    /// Prints the `NOTICE` / `COPYRIGHT` / `COPYING` files recorded when the
    /// archive with this sha256 was last extracted, as JSON.
    Notices {
        /// The archive's sha256, as declared in the build spec
        source_sha256: String,
    },
}

fn parse_duration(arg: &str) -> Result<std::time::Duration, anyhow::Error> {
    if let Some(v) = arg.strip_suffix("d") {
        let days: u64 = v.parse().map_err(|e| anyhow!("parsing days: {}", e))?;
        Ok(std::time::Duration::from_hours(24 * days))
    } else if let Some(v) = arg.strip_suffix("h") {
        let hours: u64 = v.parse().map_err(|e| anyhow!("parsing hours: {}", e))?;
        Ok(std::time::Duration::from_hours(hours))
    } else if let Some(v) = arg.strip_suffix("m") {
        let minutes: u64 = v.parse().map_err(|e| anyhow!("parsing minutes: {}", e))?;
        Ok(std::time::Duration::from_mins(minutes))
    } else {
        Err(anyhow!("invalid duration: {}", arg))
    }
}

pub async fn cmd_cache(args: CacheArgs, ctx: &mut Context) -> Result<(), Error> {
    let older_than = match args {
        CacheArgs::Clean { older_than } => older_than,
        CacheArgs::Notices { source_sha256 } => {
            let notices = op::notices::read(&ctx.local_cache(), &source_sha256)
                .map_err(|e| Error::Other(e.into()))?
                .ok_or_else(|| {
                    Error::Other(anyhow!(
                        "no notices recorded for {source_sha256}; extract the source first"
                    ))
                })?;
            let json = serde_json_lenient::to_string_pretty(&notices)
                .map_err(|e| Error::Other(e.into()))?;
            println!("{json}");
            return Ok(());
        }
    };

    // Everything this project's tasks and stack need, whatever its age.
    let keep = ctx.needed_packages()?;

    let (tx, rx) = mpsc::unbounded();
    let renderer = tokio::spawn(print_events(rx));

    let op = CleanCache {
        older_than,
        keep,
        sweep: vec![
            (StaleKind::Sandbox, ctx.builds_base_dir()),
            (StaleKind::Task, ctx.tasks_base_dir()),
            (StaleKind::TempDir, ctx.cache_base_dir().join("temp")),
        ],
        daemon_id: ctx.daemon_id(),
        events: Some(tx),
    };
    let result = op.run(&ctx.local_cache());

    // Closes the event stream, so the renderer's last lines land before the
    // outcome is reported.
    drop(op);
    let _ = renderer.await;

    result?;
    Ok(())
}

/// Prints progress until the sender is dropped.
async fn print_events(mut rx: mpsc::UnboundedReceiver<CleanEvent>) {
    while let Some(event) = rx.next().await {
        println!("{}", event.render());
    }
}
