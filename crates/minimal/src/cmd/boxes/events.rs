//! `min box events` and `min box cp`: what the daemon recorded for a box,
//! and a file copied out of a box. Both read a box that has stopped or
//! exited as well as a running one, because the daemon keeps a stopped
//! box's events and files until the box is removed.
//!
//! `min box events <box> | --parent <box> [-o jsonl] [--follow]` replays
//! the box's event stream as the daemon reads it (BOX-162, BCLI-016).
//! `--follow` replays and then tails. `--parent` merges the streams of
//! every child of a box. `min box cp <box>:<path> <local>` copies one file
//! out of the box over its `sftp` subsystem, which serves a stopped or
//! exited box from its retained files (BOX-017, BCLI-062).
//!
//! The box is found by its address on any local host (BCLI-002).

use super::*;

use crate::output::{ObjectType, OutputMode, Rendered, write_object};
use minimald_rpc::ReadEventsUpdate;

/// One box event as `min box events` renders it. Its machine form is the
/// event's own fields beside the `min/v1/event` stamp: `ts`, `box`,
/// `parent`, `type` and `data`.
#[derive(Debug, serde::Serialize)]
#[serde(transparent)]
pub(crate) struct EventRow(pub boxes::events::BoxEvent);

impl Rendered for EventRow {
    const TYPE: ObjectType = ObjectType::Event;

    /// `<time> <box> <type>`, then the event's `data` as JSON when it has
    /// any.
    fn text(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        let event = &self.0;
        let ts = i64::try_from(event.ts)
            .ok()
            .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
            .map_or_else(
                || event.ts.to_string(),
                |ts| ts.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            );
        write!(out, "{ts}  {}  {}", event.box_id, event.kind.name())?;
        if !event.data.is_empty() {
            let data = serde_json_lenient::to_string(&event.data).map_err(std::io::Error::other)?;
            write!(out, "  {data}")?;
        }
        writeln!(out)
    }
}

/// `min box events`.
pub(crate) async fn cmd_box_events(
    global: &GlobalArgs,
    args: BoxEventsArgs,
) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;
    let hosts = crate::cmd::list::local_hosts(global)?;
    let mut out = std::io::stdout().lock();
    let mut err = std::io::stderr().lock();
    box_events_on_hosts(hosts, &args, &mut out, &mut err).await
}

/// `min box events` over the local `hosts`: resolves the box, opens a read
/// of its events, or of each child's events under `--parent`, and writes
/// each event to `out` in the mode `-o` names. A note for the person goes
/// to `err`.
pub(crate) async fn box_events_on_hosts(
    hosts: Vec<crate::cmd::list::LocalHost>,
    args: &BoxEventsArgs,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    let address = args
        .parent
        .as_deref()
        .or(args.target.as_deref())
        .expect("the box_or_parent group makes clap require a box or --parent");
    let mode = match args.output {
        Some(BoxEventsOutputFormat::Jsonl) => OutputMode::Jsonl,
        None => OutputMode::Text,
    };
    let resolved = resolve_box_on_hosts(hosts, address, "box events").await?;
    crate::output::record_box_id(&resolved.box_id.to_string());
    let mut client = box_host_client(&resolved.host).await?;

    // Each stream with the name its errors call the box by: the address the
    // person typed, or a child's name, or its id when it has none.
    let ids: Vec<(boxes::BoxId, String)> = if args.parent.is_some() {
        let listing = list_box_records(&mut client, None).await?;
        let children: Vec<_> = child_boxes(&listing, resolved.box_id)
            .into_iter()
            .map(|id| {
                let name = listing
                    .iter()
                    .find(|entry| entry.box_id == id)
                    .and_then(|entry| entry.name.clone())
                    .unwrap_or_else(|| id.to_string());
                (id, name)
            })
            .collect();
        if children.is_empty() {
            tracing::info!(verb = "box events", box_id = %resolved.box_id, outcome = "no children");
            writeln!(
                err,
                "Box {} has no child boxes on host {}.",
                resolved.box_id, resolved.host.host
            )?;
            return Ok(());
        }
        children
    } else {
        vec![(resolved.box_id, address.to_owned())]
    };

    let mut reads = Vec::with_capacity(ids.len());
    for (id, label) in &ids {
        let lines = client
            .read_box_events(*id, args.follow)
            .await
            .map_err(|e| {
                tracing::warn!(verb = "box events", box_id = %id, "open the events read: {e:#}");
                anyhow::anyhow!(
                    "Could not read the events of box {label}. \
                     Run `min box show {label}` to check that the box still exists."
                )
            })?;
        reads.push((label.clone(), lines));
    }
    let written = if args.follow {
        follow_events(reads, mode, out).await
    } else {
        replay_events(reads, mode, out).await
    };
    let outcome = if written.is_ok() { "ok" } else { "error" };
    tracing::info!(verb = "box events", box_id = %resolved.box_id, boxes = ids.len(), outcome);
    written
}

/// The ids of the boxes `listing` names as children of `parent`, in the
/// order the listing gives them.
pub(crate) fn child_boxes(
    listing: &[minimald_rpc::BoxListingEntry],
    parent: boxes::BoxId,
) -> Vec<boxes::BoxId> {
    listing
        .iter()
        .filter(|entry| entry.parent == Some(parent))
        .map(|entry| entry.box_id)
        .collect()
}

/// The events of several streams as one: ordered by time, and a tie kept
/// in the order of the streams, so one box's stream keeps its own order.
pub(crate) fn merge_events(
    streams: Vec<Vec<boxes::events::BoxEvent>>,
) -> Vec<boxes::events::BoxEvent> {
    let mut merged: Vec<_> = streams.into_iter().flatten().collect();
    merged.sort_by_key(|event| event.ts);
    merged
}

/// The next update of the read of the box `label` names, or `None` once it
/// ended. A `Failed` update and a stream that ends early are errors, which
/// name the box by `label`. The detail goes to the log.
async fn next_event(
    label: &str,
    lines: &mut client::SubsystemLines,
) -> Result<Option<boxes::events::BoxEvent>, anyhow::Error> {
    let line = match lines.next_line().await {
        Ok(Some(line)) => line,
        Ok(None) => {
            tracing::warn!(
                verb = "box events",
                box_name = label,
                "the events read ended early"
            );
            bail!(
                "The events of box {label} stopped before the last one arrived. \
                 Run `min box events {label}` to read them again."
            );
        }
        Err(e) => {
            tracing::warn!(
                verb = "box events",
                box_name = label,
                "read an events line: {e:#}"
            );
            bail!(
                "Could not read the events of box {label}. \
                 Run `min box show {label}` to check that the box still exists."
            );
        }
    };
    let update: ReadEventsUpdate = match serde_json_lenient::from_str(&line) {
        Ok(update) => update,
        Err(e) => {
            tracing::warn!(
                verb = "box events",
                box_name = label,
                line,
                "decode an events line: {e}"
            );
            bail!("An event of box {label} is in a form this version of min cannot read.");
        }
    };
    match update {
        ReadEventsUpdate::Event { event } => Ok(Some(event)),
        ReadEventsUpdate::Done | ReadEventsUpdate::Reaped => Ok(None),
        ReadEventsUpdate::Failed { error } => {
            tracing::warn!(
                verb = "box events",
                box_name = label,
                "the events read failed: {error}"
            );
            bail!(
                "Could not read the events of box {label}. \
                 Run `min box show {label}` to check that the box still exists."
            )
        }
    }
}

/// Reads each stream to its end, then writes the events of all of them in
/// time order.
async fn replay_events(
    reads: Vec<(String, client::SubsystemLines)>,
    mode: OutputMode,
    out: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    let mut streams = Vec::with_capacity(reads.len());
    for (label, mut lines) in reads {
        let mut events = Vec::new();
        while let Some(event) = next_event(&label, &mut lines).await? {
            events.push(event);
        }
        streams.push(events);
    }
    for event in merge_events(streams) {
        write_object(out, mode, &EventRow(event))?;
    }
    out.flush()?;
    Ok(())
}

/// Writes each event of every stream as it arrives: first the events each
/// box kept, then each new one, until every followed box is removed or the
/// command is interrupted.
async fn follow_events(
    reads: Vec<(String, client::SubsystemLines)>,
    mode: OutputMode,
    out: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let mut readers = tokio::task::JoinSet::new();
    for (label, mut lines) in reads {
        let tx = tx.clone();
        readers.spawn(async move {
            loop {
                let next = next_event(&label, &mut lines).await;
                let end = !matches!(next, Ok(Some(_)));
                if tx.send(next).await.is_err() || end {
                    return;
                }
            }
        });
    }
    drop(tx);
    while let Some(next) = rx.recv().await {
        if let Some(event) = next? {
            write_object(out, mode, &EventRow(event))?;
            out.flush()?;
        }
    }
    Ok(())
}

/// `min box cp`.
pub(crate) async fn cmd_box_cp(global: &GlobalArgs, args: BoxCpArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;
    let hosts = crate::cmd::list::local_hosts(global)?;
    box_cp_on_hosts(hosts, &args.source, &args.destination).await?;
    Ok(())
}

/// `min box cp` over the local `hosts`: reads the file `source` names,
/// `<box>:<path>`, from the box, and writes it to `destination`. Returns
/// the path it wrote.
pub(crate) async fn box_cp_on_hosts(
    hosts: Vec<crate::cmd::list::LocalHost>,
    source: &str,
    destination: &std::path::Path,
) -> Result<std::path::PathBuf, anyhow::Error> {
    let Some((address, path)) = source
        .split_once(':')
        .filter(|(address, path)| !address.is_empty() && !path.is_empty())
    else {
        bail!(
            "min box cp copies a file out of a box, so the first argument must be \
             <box>:<path>. Run `min box cp <box>:<path> {}`.",
            destination.display()
        );
    };
    let resolved = resolve_box_on_hosts(hosts, address, "box cp").await?;
    crate::output::record_box_id(&resolved.box_id.to_string());
    let target = if destination.is_dir() {
        let Some(name) = std::path::Path::new(path).file_name() else {
            bail!(
                "`{path}` does not name a file. Run `min box cp {address}:<path>/<file> {}`.",
                destination.display()
            );
        };
        destination.join(name)
    } else {
        destination.to_path_buf()
    };
    let mut client = box_host_client(&resolved.host).await?;
    let copied = copy_box_file(&mut client, resolved.box_id, address, path, &target).await;
    match &copied {
        Ok(bytes) => {
            tracing::info!(verb = "box cp", box_id = %resolved.box_id, bytes, outcome = "ok");
        }
        Err(e) => {
            tracing::info!(verb = "box cp", box_id = %resolved.box_id, outcome = "error", "{e:#}");
        }
    }
    copied.map(|_| target)
}

/// Streams the file at `path` in the box `box_id`, which the person named
/// `address`, into `target`. The bytes go to a temporary file beside
/// `target`, which is renamed into place only when the whole file arrived,
/// so a failed copy leaves no file at `target`. Returns the bytes copied.
async fn copy_box_file(
    client: &mut client::Client,
    box_id: boxes::BoxId,
    address: &str,
    path: &str,
    target: &std::path::Path,
) -> Result<u64, anyhow::Error> {
    let mut file = client.open_box_file(box_id, path).await.map_err(|e| {
        tracing::warn!(verb = "box cp", box_id = %box_id, path, "open the file in the box: {e}");
        match e {
            client::BoxFileError::NotFound => anyhow::anyhow!("Box {address} has no file {path}."),
            client::BoxFileError::PermissionDenied => {
                anyhow::anyhow!("Box {address} does not allow reading {path}.")
            }
            client::BoxFileError::Unavailable(_) | client::BoxFileError::Refused(_) => {
                anyhow::anyhow!(
                    "Could not read {path} from box {address}. \
                     Run `min box show {address}` to check that the box still exists."
                )
            }
        }
    })?;

    let partial = PartialFile::beside(target);
    let mut out = tokio::fs::File::create(&partial.path)
        .await
        .with_context(|| format!("Could not write {}", target.display()))?;
    let mut buf = vec![0_u8; 64 * 1024];
    let mut copied = 0_u64;
    loop {
        let n = file.read(&mut buf).await.map_err(|e| {
            tracing::warn!(verb = "box cp", box_id = %box_id, path, copied, "read the file in the box: {e}");
            anyhow::anyhow!(
                "Could not read all of {path} from box {address}, so min did not write {}. \
                 Run `min box show {address}` to check that the box still exists.",
                target.display()
            )
        })?;
        let Some(chunk) = buf.get(..n).filter(|chunk| !chunk.is_empty()) else {
            break;
        };
        out.write_all(chunk)
            .await
            .with_context(|| format!("Could not write {}", target.display()))?;
        copied += n as u64;
    }
    out.flush()
        .await
        .with_context(|| format!("Could not write {}", target.display()))?;
    drop(out);
    // The conversation is done either way. A close that fails changes
    // nothing about the bytes already read.
    drop(file.shutdown().await);
    tokio::fs::rename(&partial.path, target)
        .await
        .with_context(|| format!("Could not write {}", target.display()))?;
    partial.keep();
    Ok(copied)
}

/// A temporary file beside the destination of `min box cp`, removed when
/// it drops unless [`Self::keep`] says it was renamed into place.
struct PartialFile {
    path: std::path::PathBuf,
    kept: bool,
}

impl PartialFile {
    /// A hidden name in the directory of `target`, unique to this process.
    fn beside(target: &std::path::Path) -> Self {
        let name = target
            .file_name()
            .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
        let path = target.with_file_name(format!(".{name}.min-cp-{}", std::process::id()));
        Self { path, kept: false }
    }

    fn keep(mut self) {
        self.kept = true;
    }
}

impl Drop for PartialFile {
    fn drop(&mut self) {
        if !self.kept {
            // Nothing to do if the file was never created.
            drop(std::fs::remove_file(&self.path));
        }
    }
}
