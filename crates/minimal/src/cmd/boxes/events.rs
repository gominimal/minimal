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
    let address = match (&args.target, &args.parent) {
        (_, Some(parent)) => parent.as_str(),
        (Some(target), None) => target.as_str(),
        (None, None) => bail!("Name a box: run `min box events <box>`."),
    };
    let mode = match args.output {
        Some(BoxEventsOutputFormat::Jsonl) => OutputMode::Jsonl,
        None => OutputMode::Text,
    };
    let resolved = resolve_box_on_hosts(hosts, address, "box events").await?;
    crate::output::record_box_id(&resolved.box_id.to_string());
    let mut client = box_host_client(&resolved.host).await?;

    let ids = if args.parent.is_some() {
        let listing = list_box_records(&mut client, None).await?;
        let children = child_boxes(&listing, resolved.box_id);
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
        vec![resolved.box_id]
    };

    let mut reads = Vec::with_capacity(ids.len());
    for id in &ids {
        reads.push((*id, client.read_box_events(*id, args.follow).await?));
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
    parent: boxes::SessionId,
) -> Vec<boxes::SessionId> {
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

/// The next update of the read of box `id`, or `None` once it ended. A
/// `Failed` update and a stream the daemon ends early are errors.
async fn next_event(
    id: boxes::SessionId,
    lines: &mut client::SubsystemLines,
) -> Result<Option<boxes::events::BoxEvent>, anyhow::Error> {
    let Some(line) = lines.next_line().await? else {
        bail!("The daemon closed the events of box {id} before it sent all of them.");
    };
    let update: ReadEventsUpdate = serde_json_lenient::from_str(&line)
        .with_context(|| format!("the daemon sent an events line this min cannot read: {line}"))?;
    match update {
        ReadEventsUpdate::Event { event } => Ok(Some(event)),
        ReadEventsUpdate::Done | ReadEventsUpdate::Reaped => Ok(None),
        ReadEventsUpdate::Failed { error } => bail!("{error}"),
    }
}

/// Reads each stream to its end, then writes the events of all of them in
/// time order.
async fn replay_events(
    reads: Vec<(boxes::SessionId, client::SubsystemLines)>,
    mode: OutputMode,
    out: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    let mut streams = Vec::with_capacity(reads.len());
    for (id, mut lines) in reads {
        let mut events = Vec::new();
        while let Some(event) = next_event(id, &mut lines).await? {
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
    reads: Vec<(boxes::SessionId, client::SubsystemLines)>,
    mode: OutputMode,
    out: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let mut readers = tokio::task::JoinSet::new();
    for (id, mut lines) in reads {
        let tx = tx.clone();
        readers.spawn(async move {
            loop {
                let next = next_event(id, &mut lines).await;
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
                "`{path}` does not name a file. Run `min box cp {address}:<path>/<file> <local>`."
            );
        };
        destination.join(name)
    } else {
        destination.to_path_buf()
    };
    let mut client = box_host_client(&resolved.host).await?;
    let copied = async {
        let bytes = client
            .read_box_file(resolved.box_id, path)
            .await
            .with_context(|| format!("Could not copy {path} out of box {address}"))?;
        std::fs::write(&target, &bytes)
            .with_context(|| format!("Could not write {}", target.display()))?;
        Ok::<_, anyhow::Error>(bytes.len())
    }
    .await;
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
