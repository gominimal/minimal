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
/// `parent`, `type` and `data`. `ts` is an RFC 3339 UTC string, as every
/// machine-mode timestamp is.
#[derive(Debug)]
pub(crate) struct EventRow(pub boxes::events::BoxEvent);

impl EventRow {
    /// The event's time as RFC 3339 UTC with milliseconds, or the raw
    /// milliseconds when they are out of the range a date can hold.
    fn ts(&self) -> String {
        let ts = self.0.ts;
        i64::try_from(ts)
            .ok()
            .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
            .map_or_else(
                || ts.to_string(),
                |ts| ts.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            )
    }
}

/// The machine form of an [`EventRow`]: the [`boxes::events::BoxEvent`]
/// fields under their wire names, with `ts` as a string.
#[derive(serde::Serialize)]
struct EventRowWire<'a> {
    #[serde(rename = "box")]
    box_id: &'a boxes::BoxId,
    parent: &'a Option<boxes::BoxId>,
    ts: String,
    #[serde(rename = "type")]
    kind: &'a boxes::events::BoxEventType,
    data: &'a boxes::events::EventData,
}

impl serde::Serialize for EventRow {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let event = &self.0;
        EventRowWire {
            box_id: &event.box_id,
            parent: &event.parent,
            ts: self.ts(),
            kind: &event.kind,
            data: &event.data,
        }
        .serialize(serializer)
    }
}

impl Rendered for EventRow {
    const TYPE: ObjectType = ObjectType::Event;

    /// `<time> <box> <type>`, then the event's `data` as JSON when it has
    /// any.
    fn text(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        let event = &self.0;
        write!(
            out,
            "{}  {}  {}",
            self.ts(),
            event.box_id,
            event.kind.name()
        )?;
        if !event.data.is_empty() {
            let data = serde_json_lenient::to_string(&event.data).map_err(std::io::Error::other)?;
            write!(out, "  {data}")?;
        }
        writeln!(out)
    }
}

/// A file `min box cp` could not open in the box, for a reason with its
/// own exit code: 4 when the box has no such file, 5 when the box does
/// not allow the read (BCLI-034).
#[derive(Debug)]
pub enum BoxFileRefusal {
    /// The box has no file at the path.
    NotFound {
        /// The box as the person named it.
        address: String,
        /// The path in the box.
        path: String,
    },
    /// The box does not allow the read.
    PermissionDenied {
        /// The box as the person named it.
        address: String,
        /// The path in the box.
        path: String,
    },
}

impl BoxFileRefusal {
    /// The exit code the command ends with: 4 for not found, 5 for
    /// permission denied.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::NotFound { .. } => 4,
            Self::PermissionDenied { .. } => 5,
        }
    }
}

impl std::fmt::Display for BoxFileRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound { address, path } => write!(f, "Box {address} has no file {path}."),
            Self::PermissionDenied { address, path } => {
                write!(f, "Box {address} does not allow reading {path}.")
            }
        }
    }
}

impl std::error::Error for BoxFileRefusal {}

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
        let children = child_labels(&listing, resolved.box_id);
        // Under --follow a parent with no child yet is still followed: a
        // child it gets later joins the output.
        if children.is_empty() && !args.follow {
            tracing::info!(verb = "box events", box_id = %resolved.box_id, outcome = "no children");
            writeln!(
                err,
                "Box {} has no child boxes on host {}.",
                resolved.box_id, resolved.host.host
            )?;
            return Ok(());
        }
        if children.is_empty() {
            // Without this line, a follow with nothing to print reads as a hang.
            writeln!(
                err,
                "Box {} has no child boxes on host {} yet. \
                 The events of each new child box print here. Press Ctrl-C to stop.",
                resolved.box_id, resolved.host.host
            )?;
        }
        children
    } else {
        vec![(resolved.box_id, address.to_owned())]
    };

    let mut reads = Vec::with_capacity(ids.len());
    for (id, label) in &ids {
        let lines = open_events_read(&mut client, *id, label, args.follow).await?;
        reads.push((label.clone(), lines));
    }
    let written = if args.follow {
        let watch = args.parent.as_ref().map(|_| {
            ChildWatch::new(
                HostChildren(client),
                resolved.box_id,
                address.to_owned(),
                ids.iter().map(|(id, _)| *id),
            )
        });
        follow_events(reads, watch, mode, out).await
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

/// Each child of `parent` in `listing`, with the name its errors call it
/// by: its name, or its id when it has none.
fn child_labels(
    listing: &[minimald_rpc::BoxListingEntry],
    parent: boxes::BoxId,
) -> Vec<(boxes::BoxId, String)> {
    child_boxes(listing, parent)
        .into_iter()
        .map(|id| {
            let name = listing
                .iter()
                .find(|entry| entry.box_id == id)
                .and_then(|entry| entry.name.clone())
                .unwrap_or_else(|| id.to_string());
            (id, name)
        })
        .collect()
}

/// Opens the read of the events of box `id`, which errors call `label`.
async fn open_events_read(
    client: &mut client::Client,
    id: boxes::BoxId,
    label: &str,
    follow: bool,
) -> Result<client::SubsystemLines, anyhow::Error> {
    client.read_box_events(id, follow).await.map_err(|e| {
        tracing::warn!(verb = "box events", box_id = %id, "open the events read: {e:#}");
        anyhow::anyhow!(
            "Could not read the events of box {label}. \
             Run `min box show {label}` to check that the box still exists."
        )
    })
}

/// The lines of one read of a box's events, one update in each.
pub(crate) trait EventLines: Send + 'static {
    /// The next line, or `None` once the daemon ended the read.
    fn next_line(
        &mut self,
    ) -> impl std::future::Future<Output = Result<Option<String>, anyhow::Error>> + Send;
}

impl EventLines for client::SubsystemLines {
    async fn next_line(&mut self) -> Result<Option<String>, anyhow::Error> {
        client::SubsystemLines::next_line(self).await
    }
}

/// Where `--parent --follow` lists the boxes and opens the read of a new
/// child: the parent's host, or a stand-in in the tests.
pub(crate) trait ChildSource: Send + 'static {
    /// The lines of one read that [`ChildSource::open`] gives.
    type Lines: EventLines;

    /// Every box on the host.
    fn list(
        &mut self,
    ) -> impl std::future::Future<Output = Result<Vec<minimald_rpc::BoxListingEntry>, anyhow::Error>>
    + Send;

    /// Opens the followed read of the events of box `id`, which errors
    /// call `label`.
    fn open(
        &mut self,
        id: boxes::BoxId,
        label: &str,
    ) -> impl std::future::Future<Output = Result<Self::Lines, anyhow::Error>> + Send;
}

/// The host of the parent, through its client.
pub(crate) struct HostChildren(client::Client);

impl ChildSource for HostChildren {
    type Lines = client::SubsystemLines;

    async fn list(&mut self) -> Result<Vec<minimald_rpc::BoxListingEntry>, anyhow::Error> {
        list_box_records(&mut self.0, None).await
    }

    async fn open(
        &mut self,
        id: boxes::BoxId,
        label: &str,
    ) -> Result<client::SubsystemLines, anyhow::Error> {
        open_events_read(&mut self.0, id, label, true).await
    }
}

/// How often `--parent --follow` lists the parent's children again to
/// find a child that is new since the follow started.
pub(crate) const CHILD_POLL: std::time::Duration = std::time::Duration::from_secs(1);

/// How long one listing, or one open of a new child's read, can take
/// before `--parent --follow` counts it as failed. The streams already in
/// the follow keep their output meanwhile.
pub(crate) const CHILD_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How many times in a row the read of a new child can fail to open, or
/// be refused before its first event, while the listings still show the
/// child. The next failure stops `--parent --follow` with the error.
pub(crate) const CHILD_OPEN_TRIES: u32 = 5;

/// How many listings in a row can fail before `--parent --follow` stops
/// with the list error. A shorter outage keeps the follow and its streams.
pub(crate) const CHILD_LIST_TRIES: u32 = 5;

/// The state `--parent --follow` keeps to add the stream of each new child
/// of `parent` to the follow.
pub(crate) struct ChildWatch<S> {
    source: S,
    parent: boxes::BoxId,
    /// The parent as the person named it.
    address: String,
    /// The children whose read is in the follow, or is open and waits for
    /// its first update. Only children the last listing showed stay here.
    seen: std::collections::HashSet<boxes::BoxId>,
    /// For each new child whose read did not open, the number of times in
    /// a row that it failed.
    failed: std::collections::HashMap<boxes::BoxId, u32>,
    /// The number of listings in a row that failed.
    list_failures: u32,
}

impl<S: ChildSource> ChildWatch<S> {
    /// A watch of the children of `parent`, which the person named
    /// `address`. The children in `followed` are already in the follow.
    pub(crate) fn new(
        source: S,
        parent: boxes::BoxId,
        address: String,
        followed: impl IntoIterator<Item = boxes::BoxId>,
    ) -> Self {
        Self {
            source,
            parent,
            address,
            seen: followed.into_iter().collect(),
            failed: std::collections::HashMap::new(),
            list_failures: 0,
        }
    }

    /// Lists the boxes again and opens a read for each child of the parent
    /// that is not in the follow yet. Each read comes with the child's id
    /// and name. `None` once the parent is removed: no new child can come
    /// then. A child that the last listing before that showed, and that is
    /// not in the follow yet, is never added.
    async fn new_children(
        &mut self,
    ) -> Result<Option<Vec<(boxes::BoxId, String, S::Lines)>>, anyhow::Error> {
        let listed = tokio::time::timeout(CHILD_CALL_TIMEOUT, self.source.list())
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("the listing timed out")));
        let listing = match listed {
            Ok(listing) => {
                self.list_failures = 0;
                listing
            }
            Err(e) => {
                self.list_failures += 1;
                tracing::warn!(
                    verb = "box events",
                    box_id = %self.parent,
                    tries = self.list_failures,
                    "list the children of the parent again: {e:#}"
                );
                // A short outage keeps the follow: the next poll lists again.
                if self.list_failures < CHILD_LIST_TRIES {
                    return Ok(Some(Vec::new()));
                }
                return Err(anyhow::anyhow!(
                    "Could not find the new child boxes of box {address}. \
                     Run `min box show {address}` to check that the box still exists.",
                    address = self.address
                ));
            }
        };
        if !listing.iter().any(|entry| entry.box_id == self.parent) {
            tracing::info!(verb = "box events", box_id = %self.parent, "the parent is removed");
            return Ok(None);
        }
        // A child gone from the listing is never listed again, and a count
        // starts again for a child that comes back.
        let listed = |id: &boxes::BoxId| listing.iter().any(|entry| entry.box_id == *id);
        self.seen.retain(listed);
        self.failed.retain(|id, _| listed(id));
        let mut reads = Vec::new();
        for (id, label) in child_labels(&listing, self.parent) {
            if self.seen.contains(&id) {
                continue;
            }
            let opened = tokio::time::timeout(CHILD_CALL_TIMEOUT, self.source.open(id, &label))
                .await
                .unwrap_or_else(|_| {
                    tracing::warn!(verb = "box events", box_id = %id, "the open of the events read timed out");
                    Err(anyhow::anyhow!(
                        "Could not read the events of box {label}. \
                         Run `min box show {label}` to check that the box still exists."
                    ))
                });
            match opened {
                Ok(lines) => {
                    tracing::info!(verb = "box events", box_id = %id, parent = %self.parent, "follow a new child");
                    self.seen.insert(id);
                    reads.push((id, label, lines));
                }
                Err(e) => self.not_opened(id, e)?,
            }
        }
        Ok(Some(reads))
    }

    /// Takes the first update of the read of the new child `id`. A refusal
    /// before the first event, such as for a child removed after the
    /// listing, means the read did not open: the next listing that shows
    /// the child opens it again.
    fn first_update(
        &mut self,
        id: boxes::BoxId,
        first: Result<(), anyhow::Error>,
    ) -> Result<(), anyhow::Error> {
        match first {
            Ok(()) => {
                self.failed.remove(&id);
                Ok(())
            }
            Err(e) => {
                self.seen.remove(&id);
                self.not_opened(id, e)
            }
        }
    }

    /// Counts one more failure in a row of the read of `id`, and returns
    /// `e` once the read failed [`CHILD_OPEN_TRIES`] times. A child that the
    /// listings keep showing but whose read never opens ends the follow
    /// with the error, not a silent gap.
    fn not_opened(&mut self, id: boxes::BoxId, e: anyhow::Error) -> Result<(), anyhow::Error> {
        let tries = self.failed.entry(id).or_insert(0);
        *tries += 1;
        tracing::debug!(verb = "box events", box_id = %id, tries = *tries, "{e:#}");
        if *tries >= CHILD_OPEN_TRIES {
            return Err(e);
        }
        Ok(())
    }
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
async fn next_event<L: EventLines>(
    label: &str,
    lines: &mut L,
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
/// command is interrupted. With a `watch`, the stream of each new child of
/// the parent joins the follow, and the follow lasts until the parent is
/// removed as well. The watch runs in its own task, so a slow listing or
/// open never holds back the output of the streams already in the follow.
pub(crate) async fn follow_events<S: ChildSource>(
    reads: Vec<(String, S::Lines)>,
    watch: Option<ChildWatch<S>>,
    mode: OutputMode,
    out: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Next>(64);
    // Every task ends when this set drops, on each return below.
    let mut tasks = tokio::task::JoinSet::new();
    for (label, lines) in reads {
        tasks.spawn(read_stream(label, lines, tx.clone(), None));
    }
    if let Some(watch) = watch {
        tasks.spawn(watch_children(watch, tx.clone()));
    }
    // The channel closes once every reader ended and the watch, which can
    // add a reader, ended too.
    drop(tx);
    while let Some(next) = rx.recv().await {
        if let Some(event) = next? {
            write_object(out, mode, &EventRow(event))?;
            out.flush()?;
        }
    }
    Ok(())
}

/// One update of a followed stream, as the output loop takes it.
type Next = Result<Option<boxes::events::BoxEvent>, anyhow::Error>;

/// Where the reader of a new child says how its first update went.
type FirstUpdate = tokio::sync::mpsc::UnboundedSender<(boxes::BoxId, Result<(), anyhow::Error>)>;

/// Sends each update of the read of the box `label` names to `tx`, until
/// the read ends. With `first`, the read is of a new child: an error before
/// its first event goes to the watch on `first`, not to the output.
async fn read_stream<L: EventLines>(
    label: String,
    mut lines: L,
    tx: tokio::sync::mpsc::Sender<Next>,
    mut first: Option<(boxes::BoxId, FirstUpdate)>,
) {
    loop {
        let next = next_event(&label, &mut lines).await;
        if let Some((id, watch)) = first.take() {
            if let Err(e) = next {
                let _ = watch.send((id, Err(e)));
                return;
            }
            let _ = watch.send((id, Ok(())));
        }
        let end = !matches!(next, Ok(Some(_)));
        if tx.send(next).await.is_err() || end {
            return;
        }
    }
}

/// Lists the children of the watched parent each [`CHILD_POLL`], and adds a
/// reader for each new one, until the parent is removed. Then it waits for
/// the readers it added. An error that ends the follow goes to `tx`.
async fn watch_children<S: ChildSource>(
    mut watch: ChildWatch<S>,
    tx: tokio::sync::mpsc::Sender<Next>,
) {
    let (first_tx, mut first_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut readers = tokio::task::JoinSet::new();
    let mut poll = tokio::time::interval_at(tokio::time::Instant::now() + CHILD_POLL, CHILD_POLL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        poll.tick().await;
        // A reader that ended leaves the set, so a parent whose children
        // come and go keeps only the readers that still run.
        while readers.try_join_next().is_some() {}
        while let Ok((id, first)) = first_rx.try_recv() {
            if let Err(e) = watch.first_update(id, first) {
                let _ = tx.send(Err(e)).await;
                return;
            }
        }
        match watch.new_children().await {
            Ok(Some(new)) => {
                for (id, label, lines) in new {
                    let first = Some((id, first_tx.clone()));
                    readers.spawn(read_stream(label, lines, tx.clone(), first));
                }
            }
            Ok(None) => break,
            Err(e) => {
                let _ = tx.send(Err(e)).await;
                return;
            }
        }
    }
    while readers.join_next().await.is_some() {}
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
            client::BoxFileError::NotFound => anyhow::Error::new(BoxFileRefusal::NotFound {
                address: address.to_owned(),
                path: path.to_owned(),
            }),
            client::BoxFileError::PermissionDenied => {
                anyhow::Error::new(BoxFileRefusal::PermissionDenied {
                    address: address.to_owned(),
                    path: path.to_owned(),
                })
            }
            client::BoxFileError::Unavailable(_) | client::BoxFileError::Refused(_) => {
                anyhow::anyhow!("Could not open {path} in box {address}.")
            }
        }
    })?;

    // A new file with a random name beside `target`. It is created with
    // O_EXCL, so it never follows a link or truncates a file already there.
    // It is removed on drop unless it was renamed into place.
    let dir = match target.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => std::path::Path::new("."),
    };
    let name = target
        .file_name()
        .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
    let prefix = format!(".{name}.min-cp-");
    let mut builder = tempfile::Builder::new();
    builder.prefix(&prefix);
    // The umask applies to this mode, as it does to `File::create`, so the
    // copy gets the default mode and not the 0600 of a temporary file.
    #[cfg(unix)]
    builder.permissions(std::os::unix::fs::PermissionsExt::from_mode(0o666));
    let (out, partial) = builder
        .tempfile_in(dir)
        .with_context(|| format!("Could not write {}", target.display()))?
        .into_parts();
    let mut out = tokio::fs::File::from_std(out);

    // An open directory fails only at the first read, so ask first. A
    // metadata call that fails leaves the answer to the read.
    if file.metadata().await.is_ok_and(|meta| meta.is_dir()) {
        bail!(
            "{path} in box {address} is a directory, and min box cp copies one file. \
             Run `min box cp {address}:{}/<file> {}`.",
            path.trim_end_matches('/'),
            target.display()
        );
    }

    let mut buf = vec![0_u8; 64 * 1024];
    let mut copied = 0_u64;
    loop {
        let n = file.read(&mut buf).await.map_err(|e| {
            tracing::warn!(verb = "box cp", box_id = %box_id, path, copied, "read the file in the box: {e}");
            anyhow::anyhow!(
                "Could not read all of {path} from box {address}, so min did not write {}.",
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
    partial
        .persist(target)
        .with_context(|| format!("Could not write {}", target.display()))?;
    Ok(copied)
}
