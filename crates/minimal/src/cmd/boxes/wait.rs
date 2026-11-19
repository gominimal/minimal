//! `min box wait`: waits until a box ends and gives back its exit code
//! (BCLI-013). A box that its own timeout ended, and a wait that its
//! `--timeout` ran out on, end with 124. The machine-mode error is
//! `timeout` for the first and `wait_timeout` for the second (BCLI-013,
//! BCLI-014).

use super::*;

/// How often the wait reads the box's record again while the box runs.
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

/// The exit code a `stopped` record with neither an exit code nor a signal
/// gives: 128 plus SIGKILL, the shell's code for a killed process (BOX-154).
pub(crate) const ORPHANED_STOP_EXIT_CODE: i32 = 137;

/// A box that ran past its own timeout (BCLI-014), or a `min box wait
/// --timeout` that ran out before the box ended (BCLI-013). Both end the
/// command with exit 124. A machine-mode run answers the first with `code =
/// "timeout"` and the second with `code = "wait_timeout"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxTimedOut {
    code: &'static str,
    message: String,
    hint: String,
    /// The command already printed this fact on stderr, so a human-mode
    /// run prints no `error:` line for it.
    printed: bool,
}

impl BoxTimedOut {
    /// The exit code, as `timeout(1)` gives it.
    pub const EXIT_CODE: u8 = 124;

    /// The box `target` ran for longer than its own timeout, and its host
    /// stopped it.
    #[must_use]
    pub fn ended(target: &str) -> Self {
        Self {
            code: "timeout",
            message: format!("{target} ran for longer than its timeout and was stopped."),
            hint: String::new(),
            printed: false,
        }
    }

    /// The wait stopped after `after`, before the box ended. `name` is the
    /// name the box's record holds, and `id` is the box id the wait
    /// resolved, so that a script can address the box by it.
    #[must_use]
    pub fn waited(name: Option<&str>, id: &str, after: &str) -> Self {
        let named = box_label(name, id);
        Self {
            code: "wait_timeout",
            message: format!("Stopped waiting after {after}. Box {named} has not ended."),
            hint: format!(
                "Run `min box wait {id}` to wait again, or `min box stop {id}` to stop it."
            ),
            printed: false,
        }
    }

    /// The wait for the exec `exec_id` stopped after `after`, before the
    /// exec ended (BCLI-057). `name` is the name the box's record holds,
    /// and `id` is the box id the wait resolved. The hint gives the
    /// `--exec` forms, so that neither command acts on the whole box.
    #[must_use]
    pub fn waited_exec(name: Option<&str>, id: &str, exec_id: &str, after: &str) -> Self {
        let named = box_label(name, id);
        Self {
            code: "wait_timeout",
            message: format!(
                "Stopped waiting after {after}. Exec {exec_id} in box {named} has not ended."
            ),
            hint: format!(
                "Run `min box wait {id} --exec {exec_id}` to wait again, \
                 or `min box stop {id} --exec {exec_id}` to stop it."
            ),
            printed: false,
        }
    }

    /// The `code` of the machine-mode error object: `timeout` for a box
    /// that its own timeout ended, `wait_timeout` for a wait that ran out.
    #[must_use]
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// Marks that the command already printed this fact on stderr, as a
    /// run prints its timeout line. A human-mode run then ends with 124
    /// and prints nothing more. A machine-mode run still answers the
    /// error object.
    #[must_use]
    pub fn already_printed(mut self) -> Self {
        self.printed = true;
        self
    }

    /// Whether the command already printed this fact on stderr.
    #[must_use]
    pub fn is_printed(&self) -> bool {
        self.printed
    }

    /// The hint of the machine-mode error object.
    #[must_use]
    pub fn hint(&self) -> &str {
        &self.hint
    }
}

impl std::fmt::Display for BoxTimedOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for BoxTimedOut {}

/// The box as a wait-timeout line names it after the word box:
/// `<name> (<id>)`, or `<id>` when its record holds no name.
fn box_label(name: Option<&str>, id: &str) -> String {
    match name {
        Some(name) if !name.is_empty() => format!("{name} ({id})"),
        _ => id.to_owned(),
    }
}

/// How long the lookup of a box's name can take after a wait ran out. The
/// wait's own deadline already passed, so the lookup must not hold the exit.
const NAME_LOOKUP_LIMIT: std::time::Duration = std::time::Duration::from_secs(2);

/// The name the record of the box `id` on `host` holds. A host that does
/// not answer, or does not answer inside [`NAME_LOOKUP_LIMIT`], gives
/// `None`, and the line then names the box by its id.
async fn box_name_on(host: &crate::cmd::list::LocalHost, id: boxes::SessionId) -> Option<String> {
    use minimald_rpc::{Errorable, ShowBox, ShowBoxRequest};

    let lookup = async {
        let mut client = box_host_client(host).await.ok()?;
        match client.oneshot_rpc::<ShowBox>(ShowBoxRequest { id }).await {
            Ok(Errorable::Ok(shown)) => shown.record.name,
            _ => None,
        }
    };
    tokio::time::timeout(NAME_LOOKUP_LIMIT, lookup)
        .await
        .ok()
        .flatten()
}

/// How the box `record` ended, as `min box wait` answers it, or `None`
/// while the box has not ended. `target` is the box as the user named it.
///
/// The record keeps what the box's `exited` event stored (BOX-011): a
/// `timeout` reason is [`BoxTimedOut`], an exit code is that code, and a
/// signal is 128 plus the signal. A `stopped` record with neither is an
/// orphaned stop and gives 137 (BOX-154). An `exited` record with neither
/// is not one the daemon writes, and gives 1, the unspecified error.
pub(crate) fn wait_exit(
    record: &minimald_rpc::BoxListingEntry,
    target: &str,
) -> Option<Result<i32, BoxTimedOut>> {
    let stopped = match record.state.as_str() {
        "stopped" => true,
        "exited" => false,
        _ => return None,
    };
    if record.reason.as_deref() == Some(boxes::core::record::EndReason::Timeout.name()) {
        return Some(Err(BoxTimedOut::ended(target)));
    }
    Some(Ok(match (record.exit_code, record.signal) {
        (Some(code), _) => code,
        (None, Some(signal)) => 128_i32.saturating_add(signal),
        (None, None) if stopped => ORPHANED_STOP_EXIT_CODE,
        (None, None) => 1,
    }))
}

/// `after` as the timeout message prints it: whole seconds as `30s`, and
/// anything shorter than a second, or not a whole number of seconds, in
/// milliseconds.
fn wait_label(after: std::time::Duration) -> String {
    if after.subsec_nanos() == 0 {
        format!("{}s", after.as_secs())
    } else {
        format!("{}ms", after.as_millis())
    }
}

/// Reads the record of box `id` over `client`. A box that its host no
/// longer keeps is the not-found refusal for `target`.
async fn show_box(
    client: &mut client::Client,
    id: boxes::SessionId,
    target: &str,
) -> Result<minimald_rpc::ShowBoxResponse, anyhow::Error> {
    use minimald_rpc::{Errorable, ShowBox, ShowBoxRequest};

    match client
        .oneshot_rpc::<ShowBox>(ShowBoxRequest { id })
        .await
        .context("ShowBox RPC failed")?
    {
        Errorable::Ok(shown) => Ok(shown),
        Errorable::Err { error } if error.starts_with(minimald_rpc::UNKNOWN_SESSION_ID_LEAD) => {
            // The box was removed after the address resolved.
            tracing::info!(verb = "box wait", box_id = %id, outcome = "not found");
            Err(BoxAddressRefusal::NotFound {
                address: target.to_owned(),
            }
            .into())
        }
        Errorable::Err { error } => {
            tracing::info!(verb = "box wait", box_id = %id, outcome = "error", "{error}");
            bail!("{error}")
        }
    }
}

/// Copies the declared exports of the box `id`, which `shown` shows ended,
/// and gives the code of the end as [`wait_exit`] gives it, after the
/// exports. `here` is the command's own project root.
async fn copy_after_end(
    client: &mut client::Client,
    id: boxes::SessionId,
    shown: &minimald_rpc::ShowBoxResponse,
    ended: Result<i32, BoxTimedOut>,
    target: &str,
    here: Option<&paths::HostAbsPath>,
) -> Result<i32, BoxTimedOut> {
    // BOX-185: the wait copies the box's declared exports, on every end,
    // before it gives back the box's code. It copies only into its own
    // project (BOX-199).
    //
    // A skipped export turns the code 0 of an entrypoint that exited by
    // itself into 125 (BOX-193). A stop, a timeout and any other code
    // stand (BOX-194).
    //
    // `copy_box_exports` claims each export first (BOX-198). So a later
    // wait copies, and returns 125, only for an export with no result on
    // the record.
    let root = shown.record.project_root.as_ref();
    let outcomes = copy_box_exports(
        client,
        id,
        shown.record.name.as_deref().unwrap_or(target),
        root.map(|root| std::path::Path::new(root.as_str())),
        here.map(|here| std::path::Path::new(here.as_str())),
        &mut std::io::stderr(),
    )
    .await;
    match ended {
        Ok(code) => {
            let exited_clean = shown.record.state == "exited" && shown.record.exit_code == Some(0);
            let code = exit_code_after_exports(code, exited_clean, &outcomes);
            tracing::info!(verb = "box wait", box_id = %id, exit_code = code, outcome = "ended");
            Ok(code)
        }
        Err(timed_out) => {
            tracing::info!(verb = "box wait", box_id = %id, outcome = "box timeout");
            Err(timed_out)
        }
    }
}

/// The ends on the record of a box, as its `exited` events give them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct BoxEnds {
    /// How many times the box ended: the count of its `exited` events.
    pub count: u64,
    /// When the last end was written, in milliseconds since the Unix
    /// epoch. `None` for a box that never ended.
    pub last_at: Option<u64>,
}

/// The ends on the record of box `id`, read from its events over
/// `client`. `None` when the host does not give every event.
pub(crate) async fn box_ends(client: &mut client::Client, id: boxes::SessionId) -> Option<BoxEnds> {
    use minimald_rpc::ReadEventsUpdate;

    let mut lines = match client.read_box_events(id, false).await {
        Ok(lines) => lines,
        Err(e) => {
            tracing::warn!(box_id = %id, "box ends: open the events read: {e:#}");
            return None;
        }
    };
    let mut ends = BoxEnds::default();
    loop {
        let line = match lines.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) => {
                tracing::warn!(box_id = %id, "box ends: the events read ended early");
                return None;
            }
            Err(e) => {
                tracing::warn!(box_id = %id, "box ends: read the events: {e:#}");
                return None;
            }
        };
        match serde_json_lenient::from_str::<ReadEventsUpdate>(&line) {
            Ok(ReadEventsUpdate::Event { event }) => {
                if event.kind == boxes::events::BoxEventType::Exited {
                    ends.count += 1;
                    ends.last_at = Some(event.ts);
                }
            }
            Ok(ReadEventsUpdate::Done) => return Some(ends),
            Ok(other) => {
                tracing::warn!(box_id = %id, "box ends: the events read stopped: {other:?}");
                return None;
            }
            Err(e) => {
                tracing::warn!(box_id = %id, "box ends: an events line did not parse: {e}");
                return None;
            }
        }
    }
}

/// Waits until the box `target` names on `hosts` ends, copies its declared
/// file exports into its project when `here`, the command's own project
/// root, is the one the box's record names, and returns its exit code as
/// [`wait_exit`] gives it. With `timeout`, the wait stops when the
/// box still runs after it, with a [`BoxTimedOut`], and leaves the box
/// running. The record is read again every `poll`. `min box wait` itself
/// calls [`box_wait_all_on_hosts`], for the record its `-o json` writes.
#[cfg(test)]
pub(crate) async fn box_wait_on_hosts(
    hosts: Vec<crate::cmd::list::LocalHost>,
    target: &str,
    here: Option<&paths::HostAbsPath>,
    timeout: Option<std::time::Duration>,
    poll: std::time::Duration,
) -> Result<i32, anyhow::Error> {
    let waited = box_wait_all_on_hosts(hosts, &[target.to_owned()], here, timeout, poll).await?;
    let one = waited.into_iter().next().expect("one box for one target");
    tracing::debug!(verb = "box wait", box_id = %one.box_id, "the wait ended");
    one.ended.map_err(Into::into)
}

/// One box of a wait on several boxes, after it ended and its exports
/// were copied.
#[derive(Debug)]
pub(crate) struct BoxWaited {
    /// The box's id.
    pub box_id: boxes::SessionId,
    /// The code of its end after its exports, as [`box_wait_on_hosts`]
    /// gives it.
    pub ended: Result<i32, BoxTimedOut>,
    /// The box's record as the wait last read it, after it ended.
    pub record: minimald_rpc::BoxListingEntry,
}

/// The `schema` of the object `min box wait -o json` writes (BCLI-033).
pub(crate) const WAIT_SCHEMA: &str = "min/v1/wait";

/// The object `min box wait -o json` writes when the box ends: how each
/// box it waited on ended (BCLI-013).
#[derive(Debug, serde::Serialize)]
struct WaitObject<'a> {
    schema: &'static str,
    boxes: Vec<WaitedBoxObject<'a>>,
}

/// How one box ended, in the `min/v1/wait` object. `state`, `reason`,
/// `exit_code` and `signal` are what the box's record keeps. `code` is the
/// exit code of the wait for this box.
#[derive(Debug, serde::Serialize)]
struct WaitedBoxObject<'a> {
    box_id: String,
    name: Option<&'a str>,
    state: &'a str,
    reason: Option<&'a str>,
    exit_code: Option<i32>,
    signal: Option<i32>,
    code: i32,
}

/// The exit code of the wait for one box: its code, or 124 for a box that
/// its own timeout ended.
fn waited_code(ended: &Result<i32, BoxTimedOut>) -> i32 {
    match ended {
        Ok(code) => *code,
        Err(_) => i32::from(BoxTimedOut::EXIT_CODE),
    }
}

/// Writes how the boxes in `waited` ended on `out`, in `format`. A text
/// run writes nothing, and the exit code says how the box ended. A `json`
/// run writes one `min/v1/wait` object on one line (BCLI-013, BCLI-033).
pub(crate) fn write_wait_output(
    out: &mut impl std::io::Write,
    format: Option<BoxWaitOutputFormat>,
    waited: &[BoxWaited],
) -> std::io::Result<()> {
    let Some(BoxWaitOutputFormat::Json) = format else {
        return Ok(());
    };
    let object = WaitObject {
        schema: WAIT_SCHEMA,
        boxes: waited
            .iter()
            .map(|one| WaitedBoxObject {
                box_id: one.box_id.to_string(),
                name: one.record.name.as_deref(),
                state: &one.record.state,
                reason: one.record.reason.as_deref(),
                exit_code: one.record.exit_code,
                signal: one.record.signal,
                code: waited_code(&one.ended),
            })
            .collect(),
    };
    serde_json_lenient::to_writer(&mut *out, &object)?;
    writeln!(out)?;
    out.flush()
}

/// Waits until every box `targets` names on `hosts` ended, then copies the
/// declared exports of each box in the order the boxes ended, so the file
/// of the later end stays where two boxes export one path (BOX-203). The
/// result is in the same order. `here`, `timeout` and `poll` are as
/// [`box_wait_on_hosts`] takes them. A wait that runs out names the first
/// box that still runs, and copies nothing.
pub(crate) async fn box_wait_all_on_hosts(
    hosts: Vec<crate::cmd::list::LocalHost>,
    targets: &[String],
    here: Option<&paths::HostAbsPath>,
    timeout: Option<std::time::Duration>,
    poll: std::time::Duration,
) -> Result<Vec<BoxWaited>, anyhow::Error> {
    struct Waiting {
        target: String,
        id: boxes::SessionId,
        client: client::Client,
        shown: Option<(minimald_rpc::ShowBoxResponse, Result<i32, BoxTimedOut>)>,
    }

    let mut waiting = Vec::with_capacity(targets.len());
    for target in targets {
        let ResolvedBox { host, box_id: id } =
            resolve_box_on_hosts(hosts.clone(), target, "box wait").await?;
        crate::output::record_box_id(&id.to_string());
        let client = box_host_client(&host).await?;
        waiting.push(Waiting {
            target: target.clone(),
            id,
            client,
            shown: None,
        });
    }
    let deadline = timeout.map(|after| (tokio::time::Instant::now() + after, after));
    loop {
        let mut running = None;
        for one in waiting.iter_mut().filter(|one| one.shown.is_none()) {
            let shown = show_box(&mut one.client, one.id, &one.target).await?;
            match wait_exit(&shown.record, &one.target) {
                Some(ended) => one.shown = Some((shown, ended)),
                None => {
                    running.get_or_insert((one.id, shown.record.name));
                }
            }
        }
        let Some((id, name)) = running else { break };
        let mut pause = poll;
        if let Some((at, after)) = deadline {
            let now = tokio::time::Instant::now();
            if now >= at {
                tracing::info!(verb = "box wait", box_id = %id, outcome = "wait timeout");
                return Err(BoxTimedOut::waited(
                    name.as_deref(),
                    &id.to_string(),
                    &wait_label(after),
                )
                .into());
            }
            pause = pause.min(at - now);
        }
        tokio::time::sleep(pause).await;
    }
    // BOX-203: the order of the ends, as the time of each box's last
    // `exited` event gives it. A box whose events are not readable goes
    // last, and boxes with one time keep the order of `targets`.
    let several = waiting.len() > 1;
    let mut ordered = Vec::with_capacity(waiting.len());
    for mut one in waiting {
        let mut ended_at = u64::MAX;
        if several && let Some(ends) = box_ends(&mut one.client, one.id).await {
            ended_at = ends.last_at.unwrap_or(u64::MAX);
        }
        ordered.push((ended_at, one));
    }
    ordered.sort_by_key(|(ended_at, _)| *ended_at);
    let mut waited = Vec::with_capacity(ordered.len());
    for (ended_at, mut one) in ordered {
        let (shown, ended) = one.shown.take().expect("every box ended");
        tracing::info!(verb = "box wait", box_id = %one.id, ended_at, "copying exports in the order of the ends");
        let ended = copy_after_end(&mut one.client, one.id, &shown, ended, &one.target, here).await;
        waited.push(BoxWaited {
            box_id: one.id,
            ended,
            record: shown.record,
        });
    }
    Ok(waited)
}

/// Waits until the exec `exec_text` names in the box `target` names on
/// `hosts` ends, and returns its retained exit code as BOX-149's wait gives
/// it (BCLI-057). An exec that its own timeout ended is a
/// [`BoxExecTimedOut`]. With `timeout`, the wait stops when the exec still
/// runs after it, with a [`BoxTimedOut`], and leaves the exec running. The
/// daemon's other words go to `err`.
pub(crate) async fn box_wait_exec_on_hosts<E>(
    hosts: Vec<crate::cmd::list::LocalHost>,
    target: &str,
    exec_text: &str,
    timeout: Option<std::time::Duration>,
    err: &mut E,
) -> Result<i32, anyhow::Error>
where
    E: tokio::io::AsyncWrite + Unpin,
{
    const VERB: &str = "box wait";
    let mut box_id = None;
    let result = async {
        let exec_id = exec_id_arg(target, exec_text)?;
        let resolved = resolve_box_on_hosts(hosts, target, VERB).await?;
        box_id = Some(resolved.box_id);
        crate::output::record_box_id(&resolved.box_id.to_string());
        let mut channels = exec_channels_of(&resolved, target).await?;
        let waited = wait_exec_over(&mut channels, target, &exec_id, err);
        match timeout {
            None => waited.await,
            Some(after) => match tokio::time::timeout(after, waited).await {
                Ok(waited) => waited,
                Err(_) => Err(BoxTimedOut::waited_exec(
                    box_name_on(&resolved.host, resolved.box_id)
                        .await
                        .as_deref(),
                    &resolved.box_id.to_string(),
                    exec_id.as_str(),
                    &wait_label(after),
                )
                .into()),
            },
        }
    }
    .await;
    record_exec_id_outcome(VERB, box_id, exec_text, &result);
    result
}

/// `min box wait <box> [--timeout <d>] [--exec <id>]`: waits until the box,
/// or the one exec `--exec` names, ends, then exits with its exit code.
pub async fn cmd_box_wait(global: &GlobalArgs, args: BoxWaitArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;
    let hosts = crate::cmd::list::local_hosts(global)?;
    let timeout = args.timeout.map(std::time::Duration::from_secs);
    let code = match &args.exec {
        Some(exec) => {
            let mut err = tokio::io::stderr();
            box_wait_exec_on_hosts(hosts, &args.target, exec, timeout, &mut err).await?
        }
        None => {
            // The command's own project root, found from its folder as a
            // create finds it (BOX-199). With none, nothing is copied.
            let here = crate::attach::cwd_host_path(global)
                .and_then(|cwd| box_list_scope(cwd.as_ref()))
                .inspect_err(|e| tracing::info!("box wait: no project root here: {e:#}"))
                .ok();
            let target = [args.target.clone()];
            let waited =
                box_wait_all_on_hosts(hosts, &target, here.as_ref(), timeout, POLL_INTERVAL)
                    .await?;
            // BCLI-013: under `-o json`, how the box ended goes on stdout
            // before the command exits with its code.
            write_wait_output(&mut std::io::stdout().lock(), args.output, &waited)
                .context("write how the box ended")?;
            let one = waited.into_iter().next().expect("one box for one target");
            tracing::debug!(verb = "box wait", box_id = %one.box_id, "the wait ended");
            one.ended?
        }
    };
    if code == 0 {
        Ok(())
    } else {
        Err(Handoff::Exit(code).into())
    }
}
