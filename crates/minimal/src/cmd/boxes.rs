//! The `min session` commands, one module per verb. The clap handlers stay
//! in `session.rs` and call into these modules.
//!
//! `cmd/mod.rs` mounts this file as `box_verbs`, not `boxes`: a `boxes`
//! module in `cmd` would shadow the `boxes` crate for every sibling that
//! reaches it through `use super::*`.

use super::*;

#[path = "boxes/address.rs"]
mod address;
#[path = "boxes/attach.rs"]
mod attach;
#[path = "boxes/create.rs"]
mod create;
#[path = "boxes/events.rs"]
mod events;
#[path = "boxes/exec.rs"]
mod exec;
#[path = "boxes/hooks.rs"]
mod hooks;
#[path = "boxes/lifecycle.rs"]
mod lifecycle;
#[path = "boxes/list.rs"]
mod list;
#[path = "boxes/policy.rs"]
mod policy;
#[path = "boxes/show.rs"]
mod show;
#[path = "boxes/vm_host.rs"]
mod vm_host;

pub(crate) use address::*;
pub use address::{AddressCandidate, BoxAddressRefusal};
pub use attach::BoxAttachRefusal;
pub(crate) use attach::*;
pub use create::*;
pub use events::BoxFileRefusal;
pub(crate) use events::*;
pub(crate) use exec::*;
pub(crate) use hooks::*;
pub(crate) use lifecycle::*;
pub use lifecycle::{BoxRenameRefusal, BoxRunningRefusal, PruneNeedsYes};
pub use list::*;
pub use policy::*;
pub use show::*;
pub(crate) use vm_host::*;

/// `min session logs`, `min task logs` and `min box logs` (BOX-155,
/// BCLI-012): the `min box logs` verb, filtered to `box_type` under a type
/// noun. `verb` is the command as the person typed it, for the log.
pub(crate) async fn cmd_box_logs(
    global: &GlobalArgs,
    args: BoxLogsArgs,
    box_type: Option<&str>,
    verb: &'static str,
) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;
    let hosts = crate::cmd::list::local_hosts(global)?;
    let mut out = std::io::stdout().lock();
    box_logs_on_hosts(hosts, &args, box_type, verb, &mut out).await
}

/// The logs verb over the local `hosts`: resolves the box among the boxes
/// of `box_type`, or of every type when it is `None`, reads its output log
/// from the start, and writes each byte to `out` as the box wrote it. With
/// `-f`, it keeps writing new output until the box is removed. The verb,
/// the box id and the outcome go to the log.
pub(crate) async fn box_logs_on_hosts(
    hosts: Vec<crate::cmd::list::LocalHost>,
    args: &BoxLogsArgs,
    box_type: Option<&str>,
    verb: &'static str,
    out: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    let address = args.target.as_str();
    let resolved = match box_type {
        None => resolve_box_on_hosts(hosts, address, verb).await?,
        Some(box_type) => resolve_typed_box_on_hosts(hosts, address, box_type, verb).await?,
    };
    crate::output::record_box_id(&resolved.box_id.to_string());
    let box_id = resolved.box_id;
    let written = async {
        let mut client = box_host_client(&resolved.host).await?;
        let request = minimald_rpc::ReadLogRequest {
            id: box_id,
            offset: 0,
            follow: args.follow,
        };
        let body = serde_json_lenient::to_vec(&request).context("serialize the log request")?;
        let mut lines = client
            .stream_box_subsystem(box_id, minimald_rpc::READ_LOG_SUBSYSTEM, &body)
            .await
            .map_err(|e| {
                tracing::warn!(verb, box_id = %box_id, "open the log read: {e:#}");
                log_read_failed(address)
            })?;
        copy_log(verb, address, &mut lines, out).await
    }
    .await;
    let outcome = if written.is_ok() { "ok" } else { "error" };
    tracing::info!(verb, box_id = %box_id, follow = args.follow, outcome);
    written
}

/// [`resolve_box_on_hosts`] with the records of every type but `box_type`
/// dropped before resolution, so a type noun never reaches a box of
/// another type. Such an address is refused as one that no box holds.
async fn resolve_typed_box_on_hosts(
    mut hosts: Vec<crate::cmd::list::LocalHost>,
    address: &str,
    box_type: &str,
    verb: &'static str,
) -> Result<ResolvedBox, anyhow::Error> {
    if let BoxAddress::Qualified { provider, host, .. } = parse_box_address(address) {
        hosts.retain(|h| h.provider == provider && h.host == host);
    }
    let mut listings = Vec::with_capacity(hosts.len());
    for host in hosts {
        let boxes = read_host_boxes(&host).await.inspect_err(|err| {
            tracing::info!(verb, outcome = "error", host = %host.host, "{err:#}");
        })?;
        let boxes = boxes.map(|records| {
            records
                .into_iter()
                .filter(|entry| entry.box_type.as_deref() == Some(box_type))
                .collect()
        });
        listings.push(HostListing { host, boxes });
    }
    match resolve_box_address(address, &listings) {
        Ok(resolved) => {
            tracing::info!(
                verb,
                box_id = %resolved.box_id,
                host = %resolved.host.host,
                outcome = "resolved"
            );
            Ok(resolved)
        }
        Err(refusal) => {
            tracing::info!(verb, address, box_type, outcome = "refused", "{refusal}");
            Err(refusal.into())
        }
    }
}

/// The error for a log read that did not start or did not end cleanly.
fn log_read_failed(address: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "Could not read the output of box {address}. \
         Run `min box show {address}` to check that the box still exists."
    )
}

/// Writes every `Output` chunk of the read to `out`, until the read ends.
/// A `Failed` update, a line this build cannot decode, and a stream that
/// ends with no last update are errors. The detail goes to the log.
async fn copy_log(
    verb: &'static str,
    address: &str,
    lines: &mut client::SubsystemLines,
    out: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    use minimald_rpc::ReadLogUpdate;
    loop {
        let line = match lines.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) => {
                tracing::warn!(verb, box_name = address, "the log read ended early");
                bail!(
                    "The output of box {address} stopped before its end arrived. \
                     Run `min box logs {address}` to read it again."
                );
            }
            Err(e) => {
                tracing::warn!(verb, box_name = address, "read a log line: {e:#}");
                return Err(log_read_failed(address));
            }
        };
        let update: ReadLogUpdate = match serde_json_lenient::from_str(&line) {
            Ok(update) => update,
            Err(e) => {
                // The line carries box output, which can hold secrets: log only its length.
                tracing::warn!(
                    verb,
                    box_name = address,
                    line_len = line.len(),
                    "decode a log line: {e}"
                );
                bail!("The output of box {address} is in a form this version of min cannot read.");
            }
        };
        match update {
            ReadLogUpdate::Output { data, .. } => {
                out.write_all(&data)?;
                out.flush()?;
            }
            ReadLogUpdate::Done { .. } | ReadLogUpdate::Reaped => return Ok(()),
            ReadLogUpdate::Failed { error } => {
                tracing::warn!(verb, box_name = address, "the log read failed: {error}");
                return Err(log_read_failed(address));
            }
        }
    }
}
