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
/// BCLI-012): one verb for every Box Type. `verb` is the command as the
/// person typed it, for the log.
pub(crate) async fn cmd_box_logs(
    global: &GlobalArgs,
    args: BoxLogsArgs,
    verb: &'static str,
) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;
    let hosts = crate::cmd::list::local_hosts(global)?;
    let mut out = std::io::stdout().lock();
    box_logs_on_hosts(hosts, &args, verb, &mut out).await
}

/// The logs verb over the local `hosts`: resolves the box, reads its
/// output log from the start, and writes each byte to `out` as the box
/// wrote it. With `-f`, it keeps writing new output until the box is
/// removed. The verb, the box id and the outcome go to the log.
pub(crate) async fn box_logs_on_hosts(
    hosts: Vec<crate::cmd::list::LocalHost>,
    args: &BoxLogsArgs,
    verb: &'static str,
    out: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    let address = args.target.as_str();
    let resolved = resolve_box_on_hosts(hosts, address, verb).await?;
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
