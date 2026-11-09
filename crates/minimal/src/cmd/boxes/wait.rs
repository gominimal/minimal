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
        }
    }

    /// The wait for `target` stopped after `after`, with the box still
    /// running. `id` is the box id the wait resolved, so that a script can
    /// address the box by it.
    #[must_use]
    pub fn waited(target: &str, id: &str, after: &str) -> Self {
        Self {
            code: "wait_timeout",
            // The wording is the task's `diagnostics:` line, with the id.
            message: format!("Stopped waiting after {after}; {target} ({id}) is still running."),
            hint: format!(
                "Run `min box wait {id}` to wait again, or `min box stop {id}` to stop it."
            ),
        }
    }

    /// The `code` of the machine-mode error object: `timeout` for a box
    /// that its own timeout ended, `wait_timeout` for a wait that ran out.
    #[must_use]
    pub fn code(&self) -> &'static str {
        self.code
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

/// Waits until the box `target` names on `hosts` ends, and returns its exit
/// code as [`wait_exit`] gives it. With `timeout`, the wait stops when the
/// box still runs after it, with a [`BoxTimedOut`], and leaves the box
/// running. The record is read again every `poll`.
pub(crate) async fn box_wait_on_hosts(
    hosts: Vec<crate::cmd::list::LocalHost>,
    target: &str,
    timeout: Option<std::time::Duration>,
    poll: std::time::Duration,
) -> Result<i32, anyhow::Error> {
    use minimald_rpc::{Errorable, ShowBox, ShowBoxRequest};

    let ResolvedBox { host, box_id: id } = resolve_box_on_hosts(hosts, target, "box wait").await?;
    crate::output::record_box_id(&id.to_string());
    let deadline = timeout.map(|after| (tokio::time::Instant::now() + after, after));
    let mut client = box_host_client(&host).await?;
    loop {
        let shown = match client
            .oneshot_rpc::<ShowBox>(ShowBoxRequest { id })
            .await
            .context("ShowBox RPC failed")?
        {
            Errorable::Ok(shown) => shown,
            Errorable::Err { error }
                if error.starts_with(minimald_rpc::UNKNOWN_SESSION_ID_LEAD) =>
            {
                // The box was removed after the address resolved.
                tracing::info!(verb = "box wait", box_id = %id, outcome = "not found");
                return Err(BoxAddressRefusal::NotFound {
                    address: target.to_owned(),
                }
                .into());
            }
            Errorable::Err { error } => {
                tracing::info!(verb = "box wait", box_id = %id, outcome = "error", "{error}");
                bail!("{error}")
            }
        };
        if let Some(ended) = wait_exit(&shown.record, target) {
            return match ended {
                Ok(code) => {
                    tracing::info!(verb = "box wait", box_id = %id, exit_code = code, outcome = "ended");
                    Ok(code)
                }
                Err(timed_out) => {
                    tracing::info!(verb = "box wait", box_id = %id, outcome = "box timeout");
                    Err(timed_out.into())
                }
            };
        }
        let mut pause = poll;
        if let Some((at, after)) = deadline {
            let now = tokio::time::Instant::now();
            if now >= at {
                tracing::info!(verb = "box wait", box_id = %id, outcome = "wait timeout");
                return Err(
                    BoxTimedOut::waited(target, &id.to_string(), &wait_label(after)).into(),
                );
            }
            pause = pause.min(at - now);
        }
        tokio::time::sleep(pause).await;
    }
}

/// `min box wait <box> [--timeout <d>]`: waits until the box ends, then
/// exits with the box's exit code.
pub async fn cmd_box_wait(global: &GlobalArgs, args: BoxWaitArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;
    let hosts = crate::cmd::list::local_hosts(global)?;
    let timeout = args.timeout.map(std::time::Duration::from_secs);
    let code = box_wait_on_hosts(hosts, &args.target, timeout, POLL_INTERVAL).await?;
    if code == 0 {
        Ok(())
    } else {
        Err(Handoff::Exit(code).into())
    }
}
