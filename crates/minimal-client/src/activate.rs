//! Headless session activation: the create → upload → configure → gate →
//! finalize sequence every front-end shares.
//!
//! The front-ends (`min session activate`, `min task run`, the dashboard) own
//! everything the sequence is *told*: path and loadout resolution, the
//! `minimal.toml` scaffold offer, config and policy reads, working-directory
//! announcements, and the interactive prompt. This module owns the daemon
//! conversation, the gate callback for a `Pending` composition, and the
//! cleanup around a half-built record.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, bail};
use minimald_rpc::{
    AbortSession, AbortSessionRequest, ConfigureLoadout, ConfigureLoadoutRequest, CreateSession,
    CreateSessionRequest, DestroySession, DestroySessionRequest, Errorable, FinalizeSession,
    FinalizeSessionRequest, SessionConfig,
};

use crate::{Client, ensure_version_reported, version_assertion};

/// The daemon collapses its session-store `AlreadyExists` into a plain message
/// (`serve_create_session` in `crates/minimald/src/rpc.rs`); match it so an
/// autogen name clash can be told apart from any other `CreateSession`
/// failure.
fn is_name_collision(error: &str) -> bool {
    error.contains("already exists")
}

/// Everything [`activate`] needs, resolved by the caller.
pub struct ActivateRequest {
    /// The session record to create.
    pub config: SessionConfig,
    /// Upload this directory into the fresh session before composing. `None`
    /// skips the upload (the caller's `--sync none`, or a tree it decided not
    /// to send).
    pub upload_root: Option<PathBuf>,
    /// The loadout contribution to compose.
    pub contribution: sessions::wire::request::WireContribution,
    /// External hook scripts staged for upload alongside the composition's
    /// patches.
    pub hook_scripts: Vec<sessions::client::hookscripts::StagedScript>,
    /// Deadline extension for `FinalizeSession`, sized to the composition's
    /// `on_activate` hook timeouts.
    pub hook_budget: Duration,
    /// Mint a replacement name after the daemon rejects an autogen name as a
    /// collision. `None` for a caller-named session, which never retries.
    pub rename_on_collision: Option<Box<dyn Fn() -> String + Send + Sync>>,
    /// Bound on the collision retries above.
    pub max_rename_attempts: u32,
    /// Socket to reconnect to if the user interrupts the activation, so the
    /// half-built session can be aborted. `None` leaves the interruption to
    /// the front-end.
    pub interrupt_socket: Option<PathBuf>,
    /// Render the error for a session whose composition could not be started.
    /// The front-end owns the wording because it names the project directory
    /// the user ran from.
    pub compose_failure: Box<dyn Fn(&str) -> anyhow::Error + Send + Sync>,
}

/// The front-end's half of activation: the announcements that bracket the
/// create, and the policy gate a `Pending` composition demands.
///
/// The gate's futures are not `Send`-bounded here: the CLI's interactive gate
/// holds a non-`Send` prompter, and an activation runs on one task. A caller
/// that needs a `Send` future (the MCP server) supplies a concrete, `Send`
/// gate and calls [`activate`] directly.
#[allow(
    async_fn_in_trait,
    reason = "the interactive gate is deliberately single-threaded; a Send caller supplies its own gate"
)]
pub trait ActivationGate {
    /// Called once the record exists and its build has been checked, before
    /// the upload. The default is silent.
    async fn on_created(&mut self, _created: &minimald_rpc::CreateSessionResponse) {}

    /// Gate a `Pending` configure response. Implementations submit the
    /// verdict and return the daemon-side patches the client approved, or
    /// abort the session and return an error.
    async fn on_pending(
        &mut self,
        client: &mut Client,
        response: sessions::wire::request::ContributionResponse,
    ) -> Result<Vec<(PathBuf, paths::SandboxRelPath)>, anyhow::Error>;
}

/// Create, populate, compose, gate, and finalize a session, returning its id.
///
/// The caller connects the [`Client`] and resolves every input — the daemon
/// connection stays in the front-end because spawning a daemon (or a VM)
/// pulls in `minvmd`, which is deliberately not a dependency here.
pub async fn activate<G: ActivationGate>(
    client: &mut Client,
    request: ActivateRequest,
    gate: &mut G,
) -> Result<sessions::SessionId, anyhow::Error> {
    let mut config = request.config.clone();
    let mut attempts = 0u32;
    let created = loop {
        let resp = client
            .oneshot_rpc::<CreateSession>(CreateSessionRequest {
                config: config.clone(),
                // The version gate: a daemon of another build refuses this
                // call outright, before it has allocated anything to tear
                // down. `None` under the skew override, which lets an
                // operator proceed.
                must_match_version: version_assertion(),
            })
            .await
            .context("CreateSession RPC failed")?;
        match resp {
            Errorable::Ok(r) => break r,
            Errorable::Err { error } => {
                if request.rename_on_collision.is_some()
                    && attempts < request.max_rename_attempts
                    && is_name_collision(&error)
                {
                    attempts += 1;
                    if let Some(regen) = &request.rename_on_collision {
                        config.name = Some(regen());
                    }
                    continue;
                }
                bail!("CreateSession failed: {error}");
            }
        }
    };
    // The other half of the gate: a daemon old enough to predate
    // `must_match_version` ignored the assertion instead of answering it, and
    // says so by echoing no version at all. Being older than the field is
    // itself proof of a skew, so refuse here — still before the upload, the
    // loadout, and the finalize that #1251 died at, and with the session left
    // unfinalized for the daemon to reap when this connection drops.
    ensure_version_reported(created.daemon_version.as_deref())?;
    gate.on_created(&created).await;
    let id = created.id;

    // From here the session exists on the daemon in an unfinalized state.
    // Arm a Ctrl-C guard so an interrupt during the (blocking) gating prompt
    // tears it down instead of orphaning it in `Pending`. Dropped once the
    // session is `Active`.
    let _interrupt = request
        .interrupt_socket
        .as_deref()
        .map(|sock| ActivationInterrupt::arm(Some(sock), id));

    if let Some(root) = request.upload_root.as_deref() {
        client
            .upload_workspace_files_quiet(id, root)
            .await
            .context("Failed to upload project files")?;
    }

    // Client-side patches (from loadouts) land in the final Composition
    // whether the response is `Materialized` or `Pending`, so the client is
    // authoritative for them. Daemon-side patches approved through a `Pending`
    // gate are appended below.
    let mut patches: Vec<(PathBuf, paths::SandboxRelPath)> = request
        .contribution
        .patches
        .iter()
        .map(|p| {
            (
                p.patch.host_path.as_utf8_path().as_std_path().to_path_buf(),
                p.patch.destination.clone(),
            )
        })
        .collect();

    // Composing is a second round-trip because the daemon's composer reads
    // the project config out of the session's workspace, not from a path on
    // this machine.
    let configured = client
        .oneshot_rpc::<ConfigureLoadout>(ConfigureLoadoutRequest {
            session_id: id,
            contribution: request.contribution,
        })
        .await
        .context("ConfigureLoadout RPC failed")?;
    let configured = match configured {
        Errorable::Ok(r) => r,
        // A session that cannot compose never reaches the front-end's
        // success path; the caller's wording names the directory, not the
        // internal step.
        Errorable::Err { error } => return Err((request.compose_failure)(&error)),
    };

    if let minimald_rpc::ConfigureLoadoutResponse::Pending { response } = configured {
        let approved = gate.on_pending(client, response).await?;
        patches.extend(approved);
    }

    // Upload composition patches and finalize. This has to happen before
    // attach is allowed — a `Materializing` session isn't attachable, and the
    // launcher reads patches from `<workspace>/patches/`. Dedup by sandbox
    // destination: the composer's post-gate check guarantees any duplicates
    // are exact matches (same source), so collapsing is safe.
    patches.sort_by(|a, b| a.1.as_str().cmp(b.1.as_str()));
    patches.dedup_by(|a, b| a.1.as_str() == b.1.as_str());
    if let Err(e) = upload_and_finalize(
        client,
        id,
        &patches,
        &request.hook_scripts,
        request.hook_budget,
    )
    .await
    {
        // Best-effort teardown: the session is stuck in `Materializing` on
        // the daemon. Destroy it so the operator's `min ls` doesn't fill with
        // half-finalized sessions.
        best_effort_destroy(client, id).await;
        return Err(e);
    }

    drop(_interrupt);
    Ok(id)
}

/// Upload the composition's patches and external hook scripts (if any) and
/// finalize the session. The session is `Materializing` at entry; `Active` on
/// success. On upload/finalize failure the session is left in
/// `Materializing` — the caller is responsible for destroying it.
///
/// Both uploads precede `FinalizeSession`, which gates on each upload's
/// ready-marker: a session must not become attachable while either its patches
/// or its hook scripts are still missing from the daemon.
///
/// `hook_budget` is the summed declared timeout of the composition's
/// `on_activate` hooks, which the daemon runs inside `FinalizeSession`; the
/// call's deadline is extended by it so a hook declaring more than the base
/// RPC timeout is not cut short.
pub async fn upload_and_finalize(
    client: &mut Client,
    session_id: sessions::SessionId,
    patches: &[(PathBuf, paths::SandboxRelPath)],
    hook_scripts: &[sessions::client::hookscripts::StagedScript],
    hook_budget: Duration,
) -> Result<(), anyhow::Error> {
    client
        .upload_patches(session_id, patches)
        .await
        .context("Failed to upload composition patches")?;

    client
        .upload_hook_scripts(session_id, hook_scripts)
        .await
        .context("Failed to upload lifecycle hook scripts")?;

    let resp = client
        .oneshot_rpc_with_hook_budget::<FinalizeSession>(
            FinalizeSessionRequest { session_id },
            hook_budget,
        )
        .await
        .context("FinalizeSession RPC failed")?;
    match resp {
        Errorable::Ok(ok) => {
            // An activate hook runs headlessly, so without this the only trace
            // of it is the daemon log. Say what ran — the user agreed to let
            // this code execute, and is owed the receipt.
            for hook in &ok.activate_hooks {
                match hook.description.as_deref() {
                    Some(d) => eprintln!("Ran activation hook from {}: {d}", hook.declared_by),
                    None => eprintln!("Ran activation hook from {}", hook.declared_by),
                }
                // The description is an author-supplied label; what the hook
                // actually said is its captured output. Echo it to stderr —
                // stdout is reserved for the bare session id.
                if !hook.output.is_empty() {
                    eprint!("{}", hook.output);
                    if !hook.output.ends_with('\n') {
                        eprintln!();
                    }
                }
            }
            Ok(())
        }
        Errorable::Err { error } => {
            bail!("FinalizeSession failed: {error}");
        }
    }
}

/// Best-effort destroy for a `Materializing` session the client couldn't
/// finalize (patch upload failed, network blip, etc.). Unlike `AbortSession`,
/// `DestroySession` works on any status past `Pending`. Errors are logged,
/// not propagated — the caller is already reporting a primary error.
///
/// Bounded by a hard timeout: the same network conditions that caused the
/// primary error (wedged daemon, half-open SSH channel, a VM whose bridge
/// accepted but whose guest never answered) can make the RPC hang
/// indefinitely, which would swallow the operator-visible primary error the
/// caller is racing back to its own command.
pub async fn best_effort_destroy(client: &mut Client, session_id: sessions::SessionId) {
    /// Ceiling on how long we let a cleanup RPC run. Chosen well above a
    /// healthy `DestroySession` (single-digit milliseconds on a UDS) so the
    /// timeout only fires against pathologies.
    const DESTROY_TIMEOUT: Duration = Duration::from_secs(10);
    let call = client.oneshot_rpc::<DestroySession>(DestroySessionRequest { id: session_id });
    match tokio::time::timeout(DESTROY_TIMEOUT, call).await {
        Ok(Ok(Errorable::Ok(_))) => {}
        Ok(Ok(Errorable::Err { error })) => {
            eprintln!("DestroySession failed while cleaning up: {error}");
        }
        Ok(Err(e)) => {
            eprintln!("DestroySession RPC failed while cleaning up: {e}");
        }
        Err(_) => {
            eprintln!(
                "DestroySession timed out after {DESTROY_TIMEOUT:?} while cleaning up \
                 session {session_id}; the session may still be present on the daemon \
                 (run `min session destroy {session_id}` to clean up manually)",
            );
        }
    }
}

/// Guard that tears down a half-built session if the user interrupts an
/// activation with Ctrl-C.
///
/// The front-end's interactive prompt captures a Ctrl-C as an error return, so
/// the gate's own abort-cleanup runs. During the non-prompt phases (waiting on
/// the daemon) a Ctrl-C is a plain SIGINT, which would kill the process before
/// that cleanup, leaving the daemon holding a `Pending` session that blocks
/// its name. [`ActivationInterrupt::arm`] installs a SIGINT handler that
/// best-effort `AbortSession`s the in-flight session over a fresh connection —
/// the activation borrows the primary one — then exits. The daemon's
/// connection-close reap is the backstop if the abort can't be delivered.
///
/// Dropping the guard cancels the handler, so a Ctrl-C after the session is
/// safely `Active` no longer tears it down.
pub struct ActivationInterrupt {
    task: tokio::task::JoinHandle<()>,
}

impl ActivationInterrupt {
    /// Arm the guard for `session_id`, reconnecting to `sock` to abort it on
    /// an interrupt. `None` skips arming (no known socket).
    pub fn arm(sock: Option<&Path>, session_id: sessions::SessionId) -> Self {
        let sock = sock.map(Path::to_path_buf);
        let task = tokio::spawn(async move {
            // Only the first Ctrl-C is intercepted; a second falls through to
            // the default disposition so a wedged cleanup can still be killed.
            if tokio::signal::ctrl_c().await.is_err() {
                return;
            }
            eprintln!("\nAborting activation; cleaning up session {session_id}…");
            // Deliberately not version-gated: this is the cleanup half of an
            // activation the gate already cleared, and a cleanup that refuses
            // to run is the orphaned session #1251 is about.
            if let Some(sock) = sock
                && let Ok(mut client) = Client::connect(&sock).await
            {
                let _ = client
                    .oneshot_rpc::<AbortSession>(AbortSessionRequest { id: session_id })
                    .await;
            }
            std::process::exit(130);
        });
        ActivationInterrupt { task }
    }
}

impl Drop for ActivationInterrupt {
    fn drop(&mut self) {
        self.task.abort();
    }
}
