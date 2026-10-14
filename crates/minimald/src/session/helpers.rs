//! Free-function helper cluster for [`super`]'s session implementation:
//! patch materialization, lifecycle-hook running and logging, composition
//! loading, name registration, and the inherited-environment builder.

use super::*;

/// Copy every `composition.patches()` entry from the staged
/// `<workspace>/patches/<dest>` into the session's home dir at
/// the same relative path. Called once by [`Session::finalize`]
/// when the session goes `Active`; subsequent attaches see the
/// populated home without re-copying.
///
/// Parent dirs are created as needed. A missing staged patch
/// surfaces as an `io::Error` — the FinalizeSession precondition
/// checked the patches-ready marker, so a missing file at this
/// point is a bug (the marker was written but the file it should
/// have gated on didn't land).
///
/// The copy is `fs::copy` specifically because it carries the source's
/// permission bits across, which is the last link in the chain that
/// keeps a patched script executable in the session (the unpacker set
/// those bits on the staged file from the tar header). A hand-rolled
/// read-then-write here would silently flatten every patch to the
/// daemon's umask default.
pub(crate) async fn materialize_patches_into_home(
    patches_dir: &DaemonAbsPath,
    home_dir: &DaemonAbsPath,
    composition: &Composition,
) -> Result<(), std::io::Error> {
    for sp in composition.patches() {
        let dest = sp.patch().destination().as_utf8_path();
        let src = patches_dir.as_utf8_path().join(dest);
        let target = home_dir.as_utf8_path().join(dest);
        if let Some(parent) = target.parent() {
            tokio::fs::create_dir_all(parent.as_std_path()).await?;
        }
        tokio::fs::copy(src.as_std_path(), target.as_std_path())
            .await
            .map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!(
                        "materializing patch {} → {}: {e}",
                        src.as_str(),
                        target.as_str()
                    ),
                )
            })?;
    }
    Ok(())
}

/// Run the session's hooks for `event` and log what each one did.
///
/// Returns an empty list when there is nothing to run *or nothing to
/// run it in*: a session with no composition, or with no live host,
/// has no namespaces to join. That is not an error — a session that
/// was never attached, whose shell has exited, or that came up from
/// disk after a daemon restart genuinely has no sandbox for a hook to
/// enter, and teardown must proceed regardless.
pub(super) async fn run_session_hooks(
    inner: &SessionInner,
    record: &SessionRecordHandle,
    event: crate::hooks::HookEvent,
) -> Vec<crate::hooks::HookOutcome> {
    use sessions::store::SessionObject as _;

    let SessionInner::Active {
        composition: Some(composition),
        host: Some((handle, _)),
        ..
    } = inner
    else {
        return Vec::new();
    };
    let object = match record.object().await {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!(
                event = event.as_str(),
                error = %e,
                "reading the session record failed; skipping lifecycle hooks",
            );
            return Vec::new();
        }
    };
    let name = registry_name(object.record());
    let ctx = crate::hooks::HookContext {
        session_id: *record.id(),
        session_name: &name,
        composition,
        hooks_dir: object.hooks_path(),
        workspace: object.workspace_path(),
    };
    // Teardown runs under one budget across all of its hooks; setup runs
    // unbounded (see [`crate::hooks::run_hooks`]). Every event reaching
    // this function is headless, and the two teardown ones are the pair
    // that must not be able to hold a session open.
    let budget = event.is_teardown().then_some(TEARDOWN_HOOK_BUDGET);
    let outcomes = crate::hooks::run_hooks(
        handle,
        &ctx,
        event,
        crate::hooks::HookOutput::Capture,
        budget,
    )
    .await;
    log_hook_outcomes(&name, &outcomes);
    outcomes
}

/// Emit one record per hook run. Failures are warnings so an operator
/// sees them without turning on debug logging; the captured tail rides
/// along because a hook's own output is usually the only explanation
/// of why it failed.
pub(crate) fn log_hook_outcomes(session: &str, outcomes: &[crate::hooks::HookOutcome]) {
    for o in outcomes {
        if o.failed() {
            tracing::warn!(
                session,
                event = o.event,
                declared_by = %o.declared_by,
                status = ?o.status,
                output = %o.output,
                "lifecycle hook failed",
            );
        } else {
            tracing::info!(
                session,
                event = o.event,
                declared_by = %o.declared_by,
                "lifecycle hook ran",
            );
        }
    }
}

/// True when `composition` has a hook whose external script can only
/// reach the daemon through the hook-script upload — and which therefore
/// must not be finalized until that upload lands.
///
/// Two exclusions, and both are the difference between a session that
/// activates and one that cannot:
///
/// - **Inline** hooks carry their body in the composition, so a session
///   whose hooks are all inline uploads nothing and must not wait on a
///   marker that will never appear.
/// - **Project** hooks name a path inside the project, and the project
///   tree is uploaded wholesale by the activation that precedes this.
///   Their scripts arrive with it, which is why the client stages only
///   *loadout* scripts and why [`crate::hooks::read_script`] falls back
///   to the workspace for a project source. Gating on the marker here
///   would demand an upload that is never sent, and no project could
///   ever declare an external hook script.
pub(crate) fn composition_needs_staged_scripts(composition: &Composition) -> bool {
    use sessions::core::lifecyclehook::{HookScript, HookScriptBody};
    use sessions::core::source::{Provenanced, Source};
    composition
        .lifecycle_hooks()
        .iter()
        .filter(|ph| !matches!(ph.source(), Source::Project { .. }))
        .any(|ph| {
            let hook = ph.hook();
            [
                hook.on_activate(),
                hook.on_destroy(),
                hook.on_attach(),
                hook.on_detach(),
            ]
            .into_iter()
            .flatten()
            .map(HookScript::body)
            .any(|b| matches!(b, HookScriptBody::External(_)))
        })
}

/// Load the persisted composition snapshot for an `Active` session
/// brought up from disk after a daemon restart. Returns `None` (with
/// a warning log) when the sidecar is missing or corrupt. The
/// launcher then falls back to its baseline set, preserving the
/// "attach still works" property at the cost of the lost loadout
/// contributions. This is the loud-fallback path: the operator sees
/// the warning instead of a silent drop.
pub(crate) async fn load_composition(record: &SessionRecordHandle) -> Option<Arc<Composition>> {
    match record.load_composition().await {
        Ok(Some(comp)) => Some(Arc::new(comp)),
        Ok(None) => {
            tracing::warn!(
                session_id = %record.id(),
                "no composition snapshot for Active session; falling back to baseline",
            );
            None
        }
        Err(e) => {
            tracing::warn!(
                session_id = %record.id(),
                error = %e,
                "failed to load composition snapshot; falling back to baseline",
            );
            None
        }
    }
}

/// The name a session's PTask hostname is registered under, doubling as the
/// session host's display name: the session's assigned name, or the project
/// directory's basename when unnamed.
pub(crate) fn registry_name(record: &Record) -> String {
    match &record.name {
        Some(s) => s.clone(),
        None => record
            .project_path
            .file_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "session".to_string()),
    }
}

/// The server-side `AcceptEnv` allowlist: locale and timezone vars a client is
/// permitted to forward from its shell into the session (OpenSSH's default
/// `AcceptEnv LANG LC_*`, plus `TZ`). Everything else the client set on the
/// channel — e.g. `MINIMAL_SESSION_ID`, `TRACEPARENT`, and the session-key
/// negotiation vars in `sessions::keys` (`LEADER_ENV`, `DETACH_KEY_ENV`,
/// `FORWARD_KEY_ENV`, `BELL_ENV`) — is control plumbing read by the daemon's
/// `shell_request` (and re-validated as a backstop) and must not leak into the
/// shell environment, so it is filtered out here.
pub(crate) fn inherited_session_env(
    channel_env: &std::collections::BTreeMap<String, String>,
) -> Vec<(String, String)> {
    channel_env
        .iter()
        .filter(|(k, _)| k.as_str() == "LANG" || k.as_str() == "TZ" || k.starts_with("LC_"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}
