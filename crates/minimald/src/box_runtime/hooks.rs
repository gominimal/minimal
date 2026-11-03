//! The lifecycle hooks a host runs, and the per-attach environment files it
//! publishes.

use super::*;

/// An owned snapshot of everything a hook run needs.
///
/// Owned rather than borrowed because a `Host` holds a non-`Sync`
/// `dyn NetGuard`: keeping a `&Host` alive across an await would make
/// the whole session future non-`Send`.
pub(super) struct HookPlan {
    pub(super) event: crate::hooks::HookEvent,
    pub(super) commands: crate::hooks::InjectedCommands,
    pub(super) composition: Arc<boxes::core::compose::Composition>,
    pub(super) session_id: boxes::SessionId,
    pub(super) session_name: String,
    pub(super) hooks_dir: paths::DaemonAbsPath,
    pub(super) workspace: paths::DaemonAbsPath,
    pub(super) output: crate::hooks::HookOutput,
}

/// Writes the session's per-attach environment files: `env` rendered into
/// [`ATTACH_ENV_SH_REL`], [`ATTACH_ENV_FISH_REL`], and [`ATTACH_ENV_JSON_REL`]
/// under the session's `home` directory.
///
/// This is how a fact about the *current* terminal reaches a shell that was
/// spawned for a previous one — a process's `environ` cannot be rewritten from
/// outside, so the value is published to a file the shell re-reads, at every
/// prompt and before every command, through the hooks `crate::env` installs
/// into the session rootfs. Written from the daemon's side of the session home
/// rather than through the sandbox: it is the same directory, and it works
/// before the session has anything running to inject into.
///
/// Best-effort. A failure here costs a stale `TERM` in the shell, which must
/// never be allowed to refuse an attach.
pub(super) async fn write_connection_env(home: paths::DaemonAbsPath, env: ConnectionEnv) {
    // Nothing to say: leave whatever the last attach published in place. An
    // attach that carries no facts is a client that couldn't describe its
    // terminal, not a client asserting there is no terminal.
    if env.is_empty() {
        return;
    }

    let dir = home.sub_path_unchecked(ATTACH_ENV_DIR_REL);
    if let Err(e) = tokio::fs::create_dir_all(dir.as_str()).await {
        tracing::warn!(error = %e, dir = %dir, "creating the per-attach env dir");
        return;
    }

    let mut sh = String::from("# Written by minimald on attach; edits are lost.\n");
    let mut fish = sh.clone();
    for (k, v) in &env {
        // Single quotes are the only quoting both shells read literally. POSIX
        // has no escape inside them, so a quote is closed, escaped, and
        // reopened; fish does take a backslash escape.
        sh.push_str(&format!("export {k}='{}'\n", v.replace('\'', r"'\''")));
        fish.push_str(&format!(
            "set -gx {k} '{}'\n",
            v.replace('\\', r"\\").replace('\'', r"\'")
        ));
    }

    // The data form. Serialized rather than hand-rendered so the escaping is
    // the serializer's problem; a failure here is not fatal to the others.
    let json = match serde_json_lenient::to_string_pretty(&env) {
        Ok(j) => Some(j),
        Err(e) => {
            tracing::warn!(error = %e, "rendering the per-attach env as JSON");
            None
        }
    };

    let files = [
        (ATTACH_ENV_SH_REL, Some(sh)),
        (ATTACH_ENV_FISH_REL, Some(fish)),
        (ATTACH_ENV_JSON_REL, json),
    ];
    for (rel, body) in files {
        let Some(body) = body else { continue };
        let path = home.sub_path_unchecked(rel);

        // Write a sibling and rename over the destination, rather than
        // truncating in place. A shell reads these files constantly — bash's
        // `DEBUG` trap sources one before every command — so an in-place
        // rewrite has a window where a reader sees a truncated file, and half
        // an `export TERM='xterm-256co` is a syntax error on the user's
        // terminal. `rename(2)` is atomic within a directory, and the sibling
        // is in the same one by construction.
        let tmp = home.sub_path_unchecked(&format!(
            "{rel}.{}.{}.tmp",
            std::process::id(),
            ATTACH_ENV_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        if let Err(e) = tokio::fs::write(tmp.as_str(), body).await {
            tracing::warn!(error = %e, path = %tmp, "writing the per-attach env file");
            // Nothing was published, so nothing is half-written — but the
            // sibling may exist and must not accumulate.
            let _ = tokio::fs::remove_file(tmp.as_str()).await;
            continue;
        }
        if let Err(e) = tokio::fs::rename(tmp.as_str(), path.as_str()).await {
            tracing::warn!(error = %e, path = %path, "publishing the per-attach env file");
            let _ = tokio::fs::remove_file(tmp.as_str()).await;
        }
    }
}

/// Distinguishes the temporary files [`write_connection_env`] renames into
/// place, so two attaches publishing at once cannot pick the same sibling and
/// clobber each other's half-written file.
pub(super) static ATTACH_ENV_SEQ: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Run a snapshotted plan, warning on any hook that failed.
///
/// Never fatal: an attach must not be refused, and a detach must not be
/// blocked, because a hook misbehaved.
pub(super) async fn run_hook_plan(plan: HookPlan) {
    let ctx = crate::hooks::HookContext {
        session_id: plan.session_id,
        session_name: &plan.session_name,
        composition: &plan.composition,
        hooks_dir: plan.hooks_dir,
        workspace: plan.workspace,
    };
    // No budget: the only event still routed through the host is
    // `on_attach`, which runs on the user's terminal under a command
    // they can interrupt. Teardown is budgeted where it runs, on the
    // session actor.
    for o in crate::hooks::run_hooks(&plan.commands, &ctx, plan.event, plan.output, None).await {
        if o.failed() {
            tracing::warn!(
                session = plan.session_name,
                event = o.event,
                declared_by = %o.declared_by,
                status = ?o.status,
                "lifecycle hook failed",
            );
        }
    }
}
