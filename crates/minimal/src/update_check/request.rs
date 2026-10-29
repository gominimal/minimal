//! The request and the command: the URL the child asks ([`request_url`]),
//! the one bounded GET ([`fetch_latest`]), the detached child
//! ([`spawn_background`]) and `min update-check` itself
//! ([`cmd_update_check`]).

use serde::Deserialize;

use super::{
    ENDPOINT, ENDPOINT_VAR, Install, LOCK_FILE, REQUEST_BUDGET, STATE_FILE, read_install,
    read_state, record_answer, release_lock, state_dir,
};
use crate::cli::{GlobalArgs, UpdateCheckArgs};

/// The request the child makes.
pub fn request_url(base: &str, install: &Install, id: &str) -> String {
    format!(
        "{}/{}/{}?os={}&arch={}&install={}&id={}",
        base.trim_end_matches('/'),
        install.channel,
        install.key,
        std::env::consts::OS,
        std::env::consts::ARCH,
        install.method,
        id
    )
}

pub(super) fn endpoint() -> String {
    std::env::var(ENDPOINT_VAR)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| ENDPOINT.to_string())
}

/// The detached child: this binary, `update-check --background`, its own
/// process group, null stdio, never waited on. Whether it was spawned.
pub(super) fn spawn_background(global: &GlobalArgs) -> bool {
    use std::os::unix::process::CommandExt as _;
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let mut cmd = std::process::Command::new(exe);
    if let Some(d) = &global.minimal_dir {
        cmd.arg("--minimal-dir").arg(d);
    }
    if let Some(d) = &global.config_dir {
        cmd.arg("--config-dir").arg(d);
    }
    // The child is bookkeeping, not a command of the user's: it must not
    // export or spool telemetry of its own under the parent's opt-in (an
    // integration test reading the parent's spool would see a stranger's
    // `cmd` span; a collector would count a trace nobody ran).
    // `OTEL_SDK_DISABLED` is the veto mlog honours ahead of the opt-in; the
    // check's own switch (`MINIMAL_TELEMETRY=0`) is left alone, since that
    // would stop the check itself.
    cmd.env("OTEL_SDK_DISABLED", "true")
        .env_remove(minimald_rpc::trace::TRACEPARENT_ENV)
        .args(["update-check", "--background"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .process_group(0);
    // Not waited on: a child that outlives a short command is reparented;
    // one that outlives a long one is reaped with it.
    cmd.spawn().is_ok()
}

/// The endpoint's answer.
#[derive(Debug, Deserialize)]
struct Answer {
    channel: String,
    latest: String,
}

/// One GET within [`REQUEST_BUDGET`], no retry. Any failure is `None`.
pub async fn fetch_latest(url: &str) -> Option<(String, String)> {
    // One fixed-host GET: a redirect would carry the query (the install id,
    // the OS) to whatever host the answer named, over whatever scheme, so
    // none is followed.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_BUDGET)
        .connect_timeout(REQUEST_BUDGET)
        .user_agent(format!("min/{}", version::VERSION))
        .build()
        .ok()?;
    let resp = client.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let text = resp.text().await.ok()?;
    let answer: Answer = serde_json_lenient::from_str(&text).ok()?;
    let ok = |s: &str| {
        !s.is_empty()
            && s.len() <= 64
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    };
    (ok(&answer.channel) && ok(&answer.latest)).then_some((answer.channel, answer.latest))
}

/// `min update-check`: the check, now. `--background` is the detached
/// child (silent, exit 0 whatever happens); `--dry-run` prints the request
/// that would be made and the switch that stops it, if any; neither flag
/// makes the request in the foreground and prints the answer.
pub async fn cmd_update_check(
    global: &GlobalArgs,
    args: UpdateCheckArgs,
) -> Result<(), anyhow::Error> {
    let off = super::off(global);
    let Some(dir) = state_dir(global) else {
        anyhow::bail!("no state directory (HOME is not set)");
    };
    let state_path = dir.join(STATE_FILE);
    let mut state = read_state(&state_path);
    let install = read_install(&dir, std::env::current_exe().ok().as_deref());
    // The placeholder is for the eye only: a request is never made with it.
    // A foreground check the user asked for on a fresh install mints the id
    // first, as a first command would; the background child never runs
    // without one (its parent minted it).
    // A disabled install keeps no id: the switches are read first.
    if state.install_id.is_none() && off.is_none() && !args.dry_run && !args.background {
        // Sent only once it is on disk, and minted under the spawn lock by
        // re-reading the file (as the per-command hook does): an id that was
        // not written, or one written over another command's, would count
        // the install twice.
        state = super::state::claim_install_id(&dir, &state_path).ok_or_else(|| {
            anyhow::anyhow!(
                "another min command is minting the install id or checking now; run this again"
            )
        })?;
    }
    let id = state
        .install_id
        .clone()
        .unwrap_or_else(|| "<minted on the first run>".to_string());
    let url = request_url(&endpoint(), &install, &id);

    if args.dry_run {
        println!("GET {url}");
        match off {
            Some(off) => println!("disabled by {off}: the request is not made"),
            None => println!("enabled: made at most once every 24 hours"),
        }
        println!(
            "channel {} via {}, installed key {}",
            install.channel, install.method, install.key
        );
        return Ok(());
    }
    if args.background {
        if off.is_none() && state.install_id.is_some() {
            let answer = fetch_latest(&url).await;
            record_answer(&state_path, answer);
        }
        release_lock(&dir.join(LOCK_FILE));
        return Ok(());
    }
    if let Some(off) = off {
        anyhow::bail!("the update check is disabled by {off}");
    }
    match fetch_latest(&url).await {
        Some((channel, latest)) => {
            let standing = if latest == install.key {
                "up to date"
            } else {
                "newer pointer available"
            };
            println!(
                "{channel}: {latest} ({standing}; installed key {})",
                install.key
            );
            if state.install_id.is_some() {
                record_answer(&state_path, Some((channel, latest)));
            }
            Ok(())
        }
        None => anyhow::bail!("no answer from {url} within {}s", REQUEST_BUDGET.as_secs()),
    }
}
