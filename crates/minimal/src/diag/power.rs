//! Host power-state capture: sleep/wake history.
//!
//! A silently-dying long-lived stream (#788) has suspend/resume as its most
//! plausible mundane explanation, and ruling that in or out previously meant
//! asking the user to run `pmset -g log` by hand. Captured here so the
//! timeline can interleave power transitions with connection events.

use std::fmt::Write as _;

use super::procs::command_capture;
use diagnostics::bundle::BundleWriter;
use diagnostics::manifest::Redaction;

/// Sleep/wake transitions kept from the (potentially huge) power log.
const POWER_EVENTS_MAX: usize = 100;

const COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// `host/power.txt`: recent sleep/wake transitions plus instant
/// last-sleep/last-wake facts. Every source is best-effort — a host without
/// the tooling records why instead of failing the collector.
pub async fn power(w: &mut BundleWriter) -> Result<(), anyhow::Error> {
    let mut text = String::new();

    if cfg!(target_os = "macos") {
        let sysctls = ["kern.boottime", "kern.sleeptime", "kern.waketime"].map(String::from);
        match command_capture("sysctl", &sysctls, COMMAND_TIMEOUT).await {
            Ok(out) => {
                let _ = writeln!(text, "$ sysctl kern.boottime kern.sleeptime kern.waketime");
                text.push_str(&out);
            }
            Err(e) => {
                let _ = writeln!(text, "(sysctl unavailable: {e:#})");
            }
        }
        // The full pmset log runs to megabytes of assertion chatter; only
        // the state-transition lines carry sleep/wake signal.
        match command_capture("pmset", &["-g".into(), "log".into()], COMMAND_TIMEOUT).await {
            Ok(out) => {
                let events: Vec<&str> = out
                    .lines()
                    .filter(|l| {
                        l.contains("Entering Sleep")
                            || l.contains("Wake from")
                            || l.contains("DarkWake from")
                    })
                    .collect();
                let tail = &events[events.len().saturating_sub(POWER_EVENTS_MAX)..];
                let _ = writeln!(
                    text,
                    "\n$ pmset -g log (sleep/wake transitions, last {} of {})",
                    tail.len(),
                    events.len()
                );
                for line in tail {
                    let _ = writeln!(text, "{}", line.trim_end());
                }
            }
            Err(e) => {
                let _ = writeln!(text, "(pmset unavailable: {e:#})");
            }
        }
    } else {
        // Linux: the journal is the only common source; kernel messages
        // alone ("PM: suspend entry/exit") avoid grepping the full journal.
        let args = ["-b", "-k", "--no-pager", "-q"].map(String::from);
        match command_capture("journalctl", &args, COMMAND_TIMEOUT).await {
            Ok(out) => {
                let events: Vec<&str> = out
                    .lines()
                    .filter(|l| {
                        l.contains("PM: suspend") || l.contains("hibernat") || l.contains("resume")
                    })
                    .collect();
                let tail = &events[events.len().saturating_sub(POWER_EVENTS_MAX)..];
                let _ = writeln!(
                    text,
                    "$ journalctl -b -k (suspend/resume lines, last {})",
                    tail.len()
                );
                for line in tail {
                    let _ = writeln!(text, "{}", line.trim_end());
                }
            }
            Err(e) => {
                let _ = writeln!(text, "(journalctl unavailable: {e:#})");
            }
        }
    }

    w.add_bytes("host/power.txt", text.as_bytes(), Redaction::None)
        .await
}
