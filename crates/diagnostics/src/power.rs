//! Host power-state capture: sleep/wake history, so a bundle's timeline can
//! interleave power transitions with connection events. A silently-dying
//! long-lived stream (#788) has suspend/resume as its most plausible mundane
//! explanation, and ruling that in or out previously meant asking the user to
//! run `pmset -g log` by hand.

use std::fmt::Write as _;
use std::time::Duration;

use crate::bundle::{BundleSink, BundleWriter};
use crate::capture::command_stdout;
use crate::manifest::Redaction;

/// Per-command deadline for the power log tools.
const POWER_TIMEOUT: Duration = Duration::from_secs(10);
/// Sleep/wake transitions kept from the (potentially huge) power log.
const POWER_EVENTS_MAX: usize = 100;

/// The last [`POWER_EVENTS_MAX`] of `events` — the whole slice when it is
/// shorter. The full pmset/journal log runs to megabytes; only the tail of the
/// state transitions carries current signal.
fn last_events<'a>(events: &'a [&'a str]) -> &'a [&'a str] {
    &events[events.len().saturating_sub(POWER_EVENTS_MAX)..]
}

/// `<dest>/power.txt`: recent sleep/wake transitions. Best-effort — a host
/// without the tooling records why instead of failing the collector.
pub async fn power<W: BundleSink>(
    w: &mut BundleWriter<W>,
    dest: &str,
) -> Result<(), anyhow::Error> {
    let mut text = String::new();

    #[cfg(target_os = "macos")]
    {
        match command_stdout(
            "sysctl",
            &["kern.boottime", "kern.sleeptime", "kern.waketime"],
            POWER_TIMEOUT,
        )
        .await
        {
            Ok(out) => {
                let _ = writeln!(text, "$ sysctl kern.boottime kern.sleeptime kern.waketime");
                text.push_str(&out);
            }
            Err(e) => {
                let _ = writeln!(text, "(sysctl unavailable: {e})");
            }
        }
        // The full pmset log is mostly assertion chatter; only the state-
        // transition lines carry sleep/wake signal.
        match command_stdout("pmset", &["-g", "log"], POWER_TIMEOUT).await {
            Ok(out) => {
                let events: Vec<&str> = out
                    .lines()
                    .filter(|l| {
                        l.contains("Entering Sleep")
                            || l.contains("Wake from")
                            || l.contains("DarkWake from")
                    })
                    .collect();
                let tail = last_events(&events);
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
                let _ = writeln!(text, "(pmset unavailable: {e})");
            }
        }
    }

    // Linux (and any other unix): the journal's kernel messages are the only
    // common source, and "PM: suspend entry/exit" avoids grepping the whole
    // journal.
    #[cfg(not(target_os = "macos"))]
    {
        match command_stdout(
            "journalctl",
            &["-b", "-k", "--no-pager", "-q"],
            POWER_TIMEOUT,
        )
        .await
        {
            Ok(out) => {
                let events: Vec<&str> = out
                    .lines()
                    .filter(|l| {
                        l.contains("PM: suspend") || l.contains("hibernat") || l.contains("resume")
                    })
                    .collect();
                let tail = last_events(&events);
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
                let _ = writeln!(text, "(journalctl unavailable: {e})");
            }
        }
    }

    w.add_bytes(
        &format!("{dest}/power.txt"),
        text.as_bytes(),
        Redaction::None,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_events_caps_to_the_most_recent() {
        let all: Vec<String> = (0..250).map(|i| format!("evt{i}")).collect();
        let refs: Vec<&str> = all.iter().map(String::as_str).collect();
        let tail = last_events(&refs);
        assert_eq!(tail.len(), POWER_EVENTS_MAX);
        assert_eq!(tail[0], "evt150", "kept the newest 100");
        assert_eq!(tail[POWER_EVENTS_MAX - 1], "evt249");

        let few = ["a", "b", "c"];
        assert_eq!(last_events(&few).len(), 3, "fewer than the cap: all kept");
    }
}
