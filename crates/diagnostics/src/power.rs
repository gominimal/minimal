//! Host power-state capture: sleep/wake history, shutdown cause, and kernel
//! panic reports, so a bundle's timeline can interleave power transitions with
//! connection events. A silently-dying long-lived stream (#788) has
//! suspend/resume as its most plausible mundane explanation, and ruling that
//! in or out previously meant asking the user to run `pmset -g log` by hand.
//!
//! The same question one step harder is "my Mac rebooted under it" (#1222):
//! that needs the shutdown cause and the panic report, not the sleep/wake
//! lines, which is why the pmset capture keeps the restart events in their own
//! bucket rather than letting a laptop's daily sleeps evict them.

use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

use anyhow::Context as _;

use crate::bundle::{BundleSink, BundleWriter, open_regular_nofollow};
use crate::capture::command_stdout;
use crate::manifest::Redaction;

/// Per-command deadline for the power log tools.
const POWER_TIMEOUT: Duration = Duration::from_secs(10);
/// Sleep/wake transitions kept from the (potentially huge) power log.
const POWER_EVENTS_MAX: usize = 100;
/// Journal lines read before filtering. The capture buffers the command's
/// whole stdout, so the read is bounded at the source rather than after the
/// fact; suspend/resume lines are sparse enough that the newest few thousand
/// comfortably cover [`POWER_EVENTS_MAX`] transitions.
#[cfg(not(target_os = "macos"))]
const JOURNAL_LINES_MAX: &str = "5000";

/// Panic reports named in the capture. Only the newest is excerpted; the rest
/// are listed so a reader can see whether this host panics repeatedly.
const PANIC_REPORTS_LISTED: usize = 10;

/// Opening lines excerpted from the newest panic report. Enough to carry the
/// `panic(cpu N caller …)` string and the top of the backtrace — which name
/// the panicking subsystem — and no more: a whole crash log is a dump of the
/// user's machine state, not evidence anyone asked to share.
const PANIC_EXCERPT_LINES: usize = 40;

/// Byte ceiling on the excerpt read, applied before the line cap so a report
/// written as one enormous line cannot pull the whole file into the bundle.
const PANIC_EXCERPT_BYTES: u64 = 8 * 1024;

/// The last [`POWER_EVENTS_MAX`] of `events` — the whole slice when it is
/// shorter. The full pmset/journal log runs to megabytes; only the tail of the
/// state transitions carries current signal.
fn last_events<'a>(events: &'a [&'a str]) -> &'a [&'a str] {
    &events[events.len().saturating_sub(POWER_EVENTS_MAX)..]
}

/// `<dest>/power.txt`: recent sleep/wake transitions and, on macOS, the
/// shutdown-cause and boot events that date a restart. Best-effort — a host
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
        // transition and restart lines carry signal. The two get independent
        // caps: a laptop sleeps many times a day, so a shared cap would evict
        // the restart lines — the ones a "my Mac rebooted" report turns on —
        // while they were still the newest thing that mattered.
        match command_stdout("pmset", &["-g", "log"], POWER_TIMEOUT).await {
            Ok(out) => {
                text.push_str(&pmset::sections(&out));
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
        // `-n` bounds the read at the source: `command_stdout` buffers all of
        // stdout before returning, and a whole boot's kernel journal can run to
        // many megabytes of which we keep 100 lines. `-n` yields the *newest*
        // lines, which is the end we filter for anyway.
        match command_stdout(
            "journalctl",
            &["-b", "-k", "--no-pager", "-q", "-n", JOURNAL_LINES_MAX],
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

/// Pure text handling for `pmset -g log` output.
///
/// Deliberately not `cfg`-gated to macOS even though only the macOS arm runs
/// `pmset`: these filters are the #1222 regression surface, and the tests that
/// pin them have to run on the lane that actually runs this crate's suite. The
/// unused-on-Linux allow is the price of that coverage.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod pmset {
    use std::fmt::Write as _;

    use super::last_events;

    /// Detail substrings marking a sleep/wake transition.
    const SLEEP_WAKE: &[&str] = &["Entering Sleep", "Wake from", "DarkWake from"];

    /// Detail substring of the line naming why the machine last went down. A
    /// negative cause is the kernel's own verdict — panic, watchdog, power
    /// loss — which is the fact that separates "minimal wedged the box" from
    /// "the box died under it".
    const SHUTDOWN_CAUSE: &str = "Shutdown Cause";

    /// Event-type columns kept whole. `Boot` carries no detail substring
    /// distinctive enough to match on, and it is the line that dates the
    /// restart a shutdown cause explains.
    const RESTART_EVENT_TYPES: &[&str] = &["Boot"];

    /// The kept sections of a `pmset -g log` dump: restart events, then
    /// sleep/wake transitions.
    ///
    /// The two are capped independently. A laptop sleeps many times a day, so
    /// one shared cap would evict the restart lines — the ones a "my Mac
    /// rebooted" report turns on — while they were still the newest thing that
    /// mattered.
    pub(super) fn sections(out: &str) -> String {
        let restarts: Vec<&str> = out.lines().filter(|l| is_restart(l)).collect();
        let sleep_wake: Vec<&str> = out
            .lines()
            .filter(|l| SLEEP_WAKE.iter().any(|m| l.contains(m)))
            .collect();
        let mut text = String::new();
        push_section(&mut text, "shutdown cause / boot", &restarts);
        push_section(&mut text, "sleep/wake transitions", &sleep_wake);
        text
    }

    /// One labelled, tail-capped section under its echoed command banner.
    fn push_section(text: &mut String, label: &str, events: &[&str]) {
        let tail = last_events(events);
        let _ = writeln!(
            text,
            "\n$ pmset -g log ({label}, last {} of {})",
            tail.len(),
            events.len()
        );
        for line in tail {
            let _ = writeln!(text, "{}", line.trim_end());
        }
    }

    /// Whether a line records the machine going down or coming back up.
    fn is_restart(line: &str) -> bool {
        line.contains(SHUTDOWN_CAUSE)
            || event_type(line).is_some_and(|t| RESTART_EVENT_TYPES.contains(&t))
    }

    /// The event-type column of a log line — the field after the
    /// `YYYY-MM-DD HH:MM:SS ±ZZZZ` timestamp. `None` for anything that does
    /// not open a record (headers, blanks, wrapped detail lines), which is
    /// what keeps `BootCache` assertion chatter out of the restart bucket.
    fn event_type(line: &str) -> Option<&str> {
        let mut fields = line.split_whitespace();
        let date = fields.next()?;
        let opens_a_record = date.len() == 10
            && date.as_bytes()[4] == b'-'
            && date.starts_with(|c: char| c.is_ascii_digit());
        // Past the time and the zone offset sits the event type.
        opens_a_record.then(|| fields.nth(2)).flatten()
    }
}

/// Where the OS writes kernel panic reports; `None` on a platform with no such
/// facility — the honest answer for Linux, whose panics go to the kernel ring
/// buffer the [`kmsg`](crate::kmsg) collector already carries.
const fn panic_report_dir() -> Option<&'static str> {
    #[cfg(target_os = "macos")]
    {
        Some("/Library/Logs/DiagnosticReports")
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// `<dest>/panic.txt`: the newest kernel panic reports by name, plus the
/// opening lines of the newest.
///
/// A hard reboot leaves the *why* in a panic report, and "was it us?" is
/// answered by the subsystem the panic string names. The capture carries
/// enough to read that and no more — a whole panic log is a dump of the user's
/// machine state, not evidence anyone offered to share.
///
/// Best-effort throughout: a missing directory and an empty one are both
/// recorded as data. Where the platform has no panic reports at all, the entry
/// is a manifest skip rather than an error.
pub async fn panic_report<W: BundleSink>(
    w: &mut BundleWriter<W>,
    dest: &str,
) -> Result<(), anyhow::Error> {
    let path = format!("{dest}/panic.txt");
    let Some(dir) = panic_report_dir() else {
        w.skip(path, "kernel panic reports are a macOS facility");
        return Ok(());
    };
    let text = panic_report_text(Path::new(dir)).await;
    w.add_bytes(&path, text.as_bytes(), Redaction::None).await
}

/// The panic-report capture for `dir`. Parameterized by directory so the
/// mechanic is exercisable without the real system location.
async fn panic_report_text(dir: &Path) -> String {
    let reports =
        crate::logs::newest_matching(dir, PANIC_REPORTS_LISTED, |name| name.ends_with(".panic"))
            .await;
    let mut text = String::new();
    let _ = writeln!(
        text,
        "$ ls -t {}/*.panic | head -{PANIC_REPORTS_LISTED}",
        dir.display()
    );
    for report in &reports {
        let _ = writeln!(text, "{}", report.display());
    }
    let Some(newest) = reports.first() else {
        let _ = writeln!(text, "(no panic reports)");
        return text;
    };
    let _ = writeln!(
        text,
        "\n=== {} (first {PANIC_EXCERPT_LINES} lines) ===",
        newest.display()
    );
    match report_excerpt(newest).await {
        Ok(excerpt) => text.push_str(&excerpt),
        Err(e) => {
            let _ = writeln!(text, "(unreadable: {e:#})");
        }
    }
    text
}

/// The opening lines of a panic report, read no-follow and capped at both
/// [`PANIC_EXCERPT_BYTES`] and [`PANIC_EXCERPT_LINES`]. A panic report opens
/// with its JSON metadata header and the `panic(cpu N caller …)` string, so
/// the front of the file is exactly the identifying part.
async fn report_excerpt(path: &Path) -> Result<String, anyhow::Error> {
    use tokio::io::AsyncReadExt as _;

    let (file, _) = open_regular_nofollow(path).await?;
    let mut head = Vec::new();
    file.take(PANIC_EXCERPT_BYTES)
        .read_to_end(&mut head)
        .await
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(String::from_utf8_lossy(&head)
        .lines()
        .take(PANIC_EXCERPT_LINES)
        .fold(String::new(), |mut acc, line| {
            let _ = writeln!(acc, "{}", line.trim_end());
            acc
        }))
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

    /// A `pmset -g log` dump shaped like the real thing: a restart (shutdown
    /// cause plus the boot that followed), sleep/wake transitions around it,
    /// and the assertion chatter that dominates the file.
    fn pmset_dump(sleeps: usize) -> String {
        let mut dump = String::from(
            "2026-08-11 03:14:07 -0700 Assertions      \tPID 148(powerd) Summary BootCache\n\
             2026-08-11 03:14:09 -0700 Summary         \tShutdown Cause: -128\n\
             2026-08-11 03:15:44 -0700 Boot            \tOS Version: macOS 26.1\n",
        );
        for i in 0..sleeps {
            let _ = writeln!(
                dump,
                "2026-08-11 0{}:00:00 -0700 Sleep           \t\
                 Entering Sleep state due to 'Idle Sleep': Using AC",
                i % 10
            );
            let _ = writeln!(
                dump,
                "2026-08-11 0{}:30:00 -0700 Wake            \tWake from Standby: due to xhci",
                i % 10
            );
        }
        dump
    }

    /// #1222: a bundle has to be able to answer "why did my Mac reboot".
    /// The shutdown cause and the boot line that follows it are what pin
    /// hardware-or-panic against a minimal-side hang.
    #[test]
    fn pmset_capture_keeps_the_shutdown_cause_and_boot() {
        let text = pmset::sections(&pmset_dump(2));
        assert!(
            text.contains("Shutdown Cause: -128"),
            "the shutdown cause is the whole point: {text}"
        );
        assert!(text.contains("Boot            \tOS Version"), "{text}");
        assert!(
            !text.contains("Summary BootCache"),
            "assertion chatter must not ride in on the `Boot` match: {text}"
        );
        assert!(text.contains("Entering Sleep"), "{text}");
        assert!(text.contains("Wake from Standby"), "{text}");
    }

    /// The restart lines get their own cap: a laptop that sleeps all day must
    /// not push the reboot record out of the capture.
    #[test]
    fn frequent_sleeps_do_not_evict_the_restart_lines() {
        let text = pmset::sections(&pmset_dump(POWER_EVENTS_MAX * 2));
        assert!(text.contains("Shutdown Cause: -128"), "{text}");
        assert!(
            text.contains("(sleep/wake transitions, last 100 of 400)"),
            "sleep/wake is capped, and says so: {text}"
        );
    }

    #[tokio::test]
    async fn panic_capture_names_the_newest_report_and_excerpts_its_head() {
        let dir = tempfile::TempDir::new().unwrap();
        let body: String = (0..PANIC_EXCERPT_LINES * 2)
            .map(|i| format!("backtrace line {i}\n"))
            .collect();
        for (name, age_secs) in [("Kernel-old.panic", 600), ("Kernel-new.panic", 0)] {
            let path = dir.path().join(name);
            std::fs::write(&path, format!("panic(cpu 4 caller 0x0): {name}\n{body}")).unwrap();
            std::fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(std::time::SystemTime::now() - Duration::from_secs(age_secs))
                .unwrap();
        }
        std::fs::write(dir.path().join("other.ips"), "not a panic").unwrap();

        let text = panic_report_text(dir.path()).await;
        assert!(text.contains("Kernel-new.panic"), "{text}");
        assert!(text.contains("Kernel-old.panic"), "both are listed: {text}");
        assert!(
            !text.contains("other.ips"),
            "only *.panic is listed: {text}"
        );
        assert!(
            text.contains("panic(cpu 4 caller 0x0): Kernel-new.panic"),
            "the newest report is the one excerpted: {text}"
        );
        assert!(
            // The panic string takes the first of the capped lines, so the
            // last backtrace line kept is two short of the cap.
            !text.contains(&format!("backtrace line {}", PANIC_EXCERPT_LINES - 1)),
            "the excerpt stops at the line cap: {text}"
        );
    }

    #[tokio::test]
    async fn a_host_with_no_panic_reports_records_that_as_data() {
        let dir = tempfile::TempDir::new().unwrap();
        let text = panic_report_text(dir.path()).await;
        assert!(
            text.contains("(no panic reports)"),
            "absence is data, not an error"
        );

        let missing = panic_report_text(Path::new("/nonexistent/diag-panics")).await;
        assert!(
            missing.contains("(no panic reports)"),
            "so is a missing directory"
        );
    }
}
