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

/// Bytes of the newest report's head searched for the panic string. A report
/// carries it either as its opening line or as a field of the JSON header
/// that precedes the backtrace, so the sentence always sits inside the first
/// few KiB; the cap is what keeps a report written as one enormous line from
/// being pulled into memory whole.
const PANIC_EXCERPT_BYTES: u64 = 8 * 1024;

/// Bytes kept of the panic string itself. The `panic(cpu N caller …): …`
/// sentence names the failing subsystem in far less than this; the cap bounds
/// a report whose string runs on.
const PANIC_STRING_MAX_BYTES: usize = 512;

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
/// panic string of the newest.
///
/// A hard reboot leaves the *why* in a panic report, and "was it us?" is
/// answered by the subsystem the panic string names. The capture carries that
/// sentence and no more — see [`report_panic_string`] for why the rest of a
/// crash log does not travel.
///
/// Best-effort throughout, and every outcome is accounted for: an empty
/// directory is recorded as data ("no panic reports"), an absent or unlistable
/// one as a manifest skip naming the reason, and a platform with no panic
/// reports at all as a skip too. Nothing here reports *not having looked* as
/// an answer.
pub async fn panic_report<W: BundleSink>(
    w: &mut BundleWriter<W>,
    dest: &str,
) -> Result<(), anyhow::Error> {
    let path = format!("{dest}/panic.txt");
    let Some(dir) = panic_report_dir() else {
        w.skip(path, "kernel panic reports are a macOS facility");
        return Ok(());
    };
    match panic_report_text(Path::new(dir)).await {
        Ok(text) => w.add_bytes(&path, text.as_bytes(), Redaction::Keys).await,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            w.skip(path, format!("no {dir} — this host keeps no panic reports"));
            Ok(())
        }
        // "Nothing panicked" and "we were not allowed to look" are opposite
        // answers to the one question this collector exists to settle, so the
        // errno travels rather than collapsing into "(no panic reports)".
        // Not hypothetical: `/Library/Logs/DiagnosticReports` is
        // TCC-protected, so `min bug` from a terminal without Full Disk
        // Access is denied here on a Mac that panicked minutes ago.
        Err(e) => {
            w.skip(
                path,
                format!("{dir} unreadable ({e}) — whether this host panicked is unknown"),
            );
            Ok(())
        }
    }
}

/// The panic-report capture for `dir`, or the error that made the directory
/// unlistable — which the caller must be able to tell from an empty one.
/// Parameterized by directory so the mechanic is exercisable without the real
/// system location.
async fn panic_report_text(dir: &Path) -> std::io::Result<String> {
    let reports = crate::logs::try_newest_matching(dir, PANIC_REPORTS_LISTED, |name| {
        name.ends_with(".panic")
    })
    .await?;
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
        // Reached only when the directory *was* read: absence of reports is a
        // fact about the host, not the shrug of a failed read.
        let _ = writeln!(text, "(no panic reports)");
        return Ok(text);
    };
    let _ = writeln!(
        text,
        "\n=== {} (panic string only; report header and backtrace withheld) ===",
        newest.display()
    );
    match report_panic_string(newest).await {
        Ok(Some(panic_string)) => {
            let _ = writeln!(text, "{panic_string}");
        }
        Ok(None) => {
            let _ = writeln!(
                text,
                "(no panic string in the first {PANIC_EXCERPT_BYTES} bytes)"
            );
        }
        Err(e) => {
            let _ = writeln!(text, "(unreadable: {e:#})");
        }
    }
    Ok(text)
}

/// The panic string of the report at `path`: the one sentence naming the
/// failing subsystem, read no-follow out of the first [`PANIC_EXCERPT_BYTES`]
/// and capped at [`PANIC_STRING_MAX_BYTES`].
///
/// Deliberately *not* the head of the file. A `.panic` report is OS- and
/// third-party-authored text whose contents this project does not control,
/// and the parts around the panic string are the parts we have no business
/// shipping: the metadata header carries a device-stable identifier
/// (`crashReporterKey`, the incident id) and the hardware model, and the
/// backtrace names every kext loaded at the time — an inventory of the user's
/// security, VPN, and virtualization software. None of that answers "was it
/// us?"; the panic string does. So the string alone travels, and it travels
/// through the same fail-closed sensitive-token scrub every other flattened
/// free-text line in a bundle goes through.
async fn report_panic_string(path: &Path) -> Result<Option<String>, anyhow::Error> {
    use tokio::io::AsyncReadExt as _;

    let (file, _) = open_regular_nofollow(path).await?;
    let mut head = Vec::new();
    file.take(PANIC_EXCERPT_BYTES)
        .read_to_end(&mut head)
        .await
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(panic_string(&String::from_utf8_lossy(&head)))
}

/// The panic string carried by a report's head, in either shape the OS
/// writes it: a plain-text report opens with the `panic(cpu N caller …)`
/// sentence itself, while a modern one carries it as the `panicString` field
/// of a JSON header, where an escaped newline separates the sentence from the
/// backtrace that follows it. Everything else in the head is dropped on the
/// floor; what survives is truncated and scrubbed.
fn panic_string(head: &str) -> Option<String> {
    let raw = head.lines().find_map(|line| {
        let line = line.trim_start();
        if line.starts_with("panic(") {
            return Some(line);
        }
        let (_, rest) = line.split_once("\"panicString\"")?;
        let value = rest.trim_start().strip_prefix(':')?.trim_start();
        let value = value.strip_prefix('"').unwrap_or(value);
        // Past the first escaped newline lie the backtrace and the kext list.
        Some(
            value
                .split("\\n")
                .next()
                .unwrap_or(value)
                .trim_end_matches('"'),
        )
    })?;
    let raw = raw.trim_end();
    let kept = clamp_bytes(raw, PANIC_STRING_MAX_BYTES);
    let mut out = crate::procs::scrub_flattened(kept);
    if kept.len() < raw.len() {
        out.push_str(" (truncated)");
    }
    Some(out)
}

/// `s` cut to at most `max` bytes, on a character boundary.
fn clamp_bytes(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
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

    /// A `.panic` report shaped like a modern one: a JSON metadata header
    /// carrying the device-stable identifiers, the panic string, and then the
    /// backtrace with its kext inventory.
    fn panic_report_file(tag: &str) -> String {
        format!(
            "{{\"bug_type\":\"210\",\"os_version\":\"macOS 26.1\",\
             \"incident_id\":\"1A2B3C4D-DEAD-BEEF-0000-000000000001\",\
             \"crashReporterKey\":\"a1b2c3d4e5f60718293a4b5c6d7e8f9012345678\"}}\n\
             {{\n\
             \"build\" : \"Darwin Kernel Version 26.1.0\",\n\
             \"product\" : \"MacBookPro18,3\",\n\
             \"crashReporterKey\" : \"a1b2c3d4e5f60718293a4b5c6d7e8f9012345678\",\n\
             \"panicString\" : \"panic(cpu 4 caller 0xfffffe001): Kernel data abort {tag}\\n\
             Debugger message: panic\\nKernel Extensions in backtrace:\\n\
             com.vendorvpn.tunnel(1.2)\\ncom.othervendor.security(3.4)\",\n\
             \"panicFlags\" : \"0x0\"\n\
             }}\n"
        )
    }

    #[tokio::test]
    async fn panic_capture_names_the_newest_report_and_quotes_its_panic_string() {
        let dir = tempfile::TempDir::new().unwrap();
        for (name, age_secs) in [("Kernel-old.panic", 600), ("Kernel-new.panic", 0)] {
            let path = dir.path().join(name);
            std::fs::write(&path, panic_report_file(name)).unwrap();
            std::fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(std::time::SystemTime::now() - Duration::from_secs(age_secs))
                .unwrap();
        }
        std::fs::write(dir.path().join("other.ips"), "not a panic").unwrap();

        let text = panic_report_text(dir.path()).await.expect("readable dir");
        assert!(text.contains("Kernel-new.panic"), "{text}");
        assert!(text.contains("Kernel-old.panic"), "both are listed: {text}");
        assert!(
            !text.contains("other.ips"),
            "only *.panic is listed: {text}"
        );
        assert!(
            text.contains("panic(cpu 4 caller 0xfffffe001): Kernel data abort Kernel-new.panic"),
            "the newest report's panic string is what the capture is for: {text}"
        );
    }

    /// The panic string is the *only* part of a third-party crash report the
    /// bundle is entitled to. The report's metadata header identifies the
    /// device (`crashReporterKey`, incident id) and its model, and the
    /// backtrace is an inventory of the user's installed kexts — neither
    /// answers "was it us?", so neither may ride along.
    #[tokio::test]
    async fn panic_capture_withholds_the_report_header_and_backtrace() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("Kernel-new.panic"),
            panic_report_file("Kernel-new.panic"),
        )
        .unwrap();

        let text = panic_report_text(dir.path()).await.expect("readable dir");
        for leaked in [
            "crashReporterKey",
            "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
            "1A2B3C4D-DEAD-BEEF-0000-000000000001",
            "MacBookPro18,3",
            "com.vendorvpn.tunnel",
            "com.othervendor.security",
            "Kernel Extensions in backtrace",
        ] {
            assert!(
                !text.contains(leaked),
                "{leaked:?} is not ours to ship: {text}"
            );
        }
    }

    #[test]
    fn panic_string_is_capped_and_scrubbed() {
        let long = format!("panic(cpu 0 caller 0x1): {}", "x".repeat(4096));
        let capped = panic_string(&long).expect("a panic string is found");
        assert!(
            capped.len() <= PANIC_STRING_MAX_BYTES + " (truncated)".len(),
            "capped at {PANIC_STRING_MAX_BYTES} bytes: {} bytes",
            capped.len()
        );
        assert!(capped.ends_with(" (truncated)"), "{capped}");

        let secret = panic_string("panic(cpu 0 caller 0x1): api_key=hunter2 boom")
            .expect("a panic string is found");
        assert!(
            !secret.contains("hunter2"),
            "sensitive tokens are scrubbed fail-closed: {secret}"
        );

        // A plain-text (pre-JSON) report opens with the sentence itself.
        assert_eq!(
            panic_string("panic(cpu 1 caller 0x2): Kernel trap\nbacktrace 0x0\n").as_deref(),
            Some("panic(cpu 1 caller 0x2): Kernel trap"),
            "the backtrace stays behind"
        );
    }

    #[tokio::test]
    async fn a_host_with_no_panic_reports_records_that_as_data() {
        let dir = tempfile::TempDir::new().unwrap();
        let text = panic_report_text(dir.path()).await.expect("readable dir");
        assert!(
            text.contains("(no panic reports)"),
            "absence is data, not an error"
        );
    }

    /// #1222 turns on this distinction: on a TCC-restricted Mac the panic
    /// directory is unreadable, and answering "(no panic reports)" there would
    /// tell a triager the machine did not panic when nobody looked. The
    /// unlistable directory must come back as an error so the collector can
    /// record a skip instead.
    #[tokio::test]
    async fn an_unreadable_panic_directory_is_never_reported_as_no_panics() {
        let missing = panic_report_text(Path::new("/nonexistent/diag-panics"))
            .await
            .expect_err("a missing directory is not an answer");
        assert_eq!(missing.kind(), std::io::ErrorKind::NotFound);

        // A non-directory stands in for the permission-denied case: the read
        // fails with something other than `NotFound`, which is the shape a
        // TCC-protected directory has.
        let tmp = tempfile::TempDir::new().unwrap();
        let not_a_dir = tmp.path().join("DiagnosticReports");
        std::fs::write(&not_a_dir, "").unwrap();
        let err = panic_report_text(&not_a_dir)
            .await
            .expect_err("an unlistable directory is not an answer");
        assert_ne!(
            err.kind(),
            std::io::ErrorKind::NotFound,
            "unreadable stays distinguishable from absent: {err}"
        );
    }
}
