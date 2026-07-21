//! Process-state capture for diagnostic bundles: a filtered process table and
//! per-process hang triage — where each of our processes is parked and what it
//! holds open — for the process family named by a caller-supplied marker list.
//!
//! The marker *data* is the caller's policy ([`crate::procs`] never names a
//! process); matching, the argv scrub, and the reads are the mechanics here.
//! The Linux path is pure `/proc` — wait-channel, syscall, kernel stack, and
//! fd readlinks — so it runs as microVM pid-1 with no external binaries.
//! External tools are host-side extras used when present: `ps` for the table
//! (a `/proc` scrape stands in), macOS `sample`, and one `lsof` over the set.

// `Cow` and the placeholder are only reachable from the Linux `/proc` scrape,
// which is the one path with true argv boundaries to redact per element.
#[cfg(target_os = "linux")]
use std::borrow::Cow;
use std::time::Duration;

use crate::bundle::{BundleSink, BundleWriter};
use crate::capture::command_stdout;
use crate::manifest::Redaction;
use crate::redact::is_sensitive_key;
#[cfg(target_os = "linux")]
use crate::redact::redaction_placeholder;

/// Timeout for `ps`; a wedged process table must not eat the collector budget.
const PS_TIMEOUT: Duration = Duration::from_secs(5);
/// Per-pid `sample` deadline on macOS. Samples run concurrently, so the macOS
/// pass is bounded by this rather than by its sum across pids.
#[cfg(target_os = "macos")]
const SAMPLE_TIMEOUT: Duration = Duration::from_secs(10);
/// Deadline for the single `lsof` over the whole matched set.
const LSOF_TIMEOUT: Duration = Duration::from_secs(8);
/// Cap on how many matched processes get the deep hang-triage treatment — a
/// runaway match list must not turn a bundle into a profiling session.
const HANG_TRIAGE_PIDS_MAX: usize = 8;

/// True when `args` (a full command line) names one of `markers` as its
/// executable — the argv0 basename only, never a substring of the whole line,
/// so `vim minimald.log` or `tail -f minvmd.log` are not dragged in.
fn argv0_matches(args: &str, markers: &[&str]) -> bool {
    args.split_whitespace().next().is_some_and(|argv0| {
        let bin = argv0.rsplit('/').next().unwrap_or(argv0);
        markers.contains(&bin)
    })
}

/// Scrubs one *true* argv element: a `key=value` whose key trips the
/// [sensitive-key policy](is_sensitive_key) has its entire value replaced by
/// the redaction placeholder — spaces included, because the element boundary
/// is known here.
///
/// Only the `/proc` scrape has real argv boundaries to work with, so this is
/// Linux-only; everywhere else [`scrub_flattened`] takes over.
#[cfg(target_os = "linux")]
fn scrub_arg(arg: &str) -> Cow<'_, str> {
    match arg.split_once('=') {
        Some((key, value)) if is_sensitive_key(key) => {
            let placeholder = redaction_placeholder(&serde_json::Value::String(value.to_string()));
            Cow::Owned(format!(
                "{key}={}",
                placeholder.as_str().unwrap_or("<redacted>")
            ))
        }
        _ => Cow::Borrowed(arg),
    }
}

/// Scrubs a command line whose argv boundaries are already lost. `ps` joins
/// arguments with spaces, so `--password=hunter two` is indistinguishable from
/// a secret followed by a separate argument; masking only up to the first space
/// would emit the tail of the value verbatim.
///
/// So this is **fail-closed**: once a sensitive `key=` appears, the remainder
/// of the line goes with it. A truncated process line is a far smaller loss
/// than a half-masked secret in a bundle that gets mailed out. Where the real
/// boundaries survive — the `/proc` scrape, whose argv is NUL-separated —
/// [`scrub_arg`] is used per element instead and nothing is over-redacted.
fn scrub_flattened(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    for (i, tok) in line.split(' ').enumerate() {
        if i > 0 {
            out.push(' ');
        }
        if let Some((key, _)) = tok.split_once('=')
            && is_sensitive_key(key)
        {
            out.push_str(key);
            out.push_str("=<redacted> <argv tail withheld: token boundaries unrecoverable>");
            return out;
        }
        out.push_str(tok);
    }
    out
}

/// `<dest>/process-tree.txt`, plus on Linux `<dest>/proc/<pid>.status` for each
/// matched pid (VmRSS, threads, and fd pressure for one of our processes).
pub async fn process_tree<W: BundleSink>(
    w: &mut BundleWriter<W>,
    dest: &str,
    markers: &[&str],
) -> Result<(), anyhow::Error> {
    let (text, pids) = process_table(markers).await?;
    w.add_bytes(
        &format!("{dest}/process-tree.txt"),
        text.as_bytes(),
        Redaction::Keys,
    )
    .await?;

    #[cfg(target_os = "linux")]
    for pid in pids {
        // Synchronous `/proc` reads go to a blocking thread for the same reason
        // as the scrape in `process_table`. A join error means the reader task
        // panicked; treat it as "no status", the same as an unreadable `/proc`.
        let status = tokio::task::spawn_blocking(move || proc_status(pid))
            .await
            .ok()
            .flatten();
        if let Some(status) = status {
            w.add_bytes(
                &format!("{dest}/proc/{pid}.status"),
                status.as_bytes(),
                Redaction::None,
            )
            .await?;
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = pids;
    Ok(())
}

/// Hang triage for the matched family (capped at [`HANG_TRIAGE_PIDS_MAX`]):
/// thread samples on macOS, wait-channel + kernel stack + open fds on Linux,
/// and one `lsof` over the set. This is the evidence "it's frozen" reports run
/// on (#788: vCPUs in WFI, proxy in kevent, a unix socket open with no EOF), so
/// it is captured while the hang is live.
pub async fn hang_triage<W: BundleSink>(
    w: &mut BundleWriter<W>,
    dest: &str,
    markers: &[&str],
) -> Result<(), anyhow::Error> {
    let (_, pids) = process_table(markers).await?;
    let pids: Vec<u32> = pids.into_iter().take(HANG_TRIAGE_PIDS_MAX).collect();
    if pids.is_empty() {
        w.skip(
            format!("{dest}/proc/"),
            "no marker-matched processes to hang-triage",
        );
        return Ok(());
    }

    // macOS: sample every pid concurrently. Sequential per-pid deadlines would
    // sum past the caller's collector budget — and a wedged process, the case
    // this capture exists for, is exactly when each sample runs long — so the
    // pass is bounded by one deadline instead of their sum. Worst case for the
    // whole collector: ps (5s) + samples (10s) + lsof (8s) ≈ 23s.
    #[cfg(target_os = "macos")]
    {
        let mut set = tokio::task::JoinSet::new();
        for &pid in &pids {
            set.spawn(async move {
                let pid_s = pid.to_string();
                let out = command_stdout("sample", &[&pid_s, "1", "10"], SAMPLE_TIMEOUT).await;
                (pid, out)
            });
        }
        let mut samples = Vec::with_capacity(pids.len());
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(sample) => samples.push(sample),
                // A panicked sample task is a bug, not a diagnostic outcome —
                // record it rather than dropping the pid silently.
                Err(e) => w.skip(format!("{dest}/proc/"), format!("sample task failed: {e}")),
            }
        }
        // Completion order is nondeterministic; keep bundle order by pid.
        samples.sort_by_key(|(pid, _)| *pid);
        for (pid, result) in samples {
            let path = format!("{dest}/proc/{pid}.sample.txt");
            match result {
                Ok(text) => w.add_bytes(&path, text.as_bytes(), Redaction::None).await?,
                Err(e) => w.skip(path, format!("sample failed: {e}")),
            }
        }
    }

    // The pid set actually captured. On Linux each pid is re-checked against
    // its own cmdline immediately before its state is read: the table snapshot
    // is stale the moment it is taken, and a pid recycled in between would put
    // an unrelated process's kernel state and open files into the bundle —
    // precisely the "someone else's activity" this collector filters out.
    #[cfg(target_os = "linux")]
    let mut captured: Vec<u32> = Vec::with_capacity(pids.len());
    #[cfg(target_os = "linux")]
    for &pid in &pids {
        if !still_matches(pid, markers).await {
            w.skip(
                format!("{dest}/proc/{pid}.stack.txt"),
                "pid no longer matches a marker (exited or recycled since the snapshot)",
            );
            continue;
        }
        let text = linux_park_state(pid).await;
        w.add_bytes(
            &format!("{dest}/proc/{pid}.stack.txt"),
            text.as_bytes(),
            Redaction::None,
        )
        .await?;
        captured.push(pid);
    }
    #[cfg(not(target_os = "linux"))]
    let captured = pids;

    if captured.is_empty() {
        w.skip(
            format!("{dest}/proc/lsof.txt"),
            "no marker-matched pids still live to inspect",
        );
        return Ok(());
    }
    let pid_list = captured
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let path = format!("{dest}/proc/lsof.txt");
    match command_stdout("lsof", &["-nP", "-p", &pid_list], LSOF_TIMEOUT).await {
        Ok(text) => w.add_bytes(&path, text.as_bytes(), Redaction::None).await?,
        Err(e) => w.skip(path, format!("lsof unavailable: {e}")),
    }
    Ok(())
}

/// Filtered `ps` output plus the matched pids; on Linux a `/proc` scrape stands
/// in when `ps` is unavailable. The header and a total count are kept so
/// "nothing matched" is distinguishable from "ps saw nothing".
async fn process_table(markers: &[&str]) -> Result<(String, Vec<u32>), anyhow::Error> {
    match ps_table(markers).await {
        Ok(v) => Ok(v),
        Err(_ps_err) => {
            #[cfg(target_os = "linux")]
            {
                use anyhow::Context as _;
                // The scrape walks all of `/proc` synchronously, so it runs on a
                // blocking thread: a wedged `/proc` must strand that thread, not
                // the worker whose collector timeout is the failsafe. `ps` being
                // absent (microVM pid-1, a starved host) is exactly when that
                // read is most likely to hang.
                let markers: Vec<String> = markers.iter().map(|m| (*m).to_string()).collect();
                tokio::task::spawn_blocking(move || {
                    let markers: Vec<&str> = markers.iter().map(String::as_str).collect();
                    proc_scrape(&markers)
                })
                .await
                .context("proc scrape worker")?
                .with_context(|| format!("ps failed ({_ps_err}), /proc fallback also failed"))
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err(_ps_err)
            }
        }
    }
}

/// The portable `ps` keyword form (works on Linux and macOS), filtered to the
/// marker-matched family and scrubbed token-wise.
async fn ps_table(markers: &[&str]) -> Result<(String, Vec<u32>), anyhow::Error> {
    let out = command_stdout(
        "ps",
        &["axww", "-o", "pid=,ppid=,user=,pcpu=,rss=,etime=,args="],
        PS_TIMEOUT,
    )
    .await?;
    let total = out.lines().count();
    let mut text = format!("pid ppid user pcpu rss etime args   (filtered; {total} total)\n");
    let mut pids = Vec::new();
    for line in out.lines() {
        let mut fields = line.split_whitespace();
        let Some(pid) = fields.next().and_then(|p| p.parse::<u32>().ok()) else {
            continue;
        };
        let args = fields.skip(5).collect::<Vec<_>>().join(" ");
        if argv0_matches(&args, markers) {
            // `ps` already flattened argv to a space-joined string, so this
            // line must be scrubbed fail-closed.
            text.push_str(&scrub_flattened(line));
            text.push('\n');
            pids.push(pid);
        }
    }
    Ok((text, pids))
}

/// Linux fallback: walk `/proc/<pid>/cmdline` directly when `ps` is absent.
#[cfg(target_os = "linux")]
fn proc_scrape(markers: &[&str]) -> Result<(String, Vec<u32>), anyhow::Error> {
    use anyhow::Context as _;
    use std::fmt::Write as _;
    let mut text = String::from("pid cmdline   (from /proc scrape)\n");
    let mut pids = Vec::new();
    for entry in std::fs::read_dir("/proc")
        .context("reading /proc")?
        .flatten()
    {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        // `/proc/<pid>/cmdline` is NUL-separated, so the true argv boundaries
        // are still intact here. Scrub each element on its own — a secret
        // containing spaces is masked whole, and nothing after it is lost.
        let argv: Vec<String> = raw
            .split(|b| *b == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect();
        let Some(argv0) = argv.first() else {
            continue;
        };
        if argv0_matches(argv0, markers) {
            let scrubbed: Vec<Cow<'_, str>> = argv.iter().map(|a| scrub_arg(a)).collect();
            let _ = writeln!(text, "{pid} {}", scrubbed.join(" "));
            pids.push(pid);
        }
    }
    Ok((text, pids))
}

/// True when `pid` still names a marker-matched process *right now*.
///
/// Hang triage reads kernel state and open-file paths, so identity has to be
/// re-pinned immediately before the read rather than trusted from the table
/// snapshot: if a matched process exits and its pid is recycled in between, the
/// bundle would carry an unrelated process's fds and stack. An unreadable
/// `cmdline` (the process is gone) is a non-match, so the capture is skipped.
/// Async `/proc` read — no blocking on the collector's worker.
#[cfg(target_os = "linux")]
async fn still_matches(pid: u32, markers: &[&str]) -> bool {
    let Ok(raw) = tokio::fs::read(format!("/proc/{pid}/cmdline")).await else {
        return false;
    };
    raw.split(|b| *b == 0)
        .find(|part| !part.is_empty())
        .is_some_and(|argv0| argv0_matches(&String::from_utf8_lossy(argv0), markers))
}

/// Where a Linux process is parked: wait channel, current syscall, kernel
/// stack (root-only; the error is data), and its open fds by readlink.
#[cfg(target_os = "linux")]
async fn linux_park_state(pid: u32) -> String {
    use std::fmt::Write as _;
    let mut text = String::new();
    for label in ["wchan", "syscall", "stack"] {
        let value = tokio::fs::read_to_string(format!("/proc/{pid}/{label}"))
            .await
            .unwrap_or_else(|e| format!("<unreadable: {e}>"));
        let _ = writeln!(text, "=== {label} ===\n{}", value.trim_end());
    }
    text.push_str("=== fds ===\n");
    match tokio::fs::read_dir(format!("/proc/{pid}/fd")).await {
        Ok(mut entries) => {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let target = tokio::fs::read_link(entry.path())
                    .await
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|e| format!("<unreadable: {e}>"));
                let _ = writeln!(text, "{} -> {target}", entry.file_name().to_string_lossy());
            }
        }
        Err(e) => {
            let _ = writeln!(text, "<unreadable: {e}>");
        }
    }
    text
}

/// `/proc/<pid>/status` plus an fd count — VmRSS, threads, and fd pressure.
#[cfg(target_os = "linux")]
fn proc_status(pid: u32) -> Option<String> {
    let mut status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    if let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) {
        use std::fmt::Write as _;
        let _ = writeln!(status, "OpenFds:\t{}", fds.count());
    }
    Some(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARKERS: &[&str] = &["min", "minimald", "minvmd", "__krun-vmm", "gvproxy"];

    #[test]
    fn argv0_matches_executable_basename_not_substring() {
        assert!(argv0_matches("/usr/bin/minimald run --detach", MARKERS));
        assert!(argv0_matches("minvmd __krun-vmm --token x", MARKERS));
        assert!(argv0_matches("/home/u/.local/bin/min activate .", MARKERS));
        assert!(argv0_matches("gvproxy -mtu 1500", MARKERS));

        assert!(!argv0_matches("vim minutes.txt", MARKERS));
        assert!(!argv0_matches("/usr/bin/administrator --min 5", MARKERS));
        // Marker names appearing as arguments (a user triaging our logs) must
        // not drag their editor/pager into the bundle.
        assert!(!argv0_matches("vim minimald.log", MARKERS));
        assert!(!argv0_matches(
            "tail -f /var/log/minvmd.log.2026-07-15",
            MARKERS
        ));
        assert!(!argv0_matches("grep minimald /home/u/notes", MARKERS));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn scrub_arg_masks_the_whole_value_including_spaces() {
        // True argv boundaries: the entire value is masked, spaces and all.
        assert_eq!(
            scrub_arg("--password=hunter two"),
            "--password=<redacted:len=10>",
            "a value with spaces must not be half-masked"
        );
        assert_eq!(
            scrub_arg("--port=8080"),
            "--port=8080",
            "non-sensitive kept"
        );
        assert_eq!(scrub_arg("--flag"), "--flag", "non key=value untouched");
    }

    #[test]
    fn scrub_flattened_is_fail_closed_once_a_secret_appears() {
        // `ps` already lost the boundaries, so everything after the secret is
        // withheld rather than risking the tail of the value.
        let scrubbed = scrub_flattened("minvmd --flag MINIMAL_AUTH_TOKEN=hunter two --port 8080");
        assert!(!scrubbed.contains("hunter"), "secret masked: {scrubbed}");
        assert!(
            !scrubbed.contains("two"),
            "the tail of a spaced secret must not survive: {scrubbed}"
        );
        assert!(!scrubbed.contains("8080"), "fail-closed tail: {scrubbed}");
        assert!(scrubbed.starts_with("minvmd --flag"), "{scrubbed}");
        assert!(
            scrubbed.contains("MINIMAL_AUTH_TOKEN=<redacted"),
            "{scrubbed}"
        );
    }

    #[test]
    fn scrub_flattened_leaves_a_clean_line_alone() {
        let line = "minimald run --detach --instance-num 0";
        assert_eq!(scrub_flattened(line), line);
    }
}
