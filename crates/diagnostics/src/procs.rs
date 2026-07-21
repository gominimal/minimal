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

use std::time::Duration;

use crate::bundle::{BundleSink, BundleWriter};
use crate::capture::command_stdout;
use crate::manifest::Redaction;
use crate::redact::{is_sensitive_key, redaction_placeholder};

/// Timeout for `ps`; a wedged process table must not eat the collector budget.
const PS_TIMEOUT: Duration = Duration::from_secs(5);
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

/// Scrubs an argv line token-wise: any `key=value` token whose key trips the
/// [sensitive-key policy](is_sensitive_key) has its value replaced by the
/// redaction placeholder, so a secret passed on a command line never rides out
/// in the process table.
fn scrub_argv(line: &str) -> String {
    line.split(' ')
        .map(|tok| match tok.split_once('=') {
            Some((key, value)) if is_sensitive_key(key) => {
                let placeholder =
                    redaction_placeholder(&serde_json::Value::String(value.to_string()));
                format!("{key}={}", placeholder.as_str().unwrap_or("<redacted>"))
            }
            _ => tok.to_string(),
        })
        .collect::<Vec<_>>()
        .join(" ")
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
        if let Some(status) = proc_status(pid) {
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

    #[cfg(target_os = "macos")]
    for &pid in &pids {
        let path = format!("{dest}/proc/{pid}.sample.txt");
        let pid_s = pid.to_string();
        match command_stdout("sample", &[&pid_s, "1", "10"], Duration::from_secs(15)).await {
            Ok(text) => w.add_bytes(&path, text.as_bytes(), Redaction::None).await?,
            Err(e) => w.skip(path, format!("sample failed: {e}")),
        }
    }

    #[cfg(target_os = "linux")]
    for &pid in &pids {
        let text = linux_park_state(pid).await;
        w.add_bytes(
            &format!("{dest}/proc/{pid}.stack.txt"),
            text.as_bytes(),
            Redaction::None,
        )
        .await?;
    }

    let pid_list = pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let path = format!("{dest}/proc/lsof.txt");
    match command_stdout("lsof", &["-nP", "-p", &pid_list], Duration::from_secs(10)).await {
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
                proc_scrape(markers)
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
            text.push_str(&scrub_argv(line));
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
        let cmdline = String::from_utf8_lossy(&raw).replace('\0', " ");
        if argv0_matches(&cmdline, markers) {
            let _ = writeln!(text, "{pid} {}", scrub_argv(cmdline.trim_end()));
            pids.push(pid);
        }
    }
    Ok((text, pids))
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

    #[test]
    fn scrub_argv_masks_sensitive_key_value_tokens_only() {
        let scrubbed = scrub_argv("minvmd --flag MINIMAL_AUTH_TOKEN=s3cr3t --port 8080");
        assert!(
            !scrubbed.contains("s3cr3t"),
            "secret value masked: {scrubbed}"
        );
        assert!(
            scrubbed.contains("MINIMAL_AUTH_TOKEN=<redacted"),
            "sensitive key masked in place: {scrubbed}"
        );
        assert!(scrubbed.contains("--flag"), "flags untouched: {scrubbed}");
        assert!(
            scrubbed.contains("--port 8080"),
            "non-sensitive kept: {scrubbed}"
        );
    }
}
