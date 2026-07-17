//! Process-state capture for the diagnostic bundle.
//!
//! One `ps` invocation (portable keyword form works on Linux and macOS),
//! filtered to minimal-related processes — a full process table would leak
//! unrelated user activity. On Linux each matched pid is enriched from
//! `/proc`; if `ps` is unavailable a `/proc` scrape stands in.

use anyhow::Context as _;

use diagnostics::bundle::BundleWriter;
use diagnostics::manifest::Redaction;

/// Process names (argv0 basenames) that mark a process as ours.
const PROCESS_MARKERS: &[&str] = &[
    "min",
    "minimal",
    "minimald",
    "minvmd",
    "__krun-vmm",
    "gvproxy",
];

/// Returns true when a `ps` args column names a minimal-related process.
/// Only the executable name (argv0 basename) is matched — substring matching
/// on the whole command line would capture unrelated user activity like
/// `vim minimald.log` or `tail -f minvmd.log.2026-07-15`.
fn is_relevant(args: &str) -> bool {
    args.split_whitespace().next().is_some_and(|argv0| {
        let bin = argv0.rsplit('/').next().unwrap_or(argv0);
        PROCESS_MARKERS.contains(&bin)
    })
}

pub async fn process_tree(w: &mut BundleWriter) -> Result<(), anyhow::Error> {
    let (text, pids) = match ps_capture().await {
        Ok(v) => v,
        #[cfg(target_os = "linux")]
        Err(ps_err) => {
            let (text, pids) = proc_scrape()
                .with_context(|| format!("ps failed ({ps_err}), /proc fallback also failed"))?;
            (text, pids)
        }
        #[cfg(not(target_os = "linux"))]
        Err(e) => return Err(e),
    };
    w.add_bytes("host/process-tree.txt", text.as_bytes(), Redaction::None)
        .await?;

    #[cfg(target_os = "linux")]
    for pid in pids {
        if let Some(status) = proc_status(pid) {
            w.add_bytes(
                &format!("host/proc/{pid}.status"),
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

/// Cap on how many matched processes get the deep hang-triage treatment; a
/// runaway match list must not turn `min bug` into a profiler session.
const HANG_TRIAGE_PIDS_MAX: usize = 8;

/// Hang-triage capture for the matched process family: where each process is
/// parked (thread samples on macOS, wait channel + kernel stack on Linux) and
/// what it holds open (`lsof`). "It's frozen" reports run almost entirely on
/// exactly this evidence (#788: vCPUs in WFI, proxy in kevent, a unix socket
/// open with no EOF), so capture it while the hang is live.
pub async fn hang_triage(w: &mut BundleWriter) -> Result<(), anyhow::Error> {
    let (_, pids) = match ps_capture().await {
        Ok(v) => v,
        #[cfg(target_os = "linux")]
        Err(_) => proc_scrape()?,
        #[cfg(not(target_os = "linux"))]
        Err(e) => return Err(e),
    };
    let pids: Vec<u32> = pids.into_iter().take(HANG_TRIAGE_PIDS_MAX).collect();
    if pids.is_empty() {
        w.skip("host/proc/", "no minimal-related processes to hang-triage");
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    for &pid in &pids {
        let dest = format!("host/proc/{pid}.sample.txt");
        let args = [pid.to_string(), "1".into(), "10".into()];
        match command_capture("sample", &args, std::time::Duration::from_secs(15)).await {
            Ok(text) => w.add_bytes(&dest, text.as_bytes(), Redaction::None).await?,
            Err(e) => w.skip(&dest, format!("sample failed: {e:#}")),
        }
    }

    #[cfg(target_os = "linux")]
    for &pid in &pids {
        let text = linux_park_state(pid).await;
        w.add_bytes(
            &format!("host/proc/{pid}.stack.txt"),
            text.as_bytes(),
            Redaction::None,
        )
        .await?;
    }

    let pid_list = pids
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let dest = "host/proc/lsof.txt";
    let args = ["-nP".to_string(), "-p".to_string(), pid_list];
    match command_capture("lsof", &args, std::time::Duration::from_secs(10)).await {
        Ok(text) => w.add_bytes(dest, text.as_bytes(), Redaction::None).await?,
        Err(e) => w.skip(dest, format!("lsof unavailable: {e:#}")),
    }
    Ok(())
}

/// Runs `cmd` with a deadline, returning stdout. Non-zero exit with output
/// still counts (lsof exits 1 whenever any pid's listing is incomplete).
pub(super) async fn command_capture(
    cmd: &str,
    args: &[String],
    timeout: std::time::Duration,
) -> Result<String, anyhow::Error> {
    let out = tokio::time::timeout(
        timeout,
        tokio::process::Command::new(cmd)
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .with_context(|| format!("{cmd} timed out"))?
    .with_context(|| format!("spawning {cmd}"))?;
    if !out.status.success() && out.stdout.is_empty() {
        anyhow::bail!(
            "{cmd} exited with {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
                .lines()
                .next()
                .unwrap_or("")
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
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

/// Filtered `ps` output plus the matched pids. The header line and a total
/// process count are kept so "nothing matched" is distinguishable from
/// "ps saw nothing".
async fn ps_capture() -> Result<(String, Vec<u32>), anyhow::Error> {
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::process::Command::new("ps")
            .args(["axww", "-o", "pid=,ppid=,user=,pcpu=,rss=,etime=,args="])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("ps timed out")?
    .context("spawning ps")?;
    if !out.status.success() {
        anyhow::bail!("ps exited with {}", out.status);
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let total = stdout.lines().count();
    let mut text = format!("pid ppid user pcpu rss etime args   (filtered; {total} total)\n");
    let mut pids = Vec::new();
    for line in stdout.lines() {
        let mut fields = line.split_whitespace();
        let Some(pid) = fields.next().and_then(|p| p.parse::<u32>().ok()) else {
            continue;
        };
        let args = fields.skip(5).collect::<Vec<_>>().join(" ");
        if is_relevant(&args) {
            text.push_str(line);
            text.push('\n');
            pids.push(pid);
        }
    }
    Ok((text, pids))
}

/// Linux fallback: walk `/proc/<pid>/cmdline` directly.
#[cfg(target_os = "linux")]
fn proc_scrape() -> Result<(String, Vec<u32>), anyhow::Error> {
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
        if is_relevant(&cmdline) {
            use std::fmt::Write as _;
            let _ = writeln!(text, "{pid} {cmdline}");
            pids.push(pid);
        }
    }
    Ok((text, pids))
}

/// `/proc/<pid>/status` plus an fd count — VmRSS, threads, and fd pressure
/// for one of our processes.
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

    #[test]
    fn relevance_matches_our_processes_only() {
        assert!(is_relevant("/usr/bin/minimald run --detach"));
        assert!(is_relevant("minvmd __krun-vmm --token x"));
        assert!(is_relevant("/home/u/.local/bin/min activate ."));
        assert!(is_relevant("gvproxy -mtu 1500"));

        assert!(!is_relevant("vim minutes.txt"));
        assert!(!is_relevant("gnome-terminal"));
        assert!(!is_relevant("/usr/bin/administrator --min 5"));

        // Marker names appearing as arguments (a user triaging our logs)
        // must not drag their editor/pager into the bundle.
        assert!(!is_relevant("vim minimald.log"));
        assert!(!is_relevant("tail -f /var/log/minvmd.log.2026-07-15"));
        assert!(!is_relevant("less gvproxy-notes.md"));
        assert!(!is_relevant("grep minimald /home/u/tickets/notes"));
    }
}
