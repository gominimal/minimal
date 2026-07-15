//! Process-state capture for the diagnostic bundle.
//!
//! One `ps` invocation (portable keyword form works on Linux and macOS),
//! filtered to minimal-related processes — a full process table would leak
//! unrelated user activity. On Linux each matched pid is enriched from
//! `/proc`; if `ps` is unavailable a `/proc` scrape stands in.

use anyhow::Context as _;

use super::bundle::BundleWriter;
use super::manifest::Redaction;

/// Substrings of a command line that mark a process as ours.
const PROCESS_MARKERS: &[&str] = &["minimald", "minvmd", "__krun-vmm", "gvproxy"];

/// Returns true when a `ps` args column names a minimal-related process.
/// `min`/`minimal` need word-ish matching so e.g. `vim minutes.txt` or
/// `terminal` don't match.
fn is_relevant(args: &str) -> bool {
    if PROCESS_MARKERS.iter().any(|m| args.contains(m)) {
        return true;
    }
    args.split_whitespace().next().is_some_and(|argv0| {
        let bin = argv0.rsplit('/').next().unwrap_or(argv0);
        bin == "min" || bin == "minimal"
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

/// Filtered `ps` output plus the matched pids. The header line and a total
/// process count are kept so "nothing matched" is distinguishable from
/// "ps saw nothing".
async fn ps_capture() -> Result<(String, Vec<u32>), anyhow::Error> {
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::process::Command::new("ps")
            .args(["axww", "-o", "pid=,ppid=,user=,pcpu=,rss=,etime=,args="])
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
    }
}
