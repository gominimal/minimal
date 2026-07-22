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

use crate::bundle::{BundleSink, BundleWriter, scoped};
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
///
/// Public because a process argv is not the only space-joined command line a
/// bundle carries: the kernel boot line (`/proc/cmdline`) is one too, with the
/// same ambiguity, and it must travel under the same rule.
pub fn scrub_flattened(line: &str) -> String {
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
        &scoped(dest, "process-tree.txt"),
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
                &scoped(dest, &format!("proc/{pid}.status")),
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

/// `<dest>/proc.txt`: the whole process table — pid, ppid, RSS, command — with
/// full (scrubbed) argv for marker-matched processes and `comm` alone for
/// everyone else.
///
/// [`process_tree`] answers "where is our family"; this answers "what else is
/// running", which is the question when the wedge is a task child or a
/// neighbour eating the machine. Unrelated processes contribute their name and
/// never their arguments — a support bundle is not a keylogger. Rows are
/// ordered by pid, so two bundles from one incident diff cleanly.
pub async fn all_processes<W: BundleSink>(
    w: &mut BundleWriter<W>,
    dest: &str,
    markers: &[&str],
) -> Result<(), anyhow::Error> {
    let path = scoped(dest, "proc.txt");
    #[cfg(not(target_os = "linux"))]
    {
        let _ = markers;
        w.skip(path, "a full process table needs /proc");
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        use anyhow::Context as _;
        // Hundreds of synchronous /proc reads on a busy host — off the caller's
        // runtime, for the same reason as the scrape in `process_table`.
        let owned: Vec<String> = markers.iter().map(|m| (*m).to_string()).collect();
        let text = tokio::task::spawn_blocking(move || {
            let markers: Vec<&str> = owned.iter().map(String::as_str).collect();
            proc_table_text(&markers)
        })
        .await
        .context("proc table worker")??;
        w.add_bytes(&path, text.as_bytes(), Redaction::Keys).await
    }
}

/// The `/proc` walk behind [`all_processes`].
#[cfg(target_os = "linux")]
fn proc_table_text(markers: &[&str]) -> Result<String, anyhow::Error> {
    use anyhow::Context as _;
    use std::fmt::Write as _;

    let mut rows: Vec<(u32, String)> = std::fs::read_dir("/proc")
        .context("reading /proc")?
        .flatten()
        .filter_map(|entry| {
            let pid = entry.file_name().to_str()?.parse::<u32>().ok()?;
            // NUL-separated, so the true argv boundaries are intact and each
            // element can be scrubbed on its own.
            let argv: Vec<String> = std::fs::read(format!("/proc/{pid}/cmdline"))
                .unwrap_or_default()
                .split(|b| *b == 0)
                .filter(|part| !part.is_empty())
                .map(|part| String::from_utf8_lossy(part).into_owned())
                .collect();
            let ours = argv
                .first()
                .is_some_and(|argv0| argv0_matches(argv0, markers));
            let cmd = if ours {
                argv.iter()
                    .map(|arg| scrub_arg(arg))
                    .collect::<Vec<_>>()
                    .join(" ")
            } else {
                // `comm` is the process name only, never its arguments.
                std::fs::read_to_string(format!("/proc/{pid}/comm"))
                    .map(|comm| comm.trim_end().to_string())
                    .unwrap_or_default()
            };
            let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
            let field = |key: &str| {
                status
                    .lines()
                    .find(|line| line.starts_with(key))
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("-")
                    .to_string()
            };
            Some((
                pid,
                format!("{pid}\t{}\t{}\t{cmd}", field("PPid:"), field("VmRSS:")),
            ))
        })
        .collect();
    rows.sort_unstable_by_key(|(pid, _)| *pid);

    let mut text = String::from("pid\tppid\tvmrss_kb\tcmd\n");
    for (_, row) in rows {
        let _ = writeln!(text, "{row}");
    }
    Ok(text)
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
    hang_triage_including(w, dest, markers, &[]).await
}

/// [`hang_triage`] over the marker-matched family *plus* `always` — pids the
/// caller knows first-hand are its own.
///
/// A daemon triaging itself has no marker to match on: its argv0 is whatever
/// it was exec'd as (an installed `minimald`, a renamed binary, a test
/// harness), and unlike a scraped pid its identity is not in question — it is
/// the process running this code. So `always` pids are captured first, ahead
/// of the cap, and skip the re-pin check the table snapshot needs.
pub async fn hang_triage_including<W: BundleSink>(
    w: &mut BundleWriter<W>,
    dest: &str,
    markers: &[&str],
    always: &[u32],
) -> Result<(), anyhow::Error> {
    let pids = triage_pids(markers, always).await?;
    if pids.is_empty() {
        w.skip(
            scoped(dest, "proc/"),
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
        for &(pid, _) in &pids {
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
                Err(e) => w.skip(scoped(dest, "proc/"), format!("sample task failed: {e}")),
            }
        }
        // Completion order is nondeterministic; keep bundle order by pid.
        samples.sort_by_key(|(pid, _)| *pid);
        for (pid, result) in samples {
            let path = scoped(dest, &format!("proc/{pid}.sample.txt"));
            match result {
                Ok(text) => w.add_bytes(&path, text.as_bytes(), Redaction::None).await?,
                Err(e) => w.skip(path, format!("sample failed: {e}")),
            }
        }
    }

    // The pid set actually captured. On Linux a pid taken from the table is
    // re-checked against its own cmdline immediately before its state is read:
    // the snapshot is stale the moment it is taken, and a pid recycled in
    // between would put an unrelated process's kernel state and open files into
    // the bundle — precisely the "someone else's activity" this collector
    // filters out.
    #[cfg(target_os = "linux")]
    let mut captured: Vec<u32> = Vec::with_capacity(pids.len());
    #[cfg(target_os = "linux")]
    for &(pid, from_snapshot) in &pids {
        if from_snapshot && !still_matches(pid, markers).await {
            w.skip(
                scoped(dest, &format!("proc/{pid}.stack.txt")),
                "pid no longer matches a marker (exited or recycled since the snapshot)",
            );
            continue;
        }
        let text = linux_park_state(pid).await;
        w.add_bytes(
            &scoped(dest, &format!("proc/{pid}.stack.txt")),
            text.as_bytes(),
            Redaction::None,
        )
        .await?;
        captured.push(pid);
    }
    #[cfg(not(target_os = "linux"))]
    let captured: Vec<u32> = pids.iter().map(|&(pid, _)| pid).collect();

    if captured.is_empty() {
        w.skip(
            scoped(dest, "proc/lsof.txt"),
            "no marker-matched pids still live to inspect",
        );
        return Ok(());
    }
    let pid_list = captured
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let path = scoped(dest, "proc/lsof.txt");
    match command_stdout("lsof", &["-nP", "-p", &pid_list], LSOF_TIMEOUT).await {
        Ok(text) => w.add_bytes(&path, text.as_bytes(), Redaction::None).await?,
        Err(e) => w.skip(path, format!("lsof unavailable: {e}")),
    }
    Ok(())
}

/// The pid set a per-process capture covers: `always` first, then the
/// marker-matched table, capped at [`HANG_TRIAGE_PIDS_MAX`]. The flag on each
/// pid is "this identity came from a stale table snapshot", i.e. whether it
/// must be re-pinned before its kernel state is read.
async fn triage_pids(markers: &[&str], always: &[u32]) -> Result<Vec<(u32, bool)>, anyhow::Error> {
    let (_, matched) = process_table(markers).await?;
    let mut pids: Vec<(u32, bool)> = always.iter().map(|&pid| (pid, false)).collect();
    pids.extend(
        matched
            .into_iter()
            .filter(|pid| !always.contains(pid))
            .map(|pid| (pid, true)),
    );
    pids.truncate(HANG_TRIAGE_PIDS_MAX);
    Ok(pids)
}

/// `<dest>/proc/sockets.txt`: which of our processes holds which socket, in
/// which state — every `socket:[inode]` fd of the family joined against the
/// `/proc/net` tables.
///
/// This is the binary-free `lsof` equivalent, and on a microVM it is the only
/// one: the guest rootfs ships no `lsof`, yet "who still holds the transport
/// socket, and is anyone reading it" is the question a partial wedge turns on.
/// The joined row is the raw table line, not a re-serialization of it.
pub async fn open_sockets<W: BundleSink>(
    w: &mut BundleWriter<W>,
    dest: &str,
    markers: &[&str],
    always: &[u32],
) -> Result<(), anyhow::Error> {
    socket_join(w, &scoped(dest, "proc/sockets.txt"), markers, always).await
}

#[cfg(not(target_os = "linux"))]
async fn socket_join<W: BundleSink>(
    w: &mut BundleWriter<W>,
    path: &str,
    _markers: &[&str],
    _always: &[u32],
) -> Result<(), anyhow::Error> {
    w.skip(path, "fd→socket-inode joins need /proc");
    Ok(())
}

#[cfg(target_os = "linux")]
async fn socket_join<W: BundleSink>(
    w: &mut BundleWriter<W>,
    path: &str,
    markers: &[&str],
    always: &[u32],
) -> Result<(), anyhow::Error> {
    use std::fmt::Write as _;

    let pids = triage_pids(markers, always).await?;
    if pids.is_empty() {
        w.skip(path, "no marker-matched processes holding sockets");
        return Ok(());
    }
    let mut tables = Vec::with_capacity(crate::net::PROC_NET_SOCKET_TABLES.len());
    for table in crate::net::PROC_NET_SOCKET_TABLES {
        if let Ok(text) = tokio::fs::read_to_string(format!("/proc/net/{table}")).await {
            tables.push((*table, text));
        }
    }
    let sockets = index_by_inode(&tables);

    let mut text = String::from("pid\tfd\tinode\ttable\tentry\n");
    for (pid, _) in pids {
        let Ok(mut entries) = tokio::fs::read_dir(format!("/proc/{pid}/fd")).await else {
            let _ = writeln!(text, "{pid}\t-\t-\t-\t<fd directory unreadable>");
            continue;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let Ok(target) = tokio::fs::read_link(entry.path()).await else {
                continue;
            };
            let Some(inode) = socket_inode(&target.to_string_lossy()) else {
                continue; // not a socket fd — files and pipes are `stack.txt`'s job
            };
            let fd = entry.file_name().to_string_lossy().into_owned();
            let (table, row) = sockets
                .get(&inode)
                .map(|(t, l)| (t.as_str(), l.as_str()))
                // A socket with no table row is itself a finding: it belongs to
                // a family /proc/net does not list (netlink) or to a network
                // namespace this process cannot see.
                .unwrap_or(("?", "<no /proc/net entry>"));
            let _ = writeln!(text, "{pid}\t{fd}\t{inode}\t{table}\t{row}");
        }
    }
    w.add_bytes(path, text.as_bytes(), Redaction::None).await
}

/// The socket inode named by an fd's readlink target, e.g. `socket:[12345]`.
#[cfg(any(target_os = "linux", test))]
fn socket_inode(link_target: &str) -> Option<u64> {
    link_target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// The field index holding the socket inode in a `/proc/net` table row.
/// `unix` has its own column layout; the IP tables share one.
#[cfg(any(target_os = "linux", test))]
fn inode_column(table: &str) -> usize {
    if table == "unix" { 6 } else { 9 }
}

/// Indexes `(table, contents)` pairs by socket inode, keeping each row
/// verbatim. Header rows fall out for free — their inode column is a label,
/// not a number.
#[cfg(any(target_os = "linux", test))]
fn index_by_inode(tables: &[(&str, String)]) -> std::collections::BTreeMap<u64, (String, String)> {
    tables
        .iter()
        .flat_map(|(table, text)| {
            text.lines().filter_map(move |line| {
                let inode = line.split_whitespace().nth(inode_column(table))?;
                Some((
                    inode.parse().ok()?,
                    ((*table).to_string(), line.trim().to_string()),
                ))
            })
        })
        .collect()
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

    #[test]
    fn socket_inode_reads_only_socket_links() {
        assert_eq!(socket_inode("socket:[12345]"), Some(12345));
        assert_eq!(socket_inode("/run/minimald/ssh.sock"), None);
        assert_eq!(socket_inode("pipe:[999]"), None);
        assert_eq!(socket_inode("anon_inode:[eventpoll]"), None);
    }

    /// The join keys on the inode column, which differs between the IP tables
    /// and `unix`; header rows must not become entries.
    #[test]
    fn index_by_inode_keys_both_table_layouts() {
        let tcp = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 41001 1 ffff 100 0 0 10 0
"
        .to_string();
        let unix = "\
Num       RefCount Protocol Flags    Type St Inode Path
ffff8880: 00000002 00000000 00010000 0001 01 41002 /run/minimald/ssh.sock
"
        .to_string();
        let index = index_by_inode(&[("tcp", tcp), ("unix", unix)]);

        assert_eq!(index.len(), 2, "headers are not entries: {index:?}");
        let (table, row) = &index[&41001];
        assert_eq!(table, "tcp");
        assert!(row.contains("00000000:0016"), "row kept verbatim: {row}");
        let (table, row) = &index[&41002];
        assert_eq!(table, "unix");
        assert!(row.ends_with("/run/minimald/ssh.sock"), "{row}");
    }

    #[tokio::test]
    async fn triage_pids_puts_caller_pids_first_and_never_repins_them() {
        // No process can match this marker, so the whole set comes from
        // `always` — the daemon-triaging-itself case, where argv0 says nothing.
        let pids = triage_pids(&["\u{1}no-such-binary"], &[4242])
            .await
            .unwrap();
        assert_eq!(pids, vec![(4242, false)]);
    }
}
