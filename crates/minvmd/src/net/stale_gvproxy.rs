//! Reap a gvproxy switch left behind by a crashed supervisor.
//!
//! A crashed or `SIGKILL`ed `minvmd` cannot run its clean teardown: the
//! supervisor's stop paths ([`super::GvproxySupervisor::stop`] and its `Drop`)
//! fire only on an orderly exit, so its gvproxy, which holds no alive lock,
//! survives with the host-side forwards still bound.
//! Unlinking the stale switch socket ([`crate::sock::remove_stale_socket`])
//! then lets the new gvproxy start while the leftover still holds the ports,
//! leaving two switches silently overlapping. [`reap_stale_gvproxy`] kills
//! the leftover first.
//!
//! The process scan reads each process's exact argv: `/proc/<pid>/cmdline`
//! on Linux, `sysctl(KERN_PROCARGS2)` on macOS. A match needs both anchors
//! as whole argv tokens: argv\[0\] is the gvproxy binary path, and the token
//! after `-listen` is `unix://<this VM's switch socket>`. Those are exactly
//! the tokens [`super::GvproxyConfig::argv`] and its spawn hand gvproxy, so
//! another VM's switch (another socket), another checkout's (another binary)
//! or a path that merely shares a prefix never match.

#![cfg_attr(not(minvmd_libkrun), allow(dead_code))]

use std::path::Path;
use std::time::{Duration, Instant};

/// How long the reap gives the killed leftovers, in total, to be gone before
/// warning and spawning anyway.
const STALE_GONE_TIMEOUT: Duration = Duration::from_secs(2);

/// How many times the scan re-reads the argv of a live process it could not
/// read, and the pause before each re-read. One pause covers every such
/// process at once, so the scan's extra cost is bounded by the product
/// however many there are.
const ARGV_REREADS: usize = 3;
const ARGV_REREAD_INTERVAL: Duration = Duration::from_millis(20);

/// Reap a leftover gvproxy of this VM before a fresh one is spawned.
///
/// The caller holds this VM's alive lock, so no other supervisor of this VM
/// is live and any process matching both anchors is a dead supervisor's
/// leftover. A match whose parent is a live `minvmd` breaks that invariant:
/// the start fails closed with an error instead of spawning a duplicate
/// switch, and nothing is killed. This process and its parent are never
/// candidates.
///
/// Each kill re-verifies the argv against the pid it signals. On Linux the
/// signal goes through a pidfd opened before that check, so it cannot land on
/// a recycled pid. On macOS, which has no pidfd, the re-check runs immediately
/// before `kill(2)`. The residual window is that one syscall gap, and a pid
/// would have to be freed and reused inside it.
///
/// The wait for the leftovers to go is bounded to [`STALE_GONE_TIMEOUT`] in
/// total. It blocks the calling thread, which is the synchronous supervisor
/// thread and never a tokio worker. Apart from the live-owner error, the reap
/// is best-effort: a leftover that cannot be signalled or outlives the wait
/// is warned about and never fails the boot.
pub(crate) fn reap_stale_gvproxy(binary: &Path, switch_sock: &Path) -> anyhow::Result<()> {
    reap_with(&HostProcesses, binary, switch_sock)
}

/// The process lookups the reap decides on: the scan and the parent lookup.
/// A seam so a test can stage a live-minvmd-owned match without a real
/// `minvmd` parent process.
trait ProcessLookup {
    fn all_pids(&self) -> Vec<u32>;
    fn argv(&self, pid: u32) -> Option<Vec<Vec<u8>>>;
    fn ppid(&self, pid: u32) -> Option<u32>;
    /// Whether `pid`'s argv, unreadable just now, may read on a retry: the
    /// process is live, not a zombie, and this user's, so it could be a
    /// leftover this reap would kill.
    fn argv_may_settle(&self, pid: u32) -> bool;
}

/// The host's process table.
struct HostProcesses;

impl ProcessLookup for HostProcesses {
    fn all_pids(&self) -> Vec<u32> {
        os::all_pids()
    }
    fn argv(&self, pid: u32) -> Option<Vec<Vec<u8>>> {
        os::argv(pid)
    }
    fn ppid(&self, pid: u32) -> Option<u32> {
        os::ppid(pid)
    }
    fn argv_may_settle(&self, pid: u32) -> bool {
        os::argv_may_settle(pid)
    }
}

fn reap_with(procs: &impl ProcessLookup, binary: &Path, switch_sock: &Path) -> anyhow::Result<()> {
    let me = std::process::id();
    // SAFETY: getppid(2) takes no arguments and cannot fail.
    let my_parent = unsafe { libc::getppid() } as u32;
    // Collect the candidates first, then signal each after a fresh check.
    let candidates = find_candidates(procs, binary, switch_sock, &[me, my_parent]);
    // Fail closed before killing anything: a live minvmd owning this VM's
    // switch means the alive-lock invariant is broken, and spawning would
    // bind a second switch beside it.
    for &pid in &candidates {
        if let Some(parent) = procs
            .ppid(pid)
            .filter(|&parent| procs.argv(parent).is_some_and(|argv| argv_is_minvmd(&argv)))
        {
            anyhow::bail!(
                "a gvproxy (pid {pid}) on this VM's switch socket is owned by a live minvmd \
                 (pid {parent}); stop it before starting"
            );
        }
    }
    let mut killed = Vec::new();
    for pid in candidates {
        if let Some(victim) = os::kill_if_still_stale(pid, binary, switch_sock) {
            tracing::warn!(
                pid,
                binary = %binary.display(),
                switch_socket = %switch_sock.display(),
                "killed stale gvproxy left by a crashed supervisor",
            );
            killed.push(victim);
        }
    }
    let deadline = Instant::now() + STALE_GONE_TIMEOUT;
    for victim in killed {
        if !os::wait_gone(&victim, deadline) {
            tracing::warn!(
                pid = victim.pid(),
                "stale gvproxy still alive after SIGKILL; spawning the fresh switch anyway",
            );
        }
    }
    Ok(())
}

/// The pids whose argv matches this VM's gvproxy, `skip` excluded. A live
/// process of this user whose argv cannot be read is re-read
/// ([`ARGV_REREADS`] times, [`ARGV_REREAD_INTERVAL`] apart) rather than
/// skipped: on macOS `sysctl(KERN_PROCARGS2)` can fail transiently, and a
/// leftover skipped that way would keep holding the switch socket.
fn find_candidates(
    procs: &impl ProcessLookup,
    binary: &Path,
    switch_sock: &Path,
    skip: &[u32],
) -> Vec<u32> {
    let mut candidates = Vec::new();
    let mut unreadable = Vec::new();
    for pid in procs.all_pids() {
        if skip.contains(&pid) {
            continue;
        }
        match procs.argv(pid) {
            Some(argv) if argv_is_stale_gvproxy(&argv, binary, switch_sock) => candidates.push(pid),
            Some(_) => {}
            None => unreadable.push(pid),
        }
    }
    for _ in 0..ARGV_REREADS {
        unreadable.retain(|&pid| procs.argv_may_settle(pid));
        if unreadable.is_empty() {
            break;
        }
        std::thread::sleep(ARGV_REREAD_INTERVAL);
        unreadable.retain(|&pid| match procs.argv(pid) {
            Some(argv) => {
                if argv_is_stale_gvproxy(&argv, binary, switch_sock) {
                    candidates.push(pid);
                }
                false
            }
            None => true,
        });
    }
    for pid in unreadable {
        if procs.argv_may_settle(pid) {
            tracing::debug!(pid, "could not read a live process's argv; not reaping it");
        }
    }
    candidates
}

/// Whether `argv` is a gvproxy of this VM: argv\[0\] is exactly `binary`, and
/// some `-listen` token is followed by exactly `unix://<switch_sock>`. Pure, so
/// its tests run on every host.
fn argv_is_stale_gvproxy(argv: &[Vec<u8>], binary: &Path, switch_sock: &Path) -> bool {
    let Some(arg0) = argv.first() else {
        return false;
    };
    if arg0.as_slice() != binary.as_os_str().as_encoded_bytes() {
        return false;
    }
    let mut listen = b"unix://".to_vec();
    listen.extend_from_slice(switch_sock.as_os_str().as_encoded_bytes());
    argv.windows(2)
        .any(|pair| pair[0] == b"-listen" && pair[1] == listen)
}

/// Whether `argv` is a `minvmd` process: argv\[0\]'s file name is `minvmd`.
fn argv_is_minvmd(argv: &[Vec<u8>]) -> bool {
    argv.first().is_some_and(|arg0| {
        let arg0 = Path::new(<std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(arg0));
        arg0.file_name().is_some_and(|name| name == "minvmd")
    })
}

/// Split a NUL-separated argv block (a trailing NUL is optional) into its
/// tokens. An empty block is a kernel thread or an exited process: no argv.
#[cfg(any(target_os = "linux", test))]
fn split_nul_argv(block: &[u8]) -> Option<Vec<Vec<u8>>> {
    let block = block.strip_suffix(&[0]).unwrap_or(block);
    if block.is_empty() {
        return None;
    }
    Some(block.split(|&b| b == 0).map(<[u8]>::to_vec).collect())
}

/// Parse a `sysctl(KERN_PROCARGS2)` buffer: a native-endian `int argc`, the
/// exec path, NUL padding, then `argc` NUL-terminated argv strings (the
/// environment follows and is ignored). `None` on a malformed buffer.
#[cfg(any(target_os = "macos", test))]
fn parse_procargs2(buf: &[u8]) -> Option<Vec<Vec<u8>>> {
    let argc = i32::from_ne_bytes(buf.get(..4)?.try_into().ok()?);
    let argc = usize::try_from(argc).ok()?;
    let rest = &buf[4..];
    // Skip the exec path, then the NUL padding after it.
    let path_end = rest.iter().position(|&b| b == 0)?;
    let mut rest = &rest[path_end..];
    let first_arg = rest.iter().position(|&b| b != 0)?;
    rest = &rest[first_arg..];
    let mut argv = Vec::with_capacity(argc);
    for _ in 0..argc {
        let end = rest.iter().position(|&b| b == 0)?;
        argv.push(rest[..end].to_vec());
        rest = &rest[end + 1..];
    }
    (!argv.is_empty()).then_some(argv)
}

/// The `/proc`-and-pidfd half of the reap.
#[cfg(target_os = "linux")]
mod os {
    use std::io;
    use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
    use std::path::Path;
    use std::time::Instant;

    /// A signalled leftover: its pidfd, which turns readable once it exits.
    pub(super) struct Victim {
        pid: u32,
        pidfd: OwnedFd,
    }

    impl Victim {
        pub(super) fn pid(&self) -> u32 {
            self.pid
        }
    }

    /// Every numeric `/proc` entry.
    pub(super) fn all_pids() -> Vec<u32> {
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
            .collect()
    }

    /// The exact argv of `pid`, from `/proc/<pid>/cmdline`.
    pub(super) fn argv(pid: u32) -> Option<Vec<Vec<u8>>> {
        super::split_nul_argv(&std::fs::read(format!("/proc/{pid}/cmdline")).ok()?)
    }

    /// `/proc/<pid>/cmdline` does not fail transiently: an empty or missing
    /// one is a kernel thread, a zombie or a reaped pid, none of which a
    /// re-read changes.
    pub(super) fn argv_may_settle(_pid: u32) -> bool {
        false
    }

    /// The parent pid of `pid`, from `/proc/<pid>/stat`. The fields follow
    /// the last `)`, since comm can embed spaces or parentheses.
    pub(super) fn ppid(pid: u32) -> Option<u32> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let (_, rest) = stat.rsplit_once(')')?;
        // `<state> <ppid> ...`
        rest.split_whitespace().nth(1)?.parse().ok()
    }

    /// Pin `pid` with a pidfd, re-check its argv, and SIGKILL it through the
    /// pidfd. If the pid exited and was reused before the pidfd opened, the
    /// re-check sees the new argv and nothing is signalled. If it exits after
    /// the pidfd opened, the signal gets `ESRCH` and lands on nothing.
    pub(super) fn kill_if_still_stale(pid: u32, binary: &Path, sock: &Path) -> Option<Victim> {
        // SAFETY: pidfd_open(2) takes a pid and flags=0, touches no memory and
        // returns an fd or -1.
        let raw =
            unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::c_long, 0 as libc::c_long) }
                as libc::c_int;
        if raw < 0 {
            // ESRCH: already gone. Anything else (ENOSYS on a pre-5.3 kernel,
            // a seccomp filter) leaves the leftover alive, so say so.
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                tracing::warn!(
                    pid,
                    %error,
                    "opening a pidfd on stale gvproxy failed; not reaping it",
                );
            }
            return None;
        }
        // SAFETY: `raw` is a valid fd just returned by pidfd_open.
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
        if !argv(pid).is_some_and(|a| super::argv_is_stale_gvproxy(&a, binary, sock)) {
            return None;
        }
        // SAFETY: pidfd_send_signal(2) with a null siginfo and flags=0 is
        // kill(2) on the pinned process; it touches no memory.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd() as libc::c_long,
                libc::SIGKILL as libc::c_long,
                0 as libc::c_long,
                0 as libc::c_long,
            )
        };
        if rc != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                tracing::warn!(pid, %error, "signalling stale gvproxy failed");
            }
            return None;
        }
        Some(Victim { pid, pidfd })
    }

    /// Wait until `victim` has exited or `deadline` passes, by polling its
    /// pidfd, which turns readable at exit. A zombie counts as gone: its
    /// sockets and ports were released when it exited. `true` when gone.
    pub(super) fn wait_gone(victim: &Victim, deadline: Instant) -> bool {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let mut pfd = libc::pollfd {
                fd: victim.pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let timeout_ms =
                libc::c_int::try_from(remaining.as_millis()).unwrap_or(libc::c_int::MAX);
            // SAFETY: `pfd` is one valid pollfd that outlives the call.
            let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
            if rc > 0 {
                return true;
            }
            if rc == 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return false;
            }
        }
    }
}

/// The libproc-and-sysctl half of the reap.
#[cfg(target_os = "macos")]
mod os {
    use std::io;
    use std::path::Path;
    use std::time::{Duration, Instant};

    /// How often the bounded wait re-probes a killed leftover. macOS has no
    /// pidfd to block on.
    const POLL_INTERVAL: Duration = Duration::from_millis(50);

    /// A signalled leftover, tracked by pid alone.
    pub(super) struct Victim {
        pid: u32,
    }

    impl Victim {
        pub(super) fn pid(&self) -> u32 {
            self.pid
        }
    }

    /// Every pid on the host, from `proc_listallpids`.
    pub(super) fn all_pids() -> Vec<u32> {
        // SAFETY: a null buffer asks only for the current count.
        let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
        let Ok(count) = usize::try_from(count) else {
            return Vec::new();
        };
        // Headroom for processes spawned between the two calls.
        let mut pids: Vec<libc::pid_t> = vec![0; count + 64];
        let bytes = libc::c_int::try_from(std::mem::size_of_val(pids.as_slice()))
            .unwrap_or(libc::c_int::MAX);
        // SAFETY: `pids` is a writable buffer of exactly `bytes` bytes.
        let got = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
        let Ok(got) = usize::try_from(got) else {
            return Vec::new();
        };
        pids.truncate(got.min(pids.len()));
        pids.into_iter()
            .filter_map(|pid| u32::try_from(pid).ok().filter(|&pid| pid > 0))
            .collect()
    }

    /// The exact argv of `pid`, from `sysctl(KERN_PROCARGS2)`. Unlike `ps`,
    /// this keeps token boundaries and never truncates.
    pub(super) fn argv(pid: u32) -> Option<Vec<Vec<u8>>> {
        let mut mib = [
            libc::CTL_KERN,
            libc::KERN_PROCARGS2,
            libc::c_int::try_from(pid).ok()?,
        ];
        let mut size: libc::size_t = 0;
        // SAFETY: a null old-pointer with a valid size pointer asks for the
        // buffer size; `mib` is a valid 3-element name.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                3,
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 || size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size];
        // SAFETY: `buf` is writable for `size` bytes, which `size` reports.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                3,
                buf.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return None;
        }
        buf.truncate(size);
        super::parse_procargs2(&buf)
    }

    /// The BSD info of `pid`. `proc_pidinfo` refuses a zombie with `ESRCH`
    /// as it does a reaped pid, so the error is returned for the caller to
    /// tell those apart.
    fn bsdinfo(pid: u32) -> io::Result<libc::proc_bsdinfo> {
        let raw_pid = libc::c_int::try_from(pid).map_err(io::Error::other)?;
        // SAFETY: proc_bsdinfo is plain old data; all-zero is a valid value.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>())
            .map_err(io::Error::other)?;
        // SAFETY: `info` is writable for `size` bytes.
        let got = unsafe {
            libc::proc_pidinfo(
                raw_pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&raw mut info).cast(),
                size,
            )
        };
        if got == size {
            Ok(info)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// The parent pid of `pid`.
    pub(super) fn ppid(pid: u32) -> Option<u32> {
        bsdinfo(pid).ok().map(|info| info.pbi_ppid)
    }

    /// Whether `pid` is live, not a zombie, and runs with this process's
    /// effective uid: the only processes a leftover gvproxy can be, and the
    /// ones whose `KERN_PROCARGS2` read is expected to succeed, so a failed
    /// read is worth retrying. Another user's process (a setuid `login`,
    /// say) fails that read every time and is never retried.
    pub(super) fn argv_may_settle(pid: u32) -> bool {
        // SAFETY: geteuid(2) takes no arguments and cannot fail.
        let me = unsafe { libc::geteuid() };
        bsdinfo(pid).is_ok_and(|info| info.pbi_uid == me && info.pbi_status != libc::SZOMB)
    }

    /// `pid`'s argv, re-read while it is unreadable but may settle
    /// ([`argv_may_settle`]), bounded like the scan's re-reads.
    fn argv_settled(pid: u32) -> Option<Vec<Vec<u8>>> {
        for _ in 0..super::ARGV_REREADS {
            if let Some(argv) = argv(pid) {
                return Some(argv);
            }
            if !argv_may_settle(pid) {
                return None;
            }
            std::thread::sleep(super::ARGV_REREAD_INTERVAL);
        }
        argv(pid)
    }

    /// Re-check `pid`'s argv and SIGKILL it immediately after. macOS has no
    /// pidfd: the residual pid-reuse window is the gap between these two
    /// syscalls (see [`super::reap_stale_gvproxy`]). A re-check that cannot
    /// read the argv of a live candidate is retried, not taken as a miss.
    pub(super) fn kill_if_still_stale(pid: u32, binary: &Path, sock: &Path) -> Option<Victim> {
        if !argv_settled(pid).is_some_and(|a| super::argv_is_stale_gvproxy(&a, binary, sock)) {
            return None;
        }
        let raw_pid = libc::pid_t::try_from(pid).ok()?;
        // SAFETY: kill(2) takes a pid and a signal number; it touches no memory.
        if unsafe { libc::kill(raw_pid, libc::SIGKILL) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                tracing::warn!(pid, %error, "signalling stale gvproxy failed");
            }
            return None;
        }
        Some(Victim { pid })
    }

    /// Whether `pid` has exited: `kill(pid, 0)` fails, or it is a zombie,
    /// whose sockets and ports were released when it exited. `kill(pid, 0)`
    /// still succeeds on a zombie while `proc_pidinfo` answers `ESRCH`, so
    /// that pair (or an `SZOMB` status) is the zombie test.
    fn is_gone(pid: u32) -> bool {
        let Ok(raw_pid) = libc::pid_t::try_from(pid) else {
            return true;
        };
        // SAFETY: kill(pid, 0) only probes for existence.
        if unsafe { libc::kill(raw_pid, 0) } != 0 {
            return true;
        }
        match bsdinfo(pid) {
            Ok(info) => info.pbi_status == libc::SZOMB,
            Err(error) => error.raw_os_error() == Some(libc::ESRCH),
        }
    }

    /// Wait, polling, until `victim` has exited or `deadline` passes. `true`
    /// when gone.
    pub(super) fn wait_gone(victim: &Victim, deadline: Instant) -> bool {
        loop {
            if is_gone(victim.pid) {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            std::thread::sleep(POLL_INTERVAL.min(deadline - now));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt as _;
    use std::os::unix::process::ExitStatusExt as _;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};

    fn tokens(argv: &[&str]) -> Vec<Vec<u8>> {
        argv.iter().map(|t| t.as_bytes().to_vec()).collect()
    }

    #[test]
    fn match_needs_both_anchors_as_exact_tokens() {
        let bin = Path::new("/opt/m/gvproxy");
        let sock = Path::new("/run/vm/gvproxy-switch.sock");
        let real = [
            "/opt/m/gvproxy",
            "-config",
            "/run/vm/gvproxy.yaml",
            "-listen",
            "unix:///run/vm/gvproxy-switch.sock",
            "-ssh-port",
            "-1",
        ];
        assert!(argv_is_stale_gvproxy(&tokens(&real), bin, sock));

        let mut other_sock = real;
        other_sock[4] = "unix:///run/other/gvproxy-switch.sock";
        assert!(!argv_is_stale_gvproxy(&tokens(&other_sock), bin, sock));

        // A socket path this one is a prefix of is a different VM's socket.
        let mut longer_sock = real;
        longer_sock[4] = "unix:///run/vm/gvproxy-switch.sock.old";
        assert!(!argv_is_stale_gvproxy(&tokens(&longer_sock), bin, sock));

        // A binary path this one is a prefix of is another consumer's gvproxy.
        let mut longer_bin = real;
        longer_bin[0] = "/opt/m/gvproxy-other";
        assert!(!argv_is_stale_gvproxy(&tokens(&longer_bin), bin, sock));

        // The binary anywhere but argv[0] is not this binary running.
        let wrapped = [
            "/usr/bin/strace",
            "/opt/m/gvproxy",
            "-listen",
            "unix:///run/vm/gvproxy-switch.sock",
        ];
        assert!(!argv_is_stale_gvproxy(&tokens(&wrapped), bin, sock));

        // The socket outside the `-listen` value is not this VM's switch.
        let mut not_listen = real;
        not_listen[3] = "-forward-sock";
        assert!(!argv_is_stale_gvproxy(&tokens(&not_listen), bin, sock));

        // One token holding both, as a joined `ps` line would, never matches.
        let joined = ["/opt/m/gvproxy -listen unix:///run/vm/gvproxy-switch.sock"];
        assert!(!argv_is_stale_gvproxy(&tokens(&joined), bin, sock));
        assert!(!argv_is_stale_gvproxy(&[], bin, sock));
    }

    #[test]
    fn minvmd_parent_is_recognised_by_file_name() {
        assert!(argv_is_minvmd(&tokens(&["/opt/m/minvmd", "run"])));
        assert!(argv_is_minvmd(&tokens(&["minvmd"])));
        assert!(!argv_is_minvmd(&tokens(&["/sbin/launchd"])));
        assert!(!argv_is_minvmd(&tokens(&["/opt/m/minvmd-old"])));
        assert!(!argv_is_minvmd(&[]));
    }

    #[test]
    fn nul_argv_splits_with_or_without_trailing_nul() {
        assert_eq!(
            split_nul_argv(b"a\0b c\0\0d\0"),
            Some(tokens(&["a", "b c", "", "d"]))
        );
        assert_eq!(split_nul_argv(b"a\0b"), Some(tokens(&["a", "b"])));
        assert_eq!(split_nul_argv(b""), None);
    }

    #[test]
    fn procargs2_skips_exec_path_and_padding_and_stops_at_argc() {
        let mut buf = 2i32.to_ne_bytes().to_vec();
        buf.extend_from_slice(b"/bin/bash\0\0\0\0/opt/m/gvproxy\0-listen\0HOME=/x\0");
        assert_eq!(
            parse_procargs2(&buf),
            Some(tokens(&["/opt/m/gvproxy", "-listen"]))
        );
        // Truncated: argc claims more strings than the buffer holds.
        let mut short = 3i32.to_ne_bytes().to_vec();
        short.extend_from_slice(b"/bin/sh\0a\0");
        assert_eq!(parse_procargs2(&short), None);
        assert_eq!(parse_procargs2(b"\x01"), None);
    }

    /// A staged process table: pid -> (argv, ppid).
    struct FakeProcesses(Vec<(u32, Vec<Vec<u8>>, u32)>);

    impl ProcessLookup for FakeProcesses {
        fn all_pids(&self) -> Vec<u32> {
            self.0.iter().map(|(pid, ..)| *pid).collect()
        }
        fn argv(&self, pid: u32) -> Option<Vec<Vec<u8>>> {
            self.0
                .iter()
                .find(|(p, ..)| *p == pid)
                .map(|(_, a, _)| a.clone())
        }
        fn ppid(&self, pid: u32) -> Option<u32> {
            self.0.iter().find(|(p, ..)| *p == pid).map(|(.., pp)| *pp)
        }
        fn argv_may_settle(&self, pid: u32) -> bool {
            self.0.iter().any(|(p, ..)| *p == pid)
        }
    }

    /// A staged table whose argv reads fail the first `fails` times per pid,
    /// as `KERN_PROCARGS2` can on a live macOS process.
    struct FlakyArgv {
        procs: FakeProcesses,
        fails: usize,
        reads: std::cell::RefCell<std::collections::HashMap<u32, usize>>,
    }

    impl ProcessLookup for FlakyArgv {
        fn all_pids(&self) -> Vec<u32> {
            self.procs.all_pids()
        }
        fn argv(&self, pid: u32) -> Option<Vec<Vec<u8>>> {
            let mut reads = self.reads.borrow_mut();
            let seen = reads.entry(pid).or_default();
            *seen += 1;
            if *seen <= self.fails {
                return None;
            }
            self.procs.argv(pid)
        }
        fn ppid(&self, pid: u32) -> Option<u32> {
            self.procs.ppid(pid)
        }
        fn argv_may_settle(&self, pid: u32) -> bool {
            self.procs.argv_may_settle(pid)
        }
    }

    #[test]
    fn scan_rereads_a_live_process_whose_argv_failed_to_read() {
        let bin = Path::new("/opt/m/gvproxy");
        let sock = Path::new("/run/vm/gvproxy-switch.sock");
        let gvproxy = 5_000_003;
        let staged = || {
            FakeProcesses(vec![(
                gvproxy,
                tokens(&[
                    "/opt/m/gvproxy",
                    "-listen",
                    "unix:///run/vm/gvproxy-switch.sock",
                ]),
                1,
            )])
        };
        // Reads that fail fewer times than the re-reads allow still find it.
        let flaky = FlakyArgv {
            procs: staged(),
            fails: ARGV_REREADS,
            reads: Default::default(),
        };
        assert_eq!(find_candidates(&flaky, bin, sock, &[]), vec![gvproxy]);
        // A process whose argv never reads is given up on, boundedly.
        let dead = FlakyArgv {
            procs: staged(),
            fails: usize::MAX,
            reads: Default::default(),
        };
        assert!(find_candidates(&dead, bin, sock, &[]).is_empty());
        assert_eq!(dead.reads.borrow()[&gvproxy], ARGV_REREADS + 1);
    }

    #[test]
    fn reap_fails_closed_on_a_live_minvmd_owned_gvproxy() {
        let bin = Path::new("/opt/m/gvproxy");
        let sock = Path::new("/run/vm/gvproxy-switch.sock");
        // Pids above Linux's and macOS's pid ceilings, so neither is this test or its parent.
        let (gvproxy, owner) = (5_000_002, 5_000_001);
        let procs = FakeProcesses(vec![
            (owner, tokens(&["/opt/m/minvmd", "run"]), 1),
            (
                gvproxy,
                tokens(&[
                    "/opt/m/gvproxy",
                    "-listen",
                    "unix:///run/vm/gvproxy-switch.sock",
                ]),
                owner,
            ),
        ]);

        let err = reap_with(&procs, bin, sock).expect_err("a live owner must fail the start");

        assert_eq!(
            err.to_string(),
            "a gvproxy (pid 5000002) on this VM's switch socket is owned by a live minvmd \
             (pid 5000001); stop it before starting"
        );
    }

    /// A stand-in gvproxy whose argv is the one the real spawn hands gvproxy:
    /// argv[0] is `binary` (via `arg0`; the file need not exist) and the
    /// `-listen unix://<sock>` pair is present as separate tokens. `/bin/sh`
    /// keeps argv[0] as given on both Linux and macOS, and the loop keeps it
    /// alive until signalled, whatever arguments follow the script.
    fn spawn_stand_in(binary: &Path, sock: &Path) -> Child {
        Command::new("/bin/sh")
            .arg0(binary)
            .arg("-c")
            .arg("while :; do sleep 1; done")
            .arg("-config")
            .arg("gvproxy.yaml")
            .arg("-listen")
            .arg(format!("unix://{}", sock.display()))
            .arg("-ssh-port")
            .arg("-1")
            // The loop's `sleep` outlives a SIGKILLed shell by up to a second;
            // it must not hold the test harness's output pipes open meanwhile.
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn stand-in gvproxy")
    }

    /// Wait until the scan would see `child` as a match, so the reap below is
    /// not racing the stand-in's exec (macOS's /bin/sh re-execs a shell).
    fn await_visible(child: &Child, binary: &Path, sock: &Path) {
        let by = Instant::now() + Duration::from_secs(5);
        while !os::argv(child.id()).is_some_and(|a| argv_is_stale_gvproxy(&a, binary, sock)) {
            assert!(Instant::now() < by, "stand-in argv never became visible");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let binary = dir.path().join("gvproxy");
        (dir, binary)
    }

    #[test]
    fn reap_kills_this_vms_leftover() {
        let (dir, binary) = fixture();
        let sock = dir.path().join("gvproxy-switch.sock");
        let mut child = spawn_stand_in(&binary, &sock);
        await_visible(&child, &binary, &sock);

        reap_stale_gvproxy(&binary, &sock).expect("reap");

        // The reap returns once the leftover is gone (a zombie, here, since
        // this test is its parent), so the exit is reapable without a wait.
        let by = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().expect("try_wait stand-in") {
                break status;
            }
            assert!(
                Instant::now() < by,
                "stale gvproxy stand-in survived the reap"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(status.signal(), Some(libc::SIGKILL));
    }

    #[test]
    fn reap_leaves_another_vms_and_another_binarys_gvproxy_alone() {
        let (dir, binary) = fixture();
        let sock = dir.path().join("gvproxy-switch.sock");
        // Another VM: same binary, a socket ours is a prefix of.
        let other_sock = dir.path().join("gvproxy-switch.sock.other");
        let mut other_vm = spawn_stand_in(&binary, &other_sock);
        await_visible(&other_vm, &binary, &other_sock);
        // Another checkout: same socket path, a different binary.
        let other_binary = dir.path().join("gvproxy-other");
        let mut other_bin = spawn_stand_in(&other_binary, &sock);
        await_visible(&other_bin, &other_binary, &sock);
        // This VM's leftover, so the same reap is shown to be active.
        let mut ours = spawn_stand_in(&binary, &sock);
        await_visible(&ours, &binary, &sock);

        reap_stale_gvproxy(&binary, &sock).expect("reap");

        // The reap returns once the leftover is gone (a zombie, since this
        // test is its parent).
        let by = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = ours.try_wait().expect("try_wait ours") {
                break status;
            }
            assert!(Instant::now() < by, "this VM's leftover survived the reap");
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert!(
            other_vm.try_wait().expect("try_wait").is_none(),
            "the reap must not touch another VM's gvproxy"
        );
        assert!(
            other_bin.try_wait().expect("try_wait").is_none(),
            "the reap must not touch another binary's gvproxy"
        );
        for child in [&mut other_vm, &mut other_bin] {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
