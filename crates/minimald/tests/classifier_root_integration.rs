//! The classifier table's live proofs (NET-079): the loaded `nft` table
//! itself, installed by the privileged step over a scratch delegated tree
//! on this host's real cgroup2, and the effect it has on a box that runs
//! the way a launched box runs — the two halves the ruleset-text proofs in
//! `minimald::net::classifier` cannot vouch for, because a text is pinned
//! before it is loaded, and a request through the proxy is answered before
//! anything refused it.
//!
//! Two proofs, both `#[ignore]`d so the default suite and the surveyed
//! nextest lines never run them. The native lane's
//! `minimald-root-integration` job runs this binary under sudo, where every
//! precondition below is the lane's own to hold; a host that cannot run one
//! **fails** the proof rather than printing a reason and passing green — a
//! proof that declines over a host that could run it proves nothing while
//! looking like it ran. The one exception is a runner with no `nft`: the
//! packet filter is the step's own dependency, the one thing no lane can
//! promise a host, so each proof declines on it, with the reason printed.
//! Locally: `just test-root-integration` (the lane's own recipe), or
//! `sudo cargo nextest run -p minimald --run-ignored all --no-tests=fail \
//! -E 'binary(classifier_root_integration$)'`.
//!
//! Neither proof ever touches a host's own install: a tree at
//! [`sandbox2::classifier::TREE_ROOT`], or an already-loaded
//! `minimal_class` table, is that host's, and a proof that found one would
//! be a proof run over something it must not replace.
#![cfg(target_os = "linux")]

use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::io::{AsRawFd as _, FromRawFd as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use minimald::net::classifier::{Family, Observed, Reading, decide_now, read_filter};
use minimald::net::dns::HostnameRegistry;
use minimald::net::proxy::{Router, serve};
use minimald::net::switch::proxied_request_verdict;
use sandbox2::classifier::{self, create_box_leaf, daemon_leaf, place_pid, remove_box_leaf};
use sandbox2::config::{ALLOW_DIR, DENY_DIR, Verdict};
use sessions::SessionId;

/// The loaded table's name, the installer's spelling of it: the daemon
/// reads only its marker, so this is the proof's own name for what it
/// loads and removes.
const TABLE_NAME: &str = "minimal_class";

/// The two source identities the proof's install renders its table with:
/// any two distinct addresses would do, and the install refuses to run
/// without the pair — half a classification is one identity wearing two
/// names — so each proof names the pair the way the installer's own harness
/// does.
const COHORT_ADDRESS: &str = "100.72.0.9";
const NODE_PLANE_ADDRESS: &str = "100.72.0.1";

/// The privileged step under proof, the one `nft -f` transaction that lays
/// out a tree and loads the table over it.
fn installer() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/install-host-classifier.sh")
}

/// Whether this host has `nft` at all — the step's own dependency, and the
/// one precondition no lane can promise a runner, which is why it is the
/// one decline this binary knows rather than a failure.
fn nft_present() -> bool {
    Command::new("nft")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
}

/// The host's live cgroup2 mount for the proofs below: the deepest mount
/// in the daemon's own mount table that is the hierarchy itself (its
/// namespace root is `/`, so it is not another cgroup namespace's view)
/// and carries `nsdelegate` — the two facts the installer's own
/// `verify_mount` demands of the tree it lays out.
fn live_cgroup2_mount() -> Option<PathBuf> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let mut mount: Option<(usize, PathBuf)> = None;
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        let Some(sep) = fields.iter().position(|field| *field == "-") else {
            continue;
        };
        if fields.len() < sep + 4 || fields[sep + 1] != "cgroup2" {
            continue;
        }
        let options = fields[sep + 3];
        if fields[3] != "/" || !options.split(',').any(|option| option == "nsdelegate") {
            continue;
        }
        if mount
            .as_ref()
            .is_none_or(|(depth, _)| fields[4].len() > *depth)
        {
            mount = Some((fields[4].len(), fields[4].into()));
        }
    }
    mount.map(|(_, mountpoint)| mountpoint)
}

/// A non-root account to delegate the scratch tree to: the install refuses
/// to delegate to root (that would hand every box the account that owns the
/// tree), so the proof takes the first human-range account in the password
/// database — the account a development host's daemon runs as.
fn delegate_account() -> Option<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        let uid: u32 = fields.get(2)?.parse().ok()?;
        let name = fields.first()?;
        (1000..=60000).contains(&uid).then(|| name.to_string())
    })
}

/// The preconditions the root lane runs under, asserted rather than
/// skipped: this binary's proofs load the installer's own table over this
/// host's real cgroup2, so a host that cannot run one must fail loudly
/// here rather than print a reason and pass green. Returns the cgroup2
/// mountpoint the scratch tree goes under; `nft` itself is the caller's to
/// decline on.
fn refuse_unless_the_root_lane_can_run() -> PathBuf {
    // SAFETY: `geteuid(2)` has no failure modes or preconditions.
    let euid = unsafe { libc::geteuid() };
    assert!(
        euid == 0,
        "the install these proofs run needs root to delegate the scratch \
         tree and load the table (try: sudo just test-root-integration)"
    );
    assert!(
        !Path::new(classifier::TREE_ROOT).exists(),
        "a classifier tree is already installed at {} — these proofs never \
         run over a host's own install",
        classifier::TREE_ROOT
    );
    assert!(
        !Command::new("nft")
            .args(["list", "table", "inet", TABLE_NAME])
            .output()
            .is_ok_and(|out| out.status.success()),
        "a table named {TABLE_NAME} is already loaded — these proofs never \
         replace a host's own table"
    );
    live_cgroup2_mount().expect(
        "no cgroup2 mounted with nsdelegate on this host — the \
         install's verify_mount would refuse the scratch tree, and \
         a tree on a mount without it confines nothing",
    )
}

/// The proof's install over `root`: the step's own rehearsal half, with
/// `--root` naming the scratch tree, delegated to `account`, and the
/// proof's two identities — one `nft -f` transaction that lays out the
/// cohort's two subtrees and loads the table over them.
fn install_over_scratch(root: &Path, account: &str) {
    let installed = Command::new("bash")
        .arg(installer())
        .arg("--root")
        .arg(root)
        .arg("--user")
        .arg(account)
        .arg("--cohort-address")
        .arg(COHORT_ADDRESS)
        .arg("--node-plane-address")
        .arg(NODE_PLANE_ADDRESS)
        .output()
        .expect("running the privileged step over the scratch tree");
    assert!(
        installed.status.success(),
        "the install lays out the scratch tree and loads its table: {}{}",
        String::from_utf8_lossy(&installed.stdout),
        String::from_utf8_lossy(&installed.stderr),
    );
}

/// Serializes this binary's two proofs against each other: each loads the
/// one table the installer owns, and a second install's transaction
/// replaces the first's table mid-proof — the replaced table is keyed on
/// the other proof's tree, so the first proof's probe would meet an
/// admitting table and fail for no reason of its own. The two run as
/// separate processes under nextest, so only a file lock can put them one
/// at a time; a stale file from a killed run holds nothing, because the
/// kernel releases the lock with the process that held it. The returned
/// file *is* the guard: its drop — or the proof's end — closes the lock.
fn one_table_at_a_time() -> std::fs::File {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(std::env::temp_dir().join("minimald-classifier-root-proof.lock"))
        .expect("the classifier proofs' lock file");
    // SAFETY: `flock(2)` on the descriptor just opened, in this process
    // only; it blocks until the other proof's process is done with the
    // table, and the kernel releases the lock when this descriptor closes.
    let taken = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    assert_eq!(taken, 0, "locking the classifier proofs against each other");
    file
}

/// The proof's own artifacts, removed on the way out however the proof
/// ended: the backend child first, when one was forked (a live process
/// pins its leaf and the tree under it), then the table (it outlives the
/// cgroups it is keyed on), then the box leaf and the scratch tree with
/// `rmdir`, never a remove-all — on a real cgroup2 these are cgroups, and
/// the kernel's own refusal to remove one that still holds a process is
/// the guard wanted here (the probe's child is reaped and its leaf gone
/// before this runs, so the tree is empty).
struct ScratchInstall {
    /// The scratch tree, named by this proof, never the daemon's slice.
    root: PathBuf,
    /// The box leaf the proof made, when it made one.
    leaf: Option<PathBuf>,
    /// The forked backend, when one was placed.
    child: Option<libc::pid_t>,
}

impl Drop for ScratchInstall {
    fn drop(&mut self) {
        if let Some(pid) = self.child.take() {
            // SAFETY: `kill(2)` addresses the proof's own backend child.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            // SAFETY: `waitpid(2)` reaps it whether or not the kill raced
            // its exit — the child never outlives the proof either way.
            unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        }
        if let Some(leaf) = self.leaf.take() {
            let _ = remove_box_leaf(&leaf);
        }
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", TABLE_NAME])
            .status();
        for dir in [
            self.root.join(classifier::TABLE_MARKER),
            self.root.join(classifier::BOXES_DIR).join(DENY_DIR),
            self.root.join(classifier::BOXES_DIR).join(ALLOW_DIR),
            self.root.join(classifier::BOXES_DIR),
            daemon_leaf(&self.root),
            self.root.clone(),
        ] {
            let _ = std::fs::remove_dir(&dir);
        }
    }
}

/// One raw write of exactly `bytes`, retrying the short writes and
/// interruptions a blocking fd can produce; `false` when the write failed
/// for any other reason. `fd` is an open file — a socketpair end, or the
/// socket a connection was answered on. No allocation, so the backend
/// child may run it between its `fork` and its `_exit`.
fn write_all(fd: libc::c_int, bytes: &[u8]) -> bool {
    let mut done = 0;
    while done < bytes.len() {
        // SAFETY: `write(2)` reads `bytes[done..]`, which outlives the call.
        let n = unsafe { libc::write(fd, bytes[done..].as_ptr().cast(), bytes.len() - done) };
        if n > 0 {
            done += n as usize;
        } else if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        } else {
            return false;
        }
    }
    true
}

/// Appends `text` to `buf` at `at` — no allocation, so the backend child
/// may run it between its `fork` and its `_exit`. `buf` is a fixed array
/// and `at` its fill level.
fn push(buf: &mut [u8], at: &mut usize, text: &[u8]) {
    for &byte in text {
        buf[*at] = byte;
        *at += 1;
    }
}

/// Appends `n` as four zero-padded decimal digits — errno 113 reads
/// `0113` — so the answer's one variable is the errno itself and its body
/// is a fixed nineteen bytes long. No allocation, so the backend child
/// may run it between its `fork` and its `_exit`.
fn push_dec4(buf: &mut [u8], at: &mut usize, n: libc::c_int) {
    for shift in [1000, 100, 10, 1] {
        buf[*at] = b'0' + ((n / shift) % 10) as u8;
        *at += 1;
    }
}

/// The backend child's whole life, raw syscalls only: this runs between a
/// `fork` and its `_exit`, where only async-signal-safe calls belong — the
/// same discipline the probe's own child keeps, because the process that
/// forked it may hold threads the child must not run code against. It
/// waits for the proof's placement ack, binds its loopback listener after
/// the placement (every socket the backend owns is made inside the leaf
/// its process was placed in, the way a box's processes' sockets are),
/// reports the port it bound, answers the hostname proxy's connection,
/// then opens its own connect to the non-answerer loopback port the proof
/// holds open — and serves, in the body of the very response that
/// answered the request, the errno that connect met, zero for one that
/// completed.
///
/// # Safety
///
/// `report` is the child's end of a live socketpair whose other end the
/// parent holds; the function never returns.
unsafe fn backend_child_role(report: libc::c_int, target_port: u16) -> ! {
    // The placement ack, one byte: the parent's word that this process is
    // in its deny leaf. A parent that died first is heard as the end of
    // the channel, and the child ends rather than serve.
    let mut ack = [0u8; 1];
    // SAFETY: `read(2)` writes into `ack` from the socketpair end `report` reads.
    if unsafe { libc::read(report, ack.as_mut_ptr().cast(), 1) } != 1 {
        // SAFETY: the child ends here.
        unsafe { libc::_exit(1) };
    }
    // SAFETY: `socket(2)` makes the one listening descriptor this backend owns.
    let listener =
        unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if listener == -1 {
        // SAFETY: the child ends here.
        unsafe { libc::_exit(2) };
    }
    // SAFETY: `sockaddr_in` is a C struct of integers and padding; zeroed
    // is its init, and every field that matters is set below.
    let mut on: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    on.sin_family = libc::AF_INET as libc::sa_family_t;
    on.sin_port = 0u16.to_be();
    on.sin_addr = libc::in_addr {
        s_addr: u32::from_ne_bytes(Ipv4Addr::LOCALHOST.octets()),
    };
    // SAFETY: `bind(2)` reads the `sockaddr_in` filled in above.
    let bound = unsafe {
        libc::bind(
            listener,
            (&raw const on).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    // SAFETY: `listen(2)` reads the descriptor `bind` was given.
    let heard = unsafe { libc::listen(listener, 8) };
    if bound != 0 || heard != 0 {
        // SAFETY: the listening descriptor, closed on the failing path.
        unsafe { libc::close(listener) };
        // SAFETY: the child ends here.
        unsafe { libc::_exit(3) };
    }
    // The port the kernel handed the listener, back to the proof over the
    // channel: two bytes, the same native order on both sides.
    // SAFETY: `sockaddr_in` zeroed is its init.
    let mut bound: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut bound_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: `getsockname(2)` writes the listener's address into `bound`
    // and its length into `bound_len`.
    if unsafe { libc::getsockname(listener, (&raw mut bound).cast(), &mut bound_len) } != 0 {
        // SAFETY: the listening descriptor, closed on the failing path.
        unsafe { libc::close(listener) };
        // SAFETY: the child ends here.
        unsafe { libc::_exit(4) };
    }
    if !write_all(report, &u16::from_be(bound.sin_port).to_ne_bytes()) {
        // SAFETY: the listening descriptor, closed on the failing path.
        unsafe { libc::close(listener) };
        // SAFETY: the child ends here.
        unsafe { libc::_exit(5) };
    }
    // The proxy's dial: a connection someone else opened to this backend,
    // whose answer leg is the reply direction the loaded table admits.
    // SAFETY: `accept4(2)` hands back the socket the proxy's dial opened.
    let served = unsafe {
        libc::accept4(
            listener,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    if served == -1 {
        // SAFETY: the listening descriptor, closed on the failing path.
        unsafe { libc::close(listener) };
        // SAFETY: the child ends here.
        unsafe { libc::_exit(6) };
    }
    // The request head, read once and dropped: the proxy has sent its
    // whole request by the time the connection is this far.
    let mut head = [0u8; 1024];
    // SAFETY: `read(2)` writes into `head` from the socket `served` reads.
    let _ = unsafe { libc::read(served, head.as_mut_ptr().cast(), head.len()) };
    // The backend's own connect: a flow this box itself originates, to
    // the non-answerer loopback port the proof holds open — the original
    // direction the loaded chain refuses, from the same process whose
    // answer to the proxy it just admitted.
    // SAFETY: `socket(2)` makes the one descriptor this backend connects with.
    let out = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    let mut errno = 0;
    if out == -1 {
        // `Error::last_os_error` is `Error::Os(RawOsError)` around this
        // thread's errno — no allocation, so it belongs to the
        // async-signal-safe set the child may run.
        errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(1);
    } else {
        // SAFETY: `sockaddr_in` zeroed is its init.
        let mut to: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        to.sin_family = libc::AF_INET as libc::sa_family_t;
        to.sin_port = target_port.to_be();
        to.sin_addr = libc::in_addr {
            s_addr: u32::from_ne_bytes(Ipv4Addr::LOCALHOST.octets()),
        };
        // SAFETY: `connect(2)` reads the `sockaddr_in` filled in above.
        if unsafe {
            libc::connect(
                out,
                (&raw const to).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        } != 0
        {
            errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(1);
        }
        // SAFETY: the connecting descriptor, done with either way.
        unsafe { libc::close(out) };
    }
    // The answer, the errno in its body: a `200 OK` over
    // `connect-errno=` and four zero-padded digits, so the proof reads
    // both halves — answered, and answering a chain that still refuses
    // what the box itself opens — off the one proxied response.
    let mut body = [0u8; 19];
    let mut body_len = 0;
    push(&mut body, &mut body_len, b"connect-errno=");
    push_dec4(&mut body, &mut body_len, errno);
    push(&mut body, &mut body_len, b"\n");
    let mut answer = [0u8; 96];
    let mut answer_len = 0;
    push(
        &mut answer,
        &mut answer_len,
        b"HTTP/1.1 200 OK\r\nContent-Length: 19\r\nConnection: close\r\n\r\n",
    );
    push(&mut answer, &mut answer_len, &body);
    let wrote = write_all(served, &answer[..answer_len]);
    // SAFETY: the connected descriptor, done with either way.
    unsafe { libc::close(served) };
    // SAFETY: the listening descriptor, done with either way.
    unsafe { libc::close(listener) };
    if !wrote {
        // SAFETY: the child ends here.
        unsafe { libc::_exit(7) };
    }
    // SAFETY: `_exit(2)` never returns, so the child ends here.
    unsafe { libc::_exit(0) };
}

/// The request through the hostname proxy, driven the way the daemon
/// serves one: the registry that routes the box's name, the proxy's own
/// `serve` loop, and a plain client reading the answer whole. The proxy's
/// dial is this process's own socket — outside the cohort, exactly as the
/// daemon's is — so the one connection that crosses the loaded table is
/// the backend's half of it.
fn request_through_the_hostname_proxy(backend_port: u16) -> String {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("the proof's request runtime");
    runtime.block_on(async {
        let registry =
            std::sync::Arc::new(std::sync::RwLock::new(HostnameRegistry::new("dev", false)));
        registry
            .write()
            .expect("the registry's lock")
            .register_host_net(SessionId::nil(), "denybox");
        let router = Router::new(std::sync::Arc::clone(&registry), proxied_request_verdict);
        let proxy = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("the proxy binds a loopback port");
        let proxy_addr = proxy.local_addr().expect("the proxy's address");
        tokio::spawn(serve(proxy, router));
        tokio::time::timeout(Duration::from_secs(30), async {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let mut client = tokio::net::TcpStream::connect(proxy_addr)
                .await
                .expect("connecting to the proxy");
            let get =
                format!("GET / HTTP/1.1\r\nHost: denybox.min.internal:{backend_port}\r\n\r\n");
            client
                .write_all(get.as_bytes())
                .await
                .expect("sending the request");
            let mut response = String::new();
            client
                .read_to_string(&mut response)
                .await
                .expect("reading the answer");
            response
        })
        .await
        .expect("the request through the hostname proxy did not answer in time")
    })
}

/// The errno the backend's own connect met, read out of the body it served
/// — `connect-errno=` and four zero-padded digits, zero for a connect that
/// completed — so the proof fails with the number it got, not a bare
/// "was refused".
fn backend_connect_errno(response: &str) -> Option<i32> {
    response
        .split("connect-errno=")
        .nth(1)?
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

/// The loaded table's live refusal, read the way a deny-all box's
/// connections meet it: the installer's own `nft -f` transaction laid out
/// over a scratch delegated tree on this host's real cgroup2, and
/// [`read_filter`] reading it — the daemon's own probe, the observed
/// errno per family, `reject with icmpx admin-prohibited` as EHOSTUNREACH
/// over IPv4 loopback and EACCES over IPv6. The stand-in trees in the
/// lib's tests pin the decision's reading of a reading; this one proves a
/// reading itself, over the only artifact that can produce it — and
/// closes with the decision that rests on it, read live over the tree it
/// was proved on.
///
/// `#[ignore]`d so the default suite never runs it; the native lane's
/// `minimald-root-integration` job runs this binary under sudo
/// (`just test-root-integration`), where the preconditions it names are
/// the lane's own to hold, and the one that is not — `nft` — declines
/// with a printed reason. No lane but that one runs it.
#[test]
#[ignore = "loads the installer's own nftables table over this host's real cgroup2; run by the native lane's minimald-root-integration job under sudo (just test-root-integration)"]
fn the_installers_table_refuses_the_probe_over_a_scratch_tree() {
    if !nft_present() {
        eprintln!(
            "skipping the_installers_table_refuses_the_probe_over_a_scratch_tree: \
             no nft on this host — the install's nftables transaction is \
             the artifact under proof (apt install nftables)"
        );
        return;
    }
    // One table at a time: this binary's two proofs each load it.
    let _table = one_table_at_a_time();
    let mountpoint = refuse_unless_the_root_lane_can_run();
    let account = delegate_account().expect(
        "no non-root account to delegate the scratch tree to (the install \
         refuses to delegate to root)",
    );
    // Both loopback families, because the proof reads one errno from
    // each: a host with no IPv6 loopback would read its V4 leg alone, and
    // that is the host's own state, not a failed refusal.
    if let Err(cause) = TcpListener::bind("[::1]:0") {
        panic!(
            "no IPv6 loopback on this host ({cause}), so the V6 leg it \
             reads EACCES from cannot be read"
        );
    }

    // The scratch tree, under the host's own cgroup2 so the loaded rules
    // are keyed on a path this host's probe can enter — named by this
    // proof, never the daemon's slice.
    let scratch = mountpoint.join(format!("minimald-proof-{}", std::process::id()));
    let _install = ScratchInstall {
        root: scratch.clone(),
        leaf: None,
        child: None,
    };
    install_over_scratch(&scratch, &account);

    // The reading: the table's refusal as the probe's legs met it, one
    // errno per family — the two loopbacks the decision's proofs name.
    let reading = read_filter(&scratch);
    let legs = reading.legs();
    assert!(
        matches!(reading, Reading::Refused(_)),
        "the loaded table refuses the probe out of the deny subtree, got: {}",
        reading.record()
    );
    assert_eq!(
        legs.iter().find(|(family, _)| *family == Family::V4),
        Some(&(Family::V4, Observed::Refused(libc::EHOSTUNREACH))),
        "IPv4 loopback reads the rejection as EHOSTUNREACH: {}",
        reading.record()
    );
    assert_eq!(
        legs.iter().find(|(family, _)| *family == Family::V6),
        Some(&(Family::V6, Observed::Refused(libc::EACCES))),
        "IPv6 loopback reads the same rejection as EACCES: {}",
        reading.record()
    );

    // And the decision that rests on it: over the scratch tree the
    // daemon's own facts — its mount table, the step's subtrees and
    // marker, the refusal just read — say this host decides per box.
    let mountinfo = classifier::own_mountinfo();
    let decision = decide_now(&scratch, mountinfo.as_deref(), false);
    assert!(
        decision.can_decide_per_box(),
        "the fresh decision over the installed scratch tree reads per box: {decision:?}"
    );
}

/// NET-079, live over the loaded table: a deny-all host-address box with a
/// loopback listener answers a request through the hostname proxy, while
/// the same box's own outbound connect is refused with EHOSTUNREACH — the
/// live half of the lib's `deny_all_host_ip_box_answers_the_proxy`, whose
/// request runs against no table at all. The backend is a forked child
/// placed in a `boxes/deny` leaf the way a launch places a box, so every
/// socket it owns is made inside the subtree the loaded chain matches;
/// the proxy's dial is the proof process's own, outside the cohort,
/// exactly as it is in the daemon. The request's answer leg — the
/// backend's SYN-ACK and data on a connection someone else opened — is
/// the reply direction the table admits; the backend's own connect is a
/// flow it originates, and the same chain refuses it, EHOSTUNREACH on
/// IPv4 loopback.
///
/// `#[ignore]`d for the lane's sake, and declined like the proof above on
/// a runner with no `nft`; every other precondition it names is the
/// lane's own to hold.
#[test]
#[ignore = "loads the installer's table and runs its backend in a real boxes/deny leaf; run by the native lane's minimald-root-integration job under sudo (just test-root-integration)"]
fn deny_all_host_ip_box_answers_the_proxy_over_a_loaded_table() {
    if !nft_present() {
        eprintln!(
            "skipping deny_all_host_ip_box_answers_the_proxy_over_a_loaded_table: \
             no nft on this host — the install's nftables transaction is \
             the artifact under proof (apt install nftables)"
        );
        return;
    }
    // One table at a time: this binary's two proofs each load it.
    let _table = one_table_at_a_time();
    let mountpoint = refuse_unless_the_root_lane_can_run();
    let account = delegate_account().expect(
        "no non-root account to delegate the scratch tree to (the install \
         refuses to delegate to root)",
    );

    // The scratch tree this proof installs over, and the backend's leaf in
    // the deny subtree — the subtree the deny-all declaration picks, the
    // choice the lib's unit proof pins — made by the same call a launch
    // makes.
    let scratch = mountpoint.join(format!("minimald-proof-proxy-{}", std::process::id()));
    let mut install = ScratchInstall {
        root: scratch.clone(),
        leaf: None,
        child: None,
    };
    install_over_scratch(&scratch, &account);
    let leaf = create_box_leaf(&scratch, "denybox", Verdict::Deny)
        .expect("the step's deny subtree takes a box leaf");
    install.leaf = Some(leaf.clone());

    // A destination the chain refuses: a loopback listener this proof holds
    // open, on a port that is not the answerer's — the one destination
    // the deny chain admits is a UDP carve-out to the answerer, so a TCP
    // connect never meets it, and a held-open listener leaves the filter
    // as the only thing that can fail the backend's connect.
    let refused_here = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("binding the non-answerer loopback port");
    let refused_port = refused_here
        .local_addr()
        .expect("the non-answerer port")
        .port();

    // The backend child: forked before this proof holds any other thread,
    // placed in its leaf before it owns a single socket, and answered
    // through the hostname proxy below. The socketpair is its whole
    // control channel — the placement ack in, the port it serves on out.
    let mut pair = [0 as libc::c_int; 2];
    // SAFETY: `socketpair(2)` writes two descriptors into `pair` and
    // touches nothing else.
    let made = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    };
    assert_eq!(made, 0, "making the backend's control channel");
    // SAFETY: `fork(2)` runs in this process — single-threaded here, the
    // runtime the request runs on is built only after the backend is
    // placed — and the child runs raw syscalls only between the fork and
    // its `_exit`, so no allocator or lock can be held across the fork by
    // the child itself.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "forking the deny-leaf backend");
    if pid == 0 {
        // SAFETY: the parent's end of the pair, closed so the child's
        // channel is its own.
        unsafe { libc::close(pair[0]) };
        // SAFETY: the child never returns; `pair[1]` is its end of the
        // live socketpair, per the function's contract.
        unsafe { backend_child_role(pair[1], refused_port) };
    }
    install.child = Some(pid);
    // SAFETY: the child's end of the pair, closed here so the parent's
    // half of the channel is held by the parent alone.
    unsafe { libc::close(pair[1]) };
    // SAFETY: `pair[0]` is the parent's end of that same live socketpair,
    // handed to the stream that now owns it.
    let mut backend = unsafe { std::os::unix::net::UnixStream::from_raw_fd(pair[0]) };
    backend
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("the backend channel's read deadline");

    // The one migration the placement rests on: the backend enters its
    // deny leaf before it owns a single socket, the way a launched box's
    // processes do.
    place_pid(
        &leaf.join("cgroup.procs"),
        u32::try_from(pid).expect("the forked backend's pid"),
    )
    .expect("placing the backend in its deny leaf");
    backend
        .write_all(b"p")
        .expect("telling the backend it is placed");
    let mut port = [0u8; 2];
    backend
        .read_exact(&mut port)
        .expect("the backend reporting the port it serves on");
    let backend_port = u16::from_ne_bytes(port);

    // The request's leg, live end to end through the proxy the daemon
    // serves, and the backend's own verdict read out of the answer.
    let response = request_through_the_hostname_proxy(backend_port);
    assert!(
        response.contains("200 OK"),
        "a request through the hostname proxy reaches the deny-all box's \
         listener and is answered, got: {response}"
    );
    assert_eq!(
        backend_connect_errno(&response),
        Some(libc::EHOSTUNREACH),
        "the backend's own connect to a non-answerer loopback port is \
         refused with EHOSTUNREACH, got: {response}"
    );
}
