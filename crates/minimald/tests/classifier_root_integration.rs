//! The classifier table's live proofs (NET-079): the loaded `nft` table
//! itself, installed by the privileged step over a scratch delegated tree
//! on this host's real cgroup2, and the effect it has on a box that runs
//! the way a launched box runs — the two halves the ruleset-text proofs in
//! `minimald::net::classifier` cannot vouch for, because a text is pinned
//! before it is loaded, and a request through the proxy is answered before
//! anything refused it.
//!
//! Seven proofs, all `#[ignore]`d so the default suite and the surveyed
//! nextest lines never run them. The native lane's
//! `minimald-root-integration` job runs this binary, and its recipe
//! (`just test-root-integration`) runs it unprivileged — the same posture
//! as that lane's netns harnesses, which sudo their own privileged
//! commands — so the privileged steps here run through `sudo -n` the same
//! way: the install, the step's `--pid` placement of this proof process
//! into the tree, the table's listing and its removal. A binary run as
//! root itself (a developer's `sudo just test-root-integration`) runs
//! each of those directly; the two postures are one flow. Every other
//! precondition — the root those steps need, a cgroup2 mounted with
//! nsdelegate, IPv6 loopback, no existing host install or table —
//! **fails** the proof rather than printing a reason and passing green:
//! a proof that declines over a host that could run it proves nothing
//! while looking like it ran. The one exception is a runner with no
//! `nft`: the packet filter is the step's own dependency, the one thing
//! no lane can promise a host, so each proof declines on it, with the
//! reason printed. Locally: `just test-root-integration`, or
//! `sudo cargo nextest run -p minimald --run-ignored all --no-tests=fail \
//! -E 'binary(/classifier_root_integration$/)'`.
//!
//! Beyond the two NET-079 refusal proofs, one proves NET-080 the same way
//! — that the daemon's own fetch of a package server's object, from its
//! own leaf, completes while the same deny-all box's own connect to the
//! same server is refused, and that the fetch is recorded as the
//! node-plane traffic it is, naming that box
//! (`daemon_fetch_survives_a_live_deny_leaf_over_a_loaded_table`) — and
//! four prove the classification itself, live on the kernel that loads
//! it: that the installer's whole transaction — the classify chain at
//! output's mangle priority, the mark-keyed postrouting — loads where
//! the socket-keyed postrouting it replaces was refused
//! (`classifier_table_loads_on_this_kernel`); that the two source
//! identities are what a peer behind a veth actually sees, one per
//! subtree and loopback untouched (`snat_identity_is_seen_by_the_peer`);
//! that a foreign component's ct-mark bits survive classification, so
//! only the mask's bits move (`foreign_ct_mark_bits_survive_classification`);
//! and that the install refuses over a host already classing with the
//! default bits, naming the rule and the override that escapes it
//! (`install_refuses_an_overlapping_ct_mark_user`). The identity proof
//! drives an eighth `#[ignore]`d test as its observer — the half of
//! itself that runs re-exec'd inside the peer's namespace — which passes
//! on its own, with nothing to observe.
//!
//! None ever touches a host's own install: a tree at
//! [`sandbox::classifier::TREE_ROOT`], or an already-loaded
//! `minimal_class` table, is that host's, and a proof that found one would
//! be a proof run over something it must not replace.
#![cfg(target_os = "linux")]

use std::io::{BufRead as _, Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::io::{AsRawFd as _, FromRawFd as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use minimald::net::classifier::{
    Family, Observed, Reading, decide_now, read_filter, record_node_plane_fetch,
};
use minimald::net::dns::HostnameRegistry;
use minimald::net::proxy::{Router, serve};
use minimald::net::switch::proxied_request_verdict;
use sandbox::classifier::{
    self, DAEMON_LEAF as THE_DAEMON_LEAF, create_box_leaf, daemon_leaf, place_pid, remove_box_leaf,
};
use sandbox::config::{ALLOW_DIR, DENY_DIR, Verdict};
use sessions::SessionId;

/// The loaded table's name, the installer's spelling of it: the daemon
/// reads only its marker, so this is the proof's own name for what it
/// loads and removes.
const TABLE_NAME: &str = "minimal_class";

/// The prefix of the ct-mark mask records an install writes beside the
/// presence marker — the installer's and the daemon's own spelling of the
/// same prefix — so the cleanup below removes whichever bits an install
/// chose, by prefix, never by the value this file pins anywhere else.
const MASK_RECORD_PREFIX: &str = "ct-mark-mask-";

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

/// Whether this binary itself runs as root — a developer's
/// `sudo just test-root-integration`, where every privileged step below
/// runs directly. The lane's own job does not: it is an unprivileged
/// process whose netns harnesses sudo their own commands, so this
/// binary's privileged steps sudo themselves the same way when this is
/// false, through the same seam a person runs the installer by
/// (`sudo scripts/install-host-classifier.sh`).
fn running_as_root() -> bool {
    // SAFETY: `geteuid(2)` has no failure modes or preconditions.
    let euid = unsafe { libc::geteuid() };
    euid == 0
}

/// A command that needs root — the install and the step's `--pid`
/// placement, the table's listing and its removal, the cgroups' removal —
/// run the way this binary got root: directly when the binary itself is
/// root, or through `sudo -n` when it is the lane's unprivileged process.
/// `-n` keeps a proof from sitting on a password prompt: a host that
/// would ask for one fails the precondition loudly instead, with the
/// recipe to run under sudo.
fn privileged(program: &str) -> Command {
    if running_as_root() {
        Command::new(program)
    } else {
        let mut sudo = Command::new("sudo");
        sudo.arg("-n").arg(program);
        sudo
    }
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

/// This process's own account, by uid — the account the scratch tree is
/// delegated to when the proof runs unprivileged, which is the lane's
/// posture: the install went through sudo, so the account that ran it is
/// the one the tree is handed to, and every migration the proof then
/// makes — the probe children's into their throwaway leaf, the backend's
/// into its deny leaf — it makes as that account, the way the daemon it
/// models does. Root itself is never the delegate: the step refuses it,
/// because a tree delegated to root is no delegation at all.
fn own_account() -> Option<String> {
    // SAFETY: `getuid(2)` has no failure modes or preconditions.
    let uid = unsafe { libc::getuid() };
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        let line_uid: u32 = fields.get(2)?.parse().ok()?;
        let name = fields.first()?;
        (line_uid == uid).then(|| name.to_string())
    })
}

/// The account the scratch tree is delegated to: this proof's own when it
/// runs unprivileged — the delegated account is the one whose migrations
/// the proof must be able to make, and unprivileged they are all its own —
/// or, when the whole binary was run as root (a developer's
/// `sudo just test-root-integration`), the first human-range account, the
/// account a development host's daemon runs as.
fn the_delegated_account() -> String {
    if running_as_root() {
        delegate_account().expect(
            "no non-root account to delegate the scratch tree to (the install \
             refuses to delegate to root)",
        )
    } else {
        own_account().expect("this proof's own account, by uid, in /etc/passwd")
    }
}

/// The preconditions the root lane runs under, asserted rather than
/// skipped: this binary's proofs load the installer's own table over this
/// host's real cgroup2, so a host that cannot run one must fail loudly
/// here rather than print a reason and pass green. Root is the reach the
/// install needs, not this binary's own uid — the lane runs its test
/// processes unprivileged and sudoes the privileged commands for them, so
/// either posture passes. Returns the cgroup2 mountpoint the scratch tree
/// goes under; `nft` itself is the caller's to decline on.
fn refuse_unless_the_root_lane_can_run() -> PathBuf {
    assert!(
        running_as_root()
            || privileged("true")
                .status()
                .is_ok_and(|status| status.success()),
        "the install and the placement these proofs run need root: run the \
         lane's recipe under sudo (sudo just test-root-integration), or \
         give this account the passwordless sudo the lane's own harnesses \
         assume"
    );
    assert!(
        !Path::new(classifier::TREE_ROOT).exists(),
        "a classifier tree is already installed at {} — these proofs never \
         run over a host's own install",
        classifier::TREE_ROOT
    );
    assert!(
        !privileged("nft")
            .args(["list", "table", "inet", TABLE_NAME])
            .output()
            .is_ok_and(|out| out.status.success()),
        "a table named {TABLE_NAME} is already loaded — these proofs never \
         replace a host's own table"
    );
    let mountpoint = live_cgroup2_mount().expect(
        "no cgroup2 mounted with nsdelegate on this host — the \
         install's verify_mount would refuse the scratch tree, and \
         a tree on a mount without it confines nothing",
    );
    assert!(
        TcpListener::bind("[::1]:0").is_ok(),
        "no IPv6 loopback on this host, so the table's V6 leg cannot be \
         read — the refusals these proofs read are family-wide, and \
         their errnos are read per family"
    );
    mountpoint
}

/// The proof's install over `root`: the step's own install half, with
/// `--root` naming the scratch tree, delegated to `account`, and the
/// proof's two identities — one `nft -f` transaction that lays out the
/// cohort's two subtrees and loads the table over them. Run through the
/// root-reach above, so the lane's unprivileged process installs the way
/// a person does: through sudo, naming its own account.
fn install_over_scratch(root: &Path, account: &str) {
    let installed = install_over_scratch_with(root, account, &[]);
    assert!(
        installed.status.success(),
        "the install lays out the scratch tree and loads its table: {}{}",
        String::from_utf8_lossy(&installed.stdout),
        String::from_utf8_lossy(&installed.stderr),
    );
}

/// The step's `--pid` half, placing this proof process in the scratch
/// tree's daemon leaf — the one migration the delegated account cannot
/// make itself, because the common ancestor of any cgroup outside the
/// slice and any leaf in it is the root-owned hierarchy root. The proofs
/// migrate inside the tree — the probe's children into their throwaway
/// leaf, the backend into its deny leaf — and v2 checks a migration's
/// permission at the common ancestor of its ends, so a proof running
/// unprivileged has to sit in the tree first, exactly as the daemon it
/// models does. A proof running as root never needed the hop and takes it
/// anyway, so both postures run one flow.
fn place_this_process_in_the_tree(root: &Path) {
    let placed = privileged("bash")
        .arg(installer())
        .arg("--root")
        .arg(root)
        .arg("--pid")
        .arg(std::process::id().to_string())
        .output()
        .expect("running the step's placement half over the scratch tree");
    assert!(
        placed.status.success(),
        "placing this proof process in the scratch tree's daemon leaf: {}{}",
        String::from_utf8_lossy(&placed.stdout),
        String::from_utf8_lossy(&placed.stderr),
    );
}

/// Returns this proof process to the hierarchy root, the cgroup the
/// placement above took it out of: the kernel refuses to remove a cgroup
/// a process still sits in, so the proof leaves the tree before its drop
/// removes the tree — through the same root-reach the placement went in
/// by, because the common ancestor of the tree and anywhere outside it is
/// the one place the delegated account cannot write, which is the barrier
/// the install is.
fn leave_the_tree(mountpoint: &Path) {
    let procs = mountpoint.join("cgroup.procs");
    let pid = format!("{}\n", std::process::id());
    // Best effort, in kind with the drop that calls it: a proof that
    // already failed must not lose its failure to a cleanup panic, and a
    // host that cannot move this process back out is left holding the
    // tree it refused to release — printed, and never a table.
    let left =
        if running_as_root() {
            std::fs::OpenOptions::new()
                .append(true)
                .open(&procs)
                .and_then(|mut file| file.write_all(pid.as_bytes()))
        } else {
            privileged("tee")
                .arg("-a")
                .arg(&procs)
                .stdin(std::process::Stdio::piped())
                .spawn()
                .and_then(|mut reached| {
                    let mut stdin = reached
                        .stdin
                        .take()
                        .ok_or_else(|| std::io::Error::other("the root-reached write's stdin"))?;
                    stdin.write_all(pid.as_bytes())?;
                    drop(stdin);
                    reached.wait()?.success().then_some(()).ok_or_else(|| {
                        std::io::Error::other("the root-reached write out of the tree")
                    })
                })
        };
    if let Err(cause) = left {
        eprintln!(
            "could not return this proof process to the hierarchy root \
             ({cause}); the scratch tree it still holds is left in place"
        );
    }
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
/// cgroups it is keyed on), then this proof process itself — the placement
/// put it in the daemon leaf, and the kernel refuses to remove a cgroup a
/// process still sits in — then the box leaf and the scratch tree with
/// `rmdir`, never a remove-all — on a real cgroup2 these are cgroups, and
/// the kernel's own refusal to remove one that still holds a process is
/// the guard wanted here (the probe's child is reaped and its leaf gone
/// before this runs, so the tree is empty).
struct ScratchInstall {
    /// The scratch tree, named by this proof, never the daemon's slice.
    root: PathBuf,
    /// The cgroup2 mountpoint the scratch tree was laid out under, and the
    /// tree's common ancestor with everywhere outside it — what the proof
    /// writes itself back out through when it leaves.
    mountpoint: PathBuf,
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
        let _ = privileged("nft")
            .args(["delete", "table", "inet", TABLE_NAME])
            .status();
        leave_the_tree(&self.mountpoint);
        // The ct-mark mask records an install writes beside the marker:
        // found by prefix — the overlap proof installs with bits of its own
        // choosing — and removed the way the step's own uninstall removes
        // them, before the tree's own directories go. On a real cgroup2 a
        // record left behind would hold the tree the way a leaf does.
        if let Ok(records) = std::fs::read_dir(&self.root) {
            for record in records.flatten() {
                if record
                    .file_name()
                    .to_string_lossy()
                    .starts_with(MASK_RECORD_PREFIX)
                {
                    let _ = privileged("rmdir").arg(record.path()).status();
                }
            }
        }
        for dir in [
            self.root.join(classifier::TABLE_MARKER),
            self.root.join(classifier::BOXES_DIR).join(DENY_DIR),
            self.root.join(classifier::BOXES_DIR).join(ALLOW_DIR),
            self.root.join(classifier::BOXES_DIR),
            daemon_leaf(&self.root),
            self.root.clone(),
        ] {
            let _ = privileged("rmdir").arg(&dir).status();
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

/// The deny-leaf child's whole life, raw syscalls only: this runs between a
/// `fork` and its `_exit`, where only async-signal-safe calls belong — the
/// same discipline the backend child keeps, because the process that forked
/// it may hold threads the child must not run code against. It waits for the
/// proof's placement ack, then opens its own connect to the package server's
/// loopback port — a flow this leaf itself originates, the original
/// direction the loaded chain refuses — and reports the errno that connect
/// met, zero for one that completed, over the same nineteen-byte
/// `connect-errno=` spelling the backend's answer carries.
///
/// # Safety
///
/// `report` is the child's end of a live socketpair whose other end the
/// parent holds; the function never returns.
unsafe fn deny_leaf_connect_role(report: libc::c_int, server_port: u16) -> ! {
    // The placement ack, one byte: the parent's word that this process is
    // in its deny leaf. A parent that died first is heard as the end of the
    // channel, and the child ends rather than report a connect made out of
    // no leaf at all.
    let mut ack = [0u8; 1];
    // SAFETY: `read(2)` writes into `ack` from the socketpair end `report` reads.
    if unsafe { libc::read(report, ack.as_mut_ptr().cast(), 1) } != 1 {
        // SAFETY: the child ends here.
        unsafe { libc::_exit(1) };
    }
    // The box's own connect: a flow this leaf originates, to the package
    // server's loopback port — the original direction the loaded chain
    // refuses, from the leaf a launched deny-all box's processes run in.
    // SAFETY: `socket(2)` makes the one descriptor this child connects with.
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
        to.sin_port = server_port.to_be();
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
    // The report, the errno the connect met: `connect-errno=` and four
    // zero-padded digits, the same spelling the backend's answer carries,
    // so the proof reads both legs off one format. The three pushes fill
    // the nineteen bytes exactly, so the whole array is the report.
    let mut answer = [0u8; 19];
    let mut answer_len = 0;
    push(&mut answer, &mut answer_len, b"connect-errno=");
    push_dec4(&mut answer, &mut answer_len, errno);
    push(&mut answer, &mut answer_len, b"\n");
    let wrote = write_all(report, &answer);
    if !wrote {
        // SAFETY: the child ends here.
        unsafe { libc::_exit(2) };
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
/// `minimald-root-integration` job runs this binary (`just
/// test-root-integration`), where the preconditions it names are the
/// lane's own to hold, and the one that is not — `nft` — declines with a
/// printed reason. No lane but that one runs it.
#[test]
#[ignore = "loads the installer's own nftables table over this host's real cgroup2; run by the native lane's minimald-root-integration job (just test-root-integration)"]
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
    let account = the_delegated_account();

    // The scratch tree, under the host's own cgroup2 so the loaded rules
    // are keyed on a path this host's probe can enter — named by this
    // proof, never the daemon's slice.
    let scratch = mountpoint.join(format!("minimald-proof-{}", std::process::id()));
    let _install = ScratchInstall {
        root: scratch.clone(),
        mountpoint: mountpoint.clone(),
        leaf: None,
        child: None,
    };
    install_over_scratch(&scratch, &account);
    // In the tree before anything migrates inside it: the probe's children
    // self-place in its throwaway deny leaf, and a migration's permission
    // is checked at the common ancestor of its ends.
    place_this_process_in_the_tree(&scratch);

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
/// lane's own to hold — the lane runs the binary unprivileged, its
/// privileged steps going through sudo for it.
#[test]
#[ignore = "loads the installer's table and runs its backend in a real boxes/deny leaf; run by the native lane's minimald-root-integration job (just test-root-integration)"]
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
    let account = the_delegated_account();

    // The scratch tree this proof installs over, and the backend's leaf in
    // the deny subtree — the subtree the deny-all declaration picks, the
    // choice the lib's unit proof pins — made by the same call a launch
    // makes.
    let scratch = mountpoint.join(format!("minimald-proof-proxy-{}", std::process::id()));
    let mut install = ScratchInstall {
        root: scratch.clone(),
        mountpoint: mountpoint.clone(),
        leaf: None,
        child: None,
    };
    install_over_scratch(&scratch, &account);
    // In the tree before the backend is forked in it: the backend is born
    // in this process's cgroup, and a migration's permission is checked
    // at the common ancestor of its ends — inside the slice that is the
    // delegated slice itself, outside it the root-owned hierarchy root.
    place_this_process_in_the_tree(&scratch);
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

/// The proof's capture of what a bundle's daemon-log tail reads: a writer
/// tracing's formatter can be pointed at, so the record a proof asserts on
/// is read off the subscriber it installs rather than off this process's
/// stderr — the way the tail reads it, a line at a time, with nothing else
/// the proof's own process prints able to make one.
#[derive(Clone, Default)]
struct LogCapture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl LogCapture {
    fn contents(&self) -> String {
        String::from_utf8(self.0.lock().expect("the record capture's lock").clone())
            .expect("the record capture holds what the formatter wrote, which is utf-8")
    }
}

impl std::io::Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // The one failure the capture knows: a lock poisoned by a panic
        // inside the proof itself, handed back as the write error it is
        // rather than ended on.
        let mut captured = self
            .0
            .lock()
            .map_err(|poisoned| std::io::Error::other(poisoned.to_string()))?;
        captured.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl tracing_subscriber::fmt::MakeWriter<'_> for LogCapture {
    type Writer = LogCapture;
    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

/// NET-080, live over the loaded table: the deny-all box's own connect to
/// a package server on this host is refused with EHOSTUNREACH while the
/// daemon's own fetch of the same server's one object, from its own leaf,
/// completes with the object's own bytes — and is recorded as the
/// node-plane traffic it is, naming that box. The box's half is a forked
/// child placed in a real `boxes/deny` leaf the way a launch places a box,
/// so its connect meets the same chain a resident deny-all box's does;
/// the package server is a loopback listener this proof holds, standing
/// in for the cache a daemon's packages come from, and the daemon's half
/// is this proof process in the daemon leaf the placement above put it in
/// — the sibling-of-the-cohort leaf the refusing chain's match cannot
/// reach, which is why the one loaded table refuses one leg and not the
/// other. The record is read through a tracing subscriber the proof
/// installs, the way a bundle's tail reads it: one line, at the level the
/// tail reads, naming the host fetched with the port it left for, the
/// leaf the fetch left from, the box it was made for, and the object.
///
/// `#[ignore]`d for the lane's sake, and declined like the proofs above
/// on a runner with no `nft`; every other precondition it names is the
/// lane's own to hold.
#[test]
#[ignore = "loads the installer's table and runs a real boxes/deny leaf's own connect against a local package server while the daemon's own fetch completes; run by the native lane's minimald-root-integration job (just test-root-integration)"]
fn daemon_fetch_survives_a_live_deny_leaf_over_a_loaded_table() {
    if !nft_present() {
        eprintln!(
            "skipping daemon_fetch_survives_a_live_deny_leaf_over_a_loaded_table: \
             no nft on this host — the install's nftables transaction is \
             the artifact under proof (apt install nftables)"
        );
        return;
    }
    // One table at a time: this binary's proofs each load it.
    let _table = one_table_at_a_time();
    let mountpoint = refuse_unless_the_root_lane_can_run();
    let account = the_delegated_account();

    // The scratch tree this proof installs over, and the deny-all box's
    // leaf in the deny subtree — made by the same call a launch makes, so
    // the leaf is a real leaf of the loaded table's refusing chain and not
    // a stand-in.
    let scratch = mountpoint.join(format!("minimald-proof-fetch-{}", std::process::id()));
    let mut install = ScratchInstall {
        root: scratch.clone(),
        mountpoint: mountpoint.clone(),
        leaf: None,
        child: None,
    };
    install_over_scratch(&scratch, &account);
    // In the tree before the box child is forked in it: the child is born
    // in this process's cgroup — the daemon leaf the placement puts this
    // proof process in, the leaf the daemon's own half below leaves from —
    // and a migration's permission is checked at the common ancestor of
    // its ends.
    place_this_process_in_the_tree(&scratch);
    let leaf = create_box_leaf(&scratch, "fetchbox", Verdict::Deny)
        .expect("the step's deny subtree takes a box leaf");
    install.leaf = Some(leaf.clone());

    // The package server: one loopback listener this proof holds, standing
    // in for the cache a daemon's packages come from — the one destination
    // both legs below reach for, so the only thing that can differ between
    // them is the leaf each left from.
    const PACKAGE_OBJECT: &str = "jq-1.8.0";
    let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("binding the package server's loopback port");
    let server_addr = server.local_addr().expect("the package server's address");
    let server_port = server_addr.port();

    // The box's half: a forked child, placed in its deny leaf before it
    // owns a single socket, opening its own connect to the package server.
    // The socketpair is its whole control channel — the placement ack in,
    // the errno its connect met out.
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
    assert_eq!(made, 0, "making the box child's control channel");
    // SAFETY: `fork(2)` runs in this process — single-threaded here, the
    // whole proof drives blocking sockets — and the child runs raw
    // syscalls only between the fork and its `_exit`, so no allocator or
    // lock can be held across the fork by the child itself.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "forking the deny-leaf box child");
    if pid == 0 {
        // SAFETY: the parent's end of the pair, closed so the child's
        // channel is its own.
        unsafe { libc::close(pair[0]) };
        // SAFETY: the child never returns; `pair[1]` is its end of the
        // live socketpair, per the function's contract.
        unsafe { deny_leaf_connect_role(pair[1], server_port) };
    }
    install.child = Some(pid);
    // SAFETY: the child's end of the pair, closed here so the parent's
    // half of the channel is held by the parent alone.
    unsafe { libc::close(pair[1]) };
    // SAFETY: `pair[0]` is the parent's end of that same live socketpair,
    // handed to the stream that now owns it.
    let mut box_leg = unsafe { std::os::unix::net::UnixStream::from_raw_fd(pair[0]) };
    box_leg
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("the box child channel's read deadline");

    // The one migration the box's half rests on: the child enters its deny
    // leaf before it owns a single socket, the way a launched box's
    // processes do.
    place_pid(
        &leaf.join("cgroup.procs"),
        u32::try_from(pid).expect("the forked box child's pid"),
    )
    .expect("placing the box child in its deny leaf");
    box_leg
        .write_all(b"p")
        .expect("telling the box child it is placed");
    let mut report = [0u8; 19];
    box_leg
        .read_exact(&mut report)
        .expect("the box child reporting the errno its connect met");
    let refused = backend_connect_errno(&String::from_utf8_lossy(&report))
        .unwrap_or_else(|| panic!("the box child reported its connect's errno: {report:?}"));
    assert_eq!(
        refused,
        libc::EHOSTUNREACH,
        "the deny-all box's own connect to the package server is refused \
         with EHOSTUNREACH over IPv4 loopback, the loaded chain's own \
         rejection"
    );

    // The daemon's half: this proof process, in the daemon leaf the
    // placement put it in, fetching the same server's one object — the leg
    // the requirement is about, completing beside a box whose own connect
    // the same loaded table just refused.
    let mut fetched = TcpStream::connect(server_addr).expect(
        "the daemon's own fetch connects from its own leaf, beside the \
         cohort: the loaded chain's refusing match takes the deny subtree \
         alone",
    );
    fetched
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("the fetch leg's read deadline");
    let get = format!(
        "GET /{PACKAGE_OBJECT} HTTP/1.1\r\nHost: cache.min.internal\r\nConnection: close\r\n\r\n"
    );
    fetched
        .write_all(get.as_bytes())
        .expect("sending the fetch's request");
    let (mut served, _) = server
        .accept()
        .expect("the package server answers the daemon's fetch");
    let mut head = [0u8; 1024];
    let read = served.read(&mut head).expect("reading the fetch's request");
    let head = String::from_utf8_lossy(&head[..read]);
    assert!(
        head.starts_with(&format!("GET /{PACKAGE_OBJECT} ")),
        "the package server serves the object the fetch asked for, got: {head}"
    );
    let answer = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        PACKAGE_OBJECT.len(),
    );
    served
        .write_all(answer.as_bytes())
        .expect("the package server answers the fetch");
    served
        .write_all(PACKAGE_OBJECT.as_bytes())
        .expect("the package server serves the object");
    drop(served);
    let mut body = Vec::new();
    fetched
        .read_to_end(&mut body)
        .expect("reading the fetched object whole");
    assert!(
        body.starts_with(b"HTTP/1.1 200 OK"),
        "the daemon's own fetch is answered, got: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(
        &body[body.len() - PACKAGE_OBJECT.len()..],
        PACKAGE_OBJECT.as_bytes(),
        "the daemon's own fetch completes with the object's own bytes"
    );

    // The record: the fetch above is the one the daemon makes for the box,
    // and this is how a person reads that it was node-plane traffic —
    // captured through a tracing subscriber this proof installs, the way a
    // bundle's daemon-log tail reads the line, never off this process's
    // stderr. The leaf the line names is read live, over this real cgroup2,
    // from the placement the step's `--pid` half made of this process before
    // the box child was forked — the record's leaf claim is a fact the tree
    // states, not a constant it asserts on hosts that carry no tree. One
    // line, at the level the tail reads, naming the host fetched with the
    // port it left for, the leaf the fetch left from, the box it was made
    // for, and the object.
    let box_id = leaf
        .file_name()
        .and_then(|name| name.to_str())
        .expect("the box's leaf is named with its id")
        .to_owned();
    let fetched_from = minimald::net::classifier::daemon_fetch_leaf(&scratch);
    assert_eq!(
        fetched_from,
        Some(THE_DAEMON_LEAF),
        "the proof process the step placed in the scratch tree's daemon leaf \
         reads back as in it, over this host's real cgroup2"
    );
    let log = LogCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(log.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    record_node_plane_fetch(
        &box_id,
        fetched_from,
        &server_addr.to_string(),
        PACKAGE_OBJECT,
    );
    let recorded = log.contents();
    let lines: Vec<&str> = recorded
        .lines()
        .filter(|line| line.contains("node-plane traffic"))
        .collect();
    assert_eq!(
        lines.len(),
        1,
        "the daemon's own fetch is recorded once, as node-plane traffic: {recorded}"
    );
    let line = lines[0];
    assert!(
        line.contains("INFO"),
        "the record is at the level a bundle's tail reads: {line}"
    );
    assert!(
        line.contains(&server_addr.to_string()),
        "the record names the host fetched, the port it left for beside it: {line}"
    );
    assert!(
        line.contains(THE_DAEMON_LEAF),
        "the record names the leaf the fetch left from: {line}"
    );
    assert!(
        line.contains(&box_id),
        "the record names the box the fetch was made for: {line}"
    );
    assert!(
        line.contains(PACKAGE_OBJECT),
        "the record names the object fetched: {line}"
    );
}

// ── The classification's own proofs ─────────────────────────────────────────
//
// The three proofs above read the table's refusal; the four below read its
// classification — the ct-mark bits the classify chain writes, the
// identities the postrouting chain translates to, and the bits of the
// connection mark the step shares with nobody.

/// One privileged `nft` invocation, with its whole output handed back: the
/// proofs below read listings and load small fixture tables of their own,
/// so a refusal must stay readable in the assert that reports it.
fn nft(args: &[&str]) -> std::process::Output {
    privileged("nft")
        .args(args)
        .output()
        .expect("running nft for the proof")
}

/// One privileged `ip` invocation, asserted: every link, address and route
/// below is a fact a proof rests on, and one that failed to appear must
/// fail the proof rather than leave it reading a half-built host.
fn ip(args: &[&str]) {
    let ran = privileged("ip")
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("running ip {}: {e}", args.join(" ")));
    assert!(
        ran.status.success(),
        "ip {}: {}{}",
        args.join(" "),
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr),
    );
}

/// The same, inside the namespace the proof holds for its peer: `nsenter
/// -t <pid> -n` addressing the holder's pid is the same move-then-reach
/// shape the production launcher drives a tap's namespace with.
fn nsenter_ip(pid: u32, args: &[&str]) {
    let reached = privileged("nsenter")
        .arg("-t")
        .arg(pid.to_string())
        .arg("-n")
        .arg("ip")
        .args(args)
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "reaching the peer's namespace with ip {}: {e}",
                args.join(" ")
            )
        });
    assert!(
        reached.status.success(),
        "ip {} inside the peer's namespace: {}{}",
        args.join(" "),
        String::from_utf8_lossy(&reached.stdout),
        String::from_utf8_lossy(&reached.stderr),
    );
}

/// Loads `rules` — a small nftables program one of the proofs below owns —
/// as one `nft -f` transaction named `table`: a fixture never shares a
/// name with the step's own table or another proof's, and the one
/// transaction means a fixture that dies leaves none of itself behind.
fn load_fixture_table(table: &str, rules: &str) {
    let file = std::env::temp_dir().join(format!("{table}.nft"));
    std::fs::write(&file, rules)
        .unwrap_or_else(|e| panic!("writing the proof's fixture table: {e}"));
    let loaded = nft(&["-f", &file.to_string_lossy()]);
    let _ = std::fs::remove_file(&file);
    assert!(
        loaded.status.success(),
        "loading the proof's fixture table {table}: {}{}",
        String::from_utf8_lossy(&loaded.stdout),
        String::from_utf8_lossy(&loaded.stderr),
    );
}

/// A fixture table a proof loaded, removed on the way out however the
/// proof ended: a fixture left loaded is a ct-mark user on this host, and
/// the next proof's install refuses those — by the same scan the overlap
/// proof below puts under proof.
struct FixtureTable(String);

impl Drop for FixtureTable {
    fn drop(&mut self) {
        let _ = nft(&["delete", "table", "inet", &self.0]);
    }
}

/// The lines of `text` that carry `needle`: a listing is the kernel's own
/// spelling of a rule, not the text the installer rendered, so a proof
/// pins the tokens that spelling keeps — quoted paths, values, verdicts —
/// and never the operator style a version of `nft` might print
/// differently.
fn lines_with<'a>(text: &'a str, needle: &str) -> Vec<&'a str> {
    text.lines().filter(|line| line.contains(needle)).collect()
}

/// Moves this proof process into the cgroup whose `cgroup.procs` is named
/// — a migration inside the slice the placement above already entered, so
/// the delegated account may make it, exactly as the backend proof's
/// child's placement was made for it — because the cgroup a socket-cgroup
/// match reads is fixed at the socket's creation, and every leg below
/// creates its socket only after the move, the way a launched box's
/// processes do.
fn migrate_self(procs: &Path) {
    place_pid(procs, std::process::id())
        .unwrap_or_else(|e| panic!("migrating this proof process into {}: {e}", procs.display()));
}

/// The install the proofs run, with the arguments a proof may add — the
/// escape hatch the conflict refusal names — run the same way through the
/// root-reach, output handed back whole and asserted by the caller: the
/// overlap proof below needs the refusal itself, not a panic on it.
fn install_over_scratch_with(root: &Path, account: &str, extra: &[&str]) -> std::process::Output {
    let mut step = privileged("bash");
    step.arg(installer())
        .arg("--root")
        .arg(root)
        .arg("--user")
        .arg(account)
        .arg("--cohort-address")
        .arg(COHORT_ADDRESS)
        .arg("--node-plane-address")
        .arg(NODE_PLANE_ADDRESS);
    if !extra.is_empty() {
        step.args(extra);
    }
    step.output()
        .expect("running the privileged step over the scratch tree")
}

/// That the installer's whole transaction loads on this kernel: the
/// classify chain at output's mangle priority and the postrouting chain
/// that translates by the mark it set are one `nft -f`, so the identities
/// never exist without their classification — and the socket-cgroup
/// matches at postrouting this table replaces were rules the kernel
/// refuses outright, which is the failure this proof exists to catch
/// before any lane ships that shape again. What it reads back is the table
/// as the kernel holds it, listed, not the text the installer rendered —
/// and the mask is read back beside the marker, the way the daemon's probe
/// reads it.
///
/// `#[ignore]`d like the proofs above: the lane's own job runs this
/// binary (`just test-root-integration`), and a runner with no `nft` is
/// the one decline this binary knows.
#[test]
#[ignore = "loads the installer's own nftables table over this host's real cgroup2; run by the native lane's minimald-root-integration job (just test-root-integration)"]
fn classifier_table_loads_on_this_kernel() {
    if !nft_present() {
        eprintln!(
            "skipping classifier_table_loads_on_this_kernel: no nft on this \
             host — the install's nftables transaction is the artifact under \
             proof (apt install nftables)"
        );
        return;
    }
    // One table at a time: this binary's proofs each load it.
    let _table = one_table_at_a_time();
    let mountpoint = refuse_unless_the_root_lane_can_run();
    let account = the_delegated_account();
    let scratch = mountpoint.join(format!("minimald-proof-load-{}", std::process::id()));
    let _install = ScratchInstall {
        root: scratch.clone(),
        mountpoint: mountpoint.clone(),
        leaf: None,
        child: None,
    };
    // The install is itself half the proof: `nft -f` applies a batch whole
    // or not at all, so a kernel that refused the socket match at output's
    // mangle priority — or the mark-keyed translation — failed here, before
    // anything was listed back.
    install_over_scratch(&scratch, &account);
    place_this_process_in_the_tree(&scratch);

    // The transaction this kernel accepted, listed back whole.
    let listed = nft(&["list", "table", "inet", TABLE_NAME]);
    assert!(
        listed.status.success(),
        "listing the table the install just loaded: {}{}",
        String::from_utf8_lossy(&listed.stdout),
        String::from_utf8_lossy(&listed.stderr),
    );
    let table = String::from_utf8_lossy(&listed.stdout).into_owned();
    let rel = scratch
        .file_name()
        .and_then(|name| name.to_str())
        .expect("the scratch tree's name under the mountpoint");

    // The classification, at output's mangle priority — the last place the
    // kernel admits a socket-cgroup match, which is where the round that
    // put the same match at postrouting lost its table: only a new
    // connection is classed, the boxes subtree takes the cohort bit, the
    // rest of the slice the node bit behind a mask guard so the boxes
    // rule's mark is final, and every set writes the mask's two bits alone
    // (the clear mask beside the bit each rule sets). nft lists the set
    // folded: `and 0xcfffffff or BIT` comes back as
    // `& (0xcfffffff | BIT) | BIT` — `& 0xdfffffff | 0x10000000` for the
    // cohort bit, `& 0xefffffff | 0x20000000` for the node bit — which
    // clears and sets exactly the same bits, so that is the spelling pinned.
    let classify = table
        .split("chain classify {")
        .nth(1)
        .unwrap_or_else(|| panic!("no classify chain in the loaded table: {table}"));
    let classify = classify
        .lines()
        .take_while(|line| !line.trim_start().starts_with('}'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        classify.contains("hook output priority mangle")
            || classify.contains("hook output priority -150"),
        "the classify chain runs at output's mangle priority, the last \
         place the kernel admits a socket-cgroup match: {classify}"
    );
    let boxes_rule = lines_with(&classify, &format!("\"{rel}/boxes\""));
    assert_eq!(
        boxes_rule.len(),
        1,
        "exactly one rule of the classify chain keys on the boxes subtree: {classify}"
    );
    assert!(
        boxes_rule[0].contains("ct state new")
            && boxes_rule[0].contains("socket cgroupv2 level 2")
            && boxes_rule[0].contains("& 0xdfffffff | 0x10000000"),
        "the boxes subtree's rule classes a new connection with the cohort \
         bit, writing the mask's two bits and no others: {classify}"
    );
    let slice_rule = lines_with(&classify, &format!("\"{rel}\""));
    assert_eq!(
        slice_rule.len(),
        1,
        "exactly one rule of the classify chain keys on the slice itself: {classify}"
    );
    assert!(
        slice_rule[0].contains("ct state new")
            && slice_rule[0].contains("socket cgroupv2 level 1")
            && slice_rule[0].contains("0x30000000")
            && slice_rule[0].contains("& 0xefffffff | 0x20000000"),
        "the slice's own rule classes a new connection that no mark claims \
         yet with the node bit, the mask's own guard keeping a flow the \
         boxes rule already decided final: {classify}"
    );

    // The translation at postrouting, by the mark and never a socket — the
    // two rules this kernel refused in the shape this table replaces, one
    // per identity, loopback excluded.
    let postrouting = table
        .split("chain postrouting {")
        .nth(1)
        .unwrap_or_else(|| panic!("no postrouting chain in the loaded table: {table}"));
    let postrouting = postrouting
        .lines()
        .take_while(|line| !line.trim_start().starts_with('}'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !postrouting.contains("socket"),
        "the postrouting chain translates by the mark alone — a socket-cgroup \
         match there is a rule this kernel has never admitted: {postrouting}"
    );
    let cohort_rule = lines_with(&postrouting, &format!("snat ip to {COHORT_ADDRESS}"));
    assert_eq!(
        cohort_rule.len(),
        1,
        "exactly one postrouting rule translates to the cohort's identity: {postrouting}"
    );
    assert!(
        cohort_rule[0].contains("0x10000000")
            && cohort_rule[0].contains("oifname")
            && cohort_rule[0].contains("\"lo\""),
        "the cohort's bit translates to the cohort's identity, loopback \
         excluded by the rule's own guard: {postrouting}"
    );
    let node_rule = lines_with(&postrouting, &format!("snat ip to {NODE_PLANE_ADDRESS}"));
    assert_eq!(
        node_rule.len(),
        1,
        "exactly one postrouting rule translates to the node plane's identity: {postrouting}"
    );
    assert!(
        node_rule[0].contains("0x20000000")
            && node_rule[0].contains("oifname")
            && node_rule[0].contains("\"lo\""),
        "the node plane's bit translates to the node plane's identity: {postrouting}"
    );

    // The mask, recorded beside the marker the way the daemon's probe reads
    // it: the step's own two bits, in the one record that names them.
    assert!(
        scratch.join("ct-mark-mask-0x30000000").is_dir(),
        "the install records the mask it classifies with beside the marker, \
         so the step and the daemon read one value: {}",
        scratch.display()
    );
}

/// The host-side end of the veth pair the identity proof speaks over, and
/// the peer's address behind the other end: a /24 out of TEST-NET-1,
/// addresses reserved for exactly this — no host routes them, so the
/// proof never collides with a host's own addressing, and a connection
/// that leaves through the pair really leaves the host.
const HOST_VETH: &str = "mclass-host";
const PEER_VETH: &str = "mclass-peer";
const PEER_ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const HOST_VETH_ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

/// A process this proof drove — the namespace holder below, or the peer's
/// observer — killed on the way out however the proof ended, and by the
/// pid the process itself reported, never the sudo wrapper's: the wrapper
/// only waits on the command it was given, so killing it would orphan a
/// holder that keeps a namespace — and the scratch tree's own daemon leaf,
/// which a driven process is born in — alive after the proof is gone.
/// Waited too, so the wrapper, which exits once its command does, never
/// outlives the proof either.
struct Driven {
    /// The driven process's own pid, as it reported: `$$` for a holder, the
    /// report's first line for an observer.
    pid: u32,
    /// The wrapper this proof spawned — sudo when the proof runs
    /// unprivileged — reaped here.
    wrapper: std::process::Child,
}

impl Driven {
    /// The driven process's own exit, once the proof is done driving it:
    /// the wrapper exits with the driven process's status, so this is the
    /// observer's own verdict about the legs it watched.
    fn finished(&mut self) -> std::process::ExitStatus {
        self.wrapper
            .wait()
            .expect("the driven process's wrapper exiting")
    }
}

impl Drop for Driven {
    fn drop(&mut self) {
        // A wrapper that already exited means its command did too: no kill,
        // so a reused pid is never signalled.
        if self.wrapper.try_wait().is_ok_and(|state| state.is_some()) {
            return;
        }
        let _ = privileged("kill").arg(self.pid.to_string()).status();
        let _ = self.wrapper.wait();
    }
}

/// A process holding a fresh network namespace, spawned the way the netns
/// harnesses spawn theirs — `unshare --net` around a `bash` that prints
/// its own pid and then `exec`s a lingering `sleep` — so the namespace is
/// identified by the holder's pid, exactly the `/proc/<pid>/ns/net` the
/// production launcher targets a sandbox's by. `echo $$` before the `exec`
/// is the holder's own pid: `exec` keeps the process, so the pid that
/// printed is the pid that holds.
fn spawn_netns_holder() -> Driven {
    let mut wrapper = privileged("unshare")
        .args(["--net", "bash", "-c", "echo $$; exec sleep 600"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawning the peer's network namespace holder");
    let stdout = wrapper.stdout.as_mut().expect("the holder's stdout");
    let mut line = String::new();
    std::io::BufReader::new(stdout)
        .read_line(&mut line)
        .expect("reading the holder's pid");
    let pid: u32 = line
        .trim()
        .parse()
        .expect("the holder's pid, as it printed");
    Driven { pid, wrapper }
}

/// Deletes the proof's veth pair on the way out: deleting the host's end
/// deletes the pair, wherever the other end lives — the peer's end dies
/// with the namespace the holder gave it.
struct Veth(&'static str);

impl Drop for Veth {
    fn drop(&mut self) {
        let _ = privileged("ip").args(["link", "del", self.0]).status();
    }
}

/// Appends one line to the driven observer's report: the observer is a
/// process of its own, and its report is a file both ends reach without
/// sharing a descriptor, a channel, or a timeout policy — each line lands
/// the moment it is written, and the proof reads the file, bounded, below.
fn append_report(report: &Path, line: &str) {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(report)
        .unwrap_or_else(|e| panic!("opening the peer's report to append: {e}"));
    writeln!(file, "{line}").unwrap_or_else(|e| panic!("appending to the peer's report: {e}"));
}

/// Waits, bounded, for the driven observer's report to reach `lines` lines
/// and returns it: the observer is its namespace's only writer and appends
/// one line per event, so a report that never arrives is a failure that
/// names what did arrive — never a blocking read, which is how an
/// observer that died would hang the proof instead of failing it.
fn observer_report(report: &Path, lines: usize) -> Vec<String> {
    let mut waited = Duration::ZERO;
    let mut seen = String::new();
    loop {
        if let Ok(text) = std::fs::read_to_string(report) {
            seen = text;
            let observed: Vec<String> = seen.lines().map(str::to_owned).collect();
            if observed.len() >= lines {
                return observed;
            }
            if let Some(failure) = observed.iter().find(|line| line.starts_with("error")) {
                panic!("the peer's observer reported its own failure: {failure}");
            }
        }
        if waited >= Duration::from_secs(30) {
            panic!(
                "the peer's observer never reported {lines} lines within 30s: {}",
                seen.trim()
            );
        }
        std::thread::sleep(Duration::from_millis(100));
        waited += Duration::from_millis(100);
    }
}

/// The observer half of the identity proof below: it runs re-exec'd inside
/// the namespace that proof builds, binds the peer's address, and reports
/// — one line per accepted connection, to the report file the proof
/// reads — the source address each connection arrived with, which is the
/// one view of a source translation that cannot lie about it.
/// `MINIMALD_PROOF_OBSERVER` names that file, and is how the observer
/// knows it was driven: the lane runs this binary with `--run-ignored
/// all`, so a standalone run of this test has nothing to observe and
/// passes, and only the proof that spawned it sets the variable — as an
/// argument to `env`, because the sudo it went through would strip an
/// inherited variable from the environment.
#[test]
#[ignore = "the observer half of snat_identity_is_seen_by_the_peer; it runs re-exec'd inside that proof's network namespace"]
fn snat_peer_observes_the_source() {
    let Some(report) = std::env::var_os("MINIMALD_PROOF_OBSERVER").map(PathBuf::from) else {
        eprintln!(
            "declining snat_peer_observes_the_source: it is the observer half \
             of snat_identity_is_seen_by_the_peer and runs only where that \
             proof drives it"
        );
        return;
    };
    append_report(&report, &format!("pid {}", std::process::id()));
    let listener = match TcpListener::bind((PEER_ADDRESS, 0)) {
        Ok(listener) => listener,
        Err(cause) => {
            append_report(&report, &format!("error binding {PEER_ADDRESS}: {cause}"));
            return;
        }
    };
    let port = listener
        .local_addr()
        .expect("the peer's listening address")
        .port();
    append_report(&report, &format!("ready {port}"));
    // One line per leg the proof drives, then done: three legs — the
    // cohort's, the node plane's, and a process in neither subtree.
    for _ in 0..3 {
        let (connection, peer) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(cause) => {
                append_report(&report, &format!("error accepting a leg: {cause}"));
                return;
            }
        };
        append_report(&report, &format!("peer {}", peer.ip()));
        drop(connection);
    }
}

/// NET-078's two identities, read where only the far end can read them:
/// over a veth pair, with a listener behind it in a network namespace of
/// its own, so a connection the proof drives really leaves the host —
/// loopback can never show this, because a packet to the host's own
/// address egresses `lo`, which the postrouting rules' guard skips. The
/// proof process is placed in the scratch tree the install above it laid
/// out, and each leg migrates itself into the cgroup it is classed by
/// before creating its socket, the way a launched box's processes are
/// placed before they own one: a box's leaf reports the cohort's address,
/// the daemon's leaf the node plane's, a process in neither keeps the
/// host's own source unchanged, and loopback is never translated.
///
/// `#[ignore]`d like the proofs above, declined the same way on a runner
/// with no `nft`; every other precondition it names fails it loudly.
#[test]
#[ignore = "loads the installer's table and drives real connections through it to a peer behind a veth; run by the native lane's minimald-root-integration job (just test-root-integration)"]
fn snat_identity_is_seen_by_the_peer() {
    if !nft_present() {
        eprintln!(
            "skipping snat_identity_is_seen_by_the_peer: no nft on this \
             host — the install's nftables transaction is the artifact \
             under proof (apt install nftables)"
        );
        return;
    }
    // One table at a time: this binary's proofs each load it.
    let _table = one_table_at_a_time();
    let mountpoint = refuse_unless_the_root_lane_can_run();
    let account = the_delegated_account();
    let scratch = mountpoint.join(format!("minimald-proof-snat-{}", std::process::id()));
    let mut install = ScratchInstall {
        root: scratch.clone(),
        mountpoint: mountpoint.clone(),
        leaf: None,
        child: None,
    };
    install_over_scratch(&scratch, &account);
    place_this_process_in_the_tree(&scratch);
    // An allow leaf: a deny-all box's own egress is refused before it
    // reaches postrouting, so the leg that must be translated as the
    // cohort runs from a box that admits destinations.
    let leaf = create_box_leaf(&scratch, "snatbox", Verdict::Allow)
        .expect("the step's allow subtree takes a box leaf");
    install.leaf = Some(leaf.clone());

    // The veth pair, and the namespace behind its peer end. The holders
    // and the observer this proof drives are born in the tree's daemon
    // leaf, so each is reaped before the tree comes down — killed by the
    // pid it reported, never by the wrapper that spawned it.
    let _veth = Veth(HOST_VETH);
    let holder = spawn_netns_holder();
    let host_prefix = format!("{HOST_VETH_ADDRESS}/24");
    let peer_prefix = format!("{PEER_ADDRESS}/24");
    let gateway = format!("{HOST_VETH_ADDRESS}");
    ip(&[
        "link", "add", HOST_VETH, "type", "veth", "peer", "name", PEER_VETH,
    ]);
    ip(&["address", "add", &host_prefix, "dev", HOST_VETH]);
    ip(&["link", "set", HOST_VETH, "up"]);
    ip(&["link", "set", PEER_VETH, "netns", &holder.pid.to_string()]);
    nsenter_ip(holder.pid, &["link", "set", "lo", "up"]);
    nsenter_ip(
        holder.pid,
        &["address", "add", &peer_prefix, "dev", PEER_VETH],
    );
    nsenter_ip(holder.pid, &["link", "set", PEER_VETH, "up"]);
    nsenter_ip(holder.pid, &["route", "add", "default", "via", &gateway]);

    // The observer: this binary re-exec'd inside the peer's namespace, its
    // report a file both processes reach, its marker riding the command
    // line through `env` because the sudo it went through would strip an
    // inherited variable. Its first line names its own pid, so the guard
    // that reaps it is armed before the proof drives anything.
    let report =
        std::env::temp_dir().join(format!("minimald-proof-snat-{}.report", std::process::id()));
    let wrapper = privileged("nsenter")
        .arg("-t")
        .arg(holder.pid.to_string())
        .arg("-n")
        .arg("env")
        .arg(format!("MINIMALD_PROOF_OBSERVER={}", report.display()))
        .arg(std::env::current_exe().expect("this test binary's own path"))
        .args([
            "--exact",
            "snat_peer_observes_the_source",
            "--ignored",
            "--test-threads=1",
        ])
        .spawn()
        .expect("spawning the peer's observer");
    let mut observer = Driven {
        pid: observer_report(&report, 1)[0]
            .strip_prefix("pid ")
            .and_then(|pid| pid.parse().ok())
            .unwrap_or_else(|| panic!("the observer reported itself unparseably")),
        wrapper,
    };
    let port: u16 = observer_report(&report, 2)[1]
        .strip_prefix("ready ")
        .and_then(|port| port.parse().ok())
        .unwrap_or_else(|| panic!("the observer never named the port it listens on"));
    let peer = SocketAddr::from((PEER_ADDRESS, port));

    // The cohort's leg: this proof process in a box's leaf, its socket
    // made there, the connection driven to the peer behind the veth.
    migrate_self(&leaf.join("cgroup.procs"));
    let cohort_leg = TcpStream::connect_timeout(&peer, Duration::from_secs(10))
        .expect("the box's leg reaches the peer behind the veth");
    drop(cohort_leg);

    // Loopback, from the same box's leaf: a listener this proof holds on
    // its own loopback, a connect to it, and the address the listener met
    // — the cohort's identity, if the postrouting rules' `lo` guard were
    // missing, and the connection's own source where it holds.
    let loopback = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("binding the loopback listener the guard is proved on");
    let loop_port = loopback
        .local_addr()
        .expect("the loopback listener's address")
        .port();
    let loop_leg = TcpStream::connect((Ipv4Addr::LOCALHOST, loop_port))
        .expect("the loopback leg the guard is proved on");
    let (_, met) = loopback
        .accept()
        .expect("accepting the loopback leg the guard is proved on");
    assert_eq!(
        met.ip(),
        IpAddr::from(Ipv4Addr::LOCALHOST),
        "the loopback leg keeps its own source — never the cohort's identity \
         {COHORT_ADDRESS}, which is what the postrouting rules' lo guard is \
         there to spare it: the listener met {met}"
    );
    drop(loop_leg);
    drop(loopback);

    // The node plane's leg: the same proof process, migrated into the
    // daemon's leaf before its socket is made.
    migrate_self(&daemon_leaf(&scratch).join("cgroup.procs"));
    let node_plane_leg = TcpStream::connect_timeout(&peer, Duration::from_secs(10))
        .expect("the daemon leaf's leg reaches the peer behind the veth");
    drop(node_plane_leg);

    // Neither subtree: this proof process back outside the whole tree, a
    // host process like any other, keeping the host's own source.
    leave_the_tree(&mountpoint);
    let own_leg = TcpStream::connect_timeout(&peer, Duration::from_secs(10))
        .expect("the unclassed leg reaches the peer behind the veth");
    drop(own_leg);

    // The report, read whole: three legs in the order they were driven,
    // each address the one the peer's own accept met.
    let legs = observer_report(&report, 5);
    assert_eq!(
        legs.len(),
        5,
        "the observer reported exactly its own pid, the port, and the three \
         legs driven, got: {legs:?}"
    );
    assert_eq!(
        legs[2],
        format!("peer {COHORT_ADDRESS}"),
        "the peer met the boxes leaf's connection with the cohort's identity, got: {legs:?}"
    );
    assert_eq!(
        legs[3],
        format!("peer {NODE_PLANE_ADDRESS}"),
        "the peer met the daemon leaf's connection with the node plane's \
         identity, got: {legs:?}"
    );
    assert_eq!(
        legs[4],
        format!("peer {HOST_VETH_ADDRESS}"),
        "the peer met a connection from outside the tree with the host's own \
         source, unchanged, got: {legs:?}"
    );
    let finished = observer.finished();
    assert!(
        finished.success(),
        "the peer's observer ended its three legs clean: {finished}"
    );
    let _ = std::fs::remove_file(&report);
}

/// That classification is a pair of bits and never a whole mark: a second
/// component of this host — the proof's own witness, a table that classes
/// connections with two foreign bits below the mask — sets its bits on a
/// new connection first, the installer's classify chain runs after it, and
/// the mark that comes out of the two carries the foreign bits beside the
/// class bit, not instead of it. The witness reads the mark back with
/// counters at a priority after classification, one rule per expectation:
/// the box leaf's flow as the cohort's bit with the foreign bits intact,
/// the daemon leaf's as the node plane's bit with them intact, and a
/// third counter for any flow that lost a foreign bit, which is the
/// failure mode the mask exists to make impossible.
///
/// The witness is loaded *after* the install — its own ct-mark rules name
/// the cohort's bit in passing, and the install's scan refuses any
/// ct-mark use that touches the bits it classes with — and removed before
/// this proof's lock releases, so the scan never runs over a table this
/// proof owns.
///
/// `#[ignore]`d like the proofs above, declined the same way on a runner
/// with no `nft`.
#[test]
#[ignore = "loads the installer's table beside a witness that classes with foreign ct-mark bits, and reads the marks back; run by the native lane's minimald-root-integration job (just test-root-integration)"]
fn foreign_ct_mark_bits_survive_classification() {
    if !nft_present() {
        eprintln!(
            "skipping foreign_ct_mark_bits_survive_classification: no nft on \
             this host — the install's nftables transaction is the artifact \
             under proof (apt install nftables)"
        );
        return;
    }
    // One table at a time: this binary's proofs each load it.
    let _table = one_table_at_a_time();
    let mountpoint = refuse_unless_the_root_lane_can_run();
    let account = the_delegated_account();
    let scratch = mountpoint.join(format!("minimald-proof-foreign-{}", std::process::id()));
    let mut install = ScratchInstall {
        root: scratch.clone(),
        mountpoint: mountpoint.clone(),
        leaf: None,
        child: None,
    };
    install_over_scratch(&scratch, &account);
    place_this_process_in_the_tree(&scratch);
    let leaf = create_box_leaf(&scratch, "foreignbox", Verdict::Allow)
        .expect("the step's allow subtree takes a box leaf");
    install.leaf = Some(leaf.clone());

    // The one destination the witness keys on: a loopback listener this
    // proof holds open, so the port is the proof's own and no other flow
    // on this host can reach the witness's counters.
    let held = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("binding the listener the witness keys on");
    let port = held
        .local_addr()
        .expect("the listener's address the witness keys on")
        .port();

    // The witness: foreign bits 0x00000003, set on a new connection to
    // that port before the classify chain runs (-180: after conntrack at
    // -200, so the connection's ct exists to mark — an equal -200 hook would
    // be inserted ahead of conntrack's and set nothing — and before
    // classify at -150), and the mark read back after it (-100), one
    // counter per expectation. The set writes bits the install's mask
    // never names; the read names the two marks the legs must leave and
    // the one loss a leg must never show.
    let witness = format!("minimald_witness_{}", std::process::id());
    load_fixture_table(
        &witness,
        &format!(
            "table inet {witness} {{
    chain set_foreign {{
        type filter hook output priority -180; policy accept;
        oifname \"lo\" tcp dport {port} ct state new ct mark set ct mark or 0x00000003
    }}
    chain read_marks {{
        type filter hook output priority -100; policy accept;
        oifname \"lo\" tcp dport {port} ct mark == 0x10000003 counter
        oifname \"lo\" tcp dport {port} ct mark == 0x20000003 counter
        oifname \"lo\" tcp dport {port} ct mark and 0x00000003 != 0x00000003 counter
    }}
}}
"
        ),
    );
    let _witness = FixtureTable(witness.clone());

    // The two legs, each with its socket made inside the cgroup it is
    // classed by: one from the box's leaf, one from the daemon's.
    migrate_self(&leaf.join("cgroup.procs"));
    let box_leg = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .expect("the box leaf's leg reaches the held listener");
    drop(box_leg);
    migrate_self(&daemon_leaf(&scratch).join("cgroup.procs"));
    let daemon_leg = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .expect("the daemon leaf's leg reaches the held listener");
    drop(daemon_leg);

    // The marks, as the witness's own counters read them: the box leg's
    // flow with the cohort bit over intact foreign bits, the daemon
    // leaf's with the node plane's bit over intact foreign bits, and the
    // third counter — any flow to that port that lost a foreign bit —
    // still at zero.
    let listed = nft(&["list", "chain", "inet", &witness, "read_marks"]);
    assert!(
        listed.status.success(),
        "listing the witness's counters: {}{}",
        String::from_utf8_lossy(&listed.stdout),
        String::from_utf8_lossy(&listed.stderr),
    );
    let marks = String::from_utf8_lossy(&listed.stdout).into_owned();
    let counters: Vec<u64> = marks
        .lines()
        .filter_map(|line| line.split("counter packets ").nth(1))
        .filter_map(|counted| counted.split(' ').next())
        .filter_map(|counted| counted.parse().ok())
        .collect();
    assert_eq!(
        counters.len(),
        3,
        "the witness read three counters back, one rule each: {marks}"
    );
    assert!(
        counters[0] >= 1,
        "a boxes-subtree flow classed the cohort bit with the foreign bits \
         intact — its mark read back 0x10000003: {marks}"
    );
    assert!(
        counters[1] >= 1,
        "a slice flow classed the node plane's bit with the foreign bits \
         intact — its mark read back 0x20000003: {marks}"
    );
    assert_eq!(
        counters[2], 0,
        "no flow to that port lost a foreign bit to classification — the \
         classify chain writes the mask's two bits and no others: {marks}"
    );
}

/// The one thing the install refuses to run over: a host that already
/// classes connections with the bits the default mask names. The scan is
/// read live here — a fixture table standing in for another component's
/// ct-mark use, loaded before the install, so the refusal is over a real
/// ruleset this kernel holds — and the refusal must name the rule it
/// found and the override that escapes it, and lay out nothing. Then the
/// escape itself: the same host, the same standing fixture, and an
/// install told to class with bits nothing else uses goes through — and
/// records the mask it chose, so the step and the daemon read one value.
///
/// `#[ignore]`d like the proofs above, declined the same way on a runner
/// with no `nft`.
#[test]
#[ignore = "proves the install's conflict scan live, over a standing ct-mark user on this host; run by the native lane's minimald-root-integration job (just test-root-integration)"]
fn install_refuses_an_overlapping_ct_mark_user() {
    if !nft_present() {
        eprintln!(
            "skipping install_refuses_an_overlapping_ct_mark_user: no nft on \
             this host — the install's nftables transaction is the artifact \
             under proof (apt install nftables)"
        );
        return;
    }
    // One table at a time: this binary's proofs each load it.
    let _table = one_table_at_a_time();
    let mountpoint = refuse_unless_the_root_lane_can_run();
    let account = the_delegated_account();
    let scratch = mountpoint.join(format!("minimald-proof-overlap-{}", std::process::id()));
    let _install = ScratchInstall {
        root: scratch.clone(),
        mountpoint: mountpoint.clone(),
        leaf: None,
        child: None,
    };

    // The standing user: a fixture table that classes connections to one
    // port with the cohort bit the default mask names — the bit overlap
    // the scan exists to refuse, kept inert by the narrowest match that
    // still names the bit.
    let fixture = format!("minimald_proof_overlap_{}", std::process::id());
    load_fixture_table(
        &fixture,
        &format!(
            "table inet {fixture} {{
    chain set_mark {{
        type filter hook output priority filter; policy accept;
        oifname \"lo\" tcp dport 9 ct state new ct mark set ct mark or 0x10000000
    }}
}}
"
        ),
    );
    let _fixture = FixtureTable(fixture);

    // The refusal: the install names the rule it found, the override that
    // escapes it, and lays out nothing — no tree, so no marker, no record,
    // no table.
    let refused = install_over_scratch_with(&scratch, &account, &[]);
    assert!(
        !refused.status.success(),
        "the install refuses to class over a host already using the bits the \
         default mask names: {}{}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr),
    );
    let refusal = format!(
        "{}{}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr),
    );
    // nft lists the fixture's `or` as `|`; either spelling is the rule.
    assert!(
        refusal.contains("ct mark set ct mark | 0x10000000")
            || refusal.contains("ct mark set ct mark or 0x10000000"),
        "the refusal names the rule it found: {refusal}"
    );
    assert!(
        refusal.contains("--ct-mark-mask"),
        "the refusal names the override that escapes it: {refusal}"
    );
    assert!(
        !scratch.exists(),
        "the refused install laid out no tree: {refusal}"
    );

    // The escape, over the same standing user: the install goes through,
    // and the mask it chose is the one it recorded beside the marker. The
    // escape's bits avoid the fixture's, the default 0x30000000, Tailscale's
    // 0x00ff0000 and kube-proxy's 0x4000/0x8000.
    let escaped = install_over_scratch_with(&scratch, &account, &["--ct-mark-mask", "0x0c000000"]);
    assert!(
        escaped.status.success(),
        "the install goes through over the same standing user once told to class \
         with bits nothing else uses: {}{}",
        String::from_utf8_lossy(&escaped.stdout),
        String::from_utf8_lossy(&escaped.stderr),
    );
    assert!(
        scratch.join("ct-mark-mask-0x0c000000").is_dir(),
        "the escaped install records the mask it classifies with, named as it \
         rendered it: {}",
        scratch.display()
    );
}
