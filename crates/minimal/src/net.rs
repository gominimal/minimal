//! `min net forward`: a local listener relayed into a box over its session.
//!
//! The forward is an `ssh -L` with a session in place of a host. A listener
//! on this machine's loopback accepts connections and relays each one over a
//! `direct-tcpip` channel the daemon serves, so a server inside the box
//! answers on `localhost` here with nothing installed in between (NET-104).
//! The listener lives as long as the session does (NET-105).
//!
//! `min net setup`: the one privileged step behind the resolver advisory a
//! session start prints (NET-122). It routes the box zone to the daemon's
//! answerer through the host's own resolver, so any process on the machine
//! resolves `<name>.min.internal` with no proxy, PAC file or proxy variable
//! (NET-009), and on macOS reserves the local range boxes are published from.
//!
//! `min net expose <port>`: the dynamic ingress request. One request shape
//! goes to the local daemon, which decides it against the box's
//! `dynamic_ingress` setting (NET-043): an allow publishes the port and
//! lists it in `min session policy`, anything else is a typed refusal that
//! publishes nothing (NET-044, NET-047).

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use tokio::net::{TcpListener, TcpStream};

use crate::{GlobalArgs, NetExposeArgs, NetForwardArgs, NetSetupArgs, client, cmd};

/// How often the forward re-checks that its session is still there.
///
/// The daemon offers no session-closed event to subscribe to, so the record
/// is polled. A second is short enough that a destroyed session's port stops
/// answering while the operator is still looking at it, and cheap enough
/// against a daemon on a UNIX socket to be unremarkable.
const SESSION_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// The address the daemon connects to on the box's behalf.
///
/// Every box's ports are reached on the box host's loopback — a host-address
/// box listens there directly, and an own-address box is published there by
/// the switch's forwarder — so this is the target for both.
const BOX_HOST: &str = "127.0.0.1";

/// A parsed `<local>:<port>` forward spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ForwardSpec {
    /// The port bound on this machine's loopback.
    local_port: u16,
    /// The port the box's own server listens on.
    box_port: u16,
}

/// Parse the `<local>:<port>` argument of `min net forward`.
pub(crate) fn parse_forward_spec(spec: &str) -> Result<ForwardSpec, anyhow::Error> {
    let (local, remote) = spec
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("forward '{spec}': expected <local>:<port>"))?;
    let local_port = local
        .parse::<u16>()
        .map_err(|_| anyhow::anyhow!("forward '{spec}': invalid local port '{local}'"))?;
    let box_port = remote
        .parse::<u16>()
        .map_err(|_| anyhow::anyhow!("forward '{spec}': invalid box port '{remote}'"))?;
    // Port 0 means "whatever is free" to bind(2) and is never a listening
    // port in the box; either way there is nothing the operator asked for.
    if local_port == 0 || box_port == 0 {
        anyhow::bail!("forward '{spec}': 0 is not a port to forward");
    }
    Ok(ForwardSpec {
        local_port,
        box_port,
    })
}

/// `min net forward <box> <local>:<port>`: bind `localhost:<local>` and relay
/// it into the box until the session goes away or the operator stops it.
pub(crate) async fn cmd_net_forward(
    global: &GlobalArgs,
    args: NetForwardArgs,
) -> Result<(), anyhow::Error> {
    let spec = parse_forward_spec(&args.ports)?;
    cmd::ensure_daemon(global)?;
    let mut lookup = cmd::connect_daemon(global).await?;
    let record = cmd::resolve_session(&mut lookup, &args.session).await?;
    let session_id = record.id;

    // A second connection, authenticated as the session: that username is how
    // the daemon scopes the forward's channels (see `Client::connect_as`), and
    // the first one is still needed to watch the session.
    let sock = client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd())
        .context("Failed to resolve daemon socket path")?;
    let forwarder = Arc::new(
        client::Client::connect_as(&sock, &session_id.to_string())
            .await
            .context("Failed to open the forward's connection to minimald")?,
    );

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, spec.local_port))
        .await
        .with_context(|| {
            format!(
                "Failed to bind localhost:{} for the forward",
                spec.local_port
            )
        })?;

    eprintln!(
        "Forwarding localhost:{} to port {} in '{}' — press Ctrl-C to stop",
        spec.local_port, spec.box_port, args.session,
    );

    serve_forward(
        listener,
        spec,
        session_id,
        forwarder,
        session_closed(lookup, session_id),
    )
    .await
}

/// Accept connections on the forward's listener and relay each one into the
/// box, until `closed` resolves.
///
/// Returning drops the listener, which is how the forwarded port stops
/// answering when the session it belongs to is gone (NET-105).
async fn serve_forward(
    listener: TcpListener,
    spec: ForwardSpec,
    session_id: sessions::SessionId,
    forwarder: Arc<client::Client>,
    closed: impl Future<Output = ()>,
) -> Result<(), anyhow::Error> {
    tracing::info!(
        %session_id,
        local_port = spec.local_port,
        box_port = spec.box_port,
        "forward opened"
    );
    let mut closed = std::pin::pin!(closed);
    loop {
        tokio::select! {
            () = &mut closed => {
                tracing::info!(
                    %session_id,
                    local_port = spec.local_port,
                    box_port = spec.box_port,
                    "forward closed with its session"
                );
                return Ok(());
            }
            accepted = listener.accept() => {
                let (local, _) = accepted.context("accept on the forward's listener")?;
                // Relayed off the accept loop, channel open included: opening
                // a channel to a port nothing answers on costs the daemon's
                // connect timeout, and the next connection must not wait it
                // out behind this one.
                let forwarder = Arc::clone(&forwarder);
                tokio::spawn(async move {
                    match forwarder.open_direct_tcpip(BOX_HOST, spec.box_port).await {
                        Ok(channel) => relay(local, channel.into_stream()).await,
                        Err(error) => tracing::warn!(
                            box_port = spec.box_port,
                            %error,
                            "forward could not reach the box port"
                        ),
                    }
                });
            }
        }
    }
}

/// Relay one accepted connection to the box and back, until either side ends
/// it.
async fn relay<S>(mut local: TcpStream, mut boxed: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if let Err(error) = tokio::io::copy_bidirectional(&mut local, &mut boxed).await {
        tracing::debug!(%error, "forwarded connection ended with an error");
    }
}

/// Resolve once the session behind a forward is gone.
///
/// The forward's own connection outlives its session — the daemon scopes each
/// channel open, not the connection — so the record is the signal. A failed
/// lookup counts as gone too: the daemon the forward relays through is no
/// longer answering, so neither is the forward.
async fn session_closed(mut lookup: client::Client, session_id: sessions::SessionId) {
    let key = session_id.to_string();
    loop {
        tokio::time::sleep(SESSION_POLL_INTERVAL).await;
        match cmd::get_session_record(&mut lookup, &key).await {
            Ok(resp) if resp.record.is_some() => {}
            Ok(_) => return,
            Err(error) => {
                tracing::warn!(%session_id, %error, "forward lost sight of its session");
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// `min net expose`

/// The variable every box's shell carries its session's name in, seeded by
/// the daemon's launcher baseline: how `min net expose` inside a box knows
/// which box it is in without being told.
const SESSION_NAME_ENV: &str = "MINIMAL_SESSION_NAME";

/// `min net expose <port> [--session <box>]`: ask the daemon to publish a
/// port of the box, subject to its `dynamic_ingress` setting.
pub(crate) async fn cmd_net_expose(
    global: &GlobalArgs,
    args: NetExposeArgs,
) -> Result<(), anyhow::Error> {
    let session = match args.session {
        Some(session) => session,
        None => std::env::var(SESSION_NAME_ENV).ok().ok_or_else(|| {
            anyhow::anyhow!(
                "min net expose runs inside a box, where {SESSION_NAME_ENV} names it; outside \
                 one, name the box with --session"
            )
        })?,
    };
    cmd::ensure_daemon(global)?;
    // The box's name resolves the VM holding it, so nothing has to name the VM
    // (NET-058); on a machine with one box host this is that box host.
    let mut client = cmd::connect_box_host(global, &session).await?;
    let record = cmd::resolve_session(&mut client, &session).await?;
    match send_expose(&mut client, record.id, args.port).await? {
        minimald_rpc::ExposeResponse::Published {
            hostname,
            address,
            mapping,
        } => {
            eprintln!(
                "published {hostname}:{} at {address}:{}; `min session policy {session}` lists it",
                mapping.internal_port, mapping.external_port
            );
            Ok(())
        }
        minimald_rpc::ExposeResponse::Refused { reason } => {
            bail!("min net expose {} refused: {reason}", args.port)
        }
    }
}

/// Sends the one request shape the daemon decides (NET-043) for `port` of
/// the box `session_id`, over TCP, and returns the decision as the daemon
/// gave it: a publication or a typed refusal. The RPC's own error — no such
/// session, a record that could not be written — is the error.
///
/// Split from the command so the request and the daemon's answer are
/// assertable without capturing stderr.
pub(crate) async fn send_expose(
    client: &mut client::Client,
    session_id: sessions::SessionId,
    port: u16,
) -> Result<minimald_rpc::ExposeResponse, anyhow::Error> {
    use minimald_rpc::{Errorable, Expose, ExposeRequest};

    let resp = client
        .oneshot_rpc::<Expose>(ExposeRequest {
            id: session_id,
            port,
            proto: sessions::IpProto::Tcp,
        })
        .await
        .context("Expose RPC failed")?;
    match resp {
        Errorable::Ok(response) => Ok(response),
        Errorable::Err { error } => bail!("{error}"),
    }
}

// ---------------------------------------------------------------------------
// `min net setup`

/// Where the answerer listens: the address the resolver hook is pointed at.
const ANSWERER: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
    minimald_rpc::ANSWERER_PORT,
);

/// How long the setup waits for the answerer before refusing to write the
/// resolver hook. A daemon that is up answers at once; one that is not is
/// not going to appear because the command waits.
const ANSWERER_WAIT: Duration = Duration::from_secs(10);

/// How long the macOS setup waits for the boot step to alias the whole
/// range. `launchctl bootstrap` returns before the helper runs; 254
/// `ifconfig` calls take well under a second on an idle host.
const RANGE_WAIT: Duration = Duration::from_secs(30);

/// The Linux resolver hook: a oneshot unit that gives systemd-resolved a
/// dedicated link routing the zone to the answerer, re-applied at boot. The
/// link needs an address of global scope or resolved does not consult it;
/// the address is a literal outside the reserved range and nothing binds it.
const LINUX_UNIT_PATH: &str = "/etc/systemd/system/min-resolver.service";
const LINUX_UNIT: &str = "[Unit]\n\
Description=Route the min.internal box zone to the Minimal answerer\n\
After=systemd-resolved.service\n\
Wants=systemd-resolved.service\n\
\n\
[Service]\n\
Type=oneshot\n\
RemainAfterExit=yes\n\
ExecStart=/bin/sh -c 'ip link show min0 >/dev/null 2>&1 || ip link add min0 type dummy; \
ip link set min0 up; ip addr replace 127.0.65.1/32 dev min0 scope global; \
resolvectl dns min0 127.0.0.1:15353; resolvectl domain min0 ~min.internal'\n\
ExecStop=/bin/sh -c 'ip link del min0'\n\
\n\
[Install]\n\
WantedBy=multi-user.target\n";

/// The macOS resolver hook: the scoped resolver file `mDNSResponder` reads
/// for the zone, with the answerer's port.
const MACOS_RESOLVER_PATH: &str = "/etc/resolver/min.internal";
const MACOS_RESOLVER: &str = "nameserver 127.0.0.1\nport 15353\n";

/// The macOS boot step: a root LaunchDaemon that runs the alias script at
/// every boot and retries a partial apply (`KeepAlive` on failure — never
/// `LaunchOnlyOnce`, which drops the job on its first non-zero exit).
const MACOS_LABEL: &str = "dev.minimal.loopback";
const MACOS_PLIST_PATH: &str = "/Library/LaunchDaemons/dev.minimal.loopback.plist";
const MACOS_SCRIPT_PATH: &str = "/Library/PrivilegedHelperTools/dev.minimal.loopback.sh";
const MACOS_PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dev.minimal.loopback</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>/Library/PrivilegedHelperTools/dev.minimal.loopback.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>/var/log/dev.minimal.loopback.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/dev.minimal.loopback.log</string>
</dict>
</plist>
"#;
/// Aliases the reserved range onto `lo0`. Idempotent: an alias already
/// present is skipped. The range and the interface are literals on purpose;
/// the script reads no configuration.
const MACOS_SCRIPT: &str = r#"#!/bin/sh
# dev.minimal.loopback: re-apply the reserved local range 127.0.64.0/24 on lo0.
# Installed by `min net setup`; run by launchd at boot and at install.
set -u
PATH=/sbin:/usr/sbin:/bin:/usr/bin
IFACE=lo0
PREFIX=127.0.64
present=$(ifconfig "$IFACE" inet 2>/dev/null | awk '$1 == "inet" { printf "%s ", $2 }')
added=0
n=1
while [ "$n" -le 254 ]; do
    addr="$PREFIX.$n"
    case " $present " in
        *" $addr "*) ;;
        *)
            if ifconfig "$IFACE" alias "$addr" 255.255.255.255; then
                added=$((added + 1))
            else
                echo "dev.minimal.loopback: alias $addr failed" >&2
            fi
            ;;
    esac
    n=$((n + 1))
done
count=$(ifconfig "$IFACE" inet 2>/dev/null | awk -v p="$PREFIX." 'index($2, p) == 1 { c++ } END { print c + 0 }')
echo "dev.minimal.loopback: $(date -u +%Y-%m-%dT%H:%M:%SZ) added=$added present=$count/254 on $IFACE"
[ "$count" -eq 254 ]
"#;

/// Every address of the reserved local range, `127.0.64.1` to `.254`.
fn reserved_range() -> impl Iterator<Item = Ipv4Addr> {
    (1..=254).map(|host| Ipv4Addr::new(127, 0, 64, host))
}

/// NET-123's bind probe, client side: the first address of the range that
/// does not bind, or `None` when the whole range is present.
fn range_gap() -> Option<(Ipv4Addr, std::io::Error)> {
    reserved_range().find_map(|address| {
        std::net::TcpListener::bind((address, 0))
            .err()
            .map(|error| (address, error))
    })
}

/// Where the resolver hook shows on this host once `min net setup` has run:
/// the scoped resolver file on macOS, the dedicated systemd-resolved link
/// (as sysfs lists it) on Linux — the same signal the daemon reads.
fn resolver_hook_path() -> std::path::PathBuf {
    if cfg!(target_os = "macos") {
        std::path::PathBuf::from(MACOS_RESOLVER_PATH)
    } else {
        Path::new("/sys/class/net").join(minimald_rpc::RESOLVER_LINK)
    }
}

/// The host's native-resolution state read from this side, for a session
/// start whose daemon said nothing about it (NET-122, NET-123). On macOS
/// every daemon is a guest: the loopback it could probe is the VM's and
/// `/etc/resolver` is out of its reach, so the client, which runs on the
/// host, judges both halves itself. Same shape as the daemon's advisory:
/// present whenever either half is missing, `None` when nothing needs doing.
pub(crate) fn host_resolution_advisory() -> Option<minimald_rpc::ResolverAdvisory> {
    advisory_from(resolver_hook_path().exists(), range_gap())
}

fn advisory_from(
    resolver_configured: bool,
    gap: Option<(Ipv4Addr, std::io::Error)>,
) -> Option<minimald_rpc::ResolverAdvisory> {
    let range_gap = gap.map(|(address, error)| format!("{address}: {error}"));
    let range_present = range_gap.is_none();
    (!resolver_configured || !range_present).then_some(minimald_rpc::ResolverAdvisory {
        resolver_configured,
        range_present,
        range_gap,
    })
}

/// Whether something answers DNS at `server`: sends an `SOA` query for the
/// zone apex and waits up to `timeout` for any reply with the query's id.
/// The resolver hook must not be written before this is true — a scoped
/// resolver with nothing behind it stalls every lookup on a macOS host.
pub(crate) fn answerer_listening(server: SocketAddr, timeout: Duration) -> bool {
    // A standard query, RD set, one question: `min.internal IN SOA`.
    let id: [u8; 2] = [0x4d, 0x49];
    let mut query = Vec::with_capacity(32);
    query.extend_from_slice(&id);
    query.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in minimald_rpc::BOX_ZONE.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0x00, 0x00, 0x06, 0x00, 0x01]);

    let deadline = Instant::now() + timeout;
    let Ok(socket) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) else {
        return false;
    };
    let _ = socket.set_read_timeout(Some(Duration::from_millis(500)));
    let mut buf = [0u8; 512];
    loop {
        if socket.send_to(&query, server).is_ok()
            && let Ok(len) = socket.recv(&mut buf)
            && len >= 2
            && buf[..2] == id
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Runs `program` with `args` as a privileged step, failing with its stderr.
fn run(program: &str, args: &[&str]) -> Result<(), anyhow::Error> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("could not run {program}"))?;
    if !output.status.success() {
        bail!(
            "{program} {} failed ({}): {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Writes `contents` at `path` with `mode`, creating the parent, root-owned
/// since this runs as root.
fn install(path: &str, contents: &str, mode: u32) -> Result<(), anyhow::Error> {
    use std::os::unix::fs::PermissionsExt as _;

    let path = Path::new(path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
    }
    std::fs::write(path, contents)
        .with_context(|| format!("could not write {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("could not set the mode of {}", path.display()))?;
    Ok(())
}

/// `sudo min net setup [--remove]`: install (or remove) the resolver hook
/// and, on macOS, the boot step that reserves the local range.
pub(crate) fn cmd_net_setup(args: NetSetupArgs) -> Result<(), anyhow::Error> {
    if !nix::unistd::geteuid().is_root() {
        bail!(
            "min net setup needs root: it writes the host resolver hook. Run it as `sudo {} net \
             setup`",
            std::env::current_exe()
                .map(|exe| exe.display().to_string())
                .unwrap_or_else(|_| "min".to_string())
        );
    }
    if args.remove {
        return remove_setup();
    }
    if cfg!(target_os = "macos") {
        // The range first: the boot step applies it now and at every boot,
        // and the probe below is what says it took.
        install(MACOS_SCRIPT_PATH, MACOS_SCRIPT, 0o755)?;
        install(MACOS_PLIST_PATH, MACOS_PLIST, 0o644)?;
        // A previous install is unloaded first so bootstrap does not refuse
        // a job that is already there.
        let _ = Command::new("launchctl")
            .args(["bootout", &format!("system/{MACOS_LABEL}")])
            .output();
        run("launchctl", &["bootstrap", "system", MACOS_PLIST_PATH])?;
        let deadline = Instant::now() + RANGE_WAIT;
        while let Some((address, error)) = range_gap() {
            if Instant::now() >= deadline {
                bail!(
                    "the boot step did not alias the whole reserved range {} onto lo0 in \
                     {}s: {address} still does not bind ({error}). See \
                     /var/log/dev.minimal.loopback.log",
                    minimald_rpc::RESERVED_RANGE,
                    RANGE_WAIT.as_secs()
                );
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        eprintln!(
            "reserved local range {} present on lo0 (re-applied at boot by {MACOS_LABEL})",
            minimald_rpc::RESERVED_RANGE
        );
    } else if let Some((address, error)) = range_gap() {
        // Linux carries all of 127/8 on `lo`; a gap here is not something
        // this command can fix, so it is reported and the hook still goes in.
        eprintln!(
            "warning: {address} of the reserved local range does not bind ({error}); boxes \
             stay published at 127.0.0.1"
        );
    }

    // The hook is pointed at the answerer only once the answerer is there.
    if !answerer_listening(ANSWERER, ANSWERER_WAIT) {
        bail!(
            "nothing answers the box zone on {ANSWERER}, so the resolver hook was not written \
             (a resolver pointed at a dead port stalls every lookup on macOS). Start the \
             daemon — any `min ls` does — and run this again"
        );
    }
    if cfg!(target_os = "macos") {
        install(MACOS_RESOLVER_PATH, MACOS_RESOLVER, 0o644)?;
        eprintln!("installed {MACOS_RESOLVER_PATH} -> {ANSWERER}");
    } else {
        install(LINUX_UNIT_PATH, LINUX_UNIT, 0o644)?;
        run("systemctl", &["daemon-reload"])?;
        run("systemctl", &["enable", "--now", "min-resolver.service"])?;
        if !Path::new("/sys/class/net")
            .join(minimald_rpc::RESOLVER_LINK)
            .exists()
        {
            bail!(
                "min-resolver.service ran but the {} link is not up; see `systemctl status \
                 min-resolver.service`",
                minimald_rpc::RESOLVER_LINK
            );
        }
        eprintln!(
            "installed {LINUX_UNIT_PATH}: systemd-resolved routes {} to {ANSWERER} over {}",
            minimald_rpc::BOX_ZONE,
            minimald_rpc::RESOLVER_LINK
        );
    }
    eprintln!(
        "<name>.{} now resolves natively on this host; the next session start says nothing",
        minimald_rpc::BOX_ZONE
    );
    Ok(())
}

/// Undoes [`cmd_net_setup`]. Each step is best effort so a half-installed
/// host can still be cleaned; the last error, if any, is reported.
fn remove_setup() -> Result<(), anyhow::Error> {
    let mut failed = None;
    let mut step = |result: Result<(), anyhow::Error>| {
        if let Err(error) = result {
            eprintln!("warning: {error:#}");
            failed = Some(error);
        }
    };
    let remove_file = |path: &str| match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(anyhow::Error::from(error).context(format!("could not remove {path}"))),
    };
    if cfg!(target_os = "macos") {
        step(remove_file(MACOS_RESOLVER_PATH));
        let _ = Command::new("launchctl")
            .args(["bootout", &format!("system/{MACOS_LABEL}")])
            .output();
        step(remove_file(MACOS_PLIST_PATH));
        step(remove_file(MACOS_SCRIPT_PATH));
        for address in reserved_range() {
            let _ = Command::new("ifconfig")
                .args(["lo0", "-alias", &address.to_string()])
                .output();
        }
    } else {
        if Path::new(LINUX_UNIT_PATH).exists() {
            step(run(
                "systemctl",
                &["disable", "--now", "min-resolver.service"],
            ));
        }
        step(remove_file(LINUX_UNIT_PATH));
        step(run("systemctl", &["daemon-reload"]));
        let _ = Command::new("ip")
            .args(["link", "del", minimald_rpc::RESOLVER_LINK])
            .output();
    }
    match failed {
        Some(error) => Err(error),
        None => {
            eprintln!("removed the native resolution setup");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use minimald::test_harness::{TestServer, create_configured_session};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// A daemon on a UNIX socket with one live session to forward into.
    ///
    /// The tempdir is returned so the caller keeps the socket alive, and the
    /// server so its accept loop keeps serving. The socket sits where
    /// `GlobalArgs::minimal_dir` resolves it, so the forward reaches this
    /// daemon by the same path a real one does.
    struct Daemon {
        _server: TestServer,
        _dir: tempfile::TempDir,
        global: GlobalArgs,
        sock: std::path::PathBuf,
        admin: minimald::test_harness::TestClient,
        session_id: sessions::SessionId,
    }

    async fn daemon_with_session(name: &str) -> Daemon {
        let server = TestServer::new().await;
        let dir = tempfile::TempDir::new().unwrap();
        let sock_dir = dir.path().join("providers/local-minimald0");
        std::fs::create_dir_all(&sock_dir).unwrap();
        let sock = sock_dir.join("ssh.sock");
        server.listen_on_uds(&sock).await;
        let mut admin = server.connect().await;
        let session_id = create_configured_session(&mut admin, name, "/tmp").await;
        Daemon {
            _server: server,
            global: GlobalArgs {
                minimal_dir: Some(dir.path().to_path_buf()),
                ..GlobalArgs::default()
            },
            _dir: dir,
            sock,
            admin,
            session_id,
        }
    }

    /// A server standing in for one inside the box: answers each connection
    /// with what it was sent, uppercased. Returns the port it listens on.
    async fn uppercasing_backend() -> u16 {
        let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = backend.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = backend.accept().await {
                tokio::spawn(async move {
                    let mut request = [0u8; 5];
                    if sock.read_exact(&mut request).await.is_ok() {
                        let _ = sock.write_all(&request.to_ascii_uppercase()).await;
                    }
                });
            }
        });
        port
    }

    /// NET-104: a request to the forward's local port comes back with the
    /// in-box server's answer, carried over the session's SSH channel.
    #[tokio::test]
    async fn net_forward_relays_over_ssh_channel() {
        let box_port = uppercasing_backend().await;
        let daemon = daemon_with_session("forward-relay").await;

        let forwarder = Arc::new(
            client::Client::connect_as(&daemon.sock, &daemon.session_id.to_string())
                .await
                .unwrap(),
        );
        // Port 0 for the listener: the spec's local port is whatever the
        // operator typed, and a test cannot claim a fixed one.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let local_port = listener.local_addr().unwrap().port();
        let spec = ForwardSpec {
            local_port,
            box_port,
        };

        // Nothing destroys the session here, so the forward is ended by
        // dropping the sender once the relay has been proved.
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let forward = tokio::spawn(serve_forward(
            listener,
            spec,
            daemon.session_id,
            forwarder,
            async move {
                let _ = stopped.await;
            },
        ));

        let mut request = TcpStream::connect((Ipv4Addr::LOCALHOST, local_port))
            .await
            .expect("the forward's local port must answer");
        request.write_all(b"hello").await.unwrap();
        let mut answer = [0u8; 5];
        request
            .read_exact(&mut answer)
            .await
            .expect("the in-box server's answer must come back over the forward");
        assert_eq!(
            &answer,
            b"HELLO",
            "localhost:{local_port} returned {} rather than the box's answer",
            String::from_utf8_lossy(&answer)
        );

        drop(stop);
        forward.await.unwrap().unwrap();
    }

    /// NET-105: destroying the session closes the forward's listener, so the
    /// local port stops answering without the operator doing anything.
    #[tokio::test]
    async fn net_forward_closes_with_session() {
        use minimald_rpc::{DestroySession, DestroySessionRequest, Errorable};

        let box_port = uppercasing_backend().await;
        let mut daemon = daemon_with_session("forward-closes").await;

        let forwarder = Arc::new(
            client::Client::connect_as(&daemon.sock, &daemon.session_id.to_string())
                .await
                .unwrap(),
        );
        // The session watch runs on the command's own lookup connection, so
        // the test opens it the same way `cmd_net_forward` does.
        let watcher = cmd::connect_daemon(&daemon.global).await.unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let local_port = listener.local_addr().unwrap().port();
        let spec = ForwardSpec {
            local_port,
            box_port,
        };
        let forward = tokio::spawn(serve_forward(
            listener,
            spec,
            daemon.session_id,
            forwarder,
            session_closed(watcher, daemon.session_id),
        ));

        // The port answers while the session is there, so what the assertion
        // below observes is the close and not a listener that never bound.
        TcpStream::connect((Ipv4Addr::LOCALHOST, local_port))
            .await
            .expect("the forward's local port must answer while the session lives");

        match daemon
            .admin
            .call::<DestroySession>(&DestroySessionRequest {
                id: daemon.session_id,
            })
            .await
        {
            Errorable::Ok(_) => {}
            Errorable::Err { error } => panic!("DestroySession failed: {error}"),
        }

        // Generous against the poll interval: what is asserted is that the
        // forward ends by itself, not how quickly it notices.
        tokio::time::timeout(Duration::from_secs(30), forward)
            .await
            .expect("the forward must close when its session is destroyed")
            .unwrap()
            .unwrap();

        assert!(
            TcpStream::connect((Ipv4Addr::LOCALHOST, local_port))
                .await
                .is_err(),
            "localhost:{local_port} still answers after the session was destroyed"
        );
    }

    /// An own-address box on the harness daemon with the given
    /// `dynamic_ingress` setting: what `min net expose` is decided against.
    async fn own_ip_box(
        client: &mut minimald::test_harness::TestClient,
        name: &str,
        setting: sessions::DynamicIngress,
    ) -> sessions::SessionId {
        use minimald::test_harness::{create_session_req, unwrap_ready};
        use minimald_rpc::{
            ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, Errorable, FinalizeSession,
            FinalizeSessionRequest,
        };
        let mut req = create_session_req(name, "/tmp");
        req.config.network = sessions::NetworkMode::OwnIp;
        req.config.policy.dynamic_ingress = Some(setting);
        let id = client.call::<CreateSession>(&req).await.unwrap().id;
        unwrap_ready(
            client
                .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
                    session_id: id,
                    contribution: Default::default(),
                })
                .await
                .unwrap(),
        );
        match client
            .call::<FinalizeSession>(&FinalizeSessionRequest { session_id: id })
            .await
        {
            Errorable::Ok(_) => id,
            Errorable::Err { error } => panic!("FinalizeSession failed: {error}"),
        }
    }

    /// NET-043, NET-044: `min net expose <port>` sends the one request shape
    /// to the local daemon over its socket, and what comes back is the
    /// daemon's decision against the box's `dynamic_ingress` setting: an
    /// allow publishes the port and `min session policy` lists the mapping;
    /// a deny reaches the operator as the typed refusal, naming the setting.
    #[tokio::test]
    async fn net_expose_sends_request_to_local_daemon() {
        use minimald_rpc::{
            ExposeRefusal, ExposeResponse, GetSessionPolicy, GetSessionPolicyRequest,
        };

        let mut daemon = daemon_with_session("expose-host").await;
        let allowing = own_ip_box(
            &mut daemon.admin,
            "expose-allowing",
            sessions::DynamicIngress::Allow,
        )
        .await;
        let denying = own_ip_box(
            &mut daemon.admin,
            "expose-denying",
            sessions::DynamicIngress::Deny,
        )
        .await;

        // The command's own path to the daemon: the socket `GlobalArgs`
        // resolves, as `cmd_net_expose` connects.
        let mut client = cmd::connect_daemon(&daemon.global).await.unwrap();
        let response = send_expose(&mut client, allowing, 18_480).await.unwrap();
        let ExposeResponse::Published {
            hostname, mapping, ..
        } = response
        else {
            panic!("an allowing box must publish the port: {response:?}");
        };
        assert_eq!(hostname, "expose-allowing.min.internal");
        assert_eq!(mapping.internal_port, 18_480);
        let policy = client
            .oneshot_rpc::<GetSessionPolicy>(GetSessionPolicyRequest::Id(allowing))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            policy.ingress.map(|ingress| ingress.port_mappings),
            Some(vec![mapping]),
            "`min session policy` lists the published mapping"
        );

        assert_eq!(
            send_expose(&mut client, denying, 18_480).await.unwrap(),
            ExposeResponse::Refused {
                reason: ExposeRefusal::Denied
            }
        );
        let refused = cmd_net_expose(
            &daemon.global,
            NetExposeArgs {
                port: 18_480,
                session: Some("expose-denying".to_string()),
            },
        )
        .await
        .expect_err("a denied request fails the command");
        assert!(
            format!("{refused:#}").contains("dynamic_ingress"),
            "the operator reads the typed refusal: {refused:#}"
        );
        let policy = client
            .oneshot_rpc::<GetSessionPolicy>(GetSessionPolicyRequest::Id(denying))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(policy.ingress, None, "a refusal publishes nothing");

        // Outside a box, with no box named, the command says what it needs
        // rather than guessing a session.
        assert!(std::env::var(SESSION_NAME_ENV).is_err(), "not inside a box");
        let unnamed = cmd_net_expose(
            &daemon.global,
            NetExposeArgs {
                port: 18_480,
                session: None,
            },
        )
        .await
        .expect_err("no box to expose from");
        assert!(format!("{unnamed:#}").contains("--session"), "{unnamed:#}");
    }

    /// The spec's spelling reaches the command with the port intact and
    /// the box left to the environment, as inside a box.
    #[test]
    fn net_expose_parses_the_documented_spelling() {
        use crate::{Cli, Command, NetArgs, NetCommand, Parser as _};

        let cli = Cli::try_parse_from(["min", "net", "expose", "3000"])
            .expect("`min net expose 3000` must parse");
        let Some(Command::Net(NetArgs {
            command: NetCommand::Expose(args),
        })) = cli.command
        else {
            panic!("`min net expose` must reach the expose command");
        };
        assert_eq!(args.port, 3000);
        assert_eq!(args.session, None);
        assert!(
            Cli::try_parse_from(["min", "net", "expose", "web"]).is_err(),
            "the argument is a port"
        );
    }

    /// The setup writes the resolver hook only after the answerer answers:
    /// a listener that replies is seen, and a port nothing listens on is
    /// reported within the wait rather than hung on.
    #[test]
    fn setup_waits_for_the_answerer_before_the_resolver_hook() {
        let stand_in = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let server = stand_in.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            if let Ok((len, peer)) = stand_in.recv_from(&mut buf) {
                // Echo the id with QR set: what any answerer's reply carries.
                buf[2] |= 0x80;
                let _ = stand_in.send_to(&buf[..len], peer);
            }
        });
        assert!(answerer_listening(server, Duration::from_secs(5)));

        let vacant = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let vacant_addr = vacant.local_addr().unwrap();
        drop(vacant);
        let started = Instant::now();
        assert!(!answerer_listening(vacant_addr, Duration::from_secs(1)));
        assert!(started.elapsed() < Duration::from_secs(5), "bounded wait");
    }

    /// The client-side judgement a session start falls back on when the
    /// daemon sends no advisory (every daemon on macOS is a guest): either
    /// half missing is advised with the probe's gap, nothing missing is
    /// silence, and the hook is looked for where the setup writes it.
    #[test]
    fn host_resolution_is_judged_client_side() {
        let unhooked = advisory_from(false, None).expect("a missing hook is advised");
        assert!(!unhooked.resolver_configured && unhooked.range_present);
        assert_eq!(unhooked.range_gap, None);

        let refused = std::net::TcpListener::bind((Ipv4Addr::new(192, 0, 2, 1), 0))
            .expect_err("TEST-NET-1 is on no host's loopback");
        let interim = advisory_from(true, Some((Ipv4Addr::new(192, 0, 2, 1), refused)))
            .expect("an absent range is advised, resolver hook or not");
        assert!(interim.resolver_configured && !interim.range_present);
        let gap = interim.range_gap.expect("the gap names the address");
        assert!(gap.starts_with("192.0.2.1: "), "{gap}");

        assert_eq!(advisory_from(true, None), None, "nothing to advise");

        let hook = resolver_hook_path();
        if cfg!(target_os = "macos") {
            assert_eq!(hook, Path::new(MACOS_RESOLVER_PATH));
        } else {
            assert_eq!(hook, Path::new("/sys/class/net/min0"));
        }
    }

    /// The spelling the spec gives for this command reaches it with both ports
    /// intact — the wiring the two relay tests above take as given.
    #[test]
    fn net_forward_parses_the_documented_spelling() {
        use crate::{Cli, Command, NetArgs, NetCommand, Parser as _};

        let cli = Cli::try_parse_from(["min", "net", "forward", "web", "8080:3000"])
            .expect("`min net forward web 8080:3000` must parse");
        let Some(Command::Net(NetArgs {
            command: NetCommand::Forward(args),
        })) = cli.command
        else {
            panic!("`min net forward` must reach the forward command");
        };
        assert_eq!(args.session, "web");
        assert_eq!(
            parse_forward_spec(&args.ports).unwrap(),
            ForwardSpec {
                local_port: 8080,
                box_port: 3000
            }
        );
    }

    /// The spec is the operator's two ports, and a spelling that names no two
    /// ports is refused rather than half-read.
    #[test]
    fn forward_spec_parses_local_and_box_ports() {
        assert_eq!(
            parse_forward_spec("8080:3000").unwrap(),
            ForwardSpec {
                local_port: 8080,
                box_port: 3000
            }
        );
        for bad in ["8080", "8080:", ":3000", "8080:0", "0:3000", "8080:70000"] {
            assert!(
                parse_forward_spec(bad).is_err(),
                "'{bad}' is not a forward spec"
            );
        }
    }
}
