//! `min net forward`: a local listener relayed into a box over its session.
//!
//! The forward is an `ssh -L` with a session in place of a host. A listener
//! on this machine's loopback accepts connections and relays each one over a
//! `direct-tcpip` channel the daemon serves, so a server inside the box
//! answers on `localhost` here with nothing installed in between (NET-104).
//! The listener lives as long as the session does (NET-105).

use std::future::Future;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use tokio::net::{TcpListener, TcpStream};

use crate::{GlobalArgs, NetForwardArgs, client, cmd};

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
