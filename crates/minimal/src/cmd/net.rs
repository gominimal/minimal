//! `min net …` — bring a box's services to the laptop over the session.

use super::*;

/// How often the forward re-checks that its session is still there.
///
/// The relayed connections close on their own when the daemon tears the
/// session's channels down, but the laptop-side listener is ours: this poll
/// is what makes the forward end with the session instead of outliving it.
const SESSION_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// `min net forward <SESSION> <LOCAL>:<PORT>`: bind `localhost:<LOCAL>` and
/// relay every accepted connection over the session's SSH channel to
/// `127.0.0.1:<PORT>` inside the box.
///
/// Stays in the foreground. Each accepted connection gets its own
/// `direct-tcpip` channel on a session-scoped connection — the SSH username
/// is the session's UUID, which is how the daemon knows which box's loopback
/// to dial — and ends when either side closes it. The forward itself ends on
/// Ctrl-C or when the session goes away (destroyed, or the daemon with it),
/// taking the listener and every open relay down with it.
pub async fn cmd_net_forward(
    global: &GlobalArgs,
    args: NetForwardArgs,
) -> Result<(), anyhow::Error> {
    let (local_port, box_port) = parse_forward_spec(&args.spec)?;
    ensure_daemon(global)?;
    let sock = client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd())
        .context("Failed to resolve daemon socket path")?;
    let mut client = client::Client::connect(&sock)
        .await
        .context("Failed to connect to minimald")?;
    let record = resolve_session_version_gated(&mut client, &args.session).await?;

    // Loopback only: the forward publishes a box's service to the laptop
    // running the command, not to the network the laptop sits on.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", local_port))
        .await
        .with_context(|| format!("forward: cannot listen on localhost:{local_port}"))?;

    // The scoped half of the pair: every direct-tcpip channel opened on this
    // connection is dialed from the session's box.
    let mut box_conn = client::Client::connect_scoped(&sock, record.id)
        .await
        .context("Failed to open the session-scoped connection")?;

    let label = session_announce_label(&record.id, record.name.as_deref());
    eprintln!(
        "Forwarding localhost:{local_port} → 127.0.0.1:{box_port} in session {label}. \
         Ctrl-C to stop."
    );
    tracing::info!(
        session_id = %record.id,
        local_port,
        box_port,
        "net forward opened"
    );

    let session_id = record.id;
    let mut relays: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    let mut poll = tokio::time::interval(SESSION_POLL_INTERVAL);
    loop {
        tokio::select! {
            // Ctrl-C is the manual half of the forward's lifecycle.
            _ = tokio::signal::ctrl_c() => break,

            // The other half: a session that is gone — destroyed, or lost
            // with its daemon — ends the forward rather than leaving a
            // listener that can no longer reach anything.
            _ = poll.tick() => {
                let listed = list_sessions_version_gated(&mut client)
                    .await
                    .is_ok_and(|resp| resp.sessions.iter().any(|s| s.id == session_id));
                if !listed {
                    eprintln!("Session {label} is gone; closing the forward.");
                    break;
                }
            }

            // One direct-tcpip channel per accepted connection.
            accepted = listener.accept() => {
                let (downstream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        tracing::warn!(
                            local_port, box_port, error = %e,
                            "forward listener failed; closing the forward"
                        );
                        break;
                    }
                };
                let channel = match box_conn.open_direct_tcpip("127.0.0.1", box_port).await {
                    Ok(channel) => channel,
                    // The box can refuse (its service not up yet) just as
                    // easily as the session can be mid-teardown; either way
                    // this one connection ends and the forward stands. The
                    // poll arm is what decides the session-gone case.
                    Err(e) => {
                        tracing::warn!(
                            local_port, box_port, %peer, error = %e,
                            "forward connection refused by the box"
                        );
                        continue;
                    }
                };
                relays.push(tokio::spawn(relay(
                    downstream,
                    channel.into_stream(),
                    peer,
                    local_port,
                    box_port,
                )));
            }
        }
    }

    // The forward is over: take the open relays down with the listener
    // rather than leaving them orphaned against a session that is closing.
    for relay in std::mem::take(&mut relays) {
        relay.abort();
    }
    tracing::info!(session_id = %session_id, local_port, box_port, "net forward closed");
    eprintln!("Forward localhost:{local_port} → 127.0.0.1:{box_port} closed.");
    Ok(())
}

/// Copy one accepted laptop-side connection onto its box-side channel, in
/// both directions, until either side closes — logging the open and the
/// close with the ports the forward joins.
async fn relay(
    mut downstream: tokio::net::TcpStream,
    mut upstream: russh::ChannelStream<russh::client::Msg>,
    peer: std::net::SocketAddr,
    local_port: u16,
    box_port: u16,
) {
    tracing::info!(local_port, box_port, %peer, "forward connection opened");
    if let Err(e) = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await {
        tracing::warn!(local_port, box_port, %peer, error = %e, "forward connection failed");
    }
    tracing::info!(local_port, box_port, %peer, "forward connection closed");
}
