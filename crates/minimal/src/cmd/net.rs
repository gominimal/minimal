//! `min net …` — bring a box's services to the laptop over the session.

use std::sync::Arc;

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
/// to dial — and ends when either side closes it.
///
/// The forward follows the *session*, not the box's process. A box whose
/// process is down — never started, exited with its entrypoint, or stopped by
/// a daemon shutdown — is brought up to serve the forward, exactly as
/// `min session attach` brings one up to serve a terminal: a session record
/// that outlives its box is the normal state after `min stop`, which keeps
/// records, so refusing would strand a forward against every session that
/// survived a restart. What ends the forward is the session ending — it is
/// destroyed, or the daemon it lives behind goes away (the transport is the
/// daemon's, so a `min stop` that succeeds ends the forward with it) — or a
/// Ctrl-C, and the listener and every open relay close with it (NET-105).
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
    // connection is dialed from the session's box. Shared behind a mutex
    // because the SSH connection answers one channel open at a time — the
    // per-connection tasks below each take it in turn to open their channel,
    // so a slow open delays only its own connection.
    let box_conn = Arc::new(tokio::sync::Mutex::new(
        client::Client::connect_scoped(&sock, record.id)
            .await
            .context("Failed to open the session-scoped connection")?,
    ));

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
            // listener that can no longer reach anything. The record is what
            // the poll keys on, because the record is the session: it is what
            // a destroy removes and what a daemon stop keeps.
            _ = poll.tick() => {
                match list_sessions_version_gated(&mut client).await {
                    Ok(resp) if resp.sessions.iter().any(|s| s.id == session_id) => {}
                    Ok(_) => {
                        eprintln!("Session {label} is gone; closing the forward.");
                        break;
                    }
                    // The list itself failed, which means the daemon is no
                    // longer there to answer it. A different ending than the
                    // session's own, so it says so rather than blaming the
                    // session; the cause is in the log, not the console line.
                    Err(e) => {
                        tracing::warn!(
                            local_port, box_port, error = %e,
                            "forward lost the daemon; closing the forward"
                        );
                        eprintln!(
                            "The daemon is no longer reachable; closing the forward."
                        );
                        break;
                    }
                }
            }

            // One direct-tcpip channel per accepted connection, opened in
            // the connection's own task rather than here: a slow open — a box
            // that has to come up first — would otherwise hold the accept
            // arm and the session poll with it.
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
                // Live handles only: a long-lived forward serves many
                // short-lived connections, and the finished ones are dropped
                // here rather than accumulating until the whole forward ends.
                relays.retain(|relay| !relay.is_finished());
                let conn = Arc::clone(&box_conn);
                relays.push(tokio::spawn(open_and_relay(
                    conn, downstream, peer, local_port, box_port,
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

/// Open one accepted connection's `direct-tcpip` channel, then relay it.
///
/// The open is part of the per-connection task, not the accept arm, so a
/// connection whose channel is slow to open — a box being brought up for it
/// — waits on its own rather than stalling every later connection and the
/// forward's session poll. See [`cmd_net_forward`].
async fn open_and_relay(
    conn: Arc<tokio::sync::Mutex<client::Client>>,
    downstream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    local_port: u16,
    box_port: u16,
) {
    // The lock is held for the open alone: the relay below runs beside every
    // other connection's, once each has its channel.
    let channel = {
        let mut conn = conn.lock().await;
        conn.open_direct_tcpip("127.0.0.1", box_port).await
    };
    let channel = match channel {
        Ok(channel) => channel,
        // The box can refuse (its service not up yet) just as easily as the
        // session can be mid-teardown; either way this one connection ends
        // and the forward stands. The poll arm is what decides the
        // session-gone case.
        Err(e) => {
            tracing::warn!(
                local_port, box_port, %peer, error = %e,
                "forward connection refused by the box"
            );
            return;
        }
    };
    relay(
        downstream,
        channel.into_stream(),
        peer,
        local_port,
        box_port,
    )
    .await;
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
