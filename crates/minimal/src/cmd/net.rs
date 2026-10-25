//! `min net …` — bring a box's services to the laptop over the session.

use std::sync::Arc;

use nix::sys::signal::Signal;
use tokio::signal::unix::SignalKind;

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
/// The forward follows the *session*, not the box's process. A session
/// record that outlives its box is the normal state after `min stop`, which
/// keeps records, so a forward that refused a box-less session would be
/// stranded against every session that survived a restart. Where the dial
/// has to run inside the box — an isolated session's own network namespace
/// — the daemon brings a box that isn't running up for the dial, exactly as
/// `min session exec` brings one up for a command; a shared-namespace
/// (`host_ip`) box is dialed from the daemon's own namespaces, where no box
/// needs to exist, so a session nothing has started answers with a refused
/// connection instead. What ends the forward is the session ending — it is
/// destroyed, or the daemon it lives behind goes away (the transport is the
/// daemon's, so a `min stop` that succeeds ends the forward with it) — or a
/// Ctrl-C, and the listener and every open relay close with it (NET-105).
///
/// A SIGTERM (a supervisor, a `timeout`, a script's cleanup `kill`) or a
/// SIGHUP (the terminal it runs in closed) closes the forward the same way,
/// then returns a [`Handoff::Raise`]: [`run`] ends the `cmd` span, flushes,
/// and dies of the signal as an uncaught one would have, with no closing
/// line. Without it the process died inside the span, which never ended, so
/// the `cmd` root of every forward stopped this way reached no collector and
/// its spans were orphans.
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
    // running the command, not to the network the laptop sits on. A local
    // port of 0 asks the OS to pick a free port; the bound port is read back
    // so the announcements name the port that is actually listening.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", local_port))
        .await
        .with_context(|| format!("forward: cannot listen on localhost:{local_port}"))?;
    let local_port = listener
        .local_addr()
        .context("forward: cannot read the bound local port")?
        .port();

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

    // Before the announcement, so a caller that waits for it and then sends
    // SIGTERM or SIGHUP always reaches the handler.
    let mut sigterm = signal_stream(SignalKind::terminate());
    let mut sighup = signal_stream(SignalKind::hangup());

    let label = box_announce_label(&record.id, record.name.as_deref());
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
    // Registered once, outside the loop: a fresh `ctrl_c()` per iteration
    // leaves a window between arms where no listener is installed, so a
    // SIGINT landing there is dropped.
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let end = loop {
        tokio::select! {
            // Ctrl-C is the manual half of the forward's lifecycle.
            _ = &mut ctrl_c => break ForwardEnd::Closed,

            // SIGTERM and SIGHUP are the other manual endings; see
            // `ForwardEnd::Terminated`.
            () = next_signal(&mut sigterm) => break ForwardEnd::Terminated(Signal::SIGTERM),
            () = next_signal(&mut sighup) => break ForwardEnd::Terminated(Signal::SIGHUP),

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
                        break ForwardEnd::Closed;
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
                        break ForwardEnd::Closed;
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
                        break ForwardEnd::Closed;
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
    };

    // The forward is over: take the open relays down with the listener
    // rather than leaving them orphaned against a session that is closing.
    for relay in std::mem::take(&mut relays) {
        relay.abort();
    }
    tracing::info!(
        session_id = %session_id,
        local_port,
        box_port,
        terminated = matches!(end, ForwardEnd::Terminated(_)),
        "net forward closed"
    );
    finish_forward(end, local_port, box_port)
}

/// How the forward's loop ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForwardEnd {
    /// Ctrl-C, the session gone, the daemon lost, or the listener failed:
    /// the forward says it closed and the command succeeds.
    Closed,
    /// SIGTERM or SIGHUP. The process dies of it once the `cmd` span has
    /// ended and been flushed ([`Handoff::Raise`]), exactly as it did when
    /// nothing caught the signal: same status, nothing more on the console.
    Terminated(Signal),
}

/// The command's outcome once the forward has closed: a closing line and
/// success, or, after a SIGTERM or SIGHUP, the [`Handoff`] that has [`run`]
/// die of it.
fn finish_forward(end: ForwardEnd, local_port: u16, box_port: u16) -> Result<(), anyhow::Error> {
    match end {
        ForwardEnd::Closed => {
            eprintln!("Forward localhost:{local_port} → 127.0.0.1:{box_port} closed.");
            Ok(())
        }
        ForwardEnd::Terminated(signal) => Err(Handoff::Raise(signal).into()),
    }
}

/// A listener for `kind` in the forward's loop, or `None` when the handler
/// cannot be installed: the signal then keeps its default action and kills
/// the forward where it stands, as before.
fn signal_stream(kind: SignalKind) -> Option<tokio::signal::unix::Signal> {
    tokio::signal::unix::signal(kind).ok()
}

/// Resolve on the next signal `stream` listens for; never, without a
/// listener or once the listener has shut down (`recv` returning `None`), so
/// a select arm on it cannot spin.
async fn next_signal(stream: &mut Option<tokio::signal::unix::Signal>) {
    if let Some(signal) = stream.as_mut()
        && signal.recv().await.is_some()
    {
        return;
    }
    std::future::pending::<()>().await;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A forward closed by Ctrl-C or by its session succeeds, as before.
    #[test]
    fn a_closed_forward_succeeds() {
        finish_forward(ForwardEnd::Closed, 18769, 8769).unwrap();
    }

    /// A forward stopped by SIGTERM or SIGHUP hands `run` that signal to
    /// die of, so the `cmd` span ends and is flushed first (a forward that died
    /// of the signal uncaught left its spans unexported; a closed terminal is
    /// the everyday SIGHUP).
    #[test]
    fn a_terminated_forward_hands_off_its_signal() {
        for signal in [Signal::SIGTERM, Signal::SIGHUP] {
            let Err(err) = finish_forward(ForwardEnd::Terminated(signal), 18769, 8769) else {
                panic!("a forward ended by {signal} must not succeed");
            };
            assert!(
                matches!(err.downcast_ref::<Handoff>(), Some(Handoff::Raise(s)) if *s == signal),
                "{signal}: {err:?}"
            );
        }
    }
}
