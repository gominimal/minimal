//! `min net …` — bring a box's services to the laptop over the session.

use std::sync::Arc;

use super::*;

/// How often the forward re-checks that its session is still there.
///
/// The relayed connections close on their own when the daemon tears the
/// session's channels down, but the laptop-side listener is ours: this poll
/// is what makes the forward end with the session instead of outliving it.
const SESSION_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// What `min net setup` prints when the daemon has no answerer port to point
/// a command at.
const NET_SETUP_NO_PORT: &str =
    "the daemon is not running or has not bound its answerer yet; start a session first";

/// What `min net setup` prints on a host that needs no step.
const NET_SETUP_NOTHING_TO_RUN: &str =
    "This host is already set up to resolve boxes by name; there is nothing to run.";

/// `min net setup`: set this host up to resolve and reach boxes by name
/// (NET-122) by running the command an interactive session start prints,
/// built from the same host reads. The command's own `sudo` is the one
/// privilege prompt. With `--print` it prints the advisory, command block
/// included, and runs nothing.
///
/// The answerer port is the one `min ls` reads: each listed VM's own state
/// from its VM host daemon's control socket (NET-138), else the daemon's
/// listing. It never starts a daemon: with none reachable, or none that
/// reports a port, there is no port to point a command at, so it says so
/// and exits 1.
pub async fn cmd_net_setup(global: &GlobalArgs, args: NetSetupArgs) -> Result<(), anyhow::Error> {
    let listings = match ls_listings(global).await {
        Ok(listings) => listings,
        Err(err) => {
            tracing::debug!("min net setup: no daemon listing: {err:#}");
            Vec::new()
        }
    };
    let mut answerer = None;
    let mut held_no_channel = None;
    for listing in &listings {
        let (port, bound, held) =
            match crate::cmd::session::vm_host_answerer_status_at(listing.control_sock.clone())
                .await
            {
                Some(status) => {
                    let read = crate::resolver::host_answerer_read(status).await;
                    (read.port, read.answerer_bound, read.held_no_channel)
                }
                None => (
                    listing.resp.zone_answerer_port,
                    listing.resp.answerer_bound,
                    false,
                ),
            };
        match port {
            // A port no channel reaches is no daemon's answerer: a session
            // start names that fact instead of the advisory, and so does
            // this, unless another listing reports a port that answers.
            Some(port) if held => held_no_channel = held_no_channel.or(Some(port)),
            Some(port) => {
                answerer = Some((port, bound));
                break;
            }
            None => {}
        }
    }
    let Some((port, bound)) = answerer else {
        match held_no_channel {
            Some(port) => eprintln!("{}", crate::resolver::port_held_no_channel_warning(port)),
            None => eprintln!("{NET_SETUP_NO_PORT}"),
        }
        std::process::exit(1);
    };
    let (detection, answerer_step) = crate::cmd::session::advisory_host_reads(global).await;
    // The range read a session start shares with its advisory, so the two
    // name the same missing facts.
    let range_present =
        crate::resolver::live_name_surface_with_range_at(&detection, Some(port), bound)
            .await
            .and_then(|verdict| verdict.range_present);
    let advisory = crate::resolver::session_advisory_at(
        &detection,
        Some(port),
        false,
        range_present,
        &answerer_step,
    );
    if args.print {
        println!("{}", net_setup_output(advisory.as_deref()));
        return Ok(());
    }
    let Some(advisory) = advisory else {
        println!("{NET_SETUP_NOTHING_TO_RUN}");
        return Ok(());
    };
    let Some((note, command)) = advisory_command(&advisory) else {
        // A blocker: the advisory names what stops every command from
        // reaching host lookups, and there is no command to run.
        eprintln!("{advisory}");
        std::process::exit(1);
    };
    eprintln!("{note}");
    let status = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .status()
        .context("min net setup: could not start /bin/sh to run the setup command")?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

/// What `min net setup --print` prints for an advisory: the advisory whole,
/// or the sentence that says this host needs no step. Pure, so the test
/// asserts it without capturing stdout.
fn net_setup_output(advisory: Option<&str>) -> String {
    advisory.map_or_else(|| NET_SETUP_NOTHING_TO_RUN.to_string(), str::to_string)
}

/// An advisory split into its note line and the command it names: the
/// command starts on the second line, indented two spaces, and runs to the
/// end (the macOS command's heredoc bodies are not indented). `None` for an
/// advisory with no command block, a blocker.
fn advisory_command(advisory: &str) -> Option<(&str, &str)> {
    let (note, rest) = advisory.split_once('\n')?;
    Some((note, rest.strip_prefix("  ").unwrap_or(rest)))
}

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
    // Registered once, outside the loop: a fresh `ctrl_c()` per iteration
    // leaves a window between arms where no listener is installed, so a
    // SIGINT landing there is dropped.
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    loop {
        tokio::select! {
            // Ctrl-C is the manual half of the forward's lifecycle.
            _ = &mut ctrl_c => break,

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

#[cfg(test)]
mod tests {
    use super::*;

    /// NET-122: `min net setup --print` prints the advisory whole, command
    /// block included, and on a host that needs no step says there is
    /// nothing to run.
    #[test]
    fn net_setup_prints_the_advisory_command() {
        let advisory = "note: the resolver file is missing. Configure the host's \
                        resolver with:\n  sudo sh -c 'true'";
        assert_eq!(net_setup_output(Some(advisory)), advisory);
        assert_eq!(net_setup_output(None), NET_SETUP_NOTHING_TO_RUN);
    }

    /// NET-122: `min net setup` runs exactly the command the advisory names:
    /// the block after the note, de-indented on its first line only, so a
    /// multi-line command's heredoc bodies run byte for byte. A blocker
    /// names no command, so there is nothing to run.
    #[test]
    fn net_setup_runs_the_advisory_command() {
        let advisory = "note: the range is missing. Configure the host's resolver and \
                        reserve the local range with:\n  sudo sh -c 'set -e; cat > /x <<\\EOF\n\
                        body line\nEOF\nchmod 0755 /x'";
        let (note, command) = advisory_command(advisory).unwrap();
        assert!(note.starts_with("note: the range is missing."), "{note}");
        assert_eq!(
            command,
            "sudo sh -c 'set -e; cat > /x <<\\EOF\nbody line\nEOF\nchmod 0755 /x'"
        );
        assert_eq!(
            advisory_command("note: host lookups bypass the resolver."),
            None
        );
    }
}
