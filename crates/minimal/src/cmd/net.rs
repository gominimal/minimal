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
/// (NET-122), an opt-in step a session start only points at. It builds the
/// privileged script from this host's reads, prints the note saying what
/// is missing, and runs the script as root with `sudo sh <file>` — the
/// script's one privilege prompt. With `--print` it prints the script and
/// runs nothing. With `--undo` the script removes everything the step
/// installs instead (see [`cmd_net_setup_undo`]).
///
/// The answerer port is the one `min ls` reads: each listed VM's own state
/// from its VM host daemon's control socket (NET-138), else the daemon's
/// listing. It never starts a daemon: with none reachable, or none that
/// reports a port, there is no port to point a script at, so it says so
/// and exits 1.
pub async fn cmd_net_setup(global: &GlobalArgs, args: NetSetupArgs) -> Result<(), anyhow::Error> {
    if args.undo {
        return cmd_net_setup_undo(args.print);
    }
    let listings = ls_listings_best_effort(global).await;
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
            // A port no channel reaches is no daemon's answerer: say that
            // fact instead of a script, unless another listing reports a
            // port that answers.
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
    // The range read the live-surface verdict makes, so the note names the
    // same missing facts the surface line reports.
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
    let Some(advisory) = advisory else {
        eprintln!("{NET_SETUP_NOTHING_TO_RUN}");
        return Ok(());
    };
    let Some((note, script)) = advisory_command(&advisory) else {
        // A blocker: the advisory names what stops every script from
        // reaching host lookups, and there is no script to print or run.
        eprintln!("{advisory}");
        std::process::exit(1);
    };
    eprintln!("{note}");
    if args.print {
        print!("{script}");
        return Ok(());
    }
    // The installed service runs as one operator; replacing another user's
    // is not this user's call (spec 18's open question on several users).
    if let Some(refusal) = crate::resolver::other_operator_refusal_on_this_host() {
        eprintln!("min net setup: {refusal}");
        std::process::exit(1);
    }
    run_as_root(script)
}

/// `min net setup --undo`: remove everything the setup step installs on
/// this host (NET-122's removal). The script reads no daemon and needs no
/// answerer port, so it works with nothing running, and every step of it
/// tolerates what is already gone, so it succeeds on a clean host. With
/// `print` it prints the script and runs nothing.
fn cmd_net_setup_undo(print: bool) -> Result<(), anyhow::Error> {
    let script = crate::resolver::undo_command();
    if print {
        print!("{script}");
        return Ok(());
    }
    run_as_root(&script)
}

/// Runs a host-setup script as root: written to a private temp file —
/// created exclusively, mode 0600, so no other user can read or swap it —
/// and run with `sudo sh <file>`, whose prompt is the one privilege prompt.
/// The file is removed once the script exits, and the process exits with
/// the script's status. The script is the one `--print` prints, byte for
/// byte, so the printed and the run steps cannot diverge.
fn run_as_root(script: &str) -> Result<(), anyhow::Error> {
    use std::io::Write as _;
    let mut file = tempfile::Builder::new()
        .prefix("min-net-setup-")
        .suffix(".sh")
        .tempfile()
        .context("min net setup: could not create a private file for the setup script")?;
    file.write_all(script.as_bytes())
        .and_then(|()| file.flush())
        .context("min net setup: could not write the setup script")?;
    let status = std::process::Command::new("sudo")
        .arg("sh")
        .arg(file.path())
        .status()
        .context("min net setup: could not start sudo to run the setup script")?;
    // Removed before the exit below, which runs no destructor.
    file.close()
        .context("min net setup: could not remove the setup script")?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

/// An advisory split into its note line and the script it names: the note
/// is the first line, the script the rest, starting at its `#!/bin/sh`.
/// `None` for an advisory with no script, a blocker.
fn advisory_command(advisory: &str) -> Option<(&str, &str)> {
    let (note, script) = advisory.split_once('\n')?;
    script.starts_with("#!/bin/sh").then_some((note, script))
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

    /// NET-122: `min net setup` runs, and `--print` prints, exactly the
    /// script the advisory names: everything after the note line, from its
    /// `#!/bin/sh`, byte for byte, so a script's heredoc bodies reach the
    /// root shell as rendered. A blocker names no script, so there is
    /// nothing to print or run.
    #[test]
    fn net_setup_runs_the_advisory_script() {
        let script = "#!/bin/sh\n# Configure the host's resolver.\nset -eu\n\
                      cat > /x <<\\EOF\nbody line\nEOF\nchmod 0755 /x\n";
        let advisory = format!("note: the range is missing.\n{script}");
        let (note, split) = advisory_command(&advisory).unwrap();
        assert_eq!(note, "note: the range is missing.");
        assert_eq!(split, script);
        assert_eq!(
            advisory_command("note: host lookups bypass the resolver."),
            None
        );
        assert_eq!(advisory_command("note: one.\nnot a script"), None);
    }
}
