//! The attach handshake against an in-process russh server that enforces the
//! same preconditions `crates/minimald/src/connection.rs` does: `shell` is
//! refused unless a pty was requested and `MINIMAL_SESSION_ID` was set on the
//! channel. No sockets: client and server share a `tokio::io::duplex` pipe,
//! which is also the shape of the browser path (a byte stream, nothing more).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use min_core::{Attach, Error, Event, Grid, MINIMAL_SESSION_ID_ENV};
use russh::keys::PrivateKey;
use russh::server::{self, Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId};

#[derive(Default)]
struct FakeMinimald {
    env: HashMap<ChannelId, HashMap<String, String>>,
    pty: HashSet<ChannelId>,
    grid: HashMap<ChannelId, (u32, u32)>,
}

impl server::Handler for FakeMinimald {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn env_request(
        &mut self,
        id: ChannelId,
        name: &str,
        value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.env
            .entry(id)
            .or_default()
            .insert(name.to_string(), value.to_string());
        session.channel_success(id)
    }

    async fn pty_request(
        &mut self,
        id: ChannelId,
        _term: &str,
        cols: u32,
        rows: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.pty.insert(id);
        self.grid.insert(id, (cols, rows));
        session.channel_success(id)
    }

    async fn shell_request(&mut self, id: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        let session_id = self
            .env
            .get(&id)
            .and_then(|env| env.get(MINIMAL_SESSION_ID_ENV))
            .cloned();
        match (self.pty.contains(&id), session_id) {
            (true, Some(session_id)) => {
                session.channel_success(id)?;
                let (cols, rows) = self.grid[&id];
                session.data(id, format!("attached {session_id} {cols}x{rows}\r\n"))
            }
            _ => session.channel_failure(id),
        }
    }

    async fn window_change_request(
        &mut self,
        id: ChannelId,
        cols: u32,
        rows: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.grid.insert(id, (cols, rows));
        session.data(id, format!("resize {cols}x{rows}\r\n"))
    }

    async fn data(&mut self, id: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        if data == b"exit\n" {
            // All three through the handle so they are queued in order; mixing
            // the async handle with the sync `Session` methods sends close first.
            let handle = session.handle();
            let _ = handle.exit_status_request(id, 7).await;
            let _ = handle.eof(id).await;
            let _ = handle.close(id).await;
            return Ok(());
        }
        let mut echo = b"echo ".to_vec();
        echo.extend_from_slice(data);
        session.data(id, echo)
    }
}

fn host_key() -> PrivateKey {
    let dir = tempdir();
    let path = dir.join("host_ed25519");
    let status = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&path)
        .status()
        .expect("ssh-keygen on PATH");
    assert!(status.success(), "ssh-keygen failed");
    let pem = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    PrivateKey::from_openssh(pem).unwrap()
}

fn tempdir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("min-core-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Client end of a pipe whose server end runs `FakeMinimald`.
fn serve() -> tokio::io::DuplexStream {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let config = Arc::new(server::Config {
        keys: vec![host_key()],
        ..Default::default()
    });
    tokio::spawn(async move {
        let running = server::run_stream(config, server_io, FakeMinimald::default())
            .await
            .expect("server handshake");
        let _ = running.await;
    });
    client_io
}

async fn next_text(reader: &mut min_core::Reader) -> String {
    match tokio::time::timeout(Duration::from_secs(5), reader.next()).await {
        Ok(Some(Event::Data(bytes))) => String::from_utf8(bytes.to_vec()).unwrap(),
        other => panic!("expected data, got {other:?}"),
    }
}

#[tokio::test]
async fn attach_write_resize_exit() {
    let attached = Attach::connect(serve(), "sess-1", "xterm-256color", Grid { cols: 80, rows: 24 })
        .await
        .expect("attach handshake");
    let (writer, mut reader) = attached.split();

    assert_eq!(next_text(&mut reader).await, "attached sess-1 80x24\r\n");

    writer.write(b"hello\n").await.unwrap();
    assert_eq!(next_text(&mut reader).await, "echo hello\n");

    writer.resize(Grid { cols: 100, rows: 30 }).await.unwrap();
    assert_eq!(next_text(&mut reader).await, "resize 100x30\r\n");

    writer.write(b"exit\n").await.unwrap();
    let mut seen = Vec::new();
    while let Ok(Some(event)) = tokio::time::timeout(Duration::from_secs(5), reader.next()).await {
        let is_close = matches!(event, Event::Closed);
        seen.push(format!("{event:?}"));
        if is_close {
            break;
        }
    }
    assert!(
        seen.iter().any(|e| e == "Exit(7)"),
        "exit status should be reported: {seen:?}"
    );
    assert_eq!(seen.last().map(String::as_str), Some("Closed"), "{seen:?}");
}

#[tokio::test]
async fn shell_is_refused_without_a_session_id() {
    // An empty id still sends the env request, but our fake (like minimald)
    // only accepts `shell` when the id it stored parses; an empty string is
    // stored, so drive the refusal from the pty side instead: the handshake
    // always sends pty-req, so refuse via a server that never saw env.
    let err = Attach::connect(serve_without_env(), "sess-2", "xterm", Grid { cols: 1, rows: 1 })
        .await
        .err()
        .expect("shell must be refused");
    assert!(matches!(err, Error::Rejected("env") | Error::Rejected("shell")), "{err}");
}

/// A server that drops env requests on the floor (answers failure), so the
/// handshake's `env` reply is the first refusal the client sees.
fn serve_without_env() -> tokio::io::DuplexStream {
    struct NoEnv(FakeMinimald);
    impl server::Handler for NoEnv {
        type Error = russh::Error;
        async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
            self.0.auth_none(user).await
        }
        async fn channel_open_session(
            &mut self,
            channel: Channel<Msg>,
            reply: ChannelOpenHandle,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            self.0.channel_open_session(channel, reply, session).await
        }
        async fn env_request(
            &mut self,
            id: ChannelId,
            _name: &str,
            _value: &str,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            session.channel_failure(id)
        }
        async fn pty_request(
            &mut self,
            id: ChannelId,
            term: &str,
            cols: u32,
            rows: u32,
            pw: u32,
            ph: u32,
            modes: &[(russh::Pty, u32)],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            self.0.pty_request(id, term, cols, rows, pw, ph, modes, session).await
        }
        async fn shell_request(&mut self, id: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
            self.0.shell_request(id, session).await
        }
    }
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let config = Arc::new(server::Config {
        keys: vec![host_key()],
        ..Default::default()
    });
    tokio::spawn(async move {
        let running = server::run_stream(config, server_io, NoEnv(FakeMinimald::default()))
            .await
            .expect("server handshake");
        let _ = running.await;
    });
    client_io
}
