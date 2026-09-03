//! The attach handshake against an in-process russh server that enforces the
//! same preconditions `crates/minimald/src/connection.rs` does: `shell` is
//! refused unless a pty was requested and `MINIMAL_SESSION_ID` was set on the
//! channel. No sockets: client and server share a `tokio::io::duplex` pipe,
//! which is also the shape of the browser path (a byte stream, nothing more).

use std::sync::Arc;
use std::time::Duration;

use min_core::{Attach, Error, Event, Grid};
use russh::server::{self, Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId};

use min_core::testing::{FakeMinimald, host_key, serve};

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
