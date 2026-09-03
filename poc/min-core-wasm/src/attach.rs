//! The `min session attach` sequence, transport-agnostic.
//!
//! Mirrors what `crates/minimal-client` does today through the system `ssh`
//! binary (`attach.rs`) and what `crates/minimald/src/connection.rs` expects
//! on the other end: `auth_none` under local trust, then on one session
//! channel `env MINIMAL_SESSION_ID=<uuid>` → `pty-req` → `shell`. Resize is a
//! `window-change` on the same channel, which the session host consumes as
//! `ChannelMsg::WindowChange`.

use std::sync::Arc;

use bytes::Bytes;
use russh::{ChannelReadHalf, ChannelWriteHalf};
use russh::client::{self, Msg};
use russh::keys::PublicKeyOrCertificate;
use russh::{Channel, ChannelMsg};
use tokio::io::{AsyncRead, AsyncWrite};

/// Env var minimald reads the session id from (`MINIMAL_SESSION_ID_ENV` in
/// `crates/minimald`).
pub const MINIMAL_SESSION_ID_ENV: &str = "MINIMAL_SESSION_ID";
/// SSH username `minimal-client` authenticates with.
pub const SSH_USER: &str = "minimal-cli";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ssh: {0}")]
    Ssh(#[from] russh::Error),
    #[error("authentication rejected by daemon")]
    AuthRejected,
    #[error("daemon rejected the {0} request")]
    Rejected(&'static str),
    #[error("channel closed before the shell was established")]
    ClosedEarly,
}

/// Accepts any host key: the same posture as `minimal-client` on the UDS,
/// where the transport itself is the trust boundary. Gatehouse host
/// certificates replace this in Milestone 2.
pub struct TrustTransport;

impl client::Handler for TrustTransport {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grid {
    pub cols: u32,
    pub rows: u32,
}

#[derive(Debug)]
pub enum Event {
    /// PTY output.
    Data(Bytes),
    /// Extended data on stream 1, where the daemon writes handler errors.
    Stderr(Bytes),
    /// The session shell exited.
    Exit(u32),
    Eof,
    Closed,
}

/// An attached session shell: the channel after `shell` was accepted.
pub struct Attach {
    handle: client::Handle<TrustTransport>,
    channel: Channel<Msg>,
}

impl Attach {
    /// Run the handshake over `stream`, whatever it is: a `UnixStream` to the
    /// daemon socket natively, a WebSocket-to-UDS relay in the browser.
    pub async fn connect<S>(
        stream: S,
        session_id: &str,
        term: &str,
        grid: Grid,
    ) -> Result<Self, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // Defaults keep `keepalive_interval` and `inactivity_timeout` at
        // `None`. That matters on wasm: russh drives both with `tokio::time`,
        // which has no driver in a browser.
        let config = Arc::new(client::Config::default());
        let mut handle = client::connect_stream(config, stream, TrustTransport).await?;
        if !handle.authenticate_none(SSH_USER).await?.success() {
            return Err(Error::AuthRejected);
        }
        let mut channel = handle.channel_open_session().await?;
        channel
            .set_env(true, MINIMAL_SESSION_ID_ENV, session_id)
            .await?;
        channel
            .request_pty(true, term, grid.cols, grid.rows, 0, 0, &[])
            .await?;
        channel.request_shell(true).await?;
        // Three want_reply requests, three replies in order. minimald answers
        // `shell` with CHANNEL_FAILURE when the pty or session id is missing.
        for request in ["env", "pty-req", "shell"] {
            await_reply(&mut channel, request).await?;
        }
        Ok(Self { handle, channel })
    }

    /// Split into the two halves a UI needs: one task pumps `Reader` into the
    /// terminal, the input and resize paths call `Writer` from anywhere.
    pub fn split(self) -> (Writer, Reader) {
        let (read, write) = self.channel.split();
        (
            Writer {
                half: write,
                _handle: self.handle,
            },
            Reader { half: read },
        )
    }
}

async fn await_reply(channel: &mut Channel<Msg>, request: &'static str) -> Result<(), Error> {
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => return Ok(()),
            Some(ChannelMsg::Failure) => return Err(Error::Rejected(request)),
            Some(ChannelMsg::Close) | None => return Err(Error::ClosedEarly),
            Some(_) => continue,
        }
    }
}

pub struct Reader {
    half: ChannelReadHalf,
}

impl Reader {
    /// Next terminal-relevant event, or `None` once the channel is gone.
    pub async fn next(&mut self) -> Option<Event> {
        loop {
            return Some(match self.half.wait().await? {
                ChannelMsg::Data { data } => Event::Data(data),
                ChannelMsg::ExtendedData { data, ext: 1 } => Event::Stderr(data),
                ChannelMsg::ExitStatus { exit_status } => Event::Exit(exit_status),
                ChannelMsg::Eof => Event::Eof,
                ChannelMsg::Close => Event::Closed,
                _ => continue,
            });
        }
    }
}

pub struct Writer {
    half: ChannelWriteHalf<Msg>,
    // Dropping the handle ends the session task; the writer owns it so the
    // connection lives as long as the UI can still type into it.
    _handle: client::Handle<TrustTransport>,
}

impl Writer {
    pub async fn write(&self, bytes: &[u8]) -> Result<(), Error> {
        self.half.data(bytes).await?;
        Ok(())
    }

    pub async fn resize(&self, grid: Grid) -> Result<(), Error> {
        self.half.window_change(grid.cols, grid.rows, 0, 0).await?;
        Ok(())
    }

    pub async fn close(&self) -> Result<(), Error> {
        self.half.eof().await?;
        self.half.close().await?;
        Ok(())
    }
}
