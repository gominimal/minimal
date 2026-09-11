//! The `min session attach` sequence, transport-agnostic.
//!
//! Mirrors what `crates/minimal-client` does today through the system `ssh`
//! binary (`attach.rs`) and what `crates/minimald/src/connection.rs` expects
//! on the other end: `auth_none` under local trust, then on one session
//! channel `env MINIMAL_SESSION_ID=<uuid>` → `pty-req` → `shell`. Resize is a
//! `window-change` on the same channel, which the session host consumes as
//! `ChannelMsg::WindowChange`.

use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use russh::client::{self, Msg};
use russh::keys::{Algorithm, PublicKeyOrCertificate};
use russh::{Channel, ChannelMsg, ChannelReadHalf, ChannelWriteHalf};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::credential::{Credential, HostPolicy, RawSigner, SshSigner};
use crate::rt;

/// Env var minimald reads the session id from (`MINIMAL_SESSION_ID_ENV` in
/// `crates/minimald`).
pub const MINIMAL_SESSION_ID_ENV: &str = "MINIMAL_SESSION_ID";
/// SSH username `minimal-client` authenticates with.
pub const SSH_USER: &str = "minimal-cli";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ssh: {0}")]
    Ssh(#[from] russh::Error),
    #[error("host rejected: {0}")]
    HostRejected(String),
    #[error("authentication rejected by daemon")]
    AuthRejected,
    #[error("{0}")]
    Sign(#[from] crate::credential::SignError),
    #[error("daemon rejected the {0} request")]
    Rejected(&'static str),
    #[error("channel closed before the shell was established")]
    ClosedEarly,
}

/// Host trust. Without a policy: accept any key, the `minimal-client`
/// posture on a UDS where the transport is the trust boundary. With one: the
/// host must present a certificate that passes [`HostPolicy::check`]; the
/// reason for a refusal is kept so the caller can report it, since russh
/// only sees the handshake abort.
pub struct HostTrust {
    policy: Option<HostPolicy>,
    rejection: Arc<Mutex<Option<String>>>,
}

impl client::Handler for HostTrust {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let Some(policy) = &self.policy else {
            return Ok(true);
        };
        match policy.check(key, rt::unix_now()) {
            Ok(()) => Ok(true),
            Err(e) => {
                *self.rejection.lock().unwrap() = Some(format!("{} ({})", e, e.code()));
                Ok(false)
            }
        }
    }
}

/// How to authenticate and what to demand of the host.
pub struct ConnectOptions<'a, S> {
    pub session_id: &'a str,
    pub term: &'a str,
    pub grid: Grid,
    /// `None`: `auth_none` as `minimal-cli` (the UDS posture).
    pub credential: Option<Credential<S>>,
    /// `None`: accept any host key.
    pub host_policy: Option<HostPolicy>,
}

/// A signer type for the `None`-credential case.
pub struct NoSigner;

impl RawSigner for NoSigner {
    fn sign_raw(&mut self, _data: &[u8]) -> impl Future<Output = Result<Vec<u8>, String>> + Send {
        async { Err("no signer".to_string()) }
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
    handle: client::Handle<HostTrust>,
    channel: Channel<Msg>,
}

impl Attach {
    /// `auth_none` as `minimal-cli`, any host key: the UDS posture.
    pub async fn connect<T>(stream: T, session_id: &str, term: &str, grid: Grid) -> Result<Self, Error>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::connect_with(
            stream,
            ConnectOptions::<NoSigner> {
                session_id,
                term,
                grid,
                credential: None,
                host_policy: None,
            },
        )
        .await
    }

    /// Run the handshake over `stream`, whatever it is: a `UnixStream` to the
    /// daemon socket natively, a TCP socket inside a WireGuard tunnel in the
    /// browser. With a credential, authenticate with the certificate and sign
    /// through its signer; with a host policy, refuse any host that does not
    /// present an acceptable certificate.
    pub async fn connect_with<T, S>(stream: T, opts: ConnectOptions<'_, S>) -> Result<Self, Error>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        S: RawSigner,
    {
        // Defaults keep `keepalive_interval` and `inactivity_timeout` at
        // `None`. That matters on wasm: russh drives both with `tokio::time`,
        // which has no driver in a browser.
        let mut config = client::Config::default();
        if opts.host_policy.is_some() {
            // Offer the certificate host-key algorithm, so a host that has a
            // certificate presents it rather than its bare key.
            config.preferred.host_key_certificates = Cow::Owned(vec![Algorithm::Ed25519]);
        }
        let rejection = Arc::new(Mutex::new(None));
        let handler = HostTrust {
            policy: opts.host_policy,
            rejection: rejection.clone(),
        };
        let mut handle = match client::connect_stream(Arc::new(config), stream, handler).await {
            Ok(h) => h,
            Err(e) => {
                if let Some(reason) = rejection.lock().unwrap().take() {
                    return Err(Error::HostRejected(reason));
                }
                return Err(e.into());
            }
        };
        let authenticated = match opts.credential {
            None => handle.authenticate_none(SSH_USER).await?.success(),
            Some(cred) => {
                let algorithm = cred.algorithm();
                let mut signer = SshSigner::new(cred.signer, algorithm);
                handle
                    .authenticate_certificate_with(cred.username.as_str(), cred.certificate, None, &mut signer)
                    .await?
                    .success()
            }
        };
        if !authenticated {
            return Err(Error::AuthRejected);
        }
        let session_id = opts.session_id;
        let term = opts.term;
        let grid = opts.grid;
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
    _handle: client::Handle<HostTrust>,
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
