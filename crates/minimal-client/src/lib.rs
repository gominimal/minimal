//! SSH client transport for talking to minimald over the UDS bridge.
//!
//! Provides a `russh`-based client that connects to `minimald` over the UNIX
//! domain socket, authenticates (passwordless), and invokes oneshot RPCs
//! defined in the `minimald-rpc` wire contract.

pub mod attach;
pub mod file_upload;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use minimald_rpc::OneshotSshRpc;

/// The process-wide trace context, minted once at command dispatch. The
/// root span carries its ids into every log line, and the SSH client sends
/// the same context to the daemon as a `TRACEPARENT` channel env request —
/// one grep joins host and guest records.
pub fn trace_context() -> &'static minimald_rpc::trace::TraceContext {
    static CONTEXT: std::sync::OnceLock<minimald_rpc::trace::TraceContext> =
        std::sync::OnceLock::new();
    CONTEXT.get_or_init(minimald_rpc::trace::TraceContext::mint)
}

/// Build a spinner bar on the process-global `MultiProgress` with the house
/// animation and a caller-chosen `template`.
///
/// Bars must be inserted before any style/message/tick configuration —
/// otherwise `ProgressBar::hidden`'s defaults would draw directly to stderr
/// and MP's coordinated redraws couldn't reach the stale lines
/// (`finish_and_clear` only wipes lines MP itself drew).
///
/// Animation: three quadrant-block glyphs (`▗`, then `▚`, then `▚`)
/// appear one at a time from left to right, hold for ~1 s, then
/// disappear one at a time from right to left. Every frame is padded
/// to the same 5-character width so the trailing `{msg}` doesn't
/// jitter horizontally as the animation grows and shrinks. The last
/// entry in `tick_strings` is indicatif's "finished" state — kept
/// blank so `bar.finish()` / `finish_and_clear` leave no trailing
/// glyphs behind.
fn spinner_bar(msg: &'static str, template: &str) -> indicatif::ProgressBar {
    const FRAMES: &[&str] = &[
        // build
        "     ",
        "▗    ",
        "▗ ▚  ",
        "▗ ▚ ▚",
        // hold ~1 s at 100 ms/tick
        "▗ ▚ ▚",
        "▗ ▚ ▚",
        "▗ ▚ ▚",
        "▗ ▚ ▚",
        "▗ ▚ ▚",
        "▗ ▚ ▚",
        "▗ ▚ ▚",
        "▗ ▚ ▚",
        "▗ ▚ ▚",
        "▗ ▚ ▚",
        // fade (mirrors the build, right-to-left)
        "▗ ▚  ",
        "▗    ",
        "     ",
        // finished
        "     ",
    ];
    let bar = ot::global_progress().add(indicatif::ProgressBar::hidden());
    bar.set_style(
        indicatif::ProgressStyle::with_template(template)
            .expect("valid template")
            .tick_strings(FRAMES),
    );
    bar.set_message(msg);
    bar.enable_steady_tick(Duration::from_millis(100));
    bar
}

/// Spinner bar for a byte-counted upload: `  {spinner} {msg} — {bytes} …`.
pub fn add_spinner_bar(msg: &'static str) -> indicatif::ProgressBar {
    spinner_bar(msg, "  {spinner} {msg} — {bytes} ({bytes_per_sec})")
}

/// Spinner bar for a plain narrated wait with no counter, rendering
/// `  {spinner} {msg}` — the daemon autospawn wait uses it while the VM boots.
pub fn add_wait_spinner_bar(msg: &'static str) -> indicatif::ProgressBar {
    spinner_bar(msg, "  {spinner} {msg}")
}

/// Add a file-count progress bar to the process-global `MultiProgress`.
/// Same insertion-before-configuration rationale as [`add_spinner_bar`].
///
/// Bar rendering: a leading `▗` followed by up to [`PATCHES_BAR_TAIL_UNITS`]
/// `" ▚"` units, growing left-to-right in proportion to `pos / len`.
/// Sequence at increasing progress: `▗` → `▗ ▚ ▚` → `▗ ▚ ▚ ▚ ▚ ▚ ▚ ▚ ▚ ▚`
/// → `▗ ▚ ▚ …`. Indicatif's built-in `{wide_bar}` renders one glyph per
/// cell with no way to insert spaces between filled cells, so this
/// registers a custom `{tail}` key and formats the string ourselves.
/// The un-filled tail is padded with `"  "` (matching the width of a
/// `" ▚"` unit) so `{pos}/{len}` etc. stay in a fixed column.
fn add_patches_bar(total: u64) -> indicatif::ProgressBar {
    /// Max number of `" ▚"` units at 100 % progress. Widen for a
    /// longer bar; narrow for tighter terminals.
    const PATCHES_BAR_TAIL_UNITS: usize = 30;

    let bar = ot::global_progress().add(indicatif::ProgressBar::hidden());
    bar.set_length(total);
    bar.set_style(
        indicatif::ProgressStyle::with_template(
            "  {msg} {tail} {pos}/{len} patches ({per_sec}, {eta})",
        )
        .expect("valid template")
        .with_key(
            "tail",
            |state: &indicatif::ProgressState, w: &mut dyn std::fmt::Write| {
                let progress = state
                    .len()
                    .filter(|&l| l > 0)
                    .map(|len| (state.pos() as f64) / (len as f64))
                    .unwrap_or(0.0)
                    .clamp(0.0, 1.0);
                let filled = (progress * PATCHES_BAR_TAIL_UNITS as f64).round() as usize;
                let _ = w.write_str("▗");
                for _ in 0..filled {
                    let _ = w.write_str(" ▚");
                }
                // Pad each un-filled unit with two spaces so total
                // rendered width stays constant across the animation.
                for _ in 0..(PATCHES_BAR_TAIL_UNITS - filled) {
                    let _ = w.write_str("  ");
                }
            },
        ),
    );
    bar.set_message("Uploading composition patches");
    bar
}

/// Max retries when connecting to the daemon UDS.
const CONNECT_RETRIES: u32 = 20;
/// Delay between connection retries.
const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(100);
/// Deadline for the SSH handshake + auth once the socket has accepted.
///
/// A connect is not proof that anyone is home: on the VM backend the socket is
/// libkrun's bridge, which accepts even when the guest behind it is wedged, so
/// only a completed handshake proves there is a live server. Without a deadline
/// the CLI blocks there forever (#730). Generous — a healthy endpoint answers in
/// milliseconds, so this only bounds the pathological case. Mirrors `minvmd`'s
/// own client, which guards the same bridge.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Deadline for a whole oneshot RPC round-trip.
///
/// The handshake deadline covers a peer that never speaks SSH; it does not
/// cover a peer that handshakes and then wedges (a suspended microVM behind
/// libkrun's always-accepting bridge), where the reply wait would block
/// forever. Generous — a healthy daemon answers in milliseconds, so this
/// only bounds the pathological case.
const RPC_TIMEOUT: Duration = Duration::from_secs(60);

/// russh client handler that accepts any ephemeral host key.
///
/// The daemon generates a fresh host key on every boot. Since we connect over
/// a local UDS (not the network), TOFU trust is acceptable here.
struct MinimalClientHandler;

impl russh::client::Handler for MinimalClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// An authenticated SSH session to minimald.
pub struct Client {
    handle: russh::client::Handle<MinimalClientHandler>,
}

impl Client {
    /// Connect to minimald over the UDS at `sock_path`, authenticate, and
    /// return a ready [`Client`].
    ///
    /// Retries the UDS connect for up to ~2 seconds to absorb the post-boot
    /// race on macOS where the libkrun bridge UDS appears slightly after the
    /// `vm-up` line, and bounds the handshake by [`HANDSHAKE_TIMEOUT`] so a
    /// wedged daemon behind an accepting socket fails instead of hanging.
    pub async fn connect(sock_path: &Path) -> Result<Self, anyhow::Error> {
        let stream = {
            let mut conn = None;
            let mut last_err = None;
            for _ in 0..CONNECT_RETRIES {
                match tokio::net::UnixStream::connect(sock_path).await {
                    Ok(s) => {
                        conn = Some(s);
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        tokio::time::sleep(CONNECT_RETRY_DELAY).await;
                    }
                }
            }
            conn.ok_or_else(|| {
                anyhow::anyhow!(
                    "connect to daemon at {}: {}",
                    sock_path.display(),
                    last_err.unwrap()
                )
            })?
        };

        // The client deliberately runs without keepalives: a laptop closed
        // for an hour should reconnect transparently on wake rather than have
        // the link torn down mid-sleep. The server's long-interval keepalive
        // is the only liveness mechanism, and it no longer reaps
        // idle-but-alive sessions.
        let config = Arc::new(russh::client::Config::default());
        let handshake = async {
            let mut handle = russh::client::connect_stream(config, stream, MinimalClientHandler)
                .await
                .context("ssh connect")?;

            let auth = handle
                .authenticate_none("minimal-cli")
                .await
                .context("authenticate")?;

            if !auth.success() {
                return Err(anyhow::anyhow!("authentication rejected by daemon"));
            }
            Ok(handle)
        };

        let handle = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "connect to {}: SSH handshake timed out after {HANDSHAKE_TIMEOUT:?}",
                    sock_path.display()
                )
            })??;

        Ok(Client { handle })
    }

    /// Issue a oneshot RPC: open a channel, request the subsystem, write the
    /// serialized request, half-close, and decode the response.
    ///
    /// The type parameter `R` picks the RPC from the wire contract; `request`
    /// is serialized to JSON and the response is deserialized from JSON.
    ///
    /// Uses `channel.wait()` rather than `channel.into_stream()` so that
    /// extended-data (stream 1) — where the daemon writes handler errors
    /// (#901) — is visible instead of silently discarded by the stream's
    /// `AsyncRead` impl.
    ///
    /// Bounded by [`RPC_TIMEOUT`]: on expiry the in-flight channel is
    /// dropped with the future, which closes it.
    pub async fn oneshot_rpc<R: OneshotSshRpc>(
        &mut self,
        request: R::Request<'_>,
    ) -> Result<R::Response, anyhow::Error>
    where
        <R as OneshotSshRpc>::Response: serde::de::DeserializeOwned,
    {
        let rpc = async {
            let mut channel = self
                .handle
                .channel_open_session()
                .await
                .with_context(|| format!("open channel for {}", R::NAME))?;

            send_traceparent(&channel).await;
            // want_reply = true so an unknown subsystem (CLI/daemon version
            // skew) surfaces as a Failure instead of the client writing into a
            // channel nobody serves (#901).
            channel
                .request_subsystem(true, R::NAME)
                .await
                .with_context(|| format!("request subsystem {}", R::NAME))?;

            let body = serde_json_lenient::to_vec(&request).context("serialize request")?;
            channel.data_bytes(body).await.context("write request")?;
            channel.eof().await.context("shutdown write half")?;

            // Drain the channel with wait() rather than into_stream() so that
            // extended-data (stream 1) — where the daemon writes handler errors
            // (#901) — is visible instead of silently discarded by the stream's
            // AsyncRead impl.
            let mut resp_buf = Vec::with_capacity(256);
            let mut err_buf = Vec::new();
            while let Some(msg) = channel.wait().await {
                match msg {
                    russh::ChannelMsg::Data { data } => {
                        resp_buf.extend_from_slice(&data);
                    }
                    russh::ChannelMsg::ExtendedData { data, ext: 1 } => {
                        err_buf.extend_from_slice(&data);
                    }
                    _ => {}
                }
            }

            if !err_buf.is_empty() {
                anyhow::bail!(
                    "{} RPC failed on the daemon side: {}",
                    R::NAME,
                    String::from_utf8_lossy(&err_buf)
                );
            }

            serde_json_lenient::from_slice(&resp_buf)
                .with_context(|| format!("decode response for {}", R::NAME))
        };

        tokio::time::timeout(RPC_TIMEOUT, rpc)
            .await
            .map_err(|_| anyhow::anyhow!("{} RPC timed out after {RPC_TIMEOUT:?}", R::NAME))?
    }

    /// Open a session channel and issue an `exec` request for `command`,
    /// returning the channel once the daemon has acknowledged it.
    ///
    /// The daemon replies to the exec request before the process produces
    /// any output, so everything after the ack is the process conversation:
    /// data, extended data, and finally an exit status.
    pub async fn open_exec_channel(
        &mut self,
        command: &str,
    ) -> Result<russh::Channel<russh::client::Msg>, anyhow::Error> {
        self.exec_channel(None, command).await
    }

    /// Like [`Self::open_exec_channel`], but sets `MINIMAL_SESSION_ID` on the
    /// channel before the exec request, the routing contract the daemon's
    /// `min`-prefixed exec forms (`min task run <task>`, `min package build`,
    /// `min check`) are served under.
    pub async fn open_session_exec_channel(
        &mut self,
        session_id: sessions::SessionId,
        command: &str,
    ) -> Result<russh::Channel<russh::client::Msg>, anyhow::Error> {
        self.exec_channel(Some(session_id), command).await
    }

    async fn exec_channel(
        &mut self,
        session_id: Option<sessions::SessionId>,
        command: &str,
    ) -> Result<russh::Channel<russh::client::Msg>, anyhow::Error> {
        let mut channel = self
            .handle
            .channel_open_session()
            .await
            .context("open exec channel")?;
        send_traceparent(&channel).await;
        if let Some(id) = session_id {
            channel
                .set_env(true, "MINIMAL_SESSION_ID", id.to_string())
                .await
                .context("set MINIMAL_SESSION_ID env")?;
        }
        channel
            .exec(true, command)
            .await
            .with_context(|| format!("exec request for {command:?}"))?;

        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Success) => return Ok(channel),
                Some(russh::ChannelMsg::Failure) => {
                    anyhow::bail!("daemon rejected exec request {command:?}")
                }
                // Window adjustments and the like can precede the ack;
                // process output cannot, since the server acks first.
                Some(_) => continue,
                None => anyhow::bail!("channel closed before the exec request was acknowledged"),
            }
        }
    }

    /// Stream a zstd-compressed tarball of `dir` to the daemon's
    /// `WorkspaceFilesTarZst` subsystem, which unpacks it into the
    /// session's workspace directory.
    ///
    /// `session_id` is set as the `MINIMAL_SESSION_ID` env var on the
    /// channel so the daemon can scope the upload to the correct session.
    pub async fn upload_workspace_files(
        &mut self,
        session_id: sessions::SessionId,
        dir: &Path,
    ) -> Result<(), anyhow::Error> {
        // Spinner-style bar: workspace file counts vary (and pre-walking to
        // sum sizes would double the disk work), so we drive on
        // wire-bytes-through-SSH with no fixed total. `finish_and_clear`
        // wipes the bar off the terminal on success so it doesn't hang
        // around above the next line.
        let bar = add_spinner_bar("Uploading project files");
        let result = self
            .upload_workspace_files_with(session_id, dir, &bar)
            .await;
        bar.finish_and_clear();
        result
    }

    /// [`Self::upload_workspace_files`] without terminal progress output.
    /// For callers that own the screen themselves (the `min dash` TUI),
    /// where a progress bar would corrupt the frame.
    pub async fn upload_workspace_files_quiet(
        &mut self,
        session_id: sessions::SessionId,
        dir: &Path,
    ) -> Result<(), anyhow::Error> {
        // A hidden bar that is never added to the global MultiProgress
        // renders nowhere; the upload plumbing still gets its counter.
        let bar = indicatif::ProgressBar::hidden();
        self.upload_workspace_files_with(session_id, dir, &bar)
            .await
    }

    async fn upload_workspace_files_with(
        &mut self,
        session_id: sessions::SessionId,
        dir: &Path,
        bar: &indicatif::ProgressBar,
    ) -> Result<(), anyhow::Error> {
        let bar_for_wrap = bar.clone();
        self.stream_upload(
            session_id,
            constcat::concat!(minimald_rpc::RPC_SUBSYSTEM_PREFIX, "WorkspaceFilesTarZst"),
            "workspace file",
            async |writer| {
                // `writer` is already `Box<dyn AsyncWrite + ...>`
                // from `stream_upload`, and `stream_tar_zstd` is
                // generic over `W: AsyncWrite + Unpin + Send` —
                // `ProgressWriter<Box<...>>` satisfies that
                // directly, no second heap allocation needed.
                let writer = crate::file_upload::ProgressWriter::new(writer, bar_for_wrap);
                crate::file_upload::stream_tar_zstd(dir, writer).await
            },
        )
        .await
    }

    /// Stream a zstd-compressed tarball of composition patches to the
    /// daemon's `WorkspacePatchesTarZst` subsystem, which unpacks
    /// each entry under `<workspace>/patches/<destination>`. The
    /// launcher reads from that tree when materializing the session's
    /// sandbox home.
    ///
    /// `patches` is a list of `(host_path, sandbox_destination)`
    /// pairs pulled from the finalized [`Composition`]. An empty
    /// list is a no-op — no channel is opened. Callers dedup by
    /// destination first; the composer's post-gate
    /// `check_patch_mismatches` guarantees no two Approved verdicts
    /// share a destination with different sources, so any duplicates
    /// here are exact matches and safe to collapse.
    ///
    /// The archive is streamed with `follow_symlinks: true` and
    /// `mode_override: Some(0o644)` so a `/nix/store/…` link source
    /// lands as a writable copy inside the sandbox.
    ///
    /// [`Composition`]: sessions::core::compose::Composition
    pub async fn upload_patches(
        &mut self,
        session_id: sessions::SessionId,
        patches: &[(std::path::PathBuf, paths::SandboxRelPath)],
    ) -> Result<(), anyhow::Error> {
        if patches.is_empty() {
            return Ok(());
        }
        // File-count bar: we know the target up front, so the operator
        // sees "N/M patches" instead of a spinner. Incremented inside
        // the tar loop after each `add_file` returns — the file is
        // fully queued into the encoder at that point, even if it
        // hasn't been fully compressed or shipped yet.
        let bar = add_patches_bar(patches.len() as u64);
        let bar_for_loop = bar.clone();
        let result = self
            .stream_upload(
                session_id,
                constcat::concat!(minimald_rpc::RPC_SUBSYSTEM_PREFIX, "WorkspacePatchesTarZst"),
                "composition patch",
                async |writer| {
                    // Route through the pipe helper because SSH channel
                    // writers aren't Sync but `TarZstArchive` requires
                    // Sync. The pipe's tx (a `DuplexStream`) is Sync;
                    // its rx pumps into the channel writer on the same
                    // task.
                    crate::file_upload::stream_via_pipe(writer, async |tx| {
                        let mut archive = crate::file_upload::TarZstArchive::new(tx);
                        // Always finalize the archive, even on
                        // build error: `async_tar::Builder` panics
                        // from its `Drop` impl if dropped without
                        // `finish()` (async-tar 0.6 builder.rs:668),
                        // and `?`-propagation isn't a panic-unwind
                        // so the Drop guard fires. If both branches
                        // fail, prefer the build error — it's
                        // usually the root cause (encoder writes
                        // then error with "broken pipe" once the
                        // upstream file read has already failed).
                        let build_result: Result<(), anyhow::Error> = async {
                            for (host_path, dest) in patches {
                                archive
                                    .add_file(
                                        host_path,
                                        dest.as_str(),
                                        crate::file_upload::AddFileOptions {
                                            mode_override: Some(0o644),
                                        },
                                    )
                                    .await
                                    .with_context(|| {
                                        format!(
                                            "adding patch {} → {}",
                                            host_path.display(),
                                            dest.as_str()
                                        )
                                    })?;
                                bar_for_loop.inc(1);
                            }
                            Ok(())
                        }
                        .await;
                        let finish_result = archive.finish().await;
                        match (build_result, finish_result) {
                            (Err(build), _) => Err(build),
                            (Ok(()), r) => r,
                        }
                    })
                    .await
                },
            )
            .await;
        bar.finish_and_clear();
        result
    }

    /// Stream a zstd-compressed tarball of external lifecycle-hook
    /// scripts to the daemon's `WorkspaceHookScriptsTarZst` subsystem,
    /// which unpacks each entry under `<workspace>/hooks/<staged>`.
    ///
    /// `scripts` comes from
    /// [`stage_external_scripts`](sessions::client::hookscripts::stage_external_scripts),
    /// which has already resolved every path against its anchor and
    /// refused anything symlinked or outside it. An empty list is a
    /// no-op — no channel is opened, and no hooks-ready marker is
    /// written, which is what lets `FinalizeSession` skip its marker
    /// check for an all-inline composition.
    ///
    /// A separate stream from
    /// [`upload_patches`](Self::upload_patches) rather than extra
    /// entries in that archive: patch destinations are arbitrary
    /// home-relative paths, so any prefix reserved inside the patch
    /// archive is one a user could legitimately claim, and the whole
    /// patch tree is copied into the sandbox home at finalize — which
    /// is not where scripts belong.
    pub async fn upload_hook_scripts(
        &mut self,
        session_id: sessions::SessionId,
        scripts: &[sessions::client::hookscripts::StagedScript],
    ) -> Result<(), anyhow::Error> {
        if scripts.is_empty() {
            return Ok(());
        }
        self.stream_upload(
            session_id,
            constcat::concat!(
                minimald_rpc::RPC_SUBSYSTEM_PREFIX,
                "WorkspaceHookScriptsTarZst"
            ),
            "hook script",
            async |writer| {
                crate::file_upload::stream_via_pipe(writer, async |tx| {
                    let mut archive = crate::file_upload::TarZstArchive::new(tx);
                    // Always finalize, even on a build error:
                    // `async_tar::Builder` panics from `Drop` if
                    // dropped unfinished, and `?` here is not an
                    // unwind. Same pattern as `upload_patches`.
                    let build_result: Result<(), anyhow::Error> = async {
                        for s in scripts {
                            archive
                                .add_file(
                                    s.host_path.as_std_path(),
                                    s.staged.as_str(),
                                    crate::file_upload::AddFileOptions {
                                        // 0644: the executor runs
                                        // `bash <script>`, which
                                        // reads rather than execs.
                                        mode_override: Some(0o644),
                                    },
                                )
                                .await
                                .with_context(|| {
                                    format!("adding hook script {} → {}", s.host_path, s.staged,)
                                })?;
                        }
                        Ok(())
                    }
                    .await;
                    let finish_result = archive.finish().await;
                    match (build_result, finish_result) {
                        (Err(build), _) => Err(build),
                        (Ok(()), r) => r,
                    }
                })
                .await
            },
        )
        .await
    }

    /// Common plumbing behind [`Self::upload_workspace_files`] and
    /// [`Self::upload_patches`]: open a channel, set the session-id
    /// env var, request a subsystem, drive `stream` over the
    /// channel's writer, wait for the daemon's channel close,
    /// surface any stderr the daemon relayed.
    async fn stream_upload<F>(
        &mut self,
        session_id: sessions::SessionId,
        subsystem: &'static str,
        what: &'static str,
        stream: F,
    ) -> Result<(), anyhow::Error>
    where
        // `channel.make_writer()` returns `impl AsyncWrite + 'static`,
        // not a named type. Take a closure that receives that opaque
        // writer and pumps the tar into it. `AsyncFnOnce` handles the
        // .await for us.
        F: for<'w> AsyncFnOnce(
            Box<dyn tokio::io::AsyncWrite + Unpin + Send + 'w>,
        ) -> Result<(), anyhow::Error>,
    {
        let mut channel = self
            .handle
            .channel_open_session()
            .await
            .with_context(|| format!("open channel for {what} upload"))?;

        send_traceparent(&channel).await;
        channel
            .set_env(true, "MINIMAL_SESSION_ID", session_id.to_string())
            .await
            .context("set MINIMAL_SESSION_ID env")?;

        channel
            .request_subsystem(true, subsystem)
            .await
            .with_context(|| format!("request {subsystem} subsystem"))?;

        let writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = Box::new(channel.make_writer());
        stream(writer).await?;

        // Drain the channel: collect extended-data (stream 1) errors from
        // the daemon under the same cap the diagnostic download uses, and
        // track whether we see an explicit Eof/Close to distinguish a clean
        // post-unpack close from a dropped connection (#901). Without this
        // check a connection drop mid-unpack looks identical to a successful
        // close — empty err, Ok(()) — and cmd_activate proceeds with an
        // empty workspace. An idle-progress backstop guards against a wedged
        // transport that never delivers a Close — generous, since a
        // legitimate unpack of a large archive may produce no channel
        // messages for a while (#886).
        const DRAIN_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
        let mut err = Vec::new();
        let mut saw_close = false;
        loop {
            match tokio::time::timeout(DRAIN_IDLE_TIMEOUT, channel.wait()).await {
                Ok(Some(msg)) => match msg {
                    russh::ChannelMsg::ExtendedData { data, ext: 1 } => {
                        append_daemon_error(&mut err, &data);
                    }
                    russh::ChannelMsg::Eof | russh::ChannelMsg::Close => {
                        saw_close = true;
                    }
                    _ => {}
                },
                Ok(None) => break,
                Err(_) => {
                    anyhow::bail!(
                        "upload drain stalled: no message from daemon for \
                         {DRAIN_IDLE_TIMEOUT:?} (connection may be gone)"
                    );
                }
            }
        }
        if !err.is_empty() {
            anyhow::bail!(
                "daemon failed to unpack {what}s: {}",
                String::from_utf8_lossy(&err)
            );
        }
        if !saw_close {
            anyhow::bail!(
                "upload stream ended unexpectedly: the connection to the daemon \
                 was lost before unpacking completed"
            );
        }
        Ok(())
    }

    /// Requests the daemon's diagnostic bundle (`min bug`): sends `req` on the
    /// [`minimald_rpc::DIAG_BUNDLE_SUBSYSTEM`] subsystem and collects the
    /// streamed tar+zstd archive, up to `max_bytes`.
    ///
    /// Returns `(bytes, truncated)`. Errors the daemon reports — before or
    /// during streaming — arrive over extended-data stream 1 and become the
    /// `Err` here, discarding any partial bundle; a refused subsystem request
    /// means the daemon predates the RPC.
    ///
    /// Hitting `max_bytes` ends *collection*, not the conversation: the
    /// daemon may already have queued an error behind the frames that tripped
    /// the cap, so the channel is drained for
    /// [`TRUNCATED_DRAIN_GRACE`] — payload discarded, extended data kept —
    /// before returning. That window is deliberately short: a daemon still
    /// streaming a runaway archive cannot be waited out without handing it
    /// the caller's whole deadline, and losing an already-capped bundle to a
    /// timeout is worse than missing a message that had not been sent yet.
    /// So an error the daemon emits *after* the cap trips is not observed.
    pub async fn download_diag_bundle(
        &mut self,
        req: &minimald_rpc::DiagBundleRequest,
        max_bytes: usize,
    ) -> Result<(Vec<u8>, bool), anyhow::Error> {
        let mut channel = self
            .handle
            .channel_open_session()
            .await
            .context("open channel for diagnostic bundle")?;

        send_traceparent(&channel).await;
        channel
            .request_subsystem(true, minimald_rpc::DIAG_BUNDLE_SUBSYSTEM)
            .await
            .context(
                "request DiagBundleTarZst subsystem \
                 (daemon may predate the diagnostics RPC — upgrade minimald)",
            )?;

        let body = serde_json_lenient::to_vec(req).context("serialize diag request")?;
        channel
            .data(&body[..])
            .await
            .context("write diag request")?;
        channel.eof().await.context("half-close diag request")?;

        // Data carries the archive; extended-data stream 1 carries the
        // daemon's error message.
        let mut bundle = Vec::new();
        let mut daemon_error = Vec::new();
        let mut truncated = false;
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { data } => {
                    if bundle.len() + data.len() > max_bytes {
                        bundle.extend_from_slice(&data[..max_bytes - bundle.len()]);
                        truncated = true;
                        break;
                    }
                    bundle.extend_from_slice(&data);
                }
                russh::ChannelMsg::ExtendedData { data, ext: 1 } => {
                    append_daemon_error(&mut daemon_error, &data);
                }
                // The daemon refused the subsystem (`want_reply` failure). A
                // healthy daemon replies `Success` then streams; a refusal
                // means it doesn't serve this RPC — bail now rather than block
                // on `wait()` until the caller's deadline, since a bare refusal
                // doesn't close the channel.
                russh::ChannelMsg::Failure => anyhow::bail!(
                    "daemon refused the {} subsystem — it likely predates the \
                     diagnostics RPC (upgrade minimald)",
                    minimald_rpc::DIAG_BUNDLE_SUBSYSTEM
                ),
                _ => {}
            }
        }

        // The cap stopped the collection loop, but an error the daemon put on
        // the wire before that point may still be queued behind the frames
        // that tripped it. Returning now would drop it and report a corrupt
        // partial archive as a clean truncation. Payload is discarded here —
        // the bundle is already at its cap — and only extended data is kept.
        if truncated {
            let drained = tokio::time::timeout(TRUNCATED_DRAIN_GRACE, async {
                while let Some(msg) = channel.wait().await {
                    if let russh::ChannelMsg::ExtendedData { data, ext: 1 } = msg {
                        append_daemon_error(&mut daemon_error, &data);
                    }
                }
            })
            .await;
            if drained.is_err() {
                tracing::debug!(
                    grace = ?TRUNCATED_DRAIN_GRACE,
                    "daemon still streaming after the diag bundle cap; \
                     stopped waiting for a trailing error"
                );
            }
        }

        // A daemon error can also arrive mid-stream (tar finalization failed
        // after bytes were sent); a partial archive without the error would be
        // a silently corrupt diagnostic.
        if !daemon_error.is_empty() {
            let msg = String::from_utf8_lossy(&daemon_error);
            anyhow::bail!(
                "daemon reported an error{}: {msg}",
                if bundle.is_empty() {
                    ""
                } else {
                    " after streaming a partial bundle"
                }
            );
        }
        if bundle.is_empty() {
            anyhow::bail!("daemon sent no bundle");
        }
        Ok((bundle, truncated))
    }
}

/// Cap on the accumulated daemon error message (extended-data stream 1) a
/// streaming RPC will buffer — shared by the diagnostic-bundle download and
/// the workspace-file upload.
const DAEMON_ERROR_MAX: usize = 64 * 1024;

/// How long [`Client::download_diag_bundle`] keeps reading after the size cap
/// trips, looking for an error the daemon already sent.
///
/// Sized for "already on the wire", not for "will finish streaming": a daemon
/// with gigabytes still to write cannot be drained to completion without
/// spending the caller's entire `--guest-timeout-secs`, which would turn a
/// usable truncated bundle into a total loss.
const TRUNCATED_DRAIN_GRACE: Duration = Duration::from_secs(2);

/// Appends `data` to the daemon's error message, bounded: a daemon streaming
/// only extended data must not balloon the CLI past the bound the archive
/// itself respects.
fn append_daemon_error(buf: &mut Vec<u8>, data: &[u8]) {
    let room = DAEMON_ERROR_MAX.saturating_sub(buf.len());
    buf.extend_from_slice(&data[..room.min(data.len())]);
}

/// The provider kind the CLI should talk to, given `--provider`.
///
/// The native minimald and minvmd backends now occupy distinct provider dirs,
/// so connecting — not just spawning — must pick the right one. macOS is always
/// minvmd-backed regardless of the flag; keying on the compile target keeps the
/// in-guest CLI (Linux, native) and the host CLI (macOS, minvmd) each pointed at
/// the dir their local daemon actually uses.
pub fn client_provider_kind(use_minvmd: bool) -> paths::ProviderKind {
    if use_minvmd || cfg!(target_os = "macos") {
        paths::ProviderKind::Minvmd
    } else {
        paths::ProviderKind::Minimald
    }
}

/// The minimal state-dir root the CLI resolves paths under: `--minimal-dir`
/// when set (made absolute), else the platform default.
fn resolve_state_base(
    minimal_dir_override: Option<&std::path::Path>,
) -> std::io::Result<paths::DaemonAbsPath> {
    match minimal_dir_override {
        Some(dir) => {
            let abs = std::path::absolute(dir)?;
            let utf8 = abs
                .to_str()
                .ok_or_else(|| std::io::Error::other("--minimal-dir is not valid UTF-8"))?;
            paths::DaemonAbsPath::try_new(utf8).map_err(std::io::Error::other)
        }
        None => Ok(paths::minimal_state_dir()),
    }
}

/// Adopt any pre-split `providers/local-<N>` dirs into the kind-tagged scheme
/// before the CLI resolves a provider dir, so an upgraded client finds an
/// existing instance instead of missing it. Best-effort: a bad `--minimal-dir`
/// is left for the resolve/connect path to report.
pub fn migrate_legacy_provider_dirs(minimal_dir_override: Option<&std::path::Path>) {
    if let Ok(base) = resolve_state_base(minimal_dir_override) {
        paths::migrate_legacy_provider_dirs(&base);
    }
}

/// Resolve the provider-instance dir (`<state dir>/providers/local-<kind>0`) the
/// daemon and CLI agree on: `--minimal-dir` when set, else the default minimal
/// state dir. `use_minvmd` selects the backend's dir (see [`client_provider_kind`]).
pub fn resolve_provider_dir(
    minimal_dir_override: Option<&std::path::Path>,
    use_minvmd: bool,
) -> std::io::Result<std::path::PathBuf> {
    let base = resolve_state_base(minimal_dir_override)?;
    Ok(
        paths::provider_instance_dir(&base, client_provider_kind(use_minvmd), 0)
            .as_utf8_path()
            .as_std_path()
            .to_path_buf(),
    )
}

/// Resolve the daemon socket path: `<provider dir>/ssh.sock`. Each backend
/// serves this endpoint under its own provider dir, so `use_minvmd` must select
/// the same backend the daemon was spawned as.
pub fn resolve_socket_path(
    minimal_dir_override: Option<&std::path::Path>,
    use_minvmd: bool,
) -> std::io::Result<std::path::PathBuf> {
    Ok(resolve_provider_dir(minimal_dir_override, use_minvmd)?.join(paths::SSH_SOCK_FILE))
}

/// Sends the process trace context as a `TRACEPARENT` channel env request.
/// Best-effort and reply-less: trace propagation is a diagnostic aid, and a
/// daemon predating the variable ignores unknown env names anyway.
async fn send_traceparent(channel: &russh::Channel<russh::client::Msg>) {
    use minimald_rpc::trace::TRACEPARENT_ENV;
    let _ = channel
        .set_env(false, TRACEPARENT_ENV, trace_context().traceparent())
        .await;
}

#[cfg(test)]
mod tests {
    use super::{Client, resolve_socket_path};
    use std::path::Path;

    /// The daemon-error accumulator is bounded: a daemon that sprays extended
    /// data on stream 1 (during a diagnostic download or a workspace upload)
    /// must not be able to grow the client's buffer past the cap.
    #[test]
    fn append_daemon_error_is_capped() {
        let mut buf = Vec::new();
        let chunk = vec![b'x'; 8 * 1024];
        for _ in 0..64 {
            super::append_daemon_error(&mut buf, &chunk);
        }
        assert_eq!(buf.len(), super::DAEMON_ERROR_MAX);
    }

    #[test]
    fn socket_path_honors_override() {
        let sock = resolve_socket_path(Some(Path::new("/tmp/minimal-test")), false).unwrap();
        assert_eq!(
            sock,
            Path::new("/tmp/minimal-test/providers/local-minimald0/ssh.sock")
        );
    }

    #[test]
    fn socket_path_selects_the_minvmd_dir() {
        let sock = resolve_socket_path(Some(Path::new("/tmp/minimal-test")), true).unwrap();
        assert_eq!(
            sock,
            Path::new("/tmp/minimal-test/providers/local-minvmd0/ssh.sock")
        );
    }

    /// A socket that accepts but never speaks SSH — a wedged guest behind
    /// libkrun's always-accepting bridge — must fail at the handshake deadline
    /// instead of blocking the CLI forever (#730).
    #[tokio::test(start_paused = true)]
    async fn connect_fails_at_the_handshake_deadline_on_a_mute_listener() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("mute.sock");
        let _listener = tokio::net::UnixListener::bind(&sock).unwrap();

        // `start_paused` auto-advances time while nothing is runnable, so the
        // deadline elapses in virtual time — the test does not wait it out.
        let err = Client::connect(&sock).await.map(|_| ()).unwrap_err();
        assert!(
            err.to_string().contains("SSH handshake timed out"),
            "expected a handshake-deadline error, got: {err:#}"
        );
    }
}
