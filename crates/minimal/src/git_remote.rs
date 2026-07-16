//! `git-remote-min`: the git remote-helper mode of the `min` binary.
//!
//! When the binary is invoked with the basename `git-remote-min` (a symlink
//! to, or copy of, `min`), it speaks the [gitremote-helpers] line protocol on
//! stdio instead of the normal CLI, letting `git push min://<session>` reach
//! a session's workspace. Only the `connect` capability is supported: on
//! `connect <service>` we open an SSH exec channel to minimald over its UDS —
//! the same `russh` transport every other CLI codepath uses — and bridge
//! git's pack-protocol conversation across it, with no external `ssh` or
//! `socat` involved.
//!
//! [gitremote-helpers]: https://git-scm.com/docs/gitremote-helpers

use std::process::ExitCode;

use anyhow::{Context as _, bail};
use tokio::io::{AsyncBufRead, AsyncBufReadExt as _, AsyncRead, AsyncWrite, AsyncWriteExt as _};

/// Whether this process was invoked as the git remote helper: argv[0]'s
/// basename is `git-remote-min`.
pub fn invoked_as_remote_helper() -> bool {
    std::env::args_os()
        .next()
        .is_some_and(|argv0| is_remote_helper_name(std::path::Path::new(&argv0)))
}

fn is_remote_helper_name(argv0: &std::path::Path) -> bool {
    argv0.file_name() == Some(std::ffi::OsStr::new("git-remote-min"))
}

/// Run the remote helper. `args` are the process arguments after argv[0]:
/// git invokes helpers as `git-remote-min <remote-name> <url>`, so the URL
/// (`min://<session>`) is the second argument.
///
/// Returns the exit code to terminate with — for a `connect`ed service,
/// the remote process's exit status.
pub async fn run(args: &[String]) -> Result<ExitCode, anyhow::Error> {
    let url = args
        .get(1)
        .map(String::as_str)
        .context("usage: git-remote-min <remote-name> <url>")?;

    let mut input = tokio::io::BufReader::new(tokio::io::stdin());
    let mut output = tokio::io::stdout();

    let Some(service) = drive_protocol(&mut input, &mut output).await? else {
        return Ok(ExitCode::SUCCESS);
    };
    connect_and_bridge(&service, url, input, output).await
}

/// Drive the line-oriented phase of the helper protocol until git either
/// finishes (EOF or a blank line) or asks to `connect`. Returns the
/// requested service name on `connect <service>`, `None` on an orderly
/// finish without a connect.
async fn drive_protocol<R, W>(
    input: &mut R,
    output: &mut W,
) -> Result<Option<String>, anyhow::Error>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut line = String::new();
    loop {
        line.clear();
        let n = input
            .read_line(&mut line)
            .await
            .context("read remote-helper command")?;
        if n == 0 {
            return Ok(None);
        }
        match line.trim_end_matches(['\r', '\n']) {
            "capabilities" => {
                output
                    .write_all(b"connect\n\n")
                    .await
                    .context("write capabilities")?;
                output.flush().await.context("flush capabilities")?;
            }
            "" => return Ok(None),
            cmd => match cmd.strip_prefix("connect ") {
                Some(service) => return Ok(Some(service.to_string())),
                None => bail!("unsupported remote-helper command {cmd:?} (only `connect`)"),
            },
        }
    }
}

/// Open an exec channel to minimald for `<service> <url>` and bridge git's
/// stdio conversation across it, per the `connect` contract: a blank line
/// acknowledges the established connection, then stdio carries the pack
/// protocol until the remote service exits.
async fn connect_and_bridge<R, W>(
    service: &str,
    url: &str,
    input: R,
    mut output: W,
) -> Result<ExitCode, anyhow::Error>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
{
    // git only ever asks a `connect` helper for the two pack services;
    // refuse anything else rather than forward an arbitrary command string.
    if !matches!(service, "git-upload-pack" | "git-receive-pack") {
        bail!("unsupported connect service {service:?}");
    }

    // Same daemon path as the normal CLI — autospawn if it isn't running,
    // then connect. git invokes the helper without any of our flags, so the
    // no-flags `GlobalArgs` are the right ones.
    let global = crate::GlobalArgs::default();
    crate::ensure_daemon(&global)?;
    let mut client = crate::connect_daemon(&global).await?;
    let channel = client
        .open_exec_channel(&format!("{service} {url}"))
        .await
        .with_context(|| format!("start {service} for {url} (does the session exist?)"))?;

    // Blank line: connection established. From here on stdio belongs to
    // git's pack-protocol conversation with the remote service.
    output.write_all(b"\n").await.context("ack connect")?;
    output.flush().await.context("ack connect")?;

    let exit_status = bridge(channel, input, output).await?;
    Ok(ExitCode::from(u8::try_from(exit_status).unwrap_or(1)))
}

/// Bridge stdio to an exec channel: `input` streams into the channel (with
/// EOF half-closing it so the remote service sees end-of-input), while
/// channel data and extended data stream to `output` and stderr. Returns
/// the remote exit status, or 0 if the server reported none.
async fn bridge<R, W>(
    mut channel: russh::Channel<russh::client::Msg>,
    mut input: R,
    mut output: W,
) -> Result<u32, anyhow::Error>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
{
    let mut to_channel = channel.make_writer();
    // Both results are deliberately dropped: the remote side may close the
    // channel before consuming all our input (e.g. an early pack-protocol
    // error), and that surfaces through the channel loop below, not here.
    let pump = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut input, &mut to_channel).await;
        let _ = to_channel.shutdown().await;
    });

    let mut stderr = tokio::io::stderr();
    let mut exit_status = 0;
    while let Some(msg) = channel.wait().await {
        match msg {
            russh::ChannelMsg::Data { data } => {
                output
                    .write_all(&data)
                    .await
                    .context("write remote stdout")?;
                output.flush().await.context("flush remote stdout")?;
            }
            russh::ChannelMsg::ExtendedData { data, ext: 1 } => {
                stderr
                    .write_all(&data)
                    .await
                    .context("write remote stderr")?;
                stderr.flush().await.context("flush remote stderr")?;
            }
            russh::ChannelMsg::ExitStatus { exit_status: code } => exit_status = code,
            _ => {}
        }
    }
    // The channel is closed; the pump can only be parked on an input read
    // whose result no longer matters.
    pump.abort();
    Ok(exit_status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_name_matches_symlink_and_copy_basenames() {
        assert!(is_remote_helper_name(std::path::Path::new(
            "git-remote-min"
        )));
        assert!(is_remote_helper_name(std::path::Path::new(
            "/usr/local/bin/git-remote-min"
        )));
        assert!(!is_remote_helper_name(std::path::Path::new("min")));
        assert!(!is_remote_helper_name(std::path::Path::new(
            "/usr/local/bin/min"
        )));
        assert!(!is_remote_helper_name(std::path::Path::new(
            "git-remote-minx"
        )));
    }

    #[tokio::test]
    async fn capabilities_advertises_connect_only() {
        let mut input = &b"capabilities\n\n"[..];
        let mut output = Vec::new();
        let service = drive_protocol(&mut input, &mut output).await.unwrap();
        assert_eq!(service, None);
        assert_eq!(output, b"connect\n\n");
    }

    #[tokio::test]
    async fn connect_returns_the_requested_service() {
        let mut input = &b"capabilities\nconnect git-receive-pack\n"[..];
        let mut output = Vec::new();
        let service = drive_protocol(&mut input, &mut output).await.unwrap();
        assert_eq!(service.as_deref(), Some("git-receive-pack"));
    }

    #[tokio::test]
    async fn eof_without_connect_finishes_cleanly() {
        let mut input = &b""[..];
        let mut output = Vec::new();
        let service = drive_protocol(&mut input, &mut output).await.unwrap();
        assert_eq!(service, None);
        assert!(output.is_empty());
    }

    #[tokio::test]
    async fn unsupported_command_is_an_error() {
        let mut input = &b"list\n"[..];
        let mut output = Vec::new();
        let err = drive_protocol(&mut input, &mut output)
            .await
            .expect_err("`list` is not a supported command");
        assert!(
            err.to_string()
                .contains("unsupported remote-helper command")
        );
    }

    /// `connect` with a service outside the two git pack services must be
    /// refused before anything is sent to the daemon.
    #[tokio::test]
    async fn arbitrary_connect_service_is_refused() {
        let err = connect_and_bridge("rm -rf /", "min://x", tokio::io::empty(), Vec::new())
            .await
            .expect_err("non-git service must be refused");
        assert!(err.to_string().contains("unsupported connect service"));
    }
}
