//! The supervisor's lifeline: `bep serve` stops when the process that
//! started it is gone (#2501).
//!
//! `minvmd` starts `bep serve` with a pipe on its standard input, writes the
//! per-boot token, and keeps its end of the pipe open for as long as it
//! lives. The kernel closes that end when the supervisor exits for any
//! reason: a clean stop, a crash or SIGKILL. A read on the proxy's end then
//! returns end of file. [`watch_until_closed`] turns that end of file into an
//! event the serve loop selects on, so a proxy whose supervisor died without
//! unwinding does not run on with a stale token and hold its listener socket.
//!
//! This is the mechanism on every host. Linux also arms
//! `PR_SET_PDEATHSIG` in the child. macOS has no parent-death signal, and a
//! pipe needs no polling interval and no guess about which pid a reparented
//! process gets.

use std::io::{self, Read};

use tokio::sync::oneshot;

/// The event [`watch_until_closed`] delivers: `Ok` at end of file, or the
/// read error that ended the watch. Either way, nothing more arrives on the
/// input, so the caller treats both as the supervisor being gone.
pub type Closed = io::Result<()>;

/// Reads `input` on a thread of its own until end of file or an error, and
/// discards what it reads. The receiver resolves when the read ends. If
/// the receiver is dropped first, the thread keeps reading until the input
/// ends, and nothing else changes.
///
/// The thread is detached, not a runtime's blocking task, so a runtime that
/// shuts down does not wait on a read that may never return.
pub fn watch_until_closed<R>(input: R) -> io::Result<oneshot::Receiver<Closed>>
where
    R: Read + Send + 'static,
{
    let (send, receive) = oneshot::channel();
    std::thread::Builder::new()
        .name("bep-supervisor".into())
        .spawn(move || {
            let _ = send.send(drain(input));
        })?;
    Ok(receive)
}

/// Reads `input` to its end, keeping nothing.
fn drain(mut input: impl Read) -> Closed {
    let mut buf = [0u8; 256];
    loop {
        match input.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::time::Duration;

    use super::*;

    /// How long a test waits for an event that should arrive.
    const ARRIVES: Duration = Duration::from_secs(10);
    /// How long a test waits to show that an event does not arrive.
    const QUIET: Duration = Duration::from_millis(300);

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime")
    }

    /// The watch fires when the writer closes its end, and not before: the
    /// bytes the writer sends after the token do not count as a close.
    #[test]
    fn the_watch_fires_when_the_supervisor_closes_its_end() {
        let (reader, mut writer) = io::pipe().expect("pipe");
        let mut closed = watch_until_closed(reader).expect("watch");
        runtime().block_on(async {
            writer.write_all(b"more input after the token\n").unwrap();
            assert!(
                tokio::time::timeout(QUIET, &mut closed).await.is_err(),
                "an open pipe is a live supervisor"
            );
            drop(writer);
            let event = tokio::time::timeout(ARRIVES, closed)
                .await
                .expect("the watch fires at end of file")
                .expect("the watch thread sends before it ends");
            assert!(event.is_ok(), "end of file is a clean close: {event:?}");
        });
    }

    /// A supervisor that dies without unwinding still closes the pipe: the
    /// kernel closes a killed process's descriptors. Here a child process
    /// holds the only write end and is sent SIGKILL, as a crashed `minvmd`
    /// would be.
    #[test]
    fn the_watch_fires_when_the_supervisor_is_killed() {
        let (reader, writer) = io::pipe().expect("pipe");
        let mut supervisor = std::process::Command::new("sleep")
            .arg("30")
            .stdout(std::process::Stdio::from(writer))
            .spawn()
            .expect("spawn the stand-in supervisor");
        // The child now holds the only write end: `Stdio::from` moved ours
        // into the command, which dropped it after the spawn.
        let mut closed = watch_until_closed(reader).expect("watch");
        runtime().block_on(async {
            assert!(
                tokio::time::timeout(QUIET, &mut closed).await.is_err(),
                "the watch waits while the supervisor lives"
            );
            supervisor.kill().expect("SIGKILL the stand-in supervisor");
            supervisor.wait().expect("reap the stand-in supervisor");
            let event = tokio::time::timeout(ARRIVES, closed)
                .await
                .expect("a killed supervisor's pipe reaches end of file")
                .expect("the watch thread sends before it ends");
            assert!(event.is_ok(), "{event:?}");
        });
    }

    /// A read error ends the watch too, and reaches the caller as the error.
    #[test]
    fn a_read_error_ends_the_watch() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("broken input"))
            }
        }
        let closed = watch_until_closed(Broken).expect("watch");
        let event = runtime()
            .block_on(async { tokio::time::timeout(ARRIVES, closed).await })
            .expect("the watch ends")
            .expect("the watch thread sends before it ends");
        assert_eq!(event.unwrap_err().to_string(), "broken input");
    }

    /// An interrupted read is retried, not taken for a close.
    #[test]
    fn an_interrupted_read_is_retried() {
        struct InterruptedOnce(bool);
        impl Read for InterruptedOnce {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                if std::mem::replace(&mut self.0, true) {
                    Ok(0)
                } else {
                    Err(io::ErrorKind::Interrupted.into())
                }
            }
        }
        assert!(drain(InterruptedOnce(false)).is_ok());
    }
}
