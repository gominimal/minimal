use std::io::{BufRead, BufReader};
use std::path::Path;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};

use crate::Channel;

#[derive(Debug)]
pub(crate) struct Listener<C: Channel> {
    shutdown: Arc<AtomicBool>,
    socket_path: PathBuf,
    thread: Option<JoinHandle<()>>,
    // Boxed for heap-address stability: the listener thread holds a raw
    // pointer into this allocation, and `Box` guarantees the address does
    // not change when the outer `Listener` struct is moved. Our `Drop`
    // impl joins the thread before this field is dropped.
    _channel: Box<C>,
}

impl<C: Channel + Send> Listener<C> {
    pub fn new<P: Into<PathBuf>>(
        socket_path: P,
        rootfs: P,
        channel: C,
    ) -> Result<Self, std::io::Error> {
        let socket_path = socket_path.into();
        let mut channel = Box::new(channel);
        let listener = UnixListener::bind(&socket_path)?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);

        // SAFETY: We cast the pointer to `usize` to erase the type, making
        // the captured value unconditionally `Send + 'static`. The pointer
        // remains valid for the lifetime of the thread because:
        //   1. `Box` provides a stable heap address across moves of `Listener`.
        //   2. `Listener::drop` joins the thread before dropping `_channel`.
        let channel_addr = &mut *channel as *mut C as usize;

        let rootfs = rootfs.into();
        let thread = thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                let channel: &mut C = unsafe { &mut *(channel_addr as *mut C) };
                Self::run(listener, channel, shutdown_clone, rootfs);
            })?;

        Ok(Self {
            shutdown,
            socket_path,
            thread: Some(thread),
            _channel: channel,
        })
    }

    fn run(listener: UnixListener, channel: &mut C, shutdown: Arc<AtomicBool>, rootfs: PathBuf) {
        for stream in listener.incoming() {
            if shutdown.load(Ordering::Acquire) {
                return;
            }
            match stream {
                Ok(stream) => {
                    if !serve_connection(stream, channel, &shutdown, &rootfs) {
                        return;
                    }
                }
                Err(_) if shutdown.load(Ordering::Acquire) => return,
                Err(e) => {
                    tracing::warn!("listener accept error: {}", e);
                    return;
                }
            }
        }
    }
}

/// Reads one request line from `stream` and hands it to `channel`. Returns
/// `false` when the listener is shutting down.
///
/// The line is read as bytes and decoded lossily, so a non-UTF-8 byte (in an
/// exported variable or a path the request carries) does not drop the
/// request. The trace log gets only the line's length: a request can carry
/// the caller's environment, secrets included, and the channel logs its own
/// redacted form.
fn serve_connection<C: Channel>(
    stream: UnixStream,
    channel: &mut C,
    shutdown: &AtomicBool,
    rootfs: &Path,
) -> bool {
    let mut stream2 = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("listener could not clone a connection: {}", e);
            return true;
        }
    };
    let mut raw = Vec::new();
    let read = BufReader::new(&stream).read_until(b'\n', &mut raw);
    if shutdown.load(Ordering::Acquire) {
        return false;
    }
    match read {
        Ok(0) => {}
        Ok(_) => {
            if raw.last() == Some(&b'\n') {
                raw.pop();
                if raw.last() == Some(&b'\r') {
                    raw.pop();
                }
            }
            let line = String::from_utf8_lossy(&raw);
            tracing::trace!(bytes = raw.len(), "listener received a request");
            if let Err(panic) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                channel.handle(&mut stream2, &line, rootfs)
            })) {
                tracing::error!("channel handler panicked: {:?}", panic);
            };
        }
        Err(e) => {
            tracing::warn!("listener read error: {}", e);
        }
    }
    true
}

impl<C: Channel> Drop for Listener<C> {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        // Connect to the socket to unblock the blocking accept() call.
        UnixStream::connect(&self.socket_path).ok();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        if let Err(e) = std::fs::remove_file(&self.socket_path) {
            tracing::warn!("listener socket cleanup failed: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::Mutex;

    use super::*;

    /// A channel that keeps each line it is handed.
    #[derive(Default)]
    struct Recording(Vec<String>);

    impl Channel for Recording {
        fn handle(&mut self, _stream: &mut UnixStream, line: &str, _rootfs: &Path) {
            self.0.push(line.to_string());
        }
    }

    /// A subscriber that keeps the text of every event field it sees.
    #[derive(Default)]
    struct Capture(Mutex<String>);

    struct Fields<'a>(&'a mut String);

    impl tracing::field::Visit for Fields<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write as _;
            let _ = write!(self.0, "{}={:?} ", field.name(), value);
        }
    }

    impl tracing::Subscriber for Capture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut out = self.0.lock().unwrap();
            event.record(&mut Fields(&mut out));
            out.push('\n');
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// Sends `request` over a socket pair and serves it on this thread,
    /// returning the lines the channel got and the trace output.
    fn serve(request: &[u8]) -> (Vec<String>, String) {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(request).unwrap();
        drop(client);
        let capture = Arc::new(Capture::default());
        let mut channel = Recording::default();
        let shutdown = AtomicBool::new(false);
        tracing::subscriber::with_default(Arc::clone(&capture), || {
            assert!(serve_connection(server, &mut channel, &shutdown, Path::new("/")));
        });
        let logged = capture.0.lock().unwrap().clone();
        (channel.0, logged)
    }

    // BCLI-010 (T62): a `run` request carries the caller's environment, so
    // the listener's trace log must not repeat it.
    #[test]
    fn listener_trace_leaves_out_the_run_environment() {
        let request = b"run%/workbench\x1elint\x1eAPI_TOKEN=s3cr3t-value\n";
        let (lines, logged) = serve(request);
        assert_eq!(lines, ["run%/workbench\x1elint\x1eAPI_TOKEN=s3cr3t-value"]);
        assert!(logged.contains("listener received a request"), "{logged}");
        assert!(!logged.contains("s3cr3t-value"), "the trace leaked: {logged}");
        assert!(!logged.contains("API_TOKEN"), "the trace leaked: {logged}");
    }

    // BCLI-010 (T62): one non-UTF-8 byte in the request must not drop it.
    #[test]
    fn listener_serves_a_request_with_a_non_utf8_value() {
        let (lines, _) = serve(b"run%/workbench\x1elint\x1eNAME=caf\xe9\r\n");
        assert_eq!(lines, ["run%/workbench\x1elint\x1eNAME=caf\u{fffd}"]);
    }
}
