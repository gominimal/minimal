use std::io::{BufRead, BufReader};
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
                    let mut stream2 = stream.try_clone().unwrap();

                    if let Some(line) = BufReader::new(&stream).lines().next() {
                        if shutdown.load(Ordering::Acquire) {
                            return;
                        }
                        match line {
                            Ok(line) => {
                                tracing::trace!("listener received: {}", line);
                                if let Err(panic) =
                                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                        channel.handle(&mut stream2, &line, &rootfs)
                                    }))
                                {
                                    tracing::error!("channel handler panicked: {:?}", panic);
                                };
                            }
                            Err(e) => {
                                tracing::warn!("listener read error: {}", e);
                            }
                        }
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
