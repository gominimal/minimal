//! Backpressure for a transport that under-delivers it.
//!
//! A `write(2)` on a guest AF_VSOCK socket fails with `ENOBUFS` when the
//! virtio TX virtqueue is full — the guest has queued more than the host-side
//! VMM has drained. Unlike `EWOULDBLOCK` this is a hard error: `tokio-vsock`
//! surfaces the raw errno as an [`io::Error`] that is not
//! [`ErrorKind::WouldBlock`](std::io::ErrorKind::WouldBlock), so no layer above
//! retries it. In minimald that error escapes through russh and kills the whole
//! SSH connection, not just the channel that was writing, which is how a file
//! upload turns into `channel closed` on the client.
//!
//! [`EnobufsBackpressure`] is the missing backpressure: it absorbs `ENOBUFS`
//! on the write path, waits for the host to drain, and re-issues the write.
//!
//! # Why a timer and not a readiness wait
//!
//! The obvious fix — register the waker and return [`Poll::Pending`] until the
//! socket is writable again — does not work here. `tokio-vsock` reaches this
//! error *through* a satisfied write-readiness guard, and a non-`WouldBlock`
//! error does not clear that readiness, so there is no guarantee of a fresh
//! writability edge to wake on: the wait can hang forever, and a bare
//! retry-on-wake loop would busy-spin instead. What actually clears the
//! condition is the host draining the virtqueue, which takes wall-clock time.
//! Measurement agrees: inserting a 1 µs sleep between client writes makes a
//! 1.28 GB upload succeed, while [`tokio::task::yield_now`] in the same place
//! does not. So the retry is driven by a timer.
//!
//! # Relationship to the libkrun version floor
//!
//! [`Listener`](crate::server::Listener)'s vsock impl requires libkrun >=
//! 1.19.0 because 1.18.1 had a multi-descriptor TX-chain bug in its vsock
//! device. This is a different problem and a different kind of fix: the device
//! is behaving correctly here — a full queue is a legitimate state — but the
//! socket reports it as a fatal error rather than as backpressure. This adapter
//! restores the backpressure semantics the caller already assumes; it does not
//! work around a device defect, and it does not substitute for the version
//! floor.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// Delay before the first retry of an `ENOBUFS` write. Deliberately far below
/// the drain time of a full queue: the common case is a queue that clears
/// almost immediately, and a long first wait would cost throughput on every
/// stall. Note that tokio's timer has millisecond granularity, so this is a
/// floor of "one timer tick", not a literal 100 µs.
const INITIAL_BACKOFF: Duration = Duration::from_micros(100);

/// Ceiling for the exponential backoff. A queue that has not drained in a few
/// milliseconds is not going to drain faster for being polled harder, and this
/// bounds the wasted syscalls during a long stall.
const MAX_BACKOFF: Duration = Duration::from_millis(4);

/// How long a single contiguous run of `ENOBUFS` may last before the error is
/// propagated to the caller. Past this the transport is not congested, it is
/// broken, and reporting that is better than hanging the session forever.
const MAX_STALL: Duration = Duration::from_secs(5);

/// State of an in-progress `ENOBUFS` stall: one contiguous run of failed write
/// attempts. Absent (`None` on the adapter) whenever the stream is healthy, so
/// the fast path costs one `Option` check and allocates nothing.
#[derive(Debug)]
struct Stall {
    /// The armed retry timer. Held here — not recreated per poll — so that
    /// re-polling resumes the same wait instead of restarting it. `None` once
    /// it has fired and the write has not yet been re-attempted.
    timer: Option<Pin<Box<Sleep>>>,
    /// Delay for the next backoff step, doubling up to [`MAX_BACKOFF`].
    delay: Duration,
    /// When this run of `ENOBUFS` began, for the [`MAX_STALL`] deadline.
    started: Instant,
    /// Retries issued in this run, for the logs.
    retries: u32,
}

/// An [`AsyncRead`] + [`AsyncWrite`] adapter that treats `ENOBUFS` on the write
/// path as backpressure rather than as a fatal error.
///
/// A write attempt that fails with `ENOBUFS` is retried after a short sleep,
/// backing off exponentially from `INITIAL_BACKOFF` to `MAX_BACKOFF` and
/// resetting once a write lands. A contiguous run of failures lasting longer
/// than `MAX_STALL` gives up and returns the underlying error unchanged, so a
/// genuinely wedged transport still surfaces instead of hanging.
///
/// Only `ENOBUFS` is retried. Every other error, and every read, passes through
/// untouched, so a healthy stream behaves exactly like the stream it wraps.
///
/// Generic over the inner stream rather than tied to
/// [`tokio_vsock::VsockStream`](https://docs.rs/tokio-vsock) so the retry state
/// machine can be exercised against a mock writer in unit tests.
///
/// # Buffer safety
///
/// The adapter never consumes bytes it does not report and never retains the
/// caller's buffer: `ENOBUFS` means the write moved zero bytes, so a retry is
/// free to write whatever buffer the caller offers at that time. A caller is
/// therefore allowed — as [`AsyncWrite`] permits — to poll again with a
/// different buffer after a [`Poll::Pending`], and no partial write can be
/// re-issued against mismatched data.
#[derive(Debug)]
pub struct EnobufsBackpressure<S> {
    inner: S,
    /// The current stall, if a write is presently backing off.
    stall: Option<Stall>,
    /// Stall runs seen on this stream, cumulative. Used to keep the log to one
    /// `WARN` per stream (see [`Self::arm_backoff`]).
    stalls: u64,
}

impl<S> EnobufsBackpressure<S> {
    /// Wraps `inner`, retrying `ENOBUFS` on its write path.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            stall: None,
            stalls: 0,
        }
    }

    /// Records an `ENOBUFS` write attempt and arms the next retry timer.
    ///
    /// Returns `false` when this run of failures has outlived `MAX_STALL`,
    /// meaning the caller must propagate the error instead of retrying.
    fn arm_backoff(&mut self) -> bool {
        let now = Instant::now();
        // Taken and put back so the whole update runs on an owned value; a
        // give-up simply declines to put it back, clearing the stall.
        let (mut stall, first) = match self.stall.take() {
            Some(stall) => (stall, false),
            None => {
                self.stalls += 1;
                let stall = Stall {
                    timer: None,
                    delay: INITIAL_BACKOFF,
                    started: now,
                    retries: 0,
                };
                (stall, true)
            }
        };

        let elapsed = now.saturating_duration_since(stall.started);
        if elapsed >= MAX_STALL {
            tracing::warn!(
                retries = stall.retries,
                elapsed_ms = elapsed.as_millis(),
                stalls = self.stalls,
                "vsock tx queue still full past the ENOBUFS stall deadline; propagating the error"
            );
            return false;
        }

        let delay = stall.delay;
        stall.delay = (delay * 2).min(MAX_BACKOFF);
        stall.retries += 1;
        stall.timer = Some(Box::pin(tokio::time::sleep(delay)));
        let retries = stall.retries;
        let stalls = self.stalls;
        self.stall = Some(stall);

        if first {
            // One `WARN` per stream, then `DEBUG`: a sustained upload can stall
            // hundreds of times, and burying boot.log under it would defeat the
            // point of logging this at all. The give-up warning above is not
            // rate-limited — it is the one that reports a real failure.
            if stalls == 1 {
                tracing::warn!(
                    retries,
                    elapsed_ms = elapsed.as_millis(),
                    delay_us = delay.as_micros(),
                    "vsock tx queue full; engaging ENOBUFS backoff (further stalls log at DEBUG)"
                );
            } else {
                tracing::debug!(
                    retries,
                    delay_us = delay.as_micros(),
                    stalls,
                    "vsock tx queue full; backing off"
                );
            }
        }
        true
    }
}

/// Whether `error` is the guest-side "virtio TX queue is full" report.
///
/// Matched on the raw errno rather than on [`io::ErrorKind`], which has no
/// dedicated variant for `ENOBUFS` and would need a catch-all, and certainly
/// not on the rendered message, which is not a stable interface.
fn is_enobufs(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ENOBUFS)
}

impl<S: AsyncWrite + Unpin> AsyncWrite for EnobufsBackpressure<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            // Drive an armed retry timer to completion first. Polling it here
            // is also what registers the waker for the retry: `arm_backoff`
            // only creates the timer, it never returns `Pending` itself.
            if let Some(stall) = this.stall.as_mut()
                && let Some(timer) = stall.timer.as_mut()
            {
                ready!(timer.as_mut().poll(cx));
                stall.timer = None;
            }

            match Pin::new(&mut this.inner).poll_write(cx, buf) {
                Poll::Ready(Ok(written)) => {
                    if let Some(stall) = this.stall.take() {
                        tracing::debug!(
                            retries = stall.retries,
                            stalled_us = stall.started.elapsed().as_micros(),
                            "vsock tx queue drained; write resumed"
                        );
                    }
                    return Poll::Ready(Ok(written));
                }
                Poll::Ready(Err(error)) if is_enobufs(&error) => {
                    if this.arm_backoff() {
                        // Loop back to poll the timer just armed.
                        continue;
                    }
                    return Poll::Ready(Err(error));
                }
                // Anything else ends the stall run: the deadline measures a
                // contiguous run of `ENOBUFS`, and a `Pending` from the inner
                // stream is ordinary backpressure that already registered a
                // waker of its own.
                other => {
                    this.stall = None;
                    return other;
                }
            }
        }
    }

    /// Forwarded unchanged. A vsock flush is a no-op — nothing is buffered
    /// above the socket — so it has no queue of its own to overrun, and the
    /// retry stays confined to [`Self::poll_write`].
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    // `poll_write_vectored`/`is_write_vectored` are deliberately left at their
    // defaults, which route through the retrying `poll_write` above. Nothing is
    // lost: `VsockStream` does not implement vectored writes either.
}

impl<S: AsyncRead + Unpin> AsyncRead for EnobufsBackpressure<S> {
    /// Forwarded unchanged: `ENOBUFS` is a send-side condition, and a read that
    /// silently retried would change the stream's semantics for no benefit.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// A stream whose write outcomes are scripted, recording the (virtual) time
    /// of every attempt so the retry cadence is observable.
    #[derive(Debug, Default)]
    struct MockStream {
        /// One entry per write attempt: `Some(errno)` fails it, `None` lets it
        /// succeed. Once drained, [`Self::when_drained`] applies.
        script: VecDeque<Option<i32>>,
        /// Outcome for every attempt past the end of `script`.
        when_drained: Option<i32>,
        /// [`Instant`] of each write attempt, in order.
        attempts: Vec<Instant>,
        /// Bytes accepted by successful writes.
        written: Vec<u8>,
        /// Bytes a read will yield.
        to_read: Vec<u8>,
        /// Errno a read fails with instead of yielding [`Self::to_read`].
        read_error: Option<i32>,
    }

    impl MockStream {
        /// Fails the next `count` write attempts with `ENOBUFS`, then succeeds.
        fn failing(count: usize) -> Self {
            Self {
                script: std::iter::repeat_n(Some(libc::ENOBUFS), count).collect(),
                ..Self::default()
            }
        }

        /// Gaps between successive write attempts.
        fn gaps(&self) -> Vec<Duration> {
            self.attempts
                .windows(2)
                .map(|pair| pair[1].saturating_duration_since(pair[0]))
                .collect()
        }
    }

    impl AsyncWrite for MockStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.attempts.push(Instant::now());
            match this.script.pop_front().unwrap_or(this.when_drained) {
                Some(errno) => Poll::Ready(Err(io::Error::from_raw_os_error(errno))),
                None => {
                    this.written.extend_from_slice(buf);
                    Poll::Ready(Ok(buf.len()))
                }
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for MockStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if let Some(errno) = this.read_error {
                return Poll::Ready(Err(io::Error::from_raw_os_error(errno)));
            }
            let n = this.to_read.len().min(buf.remaining());
            buf.put_slice(&this.to_read[..n]);
            this.to_read.drain(..n);
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn transient_enobufs_is_retried_until_the_write_lands() {
        let mut stream = EnobufsBackpressure::new(MockStream::failing(3));

        let written = stream.write(b"payload").await.expect("retries absorb it");

        assert_eq!(written, b"payload".len());
        assert_eq!(stream.inner.written, b"payload");
        assert_eq!(
            stream.inner.attempts.len(),
            4,
            "three failed attempts then the one that lands"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_resets_after_a_successful_write() {
        // Long enough for the delay to reach the cap, so a failure to reset is
        // unmistakable in the cadence.
        let mut stream = EnobufsBackpressure::new(MockStream::failing(8));
        stream.write_all(b"a").await.expect("first write lands");
        let first_run = stream.inner.gaps();

        stream.inner.script = VecDeque::from([Some(libc::ENOBUFS)]);
        stream.inner.attempts.clear();
        stream.write_all(b"b").await.expect("second write lands");
        let second_run = stream.inner.gaps();

        let (initial, capped) = (first_run[0], *first_run.last().expect("8 retries"));
        assert!(
            capped > initial,
            "backoff should grow within a stall: {first_run:?}"
        );
        assert_eq!(second_run.len(), 1, "one retry in the second stall");
        assert!(
            second_run[0] <= initial,
            "backoff should restart from the initial delay, not continue from {capped:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_stall_past_the_deadline_propagates_the_original_error() {
        let mut stream = EnobufsBackpressure::new(MockStream {
            when_drained: Some(libc::ENOBUFS),
            ..MockStream::default()
        });

        let start = Instant::now();
        let error = stream.write(b"payload").await.expect_err("never drains");

        assert_eq!(
            error.raw_os_error(),
            Some(libc::ENOBUFS),
            "the inner error is propagated unchanged"
        );
        assert!(
            start.elapsed() >= MAX_STALL,
            "the deadline must be honoured before giving up"
        );
        assert!(
            stream.inner.attempts.len() > 1,
            "it should have retried before giving up"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_non_enobufs_error_is_never_retried() {
        let mut stream = EnobufsBackpressure::new(MockStream {
            script: VecDeque::from([Some(libc::EPIPE)]),
            ..MockStream::default()
        });

        let error = stream.write(b"payload").await.expect_err("EPIPE is fatal");

        assert_eq!(error.raw_os_error(), Some(libc::EPIPE));
        assert_eq!(
            stream.inner.attempts.len(),
            1,
            "no retry for an error that is not ENOBUFS"
        );
    }

    #[tokio::test]
    async fn reads_pass_through_untouched() {
        let mut stream = EnobufsBackpressure::new(MockStream {
            to_read: b"from the host".to_vec(),
            ..MockStream::default()
        });

        let mut buf = [0u8; 13];
        stream.read_exact(&mut buf).await.expect("read succeeds");

        assert_eq!(&buf, b"from the host");
    }

    #[tokio::test]
    async fn a_read_error_is_propagated_even_when_it_is_enobufs() {
        let mut stream = EnobufsBackpressure::new(MockStream {
            read_error: Some(libc::ENOBUFS),
            ..MockStream::default()
        });

        let error = stream
            .read(&mut [0u8; 8])
            .await
            .expect_err("reads are not retried");

        assert_eq!(error.raw_os_error(), Some(libc::ENOBUFS));
    }
}
