//! A transport wrapper that reads what the peer already sent while a write is blocked.
//!
//! The SSH library drives each connection from one task. After every pass it writes its whole
//! send buffer (`write_all`, then `flush`) and only then reads again. If both ends do that while
//! the bytes in flight exceed the transport's buffers, each waits for the other to read, forever.
//! [`ReadWhileWriting`] reads what the peer already sent into memory whenever a write, flush or
//! shutdown cannot progress. The peer's write then finishes, the peer reads again, and ours
//! finishes. One wrapped end is enough to break the wait.
//!
//! Bytes read ahead go to the next reads, in order, before an end of stream or a read error.
//! Writes are never buffered.
//!
//! Memory: a peer can only send what our channel windows allow, and the library grants window
//! only when it processes a packet, which it does not do while it is blocked in a write. One exec
//! channel therefore leaves about 2 MiB unread at most. At the cap ([`DEFAULT_READ_AHEAD_CAP`]
//! unless [`ReadWhileWriting::with_cap`] says otherwise) the wrapper stops reading, which is the
//! back-pressure a bare socket gives, and logs one warning per stall.
//!
//! Both directions must be driven by one task, as the library does. A blocked write registers
//! the writing task to be woken when input arrives, which takes the place of any reader that a
//! different task registered with the inner stream, so that reader could miss its wakeup.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The most read-ahead bytes [`ReadWhileWriting::new`] holds unconsumed: three channels with
/// full 2 MiB windows, plus slack.
pub const DEFAULT_READ_AHEAD_CAP: usize = 8 * 1024 * 1024;

/// The most bytes asked of the inner stream by one read.
const READ_CHUNK: usize = 32 * 1024;

/// Once every read-ahead byte is consumed, at most this much storage is kept, so one burst does
/// not hold its memory for the rest of the connection.
const RETAINED_CAPACITY: usize = 256 * 1024;

/// How the inner stream's read side ended while reading ahead.
enum ReadEnd {
    /// Not ended: reading may continue.
    Open,
    /// The peer closed its side. Every read after the read-ahead bytes returns 0.
    Eof,
    /// A read failed. The error is returned once, after the read-ahead bytes.
    Failed(io::Error),
}

/// A stream that reads ahead into memory whenever a write, flush or shutdown on it cannot
/// progress, so two ends that both write before they read cannot wait on each other.
///
/// Reads return the read-ahead bytes first, in order. Writes, flushes and shutdowns go straight
/// to the inner stream, and their results, errors included, are returned unchanged. Dropping the
/// wrapper drops the inner stream; no task runs beside it. The module documentation has the
/// memory bound and the one-task rule.
///
/// It has no `Debug`: that would print the bytes read ahead.
pub struct ReadWhileWriting<S> {
    inner: S,
    /// Storage for bytes read ahead. The unconsumed ones are `ahead[pos..len]`. Storage past
    /// `len` is spare: it was zeroed once and is reused, so a read does not zero it again.
    ahead: Vec<u8>,
    pos: usize,
    len: usize,
    cap: usize,
    end: ReadEnd,
    /// Set when a stall at the cap was logged, so each stall is logged once.
    warned_at_cap: bool,
}

impl<S> ReadWhileWriting<S> {
    /// Wraps `inner`, holding at most [`DEFAULT_READ_AHEAD_CAP`] bytes read ahead.
    pub fn new(inner: S) -> Self {
        Self::with_cap(inner, DEFAULT_READ_AHEAD_CAP)
    }

    /// Wraps `inner`, holding at most `cap` bytes read ahead (at least 1). Nothing is allocated
    /// until a write blocks.
    pub fn with_cap(inner: S, cap: usize) -> Self {
        Self {
            inner,
            ahead: Vec::new(),
            pos: 0,
            len: 0,
            cap: cap.max(1),
            end: ReadEnd::Open,
            warned_at_cap: false,
        }
    }

    /// How many read-ahead bytes are waiting to be read.
    #[cfg(test)]
    fn buffered(&self) -> usize {
        self.len - self.pos
    }
}

impl<S: AsyncRead + Unpin> ReadWhileWriting<S> {
    /// Reads what the peer already sent into `ahead`, until the inner stream has nothing more,
    /// ends, fails, or the cap is reached.
    ///
    /// Called only after the inner stream returned `Pending` to a write, flush or shutdown: the
    /// task is parked anyway, and a `Pending` read registers it to be woken when more input
    /// arrives. Reading is what lets the peer finish its own write and read ours.
    fn read_ahead(&mut self, cx: &mut Context<'_>) {
        if !matches!(self.end, ReadEnd::Open) {
            return;
        }
        if self.pos > 0 {
            // Move the unconsumed bytes to the front, so the cap counts only those.
            self.ahead.copy_within(self.pos..self.len, 0);
            self.len -= self.pos;
            self.pos = 0;
        }
        loop {
            let room = self.cap.saturating_sub(self.len);
            if room == 0 {
                if !self.warned_at_cap {
                    self.warned_at_cap = true;
                    tracing::warn!(
                        cap = self.cap,
                        "the peer sent more than the read-ahead cap while a write is blocked; \
                         reading pauses until those bytes are consumed"
                    );
                }
                return;
            }
            let want = room.min(READ_CHUNK);
            if self.ahead.len() < self.len + want {
                self.ahead.resize(self.len + want, 0);
            }
            // `ahead` holds at least `len + want` bytes, so both splits are in bounds.
            let (_, spare) = self.ahead.split_at_mut(self.len);
            let (spare, _) = spare.split_at_mut(want);
            let mut chunk = ReadBuf::new(spare);
            let polled = Pin::new(&mut self.inner).poll_read(cx, &mut chunk);
            let got = chunk.filled().len();
            self.len += got;
            match polled {
                // The task is registered to be woken when more input arrives.
                Poll::Pending => return,
                Poll::Ready(Ok(())) if got == 0 => {
                    self.end = ReadEnd::Eof;
                    return;
                }
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => {
                    self.end = ReadEnd::Failed(e);
                    return;
                }
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ReadWhileWriting<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.len {
            let unread = this.ahead.get(this.pos..this.len).unwrap_or_default();
            let n = buf.remaining().min(unread.len());
            let (now, _) = unread.split_at(n);
            buf.put_slice(now);
            this.pos += n;
            if this.pos == this.len {
                this.pos = 0;
                this.len = 0;
                this.warned_at_cap = false;
                this.ahead.truncate(RETAINED_CAPACITY);
                this.ahead.shrink_to(RETAINED_CAPACITY);
            }
            return Poll::Ready(Ok(()));
        }
        match std::mem::replace(&mut this.end, ReadEnd::Open) {
            ReadEnd::Open => Pin::new(&mut this.inner).poll_read(cx, buf),
            ReadEnd::Eof => {
                this.end = ReadEnd::Eof;
                Poll::Ready(Ok(()))
            }
            // Returned once, as the inner stream returned it; later reads go to the stream again.
            ReadEnd::Failed(e) => Poll::Ready(Err(e)),
        }
    }
}

// The vectored write keeps its default, which goes through `poll_write`: the library writes with
// `write_all`, and a default that reports no vectored support keeps every write on this path.
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ReadWhileWriting<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_write(cx, buf);
        if polled.is_pending() {
            this.read_ahead(cx);
        }
        polled
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_flush(cx);
        if polled.is_pending() {
            this.read_ahead(cx);
        }
        polled
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_shutdown(cx);
        if polled.is_pending() {
            this.read_ahead(cx);
        }
        polled
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, duplex};
    use tokio::time::timeout;

    use super::{ReadEnd, ReadWhileWriting};

    /// Every wait's bound. Time is paused, so a stuck test reaches it as soon as no task can run.
    const BOUND: Duration = Duration::from_secs(10);

    /// The pipe size: far below what each end writes, so a bare end's write cannot finish
    /// unless the other end reads.
    const PIPE: usize = 64;

    /// What each end writes before it reads in the mutual-write tests.
    const EACH_WAY: usize = 1024 * 1024;

    /// `len` bytes with a period of 251 (a prime), offset by `seed`, so a dropped, repeated or
    /// swapped chunk does not compare equal.
    fn pattern(len: usize, seed: usize) -> Vec<u8> {
        (0..len).map(|i| ((i + seed) % 251) as u8).collect()
    }

    /// What an SSH session loop does with its transport here: write everything, then read
    /// everything.
    async fn write_then_read<S>(mut end: S, data: &[u8]) -> io::Result<Vec<u8>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        end.write_all(data).await?;
        end.flush().await?;
        end.shutdown().await?;
        let mut got = Vec::new();
        end.read_to_end(&mut got).await?;
        Ok(got)
    }

    /// Both ends write 1 MiB through a 64-byte pipe before reading. With one end wrapped, both
    /// finish, and each receives the other's bytes in order.
    #[tokio::test(start_paused = true)]
    async fn one_wrapped_end_breaks_the_mutual_write() {
        let (a, b) = duplex(PIPE);
        let (to_b, to_a) = (pattern(EACH_WAY, 0), pattern(EACH_WAY, 7));
        let (at_a, at_b) = timeout(BOUND, async {
            tokio::try_join!(
                write_then_read(ReadWhileWriting::new(a), &to_b),
                write_then_read(b, &to_a),
            )
        })
        .await
        .expect("one wrapped end must break the wait")
        .unwrap();
        assert_eq!(at_a.len(), EACH_WAY);
        assert!(at_a == to_a, "the wrapped end received the bytes in order");
        assert_eq!(at_b.len(), EACH_WAY);
        assert!(at_b == to_b, "the bare end received the bytes in order");
    }

    /// The control for the test above: the same two ends, neither wrapped, wait on each other
    /// until the bound. This is what shows the test above tests something.
    #[tokio::test(start_paused = true)]
    async fn bare_ends_that_both_write_first_wait_forever() {
        let (a, b) = duplex(PIPE);
        let (to_b, to_a) = (pattern(EACH_WAY, 0), pattern(EACH_WAY, 7));
        let outcome = timeout(BOUND, async {
            tokio::try_join!(write_then_read(a, &to_b), write_then_read(b, &to_a))
        })
        .await;
        if outcome.is_ok() {
            panic!("two bare ends that both write before they read must wait on each other");
        }
    }

    /// A peer that sends 4096 bytes and never reads: the wrapped end reads ahead up to its cap
    /// and stops there, which leaves the peer's write blocked. Once the wrapped end reads, the
    /// rest arrives, and all 4096 bytes come out in order.
    #[tokio::test(start_paused = true)]
    async fn at_the_cap_reading_pauses_and_loses_nothing() {
        let (a, mut b) = duplex(PIPE);
        let mut a = ReadWhileWriting::with_cap(a, 1024);
        let sent = pattern(4096, 3);
        let peer = {
            let sent = sent.clone();
            tokio::spawn(async move {
                b.write_all(&sent).await?;
                b.shutdown().await?;
                // Returned, not dropped: a dropped end would fail our writes instead of
                // leaving them blocked.
                Ok::<_, io::Error>(b)
            })
        };

        let _elapsed = timeout(BOUND, a.write_all(&[0u8; 4096]))
            .await
            .expect_err("nobody reads what this end writes, so its write must stay blocked");
        assert_eq!(a.buffered(), 1024, "reading ahead stopped at the cap");
        assert!(!peer.is_finished(), "so the peer is still blocked in its write");

        let mut got = Vec::new();
        timeout(BOUND, a.read_to_end(&mut got))
            .await
            .expect("reading resumes the peer")
            .unwrap();
        assert_eq!(got.len(), sent.len());
        assert!(got == sent, "every byte arrived once, in order");
        let _b = timeout(BOUND, peer)
            .await
            .expect("the peer finishes once read")
            .unwrap()
            .unwrap();
    }

    /// A peer that sends 3000 bytes and shuts down while our write is blocked: the end of stream
    /// is seen while reading ahead, and comes only after those 3000 bytes, and stays.
    #[tokio::test(start_paused = true)]
    async fn end_of_stream_comes_after_the_bytes_read_ahead() {
        let (a, mut b) = duplex(PIPE);
        let mut a = ReadWhileWriting::new(a);
        let sent = pattern(3000, 5);
        let peer = {
            let sent = sent.clone();
            tokio::spawn(async move {
                b.write_all(&sent).await?;
                b.shutdown().await?;
                // Returned, not dropped: a dropped end would fail our writes instead of
                // leaving them blocked.
                Ok::<_, io::Error>(b)
            })
        };

        let _elapsed = timeout(BOUND, a.write_all(&[0u8; 4096]))
            .await
            .expect_err("nobody reads what this end writes, so its write must stay blocked");
        assert_eq!(a.buffered(), 3000, "everything the peer sent was read ahead");
        assert!(
            matches!(a.end, ReadEnd::Eof),
            "and the peer's shutdown was seen while reading ahead"
        );

        let mut got = Vec::new();
        timeout(BOUND, a.read_to_end(&mut got))
            .await
            .expect("the bytes are in memory")
            .unwrap();
        assert!(got == sent, "the 3000 bytes come first, in order");
        let mut more = [0u8; 16];
        let n = timeout(BOUND, a.read(&mut more))
            .await
            .expect("the end of stream is in memory")
            .unwrap();
        assert_eq!(n, 0, "the end of stream stays");
        let _b = timeout(BOUND, peer)
            .await
            .expect("the peer finished")
            .unwrap()
            .unwrap();
    }

    /// A stream whose writes never progress and whose reads return `reads` in turn, then end of
    /// stream.
    struct Scripted {
        reads: VecDeque<io::Result<Vec<u8>>>,
    }

    impl AsyncRead for Scripted {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.reads.pop_front() {
                Some(Ok(bytes)) => {
                    buf.put_slice(&bytes);
                    Poll::Ready(Ok(()))
                }
                Some(Err(e)) => Poll::Ready(Err(e)),
                None => Poll::Ready(Ok(())),
            }
        }
    }

    impl AsyncWrite for Scripted {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A read error met while reading ahead comes after the bytes read before it, once, with
    /// its kind kept; the read after it goes to the stream again (here: its end).
    #[tokio::test(start_paused = true)]
    async fn a_read_error_comes_once_after_the_bytes_before_it() {
        let mut s = ReadWhileWriting::new(Scripted {
            reads: VecDeque::from([
                Ok(b"abc".to_vec()),
                Err(io::Error::from(io::ErrorKind::ConnectionReset)),
            ]),
        });

        // One poll, by hand: the write is `Pending`, so the wrapper reads ahead.
        let polled =
            std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut s).poll_write(cx, b"x"))).await;
        assert!(polled.is_pending(), "the scripted write never progresses");
        assert_eq!(s.buffered(), 3, "the bytes before the error were read ahead");

        let mut buf = [0u8; 16];
        let n = timeout(BOUND, s.read(&mut buf))
            .await
            .expect("in memory")
            .unwrap();
        assert_eq!(&buf[..n], b"abc");
        let err = timeout(BOUND, s.read(&mut buf))
            .await
            .expect("in memory")
            .expect_err("then the error");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
        let n = timeout(BOUND, s.read(&mut buf))
            .await
            .expect("the script is over")
            .unwrap();
        assert_eq!(n, 0, "then the stream's own end");
    }
}
