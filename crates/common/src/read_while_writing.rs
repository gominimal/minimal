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
//! Memory: a peer can only send what our channel windows allow (2 MiB per channel by default),
//! and the library grants more window only when its loop processes a packet, which it does not
//! do while it is blocked in a write. So while a write is blocked, at most about 2 MiB per open
//! channel arrives to be read ahead. At the cap ([`DEFAULT_READ_AHEAD_CAP`] unless
//! [`ReadWhileWriting::with_cap`] says otherwise) the wrapper stops reading, which is the
//! back-pressure a bare socket gives, and logs one warning per stall. The storage behind the
//! bytes held stays within a small multiple of the cap.
//!
//! The limit: the wait is broken only while what the peer has in flight toward this end stays
//! below the cap. If both ends are blocked writing and each has more than the other's cap to
//! send, both wait, as two bare ends would. With the default cap and windows that takes more
//! than 16 channels sending at full window in both directions at once.
//!
//! Both directions must be driven by one task, as the library does. A blocked write registers
//! the writing task to be woken when input arrives, which takes the place of any reader that a
//! different task registered with the inner stream, so that reader could miss its wakeup.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The most read-ahead bytes [`ReadWhileWriting::new`] holds unconsumed: 16 channels with full
/// 2 MiB windows. A peer that keeps to its windows never sends more than they allow, so the cap
/// binds only with more channels than that, or a peer that ignores its windows.
pub const DEFAULT_READ_AHEAD_CAP: usize = 32 * 1024 * 1024;

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
    /// Bytes moved to the front of `ahead` so far, read by the test of what reading ahead costs.
    #[cfg(test)]
    moved: usize,
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
            #[cfg(test)]
            moved: 0,
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
        loop {
            // The cap counts only the unconsumed bytes, wherever they sit in `ahead`.
            let unread = self.len - self.pos;
            let room = self.cap.saturating_sub(unread);
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
            if self.ahead.len() - self.len < want && self.pos > 0 && self.pos >= unread {
                // Moving the unconsumed bytes to the front copies no more bytes than were
                // consumed since the last move, so the bytes moved in all never exceed the
                // bytes consumed, however slowly the buffer drains. Growing instead, when fewer
                // were consumed, keeps `len` below twice the cap.
                self.ahead.copy_within(self.pos..self.len, 0);
                self.len = unread;
                self.pos = 0;
                #[cfg(test)]
                {
                    self.moved += unread;
                }
            }
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

/// Scaffolding for tests of the code that wires [`ReadWhileWriting`] in. A [`test_util::Probe`]
/// sits between a session loop and its transport, so a test can make one end stop reading and
/// see when the other end's writes block or go through. The `test-util` cargo feature builds it
/// for other crates' tests; no normal build has it.
#[cfg(any(test, feature = "test-util"))]
pub mod test_util {
    use std::io;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::sync::watch;

    /// What a [`Probe`] has seen of the writes to its stream.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct Writes {
        /// Bytes the stream accepted, in all.
        pub accepted: usize,
        /// Whether the latest write returned `Pending`: the writer waits for room, which only a
        /// read by the other end makes.
        pub blocked: bool,
    }

    /// A stream that passes reads and writes through to `inner` and reports the writes to its
    /// [`ProbeHandle`], which can also stop this end reading for good.
    pub struct Probe<S> {
        inner: S,
        reads_paused: Arc<AtomicBool>,
        writes: watch::Sender<Writes>,
    }

    /// The test's side of a [`Probe`].
    pub struct ProbeHandle {
        reads_paused: Arc<AtomicBool>,
        writes: watch::Receiver<Writes>,
    }

    impl<S> Probe<S> {
        /// Wraps `inner`. Reads go through until [`ProbeHandle::pause_reads`].
        pub fn new(inner: S) -> (Self, ProbeHandle) {
            let reads_paused = Arc::new(AtomicBool::new(false));
            let (tx, rx) = watch::channel(Writes::default());
            let probe = Self {
                inner,
                reads_paused: Arc::clone(&reads_paused),
                writes: tx,
            };
            let handle = ProbeHandle {
                reads_paused,
                writes: rx,
            };
            (probe, handle)
        }
    }

    impl ProbeHandle {
        /// From now on every read of the probed stream returns `Pending`, so the end that reads
        /// it never reads again: the peer that provably does not read. Reads are not resumed.
        pub fn pause_reads(&self) {
            self.reads_paused.store(true, Ordering::SeqCst);
        }

        /// The writes seen so far.
        pub fn writes(&self) -> Writes {
            *self.writes.borrow()
        }

        /// Waits until `done` holds for the writes seen; false if the probe was dropped first.
        pub async fn wait_for_writes(&mut self, done: impl FnMut(&Writes) -> bool) -> bool {
            self.writes.wait_for(done).await.is_ok()
        }
    }

    impl<S: AsyncRead + Unpin> AsyncRead for Probe<S> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.reads_paused.load(Ordering::SeqCst) {
                // No waker is kept: reads stay paused for good, and whatever else wakes the
                // reading task finds this read still pending.
                return Poll::Pending;
            }
            Pin::new(&mut this.inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for Probe<S> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            let polled = Pin::new(&mut this.inner).poll_write(cx, buf);
            match &polled {
                Poll::Ready(Ok(n)) => {
                    let n = *n;
                    this.writes.send_modify(|w| {
                        w.accepted += n;
                        w.blocked = false;
                    });
                }
                Poll::Pending => this.writes.send_modify(|w| w.blocked = true),
                Poll::Ready(Err(_)) => {}
            }
            polled
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
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

    /// A stream whose writes never progress and whose reads return what the test put in
    /// `bytes`, or `Pending` when there is nothing. Only polled by hand.
    #[derive(Default)]
    struct Feed {
        bytes: VecDeque<u8>,
    }

    impl AsyncRead for Feed {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.bytes.is_empty() {
                return Poll::Pending;
            }
            let n = buf.remaining().min(self.bytes.len());
            let taken: Vec<u8> = self.bytes.drain(..n).collect();
            buf.put_slice(&taken);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for Feed {
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

    /// One poll of a write, by hand: it is `Pending`, so the wrapper reads ahead.
    async fn write_once(s: &mut ReadWhileWriting<Feed>) {
        let polled =
            std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut *s).poll_write(cx, b"x"))).await;
        assert!(polled.is_pending(), "the fed stream's writes never progress");
    }

    /// 1 MiB is held ahead, then the reader takes one 32 KiB packet at a time while every write
    /// blocks again and 32 KiB more arrives, as when a peer drains slowly. The bytes moved to
    /// the front stay within the bytes consumed, where moving everything unconsumed on every
    /// read ahead would move about 1 MiB per packet. Every byte still comes out once, in order.
    #[tokio::test(start_paused = true)]
    async fn a_slow_drain_moves_no_more_bytes_than_it_consumes() {
        const HELD: usize = 1024 * 1024;
        const PACKET: usize = 32 * 1024;
        const PACKETS: usize = 64;
        let sent = pattern(HELD + PACKETS * PACKET, 11);
        let mut s = ReadWhileWriting::new(Feed::default());
        s.inner.bytes.extend(sent[..HELD].iter().copied());
        write_once(&mut s).await;
        assert_eq!(s.buffered(), HELD, "everything fed was read ahead");

        let mut got = Vec::with_capacity(sent.len());
        let mut packet = vec![0u8; PACKET];
        for i in 0..PACKETS {
            let n = timeout(BOUND, s.read(&mut packet))
                .await
                .expect("in memory")
                .unwrap();
            assert_eq!(n, PACKET, "a whole packet is held");
            got.extend_from_slice(&packet[..n]);
            let more = HELD + i * PACKET;
            s.inner.bytes.extend(sent[more..more + PACKET].iter().copied());
            write_once(&mut s).await;
            assert_eq!(s.buffered(), HELD, "what arrived was read ahead");
        }
        assert!(
            s.moved <= PACKETS * PACKET,
            "moved {} bytes to consume {}",
            s.moved,
            PACKETS * PACKET
        );

        while got.len() < sent.len() {
            let n = timeout(BOUND, s.read(&mut packet))
                .await
                .expect("in memory")
                .unwrap();
            got.extend_from_slice(&packet[..n]);
        }
        assert!(got == sent, "every byte came out once, in order");
    }
}
