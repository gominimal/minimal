//! Incremental decoding of raw terminal input into logical [`Key`] events.
//!
//! The reader backing a prompt is a raw-mode terminal, so keystrokes arrive as
//! bytes: a plain key is a single byte, while arrows and other function keys
//! arrive as multi-byte escape sequences (`ESC [ A`, `ESC O B`, `ESC [ 1 ; 5 A`,
//! …). Those sequences can also be split across reads. [`KeyStream`] buffers the
//! byte stream and hands back one decoded [`Key`] at a time, holding any partial
//! escape sequence until the rest arrives.

use tokio::io::{AsyncRead, AsyncReadExt};

/// A logical key press decoded from the terminal byte stream.
///
/// Only the keys a prompt cares about are given distinct variants; anything
/// recognized-but-unhandled (function keys, unknown CSI sequences) collapses to
/// [`Key::Unknown`] so callers can ignore it without inspecting raw bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Key {
    /// Cursor up (also `Ctrl-P`).
    Up,
    /// Cursor down (also `Ctrl-N`).
    Down,
    /// Cursor left.
    Left,
    /// Cursor right.
    Right,
    /// Return / newline.
    Enter,
    /// Backspace or delete.
    Backspace,
    /// A printable ASCII character.
    Char(char),
    /// `Ctrl-C`.
    CtrlC,
    /// `Ctrl-D`.
    CtrlD,
    /// A bare `Escape` press.
    Escape,
    /// A recognized-but-unhandled byte or escape sequence.
    Unknown,
}

/// Attempts to decode a single key from the front of `bytes`.
///
/// Returns `Some((key, consumed))` when a complete key (or an unhandled but
/// fully-formed sequence) is at the front, where `consumed` is the number of
/// bytes it occupied. Returns `None` when `bytes` holds only the prefix of an
/// escape sequence (or is empty) and more input is required to disambiguate.
fn decode(bytes: &[u8]) -> Option<(Key, usize)> {
    let first = *bytes.first()?;
    match first {
        0x1b => decode_escape(bytes),
        b'\r' | b'\n' => Some((Key::Enter, 1)),
        0x03 => Some((Key::CtrlC, 1)),
        0x04 => Some((Key::CtrlD, 1)),
        0x10 => Some((Key::Up, 1)),   // Ctrl-P
        0x0e => Some((Key::Down, 1)), // Ctrl-N
        0x08 | 0x7f => Some((Key::Backspace, 1)),
        0x20..=0x7e => Some((Key::Char(first as char), 1)),
        _ => Some((Key::Unknown, 1)),
    }
}

/// Decodes an escape-introduced sequence. `bytes[0]` is known to be `ESC`.
fn decode_escape(bytes: &[u8]) -> Option<(Key, usize)> {
    match bytes.get(1) {
        // Lone ESC so far — could be the start of a longer sequence.
        None => None,
        // CSI: `ESC [ … final`.
        Some(b'[') => decode_csi(bytes),
        // SS3: `ESC O final` — cursor keys in application mode.
        Some(b'O') => bytes.get(2).map(|&f| (map_final(f), 3)),
        // ESC followed by anything else: treat the ESC as a standalone key. An
        // Alt-modified key (`ESC x`) thus surfaces as Escape then the key, which
        // is fine — prompts treat Escape as "cancel" and ignore the rest.
        Some(_) => Some((Key::Escape, 1)),
    }
}

/// Longest CSI sequence we keep buffering while waiting for a final byte. A real
/// cursor-key or modified-key sequence is only a handful of bytes; anything
/// longer is malformed. Bounding it stops a stream of parameter bytes with no
/// final byte from growing the [`KeyStream`] buffer without bound.
const MAX_CSI_LEN: usize = 32;

/// Decodes a CSI sequence (`ESC [ params… final`). `bytes[0..2]` is `ESC [`.
///
/// Scans for the final byte (`0x40..=0x7e`); everything before it is parameter
/// or intermediate bytes we don't need — the final byte alone selects the key,
/// so modified arrows like `ESC [ 1 ; 5 A` still decode to [`Key::Up`].
fn decode_csi(bytes: &[u8]) -> Option<(Key, usize)> {
    // Skip the `ESC [` prefix, then take the first final byte. Parameter and
    // intermediate bytes (all below `0x40`) are skipped.
    match bytes
        .iter()
        .enumerate()
        .skip(2)
        .find(|&(_, &c)| (0x40..=0x7e).contains(&c))
    {
        Some((i, &c)) => Some((map_final(c), i + 1)),
        // No final byte yet: normally incomplete, so wait for more input. But
        // once the sequence has outgrown any legitimate length, give up and
        // consume what's buffered as unknown so the buffer can drain.
        None if bytes.len() > MAX_CSI_LEN => Some((Key::Unknown, bytes.len())),
        None => None,
    }
}

/// Maps a CSI/SS3 final byte to a cursor key, or [`Key::Unknown`].
fn map_final(final_byte: u8) -> Key {
    match final_byte {
        b'A' => Key::Up,
        b'B' => Key::Down,
        b'C' => Key::Right,
        b'D' => Key::Left,
        _ => Key::Unknown,
    }
}

/// Buffers a raw-mode terminal byte stream and yields decoded [`Key`]s.
pub struct KeyStream<R> {
    reader: R,
    buf: Vec<u8>,
    /// Offset of the first not-yet-consumed byte in `buf`.
    pos: usize,
}

impl<R: AsyncRead + Unpin> KeyStream<R> {
    /// Wraps `reader`, which should yield raw terminal input bytes.
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buf: Vec::new(),
            pos: 0,
        }
    }

    /// Reads and decodes the next key.
    ///
    /// Resolves to `Ok(None)` at end of input (the reader returned EOF), which a
    /// prompt should treat as cancellation.
    pub async fn next(&mut self) -> std::io::Result<Option<Key>> {
        loop {
            if let Some((key, consumed)) = decode(&self.buf[self.pos..]) {
                self.pos += consumed;
                return Ok(Some(key));
            }

            // The buffer holds only an incomplete sequence (or nothing). Drop the
            // already-consumed prefix before pulling more bytes so it can't grow
            // without bound across many reads.
            if self.pos > 0 {
                self.buf.drain(..self.pos);
                self.pos = 0;
            }

            let mut chunk = [0u8; 64];
            let n = self.reader.read(&mut chunk).await?;
            if n == 0 {
                return Ok(None);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_single_byte_keys() {
        assert_eq!(decode(b"\r"), Some((Key::Enter, 1)));
        assert_eq!(decode(b"\n"), Some((Key::Enter, 1)));
        assert_eq!(decode(b"\x03"), Some((Key::CtrlC, 1)));
        assert_eq!(decode(b"\x04"), Some((Key::CtrlD, 1)));
        assert_eq!(decode(b"a"), Some((Key::Char('a'), 1)));
        assert_eq!(decode(b"\x10"), Some((Key::Up, 1)));
        assert_eq!(decode(b"\x0e"), Some((Key::Down, 1)));
    }

    #[test]
    fn decodes_csi_arrows() {
        assert_eq!(decode(b"\x1b[A"), Some((Key::Up, 3)));
        assert_eq!(decode(b"\x1b[B"), Some((Key::Down, 3)));
        assert_eq!(decode(b"\x1b[C"), Some((Key::Right, 3)));
        assert_eq!(decode(b"\x1b[D"), Some((Key::Left, 3)));
    }

    #[test]
    fn decodes_ss3_arrows() {
        assert_eq!(decode(b"\x1bOA"), Some((Key::Up, 3)));
        assert_eq!(decode(b"\x1bOB"), Some((Key::Down, 3)));
    }

    #[test]
    fn decodes_modified_arrow_by_final_byte() {
        // Ctrl+Up: ESC [ 1 ; 5 A — parameters ignored, final byte wins.
        assert_eq!(decode(b"\x1b[1;5A"), Some((Key::Up, 6)));
    }

    #[test]
    fn partial_escape_needs_more_input() {
        assert_eq!(decode(b""), None);
        assert_eq!(decode(b"\x1b"), None);
        assert_eq!(decode(b"\x1b["), None);
        assert_eq!(decode(b"\x1b[1;5"), None);
    }

    #[test]
    fn overlong_csi_without_final_is_consumed_as_unknown() {
        // A parameter-byte flood with no final byte must not buffer forever: once
        // past the cap it is consumed as unknown so the stream can drain.
        let mut seq = vec![0x1b, b'['];
        seq.extend(std::iter::repeat_n(b'1', MAX_CSI_LEN));
        assert_eq!(decode(&seq), Some((Key::Unknown, seq.len())));

        // A partial sequence still within the cap stays incomplete.
        assert_eq!(decode(b"\x1b[1111"), None);
    }

    #[test]
    fn only_leading_key_is_consumed() {
        // Down-arrow followed by Enter: decode returns just the arrow.
        assert_eq!(decode(b"\x1b[B\r"), Some((Key::Down, 3)));
    }

    #[tokio::test]
    async fn key_stream_reassembles_split_sequence() {
        // The arrow sequence is delivered one byte per read via chained slices.
        // A plain `&[u8]` reader delivers everything at once, so use a duplex
        // pipe and dribble the bytes in.
        let (mut client, server) = tokio::io::duplex(64);
        let mut keys = KeyStream::new(server);

        use tokio::io::AsyncWriteExt;
        let writer = tokio::spawn(async move {
            for byte in [0x1b, b'[', b'B', b'\r'] {
                client.write_all(&[byte]).await.unwrap();
                client.flush().await.unwrap();
            }
        });

        assert_eq!(keys.next().await.unwrap(), Some(Key::Down));
        assert_eq!(keys.next().await.unwrap(), Some(Key::Enter));
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn key_stream_reports_eof() {
        let reader: &[u8] = b"a";
        let mut keys = KeyStream::new(reader);
        assert_eq!(keys.next().await.unwrap(), Some(Key::Char('a')));
        assert_eq!(keys.next().await.unwrap(), None);
    }
}
