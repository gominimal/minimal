//! The kernel ring buffer, read straight from `/dev/kmsg`.
//!
//! A guest bundle fetched on its own carries no kernel evidence otherwise.
//! Kernel messages reach the host only over the `console=hvc0` stream the
//! *host* collector captures into `boot.log`, and that file is recreated per
//! boot and tail-capped — so the banner naming the running kernel, written
//! first, is the first thing a long-lived VM drops. The microVM rootfs ships
//! no `dmesg` either, which is fine: `/dev/kmsg` needs no tool, just one
//! `read(2)` per record.
//!
//! Mechanics only, per this crate's split — where the capture lands and how
//! much of it is kept are the caller's policy.

#[cfg(any(target_os = "linux", test))]
use std::collections::VecDeque;

use crate::bundle::{BundleSink, BundleWriter, scoped};
#[cfg(target_os = "linux")]
use crate::manifest::Redaction;

/// One `read(2)` on `/dev/kmsg` returns exactly one record, and fails with
/// `EINVAL` rather than truncating when the buffer cannot hold it whole. The
/// kernel's own record limit is `PRINTK_MESSAGE_MAX` (2 KiB); 8 KiB leaves
/// room for the dictionary half a record may carry.
#[cfg(target_os = "linux")]
const RECORD_BUF: usize = 8 * 1024;

/// Bound on records consumed in one pass. The read stops at `EAGAIN` — the end
/// of the buffer — but a kernel logging faster than this loop drains it would
/// never produce one, so the pass is bounded by count as well.
#[cfg(target_os = "linux")]
const RECORDS_MAX: usize = 64 * 1024;

/// `<dest>/logs/kmsg.txt`: the tail of the kernel ring buffer, at most `cap`
/// bytes, in the kernel's own order and format.
///
/// Raw records, not decoded — the `priority,sequence,timestamp,flags;message`
/// prefix is data (the sequence numbers show what the buffer dropped), and
/// fidelity beats prettiness here for the same reason it does in
/// [`crate::net::proc_net_tables`].
///
/// Absence, unreadability and capping are each recorded rather than silent: on
/// a restricted or stripped host "no kernel evidence" is itself the finding,
/// and a reader must be able to tell it from a collector that never ran.
pub async fn kmsg_tail<W: BundleSink>(
    w: &mut BundleWriter<W>,
    dest: &str,
    cap: u64,
) -> Result<(), anyhow::Error> {
    let path = scoped(dest, "logs/kmsg.txt");
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cap;
        w.skip(path, "the kernel ring buffer needs /dev/kmsg");
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        use anyhow::Context as _;
        // Up to `RECORDS_MAX` synchronous reads — off the caller's runtime, the
        // same discipline the `/proc` walks use. `O_NONBLOCK` means no single
        // read waits on the kernel, but the pass is still a syscall loop.
        let read = tokio::task::spawn_blocking(move || read_kmsg(cap))
            .await
            .context("kmsg worker")?;
        match read {
            Ok((bytes, dropped)) => {
                let redaction = if dropped {
                    Redaction::TailCapped
                } else {
                    Redaction::None
                };
                w.add_bytes(&path, &bytes, redaction).await
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                w.skip(
                    path,
                    "no /dev/kmsg — this kernel does not expose the ring buffer here",
                );
                Ok(())
            }
            // Most often `EACCES`/`EPERM`: not root, or `kernel.dmesg_restrict`
            // is set. Either way the errno is the answer, so it travels as-is.
            Err(e) => {
                w.skip(path, format!("unreadable: {e}"));
                Ok(())
            }
        }
    }
}

/// Reads the ring buffer to its end, keeping the last `cap` bytes of it.
///
/// `O_NONBLOCK` is what makes "read to the end" terminate at all: without it
/// the read that exhausts the buffer blocks until the kernel logs something
/// new, which on the quiet wedged guest this capture exists for may be never.
/// The end of the buffer is therefore `EAGAIN`, not EOF.
///
/// Returns the bytes and whether anything older than them is missing.
#[cfg(target_os = "linux")]
fn read_kmsg(cap: u64) -> std::io::Result<(Vec<u8>, bool)> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/dev/kmsg")?;

    let mut buf = vec![0u8; RECORD_BUF];
    let mut tail = RecordTail::new(cap);
    let mut overwritten = false;
    let mut drained = false;
    for _ in 0..RECORDS_MAX {
        match file.read(&mut buf) {
            Ok(0) => {
                drained = true;
                break;
            }
            Ok(n) => tail.push(buf[..n].to_vec()),
            // `EAGAIN`: the buffer is drained, which is the only end there is.
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                drained = true;
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            // `EPIPE`: records were overwritten between reads. The file
            // position has already advanced to the oldest surviving record, so
            // carry on — what was lost is exactly what a tail drops anyway.
            Err(e) if e.raw_os_error() == Some(libc::EPIPE) => overwritten = true,
            Err(e) => return Err(e),
        }
    }
    // Hitting the count bound truncates the *newest* end, the opposite of what
    // a tail promises, so it is stated in the capture rather than inferred.
    if !drained {
        tail.push(
            format!("<kmsg: stopped after {RECORDS_MAX} records; newer messages were not read>\n")
                .into_bytes(),
        );
    }
    let (bytes, dropped) = tail.into_bytes();
    Ok((bytes, dropped || overwritten || !drained))
}

/// A bounded tail of whole records: pushing past `cap` drops the oldest.
///
/// Whole records only. The cap is a size bound, not a line budget, and half a
/// kmsg record is a corrupt line rather than a shorter one — so the newest
/// record is kept even when it alone exceeds the cap.
#[cfg(any(target_os = "linux", test))]
struct RecordTail {
    kept: VecDeque<Vec<u8>>,
    held: u64,
    cap: u64,
    dropped: bool,
}

#[cfg(any(target_os = "linux", test))]
impl RecordTail {
    fn new(cap: u64) -> Self {
        Self {
            kept: VecDeque::new(),
            held: 0,
            cap,
            dropped: false,
        }
    }

    fn push(&mut self, record: Vec<u8>) {
        self.held += record.len() as u64;
        self.kept.push_back(record);
        while self.held > self.cap && self.kept.len() > 1 {
            let oldest = self.kept.pop_front().expect("len > 1 was just checked");
            self.held -= oldest.len() as u64;
            self.dropped = true;
        }
    }

    /// The kept records concatenated, and whether anything older was dropped.
    fn into_bytes(self) -> (Vec<u8>, bool) {
        (self.kept.into_iter().flatten().collect(), self.dropped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_tail_drops_whole_records_from_the_oldest_end() {
        let mut tail = RecordTail::new(10);
        tail.push(b"aaaa".to_vec());
        tail.push(b"bbbb".to_vec());
        tail.push(b"cccc".to_vec());
        let (bytes, dropped) = tail.into_bytes();
        assert_eq!(bytes, b"bbbbcccc", "the oldest record goes, not half of it");
        assert!(dropped, "the loss is reported, not silent");
    }

    #[test]
    fn record_tail_under_the_cap_drops_nothing() {
        let mut tail = RecordTail::new(64);
        tail.push(b"one\n".to_vec());
        tail.push(b"two\n".to_vec());
        assert_eq!(tail.into_bytes(), (b"one\ntwo\n".to_vec(), false));
    }

    /// A single record over the cap is kept whole: half a record is a corrupt
    /// line, and dropping the newest message defeats the point of the capture.
    #[test]
    fn record_tail_keeps_a_record_larger_than_the_cap() {
        let mut tail = RecordTail::new(4);
        tail.push(b"older".to_vec());
        tail.push(b"a record longer than the cap".to_vec());
        let (bytes, dropped) = tail.into_bytes();
        assert_eq!(bytes, b"a record longer than the cap");
        assert!(dropped);
    }

    /// Whatever the host permits, the bundle explains itself: the buffer is
    /// either collected or the manifest says why it is not.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn kmsg_is_either_collected_or_explained() {
        let tmp = tempfile::TempDir::new().unwrap();
        let out = tmp.path().join("b.tar.zst");
        let mut w = BundleWriter::create(&out, "r", "v").await.unwrap();
        kmsg_tail(&mut w, "", 64 * 1024).await.unwrap();
        w.finish(chrono::Utc::now(), std::time::Duration::ZERO)
            .await
            .unwrap();

        let files = crate::bundle::tests::unpack_bundle(&out, "r").await;
        let manifest: serde_json::Value = serde_json::from_slice(&files["manifest.json"]).unwrap();
        let recorded = format!("{}{}", manifest["collected"], manifest["skipped"]);
        assert!(
            recorded.contains("logs/kmsg.txt"),
            "present or explained, never silent: {recorded}"
        );
        assert!(
            manifest["errors"].as_array().unwrap().is_empty(),
            "an absent or restricted ring buffer is a skip, not a collector failure: {}",
            manifest["errors"]
        );
    }
}
