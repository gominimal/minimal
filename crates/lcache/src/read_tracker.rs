//! Tracks which cache entries have been read and when.
//!
//! The on-disk format is append-only: each record is 32 bytes of [`SpecHash`]
//! followed by 8 bytes of epoch seconds (big-endian u64). When loading, later
//! entries for the same key supersede earlier ones and the file is compacted to
//! remove duplicates and any trailing partial records.
//!
//! The file is held under an exclusive `flock` for the lifetime of the tracker,
//! preventing concurrent access from other processes.

use common::SpecHash;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, Write};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Size of each record on disk: 32 bytes (SpecHash) + 8 bytes (epoch secs).
const RECORD_SIZE: usize = 40;

/// Number of recorded reads between flushes.
const FLUSH_INTERVAL: usize = 15;

/// A read-only snapshot of access records loaded from all tracker files in a directory.
///
/// Unlike [`ReadTracker`], this does not acquire any file locks and cannot write
/// new entries. When the same spec hash appears in multiple files, the most
/// recent timestamp wins.
#[derive(Debug)]
pub struct ReadSnapshot {
    reads: BTreeMap<SpecHash, u64>,
}

impl ReadSnapshot {
    /// Loads all `*.v1` tracker files in `dir`, merging their records.
    ///
    /// File locks are ignored — files that are currently held by a
    /// [`ReadTracker`] are still read (their on-disk content may lag behind the
    /// in-memory state of the owning process by up to [`FLUSH_INTERVAL`]
    /// records).
    pub fn load_dir(dir: &Path) -> io::Result<Self> {
        let mut reads = BTreeMap::new();

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("v1") {
                continue;
            }

            let file = match File::open(&path) {
                Ok(f) => f,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };

            let (file_reads, _) = ReadTracker::read_records(file)?;
            for (hash, epoch_secs) in file_reads {
                if reads.get(&hash).map(|e| *e < epoch_secs).unwrap_or(true) {
                    reads.insert(hash, epoch_secs);
                }
            }
        }

        Ok(Self { reads })
    }

    /// Returns a reference to the merged read records.
    pub fn reads(&self) -> &BTreeMap<SpecHash, u64> {
        &self.reads
    }

    /// Returns the last access time (epoch seconds) for the given hash, if any.
    pub fn last_read_secs(&self, hash: &SpecHash) -> Option<u64> {
        self.reads.get(hash).copied()
    }

    /// Returns the last access time (epoch seconds) for the given hash, if any.
    pub fn last_read(&self, hash: &SpecHash) -> Option<SystemTime> {
        self.reads
            .get(hash)
            .map(|epoch_secs| UNIX_EPOCH + Duration::from_secs(*epoch_secs))
    }
}

/// Tracks cache reads by spec hash, recording the last access time for each.
///
/// Records are periodically flushed to a file for persistence. The writer is a
/// [`BufWriter`] so individual [`record_read`](ReadTracker::record_read) calls
/// only memcpy into the buffer; an actual `flush` syscall happens every
/// [`FLUSH_INTERVAL`] records. On [`Drop`] the file is compacted so that each
/// key appears exactly once.
///
/// An exclusive `flock` is held on the underlying file for the lifetime of this
/// value. [`at_path`](ReadTracker::at_path) fails immediately if the lock is
/// already held by another process.
#[derive(Debug)]
pub struct ReadTracker {
    /// Maps each cache entry to its last access time (epoch seconds).
    reads: BTreeMap<SpecHash, u64>,
    /// Buffered file handle for persisting records (also holds the flock).
    ///
    /// Wrapped in `Option` so [`Drop`] can take ownership via
    /// [`into_parts`](BufWriter::into_parts) without flushing stale data.
    writer: Option<BufWriter<File>>,
    /// Records written since last flush.
    pending: usize,
}

impl ReadTracker {
    /// Opens a tracker backed by `path`.
    ///
    /// If the file exists, its records are streamed into memory and the file is
    /// compacted (duplicate entries and trailing partial records are removed).
    /// If the file does not exist it is created.
    ///
    /// An exclusive `flock` is acquired on the file. Returns an error
    /// immediately if another process already holds the lock.
    pub fn at_path(path: &Path) -> io::Result<Self> {
        let mut file = File::options()
            .read(true)
            .create(true)
            .append(true)
            .open(path)?;

        // Acquire exclusive lock; fail immediately if held elsewhere.
        let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        let (reads, _records_read) = Self::read_records(&file)?;

        file.seek(io::SeekFrom::End(0))?;
        Ok(Self {
            reads,
            writer: Some(BufWriter::new(file)),
            pending: 0,
        })
    }

    /// Returns a mutable reference to the inner [`BufWriter`].
    fn writer(&mut self) -> &mut BufWriter<File> {
        self.writer.as_mut().unwrap()
    }

    /// Streams records from `reader` and returns the resolved map together with
    /// the total number of raw records read (including duplicates).
    fn read_records(reader: impl Read) -> io::Result<(BTreeMap<SpecHash, u64>, u64)> {
        let mut map = BTreeMap::new();
        let mut reader = BufReader::new(reader);
        let mut buf = [0u8; RECORD_SIZE];
        let mut records_read: u64 = 0;

        loop {
            match reader.read_exact(&mut buf) {
                Ok(()) => {
                    let hash_bytes: [u8; 32] = buf[..32].try_into().unwrap();
                    let epoch_secs = u64::from_be_bytes(buf[32..40].try_into().unwrap());

                    let hash = SpecHash::from_bytes(hash_bytes);
                    if map.get(&hash).map(|e| *e < epoch_secs).unwrap_or(true) {
                        map.insert(hash, epoch_secs);
                    }

                    records_read += 1;
                }
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
        }

        Ok((map, records_read))
    }

    /// Truncates `file` and rewrites it with exactly one record per entry in
    /// `reads`, removing duplicates and trailing garbage.
    fn compact(file: &mut File, reads: &BTreeMap<SpecHash, u64>) -> io::Result<()> {
        file.set_len(0)?;
        file.seek(io::SeekFrom::Start(0))?;
        for (hash, epoch_secs) in reads {
            file.write_all(hash.as_bytes())?;
            file.write_all(&epoch_secs.to_be_bytes())?;
        }
        file.flush()
    }

    /// Records a read of `hash` at the current time.
    ///
    /// This is the hot-path method: it writes into a [`BufWriter`] buffer and
    /// only issues a flush syscall every [`FLUSH_INTERVAL`] calls.
    pub fn record_read(&mut self, hash: &SpecHash) -> io::Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.record_read_at(hash, now)
    }

    /// Records a read of `hash` at the given epoch-seconds timestamp.
    fn record_read_at(&mut self, hash: &SpecHash, epoch_secs: u64) -> io::Result<()> {
        self.reads.insert(hash.clone(), epoch_secs);

        self.writer().write_all(hash.as_bytes())?;
        self.writer().write_all(&epoch_secs.to_be_bytes())?;
        self.pending += 1;

        if self.pending >= FLUSH_INTERVAL {
            self.writer().flush()?;
            self.pending = 0;
        }

        Ok(())
    }

    /// Returns a reference to the in-memory read records.
    #[allow(dead_code)]
    pub fn reads(&self) -> &BTreeMap<SpecHash, u64> {
        &self.reads
    }

    /// Flushes any pending writes to disk.
    #[allow(dead_code)]
    fn flush(&mut self) -> io::Result<()> {
        self.writer().flush()?;
        self.pending = 0;
        Ok(())
    }
}

impl Drop for ReadTracker {
    fn drop(&mut self) {
        if let Some(writer) = self.writer.take() {
            // `into_parts` extracts the file without flushing stale buffered
            // data — compact rewrites the entire file from the canonical
            // in-memory state.
            let (mut file, _) = writer.into_parts();
            if let Err(e) = Self::compact(&mut file, &self.reads) {
                tracing::warn!("Failed to write cache access log: {}", e);
            }
        }
        // flock is released when the file descriptor is closed.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_hash(data: &str) -> SpecHash {
        SpecHash(blake3::hash(data.as_bytes()))
    }

    #[test]
    fn new_file_and_record() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("reads.bin");

        let mut tracker = ReadTracker::at_path(&path).unwrap();
        let h = test_hash("pkg-a");
        tracker.record_read(&h).unwrap();

        assert_eq!(tracker.reads().len(), 1);
        assert!(tracker.reads().contains_key(&h));
    }

    #[test]
    fn load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("reads.bin");

        let h1 = test_hash("pkg-a");
        let h2 = test_hash("pkg-b");

        {
            let mut tracker = ReadTracker::at_path(&path).unwrap();
            tracker.record_read_at(&h1, 1000).unwrap();
            tracker.record_read_at(&h2, 2000).unwrap();
        }

        let tracker = ReadTracker::at_path(&path).unwrap();
        assert_eq!(tracker.reads().len(), 2);
        assert_eq!(tracker.reads()[&h1], 1000);
        assert_eq!(tracker.reads()[&h2], 2000);
    }

    #[test]
    fn drop_flushes_pending() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("reads.bin");

        let h = test_hash("pkg-a");

        {
            let mut tracker = ReadTracker::at_path(&path).unwrap();
            tracker.record_read_at(&h, 42).unwrap();
            assert_eq!(tracker.pending, 1);
        }

        let tracker = ReadTracker::at_path(&path).unwrap();
        assert_eq!(tracker.reads().len(), 1);
        assert_eq!(tracker.reads()[&h], 42);
    }

    #[test]
    fn drop_compacts_duplicates() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("reads.bin");

        let h = test_hash("pkg-a");

        {
            let mut tracker = ReadTracker::at_path(&path).unwrap();
            tracker.record_read_at(&h, 1000).unwrap();
            tracker.record_read_at(&h, 5000).unwrap();
        }

        // Drop compacted the two records for the same key into one.
        assert_eq!(std::fs::metadata(&path).unwrap().len(), RECORD_SIZE as u64);

        let tracker = ReadTracker::at_path(&path).unwrap();
        assert_eq!(tracker.reads().len(), 1);
        assert_eq!(tracker.reads()[&h], 5000);
    }

    #[test]
    fn concurrent_open_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("reads.bin");

        let _tracker = ReadTracker::at_path(&path).unwrap();

        // Second open on the same path should fail because the lock is held.
        let err = ReadTracker::at_path(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn snapshot_merges_multiple_files() {
        let dir = TempDir::new().unwrap();
        let alog = dir.path();

        let h1 = test_hash("pkg-a");
        let h2 = test_hash("pkg-b");
        let h3 = test_hash("pkg-c");

        // Write two separate tracker files with overlapping keys.
        {
            let mut t = ReadTracker::at_path(&alog.join("0.v1")).unwrap();
            t.record_read_at(&h1, 1000).unwrap();
            t.record_read_at(&h2, 2000).unwrap();
        }
        {
            let mut t = ReadTracker::at_path(&alog.join("1.v1")).unwrap();
            t.record_read_at(&h2, 3000).unwrap(); // newer than file 0
            t.record_read_at(&h3, 4000).unwrap();
        }

        let snap = ReadSnapshot::load_dir(alog).unwrap();
        assert_eq!(snap.reads().len(), 3);
        assert_eq!(snap.last_read_secs(&h1), Some(1000));
        assert_eq!(snap.last_read_secs(&h2), Some(3000)); // took the newer one
        assert_eq!(snap.last_read_secs(&h3), Some(4000));
    }

    #[test]
    fn snapshot_reads_while_tracker_holds_lock() {
        let dir = TempDir::new().unwrap();
        let alog = dir.path();

        let h = test_hash("pkg-a");

        // Tracker holds the flock; snapshot should still read the on-disk data.
        let mut tracker = ReadTracker::at_path(&alog.join("0.v1")).unwrap();
        tracker.record_read_at(&h, 500).unwrap();
        tracker.flush().unwrap();

        let snap = ReadSnapshot::load_dir(alog).unwrap();
        assert_eq!(snap.last_read_secs(&h), Some(500));
    }

    #[test]
    fn snapshot_skips_non_v1_files() {
        let dir = TempDir::new().unwrap();
        let alog = dir.path();

        // Write a .v1 file and a non-.v1 file.
        {
            let mut t = ReadTracker::at_path(&alog.join("0.v1")).unwrap();
            t.record_read_at(&test_hash("a"), 100).unwrap();
        }
        std::fs::write(alog.join("garbage.txt"), b"not a tracker").unwrap();

        let snap = ReadSnapshot::load_dir(alog).unwrap();
        assert_eq!(snap.reads().len(), 1);
    }
}
