//! GCS-specific writer for the shared cache that uses optimistic concurrency
//! to safely merge index updates from multiple concurrent writers.
//!
//! See the historical note at the top of `remote.rs` for why this is split
//! off from [crate::RemoteCache]: the previous design did an unsynchronized
//! read-modify-write on `index.shisha` which lost entries when two writers
//! raced.

use crate::INDEX_FILENAME;
use crate::index_file::IndexFile;
use crate::remote::Error;
use common::SpecHash;
use common::fetchers::{FetchUrl, GcsUrl};
use google_cloud_storage::Error as GcsError;
use google_cloud_storage::client::Storage;
use google_cloud_storage::stub::{DefaultStorage, Storage as StubStorage};
use ot::OpTracker;
use std::time::Duration;
use tokio::time::sleep;

/// Maximum retries on `if_generation_match` contention before giving up.
/// With the backoff schedule below, 8 retries cap total contention-wait at
/// ~508s (4+8+16+32+64+128+128+128 s). After that, the underlying GCS
/// error is bubbled up and the run fails. Total writes attempted is
/// `MAX_INDEX_WRITE_RETRIES + 1` (the initial attempt).
const MAX_INDEX_WRITE_RETRIES: u32 = 8;

/// Initial backoff between retries; doubled each attempt up to a cap.
/// Set to span the index file's `Cache-Control: max-age=300` window so
/// retries can wait out any HTTP cache layer that might serve a stale
/// generation back during refetch.
const INITIAL_RETRY_BACKOFF_MS: u64 = 2000;

/// HTTP status returned by GCS when an `if_generation_match` precondition
/// fails (i.e. the object's generation has changed since we read it).
const PRECONDITION_FAILED: u16 = 412;
/// GCS returns 429 when one object name is mutated more than about once a second.
const TOO_MANY_REQUESTS: u16 = 429;
/// Retries for a 429 on an artifact write; the collision is another uploader of the
/// same content, so a short wait is enough.
const MAX_OBJECT_WRITE_RETRIES: u32 = 5;
const OBJECT_WRITE_BACKOFF_MS: u64 = 600;

/// HTTP status returned by GCS when reading a non-existent object.
const NOT_FOUND: u16 = 404;

/// A writer for the shared cache that uses optimistic concurrency on the
/// index file's GCS generation.
///
/// Construct with [Self::new], call [Self::upload] for each artifact, then
/// [Self::finish_uploads] to commit the merged index. On contention with
/// another writer (412 Precondition Failed), refetches the current index
/// and retries with bounded exponential backoff, so the new write always
/// includes both our pending entries AND any entries committed by the
/// other writer in the meantime.
///
/// Not `Clone` on purpose — cloning the pending list and committing twice
/// would either redo work or upload divergent state. Construct one writer
/// per upload session and consume it via [Self::finish_uploads].
///
/// Generic over the GCS backend stub so tests can inject a mock via
/// [`google_cloud_storage::client::Storage::from_stub`] and exercise the
/// CAS retry loop end-to-end through the public API. Production code
/// uses the default ([`DefaultStorage`]) and never names the type
/// parameter.
#[derive(Debug)]
pub struct RemoteCacheWriter<S: StubStorage + 'static = DefaultStorage> {
    backend: Storage<S>,
    base: GcsUrl,

    /// The index as it was when we last fetched it from GCS. Used both as the
    /// base to merge `pending` into, and as a dedup check in [Self::upload]
    /// to skip uploads of artifacts already present.
    fetched_index: IndexFile,

    /// The GCS object generation that `fetched_index` was loaded from.
    /// `0` means the index file did not exist at fetch time, which
    /// also doubles as the "create-if-not-exists" precondition value
    /// for `set_if_generation_match`.
    fetched_generation: i64,

    /// `(spec_hash, sha256)` entries to merge into the index on finish.
    pending: Vec<(SpecHash, [u8; 32])>,

    #[allow(dead_code)]
    ot: Option<OpTracker>,
}

impl RemoteCacheWriter<DefaultStorage> {
    /// Initialize a writer against the given GCS bucket. Always fetches the
    /// current index fresh from GCS — there's no local-cache fast path,
    /// because the recorded generation must match the actual cloud state
    /// for the compare-and-swap on commit to be meaningful.
    pub async fn new(
        storage: Storage,
        bucket_id: &str,
        ot: Option<OpTracker>,
    ) -> Result<Self, Error<GcsError>> {
        let base = GcsUrl {
            bucket: format!("projects/_/buckets/{bucket_id}"),
            object: "".to_string(),
        };

        let (fetched_index, fetched_generation) = fetch_gcs_index(&storage, &base).await?;

        Ok(Self::from_parts(
            storage,
            base,
            fetched_index,
            fetched_generation,
            ot,
        ))
    }
}

impl<S: StubStorage + 'static> RemoteCacheWriter<S> {
    /// Construct directly from already-fetched index + generation. Used by
    /// [`crate::RemoteCache::into_writer`] to avoid a redundant fetch when
    /// converting a freshly-loaded reader into a writer, and by tests to
    /// inject a mock backend via [`Storage::from_stub`].
    pub(crate) fn from_parts(
        backend: Storage<S>,
        base: GcsUrl,
        fetched_index: IndexFile,
        fetched_generation: i64,
        ot: Option<OpTracker>,
    ) -> Self {
        Self {
            backend,
            base,
            fetched_index,
            fetched_generation,
            pending: Vec::new(),
            ot,
        }
    }

    /// Upserts the given artifact to the GCS bucket, staging it for inclusion
    /// in the index. Returns `false` if the given artifact's `(spec_hash, sha256)`
    /// pair is already in the fetched index (and the upload was skipped).
    ///
    /// The artifact blob upload is content-addressed, so concurrent uploads
    /// of the same blob bytes are safe (last-writer-wins on identical content).
    /// The index update is deferred to [Self::finish_uploads].
    #[tracing::instrument(skip_all, err)]
    pub async fn upload(
        &mut self,
        spec_hash: &SpecHash,
        artifact: (std::fs::File, [u8; 32]),
    ) -> Result<bool, Error<GcsError>> {
        let (tar_file, sha256) = artifact;
        let indexed_sha = self.fetched_index.sha256(spec_hash);
        if indexed_sha == Some(sha256) {
            return Ok(false); // Cached one is up to date.
        }
        let object = self
            .base
            .join(&format!("{}.zst", hex::encode(sha256)))
            .unwrap()
            .object;
        // An unreadable length is an error, not 0: a 0 would match an empty
        // object left by a partial upload under this name.
        let local_len = tar_file.metadata().map(|m| m.len()).map_err(Error::IO)?;
        let local_crc32c = {
            let f = tar_file.try_clone().map_err(Error::IO)?;
            tokio::task::spawn_blocking(move || file_crc32c(&f))
                .await
                .map_err(|e| Error::IO(std::io::Error::other(e)))?
                .map_err(Error::IO)?
        };
        if self.object_present(&object, local_len, local_crc32c).await {
            // The object is content-addressed, and GCS keeps a CRC32C of every
            // object it stores: the same name at the same length with the same
            // checksum is the same bytes, so nothing to write. (A partial earlier
            // upload differs in length; an object someone else put under this
            // name differs in checksum, and is written over as it always was.)
            // Small identical outputs — several packages produce the same empty
            // tarball — are the common case here, and rewriting them from
            // parallel uploaders trips GCS's per-object mutation rate limit.
            // Still pending: the index may not map this spec hash to it yet.
            self.pending.push((spec_hash.clone(), sha256));
            return Ok(false);
        }

        let mut attempt = 0;
        loop {
            let mut f = tar_file.try_clone().map_err(Error::IO)?;
            // The clones share one file offset, and an attempt that failed has
            // usually read to the end (a small object is read whole before it is
            // sent): every attempt starts from the first byte, or a retry would
            // write an empty object under this content's name.
            std::io::Seek::seek(&mut f, std::io::SeekFrom::Start(0)).map_err(Error::IO)?;
            match self
                .backend
                .write_object(
                    self.base.bucket.clone(),
                    object.clone(),
                    tokio::fs::File::from_std(f),
                )
                .set_cache_control("public, max-age=7200")
                .send_buffered()
                .await
            {
                Ok(_) => break,
                Err(e)
                    if e.http_status_code() == Some(TOO_MANY_REQUESTS)
                        && attempt < MAX_OBJECT_WRITE_RETRIES =>
                {
                    // Another uploader wrote this same object within the last second.
                    attempt += 1;
                    let backoff_ms = OBJECT_WRITE_BACKOFF_MS.saturating_mul(1u64 << attempt.min(4));
                    tokio::time::sleep(std::time::Duration::from_millis(
                        backoff_ms + jitter_ms(backoff_ms),
                    ))
                    .await;
                    // That write was this same content: once it has landed there is
                    // nothing left to write, and not writing spares the hot name
                    // another mutation.
                    if self.object_present(&object, local_len, local_crc32c).await {
                        self.pending.push((spec_hash.clone(), sha256));
                        return Ok(false);
                    }
                }
                // Out of retries on a 429: the name was mutated within the last
                // second, so the other uploader's object has very likely landed.
                // One last look before giving up, as after every other 429.
                Err(e) if e.http_status_code() == Some(TOO_MANY_REQUESTS) => {
                    if self.object_present(&object, local_len, local_crc32c).await {
                        self.pending.push((spec_hash.clone(), sha256));
                        return Ok(false);
                    }
                    return Err(Error::Backend(e));
                }
                Err(e) => return Err(Error::Backend(e)),
            }
        }

        self.pending.push((spec_hash.clone(), sha256));
        Ok(true)
    }

    /// Whether the content-addressed object `object` exists at `len` bytes
    /// with the CRC32C `crc32c`, which GCS computes over every object it
    /// stores: the name alone is only a claim about the bytes (anyone who can
    /// write the bucket can put other bytes under it, at any length), and the
    /// local artifact is the bytes the name was derived from. A read that
    /// fails, or an object with no checksum, reads as absent, so the caller
    /// writes.
    async fn object_present(&self, object: &str, len: u64, crc32c: u32) -> bool {
        matches!(
            self.backend
                .open_object(self.base.bucket.clone(), object.to_string())
                .send()
                .await,
            Ok(stat) if stat.object().size as u64 == len
                && stat.object().checksums.as_ref().and_then(|c| c.crc32c) == Some(crc32c)
        )
    }

    /// Commit the merged index back to GCS with compare-and-swap semantics.
    ///
    /// Writes `index.shisha` with `if_generation_match=fetched_generation`.
    /// On 412 (another writer committed in between), refetches the current
    /// index, re-merges our pending entries onto it, and retries with the
    /// new generation. The merge is naturally idempotent because
    /// `BTreeMap::extend` with the same `(spec_hash, sha256)` is a no-op,
    /// so concurrent writers committing the same entries will both succeed
    /// without producing inconsistent state.
    ///
    /// Bounded by [MAX_INDEX_WRITE_RETRIES] attempts with exponential backoff
    /// + jitter; after exhaustion the underlying GCS error is returned.
    #[tracing::instrument(skip_all, err)]
    pub async fn finish_uploads(self) -> Result<(), Error<GcsError>> {
        let Self {
            backend,
            base,
            mut fetched_index,
            mut fetched_generation,
            pending,
            ot: _,
        } = self;

        let mut attempt: u32 = 0;
        loop {
            // Build the merged index for this attempt. We rebuild from the
            // freshly-fetched base each iteration so retries pick up any
            // entries other writers committed in the meantime.
            let merged = merge_for_commit(&fetched_index, &pending);

            let mut data = Vec::with_capacity(2048);
            merged.write_to(&mut data).map_err(Error::IO)?;

            let result = backend
                .write_object(
                    base.bucket.clone(),
                    base.join(INDEX_FILENAME).unwrap().object,
                    bytes::Bytes::from(data),
                )
                .set_cache_control("public, max-age=300")
                .set_if_generation_match(fetched_generation)
                .send_buffered()
                .await;

            let err = match result {
                Ok(_) => return Ok(()),
                Err(e) => e,
            };
            let status = err.http_status_code();

            match decide_retry_after_failure(status, attempt) {
                RetryAfterFailure::GiveUp => {
                    if status == Some(PRECONDITION_FAILED) {
                        tracing::warn!(
                            attempt,
                            "index write contention exceeded retries; giving up"
                        );
                    }
                    return Err(Error::Backend(err));
                }
                RetryAfterFailure::Retry { backoff_ms } => {
                    attempt += 1;
                    let jitter = jitter_ms(backoff_ms);
                    tracing::info!(
                        attempt,
                        backoff_ms,
                        "index write contention (412); refetching and retrying"
                    );
                    sleep(Duration::from_millis(backoff_ms + jitter)).await;

                    let (new_index, new_gen) = fetch_gcs_index(&backend, &base).await?;
                    fetched_index = new_index;
                    fetched_generation = new_gen;
                }
            }
        }
    }
}

/// Decision returned by [decide_retry_after_failure] for a single failed
/// write attempt. Only consulted on `Err` — `Ok` returns are handled at the
/// call site before reaching this. Modeling it this way prevents a class
/// of bugs where a non-HTTP transport error (no status code) would be
/// silently mapped to "success."
#[derive(Debug, PartialEq, Eq)]
enum RetryAfterFailure {
    /// Schedule a retry after sleeping `backoff_ms` (plus jitter).
    Retry { backoff_ms: u64 },
    /// Bubble up the underlying error.
    GiveUp,
}

/// Pure retry policy: given a failed write's HTTP status code (or `None` for
/// non-HTTP errors like network timeouts) and the count of attempts already
/// made, decide whether to retry or surface the error.
///
/// Retries only on 412 Precondition Failed (the contention signal). All
/// other errors — including transport errors with no status code — are
/// surfaced immediately, since they aren't transient in a way retrying
/// could fix here.
fn decide_retry_after_failure(status_code: Option<u16>, attempts_so_far: u32) -> RetryAfterFailure {
    if status_code == Some(PRECONDITION_FAILED) && attempts_so_far < MAX_INDEX_WRITE_RETRIES {
        // Exponential backoff capped at 2^6 * INITIAL = ~6.4s. We index by
        // `attempts_so_far + 1` so the first retry waits 2x INITIAL — there
        // was already a round-trip's worth of contention before getting here.
        let exp = (attempts_so_far + 1).min(6);
        let backoff_ms = INITIAL_RETRY_BACKOFF_MS.saturating_mul(1u64 << exp);
        RetryAfterFailure::Retry { backoff_ms }
    } else {
        RetryAfterFailure::GiveUp
    }
}

/// Build the index that will be written for this attempt: fetched + pending.
/// Extracted so the merge invariant ("no entries lost across retries") can
/// be exercised at the data-structure level without going through GCS.
fn merge_for_commit(fetched: &IndexFile, pending: &[(SpecHash, [u8; 32])]) -> IndexFile {
    let mut merged = fetched.clone();
    merged.extend(pending.iter().cloned());
    merged
}

/// Fetch the index file from GCS, returning both its parsed content and the
/// GCS generation it was loaded from. Returns `(default, 0)` if the index
/// doesn't exist yet — `0` doubles as the "create-if-not-exists" precondition
/// value for subsequent `if_generation_match` writes.
///
/// Shared between [`RemoteCacheWriter::new`] and
/// [`crate::RemoteCache::into_writer`] (the latter calls this only when
/// the reader was loaded from local cache and lacks a recorded generation).
pub(crate) async fn fetch_gcs_index<S: StubStorage + 'static>(
    backend: &Storage<S>,
    base: &GcsUrl,
) -> Result<(IndexFile, i64), Error<GcsError>> {
    let url = base.join(INDEX_FILENAME).unwrap();
    let mut response = match backend.read_object(url.bucket, url.object).send().await {
        Ok(r) => r,
        Err(e) => {
            if e.http_status_code() == Some(NOT_FOUND) {
                return Ok((IndexFile::default(), 0));
            }
            return Err(Error::Backend(e));
        }
    };

    let generation = response.object().generation;
    let size = response.object().size as usize;

    let mut buffer = Vec::with_capacity(size);
    while let Some(chunk) = response.next().await {
        let chunk = chunk.map_err(Error::Backend)?;
        buffer.extend_from_slice(&chunk);
    }

    let index = IndexFile::from_reader(&mut std::io::Cursor::new(buffer)).map_err(Error::IO)?;

    Ok((index, generation))
}

/// The CRC32C of `file`'s bytes, read from the start through a clone of its
/// own: the clones share one offset, and the write that may follow rewinds
/// the one it reads through.
fn file_crc32c(file: &std::fs::File) -> std::io::Result<u32> {
    use std::io::{Read as _, Seek as _};
    let mut f = file.try_clone()?;
    f.seek(std::io::SeekFrom::Start(0))?;
    let mut crc = 0;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            return Ok(crc);
        }
        crc = crc32c::crc32c_append(crc, &buf[..n]);
    }
}

/// Pseudo-random jitter in `0..backoff_ms` derived from the system clock.
/// Avoids pulling in a real RNG dep for the modest amount of randomness
/// needed to break synchronized retry storms across concurrent writers.
fn jitter_ms(backoff_ms: u64) -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    nanos % backoff_ms.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use google_cloud_storage as gcs;
    use google_cloud_storage::Result as GcsResult;
    use google_cloud_storage::http::HeaderMap;
    use google_cloud_storage::model::{Object, ReadObjectRequest};
    use google_cloud_storage::model_ext::{
        ObjectHighlights, OpenObjectRequest, WriteObjectRequest,
    };
    use google_cloud_storage::object_descriptor::ObjectDescriptor;
    use google_cloud_storage::read_object::ReadObjectResponse;
    use google_cloud_storage::request_options::RequestOptions;
    use google_cloud_storage::streaming_source::{BytesSource, Payload, Seek, StreamingSource};
    use mockall::Sequence;

    // The mock backend implements the GCS stub trait so we can wrap it in a
    // real `Storage<MockStorage>` client via `Storage::from_stub`. The writer
    // is generic over the stub type, so the tests construct
    // `RemoteCacheWriter<MockStorage>` and exercise `finish_uploads` through
    // its public API. Asserting on `if_generation_match` in the recorded
    // requests is how we prove the writer used the right generation on each
    // retry — the actual contract under contention.
    mockall::mock! {
        #[derive(Debug)]
        Storage {}
        impl gcs::stub::Storage for Storage {
            async fn read_object(
                &self,
                _req: ReadObjectRequest,
                _options: RequestOptions,
            ) -> GcsResult<ReadObjectResponse>;
            async fn write_object_buffered<P: StreamingSource + Send + Sync + 'static>(
                &self,
                _payload: P,
                _req: WriteObjectRequest,
                _options: RequestOptions,
            ) -> GcsResult<Object>;
            async fn write_object_unbuffered<P: StreamingSource + Seek + Send + Sync + 'static>(
                &self,
                _payload: P,
                _req: WriteObjectRequest,
                _options: RequestOptions,
            ) -> GcsResult<Object>;
            async fn open_object(
                &self,
                _request: OpenObjectRequest,
                _options: RequestOptions,
            ) -> GcsResult<(ObjectDescriptor, Vec<ReadObjectResponse>)>;
        }
    }

    fn test_base() -> GcsUrl {
        GcsUrl {
            bucket: "projects/_/buckets/test".to_string(),
            object: "".to_string(),
        }
    }

    fn writer_from_mock(
        mock: MockStorage,
        fetched_index: IndexFile,
        fetched_generation: i64,
    ) -> RemoteCacheWriter<MockStorage> {
        let storage = gcs::client::Storage::from_stub(mock);
        RemoteCacheWriter::from_parts(
            storage,
            test_base(),
            fetched_index,
            fetched_generation,
            None,
        )
    }

    /// Serialize a IndexFile to bytes and return as a ReadObjectResponse
    /// with the given generation, the way GCS would return it on a fetch.
    fn read_response_for(index: &IndexFile, generation: i64) -> ReadObjectResponse {
        let mut bytes = Vec::with_capacity(2048);
        index.write_to(&mut bytes).unwrap();
        let mut highlights = ObjectHighlights::default();
        highlights.generation = generation;
        highlights.size = bytes.len() as i64;
        ReadObjectResponse::from_source(highlights, bytes::Bytes::from(bytes))
    }

    fn http_412_error() -> gcs::Error {
        gcs::Error::http(412, HeaderMap::new(), bytes::Bytes::new())
    }

    fn http_500_error() -> gcs::Error {
        gcs::Error::http(500, HeaderMap::new(), bytes::Bytes::new())
    }

    fn http_429_error() -> gcs::Error {
        gcs::Error::http(429, HeaderMap::new(), bytes::Bytes::new())
    }

    fn http_404_error() -> gcs::Error {
        gcs::Error::http(404, HeaderMap::new(), bytes::Bytes::new())
    }

    /// An existing object as `open_object` describes it: its size and the
    /// CRC32C GCS computed over its bytes are read, nothing else.
    #[derive(Debug)]
    struct Existing {
        size: i64,
        crc32c: u32,
    }

    impl gcs::stub::ObjectDescriptor for Existing {
        fn object(&self) -> Object {
            Object::new()
                .set_size(self.size)
                .set_checksums(gcs::model::ObjectChecksums::new().set_crc32c(self.crc32c))
        }
        async fn read_range(&self, _range: gcs::model_ext::ReadRange) -> ReadObjectResponse {
            unreachable!("the writer only reads an object's size and checksum")
        }
        fn headers(&self) -> HeaderMap {
            HeaderMap::new()
        }
    }

    /// An object holding exactly `bytes`, as GCS would describe it.
    fn existing(bytes: &[u8]) -> GcsResult<(ObjectDescriptor, Vec<ReadObjectResponse>)> {
        Ok((
            ObjectDescriptor::new(Existing {
                size: bytes.len() as i64,
                crc32c: crc32c::crc32c(bytes),
            }),
            Vec::new(),
        ))
    }

    /// An artifact file with these bytes, and a second handle on it that
    /// shares its file offset (as the writer's clones do).
    fn artifact(bytes: &[u8]) -> (std::fs::File, std::fs::File) {
        use std::io::Write as _;
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        let shared = file.try_clone().unwrap();
        (file, shared)
    }

    fn spec() -> SpecHash {
        SpecHash::from_hex("1234000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
    }

    /// The object already exists with the artifact's bytes (same length, same
    /// CRC32C): nothing is written, and the spec hash still goes to the index.
    #[tokio::test(start_paused = true)]
    async fn upload_skips_an_object_present_with_the_same_bytes() {
        let mut mock = MockStorage::new();
        mock.expect_open_object()
            .times(1)
            .returning(|_, _| existing(&[7u8; 18]));
        let mut writer = writer_from_mock(mock, IndexFile::default(), 1);
        let (file, _shared) = artifact(&[7u8; 18]);
        let wrote = writer.upload(&spec(), (file, [1u8; 32])).await.unwrap();
        assert!(!wrote, "a present object is not written again");
        assert_eq!(writer.pending.len(), 1);
    }

    /// An object under this name at the artifact's length but with other
    /// bytes is not the artifact, whoever put it there: it is written over,
    /// as every object under a name used to be. The length alone would have
    /// let a small planted object stand for good.
    #[tokio::test(start_paused = true)]
    async fn upload_writes_over_an_object_of_the_same_length_but_other_bytes() {
        let mut mock = MockStorage::new();
        let mut seq = Sequence::new();
        mock.expect_open_object()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _| existing(&[8u8; 18]));
        mock.expect_write_object_buffered()
            .times(1)
            .in_sequence(&mut seq)
            .return_once(|_p: Payload<gcs::streaming_source::FileSource>, _, _| {
                Ok(Object::default())
            });
        let mut writer = writer_from_mock(mock, IndexFile::default(), 1);
        let (file, _shared) = artifact(&[7u8; 18]);
        let wrote = writer.upload(&spec(), (file, [1u8; 32])).await.unwrap();
        assert!(wrote, "an object with other bytes is written over");
        assert_eq!(writer.pending.len(), 1);
    }

    /// A 429 retried writes the whole file again, even when the failed attempt
    /// read it to the end first: the clones share one offset. Without the
    /// rewind the retry sent zero bytes and wrote an empty object.
    #[tokio::test(start_paused = true)]
    async fn upload_retry_after_429_sends_the_whole_file() {
        let bytes = b"eighteen byte blob".to_vec();
        let (file, mut shared) = artifact(&bytes);
        let sent = std::sync::Arc::new(std::sync::Mutex::new(None::<Payload<_>>));
        let mut mock = MockStorage::new();
        let mut seq = Sequence::new();
        mock.expect_open_object()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _| Err(http_404_error()));
        mock.expect_write_object_buffered()
            .times(1)
            .in_sequence(&mut seq)
            .return_once(
                move |_p: Payload<gcs::streaming_source::FileSource>, _, _| {
                    // The failed attempt read the whole file before GCS answered.
                    std::io::Seek::seek(&mut shared, std::io::SeekFrom::End(0)).unwrap();
                    Err(http_429_error())
                },
            );
        mock.expect_open_object()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _| Err(http_404_error()));
        let captured = std::sync::Arc::clone(&sent);
        mock.expect_write_object_buffered()
            .times(1)
            .in_sequence(&mut seq)
            .return_once(move |p: Payload<gcs::streaming_source::FileSource>, _, _| {
                *captured.lock().unwrap() = Some(p);
                Ok(Object::default())
            });
        let mut writer = writer_from_mock(mock, IndexFile::default(), 1);
        let wrote = writer.upload(&spec(), (file, [1u8; 32])).await.unwrap();
        assert!(wrote);
        let mut payload = sent.lock().unwrap().take().expect("the retry wrote");
        let mut got = Vec::new();
        while let Some(chunk) = StreamingSource::next(&mut payload).await {
            got.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(got, bytes, "the retry sends every byte of the artifact");
    }

    /// Out of retries on a 429, the object is looked for one last time: when
    /// the other uploader's write has landed, the upload is a skip, not an
    /// error that would abort the whole upload session.
    #[tokio::test(start_paused = true)]
    async fn upload_out_of_retries_on_429_still_skips_a_present_object() {
        let mut mock = MockStorage::new();
        let mut seq = Sequence::new();
        mock.expect_open_object()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _| Err(http_404_error()));
        for _ in 0..MAX_OBJECT_WRITE_RETRIES {
            mock.expect_write_object_buffered()
                .times(1)
                .in_sequence(&mut seq)
                .return_once(|_p: Payload<gcs::streaming_source::FileSource>, _, _| {
                    Err(http_429_error())
                });
            mock.expect_open_object()
                .times(1)
                .in_sequence(&mut seq)
                .returning(|_, _| Err(http_404_error()));
        }
        // The last attempt, past the retry budget, and the look after it.
        mock.expect_write_object_buffered()
            .times(1)
            .in_sequence(&mut seq)
            .return_once(|_p: Payload<gcs::streaming_source::FileSource>, _, _| {
                Err(http_429_error())
            });
        mock.expect_open_object()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _| existing(&[7u8; 18]));
        let mut writer = writer_from_mock(mock, IndexFile::default(), 1);
        let (file, _shared) = artifact(&[7u8; 18]);
        let wrote = writer.upload(&spec(), (file, [1u8; 32])).await.unwrap();
        assert!(!wrote, "the other uploader's write stands");
        assert_eq!(writer.pending.len(), 1);
    }

    /// Out of retries on a 429 with no object under the name by the last
    /// look, the upload gives up with the 429: the bound on the wait for the
    /// other uploader's write is the one 429 path that is an error, and the
    /// caller aborts the upload session on it.
    #[tokio::test(start_paused = true)]
    async fn upload_out_of_retries_on_429_with_no_object_present_errors() {
        let mut mock = MockStorage::new();
        let mut seq = Sequence::new();
        mock.expect_open_object()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _| Err(http_404_error()));
        // Every attempt, the one past the retry budget included, and the
        // look after each: the object never appears.
        for _ in 0..=MAX_OBJECT_WRITE_RETRIES {
            mock.expect_write_object_buffered()
                .times(1)
                .in_sequence(&mut seq)
                .return_once(|_p: Payload<gcs::streaming_source::FileSource>, _, _| {
                    Err(http_429_error())
                });
            mock.expect_open_object()
                .times(1)
                .in_sequence(&mut seq)
                .returning(|_, _| Err(http_404_error()));
        }
        let mut writer = writer_from_mock(mock, IndexFile::default(), 1);
        let (file, _shared) = artifact(&[7u8; 18]);
        let err = writer
            .upload(&spec(), (file, [1u8; 32]))
            .await
            .expect_err("out of retries with no object present is an error");
        assert!(
            matches!(&err, Error::Backend(e) if e.http_status_code() == Some(TOO_MANY_REQUESTS)),
            "the 429 is surfaced: {err:?}"
        );
        assert!(writer.pending.is_empty(), "nothing is staged for the index");
    }

    /// A 429 is another uploader writing this same content: when the object
    /// is present by the retry, the retry writes nothing.
    #[tokio::test(start_paused = true)]
    async fn upload_429_then_present_does_not_write_again() {
        let mut mock = MockStorage::new();
        let mut seq = Sequence::new();
        mock.expect_open_object()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _| Err(http_404_error()));
        mock.expect_write_object_buffered()
            .times(1)
            .in_sequence(&mut seq)
            .return_once(|_p: Payload<gcs::streaming_source::FileSource>, _, _| {
                Err(http_429_error())
            });
        mock.expect_open_object()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _| existing(&[7u8; 18]));
        let mut writer = writer_from_mock(mock, IndexFile::default(), 1);
        let (file, _shared) = artifact(&[7u8; 18]);
        let wrote = writer.upload(&spec(), (file, [1u8; 32])).await.unwrap();
        assert!(!wrote, "the other uploader's write stands");
        assert_eq!(writer.pending.len(), 1);
    }

    /// Single attempt with no contention writes once and is done.
    /// Verifies the writer issues exactly one write with the observed
    /// generation as the precondition, and returns Ok.
    #[tokio::test(start_paused = true)]
    async fn finish_uploads_no_contention_writes_once() {
        let mut mock = MockStorage::new();
        mock.expect_write_object_buffered()
            .times(1)
            .withf(|_p: &Payload<BytesSource>, req, _| req.spec.if_generation_match == Some(42))
            .return_once(|_p: Payload<BytesSource>, _, _| Ok(Object::default()));

        let writer = writer_from_mock(mock, IndexFile::default(), 42);
        writer.finish_uploads().await.expect("expected Ok");
    }

    /// 412 on first attempt should refetch the index and retry the write
    /// with the refetched generation. Verifies both the call ordering and
    /// that the second write uses the new generation.
    #[tokio::test(start_paused = true)]
    async fn finish_uploads_retries_on_412_then_succeeds() {
        let mut mock = MockStorage::new();
        let mut seq = Sequence::new();

        // First write: contention signal.
        mock.expect_write_object_buffered()
            .times(1)
            .in_sequence(&mut seq)
            .withf(|_p: &Payload<BytesSource>, req, _| req.spec.if_generation_match == Some(50))
            .return_once(|_p: Payload<BytesSource>, _, _| Err(http_412_error()));

        // Refetch returns the new state at generation 100.
        mock.expect_read_object()
            .times(1)
            .in_sequence(&mut seq)
            .return_once(|_, _| Ok(read_response_for(&IndexFile::default(), 100)));

        // Second write uses the refetched generation, succeeds.
        mock.expect_write_object_buffered()
            .times(1)
            .in_sequence(&mut seq)
            .withf(|_p: &Payload<BytesSource>, req, _| req.spec.if_generation_match == Some(100))
            .return_once(|_p: Payload<BytesSource>, _, _| Ok(Object::default()));

        let writer = writer_from_mock(mock, IndexFile::default(), 50);
        writer
            .finish_uploads()
            .await
            .expect("expected Ok after retry");
    }

    /// 412 forever exhausts the retry budget and surfaces the underlying
    /// error rather than looping indefinitely. The writer makes
    /// `MAX_INDEX_WRITE_RETRIES + 1` write attempts (initial + retries),
    /// each interleaved with a refetch except the first.
    #[tokio::test(start_paused = true)]
    async fn finish_uploads_exhausts_retries_and_surfaces_error() {
        let mut mock = MockStorage::new();

        // Every write returns 412.
        mock.expect_write_object_buffered()
            .times((MAX_INDEX_WRITE_RETRIES + 1) as usize)
            .returning(|_p: Payload<BytesSource>, _, _| Err(http_412_error()));

        // Each retry refetches (`MAX_INDEX_WRITE_RETRIES` times, since the
        // initial attempt skips the refetch).
        mock.expect_read_object()
            .times(MAX_INDEX_WRITE_RETRIES as usize)
            .returning(|_, _| Ok(read_response_for(&IndexFile::default(), 0)));

        let writer = writer_from_mock(mock, IndexFile::default(), 0);
        let err = writer
            .finish_uploads()
            .await
            .expect_err("expected error after retry exhaustion");
        match err {
            Error::Backend(e) => assert_eq!(e.http_status_code(), Some(412)),
            other => panic!("expected Backend(412), got {other:?}"),
        }
    }

    /// Non-412 errors are not retried. They surface to the caller after a
    /// single write attempt.
    #[tokio::test(start_paused = true)]
    async fn finish_uploads_does_not_retry_on_non_412() {
        let mut mock = MockStorage::new();
        mock.expect_write_object_buffered()
            .times(1)
            .return_once(|_p: Payload<BytesSource>, _, _| Err(http_500_error()));

        let writer = writer_from_mock(mock, IndexFile::default(), 1);
        let err = writer
            .finish_uploads()
            .await
            .expect_err("expected immediate error");
        match err {
            Error::Backend(e) => assert_eq!(e.http_status_code(), Some(500)),
            other => panic!("expected Backend(500), got {other:?}"),
        }
    }
}
