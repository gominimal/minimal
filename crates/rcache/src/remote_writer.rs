//! GCS-specific writer for the shared cache that uses optimistic concurrency
//! to safely merge index updates from multiple concurrent writers.
//!
//! See the historical note at the top of `remote.rs` for why this is split
//! off from [crate::RemoteCache]: the previous design did an unsynchronized
//! read-modify-write on `index.shisha` which lost entries when two writers
//! raced.

use crate::INDEX_FILENAME;
use crate::remote::Error;
use crate::remote_index::RemoteIndex;
use common::SpecHash;
use common::fetchers::{FetchUrl, GcsUrl};
use google_cloud_storage::{Error as GcsError, client::Storage};
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
#[derive(Debug)]
pub struct RemoteCacheWriter {
    backend: Storage,
    base: GcsUrl,

    /// The index as it was when we last fetched it from GCS. Used both as the
    /// base to merge `pending` into, and as a dedup check in [Self::upload]
    /// to skip uploads of artifacts already present.
    fetched_index: RemoteIndex,

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

impl RemoteCacheWriter {
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

    /// Construct directly from already-fetched index + generation. Used by
    /// [`crate::RemoteCache::into_writer`] to avoid a redundant fetch when
    /// converting a freshly-loaded reader into a writer.
    pub(crate) fn from_parts(
        backend: Storage,
        base: GcsUrl,
        fetched_index: RemoteIndex,
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
        if let Ok(stat) = self
            .backend
            .open_object(
                self.base.bucket.clone(),
                self.base
                    .join(&format!("{}.zst", hex::encode(sha256)))
                    .unwrap()
                    .object,
            )
            .send()
            .await
        {
            if stat.object().size > 1024 * 1024 {
                // Object already exists and is large enough to be real, skip the upload.
                // We still push to the pending-set because while this tarball may exist,
                // its likely not wired to this spec hash.
                self.pending.push((spec_hash.clone(), sha256));
                return Ok(false);
            }
        }

        self.backend
            .write_object(
                self.base.bucket.clone(),
                self.base
                    .join(&format!("{}.zst", hex::encode(sha256)))
                    .unwrap()
                    .object,
                tokio::fs::File::from_std(tar_file),
            )
            .set_cache_control("public, max-age=7200")
            .send_buffered()
            .await?;

        self.pending.push((spec_hash.clone(), sha256));
        Ok(true)
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
fn merge_for_commit(fetched: &RemoteIndex, pending: &[(SpecHash, [u8; 32])]) -> RemoteIndex {
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
pub(crate) async fn fetch_gcs_index(
    backend: &Storage,
    base: &GcsUrl,
) -> Result<(RemoteIndex, i64), Error<GcsError>> {
    let url = base.join(INDEX_FILENAME).unwrap();
    let mut response = match backend.read_object(url.bucket, url.object).send().await {
        Ok(r) => r,
        Err(e) => {
            if e.http_status_code() == Some(NOT_FOUND) {
                return Ok((RemoteIndex::default(), 0));
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

    let index = RemoteIndex::from_reader(&mut std::io::Cursor::new(buffer)).map_err(Error::IO)?;

    Ok((index, generation))
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

    // Tests cover only the retry policy table because that's the contract
    // for behavior under contention (which status codes retry, the bound,
    // the backoff schedule). Higher-level behavior of the writer is tested
    // through the buildbot integration against real GCS, since the
    // remaining new logic in this module is small enough that mock
    // infrastructure to test it would be disproportionate.

    #[test]
    fn retry_412_uses_exponential_backoff_capped_at_64x() {
        // First retry waits 2x INITIAL, doubling each attempt up to
        // 2^6 * INITIAL = 128_000ms (which exceeds the 300s
        // Cache-Control max-age on the index file).
        assert_eq!(
            decide_retry_after_failure(Some(PRECONDITION_FAILED), 0),
            RetryAfterFailure::Retry { backoff_ms: 4_000 }
        );
        assert_eq!(
            decide_retry_after_failure(Some(PRECONDITION_FAILED), 1),
            RetryAfterFailure::Retry { backoff_ms: 8_000 }
        );
        assert_eq!(
            decide_retry_after_failure(Some(PRECONDITION_FAILED), 5),
            RetryAfterFailure::Retry {
                backoff_ms: 128_000
            }
        );
        assert_eq!(
            decide_retry_after_failure(Some(PRECONDITION_FAILED), 7),
            RetryAfterFailure::Retry {
                backoff_ms: 128_000
            }
        );
    }

    #[test]
    fn retry_412_gives_up_at_max() {
        assert_eq!(
            decide_retry_after_failure(Some(PRECONDITION_FAILED), MAX_INDEX_WRITE_RETRIES),
            RetryAfterFailure::GiveUp
        );
    }

    #[test]
    fn non_precondition_failures_do_not_retry() {
        // The contention signal is 412 specifically. Other HTTP errors
        // (server errors, auth failures, missing buckets) and transport
        // errors that surface no status code are not retried, since
        // retrying wouldn't fix any of them and would only delay
        // surfacing the real problem to the caller.
        for status in [Some(500u16), Some(404), Some(403), None] {
            assert_eq!(
                decide_retry_after_failure(status, 0),
                RetryAfterFailure::GiveUp,
                "status {status:?} should not retry"
            );
        }
    }
}
