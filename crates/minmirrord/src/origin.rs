//! Cache objects: pull-through from the origin a request names (MIR-002 to
//! MIR-005, MIR-009), with absence records and a root index that revalidates.

use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use common::mirror::{CacheKey, CacheOrigin};
use futures::StreamExt;
use sha2::Digest;
use tokio::sync::Semaphore;

use crate::status::{Failure, OriginStatus};
use crate::store::Store;

/// How long a held root index answers without a revalidation (MIR-004).
const ROOT_INDEX_FRESH: Duration = Duration::from_secs(5 * 60);
/// How long an absence record answers before the origin is asked again
/// while it is reachable (MIR-002).
const ABSENCE_FRESH: Duration = Duration::from_secs(60);
/// How many absence records requests may cause (MIR-002).
const ABSENCE_LIMIT: usize = 100_000;
/// The bound on one connection attempt to an origin (MIR-009).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a host that failed to answer is left alone (MIR-009).
const UNREACHABLE_FOR: Duration = Duration::from_secs(30);
/// How many origin fetches run at once (MIR-N03).
const FETCH_LIMIT: usize = 8;

/// What the mirror answers for a cache object.
#[derive(Debug)]
pub enum Served {
    /// A held file; `age` is set when it is served stale because the origin
    /// could not be reached (MIR-004).
    File { path: PathBuf, age: Option<u64> },
    /// The origin does not publish the key.
    NotFound,
    /// The origin could not be reached or answered an error; the body of the
    /// 502 (MIR-002).
    Unavailable(String),
}

#[derive(Default)]
struct Absences {
    order: VecDeque<String>,
    at: HashMap<String, Instant>,
}

impl Absences {
    fn get(&self, key: &str) -> Option<Instant> {
        self.at.get(key).copied()
    }

    fn record(&mut self, key: String) {
        if self.at.insert(key.clone(), Instant::now()).is_none() {
            self.order.push_back(key);
        }
        while self.order.len() > ABSENCE_LIMIT {
            if let Some(oldest) = self.order.pop_front() {
                self.at.remove(&oldest);
            }
        }
    }

    fn drop_record(&mut self, key: &str) {
        self.at.remove(key);
    }
}

/// The pull-through reader of every origin.
pub struct Origins {
    client: reqwest::Client,
    store: Store,
    /// `http` in tests against a local origin, `https` otherwise.
    scheme: &'static str,
    absences: Mutex<Absences>,
    unreachable: Mutex<HashMap<String, (Instant, String)>>,
    inflight: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    fetches: Semaphore,
    status: Mutex<HashMap<CacheOrigin, OriginStatus>>,
}

impl Origins {
    pub fn new(store: Store) -> Self {
        Self::with_scheme(store, "https")
    }

    /// An origins reader that speaks plain `http` to its origins: for tests
    /// against a local server only.
    pub fn with_scheme(store: Store, scheme: &'static str) -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("minimal/mirror")
            .build()
            .expect("a reqwest client with static settings builds");
        Self {
            client,
            store,
            scheme,
            absences: Mutex::new(Absences::default()),
            unreachable: Mutex::new(HashMap::new()),
            inflight: Mutex::new(HashMap::new()),
            fetches: Semaphore::new(FETCH_LIMIT),
            status: Mutex::new(HashMap::new()),
        }
    }

    fn url(&self, origin: &CacheOrigin, key: &CacheKey) -> String {
        format!("{}://{}/{key}", self.scheme, origin.as_str())
    }

    fn host_of(origin: &CacheOrigin) -> String {
        origin
            .as_str()
            .split('/')
            .next()
            .unwrap_or_default()
            .to_string()
    }

    fn unreachable_cause(&self, origin: &CacheOrigin) -> Option<String> {
        let map = self.unreachable.lock().expect("lock");
        map.get(&Self::host_of(origin))
            .filter(|(until, _)| *until > Instant::now())
            .map(|(_, cause)| cause.clone())
    }

    fn mark_unreachable(&self, origin: &CacheOrigin, cause: &str) {
        self.unreachable.lock().expect("lock").insert(
            Self::host_of(origin),
            (Instant::now() + UNREACHABLE_FOR, cause.to_string()),
        );
        self.status
            .lock()
            .expect("lock")
            .entry(origin.clone())
            .or_default()
            .last_failure = Some(Failure::now(cause));
    }

    fn mark_contact(&self, origin: &CacheOrigin) {
        self.unreachable
            .lock()
            .expect("lock")
            .remove(&Self::host_of(origin));
        self.status
            .lock()
            .expect("lock")
            .entry(origin.clone())
            .or_default()
            .last_contact = Some(crate::status::now_secs());
    }

    /// The origins this reader contacted, for `min mirror status`.
    pub fn status(&self) -> Vec<(CacheOrigin, OriginStatus)> {
        let map = self.status.lock().expect("lock");
        let mut rows: Vec<_> = map.iter().map(|(o, s)| (o.clone(), s.clone())).collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        rows
    }

    fn unavailable(&self, origin: &CacheOrigin, cause: &str) -> Served {
        Served::Unavailable(format!(
            "the mirror could not reach https://{}/: {cause}",
            origin.as_str()
        ))
    }

    /// Answers a request for one cache object.
    pub async fn get(&self, origin: &CacheOrigin, key: &CacheKey) -> Served {
        let path = self.store.object_path(origin, key);
        if key.is_mutable() {
            return self.get_root_index(origin, key, &path).await;
        }
        if path.is_file() {
            if let Err(e) = Store::touch(&path) {
                tracing::debug!(error = %e, path = %path.display(), "could not record the request");
            }
            return Served::File { path, age: None };
        }
        let record_key = format!("{}/{key}", origin.as_str());
        let recorded = self.absences.lock().expect("lock").get(&record_key);
        if let Some(at) = recorded {
            let offline = self.unreachable_cause(origin).is_some();
            if offline || at.elapsed() < ABSENCE_FRESH {
                return Served::NotFound;
            }
        }
        // One fetch per key: a second request for the same miss waits for
        // the first and then finds the file.
        let gate = self
            .inflight
            .lock()
            .expect("lock")
            .entry(record_key.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = gate.lock().await;
        if path.is_file() {
            return Served::File { path, age: None };
        }
        let served = match self.fetch_immutable(origin, key, &path).await {
            Ok(true) => {
                self.absences.lock().expect("lock").drop_record(&record_key);
                Served::File { path, age: None }
            }
            Ok(false) => {
                self.absences
                    .lock()
                    .expect("lock")
                    .record(record_key.clone());
                Served::NotFound
            }
            Err(cause) => {
                if recorded.is_some() {
                    // The origin is out of reach and the key was absent when
                    // it was last in reach: answer from the record.
                    return Served::NotFound;
                }
                self.unavailable(origin, &cause)
            }
        };
        self.inflight.lock().expect("lock").remove(&record_key);
        served
    }

    /// Fetches an immutable object into the store. `Ok(true)` when it is held
    /// now, `Ok(false)` when the origin answers 404, `Err(cause)` otherwise.
    async fn fetch_immutable(
        &self,
        origin: &CacheOrigin,
        key: &CacheKey,
        dest: &Path,
    ) -> Result<bool, String> {
        if let Some(cause) = self.unreachable_cause(origin) {
            return Err(cause);
        }
        let _permit = self.fetches.acquire().await.map_err(|e| e.to_string())?;
        let url = self.url(origin, key);
        let response = match self.client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                let cause = e.to_string();
                self.mark_unreachable(origin, &cause);
                return Err(cause);
            }
        };
        self.mark_contact(origin);
        let status = response.status();
        if status.as_u16() == 404 {
            return Ok(false);
        }
        if !status.is_success() {
            return Err(format!("{url} answered {status}"));
        }
        let expected = match key {
            CacheKey::Artifact { sha256 } => Some(sha256.clone()),
            _ => None,
        };
        let tmp = self.store.tmp_path();
        let written = write_stream(response, &tmp, expected.as_deref()).await;
        match written {
            Ok(()) => {
                self.store.commit(&tmp, dest).map_err(|e| e.to_string())?;
                tracing::info!(origin = %origin, key = %key, "fetched");
                if !key.companions().is_empty() {
                    self.fetch_companions(origin.clone(), key.clone());
                }
                Ok(true)
            }
            Err(cause) => {
                let _ = std::fs::remove_file(&tmp);
                Err(cause)
            }
        }
    }

    /// Fetches a closure's companions in the background, best effort
    /// (MIR-005).
    fn fetch_companions(&self, origin: CacheOrigin, key: CacheKey) {
        let client = self.client.clone();
        let store = self.store.clone();
        let scheme = self.scheme;
        tokio::spawn(async move {
            for companion in key.companions() {
                let dest = store.object_path(&origin, &companion);
                if dest.is_file() {
                    continue;
                }
                let url = format!("{scheme}://{}/{companion}", origin.as_str());
                let Ok(response) = client.get(&url).send().await else {
                    continue;
                };
                if !response.status().is_success() {
                    continue;
                }
                let tmp = store.tmp_path();
                if write_stream(response, &tmp, None).await.is_ok() {
                    if let Err(e) = store.commit(&tmp, &dest) {
                        tracing::debug!(error = %e, "could not keep a companion");
                    }
                } else {
                    let _ = std::fs::remove_file(&tmp);
                }
            }
        });
    }

    /// The root index: held while fresh, revalidated after, stale with `Age`
    /// when the origin cannot be reached (MIR-004).
    async fn get_root_index(&self, origin: &CacheOrigin, key: &CacheKey, path: &Path) -> Served {
        let held = path.is_file();
        if held && Store::age(path).is_some_and(|age| age < ROOT_INDEX_FRESH) {
            return Served::File {
                path: path.to_path_buf(),
                age: None,
            };
        }
        let stale = |cause: &str| {
            if held {
                let age = Store::age(path).map(|a| a.as_secs());
                tracing::info!(origin = %origin, cause, "serving the held root index");
                Served::File {
                    path: path.to_path_buf(),
                    age,
                }
            } else {
                self.unavailable(origin, cause)
            }
        };
        if let Some(cause) = self.unreachable_cause(origin) {
            return stale(&cause);
        }
        let _permit = match self.fetches.acquire().await {
            Ok(p) => p,
            Err(e) => return stale(&e.to_string()),
        };
        let etag_path = self.store.etag_path(origin, key);
        let mut request = self.client.get(self.url(origin, key));
        if held && let Ok(etag) = std::fs::read_to_string(&etag_path) {
            request = request.header(reqwest::header::IF_NONE_MATCH, etag.trim());
        }
        let response = match request.send().await {
            Ok(r) => r,
            Err(e) => {
                let cause = e.to_string();
                self.mark_unreachable(origin, &cause);
                return stale(&cause);
            }
        };
        self.mark_contact(origin);
        match response.status().as_u16() {
            304 => {
                let _ = Store::touch(path);
                Served::File {
                    path: path.to_path_buf(),
                    age: None,
                }
            }
            404 => Served::NotFound,
            200 => {
                let etag = response
                    .headers()
                    .get(reqwest::header::ETAG)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let tmp = self.store.tmp_path();
                match write_stream(response, &tmp, None).await {
                    Ok(()) => {
                        if let Err(e) = self.store.commit(&tmp, path) {
                            return stale(&e.to_string());
                        }
                        match etag {
                            Some(etag) => {
                                let _ = std::fs::write(&etag_path, etag);
                            }
                            None => {
                                let _ = std::fs::remove_file(&etag_path);
                            }
                        }
                        Served::File {
                            path: path.to_path_buf(),
                            age: None,
                        }
                    }
                    Err(cause) => {
                        let _ = std::fs::remove_file(&tmp);
                        stale(&cause)
                    }
                }
            }
            other => stale(&format!("the origin answered {other}")),
        }
    }
}

/// Streams a response body to `tmp`, checking its sha256 against `expected`
/// when one is given (MIR-003).
async fn write_stream(
    response: reqwest::Response,
    tmp: &Path,
    expected: Option<&str>,
) -> Result<(), String> {
    let mut file = std::fs::File::create(tmp).map_err(|e| e.to_string())?;
    let mut hasher = sha2::Sha256::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| e.to_string())?;
        hasher.update(&chunk);
        file.write_all(&chunk).map_err(|e| e.to_string())?;
    }
    file.sync_all().map_err(|e| e.to_string())?;
    if let Some(expected) = expected {
        let got = hex::encode(hasher.finalize());
        if got != expected {
            return Err(format!("sha256 {got} does not match the name {expected}"));
        }
    }
    Ok(())
}

/// A `SystemTime` as seconds since the epoch, for status rows.
pub fn epoch_secs(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
