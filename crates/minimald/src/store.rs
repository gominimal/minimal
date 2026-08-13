use paths::DaemonAbsPath;
use sessions::{
    Record, SessionId,
    store::{DiskLoader, DiskSession, DiskSessionKey, Loader as _, SessionKey, SessionObject},
};

use std::fmt;
use tokio::sync::{mpsc, oneshot};

/// The different ways to identify a session record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordPredicate {
    Id(SessionId),
    Name(String),
}

impl fmt::Display for RecordPredicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordPredicate::Id(id) => write!(f, "id={id}"),
            RecordPredicate::Name(name) => write!(f, "name={name}"),
        }
    }
}

enum StoreMessage {
    Handles(oneshot::Sender<Result<Vec<SessionRecordHandle>, std::io::Error>>),
    Create(
        Box<Record>,
        oneshot::Sender<Result<SessionRecordHandle, std::io::Error>>,
    ),
    Find(
        RecordPredicate,
        oneshot::Sender<Result<Option<SessionRecordHandle>, std::io::Error>>,
    ),
    SessionGet(
        DiskSessionKey,
        oneshot::Sender<Result<Record, std::io::Error>>,
    ),
    SessionObject(
        DiskSessionKey,
        oneshot::Sender<Result<DiskSession, std::io::Error>>,
    ),
    SessionWrite(
        DiskSessionKey,
        Box<Record>,
        oneshot::Sender<Result<(), std::io::Error>>,
    ),
    SessionDelete(DiskSessionKey, oneshot::Sender<Result<(), std::io::Error>>),
    CompositionLoad(
        DiskSessionKey,
        oneshot::Sender<Result<Option<sessions::core::compose::Composition>, std::io::Error>>,
    ),
    CompositionStore(
        DiskSessionKey,
        std::sync::Arc<sessions::core::compose::Composition>,
        oneshot::Sender<Result<(), std::io::Error>>,
    ),
}

/// The session store actor. Mediates reading, writing, and enumerating
/// session records.
pub struct Store {
    receiver: mpsc::Receiver<StoreMessage>,
    weak_self: WeakStoreHandle,
    store: DiskLoader,
}

impl Store {
    /// Launches the session store actor, managing session records in
    /// the given minimal state dir.
    pub async fn init(minimal_state_dir: DaemonAbsPath) -> Result<StoreHandle, std::io::Error> {
        let l = DiskLoader::new(minimal_state_dir.clone())?;

        let (sender, receiver) = mpsc::channel(8);
        let handle = StoreHandle { sender };
        let weak_self = handle.downgrade();
        let store = Self {
            receiver,
            weak_self,
            store: l,
        };

        tokio::spawn(store.mainloop());
        Ok(handle)
    }
}

impl Store {
    async fn mainloop(mut self) {
        while let Some(msg) = self.receiver.recv().await {
            self.handle_message(msg).await;
        }
    }

    /// Resolves a predicate to a key, if a matching record exists.
    fn resolve(&self, pred: &RecordPredicate) -> Result<Option<DiskSessionKey>, std::io::Error> {
        match pred {
            RecordPredicate::Id(id) => self.store.find_by_id(id),
            RecordPredicate::Name(name) => self.store.find_by_name(name),
        }
    }

    /// Wraps a key in a record handle. The caller awaiting this message holds a
    /// strong [`StoreHandle`], so the upgrade always succeeds.
    fn handle_for(&self, k: DiskSessionKey) -> SessionRecordHandle {
        SessionRecordHandle {
            h: self
                .weak_self
                .upgrade()
                .expect("store handle is live while its message is being handled"),
            k,
        }
    }

    /// Handles a specific message recieved by the store.
    async fn handle_message(&mut self, msg: StoreMessage) {
        match msg {
            StoreMessage::Handles(r) => {
                let _ = r.send(Ok(self.store.keys().map(|k| self.handle_for(k)).collect()));
            }
            StoreMessage::Create(record, r) => {
                let created = self.store.create(*record);
                let _ = r.send(created.map(|k| self.handle_for(k)));
            }
            StoreMessage::Find(pred, r) => {
                let _ = r.send(
                    self.resolve(&pred)
                        .map(|opt| opt.map(|k| self.handle_for(k))),
                );
            }
            StoreMessage::SessionGet(k, r) => {
                let _ = r.send(self.store.get(&k).map(|o| o.record().clone()));
            }
            StoreMessage::SessionObject(k, r) => {
                let _ = r.send(self.store.get(&k));
            }
            StoreMessage::SessionWrite(k, v, r) => {
                let _ = r.send(self.store.save(&k, &v));
            }
            StoreMessage::SessionDelete(k, r) => {
                let _ = r.send(self.store.delete(&k));
            }
            StoreMessage::CompositionLoad(k, r) => {
                let _ = r.send(self.store.load_composition(&k));
            }
            StoreMessage::CompositionStore(k, comp, r) => {
                let _ = r.send(self.store.store_composition(&k, &comp));
            }
        }
    }
}

/// The handle to the session store.
#[derive(Debug, Clone)]
pub struct StoreHandle {
    sender: mpsc::Sender<StoreMessage>,
}

impl StoreHandle {
    /// Returns a non-owning handle to this manager.
    #[must_use]
    pub fn downgrade(&self) -> WeakStoreHandle {
        WeakStoreHandle {
            sender: self.sender.downgrade(),
        }
    }

    /// Returns a handle to every session record known to this store.
    pub async fn handles(&self) -> Result<Vec<SessionRecordHandle>, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.sender.send(StoreMessage::Handles(send)).await;
        recv.await.expect("corresponding store is dead")
    }

    /// Creates a record, returning a handle to it. The record's `id` is
    /// ignored — the store allocates the real one.
    pub async fn create(&self, record: Record) -> Result<SessionRecordHandle, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .sender
            .send(StoreMessage::Create(Box::new(record), send))
            .await;
        recv.await.expect("corresponding store is dead")
    }

    /// Returns a handle to the given record, or `None` if none matches.
    pub async fn find(
        &self,
        record: RecordPredicate,
    ) -> Result<Option<SessionRecordHandle>, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.sender.send(StoreMessage::Find(record, send)).await;
        recv.await.expect("corresponding store is dead")
    }
}

/// A handle to read or write a specific session record. All mutations to
/// a specific record are mediated through one of these handles.
#[derive(Debug, Clone)]
pub struct SessionRecordHandle {
    h: StoreHandle,
    k: DiskSessionKey,
}

impl SessionRecordHandle {
    /// Returns the session ID this handle corresponds to.
    pub fn id(&self) -> &SessionId {
        self.k.id()
    }

    /// Returns the full session object (record plus its on-disk paths), for
    /// callers that need the workspace/home/cache layout to spawn a session.
    pub async fn object(&self) -> Result<DiskSession, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .h
            .sender
            .send(StoreMessage::SessionObject(self.k.clone(), send))
            .await;
        recv.await.expect("corresponding store is dead")
    }

    /// Returns the current state of the session record.
    pub async fn record(&self) -> Result<Record, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .h
            .sender
            .send(StoreMessage::SessionGet(self.k.clone(), send))
            .await;
        recv.await.expect("corresponding store is dead")
    }

    /// Overwrites the contents of the session record with the given value.
    pub async fn write(&self, new: Record) -> Result<(), std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .h
            .sender
            .send(StoreMessage::SessionWrite(
                self.k.clone(),
                Box::new(new),
                send,
            ))
            .await;
        recv.await.expect("corresponding store is dead")
    }

    /// Deletes the record.
    pub async fn delete(self) -> Result<(), std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .h
            .sender
            .send(StoreMessage::SessionDelete(self.k.clone(), send))
            .await;
        recv.await.expect("corresponding store is dead")
    }

    /// Loads the persisted composition snapshot for this session, if
    /// one exists. Returns `Ok(None)` when the sidecar is absent
    /// (pre-sidecar session, or composition was never assembled). A
    /// corrupt sidecar surfaces as an error so the caller can log it
    /// and fall back to baseline.
    pub async fn load_composition(
        &self,
    ) -> Result<Option<sessions::core::compose::Composition>, std::io::Error> {
        let (send, recv) = oneshot::channel();
        let _ = self
            .h
            .sender
            .send(StoreMessage::CompositionLoad(self.k.clone(), send))
            .await;
        recv.await.expect("corresponding store is dead")
    }

    /// Atomically persists the composition snapshot for this session
    /// (tmp + rename). Called at composition-assembly time so a
    /// restart can re-apply the exact composition that was approved at
    /// `min session activate` time.
    pub async fn store_composition(
        &self,
        composition: &sessions::core::compose::Composition,
    ) -> Result<(), std::io::Error> {
        let (send, recv) = oneshot::channel();
        let _ = self
            .h
            .sender
            .send(StoreMessage::CompositionStore(
                self.k.clone(),
                std::sync::Arc::new(composition.clone()),
                send,
            ))
            .await;
        recv.await.expect("corresponding store is dead")
    }
}

/// A non-owning handle to the [`Store`] actor.
#[derive(Debug, Clone)]
pub struct WeakStoreHandle {
    sender: mpsc::WeakSender<StoreMessage>,
}

impl WeakStoreHandle {
    /// Promotes to a strong [`StoreHandle`], or `None` if the manager actor
    /// has already shut down (all strong senders dropped).
    #[must_use]
    pub fn upgrade(&self) -> Option<StoreHandle> {
        Some(StoreHandle {
            sender: self.sender.upgrade()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paths::HostAbsPath;
    use sessions::{NetworkMode, SessionStatus};
    use std::collections::BTreeSet;
    use std::io::ErrorKind;
    use tempfile::TempDir;

    fn daemon_dir(tmp: &TempDir) -> DaemonAbsPath {
        DaemonAbsPath::try_new(tmp.path().to_str().unwrap()).unwrap()
    }

    /// A minimal session record carrying the given name.
    fn record_named(name: &str) -> Record {
        Record {
            id: SessionId::nil(),
            name: Some(name.to_string()),
            username: Some("alice".to_string()),
            project_path: HostAbsPath::try_new("/home/alice/proj").unwrap(),
            network: NetworkMode::default(),
            policy: Default::default(),
            hooks_enabled: true,
            status: SessionStatus::default(),
            attrs: Default::default(),
        }
    }

    /// Launch a [`Store`] actor over a fresh directory rooted at `dir`, seeded
    /// with `records`. Returns the handle alongside the ids the store assigned,
    /// in creation order.
    async fn store_seeded_with(
        dir: &TempDir,
        records: impl IntoIterator<Item = Record>,
    ) -> (StoreHandle, Vec<SessionId>) {
        let handle = Store::init(daemon_dir(dir)).await.unwrap();
        let mut ids = Vec::new();
        for r in records {
            ids.push(*handle.create(r).await.unwrap().id());
        }
        (handle, ids)
    }

    /// Resolve a handle to a record expected to exist.
    async fn open(store: &StoreHandle, pred: RecordPredicate) -> SessionRecordHandle {
        store
            .find(pred)
            .await
            .unwrap()
            .expect("record should resolve")
    }

    /// The set of session ids the store currently holds, read via `handles`.
    async fn stored_ids(store: &StoreHandle) -> BTreeSet<SessionId> {
        store
            .handles()
            .await
            .unwrap()
            .iter()
            .map(|h| *h.id())
            .collect()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handles_is_empty_for_a_fresh_store() {
        let tmp = TempDir::new().unwrap();
        let store = Store::init(daemon_dir(&tmp)).await.unwrap();
        assert!(store.handles().await.unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handles_yield_one_per_seeded_session() {
        let tmp = TempDir::new().unwrap();
        let (store, ids) =
            store_seeded_with(&tmp, (0..3).map(|i| record_named(&format!("s{i}")))).await;

        assert_eq!(stored_ids(&store).await, ids.into_iter().collect());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn find_by_id_resolves_a_handle_to_the_record() {
        let tmp = TempDir::new().unwrap();
        let (store, ids) = store_seeded_with(&tmp, [record_named("solo")]).await;

        let handle = open(&store, RecordPredicate::Id(ids[0])).await;
        // The handle names the session it resolved...
        assert_eq!(*handle.id(), ids[0]);
        // ...and reads back the seeded record contents.
        let record = handle.record().await.unwrap();
        assert_eq!(record.id, ids[0]);
        assert_eq!(record.name.as_deref(), Some("solo"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn find_by_name_resolves_a_handle_to_the_record() {
        let tmp = TempDir::new().unwrap();
        let (store, ids) = store_seeded_with(&tmp, [record_named("named")]).await;

        let handle = open(&store, RecordPredicate::Name("named".to_string())).await;
        assert_eq!(*handle.id(), ids[0]);
        assert_eq!(
            handle.record().await.unwrap().name.as_deref(),
            Some("named")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn write_is_reflected_when_the_record_is_read_back() {
        let tmp = TempDir::new().unwrap();
        let (store, _ids) = store_seeded_with(&tmp, [record_named("mut")]).await;

        let handle = open(&store, RecordPredicate::Name("mut".to_string())).await;
        let mut record = handle.record().await.unwrap();
        record.username = Some("bob".to_string());
        record.attrs.insert("color".to_string(), "red".to_string());
        handle.write(record).await.unwrap();

        let reread = handle.record().await.unwrap();
        assert_eq!(reread.username.as_deref(), Some("bob"));
        assert_eq!(reread.attrs.get("color").map(String::as_str), Some("red"));
    }

    /// A rename issued through the handle remaps the name index: the new name
    /// resolves and the old one stops. This drives the actor's `SessionWrite`
    /// path all the way through the loader's index bookkeeping.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn write_that_renames_remaps_the_name_index() {
        let tmp = TempDir::new().unwrap();
        let (store, ids) = store_seeded_with(&tmp, [record_named("before")]).await;

        let handle = open(&store, RecordPredicate::Id(ids[0])).await;
        let mut record = handle.record().await.unwrap();
        record.name = Some("after".to_string());
        handle.write(record).await.unwrap();

        let by_new = open(&store, RecordPredicate::Name("after".to_string())).await;
        assert_eq!(*by_new.id(), ids[0]);

        assert!(
            store
                .find(RecordPredicate::Name("before".to_string()))
                .await
                .unwrap()
                .is_none(),
            "the old name should no longer resolve",
        );
    }

    /// The actor is the single owner of the record, so a write through one
    /// handle is visible through an independently obtained handle for the same
    /// session — there is no per-handle cached state to go stale.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn writes_are_visible_through_an_independently_obtained_handle() {
        let tmp = TempDir::new().unwrap();
        let (store, ids) = store_seeded_with(&tmp, [record_named("shared")]).await;

        let writer = open(&store, RecordPredicate::Id(ids[0])).await;
        let reader = open(&store, RecordPredicate::Id(ids[0])).await;

        let mut record = writer.record().await.unwrap();
        record.username = Some("changed".to_string());
        writer.write(record).await.unwrap();

        assert_eq!(
            reader.record().await.unwrap().username.as_deref(),
            Some("changed"),
        );
    }

    /// The loader rejects a write whose record id doesn't match the key (id is
    /// the immutable primary key); the actor surfaces that error to the caller
    /// rather than swallowing it. Uses a second session's id as the mismatch so
    /// the test needs no direct uuid construction.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn write_with_a_mismatched_id_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let (store, ids) =
            store_seeded_with(&tmp, [record_named("first"), record_named("second")]).await;

        let handle = open(&store, RecordPredicate::Id(ids[0])).await;
        let mut record = handle.record().await.unwrap();
        record.id = ids[1];

        let err = handle
            .write(record)
            .await
            .expect_err("a record id that doesn't match the key must be refused");
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }

    /// Deleting through the handle removes the record: it no longer lists, and
    /// neither its id nor its name resolves afterwards.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn delete_removes_the_record() {
        let tmp = TempDir::new().unwrap();
        let (store, ids) = store_seeded_with(&tmp, [record_named("doomed")]).await;

        let handle = open(&store, RecordPredicate::Id(ids[0])).await;
        handle.delete().await.unwrap();

        assert!(store.handles().await.unwrap().is_empty());
        assert!(
            store
                .find(RecordPredicate::Id(ids[0]))
                .await
                .unwrap()
                .is_none(),
            "the id should no longer resolve",
        );
        assert!(
            store
                .find(RecordPredicate::Name("doomed".to_string()))
                .await
                .unwrap()
                .is_none(),
            "the name should no longer resolve",
        );
    }

    /// Deleting one session leaves the others untouched — only the targeted
    /// record is dropped from the store.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn delete_leaves_other_sessions_intact() {
        let tmp = TempDir::new().unwrap();
        let (store, ids) =
            store_seeded_with(&tmp, [record_named("keep"), record_named("drop")]).await;

        let doomed = open(&store, RecordPredicate::Id(ids[1])).await;
        doomed.delete().await.unwrap();

        assert_eq!(stored_ids(&store).await, BTreeSet::from([ids[0]]));

        // The survivor still resolves and reads back its own record.
        let survivor = open(&store, RecordPredicate::Name("keep".to_string())).await;
        assert_eq!(*survivor.id(), ids[0]);
    }

    /// Two handles can name the same session; once one deletes it, a read
    /// through the other (now stale) handle fails cleanly with `NotFound`
    /// rather than resurrecting — or panicking the actor over — the removed
    /// record. Guards the store's reliance on the loader's id-strict lookup.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reads_through_a_stale_handle_fail_after_delete() {
        let tmp = TempDir::new().unwrap();
        let (store, ids) = store_seeded_with(&tmp, [record_named("solo")]).await;

        let deleter = open(&store, RecordPredicate::Id(ids[0])).await;
        let stale = open(&store, RecordPredicate::Id(ids[0])).await;

        deleter.delete().await.unwrap();

        let err = stale
            .record()
            .await
            .expect_err("reading a deleted record through a stale handle must fail");
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }

    /// `create` allocates a record and returns a handle that reads it back;
    /// the store assigns a fresh id regardless of the input record's id.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_allocates_a_record_and_returns_a_working_handle() {
        let tmp = TempDir::new().unwrap();
        let store = Store::init(daemon_dir(&tmp)).await.unwrap();

        let handle = store.create(record_named("fresh")).await.unwrap();
        assert_ne!(*handle.id(), SessionId::nil(), "id must be allocated");

        let record = handle.record().await.unwrap();
        assert_eq!(record.id, *handle.id());
        assert_eq!(record.name.as_deref(), Some("fresh"));
        // The record is discoverable through an independent lookup.
        let by_name = open(&store, RecordPredicate::Name("fresh".to_string())).await;
        assert_eq!(*by_name.id(), *handle.id());
    }

    /// A name collision on `create` surfaces the loader's `AlreadyExists`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_rejects_a_duplicate_name() {
        let tmp = TempDir::new().unwrap();
        let store = Store::init(daemon_dir(&tmp)).await.unwrap();

        store.create(record_named("dup")).await.unwrap();
        let err = store
            .create(record_named("dup"))
            .await
            .expect_err("a duplicate name must be refused");
        assert_eq!(err.kind(), ErrorKind::AlreadyExists);
    }

    /// `find` resolves an existing record and yields `None` for a miss.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn find_resolves_existing_and_is_none_for_unknown() {
        let tmp = TempDir::new().unwrap();
        let (store, ids) = store_seeded_with(&tmp, [record_named("here")]).await;

        let hit = store
            .find(RecordPredicate::Id(ids[0]))
            .await
            .unwrap()
            .expect("an existing id should resolve");
        assert_eq!(*hit.id(), ids[0]);

        assert!(
            store
                .find(RecordPredicate::Name("ghost".to_string()))
                .await
                .unwrap()
                .is_none(),
            "an unknown name should resolve to None, not an error",
        );
    }

    /// `object` exposes the on-disk layout: workspace/home/cache all sit under
    /// the session's dir, and the object carries the record.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn object_exposes_paths_and_record() {
        let tmp = TempDir::new().unwrap();
        let (store, ids) = store_seeded_with(&tmp, [record_named("laid-out")]).await;

        let handle = open(&store, RecordPredicate::Id(ids[0])).await;
        let obj = handle.object().await.unwrap();

        assert_eq!(obj.record().id, ids[0]);
        let sessions_root = daemon_dir(&tmp).as_utf8_path().join("sessions");
        for path in [obj.workspace_path(), obj.home_path(), obj.cache_path()] {
            assert!(
                path.as_utf8_path().starts_with(&sessions_root),
                "{path:?} should live under {sessions_root:?}",
            );
        }
    }
}
