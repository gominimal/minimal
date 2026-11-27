//! Items in Secret Service, over D-Bus.
//!
//! Every Linux use of Secret Service goes through [`Items`]: the proxy's
//! keys ([`secret_service`](crate::secret_service)), the GitHub sign-in
//! ([`signin`](crate::signin)), the store references of `min secret`
//! ([`store`](crate::store)), and the client's signing key in `min`.
//! [`SessionItems`] is the user's Secret Service on the session bus.
//! [`MemoryItems`] holds items in memory, for tests.
//!
//! No call unlocks a keyring or shows a prompt. A search returns the paths
//! of locked and unlocked items apart, a secret is read from an unlocked
//! item only, and a write asks whether the collection is locked first. A
//! locked item or collection is [`Cause::Locked`].
//!
//! A value is bytes: Secret Service keeps what it is given, of any length
//! and in any encoding.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use secret_service::{EncryptionType, Error, SecretService};
use zeroize::Zeroizing;

/// The content type of each item's secret, the one `secret-tool store`
/// gives, so items written by either read the same.
const CONTENT_TYPE: &str = "text/plain";

/// How long one call waits for Secret Service unless a caller gives its own
/// time. A provider that D-Bus starts for the call can take seconds.
pub const TIMEOUT: Duration = Duration::from_secs(60);

/// Why a call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Cause {
    /// The item or its collection is locked. Nothing was unlocked.
    Locked(String),
    /// This process reached no session bus.
    Unreachable(String),
    /// The session bus answers, and no Secret Service is on it.
    NoProvider(String),
    /// Secret Service did not answer in this time. No prompt is ever
    /// waiting, so the provider is stuck. A [`store`](Items::store) or a
    /// [`clear`](Items::clear) that ends this way sends nothing more, but
    /// Secret Service can still act on a request it was already sent: the
    /// item is in an unknown state.
    NoAnswer(Duration),
    /// A change was sent, and how much of it Secret Service made is not
    /// known: the answer to it did not arrive, or a later step of the
    /// change failed after an earlier one was made.
    Unsettled(String),
    /// Anything else.
    Other(String),
}

impl std::fmt::Display for Cause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Locked(detail)
            | Self::Unreachable(detail)
            | Self::NoProvider(detail)
            | Self::Unsettled(detail)
            | Self::Other(detail) => f.write_str(detail),
            Self::NoAnswer(timeout) => {
                write!(
                    f,
                    "Secret Service did not answer in {} s",
                    timeout.as_secs()
                )
            }
        }
    }
}

/// The Secret Service operations that this crate and `min` use. Attributes
/// match as Secret Service matches them: an item matches when it carries
/// every given attribute, whatever others it carries.
pub trait Items {
    /// The secret of the first unlocked item under `attributes`, or `None`
    /// when no item matches.
    ///
    /// # Errors
    ///
    /// [`Cause::Locked`] when every matching item is locked.
    fn lookup(&self, attributes: &[(&str, &str)]) -> Result<Option<Zeroizing<Vec<u8>>>, Cause>;

    /// Stores `secret` under `attributes` in the default collection, in
    /// place of the item that carries exactly these attributes.
    ///
    /// # Errors
    ///
    /// [`Cause::Locked`] when the default collection is locked. After
    /// [`Cause::NoAnswer`] or [`Cause::Unsettled`] the item holds the old
    /// secret or the new one.
    fn store(&self, label: &str, attributes: &[(&str, &str)], secret: &[u8]) -> Result<(), Cause>;

    /// Removes every item under `attributes`, and gives the count.
    ///
    /// # Errors
    ///
    /// [`Cause::Locked`] when a matching item is locked. Nothing is removed
    /// then. After [`Cause::NoAnswer`] or [`Cause::Unsettled`] any of the
    /// items can be gone.
    fn clear(&self, attributes: &[(&str, &str)]) -> Result<usize, Cause>;

    /// The value of attribute `key` on each item under `attributes`,
    /// locked items too, in order. Reads no secret.
    ///
    /// # Errors
    ///
    /// When Secret Service does not answer the search.
    fn attribute_values(
        &self,
        attributes: &[(&str, &str)],
        key: &str,
    ) -> Result<Vec<String>, Cause>;
}

/// The user's Secret Service, on the session bus. Each call makes its own
/// connection and ends within the timeout.
#[derive(Debug, Clone)]
pub struct SessionItems {
    timeout: Duration,
    /// The bus address in place of the session bus. A test sets it.
    address: Option<String>,
}

impl Default for SessionItems {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionItems {
    /// The items, with [`TIMEOUT`] for each call.
    #[must_use]
    pub fn new() -> Self {
        Self::within(TIMEOUT)
    }

    /// The items, with `timeout` for each call.
    #[must_use]
    pub fn within(timeout: Duration) -> Self {
        Self {
            timeout,
            address: None,
        }
    }

    /// The same items on the bus at `address`.
    #[cfg(test)]
    pub(crate) fn at(mut self, address: &str) -> Self {
        self.address = Some(address.to_owned());
        self
    }

    /// Runs `call` against a new connection, and gives it no longer than
    /// the timeout. The one time covers the bus handshake and every D-Bus
    /// method of the call. When it ends, the call is dropped where it
    /// stands and its connection closes: no thread and no socket outlive
    /// it, and it sends nothing more.
    fn run<T, F>(&self, call: F) -> Result<T, Cause>
    where
        F: AsyncFnOnce(&SecretService<'static>) -> Result<T, Cause>,
    {
        let timeout = self.timeout;
        let address = self.address.as_deref();
        zruntime::block_on(async {
            let runtime = zruntime::SharedRuntime::current().map_err(|err| {
                Cause::Other(format!("the Secret Service call did not start: {err}"))
            })?;
            let work = async {
                let ss = connect(timeout, address).await?;
                call(&ss).await
            };
            match runtime.timeout(timeout, work).await {
                // The time of one D-Bus method ran out just before the time
                // of the call did. It is the same time, and the same cause.
                Ok(Err(Cause::NoAnswer(_))) | Err(_) => Err(Cause::NoAnswer(timeout)),
                Ok(result) => result,
            }
        })
    }
}

type Attributes = Vec<(String, String)>;

fn owned(attributes: &[(&str, &str)]) -> Attributes {
    attributes
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

fn borrowed(attributes: &Attributes) -> HashMap<&str, &str> {
    attributes
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect()
}

impl Items for SessionItems {
    fn lookup(&self, attributes: &[(&str, &str)]) -> Result<Option<Zeroizing<Vec<u8>>>, Cause> {
        let attributes = owned(attributes);
        self.run(async |ss| {
            let found = ss.search_items(borrowed(&attributes)).await.map_err(sort)?;
            match found.unlocked.first() {
                Some(item) => item
                    .get_secret()
                    .await
                    .map(|secret| Some(Zeroizing::new(secret)))
                    .map_err(sort),
                None if found.locked.is_empty() => Ok(None),
                None => Err(Cause::Locked(
                    "Secret Service lists the item, and it is locked".into(),
                )),
            }
        })
    }

    fn store(&self, label: &str, attributes: &[(&str, &str)], secret: &[u8]) -> Result<(), Cause> {
        let attributes = owned(attributes);
        self.run(async |ss| {
            let collection = ss.get_default_collection().await.map_err(|err| match err {
                Error::NoResult => Cause::Other("Secret Service has no default collection".into()),
                err => sort(err),
            })?;
            // `CreateItem` on a locked collection answers with a prompt to
            // unlock it, so the write asks first and never shows one.
            if collection.is_locked().await.map_err(sort)? {
                return Err(Cause::Locked("the default collection is locked".into()));
            }
            collection
                .create_item(label, borrowed(&attributes), secret, true, CONTENT_TYPE)
                .await
                .map(|_| ())
                .map_err(sort_sent)
        })
    }

    fn clear(&self, attributes: &[(&str, &str)]) -> Result<usize, Cause> {
        let attributes = owned(attributes);
        let timeout = self.timeout;
        self.run(async |ss| {
            let found = ss.search_items(borrowed(&attributes)).await.map_err(sort)?;
            // A delete of a locked item answers with a prompt to unlock it.
            if !found.locked.is_empty() {
                return Err(Cause::Locked("a matching item is locked".into()));
            }
            let matching = found.unlocked.len();
            for (removed, item) in found.unlocked.iter().enumerate() {
                if let Err(err) = item.delete().await {
                    let cause = match sort_sent(err) {
                        // The time that the method had, for the text below.
                        Cause::NoAnswer(_) => Cause::NoAnswer(timeout),
                        cause => cause,
                    };
                    // A refusal of the first delete removed nothing.
                    return Err(if removed == 0 {
                        cause
                    } else {
                        Cause::Unsettled(format!(
                            "Secret Service removed {removed} of {matching} matching items, and then: {cause}"
                        ))
                    });
                }
            }
            Ok(matching)
        })
    }

    fn attribute_values(
        &self,
        attributes: &[(&str, &str)],
        key: &str,
    ) -> Result<Vec<String>, Cause> {
        let attributes = owned(attributes);
        self.run(async |ss| {
            let found = ss.search_items(borrowed(&attributes)).await.map_err(sort)?;
            let mut values = Vec::new();
            for item in found.unlocked.iter().chain(&found.locked) {
                let mut held = item.get_attributes().await.map_err(sort)?;
                values.extend(held.remove(key));
            }
            values.sort();
            Ok(values)
        })
    }
}

/// A connection to Secret Service. Each method call on it gives up after
/// `timeout`.
async fn connect(
    timeout: Duration,
    address: Option<&str>,
) -> Result<SecretService<'static>, Cause> {
    let builder = match address {
        Some(address) => zbus::connection::Builder::address(address),
        None => zbus::connection::Builder::session(),
    };
    let bus = builder
        .method_timeout(timeout)
        .build()
        .await
        .map_err(|err| match sort_bus(&err) {
            Some(Cause::Unreachable(_)) => {
                Cause::Unreachable(format!("no session bus answered: {err}"))
            }
            Some(cause) => cause,
            // A bus that is there and refuses the connection is not a
            // session with no bus.
            None => Cause::Other(format!("the session bus refused the connection: {err}")),
        })?;
    SecretService::connect_with_existing(EncryptionType::Dh, bus)
        .await
        .map_err(sort)
}

/// Sorts an error of the client by cause, from its variant and the D-Bus
/// error name. No message text is read, so the locale changes nothing.
fn sort(err: Error) -> Cause {
    let sorted = match &err {
        Error::Locked => Some(Cause::Locked("Secret Service says it is locked".into())),
        // The connection is made before the client has it, so what is
        // not there is Secret Service.
        Error::Unavailable => Some(Cause::NoProvider(
            "the session bus has no Secret Service".into(),
        )),
        Error::Zbus(bus) => sort_bus(bus),
        Error::ZbusFdo(fdo) => sort_fdo(fdo),
        _ => None,
    };
    sorted.unwrap_or_else(|| match err {
        Error::Zbus(bus) => Cause::Other(bus.to_string()),
        Error::ZbusFdo(fdo) => Cause::Other(fdo.to_string()),
        err => Cause::Other(err.to_string()),
    })
}

/// Sorts the error of a method that changes an item. An answer that
/// refuses the change is sorted as [`sort`] sorts it. An answer that did
/// not arrive leaves the change [`Cause::Unsettled`], because Secret
/// Service had the request.
fn sort_sent(err: Error) -> Cause {
    let lost = answer_lost(&err);
    match sort(err) {
        // The deadline of the call says the same, with its time.
        cause @ Cause::NoAnswer(_) => cause,
        cause if lost => Cause::Unsettled(format!(
            "the answer from Secret Service did not arrive: {cause}"
        )),
        cause => cause,
    }
}

/// The D-Bus error names that the bus gives for a method whose answer did
/// not arrive.
const LOST: [&str; 4] = [
    "org.freedesktop.DBus.Error.NoReply",
    "org.freedesktop.DBus.Error.Disconnected",
    "org.freedesktop.DBus.Error.Timeout",
    "org.freedesktop.DBus.Error.TimedOut",
];

/// Whether `err` says that the answer to a method did not arrive, and not
/// what the answer was.
fn answer_lost(err: &Error) -> bool {
    use zbus::fdo::Error as Fdo;
    fn bus(err: &zbus::Error) -> bool {
        match err {
            zbus::Error::InputOutput(_) => true,
            zbus::Error::MethodError(name, _, _) => LOST.contains(&name.as_str()),
            zbus::Error::FDO(fdo) => fdo_lost(fdo),
            _ => false,
        }
    }
    fn fdo_lost(err: &Fdo) -> bool {
        match err {
            Fdo::NoReply(_)
            | Fdo::Disconnected(_)
            | Fdo::Timeout(_)
            | Fdo::TimedOut(_)
            | Fdo::IOError(_) => true,
            Fdo::ZBus(err) => bus(err),
            _ => false,
        }
    }
    match err {
        Error::PromptDisconnected => true,
        Error::Zbus(err) => bus(err),
        Error::ZbusFdo(fdo) => fdo_lost(fdo),
        _ => false,
    }
}

/// The D-Bus error names that say the bus has no Secret Service.
const NO_PROVIDER: [&str; 2] = [
    "org.freedesktop.DBus.Error.ServiceUnknown",
    "org.freedesktop.DBus.Error.NameHasNoOwner",
];

/// The D-Bus error names that say no bus answers.
const UNREACHABLE: [&str; 2] = [
    "org.freedesktop.DBus.Error.NoServer",
    "org.freedesktop.DBus.Error.Disconnected",
];

/// The D-Bus error name that says the object is locked.
const IS_LOCKED: &str = "org.freedesktop.Secret.Error.IsLocked";

fn sort_bus(err: &zbus::Error) -> Option<Cause> {
    use std::io::ErrorKind;
    match err {
        zbus::Error::MethodError(name, _, _) if NO_PROVIDER.contains(&name.as_str()) => {
            Some(Cause::NoProvider(err.to_string()))
        }
        zbus::Error::MethodError(name, _, _) if UNREACHABLE.contains(&name.as_str()) => {
            Some(Cause::Unreachable(err.to_string()))
        }
        zbus::Error::MethodError(name, _, _) if name.as_str() == IS_LOCKED => {
            Some(Cause::Locked(err.to_string()))
        }
        zbus::Error::FDO(fdo) => sort_fdo(fdo),
        zbus::Error::Address(_) => Some(Cause::Unreachable(err.to_string())),
        // `Connection` is a socket that did not connect, as in a session
        // with no bus.
        zbus::Error::InputOutput(io) | zbus::Error::Connection(io, _) => match io.kind() {
            ErrorKind::NotFound | ErrorKind::ConnectionRefused | ErrorKind::PermissionDenied => {
                Some(Cause::Unreachable(err.to_string()))
            }
            // The time of one method ran out. `SessionItems::run` gives
            // the time that the call had.
            ErrorKind::TimedOut => Some(Cause::NoAnswer(Duration::ZERO)),
            _ => None,
        },
        _ => None,
    }
}

fn sort_fdo(err: &zbus::fdo::Error) -> Option<Cause> {
    use zbus::fdo::Error as Fdo;
    match err {
        Fdo::ServiceUnknown(_) | Fdo::NameHasNoOwner(_) => Some(Cause::NoProvider(err.to_string())),
        Fdo::NoServer(_) | Fdo::Disconnected(_) => Some(Cause::Unreachable(err.to_string())),
        Fdo::ZBus(bus) => sort_bus(bus),
        _ => None,
    }
}

/// One item of [`MemoryItems`].
#[derive(Debug)]
struct MemoryItem {
    attributes: BTreeMap<String, String>,
    secret: Zeroizing<Vec<u8>>,
}

impl MemoryItem {
    fn matches(&self, attributes: &[(&str, &str)]) -> bool {
        attributes
            .iter()
            .all(|(key, value)| self.attributes.get(*key).map(String::as_str) == Some(*value))
    }
}

#[derive(Debug, Default)]
struct Memory {
    items: Vec<MemoryItem>,
    locked: bool,
    failure: Option<Cause>,
}

/// Items held in memory, for tests. A clone shares the items. It answers
/// as Secret Service does: a locked keyring still lists its items and
/// their attributes, and gives no secret and takes no change.
#[derive(Debug, Clone, Default)]
pub struct MemoryItems {
    memory: Arc<Mutex<Memory>>,
}

impl MemoryItems {
    fn memory(&self) -> std::sync::MutexGuard<'_, Memory> {
        self.memory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The memory, or the failure that every call gives.
    fn answering(&self) -> Result<std::sync::MutexGuard<'_, Memory>, Cause> {
        let memory = self.memory();
        match &memory.failure {
            Some(cause) => Err(cause.clone()),
            None => Ok(memory),
        }
    }

    /// Locks or unlocks the keyring.
    pub fn set_locked(&self, locked: bool) {
        self.memory().locked = locked;
    }

    /// Makes every call fail with `failure`, or answer again with `None`.
    pub fn set_failure(&self, failure: Option<Cause>) {
        self.memory().failure = failure;
    }

    /// The count of items held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.memory().items.len()
    }

    /// Whether no item is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Items for MemoryItems {
    fn lookup(&self, attributes: &[(&str, &str)]) -> Result<Option<Zeroizing<Vec<u8>>>, Cause> {
        let memory = self.answering()?;
        match memory.items.iter().find(|item| item.matches(attributes)) {
            None => Ok(None),
            Some(_) if memory.locked => Err(Cause::Locked(
                "Secret Service lists the item, and it is locked".into(),
            )),
            Some(item) => Ok(Some(item.secret.clone())),
        }
    }

    fn store(&self, _label: &str, attributes: &[(&str, &str)], secret: &[u8]) -> Result<(), Cause> {
        let mut memory = self.answering()?;
        if memory.locked {
            return Err(Cause::Locked("the default collection is locked".into()));
        }
        let attributes: BTreeMap<String, String> = owned(attributes).into_iter().collect();
        memory.items.retain(|item| item.attributes != attributes);
        memory.items.push(MemoryItem {
            attributes,
            secret: Zeroizing::new(secret.to_vec()),
        });
        Ok(())
    }

    fn clear(&self, attributes: &[(&str, &str)]) -> Result<usize, Cause> {
        let mut memory = self.answering()?;
        let before = memory.items.len();
        if memory.locked && memory.items.iter().any(|item| item.matches(attributes)) {
            return Err(Cause::Locked("a matching item is locked".into()));
        }
        memory.items.retain(|item| !item.matches(attributes));
        Ok(before - memory.items.len())
    }

    fn attribute_values(
        &self,
        attributes: &[(&str, &str)],
        key: &str,
    ) -> Result<Vec<String>, Cause> {
        let memory = self.answering()?;
        let mut values: Vec<String> = memory
            .items
            .iter()
            .filter(|item| item.matches(attributes))
            .filter_map(|item| item.attributes.get(key).cloned())
            .collect();
        values.sort();
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    const ONE: &[(&str, &str)] = &[("service", "dev.minimal.test"), ("id", "one")];

    // A session with no bus is unreachable, by the error's kind and not by
    // its text.
    #[test]
    fn a_session_with_no_bus_is_unreachable() {
        let items = SessionItems::new().at("unix:path=/nonexistent/bus");
        for answer in [
            items.lookup(ONE).map(|_| ()),
            items.store("label", ONE, b"v"),
            items.clear(ONE).map(|_| ()),
            items.attribute_values(ONE, "id").map(|_| ()),
        ] {
            assert!(matches!(answer, Err(Cause::Unreachable(_))), "{answer:?}");
        }
    }

    // A bus that accepts the connection and says nothing ends the call at
    // the timeout, as a stuck Secret Service does.
    #[test]
    fn a_bus_that_says_nothing_ends_at_the_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bus");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let timeout = Duration::from_millis(300);
        let items = SessionItems::within(timeout).at(&format!("unix:path={}", path.display()));
        let started = Instant::now();
        let err = items.lookup(ONE).unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(err, Cause::NoAnswer(timeout));
        // Nothing of the call outlives it: its end of the connection is
        // closed, so the bus reads to the end.
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        std::io::Read::read_to_end(&mut peer, &mut Vec::new())
            .expect("the call closed its connection");
        // A write ends the same way.
        assert_eq!(
            items.store("label", ONE, b"v"),
            Err(Cause::NoAnswer(timeout))
        );
        assert_eq!(err.to_string(), "Secret Service did not answer in 0 s");
        assert_eq!(
            Cause::NoAnswer(Duration::from_secs(10)).to_string(),
            "Secret Service did not answer in 10 s"
        );
    }

    #[test]
    fn errors_are_sorted_by_variant_and_error_name() {
        let method = |name: &'static str| {
            let name = zbus::names::OwnedErrorName::try_from(name).unwrap();
            let message = zbus::message::Message::method_call("/", "M")
                .build(&())
                .unwrap();
            Error::Zbus(zbus::Error::MethodError(
                name,
                Some("words".into()),
                message,
            ))
        };
        assert!(matches!(sort(Error::Locked), Cause::Locked(_)));
        // A bus with no Secret Service is not a session with no bus.
        assert!(matches!(sort(Error::Unavailable), Cause::NoProvider(_)));
        for name in NO_PROVIDER {
            assert!(matches!(sort(method(name)), Cause::NoProvider(_)), "{name}");
        }
        assert!(matches!(
            sort(method("org.freedesktop.Secret.Error.IsLocked")),
            Cause::Locked(_)
        ));
        for name in UNREACHABLE {
            assert!(
                matches!(sort(method(name)), Cause::Unreachable(_)),
                "{name}"
            );
        }
        assert!(matches!(
            sort(Error::ZbusFdo(zbus::fdo::Error::ServiceUnknown("x".into()))),
            Cause::NoProvider(_)
        ));
        let io = |kind| {
            Error::Zbus(zbus::Error::InputOutput(Arc::new(std::io::Error::from(
                kind,
            ))))
        };
        for kind in [
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::ConnectionRefused,
            std::io::ErrorKind::PermissionDenied,
        ] {
            assert!(matches!(sort(io(kind)), Cause::Unreachable(_)), "{kind:?}");
        }
        for other in [
            method("org.freedesktop.DBus.Error.Failed"),
            method("org.freedesktop.Secret.Error.NoSuchObject"),
            io(std::io::ErrorKind::BrokenPipe),
            Error::NoResult,
            Error::Prompt,
        ] {
            assert!(matches!(sort(other), Cause::Other(_)));
        }
        assert!(matches!(
            sort(io(std::io::ErrorKind::TimedOut)),
            Cause::NoAnswer(_)
        ));

        // For a method that changes an item, an answer that did not arrive
        // leaves the change unsettled, and an answer that refuses does not.
        for lost in [
            io(std::io::ErrorKind::BrokenPipe),
            io(std::io::ErrorKind::ConnectionRefused),
            method("org.freedesktop.DBus.Error.NoReply"),
            method("org.freedesktop.DBus.Error.Disconnected"),
            Error::ZbusFdo(zbus::fdo::Error::NoReply("x".into())),
            Error::PromptDisconnected,
        ] {
            let cause = sort_sent(lost);
            assert!(matches!(cause, Cause::Unsettled(_)), "{cause:?}");
        }
        assert!(matches!(
            sort_sent(io(std::io::ErrorKind::TimedOut)),
            Cause::NoAnswer(_)
        ));
        assert!(matches!(sort_sent(Error::Locked), Cause::Locked(_)));
        assert!(matches!(
            sort_sent(method("org.freedesktop.Secret.Error.IsLocked")),
            Cause::Locked(_)
        ));
        assert!(matches!(
            sort_sent(method("org.freedesktop.DBus.Error.Failed")),
            Cause::Other(_)
        ));
        assert!(matches!(sort_sent(Error::Prompt), Cause::Other(_)));
    }

    // The fake answers as Secret Service does, so a test of a caller pins
    // the caller's behaviour on a real keyring.
    #[test]
    fn memory_items_match_replace_and_lock_as_secret_service_does() {
        let items = MemoryItems::default();
        assert_eq!(items.lookup(ONE).unwrap(), None);
        items.store("one", ONE, b"\xff\x00first").unwrap();
        items
            .store(
                "two",
                &[("service", "dev.minimal.test"), ("id", "two")],
                b"2",
            )
            .unwrap();
        // The exact attributes replace. A subset of them matches.
        items.store("one", ONE, b"\xff\x00second").unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(
            items.lookup(ONE).unwrap().unwrap().as_slice(),
            b"\xff\x00second"
        );
        let service = &[("service", "dev.minimal.test")];
        assert_eq!(
            items.attribute_values(service, "id").unwrap(),
            vec!["one", "two"]
        );

        items.set_locked(true);
        assert!(matches!(items.lookup(ONE), Err(Cause::Locked(_))));
        assert!(matches!(
            items.store("one", ONE, b"v"),
            Err(Cause::Locked(_))
        ));
        assert!(matches!(items.clear(ONE), Err(Cause::Locked(_))));
        assert_eq!(items.attribute_values(service, "id").unwrap().len(), 2);
        assert_eq!(items.lookup(&[("id", "absent")]).unwrap(), None);
        assert_eq!(items.clear(&[("id", "absent")]).unwrap(), 0);
        items.set_locked(false);

        items.set_failure(Some(Cause::Unreachable("no bus".into())));
        assert_eq!(items.lookup(ONE), Err(Cause::Unreachable("no bus".into())));
        items.set_failure(None);

        assert_eq!(items.clear(service).unwrap(), 2);
        assert!(items.is_empty());
    }
}
