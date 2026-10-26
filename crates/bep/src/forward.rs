//! The forwarder: what the proxy does with each request inside a terminated
//! flow, and with each response (BEP-030, BEP-055, BEP-N01).
//!
//! - The upstream leg is validated before any request goes on it
//!   (BEP-055). [`validate`] completes the upstream TLS handshake against the
//!   host trust store, and only a completed handshake gives a [`Validated`]
//!   stream. A [`Flow`] needs the [`ValidatedUpstream`] proof that only a
//!   [`Validated`] stream gives, and [`substitute`] needs it too. So no code
//!   path substitutes a credential, or forwards a request, on a leg that did
//!   not validate. A leg that fails validation is refused, and the audit log
//!   records it [`UPSTREAM_TLS_INVALID`].
//! - Each parsed request goes to the decision. Every request first goes to
//!   [`redeem::decide_plain`], which checks the box's declared egress and the
//!   request authority. Then a request that carries a sealed value goes to
//!   the [`Redeemer`]. On an admit, the forwarder puts the credential in
//!   place of the sealed value. A request that carries no sealed value goes
//!   upstream unchanged (BEP-030). Its audit record is marked
//!   [`FOREIGN_CREDENTIAL`] when it carries an `Authorization` header of its
//!   own.
//! - [`relay_responses`] writes each chunk the upstream sends to the box as
//!   it arrives, and flushes it. It does not wait for the response to
//!   complete (BEP-N01).
//!
//! [`Unwired`], the redeemer [`crate::proxy::Proxy::new`] installs, is the
//! test default. It refuses every sealed value as [`Check::Undecryptable`],
//! and declares no egress for any box, so [`redeem::decide_plain`] refuses
//! every unsealed request as [`Check::OutsideDeclaredEgress`]. `bep serve`
//! installs the real redeemer, [`crate::redeemer::BoxRedeemer`], which reads
//! each box's declared egress from the boxes the control socket registers.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::oneshot;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use zeroize::{Zeroize as _, Zeroizing};

use crate::audit::{Decision, Kind, Mapping, Outcome};
use crate::handle::{Inject, parse_authority};
use crate::http::{self, CloseReason, Forwarded, Parse, Request};
use crate::inject::{self, INJECTION_INVALID};
use crate::proxy::{AuditWriter, absolute_form, respond};
use crate::redeem::{self, Authority, Check, Plain, RequestAuthority};
use crate::seal;
use crate::store::{ReadError, ValueReader};

/// The audit marker of an upstream leg that failed validation (BEP-055).
pub const UPSTREAM_TLS_INVALID: &str = "upstream_tls_invalid";

/// The audit marker of an unsealed request that carries its own credential
/// (BEP-030).
pub const FOREIGN_CREDENTIAL: &str = "foreign_credential";

/// The audit marker of a redeemed credential that holds a CR, LF or NUL
/// byte, which would split the header it goes into.
pub const CREDENTIAL_NOT_HEADER_SAFE: &str = "credential_not_header_safe";

/// The audit marker of a request with a sealed value in one `Authorization`
/// header and another `Authorization` header beside it, or with sealed values
/// in two headers. The upstream can honour either header, so the request is
/// refused.
pub const MIXED_AUTHORIZATION: &str = "mixed_authorization";

/// The audit marker of a substitution whose `Authorization` header is not in
/// the request. [`carried`] gives the header, so this is not expected.
pub const SEALED_HEADER_MISSING: &str = "sealed_header_missing";

/// The audit marker of a sealed value in a header that its injection form
/// does not name: not the registered header or `basic_auth` field of a store
/// reference, or not `Authorization` for a sign-in. The store is not read,
/// and no credential is put in the request.
pub const SEALED_HEADER_MISPLACED: &str = "sealed_header_misplaced";

/// The audit marker of the record a sign-in renewal writes at the proxy
/// (BEP-069). The record is its own line, beside the request's decision.
pub const SIGN_IN_RENEWED: &str = "github_sign_in_renewed";

/// The audit marker of an admitted store reference whose item is no longer
/// stored (BEP-045).
pub const STORE_ITEM_DELETED: &str = "store_item_deleted";

/// The audit marker of an admitted store reference whose item does not let
/// the proxy read it (BEP-045).
pub const STORE_ITEM_DISABLED: &str = "store_item_disabled";

/// The audit marker of an admitted store reference whose store failed the
/// read, or that names a store the flow cannot read.
pub const STORE_ITEM_UNREADABLE: &str = "store_item_unreadable";

/// The size of one read on the response half.
const RESPONSE_CHUNK: usize = 16 * 1024;

/// An upstream stream whose certificate chain and hostname validated
/// against the host trust store. Only [`validate`] makes one.
#[derive(Debug)]
pub struct Validated<S> {
    stream: S,
}

/// The proof that the upstream leg of a flow validated. Only
/// [`Validated::proof`] makes one.
#[derive(Debug, Clone, Copy)]
pub struct ValidatedUpstream {
    _private: (),
}

impl<S> Validated<S> {
    /// The proof that this leg validated.
    #[must_use]
    pub fn proof(&self) -> ValidatedUpstream {
        ValidatedUpstream { _private: () }
    }

    /// The stream itself.
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// A stream taken as validated with no handshake, for the relay tests.
    #[cfg(test)]
    pub(crate) fn unchecked(stream: S) -> Self {
        Self { stream }
    }
}

/// Why the upstream leg did not come up.
#[derive(Debug)]
pub enum UpstreamError {
    /// The name did not resolve, the connection failed, or it timed out.
    Unreachable(io::Error),
    /// The chain or the hostname did not validate against the host trust
    /// store, or the upstream presented no certificate.
    Invalid(rustls::Error),
    /// The TLS handshake failed for a reason other than the certificate: the
    /// upstream sent a TLS alert, or offered nothing this proxy accepts. An
    /// upstream that closes the connection during the handshake gives an io
    /// error, and so [`UpstreamError::Unreachable`].
    Handshake(rustls::Error),
}

impl UpstreamError {
    /// Sorts a TLS error: a certificate error is [`UpstreamError::Invalid`],
    /// and every other one is [`UpstreamError::Handshake`].
    fn from_tls(err: rustls::Error) -> Self {
        match err {
            rustls::Error::InvalidCertificate(_)
            | rustls::Error::NoCertificatesPresented
            | rustls::Error::UnsupportedNameType => Self::Invalid(err),
            _ => Self::Handshake(err),
        }
    }
}

impl UpstreamError {
    /// The audit marker, when the failure is an audited refusal. A leg whose
    /// handshake did not complete did not validate either (BEP-055).
    #[must_use]
    pub fn marker(&self) -> Option<&'static str> {
        match self {
            Self::Unreachable(_) => None,
            Self::Invalid(_) | Self::Handshake(_) => Some(UPSTREAM_TLS_INVALID),
        }
    }
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(err) => write!(f, "{err}"),
            Self::Invalid(err) | Self::Handshake(err) => write!(f, "{err}"),
        }
    }
}

impl From<io::Error> for UpstreamError {
    fn from(err: io::Error) -> Self {
        Self::Unreachable(err)
    }
}

/// Completes the upstream TLS handshake for `host` on `io` (BEP-055). The
/// connector's roots are the host trust store, with the interception root
/// taken out.
///
/// # Errors
///
/// [`UpstreamError::Invalid`] when the certificate does not validate,
/// [`UpstreamError::Handshake`] when the handshake fails for another TLS
/// reason, and [`UpstreamError::Unreachable`] when the connection fails.
pub async fn validate<IO>(
    connector: &TlsConnector,
    host: &str,
    io: IO,
) -> Result<Validated<TlsStream<IO>>, UpstreamError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    match connector.connect(name, io).await {
        Ok(stream) => Ok(Validated { stream }),
        Err(err) => {
            let tls = err
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<rustls::Error>())
                .cloned();
            Err(tls.map_or(UpstreamError::Unreachable(err), UpstreamError::from_tls))
        }
    }
}

/// What the decision gives for a request that carries a sealed value.
pub enum Verdict {
    /// Every check passed. The forwarder puts `credential` in place of the
    /// sealed value.
    Admit {
        /// The credential the member resolves to.
        credential: Zeroizing<String>,
        /// The member or store identifier, for the audit.
        identifier: String,
        /// The resource and permission, for the audit.
        mapping: Mapping,
        /// True when this request renewed the sign-in that gave the
        /// credential. The forwarder audits the renewal as its own record.
        renewed: bool,
        /// The admission's audit marker: `cohort_attributed` for a cohort
        /// admission, `None` for an admission from the named box itself.
        marker: Option<&'static str>,
        /// Whether the admission is cohort-attributed, for the
        /// `box_connection` span (BEP-028).
        cohort_attributed: bool,
    },
    /// The decision refused the request. The text is the audit marker.
    Refuse(&'static str),
}

impl std::fmt::Debug for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admit {
                identifier,
                renewed,
                ..
            } => f
                .debug_struct("Admit")
                .field("identifier", identifier)
                .field("renewed", renewed)
                .finish_non_exhaustive(),
            Self::Refuse(marker) => f.debug_tuple("Refuse").field(marker).finish(),
        }
    }
}

/// An admitted store reference (BEP-032). The forwarder reads the value
/// from the store for this request and injects it in `inject`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreAdmit {
    /// The store, as the reference names it.
    pub store: String,
    /// The item's identifier in the store.
    pub id: String,
    /// The injection form the rule registers.
    pub inject: Inject,
    /// The resource and permission, for the audit.
    pub mapping: Mapping,
    /// The admission's audit marker, as [`Verdict::Admit`] carries it.
    pub marker: Option<&'static str>,
    /// Whether the admission is cohort-attributed.
    pub cohort_attributed: bool,
}

impl StoreAdmit {
    /// The identifier an audit record carries: `<store>:<id>`.
    #[must_use]
    pub fn identifier(&self) -> String {
        format!("{}:{}", self.store, self.id)
    }
}

/// What the decision gives for a sealed value: a verdict on a credential to
/// put in place of the value, or an admitted store reference.
#[derive(Debug)]
pub enum Redeemed {
    /// A [`Verdict`].
    Verdict(Verdict),
    /// An admitted store reference.
    Store(StoreAdmit),
}

/// The per-request decision.
pub trait Redeemer: Send + Sync {
    /// The authorities the box's declared egress admits (BEP-022).
    fn egress(&self, box_id: &str) -> Vec<Authority<String>>;

    /// Decides one request that carries `sealed`, on a flow to `authority`
    /// (BEP-025).
    ///
    /// The forwarder applies [`redeem::decide_plain`]'s checks, the declared
    /// egress and the request authority, before it calls this. An
    /// implementation carries the other BEP-025 checks.
    fn redeem(
        &self,
        box_id: &str,
        authority: &Authority<String>,
        request: &RequestAuthority<String>,
        sealed: &str,
    ) -> Verdict;

    /// Decides one sealed value as [`Redeemer::redeem`] does, and gives the
    /// handle's `jti` for the audit record. The `jti` is empty when the
    /// handle does not parse.
    fn redeem_with_jti(
        &self,
        box_id: &str,
        authority: &Authority<String>,
        request: &RequestAuthority<String>,
        sealed: &str,
    ) -> (Verdict, String) {
        (
            self.redeem(box_id, authority, request, sealed),
            String::new(),
        )
    }

    /// Decides one request that carries `sealed` in the header named
    /// `header`, as [`Self::redeem`] does, with an admitted store reference
    /// as [`Redeemed::Store`], and the handle's `jti` for the audit record
    /// as [`Self::redeem_with_jti`] gives it. The forwarder calls this one.
    ///
    /// The default admits no store reference, so a redeemer without store
    /// references implements `redeem` alone. A sign-in credential goes in
    /// `Authorization` only. So the default refuses a sealed value in any
    /// other header as [`SEALED_HEADER_MISPLACED`], before [`Self::redeem`]
    /// runs, and nothing is renewed for it. Otherwise it gives
    /// [`Self::redeem_with_jti`]'s verdict and `jti`.
    ///
    /// Interim: no redeemer in this crate returns [`Redeemed::Store`] yet,
    /// so `bep serve` does not inject a store value
    /// (<https://github.com/gominimal/minimal/issues/2586>). This changes
    /// when `BoxRedeemer` (`redeemer.rs`) overrides this method to return
    /// [`Redeemed::Store`] for an admitted store member, and `proxy.rs`
    /// calls [`Flow::with_store`] with the host store. Remove this note
    /// when both land.
    fn redeem_reference(
        &self,
        box_id: &str,
        authority: &Authority<String>,
        request: &RequestAuthority<String>,
        sealed: &str,
        header: &str,
    ) -> (Redeemed, String) {
        if !header.eq_ignore_ascii_case("authorization") {
            return (
                Redeemed::Verdict(Verdict::Refuse(SEALED_HEADER_MISPLACED)),
                String::new(),
            );
        }
        let (verdict, jti) = self.redeem_with_jti(box_id, authority, request, sealed);
        (Redeemed::Verdict(verdict), jti)
    }
}

/// What [`SingleFlight::run`] gave its caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ran<T> {
    /// No run for the key was in flight. This caller ran the work.
    Led(T),
    /// A run for the key was in flight. This caller waited for its outcome
    /// and ran nothing.
    Waited(T),
    /// The run this caller waited for ended with no outcome: it panicked.
    Abandoned,
    /// The run this caller waited for did not end within the wait limit.
    /// The caller stopped waiting, and the run goes on.
    TimedOut,
}

/// How long a caller waits for a run in flight before it stops waiting. A
/// renewal's exchange with GitHub has 30 seconds. The rest of the limit
/// covers the keychain reads and the write.
pub const FLIGHT_WAIT_LIMIT: Duration = Duration::from_secs(45);

/// One run in flight per key, the other callers waiting for its outcome.
///
/// The proxy renews a sign-in through it, keyed by the item's instance
/// (BEP-069). GitHub's refresh grant is single-use, so a second renewal from
/// the same refresh material fails. Each request that finds the renewal in
/// flight waits for that renewal's outcome and does not renew again.
pub struct SingleFlight<T> {
    flights: Mutex<HashMap<String, Arc<InFlight<T>>>>,
    wait_limit: Duration,
}

impl<T> Default for SingleFlight<T> {
    fn default() -> Self {
        Self::with_wait_limit(FLIGHT_WAIT_LIMIT)
    }
}

impl<T> std::fmt::Debug for SingleFlight<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SingleFlight").finish_non_exhaustive()
    }
}

/// One run: whether it finished, and its outcome.
struct InFlight<T> {
    state: Mutex<(bool, Option<T>)>,
    done: Condvar,
}

/// Ends the leader's run on drop, a panic included: removes the key, marks
/// the run finished and wakes the waiters.
struct Finish<'a, T> {
    flights: &'a Mutex<HashMap<String, Arc<InFlight<T>>>>,
    key: &'a str,
    flight: Arc<InFlight<T>>,
}

impl<T> Drop for Finish<'_, T> {
    fn drop(&mut self) {
        self.flights
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(self.key);
        self.flight
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .0 = true;
        self.flight.done.notify_all();
    }
}

impl<T> SingleFlight<T> {
    /// No run in flight, each waiter waiting at most `wait_limit`.
    #[must_use]
    pub fn with_wait_limit(wait_limit: Duration) -> Self {
        Self {
            flights: Mutex::new(HashMap::new()),
            wait_limit,
        }
    }
}

impl<T: Clone> SingleFlight<T> {
    /// Run `work` for `key`, unless a run for `key` is in flight. Then wait
    /// for that run's outcome in place of running `work`, for at most the
    /// wait limit.
    pub fn run(&self, key: &str, work: impl FnOnce() -> T) -> Ran<T> {
        let (flight, leader) = {
            let mut flights = self.flights.lock().unwrap_or_else(PoisonError::into_inner);
            match flights.get(key) {
                Some(flight) => (Arc::clone(flight), false),
                None => {
                    let flight = Arc::new(InFlight {
                        state: Mutex::new((false, None)),
                        done: Condvar::new(),
                    });
                    flights.insert(key.to_owned(), Arc::clone(&flight));
                    (flight, true)
                }
            }
        };
        if leader {
            let finish = Finish {
                flights: &self.flights,
                key,
                flight: Arc::clone(&flight),
            };
            let outcome = work();
            flight
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .1 = Some(outcome.clone());
            drop(finish);
            return Ran::Led(outcome);
        }
        let state = flight.state.lock().unwrap_or_else(PoisonError::into_inner);
        let (state, waited) = flight
            .done
            .wait_timeout_while(state, self.wait_limit, |state| !state.0)
            .unwrap_or_else(PoisonError::into_inner);
        if waited.timed_out() && !state.0 {
            return Ran::TimedOut;
        }
        state.1.clone().map_or(Ran::Abandoned, Ran::Waited)
    }
}

/// The redeemer of a proxy with no proxy key: it refuses every sealed value,
/// and declares no egress for any box. It is the test default. `bep serve`
/// installs [`crate::redeemer::BoxRedeemer`] in its place.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unwired;

impl Redeemer for Unwired {
    fn egress(&self, _box_id: &str) -> Vec<Authority<String>> {
        // No box's declared egress is known yet, so none is admitted
        // (Gatehouse §6.10 step 3).
        Vec::new()
    }

    fn redeem(
        &self,
        _box_id: &str,
        _authority: &Authority<String>,
        _request: &RequestAuthority<String>,
        _sealed: &str,
    ) -> Verdict {
        Verdict::Refuse(Check::Undecryptable.marker())
    }
}

/// Where a sealed value sits in a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedAt {
    /// The index of the header that carries the sealed value.
    header: usize,
    /// How the header carries the value.
    form: Form,
    /// The sealed value.
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Form {
    /// `<scheme> <value>`, as `Bearer` or `token`.
    Token(String),
    /// `Basic`, with the value as the user (`true`) or the password.
    Basic {
        user: String,
        pass: String,
        in_user: bool,
    },
    /// The value alone.
    Bare,
}

/// The credential a request carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Carried {
    /// A sealed value.
    Sealed(SealedAt),
    /// An `Authorization` header with no sealed value in it.
    Foreign,
    /// A sealed value, and another `Authorization` header beside it.
    Mixed,
    /// No `Authorization` header.
    None,
}

/// Whether `text` has the printed form of a sealed value: five segments,
/// the second empty, and a protected header whose `typ` is [`seal::TYP`].
#[must_use]
pub fn is_sealed(text: &str) -> bool {
    if text.len() > seal::MAX_SEALED_LEN {
        return false;
    }
    let segments: Vec<&str> = text.split('.').collect();
    if segments.len() != 5 || !segments[1].is_empty() {
        return false;
    }
    let Ok(header) = URL_SAFE_NO_PAD.decode(segments[0]) else {
        return false;
    };
    serde_json::from_slice::<serde_json::Value>(&header)
        .ok()
        .and_then(|v| {
            v.get("typ")
                .and_then(|t| t.as_str())
                .map(|t| t == seal::TYP)
        })
        .unwrap_or(false)
}

/// The credential `request` carries in its headers.
///
/// Every header is searched for a sealed value, because a store reference
/// can come in the header its client sends a key in, such as `x-api-key`.
///
/// A request with one header that holds a sealed value is
/// [`Carried::Sealed`], unless an `Authorization` header that does not hold
/// the sealed value is beside it. That, or a second sealed value, is
/// [`Carried::Mixed`]: the upstream can honour either header, so
/// the decision refuses it. A request with no sealed value and an
/// `Authorization` header is [`Carried::Foreign`].
#[must_use]
pub fn carried(request: &Request) -> Carried {
    let mut sealed: Option<(SealedAt, bool)> = None;
    let mut found = 0usize;
    let mut count = 0usize;
    for (index, header) in request.headers.iter().enumerate() {
        let authorization = header.name.eq_ignore_ascii_case("authorization");
        if authorization {
            count += 1;
        }
        if let Some(at) = sealed_in(index, &header.value) {
            found += 1;
            if sealed.is_none() {
                sealed = Some((at, authorization));
            }
        }
    }
    match sealed {
        Some(_) if found > 1 => Carried::Mixed,
        // An `Authorization` header that does not hold the sealed value is
        // the box's own credential, whichever header holds the sealed one.
        Some((_, in_authorization)) if count > usize::from(in_authorization) => Carried::Mixed,
        Some((at, _)) => Carried::Sealed(at),
        None if count == 0 => Carried::None,
        None => Carried::Foreign,
    }
}

impl SealedAt {
    /// The `Basic` field the box sent beside the sealed value, or empty when
    /// the value is not in a `Basic` header.
    fn other_basic_field(&self) -> &[u8] {
        match &self.form {
            Form::Basic {
                user,
                pass,
                in_user,
            } => {
                if *in_user {
                    pass.as_bytes()
                } else {
                    user.as_bytes()
                }
            }
            Form::Token(_) | Form::Bare => &[],
        }
    }
}

/// Whether the header at `at` in `request` is named `name`.
fn header_named(request: &Request, at: &SealedAt, name: &str) -> bool {
    request
        .headers
        .get(at.header)
        .is_some_and(|h| h.name.eq_ignore_ascii_case(name))
}

fn sealed_in(header: usize, value: &[u8]) -> Option<SealedAt> {
    let text = std::str::from_utf8(value).ok()?.trim();
    let (scheme, rest) = text.split_once(' ').unwrap_or(("", text));
    let rest = rest.trim();
    if scheme.eq_ignore_ascii_case("basic") {
        let decoded = String::from_utf8(STANDARD.decode(rest).ok()?).ok()?;
        let (user, pass) = decoded.split_once(':')?;
        let in_user = is_sealed(user);
        let sealed = if in_user { user } else { pass };
        return is_sealed(sealed).then(|| SealedAt {
            header,
            value: sealed.to_owned(),
            form: Form::Basic {
                user: user.to_owned(),
                pass: pass.to_owned(),
                in_user,
            },
        });
    }
    if scheme.is_empty() {
        return is_sealed(rest).then(|| SealedAt {
            header,
            value: rest.to_owned(),
            form: Form::Bare,
        });
    }
    is_sealed(rest).then(|| SealedAt {
        header,
        value: rest.to_owned(),
        form: Form::Token(scheme.to_owned()),
    })
}

/// Puts `credential` in place of the sealed value at `at` (BEP-025). The
/// proof says the upstream leg validated (BEP-055).
///
/// # Errors
///
/// [`CREDENTIAL_NOT_HEADER_SAFE`] when `credential` holds a CR, LF or NUL
/// byte, and [`SEALED_HEADER_MISSING`] when the request has no header at
/// `at`. The request is then unchanged.
pub fn substitute(
    request: &mut Request,
    at: &SealedAt,
    credential: &str,
    _validated: ValidatedUpstream,
) -> Result<(), &'static str> {
    if credential.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
        return Err(CREDENTIAL_NOT_HEADER_SAFE);
    }
    let value = match &at.form {
        Form::Token(scheme) => Zeroizing::new(format!("{scheme} {credential}")),
        Form::Bare => Zeroizing::new(credential.to_owned()),
        Form::Basic {
            user,
            pass,
            in_user,
        } => {
            let pair = Zeroizing::new(if *in_user {
                format!("{credential}:{pass}")
            } else {
                format!("{user}:{credential}")
            });
            Zeroizing::new(format!("Basic {}", STANDARD.encode(pair.as_bytes())))
        }
    };
    let header = request
        .headers
        .get_mut(at.header)
        .ok_or(SEALED_HEADER_MISSING)?;
    header.value.zeroize();
    header.value = value.as_bytes().to_vec();
    Ok(())
}

/// The authorities a request names: its `Host` header and an absolute-form
/// target (BEP-023).
#[must_use]
pub fn request_authority(request: &Request) -> RequestAuthority<String> {
    let mut hosts = request
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("host"));
    let host = match (hosts.next(), hosts.next()) {
        (Some(h), None) => std::str::from_utf8(&h.value)
            .ok()
            .and_then(|v| parse_authority(v.trim().trim_end_matches('.'))),
        _ => None,
    };
    let target = absolute_form(&request.target).map(|(_, host, port)| Authority { host, port });
    RequestAuthority { host, target }
}

/// One terminated flow, as the request half sees it.
pub struct Flow {
    box_id: String,
    authority: Authority<String>,
    audit: Arc<dyn AuditWriter>,
    redeemer: Arc<dyn Redeemer>,
    validated: ValidatedUpstream,
    store: Option<Arc<dyn ValueReader>>,
}

impl std::fmt::Debug for Flow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Flow")
            .field("box_id", &self.box_id)
            .field("authority", &self.authority)
            .finish_non_exhaustive()
    }
}

/// A request the decision refused, for the response half to answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The audit marker.
    pub marker: &'static str,
    /// The answer's body.
    pub body: String,
    /// Whether an earlier request of the flow went upstream. Its response
    /// goes to the box before the refusal does.
    pub after_forwarded: bool,
}

/// How the request half ended.
#[derive(Debug)]
pub enum HalfEnd {
    /// The connection closed, for this reason.
    Closed(CloseReason),
    /// The decision refused a request. Nothing of it went upstream.
    Refused(Refusal),
}

impl Flow {
    /// A flow for `box_id` to `authority`, on a leg that validated.
    #[must_use]
    pub fn new(
        box_id: &str,
        authority: Authority<String>,
        audit: Arc<dyn AuditWriter>,
        redeemer: Arc<dyn Redeemer>,
        validated: ValidatedUpstream,
    ) -> Self {
        Self {
            box_id: box_id.to_owned(),
            authority,
            audit,
            redeemer,
            validated,
            store: None,
        }
    }

    /// This flow, with `store` as the store it reads a store reference's
    /// value from. With none, every store reference is refused as
    /// [`STORE_ITEM_UNREADABLE`].
    ///
    /// Interim: `bep serve` does not call this yet, so a served flow has no
    /// store (<https://github.com/gominimal/minimal/issues/2586>). This
    /// changes when `proxy.rs` calls this method with the host store,
    /// together with the `BoxRedeemer` override of
    /// [`Redeemer::redeem_reference`]. Remove this note when both land.
    #[must_use]
    pub fn with_store(mut self, store: Arc<dyn ValueReader>) -> Self {
        self.store = Some(store);
        self
    }

    /// Reads the value of the admitted store reference `admit` for this
    /// request, and injects it in place of the sealed value at `at`
    /// (BEP-032, BEP-033, BEP-045, BEP-065, BEP-066).
    ///
    /// The value is read now, and dropped zeroized when the request is
    /// written. It goes to no file and no log.
    ///
    /// A sealed value that is not where the injection form puts the value is
    /// refused as [`SEALED_HEADER_MISPLACED`], before the store is read.
    ///
    /// Gives the lowercase name of the header that now holds the value, for
    /// the caller to zeroize once the request is written.
    fn inject_store(
        &self,
        request: &mut Request,
        at: &SealedAt,
        admit: StoreAdmit,
        jti: &str,
    ) -> Result<String, &'static str> {
        let span = tracing::Span::current();
        let identifier = admit.identifier();
        let header = match &admit.inject {
            Inject::Header { name, .. } => name.to_ascii_lowercase(),
            Inject::BasicAuth { .. } => "authorization".to_owned(),
        };
        let placed = match &admit.inject {
            Inject::Header { name, .. } => header_named(request, at, name),
            Inject::BasicAuth { field } => {
                header_named(request, at, "authorization")
                    && matches!(&at.form, Form::Basic { in_user, .. }
                        if *in_user == (field == inject::FIELD_USER))
            }
        };
        let read = || match &self.store {
            Some(store) if store.name() == admit.store => store.read(&admit.id),
            _ => Err(ReadError::Store(crate::store::StoreError::Refused {
                store: "proxy",
                action: "read the secret",
                detail: format!("no store {} is open in this flow", admit.store),
            })),
        };
        // The store is not read for a sealed value in the wrong header.
        let result = (if placed {
            Ok(())
        } else {
            Err(SEALED_HEADER_MISPLACED)
        })
        .and_then(|()| {
            read().map_err(|error| match error {
                ReadError::Deleted(_) => STORE_ITEM_DELETED,
                ReadError::Disabled(_) => STORE_ITEM_DISABLED,
                ReadError::Store(error) => {
                    tracing::warn!(store = %admit.store, id = %admit.id, %error, "the stored secret was not read");
                    STORE_ITEM_UNREADABLE
                }
            })
        })
        .and_then(|value| {
                inject::inject(
                    request,
                    at.header,
                    &admit.inject,
                    &value,
                    at.other_basic_field(),
                )
            });
        // One line per injection. It names no value.
        tracing::debug!(
            store = %admit.store,
            id = %admit.id,
            header = %header,
            outcome = result.err().unwrap_or("injected"),
            "store value injection"
        );
        match result {
            Ok(()) => {
                span.record("substitution", "substituted");
                span.record("cohort_attributed", admit.cohort_attributed);
                self.record(
                    Outcome::Admit,
                    admit.marker,
                    Some(identifier),
                    jti,
                    admit.mapping,
                );
                Ok(header)
            }
            Err(marker) => {
                span.record("substitution", "refused");
                self.record(
                    Outcome::Refuse,
                    Some(marker),
                    Some(identifier),
                    jti,
                    admit.mapping,
                );
                Err(marker)
            }
        }
    }

    fn authority_text(&self) -> String {
        format!("{}:{}", self.authority.host, self.authority.port)
    }

    fn record(
        &self,
        outcome: Outcome,
        marker: Option<&str>,
        identifier: Option<String>,
        jti: &str,
        mapping: Mapping,
    ) {
        self.audit.write(&Decision {
            kind: Kind::Decision,
            box_id: self.box_id.clone(),
            authority: self.authority_text(),
            identifier,
            jti: jti.to_owned(),
            mapping,
            outcome,
            marker: marker.map(str::to_owned),
        });
    }

    /// Decides one request, and substitutes on an admit. Writes its audit
    /// record and records the decision on the current span.
    ///
    /// # Errors
    ///
    /// The audit marker of a refusal.
    pub fn decide(&self, request: &mut Request) -> Result<(), &'static str> {
        self.decide_injected(request).map(|_| ())
    }

    /// Decides one request, as [`Self::decide`] does. Gives the lowercase
    /// name of the header a store value was injected in, if any, for the
    /// caller to zeroize once the request is written.
    fn decide_injected(&self, request: &mut Request) -> Result<Option<String>, &'static str> {
        let span = tracing::Span::current();
        // The egress and request-authority checks hold for every request,
        // sealed or not, before any redeemer sees it (BEP-022, BEP-023).
        let plain = Plain {
            authority: self.authority.clone(),
            request: request_authority(request),
            egress: self.redeemer.egress(&self.box_id),
        };
        if let Err(check) = redeem::decide_plain(&plain) {
            span.record("substitution", "refused");
            self.record(
                Outcome::Refuse,
                Some(check.marker()),
                None,
                "",
                Mapping::ModuleUnmapped,
            );
            return Err(check.marker());
        }
        match carried(request) {
            Carried::Sealed(at) => {
                let header = request
                    .headers
                    .get(at.header)
                    .map_or("", |h| h.name.as_str());
                let (redeemed, jti) = self.redeemer.redeem_reference(
                    &self.box_id,
                    &self.authority,
                    &plain.request,
                    &at.value,
                    header,
                );
                let verdict = match redeemed {
                    Redeemed::Store(admit) => {
                        return self.inject_store(request, &at, admit, &jti).map(Some);
                    }
                    Redeemed::Verdict(verdict) => verdict,
                };
                match verdict {
                    Verdict::Admit {
                        credential,
                        identifier,
                        mapping,
                        renewed,
                        marker: admitted,
                        cohort_attributed,
                    } => {
                        if renewed {
                            // BEP-069: the renewal is its own audit record,
                            // written before the request's decision.
                            self.record(
                                Outcome::Admit,
                                Some(SIGN_IN_RENEWED),
                                Some(identifier.clone()),
                                &jti,
                                mapping.clone(),
                            );
                        }
                        // A sign-in credential goes in `Authorization` only,
                        // so a sealed value in another header is refused.
                        let placed = request
                            .headers
                            .get(at.header)
                            .is_none_or(|h| h.name.eq_ignore_ascii_case("authorization"));
                        let substituted = if placed {
                            substitute(request, &at, &credential, self.validated)
                        } else {
                            Err(SEALED_HEADER_MISPLACED)
                        };
                        if let Err(marker) = substituted {
                            // The module mapped the request, so the refusal
                            // records the mapping (Gatehouse §6.10).
                            span.record("substitution", "refused");
                            self.record(
                                Outcome::Refuse,
                                Some(marker),
                                Some(identifier),
                                &jti,
                                mapping,
                            );
                            return Err(marker);
                        }
                        span.record("substitution", "substituted");
                        // Recorded only once the admit stands, so a refused
                        // substitution never shows the cohort flag.
                        span.record("cohort_attributed", cohort_attributed);
                        // BEP-028: a cohort admission keeps its marker.
                        self.record(Outcome::Admit, admitted, Some(identifier), &jti, mapping);
                        Ok(None)
                    }
                    Verdict::Refuse(marker) => {
                        span.record("substitution", "refused");
                        self.record(
                            Outcome::Refuse,
                            Some(marker),
                            None,
                            &jti,
                            Mapping::ModuleUnmapped,
                        );
                        Err(marker)
                    }
                }
            }
            Carried::Mixed => {
                // Nothing is redeemed: the upstream can honour the other
                // `Authorization` header in place of the credential.
                span.record("substitution", "refused");
                self.record(
                    Outcome::Refuse,
                    Some(MIXED_AUTHORIZATION),
                    None,
                    "",
                    Mapping::ModuleUnmapped,
                );
                Err(MIXED_AUTHORIZATION)
            }
            carried @ (Carried::Foreign | Carried::None) => {
                // BEP-030: forwarded unmodified, and audited.
                let marker = (carried == Carried::Foreign).then_some(FOREIGN_CREDENTIAL);
                span.record("substitution", marker.unwrap_or("passthrough"));
                self.record(Outcome::Admit, marker, None, "", Mapping::ModuleUnmapped);
                Ok(None)
            }
        }
    }

    fn refusal_body(&self, marker: &str) -> String {
        let authority = self.authority_text();
        if marker == Check::OutsideDeclaredEgress.marker() {
            format!(
                "The Box Egress Proxy refused the request to {authority}, because this box is not allowed to reach {authority}."
            )
        } else if marker == MIXED_AUTHORIZATION {
            format!(
                "The Box Egress Proxy refused the request to {authority}, because it carries a credential in more than one header. Send one sealed credential, in one header."
            )
        } else if marker == SEALED_HEADER_MISPLACED {
            format!(
                "The Box Egress Proxy refused the request to {authority}, because its sealed credential is in a header that does not carry a credential to {authority}. Send the sealed credential in the header that its secret store rule names, or in the Authorization header for a GitHub sign-in."
            )
        } else if marker == STORE_ITEM_DELETED {
            format!(
                "The Box Egress Proxy refused the request to {authority}, because the secret that its sealed credential refers to is no longer stored."
            )
        } else if marker == STORE_ITEM_DISABLED {
            format!(
                "The Box Egress Proxy refused the request to {authority}, because the stored secret that its sealed credential refers to does not let the proxy read it."
            )
        } else if marker == STORE_ITEM_UNREADABLE {
            format!(
                "The Box Egress Proxy refused the request to {authority}, because it was not able to read the stored secret that its sealed credential refers to."
            )
        } else if marker == INJECTION_INVALID {
            format!(
                "The Box Egress Proxy refused the request to {authority}, because the stored secret and the form that its secret store rule sets do not make a valid request header."
            )
        } else if marker == Check::HostMismatch.marker() {
            format!(
                "The Box Egress Proxy refused the request to {authority}, because its Host header or its target names a different host."
            )
        } else {
            format!(
                "The Box Egress Proxy refused the request to {authority}, because it did not accept the sealed credential in the request."
            )
        }
    }
}

/// Forward the requests of one flow to `upstream`, each after its decision,
/// until the connection closes or the decision refuses one. A refused
/// request sends nothing upstream.
pub fn forward_requests<R: Read, W: Write>(
    flow: &Flow,
    client: &mut R,
    upstream: &mut W,
) -> HalfEnd {
    let mut pending = Vec::new();
    let mut forwarded_any = false;
    let end = loop {
        let (mut request, rest) = match read_head(pending, client) {
            Ok(head) => head,
            Err(reason) => {
                if let Some(marker) = reason.audit_marker() {
                    flow.record(
                        Outcome::Refuse,
                        Some(marker),
                        None,
                        "",
                        Mapping::ModuleUnmapped,
                    );
                }
                break HalfEnd::Closed(reason);
            }
        };
        let injected = match flow.decide_injected(&mut request) {
            Ok(injected) => injected,
            Err(marker) => {
                break HalfEnd::Refused(Refusal {
                    marker,
                    body: flow.refusal_body(marker),
                    after_forwarded: forwarded_any,
                });
            }
        };
        let mut head = Zeroizing::new(request.serialize());
        // The head holds the credential after a substitution, and the stored
        // value after an injection in a header of any name.
        for header in &mut request.headers {
            if header.name.eq_ignore_ascii_case("authorization")
                || injected
                    .as_deref()
                    .is_some_and(|name| header.name.eq_ignore_ascii_case(name))
            {
                header.value.zeroize();
            }
        }
        let wrote = upstream.write_all(&head).and_then(|()| upstream.flush());
        head.zeroize();
        if let Err(err) = wrote {
            break HalfEnd::Closed(CloseReason::Io(err.kind()));
        }
        forwarded_any = true;
        let switches = request.switches_protocol();
        pending = match http::relay_request_body(Forwarded { request, rest }, client, upstream) {
            Ok(rest) => rest,
            Err(reason) => break HalfEnd::Closed(reason),
        };
        if switches {
            break HalfEnd::Closed(CloseReason::ProtocolSwitch { rest: pending });
        }
    };
    match &end {
        HalfEnd::Closed(reason) => {
            tracing::debug!(
                box_id = flow.box_id,
                rule = reason.rule(),
                "box connection closed"
            );
        }
        HalfEnd::Refused(refusal) => {
            tracing::info!(
                box_id = flow.box_id,
                marker = refusal.marker,
                "a request was refused"
            );
        }
    }
    end
}

/// Reads one request head, with `pending` bytes already read.
fn read_head<R: Read>(mut buf: Vec<u8>, reader: &mut R) -> Result<(Request, Vec<u8>), CloseReason> {
    let mut chunk = [0u8; 4096];
    loop {
        if let Parse::Complete { head, head_len } = http::parse_request(&buf)? {
            return Ok((head, buf.split_off(head_len)));
        }
        let n = match reader.read(&mut chunk) {
            Ok(0) if buf.is_empty() => return Err(CloseReason::ClientClosed),
            Ok(0) => return Err(CloseReason::Eof),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(CloseReason::Io(e.kind())),
        };
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// The response half of a flow: writes each chunk the upstream sends to the
/// box, and flushes it, as it arrives (BEP-N01). It ends when the upstream
/// closes. When the request half refuses a request, the box gets a `403`
/// for it: at once when no request went upstream, and otherwise after the
/// upstream closes.
pub async fn relay_responses<R, W>(
    upstream: &mut R,
    client: &mut W,
    refused: oneshot::Receiver<Refusal>,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; RESPONSE_CHUNK];
    let mut refused = Some(refused);
    let mut refusal = None;
    loop {
        tokio::select! {
            read = upstream.read(&mut buf) => match read {
                Ok(0) => break,
                Ok(n) => {
                    if client.write_all(&buf[..n]).await.is_err() || client.flush().await.is_err() {
                        return;
                    }
                }
                Err(err) => {
                    if err.kind() == io::ErrorKind::TimedOut {
                        tracing::info!("the relayed flow was idle too long");
                    }
                    break;
                }
            },
            got = async { refused.as_mut().expect("guarded").await }, if refused.is_some() => {
                refused = None;
                if let Ok(got) = got {
                    let now = !got.after_forwarded;
                    refusal = Some(got);
                    if now {
                        break;
                    }
                }
            }
        }
    }
    // The upstream can close before the refusal arrives: take one that is
    // already sent, so the box sees the 403 and not a silent close.
    if refusal.is_none()
        && let Some(mut rx) = refused
        && let Ok(got) = rx.try_recv()
    {
        refusal = Some(got);
    }
    match refusal {
        Some(refusal) => respond(client, 403, "Forbidden", &refusal.body).await,
        None => {
            let _ = client.shutdown().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, SystemTime};

    use proptest::prelude::*;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{RootCertStore, ServerConfig};
    use tokio::io::DuplexStream;
    use tokio::net::TcpListener;
    use tokio::sync::Notify;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::client::TlsStream as ClientTls;

    use super::*;
    use crate::audit::{AuditLog, LogReader, segment_name};
    use crate::module::GITHUB;
    use crate::proxy::tests::{To, box_connection, box_tls, interception_ca, response_head};
    use crate::proxy::{ALPN_HTTP11, Admission, LeafIssuer, Proxy, UPSTREAM_NOT_TLS, provider};

    /// The credential an admitting redeemer gives.
    const REAL: &str = "ghs_real_credential";

    /// A string with the printed form of a sealed value.
    fn sealed_text() -> String {
        let header = URL_SAFE_NO_PAD.encode(format!(r#"{{"typ":"{}"}}"#, seal::TYP));
        format!("{header}..aXY.Y3Q.dGFn")
    }

    /// An upstream CA, which the host trust store holds.
    struct UpstreamCa {
        key: KeyPair,
        params: CertificateParams,
        root: CertificateDer<'static>,
    }

    impl UpstreamCa {
        fn new() -> Self {
            let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let root = params.self_signed(&key).unwrap().der().clone();
            Self { key, params, root }
        }

        /// A leaf for `name`, and its key. An expired leaf ended in 2021.
        fn leaf(&self, name: &str, expired: bool) -> (Vec<CertificateDer<'static>>, Vec<u8>) {
            let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
            let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
            if expired {
                params.not_before = rcgen::date_time_ymd(2020, 1, 1);
                params.not_after = rcgen::date_time_ymd(2021, 1, 1);
            }
            let cert = params
                .signed_by(&key, &Issuer::from_params(&self.params, &self.key))
                .unwrap();
            (vec![cert.der().clone()], key.serialize_der())
        }

        fn roots(&self) -> RootCertStore {
            let mut roots = RootCertStore::empty();
            roots.add(self.root.clone()).unwrap();
            roots
        }
    }

    /// What the test upstream does with each request head.
    #[derive(Clone)]
    enum Answer {
        /// `200` with the body `ok`.
        Ok,
        /// A chunked `200`: the first chunk, then the rest once `release`
        /// is notified.
        Stream(Arc<Notify>),
    }

    /// A TLS upstream that serves `chain`. It records every request head it
    /// reads, and the count of application bytes it read.
    struct TestUpstream {
        addr: SocketAddr,
        heads: Arc<Mutex<Vec<String>>>,
        bytes: Arc<AtomicUsize>,
    }

    async fn test_upstream(
        chain: Vec<CertificateDer<'static>>,
        key: Vec<u8>,
        answer: Answer,
    ) -> TestUpstream {
        let mut config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)))
            .unwrap();
        config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let heads = Arc::new(Mutex::new(Vec::new()));
        let bytes = Arc::new(AtomicUsize::new(0));
        let (h, b) = (heads.clone(), bytes.clone());
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let (acceptor, h, b, answer) =
                    (acceptor.clone(), h.clone(), b.clone(), answer.clone());
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let n = match tls.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        b.fetch_add(n, Ordering::SeqCst);
                        buf.extend_from_slice(&chunk[..n]);
                        while let Ok(Parse::Complete { head, head_len }) = http::parse_request(&buf)
                        {
                            buf.drain(..head_len);
                            h.lock()
                                .unwrap()
                                .push(String::from_utf8(head.serialize()).unwrap());
                            match &answer {
                                Answer::Ok => {
                                    let _ = tls
                                        .write_all(
                                            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
                                        )
                                        .await;
                                }
                                Answer::Stream(release) => {
                                    let _ = tls
                                        .write_all(
                                            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nfirst\r\n",
                                        )
                                        .await;
                                    let _ = tls.flush().await;
                                    release.notified().await;
                                    let _ = tls.write_all(b"4\r\nlast\r\n0\r\n\r\n").await;
                                    let _ = tls.shutdown().await;
                                    return;
                                }
                            }
                        }
                    }
                    let _ = tls.shutdown().await;
                });
            }
        });
        TestUpstream { addr, heads, bytes }
    }

    /// The declared egress of the test box: the GitHub host set.
    fn github_egress() -> Vec<Authority<String>> {
        GITHUB
            .hosts
            .iter()
            .map(|a| Authority {
                host: a.host.to_owned(),
                port: a.port,
            })
            .collect()
    }

    /// A redeemer whose box declares the GitHub host set as its egress, and
    /// that refuses every sealed value, as [`Unwired`] does.
    struct Declared;

    impl Redeemer for Declared {
        fn egress(&self, _box_id: &str) -> Vec<Authority<String>> {
            github_egress()
        }

        fn redeem(
            &self,
            _box_id: &str,
            _authority: &Authority<String>,
            _request: &RequestAuthority<String>,
            _sealed: &str,
        ) -> Verdict {
            Verdict::Refuse(Check::Undecryptable.marker())
        }
    }

    /// A redeemer that admits every sealed value with [`REAL`], and counts
    /// its calls.
    #[derive(Default)]
    struct Admitting(AtomicUsize);

    impl Redeemer for Admitting {
        fn egress(&self, _box_id: &str) -> Vec<Authority<String>> {
            github_egress()
        }

        fn redeem(
            &self,
            _box_id: &str,
            _authority: &Authority<String>,
            _request: &RequestAuthority<String>,
            _sealed: &str,
        ) -> Verdict {
            self.0.fetch_add(1, Ordering::SeqCst);
            Verdict::Admit {
                credential: Zeroizing::new(REAL.to_owned()),
                identifier: "github:member".to_owned(),
                mapping: Mapping::ModuleUnmapped,
                renewed: false,
                marker: None,
                cohort_attributed: false,
            }
        }
    }

    struct Setup {
        proxy: Arc<Proxy>,
        root: CertificateDer<'static>,
        resolver: Arc<To>,
    }

    /// A proxy whose upstream names all resolve to `addr`. The host trust
    /// store is `roots` and, wrongly, the interception root too: the proxy
    /// must take it out.
    fn setup(
        roots: RootCertStore,
        addr: SocketAddr,
        audit: Arc<dyn AuditWriter>,
        redeemer: Option<Arc<dyn Redeemer>>,
        ca: Option<(Arc<dyn LeafIssuer>, CertificateDer<'static>)>,
    ) -> Setup {
        let (leaves, root) = ca.unwrap_or_else(interception_ca);
        let mut roots = roots;
        roots.add(root.clone()).unwrap();
        let resolver = Arc::new(To(addr, AtomicUsize::new(0)));
        let mut proxy = Proxy::new(
            Admission::new(&[GITHUB], [("", 0); 0]),
            Arc::clone(&leaves),
            roots,
            resolver.clone(),
            audit,
        )
        .unwrap();
        if let Some(redeemer) = redeemer {
            proxy = proxy.with_redeemer(redeemer);
        }
        Setup {
            proxy: Arc::new(proxy),
            root,
            resolver,
        }
    }

    /// CONNECT to `host:443`. The answer head, and the box's TLS stream
    /// when the answer was `200`.
    async fn tunnel(s: &Setup, host: &str) -> (String, Option<ClientTls<DuplexStream>>) {
        let mut stream = box_connection(&s.proxy);
        stream
            .write_all(
                format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let head = response_head(&mut stream).await;
        if !head.starts_with("HTTP/1.1 200 ") {
            let mut rest = Vec::new();
            let _ = stream.read_to_end(&mut rest).await;
            return (head + &String::from_utf8_lossy(&rest), None);
        }
        let name = ServerName::try_from(host.to_owned()).unwrap();
        let tls = box_tls(&s.root, &[ALPN_HTTP11])
            .connect(name, stream)
            .await
            .unwrap();
        (head, Some(tls))
    }

    async fn ok_answer<S: AsyncRead + Unpin>(tls: &mut S) -> String {
        let head = response_head(tls).await;
        let mut body = [0u8; 2];
        tls.read_exact(&mut body).await.unwrap();
        head + std::str::from_utf8(&body).unwrap()
    }

    /// Authority, decision and marker of each audit record.
    type Records = Vec<(String, Outcome, Option<String>)>;

    /// What `min box audit <box>` reads: decision and marker per record.
    fn audited(dir: &std::path::Path) -> Records {
        LogReader::new(dir)
            .read_new()
            .unwrap()
            .entries
            .into_iter()
            .map(|e| (e.record.upstream, e.record.decision, e.record.marker))
            .collect()
    }

    fn audit_log(dir: &tempfile::TempDir) -> Arc<dyn AuditWriter> {
        Arc::new(Mutex::new(
            AuditLog::open(dir.path().join(segment_name(0))).unwrap(),
        ))
    }

    // BEP-030: a request with no sealed value goes upstream unchanged, and
    // each one is audited: `foreign_credential` when it carries its own.
    #[tokio::test]
    async fn unsealed_request_passes_through_and_is_audited() {
        let ca = UpstreamCa::new();
        let (chain, key) = ca.leaf("api.github.com", false);
        let up = test_upstream(chain, key, Answer::Ok).await;
        let dir = tempfile::tempdir().unwrap();
        let s = setup(
            ca.roots(),
            up.addr,
            audit_log(&dir),
            Some(Arc::new(Declared)),
            None,
        );

        let (head, tls) = tunnel(&s, "api.github.com").await;
        let mut tls = tls.unwrap_or_else(|| panic!("{head}"));
        let own = b"GET /user HTTP/1.1\r\nhost: api.github.com\r\nauthorization: token ghp_boxs_own_token\r\n\r\n";
        tls.write_all(own).await.unwrap();
        assert!(ok_answer(&mut tls).await.starts_with("HTTP/1.1 200 OK"));
        let bare = b"GET /zen HTTP/1.1\r\nhost: api.github.com\r\n\r\n";
        tls.write_all(bare).await.unwrap();
        assert!(ok_answer(&mut tls).await.starts_with("HTTP/1.1 200 OK"));
        drop(tls);

        assert_eq!(
            *up.heads.lock().unwrap(),
            [
                String::from_utf8(own.to_vec()).unwrap(),
                String::from_utf8(bare.to_vec()).unwrap()
            ]
        );
        assert_eq!(
            audited(dir.path()),
            [
                (
                    "api.github.com:443".to_owned(),
                    Outcome::Admit,
                    Some(FOREIGN_CREDENTIAL.to_owned())
                ),
                ("api.github.com:443".to_owned(), Outcome::Admit, None),
            ]
        );
    }

    // Gatehouse §6.10 step 3: an unsealed request to a host the box's
    // declared egress does not list is refused. The default redeemer
    // declares no egress, so a valid upstream gets no application byte.
    #[tokio::test]
    async fn unsealed_request_outside_box_egress_is_refused() {
        let ca = UpstreamCa::new();
        let (chain, key) = ca.leaf("api.github.com", false);
        let up = test_upstream(chain, key, Answer::Ok).await;
        let dir = tempfile::tempdir().unwrap();
        let s = setup(ca.roots(), up.addr, audit_log(&dir), None, None);

        let (head, tls) = tunnel(&s, "api.github.com").await;
        let mut tls = tls.unwrap_or_else(|| panic!("{head}"));
        tls.write_all(b"GET /zen HTTP/1.1\r\nhost: api.github.com\r\n\r\n")
            .await
            .unwrap();
        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), tls.read_to_end(&mut out))
            .await
            .unwrap()
            .ok();
        let answer = String::from_utf8(out).unwrap();
        assert!(answer.starts_with("HTTP/1.1 403 Forbidden"), "{answer}");
        assert!(
            answer.contains("not allowed to reach api.github.com:443"),
            "{answer}"
        );
        drop(tls);

        assert_eq!(up.bytes.load(Ordering::SeqCst), 0);
        assert!(up.heads.lock().unwrap().is_empty());
        assert_eq!(
            audited(dir.path()),
            [(
                "api.github.com:443".to_owned(),
                Outcome::Refuse,
                Some(Check::OutsideDeclaredEgress.marker().to_owned())
            )]
        );
    }

    // BEP-055: an upstream whose chain does not validate against the host
    // trust store is refused before the box sends anything, it receives no
    // byte of a request, and the refusal is audited `upstream_tls_invalid`.
    #[tokio::test]
    async fn upstream_tls_failure_is_refused_and_audited() {
        let trusted = UpstreamCa::new();
        let untrusted = UpstreamCa::new();
        let (chain, key) = untrusted.leaf("api.github.com", false);
        let up = test_upstream(chain, key, Answer::Ok).await;
        let dir = tempfile::tempdir().unwrap();
        let redeemer = Arc::new(Admitting::default());
        let s = setup(
            trusted.roots(),
            up.addr,
            audit_log(&dir),
            Some(redeemer.clone()),
            None,
        );

        let (answer, tls) = tunnel(&s, "api.github.com").await;
        assert!(tls.is_none());
        assert!(answer.starts_with("HTTP/1.1 502 Bad Gateway"), "{answer}");
        assert!(answer.contains("certificate did not validate"), "{answer}");
        assert_eq!(up.bytes.load(Ordering::SeqCst), 0);
        assert_eq!(redeemer.0.load(Ordering::SeqCst), 0);
        assert_eq!(
            audited(dir.path()),
            [(
                "api.github.com:443".to_owned(),
                Outcome::Refuse,
                Some(UPSTREAM_TLS_INVALID.to_owned())
            )]
        );
    }

    // BEP-055: a request to a credentialed host on a plaintext leg is
    // refused, sealed or not, nothing is dialed, and it is audited
    // `upstream_not_tls`.
    #[tokio::test]
    async fn plaintext_request_to_credentialed_host_is_refused() {
        let ca = UpstreamCa::new();
        let (chain, key) = ca.leaf("api.github.com", false);
        let up = test_upstream(chain, key, Answer::Ok).await;
        let dir = tempfile::tempdir().unwrap();
        let redeemer = Arc::new(Admitting::default());
        let s = setup(
            ca.roots(),
            up.addr,
            audit_log(&dir),
            Some(redeemer.clone()),
            None,
        );

        let sealed = sealed_text();
        let requests = [
            format!(
                "GET http://api.github.com/user HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: Bearer {sealed}\r\n\r\n"
            ),
            "GET http://github.com/x HTTP/1.1\r\nHost: github.com\r\n\r\n".to_owned(),
        ];
        for request in requests {
            let mut stream = box_connection(&s.proxy);
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut out = Vec::new();
            tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut out))
                .await
                .unwrap()
                .unwrap();
            let answer = String::from_utf8(out).unwrap();
            assert!(answer.starts_with("HTTP/1.1 403 Forbidden"), "{answer}");
        }
        assert_eq!(s.resolver.1.load(Ordering::SeqCst), 0);
        assert_eq!(redeemer.0.load(Ordering::SeqCst), 0);
        assert_eq!(up.bytes.load(Ordering::SeqCst), 0);
        let marker = Some(UPSTREAM_NOT_TLS.to_owned());
        assert_eq!(
            audited(dir.path()),
            [
                (
                    "api.github.com:80".to_owned(),
                    Outcome::Refuse,
                    marker.clone()
                ),
                ("github.com:80".to_owned(), Outcome::Refuse, marker),
            ]
        );
    }

    // BEP-N01: the box gets the first chunk of a response while the
    // upstream still holds the rest. A proxy that buffered the response
    // would wait for the upstream, which waits for the box: the test then
    // times out.
    #[tokio::test]
    async fn streamed_response_is_not_buffered() {
        let ca = UpstreamCa::new();
        let (chain, key) = ca.leaf("api.github.com", false);
        let release = Arc::new(Notify::new());
        let up = test_upstream(chain, key, Answer::Stream(release.clone())).await;
        let audit: Arc<dyn AuditWriter> = Arc::new(Mutex::new(Vec::<Decision>::new()));
        let s = setup(ca.roots(), up.addr, audit, Some(Arc::new(Declared)), None);

        let (head, tls) = tunnel(&s, "api.github.com").await;
        let mut tls = tls.unwrap_or_else(|| panic!("{head}"));
        tls.write_all(b"GET /stream HTTP/1.1\r\nhost: api.github.com\r\n\r\n")
            .await
            .unwrap();
        let mut seen = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), async {
            while !seen.ends_with(b"5\r\nfirst\r\n") {
                let mut chunk = [0u8; 256];
                let n = tls.read(&mut chunk).await.unwrap();
                assert!(n > 0, "the flow closed before the first chunk");
                seen.extend_from_slice(&chunk[..n]);
            }
        })
        .await
        .expect("the first chunk reached the box before the response completed");
        release.notify_one();
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), tls.read_to_end(&mut rest))
            .await
            .unwrap()
            .ok();
        seen.extend_from_slice(&rest);
        assert!(seen.ends_with(b"4\r\nlast\r\n0\r\n\r\n"), "{seen:?}");
    }

    /// The upstream chains of the property.
    #[derive(Debug, Clone, Copy)]
    enum Chain {
        Valid,
        InterceptionRooted,
        Expired,
        HostnameMismatch,
    }

    fn one_case(chain: Chain, host: &'static str) -> (bool, usize, bool, Records) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let ca = UpstreamCa::new();
            let (leaves, root) = interception_ca();
            let (certs, key) = match chain {
                Chain::Valid => ca.leaf(host, false),
                Chain::Expired => ca.leaf(host, true),
                Chain::HostnameMismatch => ca.leaf("upstream.example.org", false),
                Chain::InterceptionRooted => {
                    let leaf = leaves.issue(host, SystemTime::now()).unwrap();
                    (leaf.chain, leaf.key.to_vec())
                }
            };
            let up = test_upstream(certs, key, Answer::Ok).await;
            let redeemer = Arc::new(Admitting::default());
            let audit = Arc::new(Mutex::new(Vec::<Decision>::new()));
            let s = setup(
                ca.roots(),
                up.addr,
                audit.clone(),
                Some(redeemer.clone()),
                Some((leaves, root)),
            );
            let (_, tls) = tunnel(&s, host).await;
            let tunnelled = tls.is_some();
            if let Some(mut tls) = tls {
                tls.write_all(
                    format!(
                        "GET /user HTTP/1.1\r\nhost: {host}\r\nauthorization: Bearer {}\r\n\r\n",
                        sealed_text()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
                ok_answer(&mut tls).await;
            }
            let substituted = up
                .heads
                .lock()
                .unwrap()
                .iter()
                .any(|h| h.contains(&format!("authorization: Bearer {REAL}")));
            let records = audit
                .lock()
                .unwrap()
                .iter()
                .map(|d| (d.authority.clone(), d.outcome, d.marker.clone()))
                .collect();
            (
                tunnelled,
                redeemer.0.load(Ordering::SeqCst),
                substituted,
                records,
            )
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        /// BEP-055: a request is forwarded on a terminated flow, and a
        /// credential substituted, only when the upstream chain validates
        /// against the host trust store for that authority. A chain under
        /// the interception root, an expired chain and a hostname mismatch
        /// are refused before any forwarding, even with the interception
        /// root in the host store.
        #[test]
        fn prop_upstream_tls_validated_before_substitution(
            chain in prop_oneof![
                Just(Chain::Valid),
                Just(Chain::InterceptionRooted),
                Just(Chain::Expired),
                Just(Chain::HostnameMismatch),
            ],
            host in prop::sample::select(GITHUB.hosts.iter().map(|a| a.host).collect::<Vec<_>>()),
        ) {
            let (tunnelled, redeemed, substituted, records) = one_case(chain, host);
            let authority = format!("{host}:443");
            if matches!(chain, Chain::Valid) {
                prop_assert!(tunnelled);
                prop_assert_eq!(redeemed, 1);
                prop_assert!(substituted);
                prop_assert_eq!(records, vec![(authority, Outcome::Admit, None)]);
            } else {
                prop_assert!(!tunnelled);
                prop_assert_eq!(redeemed, 0);
                prop_assert!(!substituted);
                prop_assert_eq!(
                    records,
                    vec![(authority, Outcome::Refuse, Some(UPSTREAM_TLS_INVALID.to_owned()))]
                );
            }
        }
    }

    /// A redeemer that admits every sealed value, counts its calls, and
    /// declares `egress` for the box.
    struct AdmitsWithin(Vec<Authority<String>>, AtomicUsize);

    impl Redeemer for AdmitsWithin {
        fn egress(&self, _box_id: &str) -> Vec<Authority<String>> {
            self.0.clone()
        }

        fn redeem(
            &self,
            _box_id: &str,
            _authority: &Authority<String>,
            _request: &RequestAuthority<String>,
            _sealed: &str,
        ) -> Verdict {
            self.1.fetch_add(1, Ordering::SeqCst);
            Verdict::Admit {
                credential: Zeroizing::new(REAL.to_owned()),
                identifier: "github:member".to_owned(),
                mapping: Mapping::ModuleUnmapped,
                renewed: false,
                marker: None,
                cohort_attributed: false,
            }
        }
    }

    // BEP-055: only a certificate error says the certificate did not
    // validate. An alert from the upstream is a failed handshake, and both
    // are audited `upstream_tls_invalid`.
    #[test]
    fn only_certificate_errors_are_invalid() {
        let invalid = UpstreamError::from_tls(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        ));
        assert!(matches!(invalid, UpstreamError::Invalid(_)));
        let alert = UpstreamError::from_tls(rustls::Error::AlertReceived(
            rustls::AlertDescription::NoApplicationProtocol,
        ));
        assert!(matches!(alert, UpstreamError::Handshake(_)));
        assert_eq!(invalid.marker(), Some(UPSTREAM_TLS_INVALID));
        assert_eq!(alert.marker(), Some(UPSTREAM_TLS_INVALID));
    }

    // BEP-022, BEP-023: the forwarder checks the declared egress and the
    // Host pin of a sealed request before the redeemer sees it, so a
    // redeemer that admits everything still substitutes nothing outside them.
    #[test]
    fn sealed_request_outside_egress_or_host_is_not_redeemed() {
        let sealed = sealed_text();
        let request = |host: &str| Request {
            method: "GET".into(),
            target: "/".into(),
            headers: vec![
                http::Header {
                    name: "host".into(),
                    value: host.as_bytes().to_vec(),
                },
                http::Header {
                    name: "authorization".into(),
                    value: format!("Bearer {sealed}").into_bytes(),
                },
            ],
            body: http::BodyFraming::None,
        };
        let cases = [
            (
                Vec::new(),
                "api.github.com",
                Err(Check::OutsideDeclaredEgress.marker()),
            ),
            (
                github_egress(),
                "github.com",
                Err(Check::HostMismatch.marker()),
            ),
            (github_egress(), "api.github.com", Ok(())),
        ];
        for (egress, host, expected) in cases {
            let redeemer = Arc::new(AdmitsWithin(egress, AtomicUsize::new(0)));
            let records = Arc::new(Mutex::new(Vec::<Decision>::new()));
            let audit: Arc<dyn AuditWriter> = records.clone();
            let flow = Flow::new(
                "b",
                Authority {
                    host: "api.github.com".to_owned(),
                    port: 443,
                },
                audit,
                redeemer.clone(),
                Validated::unchecked(()).proof(),
            );
            let mut req = request(host);
            assert_eq!(flow.decide(&mut req), expected, "{host}");
            let header = String::from_utf8(req.headers[1].value.clone()).unwrap();
            let records = records.lock().unwrap();
            assert_eq!(records.len(), 1);
            match expected {
                Ok(()) => {
                    assert_eq!(redeemer.1.load(Ordering::SeqCst), 1);
                    assert_eq!(header, format!("Bearer {REAL}"));
                    assert_eq!(records[0].outcome, Outcome::Admit);
                }
                Err(marker) => {
                    assert_eq!(redeemer.1.load(Ordering::SeqCst), 0, "{host}");
                    assert!(header.contains(&sealed), "{header}");
                    assert_eq!(records[0].marker.as_deref(), Some(marker));
                }
            }
        }
    }

    // A credential with a line break or NUL would split the header it goes
    // into, so the decision refuses the request and leaves it unchanged.
    #[test]
    fn credential_with_line_break_is_not_substituted() {
        let sealed = sealed_text();
        for bad in ["ghs_a\r\nx-injected: 1", "ghs_a\nb", "ghs_a\0b"] {
            let mut req = Request {
                method: "GET".into(),
                target: "/".into(),
                headers: vec![http::Header {
                    name: "authorization".into(),
                    value: format!("Bearer {sealed}").into_bytes(),
                }],
                body: http::BodyFraming::None,
            };
            let Carried::Sealed(at) = carried(&req) else {
                panic!("sealed");
            };
            let got = substitute(&mut req, &at, bad, Validated::unchecked(()).proof());
            assert_eq!(got, Err(CREDENTIAL_NOT_HEADER_SAFE), "{bad:?}");
            let header = String::from_utf8(req.headers[0].value.clone()).unwrap();
            assert_eq!(header, format!("Bearer {sealed}"));
        }
    }

    /// A redeemer that admits within `github_egress()`, with a mapped
    /// resource and the credential it holds.
    struct AdmitsWith(&'static str);

    impl Redeemer for AdmitsWith {
        fn egress(&self, _box_id: &str) -> Vec<Authority<String>> {
            github_egress()
        }

        fn redeem(
            &self,
            _box_id: &str,
            _authority: &Authority<String>,
            _request: &RequestAuthority<String>,
            _sealed: &str,
        ) -> Verdict {
            Verdict::Admit {
                credential: Zeroizing::new(self.0.to_owned()),
                identifier: "github:member".to_owned(),
                mapping: Mapping::Mapped {
                    resource: "repo".to_owned(),
                    permission: "read".to_owned(),
                },
                renewed: false,
                marker: None,
                cohort_attributed: false,
            }
        }
    }

    fn decide_with(
        credential: &'static str,
        authorizations: &[String],
    ) -> (Result<(), &'static str>, Request, Vec<Decision>) {
        let records = Arc::new(Mutex::new(Vec::<Decision>::new()));
        let audit: Arc<dyn AuditWriter> = records.clone();
        let flow = Flow::new(
            "b",
            Authority {
                host: "api.github.com".to_owned(),
                port: 443,
            },
            audit,
            Arc::new(AdmitsWith(credential)),
            Validated::unchecked(()).proof(),
        );
        let mut headers = vec![http::Header {
            name: "host".into(),
            value: b"api.github.com".to_vec(),
        }];
        headers.extend(authorizations.iter().map(|value| http::Header {
            name: "authorization".into(),
            value: value.clone().into_bytes(),
        }));
        let mut req = Request {
            method: "GET".into(),
            target: "/".into(),
            headers,
            body: http::BodyFraming::None,
        };
        let got = flow.decide(&mut req);
        let records = records.lock().unwrap().clone();
        (got, req, records)
    }

    // A refusal after the module mapped the request records the identifier
    // and the mapping (Gatehouse §6.10).
    #[test]
    fn unsafe_credential_refusal_records_the_mapping() {
        let sealed = sealed_text();
        let (got, req, records) = decide_with("ghs_a\r\nx: 1", &[format!("Bearer {sealed}")]);
        assert_eq!(got, Err(CREDENTIAL_NOT_HEADER_SAFE));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].outcome, Outcome::Refuse);
        assert_eq!(
            records[0].marker.as_deref(),
            Some(CREDENTIAL_NOT_HEADER_SAFE)
        );
        assert_eq!(records[0].identifier.as_deref(), Some("github:member"));
        assert_eq!(
            records[0].mapping,
            Mapping::Mapped {
                resource: "repo".to_owned(),
                permission: "read".to_owned(),
            }
        );
        let header = String::from_utf8(req.headers[1].value.clone()).unwrap();
        assert_eq!(header, format!("Bearer {sealed}"));
    }

    // A sealed value beside another `Authorization` header is refused in
    // either order, and nothing is substituted.
    #[test]
    fn sealed_beside_other_authorization_is_refused() {
        let sealed = sealed_text();
        let orders = [
            ["token ghp_own".to_owned(), format!("Bearer {sealed}")],
            [format!("Bearer {sealed}"), "token ghp_own".to_owned()],
            [format!("Bearer {sealed}"), format!("Bearer {sealed}")],
        ];
        for order in orders {
            let (got, req, records) = decide_with(REAL, &order);
            assert_eq!(got, Err(MIXED_AUTHORIZATION), "{order:?}");
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].outcome, Outcome::Refuse);
            assert_eq!(records[0].marker.as_deref(), Some(MIXED_AUTHORIZATION));
            for header in &req.headers[1..] {
                let value = String::from_utf8(header.value.clone()).unwrap();
                assert!(!value.contains(REAL), "{value}");
            }
        }
    }

    // A sealed value in another header, such as `x-api-key`, beside the
    // box's own `Authorization` header is mixed, in either order.
    #[test]
    fn sealed_in_other_header_beside_authorization_is_mixed() {
        let sealed = sealed_text();
        let api_key = http::Header {
            name: "x-api-key".into(),
            value: sealed.clone().into_bytes(),
        };
        let own = http::Header {
            name: "authorization".into(),
            value: b"Bearer sk-own".to_vec(),
        };
        let request = |headers: Vec<http::Header>| Request {
            method: "GET".into(),
            target: "/".into(),
            headers,
            body: http::BodyFraming::None,
        };
        assert!(matches!(
            carried(&request(vec![api_key.clone()])),
            Carried::Sealed(_)
        ));
        assert_eq!(
            carried(&request(vec![api_key.clone(), own.clone()])),
            Carried::Mixed
        );
        assert_eq!(carried(&request(vec![own, api_key])), Carried::Mixed);
    }

    // A substitution with no header at its index changes nothing and fails.
    #[test]
    fn substitution_without_its_header_fails() {
        let sealed = sealed_text();
        let mut req = Request {
            method: "GET".into(),
            target: "/".into(),
            headers: vec![http::Header {
                name: "authorization".into(),
                value: format!("Bearer {sealed}").into_bytes(),
            }],
            body: http::BodyFraming::None,
        };
        let Carried::Sealed(at) = carried(&req) else {
            panic!("sealed");
        };
        req.headers.clear();
        let got = substitute(&mut req, &at, REAL, Validated::unchecked(()).proof());
        assert_eq!(got, Err(SEALED_HEADER_MISSING));
        assert!(req.headers.is_empty());
    }

    // The box gets the 403 even when the upstream closes before or as the
    // refusal arrives. `select!` picks a ready branch at random, so the loop
    // takes both paths.
    #[tokio::test]
    async fn refusal_is_answered_after_upstream_closes() {
        for _ in 0..64 {
            let (mut up, mut up_far) = tokio::io::duplex(1024);
            let (mut client, mut client_far) = tokio::io::duplex(4096);
            let (tx, rx) = oneshot::channel();
            tx.send(Refusal {
                marker: Check::Undecryptable.marker(),
                body: "refused".to_owned(),
                after_forwarded: false,
            })
            .unwrap();
            up_far.shutdown().await.unwrap();
            drop(up_far);
            relay_responses(&mut up, &mut client, rx).await;
            drop(client);
            let mut out = String::new();
            client_far.read_to_string(&mut out).await.unwrap();
            assert!(out.starts_with("HTTP/1.1 403 Forbidden"), "{out}");
        }
    }

    #[test]
    fn sealed_value_is_found_in_each_authorization_form() {
        let sealed = sealed_text();
        let request = |value: String| Request {
            method: "GET".into(),
            target: "/".into(),
            headers: vec![http::Header {
                name: "authorization".into(),
                value: value.into_bytes(),
            }],
            body: http::BodyFraming::None,
        };
        let basic = STANDARD.encode(format!("x-access-token:{sealed}"));
        for value in [
            format!("Bearer {sealed}"),
            format!("token {sealed}"),
            sealed.clone(),
            format!("Basic {basic}"),
        ] {
            let mut req = request(value.clone());
            let Carried::Sealed(at) = carried(&req) else {
                panic!("{value}");
            };
            assert_eq!(at.value, sealed);
            substitute(&mut req, &at, REAL, Validated::unchecked(()).proof()).unwrap();
            let out = String::from_utf8(req.headers[0].value.clone()).unwrap();
            assert!(!out.contains(&sealed), "{out}");
        }
        assert_eq!(carried(&request("token ghp_x".into())), Carried::Foreign);
        assert!(!is_sealed("a.b.c"));
    }

    // BEP-069: a caller that waits for a run in flight stops waiting at the
    // wait limit, so a stalled renewal does not hold every request.
    #[test]
    fn a_waiter_stops_waiting_at_the_wait_limit() {
        let flights: SingleFlight<u8> = SingleFlight::with_wait_limit(Duration::from_millis(50));
        let started = std::sync::Barrier::new(2);
        let release = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let leader = scope.spawn(|| {
                flights.run("item", || {
                    started.wait();
                    release.wait();
                    7
                })
            });
            started.wait();
            assert_eq!(flights.run("item", || 9), Ran::TimedOut);
            release.wait();
            assert_eq!(leader.join().unwrap(), Ran::Led(7));
        });
        assert_eq!(flights.run("item", || 9), Ran::Led(9));
    }

    /// A redeemer that admits every sealed value as a store reference to
    /// `keychain:<id>`, in `inject`, within `egress`.
    struct AdmitsStore {
        id: &'static str,
        inject: Inject,
        egress: Vec<Authority<String>>,
    }

    impl Redeemer for AdmitsStore {
        fn egress(&self, _box_id: &str) -> Vec<Authority<String>> {
            self.egress.clone()
        }

        fn redeem(
            &self,
            _box_id: &str,
            _authority: &Authority<String>,
            _request: &RequestAuthority<String>,
            _sealed: &str,
        ) -> Verdict {
            unreachable!("the forwarder asks for the reference")
        }

        fn redeem_reference(
            &self,
            _box_id: &str,
            _authority: &Authority<String>,
            _request: &RequestAuthority<String>,
            _sealed: &str,
            _header: &str,
        ) -> (Redeemed, String) {
            (
                Redeemed::Store(StoreAdmit {
                    store: crate::store::NATIVE_STORE.to_owned(),
                    id: self.id.to_owned(),
                    inject: self.inject.clone(),
                    mapping: Mapping::ModuleUnmapped,
                    marker: None,
                    cohort_attributed: false,
                }),
                String::new(),
            )
        }
    }

    const STORE_HOST: &str = "api.openai.com";
    const STORE_ID: &str = "openai";

    fn store_authority() -> Authority<String> {
        Authority {
            host: STORE_HOST.to_owned(),
            port: 443,
        }
    }

    fn bearer_form() -> Inject {
        Inject::Header {
            name: "Authorization".to_owned(),
            prefix: Some("Bearer ".to_owned()),
        }
    }

    /// The program the store's items trust in these tests.
    fn proxy_program() -> std::path::PathBuf {
        std::path::PathBuf::from("/opt/minimal/bin/bep")
    }

    /// A memory store holding `value` under [`STORE_ID`] for the proxy.
    fn store_with(value: &[u8]) -> Arc<crate::store::MemorySecretStore> {
        use crate::store::SecretStore as _;
        let store = Arc::new(crate::store::MemorySecretStore::default());
        store.set(STORE_ID, value, &proxy_program()).unwrap();
        store
    }

    /// A flow from box `b` to [`STORE_HOST`] whose redeemer admits a store
    /// reference in `inject`, and that reads values from `store`.
    fn store_flow(
        store: &Arc<crate::store::MemorySecretStore>,
        inject: Inject,
        audit: Arc<dyn AuditWriter>,
    ) -> Flow {
        Flow::new(
            "b",
            store_authority(),
            audit,
            Arc::new(AdmitsStore {
                id: STORE_ID,
                inject,
                egress: vec![store_authority()],
            }),
            Validated::unchecked(()).proof(),
        )
        .with_store(Arc::new(crate::store::MemoryReader {
            store: Arc::clone(store),
            app: proxy_program(),
        }))
    }

    /// Sends one request with `sealed_header` carrying the sealed value on
    /// `flow`. Gives what reached the upstream and how the half ended.
    fn send_store(flow: &Flow, sealed_header: &str) -> (String, HalfEnd) {
        let request =
            format!("GET /v1/models HTTP/1.1\r\nHost: {STORE_HOST}\r\n{sealed_header}\r\n\r\n");
        let mut client = std::io::Cursor::new(request.into_bytes());
        let mut upstream = Vec::new();
        let end = forward_requests(flow, &mut client, &mut upstream);
        (String::from_utf8(upstream).unwrap(), end)
    }

    fn refusal(end: &HalfEnd) -> Option<&'static str> {
        match end {
            HalfEnd::Refused(refusal) => Some(refusal.marker),
            HalfEnd::Closed(_) => None,
        }
    }

    fn memory_audit() -> (Arc<Mutex<Vec<Decision>>>, Arc<dyn AuditWriter>) {
        let records = Arc::new(Mutex::new(Vec::<Decision>::new()));
        let audit: Arc<dyn AuditWriter> = records.clone();
        (records, audit)
    }

    // BEP-032: an admitted store reference reaches the rule's upstream with
    // the stored value in the registered header, the sealed value gone, and
    // an audit record naming the store and the identifier, not the value.
    #[test]
    fn store_reference_injects_in_registered_form() {
        let sealed = sealed_text();
        let store = store_with(b"sk-stored-key");
        let (records, audit) = memory_audit();
        let flow = store_flow(&store, bearer_form(), audit);
        let (upstream, end) = send_store(&flow, &format!("Authorization: Bearer {sealed}"));
        assert_eq!(refusal(&end), None, "{end:?}");
        assert!(
            upstream.contains("\r\nauthorization: Bearer sk-stored-key\r\n"),
            "{upstream}"
        );
        assert!(!upstream.contains(&sealed));
        let records = records.lock().unwrap().clone();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].outcome, Outcome::Admit);
        assert_eq!(records[0].identifier.as_deref(), Some("keychain:openai"));
        assert!(!format!("{records:?}").contains("sk-stored-key"));

        // A rule with a header of its own: the sealed value the client sent
        // in that header is found there, and replaced.
        let (_, audit) = memory_audit();
        let x_api_key = Inject::Header {
            name: "x-api-key".to_owned(),
            prefix: None,
        };
        let flow = store_flow(&store, x_api_key, audit);
        let (upstream, end) = send_store(&flow, &format!("x-api-key: {sealed}"));
        assert_eq!(refusal(&end), None, "{end:?}");
        assert!(
            upstream.contains("\r\nx-api-key: sk-stored-key\r\n"),
            "{upstream}"
        );
        assert!(!upstream.contains(&sealed));
        assert!(!upstream.contains("authorization"));

        // A basic_auth rule fills the password and keeps the box's user.
        let (_, audit) = memory_audit();
        let basic = Inject::BasicAuth {
            field: "password".to_owned(),
        };
        let flow = store_flow(&store, basic, audit);
        let pair = STANDARD.encode(format!("me:{sealed}"));
        let (upstream, end) = send_store(&flow, &format!("Authorization: Basic {pair}"));
        assert_eq!(refusal(&end), None, "{end:?}");
        let want = STANDARD.encode("me:sk-stored-key");
        assert!(
            upstream.contains(&format!("\r\nauthorization: Basic {want}\r\n")),
            "{upstream}"
        );

        // A flow with no store to read refuses the reference, and sends
        // nothing upstream.
        let (records, audit) = memory_audit();
        let flow = Flow::new(
            "b",
            store_authority(),
            audit,
            Arc::new(AdmitsStore {
                id: STORE_ID,
                inject: bearer_form(),
                egress: vec![store_authority()],
            }),
            Validated::unchecked(()).proof(),
        );
        let (upstream, end) = send_store(&flow, &format!("Authorization: Bearer {sealed}"));
        assert_eq!(refusal(&end), Some(STORE_ITEM_UNREADABLE));
        assert!(upstream.is_empty());
        if let HalfEnd::Refused(refused) = &end {
            assert!(
                refused.body.contains("not able to read the stored secret"),
                "{}",
                refused.body
            );
        }
        assert_eq!(
            records.lock().unwrap()[0].marker.as_deref(),
            Some(STORE_ITEM_UNREADABLE)
        );
    }

    // BEP-033: each request reads the store once, and the value goes to no
    // file: not to the audit log, and nowhere else under its directory.
    #[test]
    fn store_value_read_per_request_never_written() {
        let sealed = sealed_text();
        let value = "sk-never-on-disk-5150";
        let store = store_with(value.as_bytes());
        let dir = tempfile::tempdir().unwrap();
        let flow = store_flow(&store, bearer_form(), audit_log(&dir));
        assert_eq!(store.reads(), 0);
        for n in 1..=2 {
            let (upstream, end) = send_store(&flow, &format!("Authorization: Bearer {sealed}"));
            assert_eq!(refusal(&end), None, "{end:?}");
            assert!(upstream.contains(value));
            assert_eq!(store.reads(), n, "one read for each request");
        }
        let records = audited(dir.path());
        assert_eq!(records.len(), 2);
        let mut files = 0;
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            files += 1;
            assert!(
                !bytes.windows(value.len()).any(|w| w == value.as_bytes()),
                "the value is in a file"
            );
        }
        assert!(files > 0, "the audit log was written");
    }

    // A store reference in a header its rule does not name is refused, and
    // the store is not read for it.
    #[test]
    fn store_reference_in_unregistered_header_is_refused() {
        let sealed = sealed_text();
        let store = store_with(b"sk-stored-key");
        let user = Inject::BasicAuth {
            field: "user".to_owned(),
        };
        let pair = STANDARD.encode(format!("me:{sealed}"));
        let cases = [
            (bearer_form(), format!("x-api-key: {sealed}")),
            (bearer_form(), format!("Cookie: Bearer {sealed}")),
            (user.clone(), format!("x-api-key: Basic {pair}")),
            // The sealed value is the password, and the rule fills the user.
            (user, format!("Authorization: Basic {pair}")),
        ];
        for (form, header) in cases {
            let (records, audit) = memory_audit();
            let flow = store_flow(&store, form, audit);
            let (upstream, end) = send_store(&flow, &header);
            assert_eq!(refusal(&end), Some(SEALED_HEADER_MISPLACED), "{header}");
            assert!(upstream.is_empty(), "{upstream}");
            let records = records.lock().unwrap().clone();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].outcome, Outcome::Refuse);
            assert_eq!(records[0].marker.as_deref(), Some(SEALED_HEADER_MISPLACED));
        }
        assert_eq!(store.reads(), 0, "no read for a misplaced reference");
    }

    // A sign-in credential goes in `Authorization` only: a sealed value in
    // another header is refused, and the credential goes nowhere.
    #[test]
    fn sign_in_reference_outside_authorization_is_refused() {
        let sealed = sealed_text();
        let (records, audit) = memory_audit();
        let flow = Flow::new(
            "b",
            Authority {
                host: "api.github.com".to_owned(),
                port: 443,
            },
            audit,
            Arc::new(AdmitsWith(REAL)),
            Validated::unchecked(()).proof(),
        );
        let mut req = Request {
            method: "GET".into(),
            target: "/".into(),
            headers: vec![
                http::Header {
                    name: "host".into(),
                    value: b"api.github.com".to_vec(),
                },
                http::Header {
                    name: "cookie".into(),
                    value: format!("Bearer {sealed}").into_bytes(),
                },
            ],
            body: http::BodyFraming::None,
        };
        assert_eq!(flow.decide(&mut req), Err(SEALED_HEADER_MISPLACED));
        let value = String::from_utf8(req.headers[1].value.clone()).unwrap();
        assert_eq!(value, format!("Bearer {sealed}"));
        let records = records.lock().unwrap().clone();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].outcome, Outcome::Refuse);
        assert_eq!(records[0].marker.as_deref(), Some(SEALED_HEADER_MISPLACED));
    }

    // A sign-in value outside `Authorization` is refused before the
    // redeemer runs, so no sign-in token is renewed for it.
    #[test]
    fn sign_in_reference_outside_authorization_is_not_redeemed() {
        let sealed = sealed_text();
        let (records, audit) = memory_audit();
        let redeemer = Arc::new(Admitting::default());
        let flow = Flow::new(
            "b",
            Authority {
                host: "api.github.com".to_owned(),
                port: 443,
            },
            audit,
            redeemer.clone(),
            Validated::unchecked(()).proof(),
        );
        let mut req = Request {
            method: "GET".into(),
            target: "/".into(),
            headers: vec![
                http::Header {
                    name: "host".into(),
                    value: b"api.github.com".to_vec(),
                },
                http::Header {
                    name: "x-api-key".into(),
                    value: format!("Bearer {sealed}").into_bytes(),
                },
            ],
            body: http::BodyFraming::None,
        };
        assert_eq!(flow.decide(&mut req), Err(SEALED_HEADER_MISPLACED));
        assert_eq!(redeemer.0.load(Ordering::SeqCst), 0, "the redeemer ran");
        let records = records.lock().unwrap().clone();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].marker.as_deref(), Some(SEALED_HEADER_MISPLACED));
    }

    // The forwarder learns which header holds an injected value, so it can
    // zeroize a header of any name, not only `Authorization`.
    #[test]
    fn injected_header_is_named_for_zeroizing() {
        let sealed = sealed_text();
        let store = store_with(b"sk-stored-key");
        let (_, audit) = memory_audit();
        let x_api_key = Inject::Header {
            name: "X-Api-Key".to_owned(),
            prefix: None,
        };
        let flow = store_flow(&store, x_api_key, audit);
        let mut req = Request {
            method: "GET".into(),
            target: "/".into(),
            headers: vec![
                http::Header {
                    name: "host".into(),
                    value: STORE_HOST.as_bytes().to_vec(),
                },
                http::Header {
                    name: "x-api-key".into(),
                    value: sealed.into_bytes(),
                },
            ],
            body: http::BodyFraming::None,
        };
        assert_eq!(
            flow.decide_injected(&mut req),
            Ok(Some("x-api-key".to_owned()))
        );
    }

    // BEP-045: a deleted item refuses the next request that would inject it,
    // and so does an item that no longer lets the proxy read it.
    #[test]
    fn deleted_keychain_item_refuses_next_injection() {
        use crate::store::SecretStore as _;
        let sealed = sealed_text();
        let header = format!("Authorization: Bearer {sealed}");
        let store = store_with(b"sk-stored-key");
        let (records, audit) = memory_audit();
        let flow = store_flow(&store, bearer_form(), audit);
        let (_, end) = send_store(&flow, &header);
        assert_eq!(refusal(&end), None, "{end:?}");

        assert!(store.remove(STORE_ID).unwrap());
        let (upstream, end) = send_store(&flow, &header);
        assert_eq!(refusal(&end), Some(STORE_ITEM_DELETED));
        assert!(upstream.is_empty());
        if let HalfEnd::Refused(refused) = &end {
            assert!(
                refused.body.contains("no longer stored"),
                "{}",
                refused.body
            );
        }

        // An item whose access control no longer names the proxy.
        store
            .set(STORE_ID, b"sk-stored-key", &proxy_program())
            .unwrap();
        store.set_trusted(STORE_ID, Vec::new());
        let (upstream, end) = send_store(&flow, &header);
        assert_eq!(refusal(&end), Some(STORE_ITEM_DISABLED));
        assert!(upstream.is_empty());

        let records = records.lock().unwrap().clone();
        assert_eq!(records.len(), 3);
        assert_eq!(records[1].outcome, Outcome::Refuse);
        assert_eq!(records[1].marker.as_deref(), Some(STORE_ITEM_DELETED));
        assert_eq!(records[1].identifier.as_deref(), Some("keychain:openai"));
        assert_eq!(records[2].marker.as_deref(), Some(STORE_ITEM_DISABLED));
    }

    // BEP-054: a replaced item's new value goes in the next request, on the
    // same flow, with nothing restarted.
    #[test]
    fn replaced_secret_is_injected_on_next_request() {
        use crate::store::SecretStore as _;
        let sealed = sealed_text();
        let header = format!("Authorization: Bearer {sealed}");
        let store = store_with(b"sk-old-key");
        let (_, audit) = memory_audit();
        let flow = store_flow(&store, bearer_form(), audit);
        let (upstream, _) = send_store(&flow, &header);
        assert!(upstream.contains("Bearer sk-old-key"), "{upstream}");

        store
            .set(STORE_ID, b"sk-new-key", &proxy_program())
            .unwrap();
        let (upstream, end) = send_store(&flow, &header);
        assert_eq!(refusal(&end), None, "{end:?}");
        assert!(upstream.contains("Bearer sk-new-key"), "{upstream}");
        assert!(!upstream.contains("sk-old-key"));
    }

    // BEP-066: a stored value or a prefix with a line break is refused, and
    // the audit record is marked `injection_invalid`.
    #[test]
    fn crlf_in_value_or_prefix_refuses_injection_and_is_audited() {
        let sealed = sealed_text();
        let header = format!("Authorization: Bearer {sealed}");
        let store = store_with(b"sk-key\r\nx-smuggled: 1");
        let (records, audit) = memory_audit();
        let flow = store_flow(&store, bearer_form(), audit);
        let (upstream, end) = send_store(&flow, &header);
        assert_eq!(refusal(&end), Some(INJECTION_INVALID));
        assert!(upstream.is_empty());

        let store = store_with(b"sk-key");
        let prefix = Inject::Header {
            name: "authorization".to_owned(),
            prefix: Some("Bearer\n".to_owned()),
        };
        let flow = store_flow(&store, prefix, Arc::clone(&records) as Arc<dyn AuditWriter>);
        let (upstream, end) = send_store(&flow, &header);
        assert_eq!(refusal(&end), Some(INJECTION_INVALID));
        assert!(upstream.is_empty());
        // The text holds for each cause the marker covers, not a line
        // break alone.
        let body = flow.refusal_body(INJECTION_INVALID);
        assert!(
            body.ends_with("because the stored secret and the form that its secret store rule sets do not make a valid request header."),
            "{body}"
        );
        assert!(!body.contains("line break"));

        let records = records.lock().unwrap().clone();
        assert_eq!(records.len(), 2);
        for record in &records {
            assert_eq!(record.outcome, Outcome::Refuse);
            assert_eq!(record.marker.as_deref(), Some(INJECTION_INVALID));
            assert_eq!(record.identifier.as_deref(), Some("keychain:openai"));
        }
    }

    // BEP-045: a sign-in reference that names an instance the held sign-in
    // item does not carry is refused, and nothing goes upstream. The same
    // reference is redeemed while its own sign-in is held.
    #[test]
    fn reference_to_another_sign_in_instance_is_refused() {
        use p256::ecdsa::SigningKey;

        use crate::boxes::{BoxRegistry, Boxes, Stance};
        use crate::handle::{Claims, ClientKeys};
        use crate::keys::memory::MemoryStore;
        use crate::keys::{HeldKey as _, KeyStore as _, Role};
        use crate::redeemer::{BoxRedeemer, SIGN_IN_REQUIRED};
        use crate::seal::{Breadth, Context, Member, MemberKind, MemberList, Mode};
        use crate::signin::{
            Flow as SignInFlow, Keychain as _, Material, MemoryKeychain, Metadata,
        };

        const NOW: u64 = 1_800_000_000;
        const NODE: &str = "node-1";
        const MINTED: &str = "0123456789abcdef0123456789abcdef";
        const TOKEN: &str = "ghu_the_real_token";

        let hold = |keychain: &MemoryKeychain, instance: &str| {
            keychain
                .write(
                    &Metadata {
                        account: "octocat".into(),
                        instance: instance.into(),
                        flow: SignInFlow::Device,
                        token_expires_at: NOW + 3600,
                        refresh_expires_at: NOW + 7200,
                    },
                    &Material {
                        instance: instance.into(),
                        access_token: TOKEN.into(),
                        refresh_token: "ghr_refresh".into(),
                    },
                )
                .unwrap();
        };

        let key = MemoryStore::default().generate(Role::Sealing).unwrap();
        let sealing = key.public();
        let client = SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
        let mut keys = ClientKeys::new();
        keys.register(&client.verifying_key().to_sec1_bytes())
            .unwrap();
        let boxes: BoxRegistry = Arc::new(Boxes::new());
        let api = Authority {
            host: "api.github.com".to_owned(),
            port: 443,
        };
        boxes.register("b1", vec![api.clone()], Stance::OwnIp);
        let keychain = Arc::new(MemoryKeychain::default());
        hold(&keychain, MINTED);
        let redeemer = BoxRedeemer::new(
            key,
            NODE,
            GITHUB,
            Arc::new(std::sync::RwLock::new(keys)),
            boxes,
            Arc::clone(&keychain),
        )
        .with_clock(Arc::new(|| NOW));

        let jws = crate::handle::sign(
            &client,
            &Claims {
                sub: "b1".into(),
                node_id: NODE.into(),
                store: GITHUB.id.into(),
                id: MINTED.into(),
                upstream: GITHUB.hosts.iter().map(|a| a.host.to_owned()).collect(),
                inject: None,
                iat: NOW - 10,
                exp: NOW + 3600,
                jti: "jti-1".into(),
            },
        );
        let sealed = seal::seal(
            &sealing,
            &Context {
                box_id: "b1".into(),
                host: NODE.into(),
                module: GITHUB.id.into(),
                host_set_version: GITHUB.host_set_version,
                mode: Mode::User,
                iat: NOW - 10,
                expiry: NOW + 600,
                kid: sealing.kid(),
            },
            &MemberList {
                members: vec![Member {
                    kind: MemberKind::SignIn,
                    breadth: Breadth::Full,
                    jws: Zeroizing::new(jws),
                    exp: None,
                }],
                default_owner: None,
            },
        )
        .unwrap();

        let (records, audit) = memory_audit();
        let flow = Flow::new(
            "b1",
            api,
            audit,
            Arc::new(redeemer),
            Validated::unchecked(()).proof(),
        );
        let send = || {
            let request = format!(
                "GET /user HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: Bearer {sealed}\r\n\r\n"
            );
            let mut client = std::io::Cursor::new(request.into_bytes());
            let mut upstream = Vec::new();
            let end = forward_requests(&flow, &mut client, &mut upstream);
            (String::from_utf8(upstream).unwrap(), end)
        };

        let (upstream, end) = send();
        assert_eq!(refusal(&end), None, "{end:?}");
        assert!(upstream.contains(TOKEN));

        // A sign-in after a logout is a new instance. The reference minted
        // before it names the old one, and is refused.
        keychain.clear();
        hold(&keychain, "fedcba9876543210fedcba9876543210");
        let (upstream, end) = send();
        assert_eq!(refusal(&end), Some(SIGN_IN_REQUIRED));
        assert!(upstream.is_empty());
        let records = records.lock().unwrap().clone();
        assert_eq!(records.last().unwrap().outcome, Outcome::Refuse);
        assert_eq!(
            records.last().unwrap().marker.as_deref(),
            Some(SIGN_IN_REQUIRED)
        );
    }
}
