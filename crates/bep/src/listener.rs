//! The redemption listener: the shell around the pure decision that accepts a
//! box's connections, terminates TLS for the declared credentialed hosts,
//! decides each request and forwards it on a validated upstream leg.
//!
//! A connection is served only when its source address is a box attachment on
//! this host; anything else is closed at the listener before a byte is read
//! (BEP-026). On the plain leg a box sends either a `CONNECT`, which opens a
//! terminated flow under a leaf for the named host, or an absolute-form
//! request, which `HTTP_PROXY` sends for a plain fetch. A `CONNECT` or a
//! target naming an authority outside the union of the modules' host sets and
//! the registered store authorities is refused `off_module` (BEP-029); a
//! credentialed host that would be reached in plaintext is refused
//! `upstream_not_tls` (BEP-055); a credentialed hostname on a port the module
//! does not declare is refused as the port check names it (BEP-031).
//!
//! Inside a terminated flow the listener establishes the facts the decision
//! reads, interning every authority, box and module as the small ids of
//! [`redeem`], and calls [`redeem::decide`]. A request carrying no sealed
//! value is forwarded as sent once the connection and request checks pass,
//! marked `foreign_credential` when it carries a credential of its own
//! (BEP-030). A request carrying a sealed value is forwarded with the member's
//! credential in the value's place when every check passes (BEP-025). A
//! member that is a store handle is verified under the client keys registered
//! over the control socket and checked against the rule currently registered
//! for its store and identifier (BEP-064); admitted, the referenced value is
//! read from the store and put on the wire in the rule's registered form,
//! exactly (BEP-032, BEP-065), or not at all when the value or the prefix
//! would break the header line (BEP-066). Either way the upstream leg is
//! opened and validated against the host's trust store first, and nothing is
//! forwarded, and no credential substituted, before it is (BEP-055). Every
//! decision appends one audit record (BEP-039).
//!
//! The listener also holds the revocations in force ([`Revocations`]) and
//! reads them for every value it unseals, so a box's removal or a logout
//! refuses what it covers from the next request on (BEP-043, BEP-044).
//! [`Proxy::submit`] is the intake behind the control socket that carries
//! them.

use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{
    AUTHORIZATION, CONTENT_TYPE, HOST, HeaderMap, HeaderName, HeaderValue, PROXY_AUTHORIZATION,
};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::Instrument as _;

use crate::attribution;
use crate::audit::{self, AuditError, Event, Kind, Log, Mapping, Record};
use crate::ca::{Authority, Leaf};
use crate::control::{
    self, ClientKey, ClientKeys, ControlError, Registered, Revocations, Submission,
};
use crate::keychain::{self, KeyStore, SecretItems};
use crate::keys::Keys;
use crate::mint::{self, Inject, StoreClaims};
use crate::redeem::{
    self, Attribution, AuthorityId, BasicField, BoxId, Breadth, Check, Egress, Endpoint, HostId,
    HostSet, InjectId, Mode, ModuleId, Redemption, SealedMember, StoreHandle, StoreRule,
};
use crate::seal::{self, Member, PREFIX, SealedContext};
use crate::upstream::{self, Resolver, Trust, Validated};

/// The audit marker for a request naming an authority outside the union of
/// the modules' host sets and the store authorities (BEP-029).
pub const OFF_MODULE: &str = "off_module";

/// The audit marker for an unsealed request that carries a credential of the
/// box's own (BEP-030).
pub const FOREIGN_CREDENTIAL: &str = "foreign_credential";

/// The audit marker for a store value the registered form cannot carry: the
/// value or the registered prefix breaks the header line (BEP-066), or the
/// form names no header the value can be written to and no field it can
/// fill.
pub const INJECTION_INVALID: &str = "injection_invalid";

/// The audit marker for an admitted store handle whose value the store no
/// longer holds, or would not hand over.
pub const STORE_VALUE_MISSING: &str = "store_value_missing";

/// The most authorities the decision's interned ids can name.
pub const MAX_AUTHORITIES: usize = 255;

/// The id an authority this host does not know interns as in a store
/// handle's or a rule's `upstream`: past every known authority, so in no
/// known set. A handle naming one is within no rule that does not name it
/// too (BEP-064); two such authorities are not told apart, and neither is
/// reachable through this proxy.
const UNKNOWN_AUTHORITY: AuthorityId = AuthorityId(u8::MAX);

/// The sending box, as the decision sees it.
const SENDER: BoxId = BoxId(0);

/// A box other than the sending one, as the decision sees it.
const OTHER_BOX: BoxId = BoxId(1);

/// A module's declared host set, as the proxy is configured with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Module {
    /// The module identifier (`github`).
    pub id: String,
    /// The module's current host set: `host:port` authorities.
    pub host_set: Vec<String>,
    /// The host set's version: the one a member minted now binds to.
    pub version: u32,
}

/// How a box is addressed on the host's network (BEP-020, BEP-028).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Addressing {
    /// The box has an address of its own.
    OwnIp,
    /// The box shares the host's address with its cohort.
    HostIp,
}

/// The box a connection is attributed to: what the listener learns from a
/// source address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sender {
    /// The box.
    #[serde(rename = "box")]
    pub box_id: String,
    /// How the box is addressed.
    pub addressing: Addressing,
    /// The hostnames the box's `egress.allow_dns_hosts` admits, or `None` for
    /// a box that declares no host allow-list and so admits every authority
    /// this host knows (BEP-022).
    #[serde(default)]
    pub egress: Option<Vec<String>>,
}

impl Sender {
    /// Whether the box's declared egress admits `host`.
    fn admits(&self, host: &str) -> bool {
        self.egress.as_ref().is_none_or(|hosts| {
            hosts
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(host))
        })
    }
}

/// The box attachments on this host, looked up by a connection's source
/// address: `None` for a source that is no box's (BEP-026).
pub type Attachments = Arc<dyn Fn(SocketAddr) -> Option<Sender> + Send + Sync>;

/// A `[secret-store-rules]` rule as the proxy holds it: the current form of
/// what a store handle was minted from, which the handle is checked against
/// on every request (BEP-032, BEP-064).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredRule {
    /// The store holding the value (`keychain`).
    pub store: String,
    /// The identifier the rule registers.
    pub id: String,
    /// The authorities the value may be injected into, each `host` or
    /// `host:port`, port 443 when none is written.
    pub upstream: Vec<String>,
    /// How the value is put on the wire.
    pub inject: Inject,
}

/// The rules in force on this host, looked up by store and identifier:
/// `None` for a reference no rule registers. Read per request, never cached,
/// so a rule edited since a handle was minted bites the next request that
/// carries the handle (BEP-064).
pub type StoreRules = Arc<dyn Fn(&str, &str) -> Option<RegisteredRule> + Send + Sync>;

/// The store the proxy reads a referenced value from, once per request it
/// injects the value into (BEP-032).
pub type Secrets = Arc<dyn SecretItems + Send + Sync>;

/// How the listener is configured.
pub struct Config {
    /// The configured modules and their host sets.
    pub modules: Vec<Module>,
    /// The registered store authorities, `host:port` (BEP-029).
    pub store_authorities: Vec<String>,
    /// The `[secret-store-rules]` in force, by store and identifier.
    pub store_rules: StoreRules,
    /// The store referenced values are read from.
    pub secrets: Secrets,
    /// The box attachments on this host.
    pub attachments: Attachments,
    /// The host's trust store, for the upstream leg.
    pub trust: Trust,
    /// Where an upstream authority is reached.
    pub resolver: Resolver,
}

/// Why the listener could not be configured.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ListenerError {
    /// A configured authority is not a `host:port` pair.
    #[error("{authority} is not a host:port authority")]
    Authority { authority: String },
    /// More authorities are declared than the decision's ids can name.
    #[error("{declared} authorities are declared; the decision interns at most 255")]
    TooManyAuthorities { declared: usize },
    /// The revocations already in force could not be read back from the log.
    /// A proxy that cannot tell what is revoked must not start redeeming.
    #[error(transparent)]
    Audit(#[from] AuditError),
}

/// A `host:port` the proxy knows: one of the union of the modules' host sets
/// and the store authorities.
#[derive(Debug, Clone)]
struct Known {
    authority: String,
    host: String,
    port: u16,
}

/// One terminated flow: the box it came from and the connection authority.
struct Flow {
    sender: Sender,
    known: Known,
    id: AuthorityId,
    /// The index of the module whose host set holds the authority, or `None`
    /// for a store authority.
    module: Option<usize>,
}

/// What a sealed value presented on a flow unseals to: the member as the
/// decision sees it, the store handle it is when it is one, what goes on
/// the wire in the value's place, the identifier the audit record names it
/// by, and the revocations in force that cover it.
struct Redeemed {
    member: SealedMember,
    /// The handle's facts, when the member is a store handle (BEP-064).
    store: Option<StoreHandle>,
    credential: Credential,
    id: String,
    revocations: Vec<redeem::Revocation>,
}

/// What goes on the wire in a sealed value's place once the decision admits
/// it.
enum Credential {
    /// A module member's credential, in the place the sealed value sat
    /// (BEP-025).
    Member(Member),
    /// A store value, read from the store at injection and put on the wire in
    /// the registered form (BEP-032, BEP-065).
    Store { id: String, inject: Inject },
}

/// What a request's headers carry.
enum Carried {
    /// No credential at all.
    Nothing,
    /// A credential of the box's own in `Authorization` (BEP-030).
    Foreign,
    /// A sealed value, in the place it sits.
    Sealed { value: String, place: Place },
}

/// Where a sealed value sits in a request's headers.
enum Place {
    /// The whole value of `header`: how a store handle rides in the header
    /// its rule names (BEP-032).
    Whole(HeaderName),
    /// `<scheme> <value>` in `header`: `Bearer` or `token`.
    Scheme { header: HeaderName, scheme: String },
    /// `Authorization: Basic` with the value as `field`, and the other field
    /// as the box sent it.
    Basic { field: BasicField, other: String },
}

/// One header put in a sealed value's place: `value` as the whole of
/// `name`, with `carrying`, the header the sealed value sat in, removed
/// first — the same header for a module member, and for a store handle
/// whatever header the box sent it in.
struct Substitution {
    carrying: HeaderName,
    name: HeaderName,
    value: HeaderValue,
}

impl Carried {
    /// What `headers` carry: `Authorization` is read first, as a module
    /// member's place and the box's own credential's; a sealed value in any
    /// other header is a store handle in the header its rule names.
    fn in_headers(headers: &HeaderMap) -> Self {
        let carried = headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map_or(Self::Nothing, Self::in_authorization);
        if carried.sealed().is_some() {
            return carried;
        }
        headers
            .iter()
            .filter(|(name, _)| **name != AUTHORIZATION)
            .find_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .and_then(|value| Self::in_header(name, value))
            })
            .unwrap_or(carried)
    }

    /// What an `Authorization` value carries: a sealed value as its whole
    /// value, under a scheme, or as one field of a `Basic` credential; else
    /// a credential of the box's own.
    fn in_authorization(value: &str) -> Self {
        let value = value.trim();
        if value.starts_with(PREFIX) {
            return Self::Sealed {
                value: value.to_owned(),
                place: Place::Whole(AUTHORIZATION),
            };
        }
        let Some((scheme, param)) = value.split_once(' ') else {
            return Self::Foreign;
        };
        let param = param.trim();
        if scheme.eq_ignore_ascii_case("basic") {
            return match basic_credentials(param) {
                Some((user, password)) if password.starts_with(PREFIX) => Self::Sealed {
                    value: password,
                    place: Place::Basic {
                        field: BasicField::Password,
                        other: user,
                    },
                },
                Some((user, password)) if user.starts_with(PREFIX) => Self::Sealed {
                    value: user,
                    place: Place::Basic {
                        field: BasicField::User,
                        other: password,
                    },
                },
                _ => Self::Foreign,
            };
        }
        if param.starts_with(PREFIX) {
            return Self::Sealed {
                value: param.to_owned(),
                place: Place::Scheme {
                    header: AUTHORIZATION,
                    scheme: scheme.to_owned(),
                },
            };
        }
        Self::Foreign
    }

    /// The sealed value `value` of the header `name` carries as its whole
    /// value or under a scheme, or `None` when it carries none.
    fn in_header(name: &HeaderName, value: &str) -> Option<Self> {
        let value = value.trim();
        if value.starts_with(PREFIX) {
            return Some(Self::Sealed {
                value: value.to_owned(),
                place: Place::Whole(name.clone()),
            });
        }
        let (scheme, param) = value.split_once(' ')?;
        let param = param.trim();
        param.starts_with(PREFIX).then(|| Self::Sealed {
            value: param.to_owned(),
            place: Place::Scheme {
                header: name.clone(),
                scheme: scheme.to_owned(),
            },
        })
    }

    /// The sealed value, when one is carried.
    fn sealed(&self) -> Option<&str> {
        match self {
            Self::Sealed { value, .. } => Some(value),
            Self::Nothing | Self::Foreign => None,
        }
    }

    /// The header the sealed value sits in, when one is carried.
    fn header(&self) -> Option<HeaderName> {
        match self {
            Self::Sealed {
                place: Place::Whole(header) | Place::Scheme { header, .. },
                ..
            } => Some(header.clone()),
            Self::Sealed {
                place: Place::Basic { .. },
                ..
            } => Some(AUTHORIZATION),
            Self::Nothing | Self::Foreign => None,
        }
    }

    /// The other field of a `Basic` credential the sealed value sits in, as
    /// the box sent it; empty when the value sits anywhere else.
    fn basic_other(&self) -> &str {
        match self {
            Self::Sealed {
                place: Place::Basic { other, .. },
                ..
            } => other,
            _ => "",
        }
    }

    /// The header with the sealed value replaced by `credential`, in the
    /// place the sealed value sat (BEP-025).
    fn substitute(&self, credential: &str) -> Option<Substitution> {
        let (name, text) = match self {
            Self::Sealed {
                place: Place::Whole(header),
                ..
            } => (header.clone(), credential.to_owned()),
            Self::Sealed {
                place: Place::Scheme { header, scheme },
                ..
            } => (header.clone(), format!("{scheme} {credential}")),
            Self::Sealed {
                place: Place::Basic { field, other },
                ..
            } => (
                AUTHORIZATION,
                redeem::store::basic_value(*field, credential, other)?,
            ),
            Self::Nothing | Self::Foreign => return None,
        };
        let value = HeaderValue::from_str(&text).ok()?;
        Some(Substitution {
            carrying: name.clone(),
            name,
            value,
        })
    }
}

/// The user and password of a `Basic` parameter.
fn basic_credentials(param: &str) -> Option<(String, String)> {
    let decoded = String::from_utf8(STANDARD.decode(param).ok()?).ok()?;
    let (user, password) = decoded.split_once(':')?;
    Some((user.to_owned(), password.to_owned()))
}

/// The one body type the listener answers with.
type Body = UnsyncBoxBody<Bytes, hyper::Error>;

/// The listener over one host's keys, interception authority and audit log.
pub struct Proxy<S>
where
    S: KeyStore + 'static,
    S::Key: 'static,
{
    keys: &'static Keys<S>,
    authority: Authority<'static, S::Key>,
    log: Mutex<Log>,
    /// The revocations in force, read for every value unsealed and advanced
    /// by every submission the control socket carries (BEP-043, BEP-044).
    revocations: Mutex<Revocations>,
    modules: Vec<Module>,
    /// The union of the modules' host sets and the store authorities, sorted:
    /// the authorities the decision interns, each at its index (BEP-029).
    known: Vec<Known>,
    /// The distinct hosts of `known`, sorted, each at its index.
    hosts: Vec<String>,
    /// The hosts of the modules' host sets: the credentialed hostnames.
    credentialed: Vec<String>,
    /// Per module, its host set as endpoints and as interned authorities.
    module_sets: Vec<(Vec<Endpoint>, HostSet)>,
    /// The store authorities as endpoints and as interned authorities.
    stores: (Vec<Endpoint>, HostSet),
    /// The client keys registered over the control socket: what a store
    /// handle's signature is verified under (BEP-063, BEP-064).
    client_keys: Mutex<ClientKeys>,
    /// The `[secret-store-rules]` in force, read per request (BEP-064).
    store_rules: StoreRules,
    /// The store referenced values are read from (BEP-032).
    secrets: Secrets,
    attachments: Attachments,
    trust: Trust,
    resolver: Resolver,
}

impl<S> Proxy<S>
where
    S: KeyStore + Send + Sync + 'static,
    S::Key: Send + Sync + 'static,
{
    /// A listener over `keys`, presenting leaves from `authority`, appending
    /// every decision to `log`.
    ///
    /// The revocations already recorded in `log` are read back as the set in
    /// force, so a proxy that restarts still refuses what was revoked before
    /// it did.
    ///
    /// # Errors
    ///
    /// [`ListenerError::Authority`] when a configured authority is not
    /// `host:port`, [`ListenerError::TooManyAuthorities`] when more are
    /// declared than the decision's ids can name, or [`ListenerError::Audit`]
    /// when the log's own revocations cannot be read.
    pub fn new(
        keys: &'static Keys<S>,
        authority: Authority<'static, S::Key>,
        log: Log,
        config: Config,
    ) -> Result<Self, ListenerError> {
        let declared = config
            .modules
            .iter()
            .flat_map(|module| &module.host_set)
            .chain(&config.store_authorities);
        let mut known = Vec::new();
        for text in declared {
            let (host, port) = parse_authority(text).ok_or_else(|| ListenerError::Authority {
                authority: text.clone(),
            })?;
            known.push(Known {
                authority: format!("{host}:{port}"),
                host,
                port,
            });
        }
        known.sort_by(|a, b| a.authority.cmp(&b.authority));
        known.dedup_by(|a, b| a.authority == b.authority);
        if known.len() > MAX_AUTHORITIES {
            return Err(ListenerError::TooManyAuthorities {
                declared: known.len(),
            });
        }
        let mut hosts: Vec<String> = known.iter().map(|entry| entry.host.clone()).collect();
        hosts.sort();
        hosts.dedup();

        let revocations = Revocations::in_log(log.path())?;
        let mut proxy = Self {
            keys,
            authority,
            revocations: Mutex::new(revocations),
            log: Mutex::new(log),
            modules: config.modules,
            known,
            hosts,
            credentialed: Vec::new(),
            module_sets: Vec::new(),
            stores: (Vec::new(), HostSet::default()),
            client_keys: Mutex::new(ClientKeys::new()),
            store_rules: config.store_rules,
            secrets: config.secrets,
            attachments: config.attachments,
            trust: config.trust,
            resolver: config.resolver,
        };
        proxy.module_sets = proxy
            .modules
            .iter()
            .map(|module| proxy.intern_set(&module.host_set))
            .collect();
        proxy.stores = proxy.intern_set(&config.store_authorities);
        proxy.credentialed = proxy
            .module_sets
            .iter()
            .flat_map(|(endpoints, _)| endpoints)
            .map(|endpoint| proxy.hosts[usize::from(endpoint.host.0)].clone())
            .collect();
        proxy.credentialed.sort();
        proxy.credentialed.dedup();
        tracing::info!(
            authorities = proxy.known.len(),
            modules = proxy.modules.len(),
            revoked = !proxy
                .revocations
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_empty(),
            "configured the redemption listener"
        );
        Ok(proxy)
    }

    /// The interned form of `authorities`, every one of which is known.
    fn intern_set(&self, authorities: &[String]) -> (Vec<Endpoint>, HostSet) {
        let known: Vec<&Known> = authorities
            .iter()
            .filter_map(|authority| parse_authority(authority))
            .filter_map(|(host, port)| self.known(&format!("{host}:{port}")))
            .map(|(_, known)| known)
            .collect();
        let endpoints = known.iter().map(|known| self.endpoint(known)).collect();
        let ids = known
            .iter()
            .filter_map(|known| self.authority_id(&known.authority))
            .collect();
        (endpoints, HostSet(ids))
    }

    /// The interned form of a store handle's or a rule's `upstream`, each
    /// `host` or `host:port` with 443 when none is written, as a rule writes
    /// them (BEP-064). An authority this host does not know interns as
    /// [`UNKNOWN_AUTHORITY`] rather than dropping out, so a handle minted
    /// under a rule that has since dropped an authority is not within the
    /// rule now.
    fn intern_authorities(&self, authorities: &[String]) -> HostSet {
        HostSet(
            authorities
                .iter()
                .map(|text| {
                    let (host, port) = split_host(text, 443);
                    self.authority_id(&format!("{host}:{port}"))
                        .unwrap_or(UNKNOWN_AUTHORITY)
                })
                .collect(),
        )
    }

    /// The known authority `authority` names, with its id's index.
    fn known(&self, authority: &str) -> Option<(usize, &Known)> {
        self.known
            .binary_search_by(|known| known.authority.as_str().cmp(authority))
            .ok()
            .map(|index| (index, &self.known[index]))
    }

    /// The id of a known authority; `None` for one this host does not know.
    fn authority_id(&self, authority: &str) -> Option<AuthorityId> {
        self.known(authority)
            .and_then(|(index, _)| u8::try_from(index).ok())
            .map(AuthorityId)
    }

    /// A known authority as the port check reads it.
    fn endpoint(&self, known: &Known) -> Endpoint {
        let host = self
            .hosts
            .binary_search(&known.host)
            .ok()
            .and_then(|index| u8::try_from(index).ok())
            .map_or(HostId(u8::MAX), HostId);
        Endpoint {
            host,
            port: known.port,
        }
    }

    /// Whether `host` is a credentialed hostname: one in a module's host set.
    fn credentialed(&self, host: &str) -> bool {
        self.credentialed
            .binary_search_by(|h| h.as_str().cmp(host))
            .is_ok()
    }

    /// The index of the module whose host set holds `id`.
    fn module_of(&self, id: AuthorityId) -> Option<usize> {
        self.module_sets
            .iter()
            .position(|(_, set)| set.contains(id))
    }

    /// BEP-029 and BEP-055's plaintext clause, over a request target's
    /// authority: a credentialed host that would be reached in plaintext is
    /// refused `upstream_not_tls`; an authority outside the union,
    /// `off_module`.
    fn target_refusal(&self, host: &str, port: u16, plaintext: bool) -> Option<&'static str> {
        if plaintext && self.credentialed(host) {
            return Some(upstream::NOT_TLS);
        }
        if self.known(&format!("{host}:{port}")).is_none() {
            return Some(OFF_MODULE);
        }
        None
    }

    /// Serves `listener` until accepting fails.
    ///
    /// # Errors
    ///
    /// The error accepting a connection failed with.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> io::Result<()> {
        loop {
            let (stream, source) = listener.accept().await?;
            tokio::spawn(Arc::clone(&self).connection(stream, source));
        }
    }

    /// Serves one connection: refused at the listener unless `source` is a
    /// box attachment on this host (BEP-026).
    pub async fn connection(self: Arc<Self>, stream: TcpStream, source: SocketAddr) {
        let Some(sender) = (self.attachments)(source) else {
            tracing::warn!(
                %source,
                "refusing a connection that is not a box attachment on this host"
            );
            return;
        };
        tracing::debug!(%source, box_id = %sender.box_id, "accepted a box connection");
        let proxy = Arc::clone(&self);
        let service = service_fn(move |request| {
            let proxy = Arc::clone(&proxy);
            let sender = sender.clone();
            async move { Ok::<_, Infallible>(proxy.plain(sender, request)) }
        });
        if let Err(error) = http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .with_upgrades()
            .await
        {
            tracing::debug!(%source, %error, "a box connection ended with an error");
        }
    }

    /// A request on the plain leg: a `CONNECT` opens a terminated flow;
    /// anything else arrived outside a tunnel and would ride plaintext
    /// upstream, so it is refused as BEP-029 or BEP-055 names it.
    fn plain(self: Arc<Self>, sender: Sender, request: Request<Incoming>) -> Response<Body> {
        if request.method() == Method::CONNECT {
            return self.tunnel(sender, request);
        }
        let Some((host, port)) = request_authority(&request, 80) else {
            return text(StatusCode::BAD_REQUEST, "the request names no authority");
        };
        let marker = self
            .target_refusal(&host, port, true)
            .unwrap_or(upstream::NOT_TLS);
        self.refuse(&sender.box_id, &format!("{host}:{port}"), None, marker)
    }

    /// A `CONNECT`: on-module, the flow is terminated under a leaf for its
    /// host; otherwise it is refused (BEP-029, BEP-031).
    fn tunnel(self: Arc<Self>, sender: Sender, request: Request<Incoming>) -> Response<Body> {
        let Some((host, port)) = request_authority(&request, 443) else {
            return text(StatusCode::BAD_REQUEST, "the CONNECT names no authority");
        };
        let authority = format!("{host}:{port}");
        let Some((index, known)) = self.known(&authority) else {
            let marker = if self.credentialed(&host) {
                Check::OnDeclaredPort.name()
            } else {
                OFF_MODULE
            };
            return self.refuse(&sender.box_id, &authority, None, marker);
        };
        let Ok(leaf) = self
            .authority
            .issue_leaf(&host)
            .inspect_err(|error| tracing::error!(%error, "no leaf for a known authority"))
        else {
            return text(StatusCode::BAD_GATEWAY, "no leaf could be issued");
        };
        let Ok(acceptor) = acceptor(&leaf)
            .inspect_err(|error| tracing::error!(%error, "the leaf makes no TLS configuration"))
        else {
            return text(StatusCode::BAD_GATEWAY, "no TLS configuration for the leaf");
        };
        let Ok(id) = u8::try_from(index).map(AuthorityId) else {
            return text(StatusCode::BAD_GATEWAY, "the authority has no id");
        };
        let flow = Arc::new(Flow {
            sender,
            known: known.clone(),
            id,
            module: self.module_of(id),
        });
        let proxy = Arc::clone(&self);
        tokio::spawn(async move {
            match hyper::upgrade::on(request).await {
                Ok(upgraded) => proxy.terminated(flow, upgraded, &acceptor).await,
                Err(error) => tracing::warn!(%error, "the CONNECT was not upgraded"),
            }
        });
        Response::new(empty())
    }

    /// One terminated flow: the box-side handshake under the leaf, then each
    /// request decided and forwarded.
    async fn terminated(
        self: Arc<Self>,
        flow: Arc<Flow>,
        upgraded: Upgraded,
        acceptor: &TlsAcceptor,
    ) {
        let span = tracing::info_span!(
            "flow",
            box_id = %flow.sender.box_id,
            authority = %flow.known.authority
        );
        async move {
            let tls = match acceptor.accept(TokioIo::new(upgraded)).await {
                Ok(tls) => tls,
                Err(error) => {
                    tracing::warn!(%error, "the box did not complete the TLS handshake");
                    return;
                }
            };
            let proxy = Arc::clone(&self);
            let service = service_fn(move |request| {
                let proxy = Arc::clone(&proxy);
                let flow = Arc::clone(&flow);
                async move { Ok::<_, Infallible>(proxy.forward(&flow, request).await) }
            });
            if let Err(error) = http1::Builder::new()
                .serve_connection(TokioIo::new(tls), service)
                .await
            {
                tracing::debug!(%error, "a terminated flow ended with an error");
            }
        }
        .instrument(span)
        .await;
    }

    /// One request on a terminated flow: decided, then forwarded on a
    /// validated upstream leg with the substitution the decision allows
    /// (BEP-025, BEP-030, BEP-055).
    async fn forward(&self, flow: &Flow, request: Request<Incoming>) -> Response<Body> {
        let box_id = &flow.sender.box_id;
        let authority = &flow.known.authority;
        if let Some((host, port)) = absolute_target(&request) {
            let plaintext = request.uri().scheme_str() == Some("http");
            if let Some(marker) = self.target_refusal(&host, port, plaintext) {
                return self.refuse(box_id, &format!("{host}:{port}"), None, marker);
            }
        }

        let carried = Carried::in_headers(request.headers());
        let redeemed = carried.sealed().and_then(|value| self.unseal(flow, value));
        let credential = redeemed.as_ref().map(|redeemed| redeemed.id.clone());
        let attribution = match flow.sender.addressing {
            Addressing::OwnIp => Attribution::OwnIp(SENDER),
            Addressing::HostIp => Attribution::HostIp(SENDER),
        };
        let attributed = attribution::Kind::of(attribution);
        let redemption = Redemption {
            request: self.facts(flow, &request),
            member: redeemed.as_ref().map(|redeemed| redeemed.member.clone()),
            store: redeemed
                .as_ref()
                .and_then(|redeemed| redeemed.store.clone()),
            attribution,
            authority: flow.id,
            current_set: flow.module.map_or_else(
                || self.stores.1.clone(),
                |module| self.module_sets[module].1.clone(),
            ),
            now: now(),
            // Read for this request, never cached: a revocation submitted a
            // moment ago is in force for this one (BEP-043, BEP-044).
            revocations: redeemed
                .as_ref()
                .map_or_else(Vec::new, |redeemed| redeemed.revocations.clone()),
        };
        let decision = redeem::decide(&redemption);
        tracing::info!(
            ?decision,
            sealed = carried.sealed().is_some(),
            attribution = attributed.map_or("none", attribution::Kind::name),
            "decided a request"
        );
        let substitution = match decision {
            redeem::Decision::Admit => match redeemed.as_ref() {
                Some(redeemed) => match self.substitution(&carried, redeemed) {
                    Ok(substitution) => substitution,
                    Err(marker) => return self.refuse(box_id, authority, credential, marker),
                },
                None => None,
            },
            // No sealed value and every connection and request check passed:
            // the request rides through as sent (BEP-030).
            redeem::Decision::Refuse(Check::Decrypts) if carried.sealed().is_none() => None,
            redeem::Decision::Refuse(check) => {
                return self.refuse(box_id, authority, credential, check.name());
            }
        };

        // BEP-055: the leg validates before the substitution and before any
        // byte of the request is forwarded.
        let validated = match upstream::open(
            &self.trust,
            &self.resolver,
            &flow.known.host,
            flow.known.port,
        )
        .await
        {
            Ok(validated) => validated,
            Err(error) => return self.refuse(box_id, authority, credential, error.marker()),
        };
        let forwarded = rewrite(request, substitution);
        match send(validated, forwarded).await {
            Ok(response) => {
                let marker = match &carried {
                    Carried::Foreign => Some(FOREIGN_CREDENTIAL.to_owned()),
                    // BEP-028: the value was redeemed from a box the source
                    // address names only as one of its cohort, so the record
                    // says the cohort is what the connection was attributed
                    // to.
                    Carried::Sealed { .. } => attributed
                        .and_then(attribution::Kind::marker)
                        .map(str::to_owned),
                    Carried::Nothing => None,
                };
                self.record(&Event {
                    kind: Kind::Decision,
                    box_id: box_id.clone(),
                    authority: authority.clone(),
                    credential,
                    mapping: Mapping::Unmapped,
                    decision: audit::Decision::Admit,
                    marker,
                });
                tracing::info!(status = %response.status(), "forwarded a request");
                response.map(BodyExt::boxed_unsync)
            }
            Err(error) => {
                tracing::warn!(%error, "the upstream did not answer the forwarded request");
                self.refuse(box_id, authority, credential, upstream::UNREACHABLE)
            }
        }
    }

    /// What a sealed value unseals to under this host's key, interned for the
    /// decision; `None` when the value does not unseal here (BEP-019).
    fn unseal(&self, flow: &Flow, value: &str) -> Option<Redeemed> {
        let unsealed = seal::unseal(self.keys, value)
            .inspect_err(|error| {
                tracing::warn!(%error, "a sealed value did not unseal under this host's key");
            })
            .ok()?;
        let context = unsealed.context;
        if context.mode == mint::STORE_MODE {
            return Some(self.unseal_store(flow, &context, &unsealed.member));
        }
        let module = self
            .modules
            .iter()
            .position(|module| module.id == context.module);
        let bound_set = module
            .filter(|&module| self.modules[module].version == context.host_set_version)
            .map_or_else(HostSet::default, |module| {
                self.module_sets[module].1.clone()
            });
        let member = SealedMember {
            box_id: if context.box_id == flow.sender.box_id {
                SENDER
            } else {
                OTHER_BOX
            },
            module: ModuleId(u8::try_from(module.unwrap_or(self.modules.len())).unwrap_or(u8::MAX)),
            bound_set,
            mode: Mode::recognise(&context.mode),
            breadth: Breadth::recognise(&context.breadth),
            expires_at: context.expires_at,
        };
        let id = format!("{}:{}-token", context.module, context.mode);
        let revocations = self.revocations_in_force(&context, &member);
        Some(Redeemed {
            member,
            store: None,
            credential: Credential::Member(unsealed.member),
            id,
            revocations,
        })
    }

    /// What a store handle carried as the member unseals to, interned for the
    /// decision (BEP-064): the signature verified now under the client keys
    /// the proxy holds, the rule currently registered for the handle's store
    /// and identifier looked up now, the handle's `upstream` as the member's
    /// bound set, and the handle's and the rule's injection forms interned as
    /// one id exactly when they are the same form. An envelope in store mode
    /// whose member is no handle verifies under nothing.
    fn unseal_store(&self, flow: &Flow, context: &SealedContext, member: &Member) -> Redeemed {
        let parsed = mint::parse_store_handle(member.expose())
            .inspect_err(|error| {
                tracing::warn!(%error, "a store-mode envelope carries no readable handle");
            })
            .ok();
        let verified = parsed.as_ref().is_some_and(|parsed| {
            self.client_keys
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .holding(&parsed.claims.key)
                .is_some_and(|public| parsed.verifies_under(public))
        });
        let claims = parsed.map_or_else(
            || StoreClaims {
                store: context.module.clone(),
                id: String::new(),
                upstream: Vec::new(),
                inject: Inject::default(),
                exp: 0,
                key: String::new(),
            },
            |parsed| parsed.claims,
        );
        let rule = (self.store_rules)(&claims.store, &claims.id);
        let handle = StoreHandle {
            verified,
            expires_at: claims.exp,
            inject: InjectId(0),
            rule: rule.as_ref().map(|rule| StoreRule {
                upstream: self.intern_authorities(&rule.upstream),
                inject: InjectId(u8::from(rule.inject != claims.inject)),
            }),
        };
        let member = SealedMember {
            box_id: if context.box_id == flow.sender.box_id {
                SENDER
            } else {
                OTHER_BOX
            },
            // A store is no module: the id past every configured one.
            module: ModuleId(u8::try_from(self.modules.len()).unwrap_or(u8::MAX)),
            bound_set: self.intern_authorities(&claims.upstream),
            mode: Mode::recognise(&context.mode),
            breadth: Breadth::recognise(&context.breadth),
            expires_at: context.expires_at,
        };
        tracing::info!(
            store = %claims.store,
            id = %claims.id,
            verified,
            registered = rule.is_some(),
            exp = claims.exp,
            "read a store handle for the decision"
        );
        let revocations = self.revocations_in_force(context, &member);
        Redeemed {
            member,
            store: Some(handle),
            id: format!("{}:{}", claims.store, claims.id),
            credential: Credential::Store {
                id: claims.id,
                inject: claims.inject,
            },
            revocations,
        }
    }

    /// What goes on the wire in the sealed value's place for an admitted
    /// `redeemed`, or the marker the refusal carries when nothing can.
    fn substitution(
        &self,
        carried: &Carried,
        redeemed: &Redeemed,
    ) -> Result<Option<Substitution>, &'static str> {
        match &redeemed.credential {
            Credential::Member(member) => Ok(carried.substitute(member.expose())),
            Credential::Store { id, inject } => self.inject(carried, id, inject).map(Some),
        }
    }

    /// The registered form with the store value `id` in it (BEP-032,
    /// BEP-065): the value is read from the store now, for this request and
    /// only once the decision admitted it, and put on the wire as exactly the
    /// registered prefix then the value in the named header, or as the one
    /// basic-authentication field the rule names. A value or a prefix that
    /// would break the header line is not injected at all (BEP-066).
    fn inject(
        &self,
        carried: &Carried,
        id: &str,
        inject: &Inject,
    ) -> Result<Substitution, &'static str> {
        let Some(value) = keychain::value_for_request(&*self.secrets, id) else {
            tracing::warn!(id, "no store value for an admitted handle");
            return Err(STORE_VALUE_MISSING);
        };
        let carrying = carried.header().ok_or(INJECTION_INVALID)?;
        let (name, text) = match inject {
            Inject {
                header: Some(name),
                prefix,
                basic_auth: None,
            } => {
                let name =
                    HeaderName::from_bytes(name.as_bytes()).map_err(|_| INJECTION_INVALID)?;
                let text =
                    redeem::store::header_value(prefix.as_deref().unwrap_or(""), value.expose())
                        .ok_or(INJECTION_INVALID)?;
                (name, text)
            }
            Inject {
                header: None,
                prefix: None,
                basic_auth: Some(field),
            } => {
                let field = BasicField::recognise(field).ok_or(INJECTION_INVALID)?;
                let text = redeem::store::basic_value(field, value.expose(), carried.basic_other())
                    .ok_or(INJECTION_INVALID)?;
                (AUTHORIZATION, text)
            }
            Inject { .. } => return Err(INJECTION_INVALID),
        };
        let value = HeaderValue::from_str(&text).map_err(|_| INJECTION_INVALID)?;
        tracing::info!(id, header = %name, "injecting a store value in its registered form");
        Ok(Substitution {
            carrying,
            name,
            value,
        })
    }

    /// Registers a client's handle-signing key the control socket carried:
    /// what a store handle's signature is verified under from here on
    /// (BEP-063, BEP-064).
    ///
    /// # Errors
    ///
    /// [`ControlError::InvalidClientKey`] when the registration does not
    /// carry a P-256 point.
    pub fn register_key(&self, key: &ClientKey) -> Result<Registered, ControlError> {
        self.client_keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .register(key)
    }

    /// The revocations in force that cover `context`'s member, in the terms
    /// the decision reads: the set holds the box and module names a sealed
    /// context carries, the decision the ids the shell interned for this
    /// request (BEP-043, BEP-044).
    fn revocations_in_force(
        &self,
        context: &seal::SealedContext,
        member: &SealedMember,
    ) -> Vec<redeem::Revocation> {
        let revoked = self
            .revocations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut in_force = Vec::new();
        if revoked.covers_box(&context.box_id) {
            in_force.push(redeem::Revocation::Box(member.box_id));
        }
        if revoked.covers_module(&context.module) {
            in_force.push(redeem::Revocation::Module(member.module));
        }
        if !in_force.is_empty() {
            tracing::info!(
                box_id = %context.box_id,
                module = %context.module,
                "a revocation covers the value this request carries"
            );
        }
        in_force
    }

    /// Appends one client submission the control socket carried to the log and
    /// puts a revocation it names in force: the proxy is the log's sole
    /// writer, and the set it reads per request is its own (BEP-067, BEP-043,
    /// BEP-044).
    ///
    /// # Errors
    ///
    /// A [`ControlError`]: the submission claims a kind only the proxy
    /// records, or the log refuses the append.
    pub fn submit(&self, submission: &Submission) -> Result<Record, ControlError> {
        let mut log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        let mut revocations = self
            .revocations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        control::submit(&mut log, &mut revocations, submission)
    }

    /// The connection and request facts of `request` on `flow` (BEP-022,
    /// BEP-023, BEP-031).
    fn facts(&self, flow: &Flow, request: &Request<Incoming>) -> redeem::Request {
        let declared = flow
            .module
            .map_or(&self.stores.0, |module| &self.module_sets[module].0)
            .clone();
        let egress = Egress(
            self.known
                .iter()
                .enumerate()
                .filter(|(_, known)| flow.sender.admits(&known.host))
                .filter_map(|(index, _)| u8::try_from(index).ok())
                .map(AuthorityId)
                .collect(),
        );
        let host_header = request
            .headers()
            .get(HOST)
            .and_then(|value| value.to_str().ok())
            .map(|host| split_host(host, 443))
            .and_then(|(host, port)| self.authority_id(&format!("{host}:{port}")));
        let target = match absolute_target(request) {
            Some((host, port)) => self.authority_id(&format!("{host}:{port}")),
            None => Some(flow.id),
        };
        redeem::Request {
            endpoint: self.endpoint(&flow.known),
            declared,
            egress,
            host_header,
            target,
        }
    }

    /// Refuses a request, recording the decision under `marker`.
    fn refuse(
        &self,
        box_id: &str,
        authority: &str,
        credential: Option<String>,
        marker: &str,
    ) -> Response<Body> {
        self.record(&Event {
            kind: Kind::Decision,
            box_id: box_id.to_owned(),
            authority: authority.to_owned(),
            credential,
            mapping: Mapping::Unmapped,
            decision: audit::Decision::Refuse,
            marker: Some(marker.to_owned()),
        });
        tracing::info!(box_id, authority, marker, "refused a request");
        let status = if marker == upstream::INVALID || marker == upstream::UNREACHABLE {
            StatusCode::BAD_GATEWAY
        } else {
            StatusCode::FORBIDDEN
        };
        text(status, format!("refused: {marker}"))
    }

    /// Appends one audit record.
    fn record(&self, event: &Event) {
        let mut log = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        if let Err(error) = log.append(event) {
            tracing::error!(%error, "the audit record could not be appended");
        }
    }
}

/// Sends `request` on `validated`, the response streaming back as the
/// upstream sends it (BEP-N01).
async fn send(
    validated: Validated,
    request: Request<Incoming>,
) -> hyper::Result<Response<Incoming>> {
    let authority = validated.authority().to_owned();
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(validated.into_stream())).await?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%authority, %error, "the upstream connection ended with an error");
        }
    });
    sender.send_request(request).await
}

/// `request` as it is forwarded: origin-form, without the proxy's own
/// headers, with `substitution` in place of the sealed value when there is
/// one and every header else as the box sent it.
fn rewrite(request: Request<Incoming>, substitution: Option<Substitution>) -> Request<Incoming> {
    let (mut parts, body) = request.into_parts();
    let uri = parts
        .uri
        .path_and_query()
        .map_or_else(|| Uri::from_static("/"), |path| Uri::from(path.clone()));
    parts.uri = uri;
    parts.headers.remove(PROXY_AUTHORIZATION);
    parts.headers.remove("proxy-connection");
    parts.extensions.clear();
    if let Some(Substitution {
        carrying,
        name,
        value,
    }) = substitution
    {
        parts.headers.remove(&carrying);
        parts.headers.insert(name, value);
    }
    Request::from_parts(parts, body)
}

/// The TLS configuration presenting `leaf` on a terminated flow.
fn acceptor(leaf: &Leaf) -> Result<TlsAcceptor, rustls::Error> {
    let chain = leaf
        .chain_der()
        .into_iter()
        .map(|der| CertificateDer::from(der.to_vec()))
        .collect();
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf.private_key_der().to_vec()));
    let config = ServerConfig::builder_with_provider(Arc::clone(&*upstream::PROVIDER))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// The authority of an absolute-form or authority-form target, with the
/// scheme's default port when the target names none.
fn absolute_target(request: &Request<Incoming>) -> Option<(String, u16)> {
    let uri = request.uri();
    let authority = uri.authority()?;
    let default_port = if uri.scheme_str() == Some("http") {
        80
    } else {
        443
    };
    Some((
        normalize(authority.host()),
        uri.port_u16().unwrap_or(default_port),
    ))
}

/// The authority a request is for: its absolute-form or authority-form
/// target, or else its `Host` header, with `default_port` when neither names
/// a port.
fn request_authority(request: &Request<Incoming>, default_port: u16) -> Option<(String, u16)> {
    absolute_target(request).or_else(|| {
        let host = request.headers().get(HOST)?.to_str().ok()?;
        Some(split_host(host, default_port))
    })
}

/// A `host[:port]` split, with `default_port` when there is no port.
fn split_host(text: &str, default_port: u16) -> (String, u16) {
    text.rsplit_once(':')
        .and_then(|(host, port)| port.parse().ok().map(|port| (normalize(host), port)))
        .unwrap_or_else(|| (normalize(text), default_port))
}

/// A configured `host:port`, or `None` when it is not one.
fn parse_authority(text: &str) -> Option<(String, u16)> {
    let (host, port) = text.rsplit_once(':')?;
    let host = normalize(host);
    let port = port.trim().parse().ok()?;
    (!host.is_empty()).then_some((host, port))
}

/// The one spelling of a hostname the listener compares.
fn normalize(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// The clock, as seconds since the Unix epoch.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// A response of `status` with a short text body.
fn text(status: StatusCode, text: impl Into<String>) -> Response<Body> {
    let body = Full::new(Bytes::from(text.into()))
        .map_err(|never| match never {})
        .boxed_unsync();
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body)
        .expect("a status and a text body form a response")
}

/// An empty body.
fn empty() -> Body {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed_unsync()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::LazyLock;
    use std::time::Duration;

    use proptest::prelude::*;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, date_time_ymd,
    };
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, RootCertStore};
    use tokio::io::{
        AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _,
    };
    use tokio::net::TcpSocket;
    use tokio::sync::oneshot;
    use tokio_rustls::TlsConnector;
    use tokio_rustls::client::TlsStream;

    use super::*;
    use crate::audit::Record;
    use crate::ca::DeclaredUnion;
    use crate::github::Secret;
    use crate::keychain::{ItemAcl, MemoryKey, MemorySecrets, MemoryStore, PrivateKey as _};
    use crate::redeem::STORE_HANDLE_INVALID;
    use crate::seal::SealedContext;

    /// The v1 GitHub host set.
    const GITHUB: [&str; 4] = [
        "github.com:443",
        "api.github.com:443",
        "uploads.github.com:443",
        "codeload.github.com:443",
    ];

    /// The member a sealed value carries.
    const CREDENTIAL: &str = "gho_16C7e42F292c6912E7710c838347Ae178B4a";

    /// The one store authority the harness registers.
    const STORE_AUTHORITY: &str = "api.anthropic.com:443";

    /// The identifier the harness stores a value under, and its rules name.
    const SECRET_ID: &str = "anthropic-api-key";

    /// The value the store holds under it.
    const SECRET_VALUE: &str = "sk-ant-api03-notreal";

    /// A `[secret-store-rules]` rule for the harness identifier.
    fn rule(upstream: &[&str], inject: Inject) -> RegisteredRule {
        RegisteredRule {
            store: "keychain".to_owned(),
            id: SECRET_ID.to_owned(),
            upstream: upstream.iter().map(|text| (*text).to_owned()).collect(),
            inject,
        }
    }

    /// The kind of chain a fake upstream presents (BEP-055).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Chain {
        /// Issued under the host CA for the authority's host.
        Valid,
        /// Issued under the host CA, but expired.
        Expired,
        /// Issued under the host CA for another host.
        Mismatched,
        /// Issued under the proxy's own interception root.
        Interception,
    }

    /// The one root the host trust store of a test anchors, and its issuer:
    /// not the interception root.
    struct HostCa {
        root: CertificateDer<'static>,
        issuer: Issuer<'static, KeyPair>,
    }

    impl HostCa {
        fn new() -> Self {
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::default();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params
                .distinguished_name
                .push(DnType::CommonName, "test host CA");
            let root = params.self_signed(&key).unwrap().der().clone();
            Self {
                root,
                issuer: Issuer::new(params, key),
            }
        }
    }

    /// A proxy over a fresh host: its keys, an interception authority over
    /// the GitHub set and the store authority, an empty audit log, a host
    /// trust store anchoring the test's host CA, attribution by the test's
    /// own table, one store rule the test puts in force, an in-memory secret
    /// store and a route to wherever the test stands its upstream up.
    struct Harness {
        proxy: Arc<Proxy<MemoryStore>>,
        addr: SocketAddr,
        log_path: PathBuf,
        _dir: tempfile::TempDir,
        attachments: Arc<Mutex<HashMap<SocketAddr, Sender>>>,
        route: Arc<Mutex<Option<SocketAddr>>>,
        rules: Arc<Mutex<Option<RegisteredRule>>>,
        secrets: MemorySecrets,
        host_ca: HostCa,
    }

    impl Harness {
        async fn start() -> Self {
            let keys: &'static Keys<MemoryStore> =
                Box::leak(Box::new(Keys::open(MemoryStore::new()).unwrap()));
            let union = DeclaredUnion::of([
                GITHUB
                    .map(|authority| authority.split(':').next().unwrap())
                    .to_vec(),
                vec![STORE_AUTHORITY.split(':').next().unwrap()],
            ]);
            let authority = Authority::open(keys, union).unwrap();
            let dir = tempfile::tempdir().unwrap();
            let log_path = dir.path().join("audit.jsonl");
            let log = Log::open(&log_path).unwrap();
            let host_ca = HostCa::new();
            let mut roots = RootCertStore::empty();
            roots.add(host_ca.root.clone()).unwrap();
            let attachments = Arc::new(Mutex::new(HashMap::new()));
            let route = Arc::new(Mutex::new(None));
            let rules = Arc::new(Mutex::new(None));
            let secrets = MemorySecrets::new();
            let table = Arc::clone(&attachments);
            let routed = Arc::clone(&route);
            let in_force = Arc::clone(&rules);
            let config = Config {
                modules: vec![Module {
                    id: "github".to_owned(),
                    host_set: GITHUB.map(str::to_owned).to_vec(),
                    version: 1,
                }],
                store_authorities: vec![STORE_AUTHORITY.to_owned()],
                store_rules: Arc::new(move |store: &str, id: &str| {
                    in_force
                        .lock()
                        .unwrap()
                        .clone()
                        .filter(|rule: &RegisteredRule| rule.store == store && rule.id == id)
                }),
                secrets: Arc::new(secrets.clone()),
                attachments: Arc::new(move |source: SocketAddr| {
                    table.lock().unwrap().get(&source).cloned()
                }),
                trust: Trust::new(roots),
                resolver: Arc::new(move |_: &str, _: u16| *routed.lock().unwrap()),
            };
            let proxy = Arc::new(Proxy::new(keys, authority, log, config).unwrap());
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(Arc::clone(&proxy).serve(listener));
            Self {
                proxy,
                addr,
                log_path,
                _dir: dir,
                attachments,
                route,
                rules,
                secrets,
                host_ca,
            }
        }

        /// Puts `rule` in force for the harness identifier, or none.
        fn set_rule(&self, rule: Option<RegisteredRule>) {
            *self.rules.lock().unwrap() = rule;
        }

        /// Stores `value` under the harness identifier, with the entry for
        /// the proxy's process identity, as `min secret set` does.
        fn store(&self, value: &str) {
            self.secrets
                .set(
                    SECRET_ID,
                    &Secret::new(value),
                    &ItemAcl::for_proxy(std::path::Path::new("/usr/local/bin/bep")),
                )
                .unwrap();
        }

        /// A client's handle-signing key, registered with the proxy as the
        /// client does over the control socket.
        fn client(&self) -> MemoryKey {
            let key = mint::client_key(&MemoryStore::new()).unwrap();
            self.proxy
                .register_key(&ClientKey::of(&key.public_key().unwrap()))
                .unwrap();
            key
        }

        /// The envelope the client delivers into `box-a1` for the store
        /// reference: a handle minted at `now` under `client`'s key from the
        /// rule in force, sealed to this host for the box.
        fn store_handle(&self, client: &MemoryKey, now: u64) -> String {
            let rule = self.rules.lock().unwrap().clone().expect("a rule in force");
            mint::mint_store_handle(
                self.proxy.keys,
                client,
                &mint::StoreMintRequest {
                    box_id: "box-a1",
                    host: "mac-1",
                    store: "keychain",
                    id: SECRET_ID,
                    upstream: &rule.upstream,
                    inject: &rule.inject,
                    now,
                },
            )
            .unwrap()
            .value
            .to_string()
        }

        /// Routes every upstream authority to `addr`.
        fn route(&self, addr: SocketAddr) {
            *self.route.lock().unwrap() = Some(addr);
        }

        /// A chain of `kind` for `host`, with its key, as an upstream
        /// presents it.
        fn chain(
            &self,
            host: &str,
            kind: Chain,
        ) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
            if kind == Chain::Interception {
                let leaf = self.proxy.authority.issue_leaf(host).unwrap();
                let chain = leaf
                    .chain_der()
                    .into_iter()
                    .map(|der| CertificateDer::from(der.to_vec()))
                    .collect();
                let key = PrivatePkcs8KeyDer::from(leaf.private_key_der().to_vec());
                return (chain, PrivateKeyDer::from(key));
            }
            let key = KeyPair::generate().unwrap();
            let name = if kind == Chain::Mismatched {
                "other.example"
            } else {
                host
            };
            let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
            if kind == Chain::Expired {
                params.not_before = date_time_ymd(2020, 1, 1);
                params.not_after = date_time_ymd(2021, 1, 1);
            }
            let cert = params.signed_by(&key, &self.host_ca.issuer).unwrap();
            (
                vec![cert.der().clone(), self.host_ca.root.clone()],
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
        }

        /// A value sealed under this host's keys for `box-a1`.
        fn sealed_value(&self) -> String {
            self.sealed_for("box-a1")
        }

        /// A value sealed under this host's keys for `box_id`.
        fn sealed_for(&self, box_id: &str) -> String {
            let mut context = context();
            context.box_id = box_id.to_owned();
            seal::seal(self.proxy.keys, &context, &Member::new(CREDENTIAL))
                .unwrap()
                .to_string()
        }

        /// The audit log's records.
        fn records(&self) -> Vec<Record> {
            std::fs::read_to_string(&self.log_path)
                .unwrap()
                .lines()
                .map(|line| serde_json_lenient::from_str(line).unwrap())
                .collect()
        }

        /// The last audit record.
        fn last(&self) -> Record {
            self.records().pop().expect("an audit record")
        }
    }

    fn context() -> SealedContext {
        SealedContext {
            box_id: "box-a1".to_owned(),
            host: "mac-1".to_owned(),
            module: "github".to_owned(),
            host_set_version: 1,
            mode: "user".to_owned(),
            breadth: "full".to_owned(),
            expires_at: 4_102_444_800,
        }
    }

    fn box_a() -> Sender {
        Sender {
            box_id: "box-a1".to_owned(),
            addressing: Addressing::OwnIp,
            egress: None,
        }
    }

    /// What the fake upstream answers.
    enum Respond {
        /// One whole response.
        Whole(&'static str),
        /// A chunked response held open between its two chunks until the
        /// gate is released.
        Streamed {
            first: &'static str,
            gate: Mutex<Option<oneshot::Receiver<()>>>,
            second: &'static str,
        },
    }

    /// A TLS upstream on loopback presenting one chain, recording every
    /// request head it receives.
    struct Upstream {
        addr: SocketAddr,
        received: Arc<Mutex<Vec<u8>>>,
    }

    impl Upstream {
        async fn serve(
            chain: Vec<CertificateDer<'static>>,
            key: PrivateKeyDer<'static>,
            respond: Respond,
        ) -> Self {
            let config = ServerConfig::builder_with_provider(Arc::clone(&*upstream::PROVIDER))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .unwrap();
            let acceptor = TlsAcceptor::from(Arc::new(config));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let received = Arc::new(Mutex::new(Vec::new()));
            let seen = Arc::clone(&received);
            let respond = Arc::new(respond);
            tokio::spawn(async move {
                loop {
                    let Ok((tcp, _)) = listener.accept().await else {
                        break;
                    };
                    let acceptor = acceptor.clone();
                    let seen = Arc::clone(&seen);
                    let respond = Arc::clone(&respond);
                    tokio::spawn(async move {
                        let Ok(mut tls) = acceptor.accept(tcp).await else {
                            return;
                        };
                        let head = read_head(&mut tls).await;
                        seen.lock().unwrap().extend_from_slice(&head);
                        answer(&mut tls, &respond).await;
                        tls.shutdown().await.ok();
                    });
                }
            });
            Self { addr, received }
        }

        /// Everything the upstream has received so far.
        fn received(&self) -> String {
            String::from_utf8_lossy(&self.received.lock().unwrap()).into_owned()
        }
    }

    /// Writes `respond`'s answer.
    async fn answer<S: AsyncWrite + Unpin>(io: &mut S, respond: &Respond) {
        match respond {
            Respond::Whole(body) => {
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                io.write_all(head.as_bytes()).await.unwrap();
                io.write_all(body.as_bytes()).await.unwrap();
            }
            Respond::Streamed {
                first,
                gate,
                second,
            } => {
                let head = format!(
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{first}\r\n",
                    first.len()
                );
                io.write_all(head.as_bytes()).await.unwrap();
                io.flush().await.unwrap();
                let gate = gate.lock().unwrap().take();
                if let Some(gate) = gate {
                    gate.await.ok();
                }
                let tail = format!("{:x}\r\n{second}\r\n0\r\n\r\n", second.len());
                io.write_all(tail.as_bytes()).await.unwrap();
            }
        }
        io.flush().await.unwrap();
    }

    /// Reads one HTTP head, up to and including its blank line, and nothing
    /// past it.
    async fn read_head<S: AsyncRead + Unpin>(io: &mut S) -> Vec<u8> {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match io.read(&mut byte).await {
                Ok(1) => head.push(byte[0]),
                _ => break,
            }
        }
        head
    }

    /// Reads to the end of the stream; a peer that closed without a TLS
    /// close-notify or reset the connection counts as the end.
    async fn read_all<S: AsyncRead + Unpin>(io: &mut S) -> String {
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            match io.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(n) => bytes.extend_from_slice(&buffer[..n]),
            }
        }
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// A connection to the proxy from `sender`'s box, or from a host shell
    /// when there is none.
    async fn attach(h: &Harness, sender: Option<Sender>) -> TcpStream {
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let source = socket.local_addr().unwrap();
        if let Some(sender) = sender {
            h.attachments.lock().unwrap().insert(source, sender);
        }
        socket.connect(h.addr).await.unwrap()
    }

    /// Opens a tunnel to `authority` through the proxy: the `CONNECT`, then
    /// the box-side handshake under the interception root. `Err` carries the
    /// refusal's status line, or `closed` when the proxy dropped the
    /// connection.
    async fn tunnel(
        h: &Harness,
        mut tcp: TcpStream,
        authority: &str,
    ) -> Result<TlsStream<TcpStream>, String> {
        let connect = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
        tcp.write_all(connect.as_bytes()).await.ok();
        let head = read_head(&mut tcp).await;
        let status = String::from_utf8_lossy(&head)
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned();
        if !status.starts_with("HTTP/1.1 200") {
            return Err(if status.is_empty() {
                "closed".to_owned()
            } else {
                status
            });
        }
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(h.proxy.authority.root_der().to_vec()))
            .unwrap();
        let config = ClientConfig::builder_with_provider(Arc::clone(&*upstream::PROVIDER))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let host = authority.split(':').next().unwrap().to_owned();
        TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from(host).unwrap(), tcp)
            .await
            .map_err(|error| error.to_string())
    }

    /// Writes `request` and reads the whole response.
    async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(io: &mut S, request: &str) -> String {
        io.write_all(request.as_bytes()).await.ok();
        read_all(io).await
    }

    /// A `GET` of `path` at `host` that closes after the response.
    fn get(path: &str, host: &str, authorization: Option<&str>) -> String {
        let authorization =
            authorization.map_or_else(String::new, |value| format!("Authorization: {value}\r\n"));
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n{authorization}Connection: close\r\n\r\n")
    }

    /// BEP-026: a connection whose source is no box attachment on this host
    /// is closed at the listener, whatever it would have sent.
    #[tokio::test]
    async fn host_shell_connection_is_refused() {
        let h = Harness::start().await;

        // A CONNECT from a host shell: closed without an answer.
        let tcp = attach(&h, None).await;
        assert_eq!(
            tunnel(&h, tcp, "api.github.com:443").await.err().as_deref(),
            Some("closed")
        );

        // The same shell with a sealed value in hand: the value is never
        // read, so nothing is decided and nothing recorded.
        let mut tcp = attach(&h, None).await;
        let request = get(
            "/user",
            "api.github.com",
            Some(&format!("token {}", h.sealed_value())),
        );
        assert_eq!(exchange(&mut tcp, &request).await, "");
        assert!(
            h.records().is_empty(),
            "a non-box connection reached a decision"
        );

        // A box on this host is served: the same CONNECT opens a tunnel.
        let tcp = attach(&h, Some(box_a())).await;
        assert!(tunnel(&h, tcp, "api.github.com:443").await.is_ok());
    }

    /// BEP-029: a CONNECT or an absolute-form target naming an authority
    /// outside the union is refused and recorded `off_module`, on the plain
    /// leg and inside a terminated flow alike.
    #[tokio::test]
    async fn request_outside_modules_is_refused_off_module() {
        let h = Harness::start().await;

        let tcp = attach(&h, Some(box_a())).await;
        let refused = tunnel(&h, tcp, "example.com:443").await.unwrap_err();
        assert!(refused.starts_with("HTTP/1.1 403"), "{refused}");
        let record = h.last();
        assert_eq!(record.decision, audit::Decision::Refuse);
        assert_eq!(record.marker, OFF_MODULE);
        assert_eq!(record.sub, "box-a1");
        assert_eq!(record.authority, "example.com:443");
        assert_eq!(record.credential, audit::NONE);

        // As HTTP_PROXY sends a plain fetch: absolute-form, not CONNECT.
        let mut tcp = attach(&h, Some(box_a())).await;
        let response = exchange(
            &mut tcp,
            "GET http://example.com/index.html HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert_eq!(h.last().marker, OFF_MODULE);
        assert_eq!(h.last().authority, "example.com:80");

        // An absolute-form target inside a terminated flow.
        let tcp = attach(&h, Some(box_a())).await;
        let mut tls = tunnel(&h, tcp, "api.github.com:443").await.unwrap();
        let response = exchange(
            &mut tls,
            "GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert_eq!(h.last().marker, OFF_MODULE);
        assert_eq!(h.records().len(), 3);
    }

    /// BEP-030: a request to a credentialed host with no sealed value is
    /// forwarded as sent and recorded, marked `foreign_credential` when it
    /// carries a credential of the box's own; a box whose egress does not
    /// admit the authority is refused (BEP-022).
    #[tokio::test]
    async fn unsealed_request_passes_through_and_is_audited() {
        let h = Harness::start().await;
        let (chain, key) = h.chain("api.github.com", Chain::Valid);
        let up = Upstream::serve(chain, key, Respond::Whole("{\"login\":\"octocat\"}")).await;
        h.route(up.addr);

        let tcp = attach(&h, Some(box_a())).await;
        let mut tls = tunnel(&h, tcp, "api.github.com:443").await.unwrap();
        let response = exchange(&mut tls, &get("/user", "api.github.com", None)).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("{\"login\":\"octocat\"}"), "{response}");
        let received = up.received();
        assert!(received.starts_with("GET /user HTTP/1.1\r\n"), "{received}");
        assert!(
            received
                .to_ascii_lowercase()
                .contains("host: api.github.com"),
            "{received}"
        );
        assert!(
            !received.to_ascii_lowercase().contains("authorization:"),
            "{received}"
        );
        let record = h.last();
        assert_eq!(record.decision, audit::Decision::Admit);
        assert_eq!(record.authority, "api.github.com:443");
        assert_eq!(record.credential, audit::NONE);
        assert_eq!(record.marker, "");
        assert_eq!(record.resource, audit::UNMAPPED);

        let tcp = attach(&h, Some(box_a())).await;
        let mut tls = tunnel(&h, tcp, "api.github.com:443").await.unwrap();
        let response = exchange(
            &mut tls,
            &get("/user", "api.github.com", Some("token ghp_TheBoxesOwn")),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            up.received().contains("token ghp_TheBoxesOwn"),
            "the box's credential was altered"
        );
        let record = h.last();
        assert_eq!(record.decision, audit::Decision::Admit);
        assert_eq!(record.marker, FOREIGN_CREDENTIAL);
        assert_eq!(record.credential, audit::NONE);

        let narrow = Sender {
            egress: Some(vec!["github.com".to_owned()]),
            ..box_a()
        };
        let tcp = attach(&h, Some(narrow)).await;
        let mut tls = tunnel(&h, tcp, "api.github.com:443").await.unwrap();
        let response = exchange(&mut tls, &get("/user", "api.github.com", None)).await;
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert_eq!(h.last().marker, Check::EgressAdmitted.name());
        assert_eq!(h.records().len(), 3);
    }

    /// One request from `box-a1` on a terminated flow to the store authority,
    /// with `headers` in its head, answered with the proxy's whole response.
    async fn store_request(h: &Harness, headers: &str) -> String {
        let tcp = attach(h, Some(box_a())).await;
        let mut tls = tunnel(h, tcp, STORE_AUTHORITY).await.unwrap();
        let request = format!(
            "GET /v1/models HTTP/1.1\r\nHost: api.anthropic.com\r\n{headers}Connection: close\r\n\r\n"
        );
        exchange(&mut tls, &request).await
    }

    /// Sends `headers` to the store authority, expects the proxy to admit the
    /// request, and returns what the upstream received for it alone.
    async fn admitted(h: &Harness, up: &Upstream, headers: &str) -> String {
        let sent = up.received().len();
        let response = store_request(h, headers).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let record = h.last();
        assert_eq!(record.decision, audit::Decision::Admit);
        assert_eq!(record.authority, STORE_AUTHORITY);
        assert_eq!(record.credential, "keychain:anthropic-api-key");
        assert_eq!(record.marker, "");
        up.received()[sent..].to_owned()
    }

    /// Sends `headers` to the store authority and expects the proxy to refuse
    /// the request, recorded `marker` against the reference, with nothing of
    /// it reaching the upstream.
    async fn refused(h: &Harness, up: &Upstream, headers: &str, marker: &str, case: &str) {
        let sent = up.received().len();
        let response = store_request(h, headers).await;
        assert!(response.starts_with("HTTP/1.1 403"), "{case}: {response}");
        let record = h.last();
        assert_eq!(record.decision, audit::Decision::Refuse, "{case}");
        assert_eq!(record.marker, marker, "{case}");
        assert_eq!(record.credential, "keychain:anthropic-api-key", "{case}");
        assert_eq!(record.authority, STORE_AUTHORITY, "{case}");
        assert_eq!(
            up.received().len(),
            sent,
            "{case}: the refused request reached the upstream"
        );
    }

    /// BEP-032, BEP-064 and BEP-065: a request carrying a valid store handle
    /// reaches the rule's registered upstream with exactly the registered
    /// prefix and the stored value as the named header's value — or the
    /// value as the one basic-authentication field the rule names — and
    /// neither the handle nor the envelope goes upstream, nor the value into
    /// the audit log. A handle whose rule has since narrowed, changed its
    /// injection form or gone, one signed under a key the proxy does not
    /// hold, and one past its expiry are each refused `store_handle_invalid`
    /// before anything reaches the upstream; the rule restored, the same
    /// handle is admitted again, because it is the rule in force that
    /// decides.
    #[tokio::test]
    async fn store_reference_injects_in_registered_form() {
        let h = Harness::start().await;
        let (chain, key) = h.chain("api.anthropic.com", Chain::Valid);
        let up = Upstream::serve(chain, key, Respond::Whole("{\"data\":[]}")).await;
        h.route(up.addr);
        h.store(SECRET_VALUE);
        let client = h.client();
        let wide = ["api.anthropic.com:443", "api.openai.com:443"];
        let wide_rule = rule(&wide, Inject::header("x-api-key", ""));

        // The header form with no prefix: the value is the header's whole
        // value, in the header the handle rode in.
        h.set_rule(Some(wide_rule.clone()));
        let handle = h.store_handle(&client, now());
        let received = admitted(&h, &up, &format!("x-api-key: {handle}\r\n")).await;
        assert!(
            received.starts_with("GET /v1/models HTTP/1.1\r\n"),
            "{received}"
        );
        assert!(
            received.contains(&format!("x-api-key: {SECRET_VALUE}\r\n")),
            "{received}"
        );
        assert!(
            !received.contains(PREFIX) && !received.contains(mint::HANDLE_PREFIX),
            "the handle reached the upstream: {received}"
        );
        assert!(
            !std::fs::read_to_string(&h.log_path)
                .unwrap()
                .contains(SECRET_VALUE),
            "the value reached the audit log"
        );

        // The header form with a prefix, in `Authorization`: exactly the
        // prefix then the value, whether the box sent the envelope bare or
        // under a scheme of its own.
        h.set_rule(Some(rule(
            &[STORE_AUTHORITY],
            Inject::header("Authorization", "Bearer "),
        )));
        let sealed = h.store_handle(&client, now());
        for carried in [
            format!("Authorization: {sealed}\r\n"),
            format!("Authorization: Bearer {sealed}\r\n"),
        ] {
            let received = admitted(&h, &up, &carried).await;
            assert!(
                received.contains(&format!("authorization: Bearer {SECRET_VALUE}\r\n")),
                "{received}"
            );
            assert_eq!(received.matches("authorization:").count(), 1, "{received}");
        }

        // The basic form: the value fills the field the rule names, and the
        // other field stays the box's own.
        h.set_rule(Some(rule(
            &[STORE_AUTHORITY],
            Inject::basic_auth("password"),
        )));
        let sealed = h.store_handle(&client, now());
        let basic = STANDARD.encode(format!("octocat:{sealed}"));
        let received = admitted(&h, &up, &format!("Authorization: Basic {basic}\r\n")).await;
        let expected = STANDARD.encode(format!("octocat:{SECRET_VALUE}"));
        assert!(
            received.contains(&format!("authorization: Basic {expected}\r\n")),
            "{received}"
        );

        // BEP-064: the handle minted under the wide rule, against each rule
        // that has since narrowed, changed its form or gone; one signed under
        // a key the proxy never held; one minted past its own lifetime.
        h.set_rule(Some(wide_rule.clone()));
        let stranger = mint::client_key(&MemoryStore::new()).unwrap();
        let unregistered = h.store_handle(&stranger, now());
        let expired = h.store_handle(&client, now() - mint::HANDLE_LIFETIME_SECS - 1);
        let refusals = [
            (
                "narrowed rule",
                Some(rule(&[STORE_AUTHORITY], Inject::header("x-api-key", ""))),
                &handle,
            ),
            (
                "changed form",
                Some(rule(&wide, Inject::header("x-api-key", "Key "))),
                &handle,
            ),
            ("no rule", None, &handle),
            ("unregistered key", Some(wide_rule.clone()), &unregistered),
            ("expired", Some(wide_rule.clone()), &expired),
        ];
        for (case, rule, sealed) in refusals {
            h.set_rule(rule);
            let headers = format!("x-api-key: {sealed}\r\n");
            refused(&h, &up, &headers, STORE_HANDLE_INVALID, case).await;
        }

        // The rule restored, the handle it was minted from is admitted again.
        h.set_rule(Some(wide_rule));
        admitted(&h, &up, &format!("x-api-key: {handle}\r\n")).await;
    }

    /// BEP-066: a store value, or a registered prefix, carrying a carriage
    /// return or a line feed is not injected — in the header form, where it
    /// would end the header and start another, and in the basic form, whose
    /// encoding would hide it: the request is refused `injection_invalid`,
    /// recorded against the reference, and nothing of it reaches the
    /// upstream.
    #[tokio::test]
    async fn crlf_in_value_or_prefix_refuses_injection_and_is_audited() {
        let h = Harness::start().await;
        let (chain, key) = h.chain("api.anthropic.com", Chain::Valid);
        let up = Upstream::serve(chain, key, Respond::Whole("{\"data\":[]}")).await;
        h.route(up.addr);
        let client = h.client();

        let broken = [
            (
                "value",
                "sk-ant\r\nX-Injected: yes",
                Inject::header("x-api-key", ""),
            ),
            (
                "prefix",
                SECRET_VALUE,
                Inject::header("x-api-key", "Key\r\n"),
            ),
            ("basic value", "sk\nant", Inject::basic_auth("password")),
        ];
        for (case, value, inject) in broken {
            h.store(value);
            h.set_rule(Some(rule(&[STORE_AUTHORITY], inject.clone())));
            let sealed = h.store_handle(&client, now());
            let headers = if inject.basic_auth.is_some() {
                format!(
                    "Authorization: Basic {}\r\n",
                    STANDARD.encode(format!("octocat:{sealed}"))
                )
            } else {
                format!("x-api-key: {sealed}\r\n")
            };
            refused(&h, &up, &headers, INJECTION_INVALID, case).await;
        }
        assert!(up.received().is_empty(), "{}", up.received());
        assert_eq!(h.records().len(), 3);

        // The same value and rule, once neither breaks the line, go through.
        h.store(SECRET_VALUE);
        h.set_rule(Some(rule(
            &[STORE_AUTHORITY],
            Inject::header("x-api-key", "Key "),
        )));
        let sealed = h.store_handle(&client, now());
        let received = admitted(&h, &up, &format!("x-api-key: {sealed}\r\n")).await;
        assert!(
            received.contains(&format!("x-api-key: Key {SECRET_VALUE}\r\n")),
            "{received}"
        );
    }

    /// BEP-028: a `host_ip` box shares the host's address with its cohort, so
    /// a value naming a live `host_ip` box of this host is redeemed from any
    /// box of that cohort, and every such admit is recorded
    /// `cohort_attributed` — the cohort, and not one box inside it, is what
    /// the connection was attributed to. The same value sent from a box
    /// addressed on its own is another box's and is refused (BEP-020), and a
    /// box redeeming its own value at an address of its own is marked as
    /// nothing.
    #[tokio::test]
    async fn host_ip_redemption_is_cohort_attributed() {
        let h = Harness::start().await;
        let (chain, key) = h.chain("api.github.com", Chain::Valid);
        let up = Upstream::serve(chain, key, Respond::Whole("{\"login\":\"octocat\"}")).await;
        h.route(up.addr);

        // The value names `box-h1`, which is up and attached as a `host_ip`
        // box of this host: a live box of the cohort, holding its attachment
        // with no request of its own in flight.
        let named = Sender {
            box_id: "box-h1".to_owned(),
            addressing: Addressing::HostIp,
            egress: None,
        };
        h.attachments
            .lock()
            .unwrap()
            .insert("127.0.0.1:1".parse().unwrap(), named.clone());
        let sealed = format!("token {}", h.sealed_for("box-h1"));

        // `box-h2` shares the host's address with it, so the source address
        // names the cohort no further than that: the value is redeemed from
        // the sibling and the member goes upstream in its place.
        let sibling = Sender {
            box_id: "box-h2".to_owned(),
            ..named.clone()
        };
        let tcp = attach(&h, Some(sibling)).await;
        let mut tls = tunnel(&h, tcp, "api.github.com:443").await.unwrap();
        let response = exchange(&mut tls, &get("/user", "api.github.com", Some(&sealed))).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let received = up.received();
        assert!(
            received.contains(&format!("token {CREDENTIAL}")),
            "{received}"
        );
        assert!(!received.contains(PREFIX), "a sealed value was forwarded");
        let record = h.last();
        assert_eq!(record.decision, audit::Decision::Admit);
        assert_eq!(record.marker, attribution::COHORT_ATTRIBUTED);
        assert_eq!(record.sub, "box-h2");
        assert_eq!(record.credential, "github:user-token");

        // A box addressed on its own is told apart from the box the value
        // names, so the value is not its to redeem (BEP-020).
        let own = Sender {
            box_id: "box-c3".to_owned(),
            addressing: Addressing::OwnIp,
            egress: None,
        };
        let tcp = attach(&h, Some(own)).await;
        let mut tls = tunnel(&h, tcp, "api.github.com:443").await.unwrap();
        let response = exchange(&mut tls, &get("/user", "api.github.com", Some(&sealed))).await;
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert_eq!(h.last().marker, Check::Attributed.name());

        // The box the value names, at the address it shares: admitted, and
        // marked the same, because the cohort is all its source address says.
        let tcp = attach(&h, Some(named)).await;
        let mut tls = tunnel(&h, tcp, "api.github.com:443").await.unwrap();
        let response = exchange(&mut tls, &get("/user", "api.github.com", Some(&sealed))).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let record = h.last();
        assert_eq!(record.decision, audit::Decision::Admit);
        assert_eq!(record.marker, attribution::COHORT_ATTRIBUTED);
        assert_eq!(record.sub, "box-h1");

        // A box with an address of its own, redeeming the value that names
        // it: an admit with no cohort marker at all.
        let own_value = format!("token {}", h.sealed_value());
        let tcp = attach(&h, Some(box_a())).await;
        let mut tls = tunnel(&h, tcp, "api.github.com:443").await.unwrap();
        let response = exchange(&mut tls, &get("/user", "api.github.com", Some(&own_value))).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let record = h.last();
        assert_eq!(record.decision, audit::Decision::Admit);
        assert_eq!(record.marker, "");
        assert_eq!(record.sub, "box-a1");
        assert_eq!(h.records().len(), 4);
    }

    /// The runtime the property drives its proxies on.
    static RUNTIME: LazyLock<tokio::runtime::Runtime> =
        LazyLock::new(|| tokio::runtime::Runtime::new().unwrap());

    fn arb_chain() -> impl Strategy<Value = Chain> {
        prop_oneof![
            Just(Chain::Valid),
            Just(Chain::Expired),
            Just(Chain::Mismatched),
            Just(Chain::Interception),
        ]
    }

    proptest! {
        // Each case stands up a proxy and an upstream and runs a flow through
        // them, so the case count stays small.
        #![proptest_config(ProptestConfig::with_cases(24))]

        /// BEP-055: for every upstream chain and every connection authority,
        /// a request is forwarded on a terminated flow, and a credential
        /// substituted, only when the chain validates against the host trust
        /// store for that authority; a chain under the interception root, an
        /// expired chain or a hostname mismatch is refused before anything is
        /// forwarded, whether or not the request carries a sealed value.
        #[test]
        fn prop_upstream_tls_validated_before_substitution(
            chain in arb_chain(),
            authority in prop::sample::select(GITHUB.to_vec()),
            sealed in any::<bool>(),
        ) {
            RUNTIME.block_on(async {
                let h = Harness::start().await;
                let host = authority.split(':').next().unwrap();
                let (certs, key) = h.chain(host, chain);
                let up = Upstream::serve(certs, key, Respond::Whole("ok")).await;
                h.route(up.addr);
                let value = sealed.then(|| format!("token {}", h.sealed_value()));

                let tcp = attach(&h, Some(box_a())).await;
                let mut tls = tunnel(&h, tcp, authority).await.unwrap();
                let response = exchange(&mut tls, &get("/user", host, value.as_deref())).await;
                let received = up.received();
                let record = h.last();
                prop_assert_eq!(record.authority.as_str(), authority);
                if chain == Chain::Valid {
                    prop_assert!(response.starts_with("HTTP/1.1 200"), "{response}");
                    prop_assert!(received.starts_with("GET /user HTTP/1.1"), "{received}");
                    prop_assert_eq!(received.contains(&format!("token {CREDENTIAL}")), sealed);
                    prop_assert!(!received.contains(PREFIX), "a sealed value was forwarded");
                    prop_assert_eq!(record.decision, audit::Decision::Admit);
                } else {
                    prop_assert!(response.starts_with("HTTP/1.1 502"), "{response}");
                    prop_assert!(received.is_empty(), "the upstream received {received}");
                    prop_assert_eq!(record.decision, audit::Decision::Refuse);
                    prop_assert_eq!(record.marker.as_str(), upstream::INVALID);
                }
                Ok::<(), TestCaseError>(())
            })?;
        }
    }

    /// BEP-055: an upstream that does not validate against the host trust
    /// store — here one presenting a chain under the interception root itself
    /// — is refused and recorded `upstream_tls_invalid`, sealed or not, and
    /// receives nothing.
    #[tokio::test]
    async fn upstream_tls_failure_is_refused_and_audited() {
        let h = Harness::start().await;
        let (chain, key) = h.chain("api.github.com", Chain::Interception);
        let up = Upstream::serve(chain, key, Respond::Whole("ok")).await;
        h.route(up.addr);

        let sealed = format!("token {}", h.sealed_value());
        for authorization in [None, Some(sealed.as_str())] {
            let tcp = attach(&h, Some(box_a())).await;
            let mut tls = tunnel(&h, tcp, "api.github.com:443").await.unwrap();
            let response = exchange(&mut tls, &get("/user", "api.github.com", authorization)).await;
            assert!(response.starts_with("HTTP/1.1 502"), "{response}");
            let record = h.last();
            assert_eq!(record.decision, audit::Decision::Refuse);
            assert_eq!(record.marker, upstream::INVALID);
            assert_eq!(record.authority, "api.github.com:443");
            assert_eq!(
                record.credential,
                authorization.map_or(audit::NONE, |_| "github:user-token")
            );
        }
        assert_eq!(
            up.received(),
            "",
            "a request reached an unvalidated upstream"
        );
        assert_eq!(h.records().len(), 2);
    }

    /// BEP-055: a request to a credentialed host that would ride a plaintext
    /// upstream leg — absolute-form `http://` on the plain leg or inside a
    /// terminated flow, sealed or not — is refused and recorded
    /// `upstream_not_tls`, and nothing is forwarded.
    #[tokio::test]
    async fn plaintext_request_to_credentialed_host_is_refused() {
        let h = Harness::start().await;
        let (chain, key) = h.chain("api.github.com", Chain::Valid);
        let up = Upstream::serve(chain, key, Respond::Whole("ok")).await;
        h.route(up.addr);
        let sealed = h.sealed_value();
        let plain = format!(
            "GET http://api.github.com/user HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: token {sealed}\r\nConnection: close\r\n\r\n"
        );

        let mut tcp = attach(&h, Some(box_a())).await;
        let response = exchange(&mut tcp, &plain).await;
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        let record = h.last();
        assert_eq!(record.decision, audit::Decision::Refuse);
        assert_eq!(record.marker, upstream::NOT_TLS);
        assert_eq!(record.authority, "api.github.com:80");

        let tcp = attach(&h, Some(box_a())).await;
        let mut tls = tunnel(&h, tcp, "api.github.com:443").await.unwrap();
        let response = exchange(&mut tls, &plain).await;
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert_eq!(h.last().marker, upstream::NOT_TLS);

        let mut tcp = attach(&h, Some(box_a())).await;
        let response = exchange(
            &mut tcp,
            "GET http://api.github.com/ HTTP/1.1\r\nHost: api.github.com\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert_eq!(h.last().marker, upstream::NOT_TLS);

        assert_eq!(
            up.received(),
            "",
            "a plaintext request reached the upstream"
        );
        assert_eq!(h.records().len(), 3);
    }

    /// BEP-N01: each chunk of an upstream response reaches the box as it
    /// arrives, before the response completes.
    #[tokio::test]
    async fn streamed_response_is_not_buffered() {
        let h = Harness::start().await;
        let (chain, key) = h.chain("api.github.com", Chain::Valid);
        let (open, gate) = oneshot::channel();
        let respond = Respond::Streamed {
            first: "first-chunk",
            gate: Mutex::new(Some(gate)),
            second: "second-chunk",
        };
        let up = Upstream::serve(chain, key, respond).await;
        h.route(up.addr);

        let tcp = attach(&h, Some(box_a())).await;
        let mut tls = tunnel(&h, tcp, "api.github.com:443").await.unwrap();
        tls.write_all(get("/events", "api.github.com", None).as_bytes())
            .await
            .unwrap();

        // The first chunk reaches the box while the upstream still holds the
        // rest of the response behind the gate.
        let mut seen = Vec::new();
        let mut buffer = [0u8; 4096];
        let first = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let n = tls.read(&mut buffer).await.unwrap();
                assert_ne!(n, 0, "the response ended before its first chunk");
                seen.extend_from_slice(&buffer[..n]);
                if String::from_utf8_lossy(&seen).contains("first-chunk") {
                    break;
                }
            }
        })
        .await;
        assert!(
            first.is_ok(),
            "the first chunk was held until the response completed"
        );
        let text = String::from_utf8_lossy(&seen).into_owned();
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert!(!text.contains("second-chunk"), "{text}");

        open.send(()).unwrap();
        let rest = read_all(&mut tls).await;
        assert!(rest.contains("second-chunk"), "{rest}");
        assert_eq!(h.last().decision, audit::Decision::Admit);
    }

    /// Stands the proxy's control socket up at `path`: one JSON-line
    /// submission per connection into the proxy's own intake, the record it
    /// appended — or the refusal — back on the same line.
    ///
    /// The production socket, owned by the operator's user at mode `0600`, is
    /// BEP-063's; the accept loop here is what stands in for it, so a
    /// submission still reaches the proxy over the wire the client speaks.
    fn control_socket(proxy: Arc<Proxy<MemoryStore>>, path: &std::path::Path) {
        let listener = tokio::net::UnixListener::bind(path).unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let proxy = Arc::clone(&proxy);
                tokio::spawn(async move {
                    let (reader, mut writer) = stream.into_split();
                    let mut line = String::new();
                    tokio::io::BufReader::new(reader)
                        .read_line(&mut line)
                        .await
                        .unwrap();
                    let submission: Submission = serde_json_lenient::from_str(&line).unwrap();
                    let reply = match proxy.submit(&submission) {
                        Ok(record) => serde_json_lenient::to_string(&record).unwrap(),
                        Err(error) => format!(r#"{{"error":"{error}"}}"#),
                    };
                    writer
                        .write_all(format!("{reply}\n").as_bytes())
                        .await
                        .unwrap();
                });
            }
        });
    }

    /// Submits `event` over the control socket at `path` the way the client
    /// does — one JSON line out, the record back — and returns the record.
    async fn submit_over(path: &std::path::Path, event: Event) -> Record {
        let stream = tokio::net::UnixStream::connect(path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut line = serde_json_lenient::to_string(&Submission::Audit(event)).unwrap();
        line.push('\n');
        writer.write_all(line.as_bytes()).await.unwrap();
        let mut reply = String::new();
        tokio::io::BufReader::new(reader)
            .read_line(&mut reply)
            .await
            .unwrap();
        serde_json_lenient::from_str(reply.trim()).unwrap()
    }

    /// Redeems a value minted for `box_id` from that box itself: one request
    /// carrying it on a terminated flow to `api.github.com`, answered with the
    /// whole response the proxy returned.
    async fn redeem_from(h: &Harness, box_id: &str) -> String {
        let mut context = context();
        context.box_id = box_id.to_owned();
        let value = seal::seal(h.proxy.keys, &context, &Member::new(CREDENTIAL))
            .unwrap()
            .to_string();
        let sender = Sender {
            box_id: box_id.to_owned(),
            addressing: Addressing::OwnIp,
            egress: None,
        };
        let tcp = attach(h, Some(sender)).await;
        let mut tls = tunnel(h, tcp, "api.github.com:443").await.unwrap();
        let request = get("/user", "api.github.com", Some(&format!("token {value}")));
        exchange(&mut tls, &request).await
    }

    /// BEP-043 and BEP-044: a box's removal, and a logout, are each one
    /// revocation submitted over the control socket, and from the next request
    /// on the proxy refuses every sealed value they cover — well inside the
    /// sixty seconds the requirements allow, because the set is read per
    /// request rather than polled. The refused request reaches no upstream and
    /// is recorded `unrevoked`.
    #[tokio::test]
    async fn revocation_over_control_socket_refuses_within_60s() {
        let h = Harness::start().await;
        let (chain, key) = h.chain("api.github.com", Chain::Valid);
        let up = Upstream::serve(chain, key, Respond::Whole("{\"login\":\"octocat\"}")).await;
        h.route(up.addr);
        let control = tempfile::tempdir().unwrap();
        let socket = control.path().join("control.sock");
        control_socket(Arc::clone(&h.proxy), &socket);

        // Both boxes redeem what was minted for them before anything is
        // revoked, and the member itself is what goes upstream.
        for box_id in ["box-a1", "box-b2"] {
            let response = redeem_from(&h, box_id).await;
            assert!(response.starts_with("HTTP/1.1 200"), "{box_id}: {response}");
            assert_eq!(h.last().decision, audit::Decision::Admit);
        }
        assert!(
            up.received().contains(CREDENTIAL),
            "the member was not sent"
        );

        // `min box rm box-a1`: one revocation record, chained onto the proxy's
        // own decisions.
        let started = std::time::Instant::now();
        let revoked = submit_over(&socket, crate::mint::box_revocation_event("box-a1")).await;
        assert_eq!(revoked.kind, Kind::Revocation);
        assert_eq!(revoked.sub, "box-a1");
        let records = h.records();
        assert_eq!(
            revoked.previous_hash,
            records[records.len() - 2].line_hash(),
            "the revocation did not chain onto the proxy's last decision"
        );

        // That box's values are refused from the next request on, and nothing
        // of the request reaches the upstream.
        let sent = up.received().len();
        let response = redeem_from(&h, "box-a1").await;
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        let record = h.last();
        assert_eq!(record.decision, audit::Decision::Refuse);
        assert_eq!(record.marker, Check::Unrevoked.name());
        assert_eq!(record.sub, "box-a1");
        assert_eq!(
            up.received().len(),
            sent,
            "a revoked value reached the upstream"
        );
        assert!(
            started.elapsed().as_secs() < crate::control::REVOCATION_DEADLINE_SECS,
            "the revocation took longer than the requirement allows"
        );

        // The other box is untouched by it: that revocation names one box.
        let response = redeem_from(&h, "box-b2").await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");

        // `min auth logout`: every GitHub member on this host, the other box's
        // included.
        let started = std::time::Instant::now();
        let logout = submit_over(&socket, crate::mint::revocation_event()).await;
        assert_eq!(logout.kind, Kind::Revocation);
        assert_eq!(logout.sub, crate::mint::EVERY_BOX);
        let response = redeem_from(&h, "box-b2").await;
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert_eq!(h.last().marker, Check::Unrevoked.name());
        assert!(
            started.elapsed().as_secs() < crate::control::REVOCATION_DEADLINE_SECS,
            "the logout revocation took longer than the requirement allows"
        );

        // What a proxy restarted on this log starts from: both revocations.
        let replayed = Revocations::in_log(&h.log_path).unwrap();
        assert!(replayed.covers_box("box-a1"));
        assert!(replayed.covers_module("github"));
    }
}
