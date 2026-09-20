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
//! credential in the value's place when every check passes (BEP-025). Either
//! way the upstream leg is opened and validated against the host's trust
//! store first, and nothing is forwarded, and no credential substituted,
//! before it is (BEP-055). Every decision appends one audit record (BEP-039).

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
    AUTHORIZATION, CONTENT_TYPE, HOST, HeaderMap, HeaderValue, PROXY_AUTHORIZATION,
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

use crate::audit::{self, Event, Kind, Log, Mapping};
use crate::ca::{Authority, Leaf};
use crate::keychain::KeyStore;
use crate::keys::Keys;
use crate::redeem::{
    self, Attribution, AuthorityId, BoxId, Breadth, Check, Egress, Endpoint, HostId, HostSet, Mode,
    ModuleId, Redemption, SealedMember,
};
use crate::seal::{self, Member, PREFIX};
use crate::upstream::{self, Resolver, Trust, Validated};

/// The audit marker for a request naming an authority outside the union of
/// the modules' host sets and the store authorities (BEP-029).
pub const OFF_MODULE: &str = "off_module";

/// The audit marker for an unsealed request that carries a credential of the
/// box's own (BEP-030).
pub const FOREIGN_CREDENTIAL: &str = "foreign_credential";

/// The most authorities the decision's interned ids can name.
pub const MAX_AUTHORITIES: usize = 255;

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

/// How the listener is configured.
pub struct Config {
    /// The configured modules and their host sets.
    pub modules: Vec<Module>,
    /// The registered store authorities, `host:port` (BEP-029).
    pub store_authorities: Vec<String>,
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

/// What a request's `Authorization` header carries.
enum Carried {
    /// No credential at all.
    Nothing,
    /// A credential of the box's own (BEP-030).
    Foreign,
    /// A sealed value, in the place it sits.
    Sealed { value: String, place: Place },
}

/// Where a sealed value sits in an `Authorization` header.
enum Place {
    /// `<scheme> <value>`: `Bearer` or `token`.
    Scheme(String),
    /// `Basic` with the value as the password.
    Basic { user: String },
}

impl Carried {
    /// What `headers` carry.
    fn in_headers(headers: &HeaderMap) -> Self {
        let Some(value) = headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
        else {
            return Self::Nothing;
        };
        let Some((scheme, param)) = value.trim().split_once(' ') else {
            return Self::Foreign;
        };
        let param = param.trim();
        if scheme.eq_ignore_ascii_case("basic") {
            return match basic_credentials(param) {
                Some((user, password)) if password.starts_with(PREFIX) => Self::Sealed {
                    value: password,
                    place: Place::Basic { user },
                },
                _ => Self::Foreign,
            };
        }
        if param.starts_with(PREFIX) {
            return Self::Sealed {
                value: param.to_owned(),
                place: Place::Scheme(scheme.to_owned()),
            };
        }
        Self::Foreign
    }

    /// The sealed value, when one is carried.
    fn sealed(&self) -> Option<&str> {
        match self {
            Self::Sealed { value, .. } => Some(value),
            Self::Nothing | Self::Foreign => None,
        }
    }

    /// The header value with the sealed value replaced by `credential`, in the
    /// place the sealed value sat.
    fn substitute(&self, credential: &str) -> Option<HeaderValue> {
        let text = match self {
            Self::Sealed {
                place: Place::Scheme(scheme),
                ..
            } => format!("{scheme} {credential}"),
            Self::Sealed {
                place: Place::Basic { user },
                ..
            } => format!("Basic {}", STANDARD.encode(format!("{user}:{credential}"))),
            Self::Nothing | Self::Foreign => return None,
        };
        HeaderValue::from_str(&text).ok()
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
    /// # Errors
    ///
    /// [`ListenerError::Authority`] when a configured authority is not
    /// `host:port`, or [`ListenerError::TooManyAuthorities`] when more are
    /// declared than the decision's ids can name.
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

        let mut proxy = Self {
            keys,
            authority,
            log: Mutex::new(log),
            modules: config.modules,
            known,
            hosts,
            credentialed: Vec::new(),
            module_sets: Vec::new(),
            stores: (Vec::new(), HostSet::default()),
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
        let member = carried.sealed().and_then(|value| self.unseal(flow, value));
        let credential = member.as_ref().map(|(_, _, id)| id.clone());
        let redemption = Redemption {
            request: self.facts(flow, &request),
            member: member.as_ref().map(|(member, _, _)| member.clone()),
            attribution: match flow.sender.addressing {
                Addressing::OwnIp => Attribution::OwnIp(SENDER),
                Addressing::HostIp => Attribution::HostIp(SENDER),
            },
            authority: flow.id,
            current_set: flow.module.map_or_else(
                || self.stores.1.clone(),
                |module| self.module_sets[module].1.clone(),
            ),
            now: now(),
            // Revocation intake is a later slice's; none is in force yet.
            revocations: Vec::new(),
        };
        let decision = redeem::decide(&redemption);
        tracing::info!(
            ?decision,
            sealed = carried.sealed().is_some(),
            "decided a request"
        );
        let substitution = match decision {
            redeem::Decision::Admit => member
                .as_ref()
                .and_then(|(_, member, _)| carried.substitute(member.expose())),
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
                let marker =
                    matches!(carried, Carried::Foreign).then(|| FOREIGN_CREDENTIAL.to_owned());
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

    /// The member a sealed value unseals to under this host's key, interned
    /// for the decision, with its credential and its audit identifier; `None`
    /// when the value does not unseal here (BEP-019).
    fn unseal(&self, flow: &Flow, value: &str) -> Option<(SealedMember, Member, String)> {
        let unsealed = seal::unseal(self.keys, value)
            .inspect_err(|error| {
                tracing::warn!(%error, "a sealed value did not unseal under this host's key");
            })
            .ok()?;
        let context = unsealed.context;
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
        Some((member, unsealed.member, id))
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
fn rewrite(request: Request<Incoming>, substitution: Option<HeaderValue>) -> Request<Incoming> {
    let (mut parts, body) = request.into_parts();
    let uri = parts
        .uri
        .path_and_query()
        .map_or_else(|| Uri::from_static("/"), |path| Uri::from(path.clone()));
    parts.uri = uri;
    parts.headers.remove(PROXY_AUTHORIZATION);
    parts.headers.remove("proxy-connection");
    parts.extensions.clear();
    if let Some(value) = substitution {
        parts.headers.insert(AUTHORIZATION, value);
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
    use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
    use tokio::net::TcpSocket;
    use tokio::sync::oneshot;
    use tokio_rustls::TlsConnector;
    use tokio_rustls::client::TlsStream;

    use super::*;
    use crate::audit::Record;
    use crate::ca::DeclaredUnion;
    use crate::keychain::MemoryStore;
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
    /// the GitHub set, an empty audit log, a host trust store anchoring the
    /// test's host CA, attribution by the test's own table and a route to
    /// wherever the test stands its upstream up.
    struct Harness {
        proxy: Arc<Proxy<MemoryStore>>,
        addr: SocketAddr,
        log_path: PathBuf,
        _dir: tempfile::TempDir,
        attachments: Arc<Mutex<HashMap<SocketAddr, Sender>>>,
        route: Arc<Mutex<Option<SocketAddr>>>,
        host_ca: HostCa,
    }

    impl Harness {
        async fn start() -> Self {
            let keys: &'static Keys<MemoryStore> =
                Box::leak(Box::new(Keys::open(MemoryStore::new()).unwrap()));
            let union =
                DeclaredUnion::of([GITHUB.map(|authority| authority.split(':').next().unwrap())]);
            let authority = Authority::open(keys, union).unwrap();
            let dir = tempfile::tempdir().unwrap();
            let log_path = dir.path().join("audit.jsonl");
            let log = Log::open(&log_path).unwrap();
            let host_ca = HostCa::new();
            let mut roots = RootCertStore::empty();
            roots.add(host_ca.root.clone()).unwrap();
            let attachments = Arc::new(Mutex::new(HashMap::new()));
            let route = Arc::new(Mutex::new(None));
            let table = Arc::clone(&attachments);
            let routed = Arc::clone(&route);
            let config = Config {
                modules: vec![Module {
                    id: "github".to_owned(),
                    host_set: GITHUB.map(str::to_owned).to_vec(),
                    version: 1,
                }],
                store_authorities: Vec::new(),
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
                host_ca,
            }
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
            seal::seal(self.proxy.keys, &context(), &Member::new(CREDENTIAL))
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
}
