//! The upstream leg of a flow the proxy terminated: a TLS connection to the
//! connection authority, validated against the host's trust store and never
//! against the interception root, and opened before any request is forwarded
//! on it or any credential substituted (BEP-055).
//!
//! [`Trust`] is the host's trust store as the leg validates against it: the
//! platform's roots for a running proxy, a store a test builds for the
//! upstream it stands up. The interception root is never in it, so a chain the
//! proxy's own signing certificate issued does not validate here, which is the
//! point: a resolver or route compromise at an allowed name that presents a
//! chain from anywhere but the host's trust store receives no request and no
//! credential. [`open`] is the only way to a [`Validated`] connection, and the
//! listener forwards on nothing else.
//!
//! Where a name is reached is the [`Resolver`]'s: `None` for the host's own
//! resolution, an address for a test that stands the upstream up on loopback.
//! The name the chain is validated for is always the connection authority's,
//! whatever address it is reached at.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};

use rustls::crypto::CryptoProvider;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// The audit marker for an upstream chain or hostname that did not validate
/// against the host's trust store (BEP-055).
pub const INVALID: &str = "upstream_tls_invalid";

/// The audit marker for a request to a credentialed host that would ride an
/// upstream leg that is not TLS (BEP-055).
pub const NOT_TLS: &str = "upstream_not_tls";

/// The audit marker for an upstream the proxy could not reach at all.
pub const UNREACHABLE: &str = "upstream_unreachable";

/// The crypto provider every TLS configuration of the proxy is built with.
pub(crate) static PROVIDER: LazyLock<Arc<CryptoProvider>> =
    LazyLock::new(|| Arc::new(rustls::crypto::ring::default_provider()));

/// Where a `host:port` is reached: an address to connect to, or `None` for the
/// host's own resolution of the name.
pub type Resolver = Arc<dyn Fn(&str, u16) -> Option<SocketAddr> + Send + Sync>;

/// The host's own resolution for every name.
#[must_use]
pub fn host_resolver() -> Resolver {
    Arc::new(|_: &str, _: u16| None)
}

/// The host's trust store, as the upstream leg validates against it.
#[derive(Clone)]
pub struct Trust {
    config: Arc<ClientConfig>,
}

impl Trust {
    /// A trust store over `roots` alone.
    ///
    /// # Panics
    ///
    /// Never: the provider's default suites cover the default protocol
    /// versions.
    #[must_use]
    pub fn new(roots: RootCertStore) -> Self {
        let config = ClientConfig::builder_with_provider(Arc::clone(&*PROVIDER))
            .with_safe_default_protocol_versions()
            .expect("ring's default provider supports the default TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            config: Arc::new(config),
        }
    }

    /// The host's own trust store, as the platform holds it.
    ///
    /// # Errors
    ///
    /// [`TrustError::NoRoots`] when the platform yields no usable root.
    pub fn native() -> Result<Self, TrustError> {
        let loaded = rustls_native_certs::load_native_certs();
        let mut roots = RootCertStore::empty();
        let (added, ignored) = roots.add_parsable_certificates(loaded.certs);
        for error in &loaded.errors {
            tracing::warn!(%error, "a host trust store entry could not be loaded");
        }
        if added == 0 {
            return Err(TrustError::NoRoots {
                errors: loaded.errors.len(),
            });
        }
        tracing::info!(added, ignored, "loaded the host trust store");
        Ok(Self::new(roots))
    }
}

/// Why the host's trust store could not be loaded.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TrustError {
    /// The platform yielded no root the upstream leg could validate against.
    #[error("the host trust store yielded no usable root ({errors} entries failed to load)")]
    NoRoots { errors: usize },
}

/// Why an upstream leg could not be opened.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UpstreamError {
    /// The authority's host is not a name TLS can validate.
    #[error("{host} is not a DNS name the upstream leg can validate")]
    NotAName { host: String },
    /// The authority could not be reached.
    #[error("connecting to {authority}: {source}")]
    Unreachable {
        authority: String,
        #[source]
        source: io::Error,
    },
    /// The authority's chain or hostname did not validate against the host's
    /// trust store.
    #[error("{authority} did not validate against the host trust store: {source}")]
    Invalid {
        authority: String,
        #[source]
        source: io::Error,
    },
}

impl UpstreamError {
    /// The marker the audit record of the refused request carries.
    #[must_use]
    pub fn marker(&self) -> &'static str {
        match self {
            Self::NotAName { .. } | Self::Invalid { .. } => INVALID,
            Self::Unreachable { .. } => UNREACHABLE,
        }
    }
}

/// An upstream connection whose chain and hostname validated against the
/// host's trust store: the only leg a terminated flow is forwarded on.
pub struct Validated {
    authority: String,
    stream: TlsStream<TcpStream>,
}

impl Validated {
    /// The `host:port` the leg was validated for.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// The validated stream, to forward on.
    #[must_use]
    pub fn into_stream(self) -> TlsStream<TcpStream> {
        self.stream
    }
}

/// Opens the upstream leg to `host:port`, validating the chain it presents,
/// and its name, against `trust`.
///
/// Nothing is written on the connection before the handshake completes, so a
/// chain that does not validate has received no request and no credential.
///
/// # Errors
///
/// [`UpstreamError::NotAName`] when `host` is no DNS name,
/// [`UpstreamError::Unreachable`] when the connection cannot be opened, and
/// [`UpstreamError::Invalid`] when the handshake fails: a chain the trust
/// store does not anchor, an expired chain, or a name the chain does not
/// carry.
pub async fn open(
    trust: &Trust,
    resolver: &Resolver,
    host: &str,
    port: u16,
) -> Result<Validated, UpstreamError> {
    let authority = format!("{host}:{port}");
    let name = ServerName::try_from(host.to_owned()).map_err(|_| UpstreamError::NotAName {
        host: host.to_owned(),
    })?;
    let tcp = match resolver(host, port) {
        Some(address) => TcpStream::connect(address).await,
        None => TcpStream::connect((host, port)).await,
    }
    .map_err(|source| UpstreamError::Unreachable {
        authority: authority.clone(),
        source,
    })?;
    let stream = TlsConnector::from(Arc::clone(&trust.config))
        .connect(name, tcp)
        .await
        .map_err(|source| {
            tracing::warn!(
                %authority,
                error = %source,
                marker = INVALID,
                "the upstream chain did not validate against the host trust store"
            );
            UpstreamError::Invalid {
                authority: authority.clone(),
                source,
            }
        })?;
    tracing::debug!(%authority, "validated the upstream leg against the host trust store");
    Ok(Validated { authority, stream })
}
