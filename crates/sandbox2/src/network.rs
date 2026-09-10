//! Per-sandbox network configuration.
//!
//! [`Network`] decouples network setup from sandbox consumers: any sandbox —
//! build, task, or session — configures networking the same way, via
//! [`Config::with_network`](crate::Config::with_network). The built-in
//! [`HostNet`]/[`NoNet`] cover the consumer-agnostic modes; richer modes (e.g.
//! an own-IP gvproxy switch attach) are supplied by consumers as out-of-crate
//! `impl Network`, keeping switch/tap/relay logic out of `sandbox2`.
//!
//! This respects the deployment-model ownership rule (spec R1.4): the gvproxy
//! **process** is owned by `minimald` (DM2) or `minvmd` (DM1/3/4), never by
//! `sandbox2`. `sandbox2` only decides netns isolation (pre-spawn) and invokes
//! the consumer-provided wiring against an already-running switch (post-spawn).

use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;

/// The future returned by [`Network::plan`].
pub type PlanFuture<'a> = Pin<Box<dyn Future<Output = Result<NetPlan, NetworkError>> + Send + 'a>>;

/// The future returned by [`Network::attach`].
pub type AttachFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Box<dyn NetGuard>, NetworkError>> + Send + 'a>>;

/// The future returned by [`Network::abandon`].
pub type AbandonFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// Parameters for a tap device the sandbox layer builds *inside* the sandbox's
/// own user+network namespace (rootless, via hakoniwa's RustSlirp — no host
/// `CAP_NET_ADMIN`), surfacing its descriptor as
/// [`hakoniwa::Child::rustslirp_tapfd`] for the provider to relay to a switch.
///
/// This is 03-spec-networking R1.5's "provision a virtual tap interface inside
/// it", and it is how an own-IP PTask gets its tap on **every** deployment
/// model; only the transport that carries the descriptor differs, and that is
/// the provider's business, not the plan's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TapSpec {
    /// The PTask's switch address, assigned to the tap in-namespace.
    pub address: Ipv4Addr,
    /// The switch subnet netmask (e.g. `255.255.0.0` for a `/16`).
    pub netmask: Ipv4Addr,
    /// The switch gateway, installed as the next-hop default route
    /// (`0.0.0.0/0 via gateway`) — gvproxy answers DNS and routes egress there.
    pub gateway: Ipv4Addr,
    /// The tap MTU; must match the relay's frame buffer.
    pub mtu: u16,
}

/// What `/etc/resolv.conf` should say inside the sandbox.
///
/// One value replaces the two independent DNS controls the sandbox config used
/// to carry (a "synthesise from the host" flag and an override address), which
/// could disagree: the override silently won, by being written second.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Resolver {
    /// Leave the rootfs's `/etc/resolv.conf` alone.
    #[default]
    None,
    /// Synthesise one from the host's resolver. Correct only when the sandbox
    /// shares a network namespace that can reach it.
    Host,
    /// Write these nameservers. An isolated sandbox needs this: the host's stub
    /// resolver (`127.0.0.53`) is unreachable from a fresh netns, so a sandbox
    /// that inherited it would have a dead resolver and no way to notice.
    Nameservers(Vec<Ipv4Addr>),
}

/// What a sandbox needs from its network, decided before the process starts.
///
/// The plan is data, deliberately: it says *what* the sandbox needs and not how
/// a provider obtains it, so a provider can be a test double and the sandbox
/// layer never depends on a switch client (which would be a dependency cycle —
/// see 03-spec-networking R1.4).
///
/// Built through the constructors rather than field-by-field, so the one
/// invariant that matters cannot be broken by construction: a plan carrying tap
/// parameters always isolates the network namespace. RustSlirp enters the
/// sandbox's *own* netns to build the tap, and hakoniwa skips the setup
/// entirely — leaving no descriptor — if that namespace was never unshared, so
/// the two are one decision and not two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetPlan {
    isolate_netns: bool,
    tap: Option<TapSpec>,
    resolver: Resolver,
}

impl NetPlan {
    /// Share the host's (or VM's) network namespace: no isolation, no tap.
    #[must_use]
    pub fn host() -> Self {
        Self {
            isolate_netns: false,
            tap: None,
            resolver: Resolver::None,
        }
    }

    /// A fresh, empty network namespace: only a down `lo`, so every egress
    /// attempt fails.
    #[must_use]
    pub fn isolated() -> Self {
        Self {
            isolate_netns: true,
            tap: None,
            resolver: Resolver::None,
        }
    }

    /// A fresh network namespace with a tap built inside it. Isolation is
    /// implied, not requested — see the type's note.
    #[must_use]
    pub fn isolated_with_tap(tap: TapSpec) -> Self {
        Self {
            isolate_netns: true,
            tap: Some(tap),
            resolver: Resolver::None,
        }
    }

    /// Sets what `/etc/resolv.conf` should say.
    #[must_use]
    pub fn with_resolver(mut self, resolver: Resolver) -> Self {
        self.resolver = resolver;
        self
    }

    /// Whether the sandbox runs in its own unshared network namespace.
    #[must_use]
    pub fn isolates_netns(&self) -> bool {
        self.isolate_netns
    }

    /// The tap to build inside that namespace, if any.
    #[must_use]
    pub fn tap(&self) -> Option<TapSpec> {
        self.tap
    }

    /// What to write to `/etc/resolv.conf`.
    #[must_use]
    pub fn resolver(&self) -> &Resolver {
        &self.resolver
    }
}

/// An error from [`Network::attach`]. Wraps a consumer error so `sandbox2` need
/// not know the concrete failure type.
#[derive(Debug)]
pub struct NetworkError(pub Box<dyn std::error::Error + Send + Sync>);

impl NetworkError {
    /// Wraps any error as a [`NetworkError`].
    #[must_use]
    pub fn new<E: std::error::Error + Send + Sync + 'static>(err: E) -> Self {
        Self(Box::new(err))
    }
}

impl std::fmt::Display for NetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "network attach failed: {}", self.0)
    }
}

impl std::error::Error for NetworkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

/// Per-sandbox network configuration, in three operations around the spawn.
///
/// `plan` runs before the container is built, `attach` after the process
/// starts, and `abandon` releases what `plan` reserved when no `attach`
/// follows. The sandbox layer owns that sequence and runs `abandon` on every
/// path out of a launch that does not reach `attach`, including a cancelled
/// one — so a provider that reserves something in `plan` has exactly one place
/// to release it, and does not need a rollback guard of its own.
pub trait Network: Send + Sync + std::fmt::Debug {
    /// Before the process starts: reserve what the sandbox needs, and describe
    /// it. Fallible and async, because reserving may mean talking to something
    /// (leasing an address, starting a switch).
    fn plan(&self) -> PlanFuture<'_>;

    /// After the process starts: wire the network namespace of the launched
    /// process `netns_pid` (which holds `/proc/<pid>/ns/net`). Returns a
    /// [`NetGuard`] whose [`teardown`](NetGuard::teardown) reverses the wiring.
    ///
    /// The default is a no-op, for modes that need no post-spawn work
    /// ([`HostNet`], [`NoNet`]).
    fn attach(&self, netns_pid: u32) -> AttachFuture<'_> {
        let _ = netns_pid;
        Box::pin(std::future::ready(Ok(noop_guard())))
    }

    /// Release whatever [`plan`](Self::plan) reserved, when no
    /// [`attach`](Self::attach) will follow.
    ///
    /// The default is a no-op, for modes that reserve nothing. Runs at most
    /// once per `plan`, and never after a successful `attach` — the
    /// [`NetGuard`] owns the release from that point.
    fn abandon(&self) -> AbandonFuture<'_> {
        Box::pin(std::future::ready(()))
    }
}

/// Reverses per-sandbox network wiring. Teardown is **explicit** — call
/// [`teardown`](NetGuard::teardown) on a live async runtime — rather than on
/// `Drop`, which cannot await and may run after the runtime has stopped.
pub trait NetGuard: Send {
    /// Reverses the wiring set up by [`Network::attach`]. Consumes the guard.
    fn teardown(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

/// Shares the host/VM network namespace (the default). No isolation, no wiring.
#[derive(Debug, Default, Clone, Copy)]
pub struct HostNet;

impl Network for HostNet {
    fn plan(&self) -> PlanFuture<'_> {
        Box::pin(std::future::ready(Ok(NetPlan::host())))
    }
}

/// A fresh, empty network namespace: only a down `lo`, so every egress attempt
/// fails (UC1). No post-spawn wiring.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoNet;

impl Network for NoNet {
    fn plan(&self) -> PlanFuture<'_> {
        Box::pin(std::future::ready(Ok(NetPlan::isolated())))
    }
}

/// The no-op guard returned by the default [`Network::attach`] and by sandboxes
/// with no custom network.
pub(crate) fn noop_guard() -> Box<dyn NetGuard> {
    struct NoopGuard;
    impl NetGuard for NoopGuard {
        fn teardown(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            Box::pin(std::future::ready(()))
        }
    }
    Box::new(NoopGuard)
}
