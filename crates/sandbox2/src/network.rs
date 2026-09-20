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
/// own user+network namespace (rootless, via hakoniwa's RustSlirp), surfacing
/// its descriptor as [`hakoniwa::Child::rustslirp_tapfd`] for the provider to
/// relay to a switch. A provider that builds the tap itself asks for an
/// isolated namespace and no tap instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TapSpec {
    /// The PTask's switch address, assigned to the tap in-namespace.
    pub address: Ipv4Addr,
    /// The switch subnet netmask (e.g. `255.255.0.0` for a `/16`).
    pub netmask: Ipv4Addr,
    /// The switch gateway, installed as the default route.
    pub gateway: Ipv4Addr,
    /// The tap MTU; must match the relay's frame buffer.
    pub mtu: u16,
}

/// What `/etc/resolv.conf` should say inside the sandbox. The container build
/// is the one place that acts on it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Resolver {
    /// Leave the rootfs's `/etc/resolv.conf` alone.
    #[default]
    None,
    /// Synthesise one from the host's resolver, unless the rootfs already has
    /// one. Correct only in a namespace that can reach it.
    Host,
    /// Write these nameservers. An isolated sandbox needs this: the host's stub
    /// resolver (`127.0.0.53`) is unreachable from a fresh netns.
    Nameservers(Vec<Ipv4Addr>),
}

/// What a sandbox needs from its network, decided before the process starts.
///
/// Data, not behaviour: it says *what* the sandbox needs and not how a provider
/// obtains it, so the sandbox layer never depends on a switch client
/// (03-spec-networking R1.4). Built through constructors so the one invariant
/// cannot be broken: a plan carrying tap parameters always isolates the
/// network namespace — hakoniwa skips the tap setup entirely, leaving no
/// descriptor, if that namespace was never unshared.
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

    /// A fresh network namespace with a tap built inside it.
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

/// A plan is its own provider, reserving nothing: what a sandbox with no
/// provider of its own launches through, so there is one launch sequence.
impl Network for NetPlan {
    fn plan(&self) -> PlanFuture<'_> {
        Box::pin(std::future::ready(Ok(self.clone())))
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
/// follows. The sandbox layer runs `abandon` on every path out of a launch
/// that does not reach `attach`, including a cancelled one.
pub trait Network: Send + Sync + std::fmt::Debug {
    /// Before the process starts: reserve what the sandbox needs (a lease, a
    /// switch), and describe it.
    fn plan(&self) -> PlanFuture<'_>;

    /// After the process starts: wire its network namespace. Returns a
    /// [`NetGuard`] whose [`teardown`](NetGuard::teardown) reverses the wiring.
    ///
    /// The default is a no-op, for modes that need no post-spawn work
    /// ([`HostNet`], [`NoNet`]).
    fn attach(&self, spawned: Spawned) -> AttachFuture<'_> {
        drop(spawned);
        Box::pin(std::future::ready(Ok(noop_guard())))
    }

    /// Release whatever [`plan`](Self::plan) reserved, when no
    /// [`attach`](Self::attach) will follow. Runs at most once per `plan`, and
    /// never after a successful `attach`. The default is a no-op.
    fn abandon(&self) -> AbandonFuture<'_> {
        Box::pin(std::future::ready(()))
    }
}

/// What a launched sandbox process hands to [`Network::attach`].
///
/// Carries the tap descriptor by value: taken from the child once, moved here,
/// and closed by the provider's guard at teardown (017-010).
#[derive(Debug)]
pub struct Spawned {
    netns_pid: u32,
    tap_fd: Option<std::os::fd::OwnedFd>,
}

impl Spawned {
    /// A launched process with no tap of its own.
    #[must_use]
    pub fn new(netns_pid: u32) -> Self {
        Self {
            netns_pid,
            tap_fd: None,
        }
    }

    /// Adds the tap descriptor the sandbox layer's in-namespace tap produced.
    #[must_use]
    pub fn with_tap_fd(mut self, tap_fd: std::os::fd::OwnedFd) -> Self {
        self.tap_fd = Some(tap_fd);
        self
    }

    /// The PID whose `/proc/<pid>/ns/net` is the sandbox's network namespace.
    #[must_use]
    pub fn netns_pid(&self) -> u32 {
        self.netns_pid
    }

    /// Takes the tap descriptor, if the plan asked for one. Yields it once;
    /// a second call returns `None`.
    pub fn take_tap_fd(&mut self) -> Option<std::os::fd::OwnedFd> {
        self.tap_fd.take()
    }

    /// Reads a just-spawned container process: its PID, and the tap descriptor
    /// hakoniwa produced if the plan asked for a tap. Taking it out of the
    /// child is what makes it once-only: a `hakoniwa::Child` never closes the
    /// fd, so a second reader could adopt and double-close it.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn from_child(child: &mut hakoniwa::Child) -> Self {
        use std::os::fd::FromRawFd as _;

        let netns_pid = child.id();
        // SAFETY: hakoniwa hands out a live, owned tap fd, and `take` makes
        // this the only adoption of it.
        let tap_fd = child
            .rustslirp_tapfd
            .take()
            .map(|raw| unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) });
        Self { netns_pid, tap_fd }
    }
}

/// Reverses per-sandbox network wiring. Teardown is **explicit** — call
/// [`teardown`](NetGuard::teardown) on a live async runtime — rather than on
/// `Drop`, which cannot await and may run after the runtime has stopped.
pub trait NetGuard: Send {
    /// Reverses the wiring set up by [`Network::attach`]. Consumes the guard.
    fn teardown(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

/// Shares the host/VM network namespace (the default), and the host's
/// resolver with it. No isolation, no wiring.
#[derive(Debug, Default, Clone, Copy)]
pub struct HostNet;

impl Network for HostNet {
    fn plan(&self) -> PlanFuture<'_> {
        Box::pin(std::future::ready(Ok(
            NetPlan::host().with_resolver(Resolver::Host)
        )))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// NET-038. `NoNet`'s plan is what `new_container` builds a sandbox's
    /// network namespace from: isolated, with no tap to relay traffic
    /// through. That combination is what leaves only a down `lo` behind, so
    /// every socket the sandbox opens to the outside is refused.
    #[tokio::test]
    async fn no_net_plan_isolates_netns() {
        let plan = NoNet.plan().await.unwrap();
        assert!(plan.isolates_netns());
        assert!(plan.tap().is_none());
        assert_eq!(plan.resolver(), &Resolver::None);
    }
}
