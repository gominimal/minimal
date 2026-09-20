//! The host-side helper's egress filter: per-box source-addressed rules
//! applied outside the VM (NET-081), and the node-plane baseline set the
//! helper enumerates for an un-enrolled host (NET-130).
//!
//! On a VM-backed host every frame a guest tap sends reaches the switch over
//! the vsock shuttle: libkrun dials a host UNIX socket for each guest
//! connection (see the `shuttle` module). Before this module that socket was
//! gvproxy's own `-listen` socket, so the guest's word was the last one on
//! what left the VM. Now `minvmd` owns the socket libkrun dials
//! ([`HostFilter`]) and relays each connection to gvproxy on a second,
//! upstream socket; on the relay it decides every frame leaving the VM with
//! the same pure verdict the guest's relay applies
//! ([`net_verdict::frame_verdict`]), keyed by the frame's **source address**:
//!
//! - a source that is a resident box's lease is decided under that box's
//!   declared rules, derived from the daemon's own record of the box;
//! - the daemon's node address (its primary tap) is node-plane traffic under
//!   the baseline set;
//! - any other source belongs to no box and is dropped, whatever it carries.
//!
//! The box table is fed from what already crosses the relay: when the guest
//! daemon attaches a box it registers the box's name and lease with the
//! switch's DNS (`POST /services/dns/add`), and the filter answers that
//! announcement by asking the daemon for the box's effective policy over the
//! bridge ([`PolicyFeed`]). A root process inside the VM can announce an
//! address, but only under a resident box's declared rules: its reach stays
//! within the union of those rules plus the baseline set.
//!
//! The baseline set ([`BaselineSet`]) is the helper's built-in enumeration of
//! categories, configurable on the host within them: which registry and which
//! cache, never whether there is one. Its named members are pinned by the
//! node's DNS layer; by address, node-plane traffic is admitted here.

use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sessions::EgressPolicy;
use sessions::core::net_verdict::{self, DropRule, EgressRules, Endpoint, Verdict};
use switch::{DEFAULT_MTU, SwitchSubnet};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

/// Host configuration of the baseline set's registry member: `host[:port]`.
pub const BASELINE_REGISTRY_ENV: &str = "MINVMD_BASELINE_REGISTRY";
/// Host configuration of the baseline set's cache member: `host[:port]`.
pub const BASELINE_CACHE_ENV: &str = "MINVMD_BASELINE_CACHE";

/// The registry the daemon's package fetch reaches by default: the host of
/// the upstream layer repositories `minimal.toml` pins.
pub const DEFAULT_REGISTRY: &str = "github.com:443";
/// The remote artifact cache the daemon reads by default.
pub const DEFAULT_CACHE: &str = "cache.minimal.dev:443";

/// A category of node-plane traffic the helper's enumeration names. The list
/// is the enumeration: a host configures a member within a category and can
/// neither add a category nor empty one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineCategory {
    /// The daemon's own package registry (the upstream layer repositories).
    Registry,
    /// The daemon's remote artifact cache.
    Cache,
    /// The resolver Minimal owns for the boxes: the switch's DNS at the
    /// gateway, the one carve-out from a deny-all verdict.
    Resolver,
}

impl BaselineCategory {
    /// Every category, in the order the set lists them.
    pub const ALL: [Self; 3] = [Self::Registry, Self::Cache, Self::Resolver];
}

/// One member of the baseline set: a destination under a category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub category: BaselineCategory,
    /// `host:port` or `ip:port`.
    pub destination: String,
}

/// The node-plane baseline set in force on this host: what the daemon's own
/// traffic may reach beside the boxes' declared egress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineSet {
    pub entries: Vec<BaselineEntry>,
}

impl BaselineSet {
    /// The helper's enumeration, with `lookup` answering the host's
    /// configuration for [`BASELINE_REGISTRY_ENV`] and [`BASELINE_CACHE_ENV`].
    /// A blank or absent answer keeps the built-in member: a category is
    /// configurable as to which member, never absent.
    #[must_use]
    pub fn enumerate_with(lookup: impl Fn(&str) -> Option<String>, subnet: SwitchSubnet) -> Self {
        let configured = |var: &str, default: &str| -> String {
            lookup(var)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| default.to_string())
        };
        let resolver = resolver_for(subnet);
        Self {
            entries: vec![
                BaselineEntry {
                    category: BaselineCategory::Registry,
                    destination: configured(BASELINE_REGISTRY_ENV, DEFAULT_REGISTRY),
                },
                BaselineEntry {
                    category: BaselineCategory::Cache,
                    destination: configured(BASELINE_CACHE_ENV, DEFAULT_CACHE),
                },
                BaselineEntry {
                    category: BaselineCategory::Resolver,
                    destination: format!("{}:{}", resolver.ip, resolver.port),
                },
            ],
        }
    }

    /// The enumeration as this host configures it, on the default switch
    /// subnet.
    #[must_use]
    pub fn from_host_env() -> Self {
        Self::enumerate_with(|var| std::env::var(var).ok(), SwitchSubnet::default())
    }

    /// The members under `category`.
    pub fn members(&self, category: BaselineCategory) -> impl Iterator<Item = &str> {
        self.entries
            .iter()
            .filter(move |e| e.category == category)
            .map(|e| e.destination.as_str())
    }
}

/// The resolver carve-out for every box on `subnet`: the switch's DNS at the
/// gateway, port 53 (design §4.1) — the same endpoint the guest relay uses.
fn resolver_for(subnet: SwitchSubnet) -> Endpoint {
    Endpoint {
        ip: subnet.dns_server(),
        port: 53,
    }
}

/// Why the filter dropped a frame, as the warning's `rule` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostDrop {
    /// The source address belongs to no box (NET-081).
    UnknownSource,
    /// Not a frame the filter can read: too short, or IPv4/ARP cut short.
    Malformed,
    /// Neither IPv4 nor ARP.
    Ethertype,
    /// A box's own rule (NET-062, NET-064, NET-084).
    Rule(DropRule),
}

impl HostDrop {
    /// The name the warning and the counters carry.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownSource => "unknown-source",
            Self::Malformed => "malformed",
            Self::Ethertype => "ethertype",
            Self::Rule(rule) => rule.as_str(),
        }
    }
}

/// The filter's decision on one Ethernet frame leaving the VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostVerdict {
    /// Forward it to the switch.
    Admit,
    /// Discard it: nothing is forwarded and nothing is answered.
    Drop {
        rule: HostDrop,
        /// The source the frame claimed, when it could be read.
        source: Option<Ipv4Addr>,
    },
}

const ETH_HDR: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;

/// The largest frame the relay accepts: MTU plus the Ethernet header and a
/// VLAN tag, matching the guest relay's bound.
const fn max_frame() -> usize {
    DEFAULT_MTU as usize + ETH_HDR + 4
}

/// The sender protocol address of an Ethernet/IPv4 ARP frame.
fn arp_sender_ip(frame: &[u8]) -> Option<Ipv4Addr> {
    let arp = frame.get(ETH_HDR..ETH_HDR + 18)?;
    (arp[..6] == [0x00, 0x01, 0x08, 0x00, 6, 4])
        .then(|| Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]))
}

/// The host-side rule table: every resident box's rules keyed by its lease,
/// beside the node address whose traffic is the daemon's own.
#[derive(Debug, Clone)]
pub struct HostRules {
    subnet: SwitchSubnet,
    boxes: BTreeMap<Ipv4Addr, EgressRules>,
}

impl HostRules {
    /// An empty table on `subnet`: only the node address is known.
    #[must_use]
    pub fn new(subnet: SwitchSubnet) -> Self {
        Self {
            subnet,
            boxes: BTreeMap::new(),
        }
    }

    /// The daemon's own address on the switch: node-plane traffic.
    #[must_use]
    pub fn node_address(&self) -> Ipv4Addr {
        self.subnet.daemon_ip()
    }

    /// Enter (or replace) the box leased `lease` with its declared `policy`;
    /// an absent section allows every destination, as the guest decides it.
    pub fn set_box(&mut self, lease: Ipv4Addr, policy: Option<&EgressPolicy>) {
        let rules = EgressRules::for_box(lease, policy, Some(resolver_for(self.subnet)));
        self.boxes.insert(lease, rules);
    }

    /// The leases the table knows, with each one's rules.
    pub fn boxes(&self) -> impl Iterator<Item = (Ipv4Addr, &EgressRules)> {
        self.boxes.iter().map(|(lease, rules)| (*lease, rules))
    }

    /// Decide `frame`, a raw Ethernet frame leaving the VM. Pure.
    #[must_use]
    pub fn decide(&self, frame: &[u8]) -> HostVerdict {
        let malformed = HostVerdict::Drop {
            rule: HostDrop::Malformed,
            source: None,
        };
        let Some(ethertype) = frame.get(12..14) else {
            return malformed;
        };
        match u16::from_be_bytes([ethertype[0], ethertype[1]]) {
            ETHERTYPE_ARP => {
                let Some(sender) = arp_sender_ip(frame) else {
                    return malformed;
                };
                if sender == self.node_address() || self.boxes.contains_key(&sender) {
                    HostVerdict::Admit
                } else {
                    HostVerdict::Drop {
                        rule: HostDrop::UnknownSource,
                        source: Some(sender),
                    }
                }
            }
            ETHERTYPE_IPV4 => {
                let Some(summary) = net_verdict::summarize_ipv4(&frame[ETH_HDR..]) else {
                    return malformed;
                };
                if summary.src == self.node_address() {
                    // Node-plane traffic: the daemon's own, under the baseline
                    // set. Its named members are pinned by the DNS layer, not
                    // by address here.
                    return HostVerdict::Admit;
                }
                let Some(rules) = self.boxes.get(&summary.src) else {
                    return HostVerdict::Drop {
                        rule: HostDrop::UnknownSource,
                        source: Some(summary.src),
                    };
                };
                match net_verdict::frame_verdict(&summary, rules) {
                    Verdict::Admit => HostVerdict::Admit,
                    Verdict::Drop(rule) => HostVerdict::Drop {
                        rule: HostDrop::Rule(rule),
                        source: Some(summary.src),
                    },
                }
            }
            _ => HostVerdict::Drop {
                rule: HostDrop::Ethertype,
                source: None,
            },
        }
    }
}

/// What the filter has dropped so far: a count per rule, and per source for
/// the first [`DropCounters::MAX_SOURCES`] sources seen (a flood of forged
/// sources is counted under its rule, not given a row each).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DropCounters {
    pub by_rule: BTreeMap<&'static str, u64>,
    pub by_source: BTreeMap<Ipv4Addr, u64>,
}

impl DropCounters {
    /// Sources tracked individually before the per-source rows stop growing.
    pub const MAX_SOURCES: usize = 256;

    fn record(&mut self, rule: HostDrop, source: Option<Ipv4Addr>) {
        *self.by_rule.entry(rule.as_str()).or_insert(0) += 1;
        if let Some(source) = source
            && (self.by_source.len() < Self::MAX_SOURCES || self.by_source.contains_key(&source))
        {
            *self.by_source.entry(source).or_insert(0) += 1;
        }
    }

    /// Every drop, across rules.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.by_rule.values().sum()
    }
}

/// One warning per rule per minute: a flood dropped by one rule cannot
/// silence the first drop by another.
const WARN_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// Where the filter learns a box's declared egress from: the daemon's record
/// of the session whose name the lease announcement carries.
pub trait PolicyFeed: Send + Sync + 'static {
    /// The `egress` section of the effective policy of the session named
    /// `label` (`None` when the box declared none), or an error when the
    /// daemon knows no such session. `label` is the DNS label the guest
    /// announced: the session's name lowercased, with `-task` appended for a
    /// task's box.
    fn egress_for<'a>(
        &'a self,
        label: &'a str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Option<EgressPolicy>>> + Send + 'a>>;
}

/// A feed answered from a fixed table keyed by label: what a test hands the
/// filter.
impl PolicyFeed for BTreeMap<String, Option<EgressPolicy>> {
    fn egress_for<'a>(
        &'a self,
        label: &'a str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Option<EgressPolicy>>> + Send + 'a>> {
        Box::pin(async move {
            self.get(label)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no session labelled {label}"))
        })
    }
}

/// The feed on a running VM: the in-VM daemon over the bridge UDS. A label
/// is matched against the daemon's session list (names compare without
/// case, since the announced label is lowercased; an unnamed session is
/// announced by its id) and the match's policy is read by id.
pub struct DaemonFeed {
    bridge_uds: PathBuf,
}

impl DaemonFeed {
    /// A feed asking the daemon behind `bridge_uds`.
    #[must_use]
    pub fn new(bridge_uds: PathBuf) -> Self {
        Self { bridge_uds }
    }
}

/// How long the feed waits for the daemon to answer: connect and handshake,
/// then each RPC.
const FEED_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const FEED_RPC_TIMEOUT: Duration = Duration::from_secs(10);

impl PolicyFeed for DaemonFeed {
    fn egress_for<'a>(
        &'a self,
        label: &'a str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Option<EgressPolicy>>> + Send + 'a>> {
        Box::pin(async move {
            let session = label.strip_suffix("-task").unwrap_or(label);
            let listed = crate::rpc_client::call_oneshot::<minimald_rpc::ListSessions>(
                &self.bridge_uds,
                (),
                FEED_CONNECT_TIMEOUT,
                FEED_RPC_TIMEOUT,
            )
            .await?;
            let id = listed
                .sessions
                .iter()
                .find(|s| {
                    let id = s.id.to_string();
                    s.name
                        .as_deref()
                        .unwrap_or(&id)
                        .eq_ignore_ascii_case(session)
                })
                .map(|s| s.id)
                .ok_or_else(|| anyhow::anyhow!("no session labelled {label}"))?;
            match crate::rpc_client::call_oneshot::<minimald_rpc::GetSessionPolicy>(
                &self.bridge_uds,
                minimald_rpc::GetSessionPolicyRequest::Id(id),
                FEED_CONNECT_TIMEOUT,
                FEED_RPC_TIMEOUT,
            )
            .await?
            {
                minimald_rpc::Errorable::Ok(policy) => Ok(policy.egress),
                minimald_rpc::Errorable::Err { error } => Err(anyhow::anyhow!(error)),
            }
        })
    }
}

/// State shared between the relay tasks and the handle that owns them.
struct Shared {
    rules: RwLock<HostRules>,
    drops: Mutex<DropCounters>,
    warned: Mutex<BTreeMap<&'static str, Instant>>,
    feed: Box<dyn PolicyFeed>,
}

impl Shared {
    /// Decide `frame`; on a drop, count it and warn if this rule's window
    /// has elapsed.
    fn admit(&self, frame: &[u8]) -> bool {
        let verdict = self
            .rules
            .read()
            .expect("host rules lock poisoned")
            .decide(frame);
        match verdict {
            HostVerdict::Admit => true,
            HostVerdict::Drop { rule, source } => {
                self.drops
                    .lock()
                    .expect("drop counters lock poisoned")
                    .record(rule, source);
                let now = Instant::now();
                let mut warned = self.warned.lock().expect("warn limiter lock poisoned");
                let due = warned
                    .get(rule.as_str())
                    .is_none_or(|last| now.duration_since(*last) >= WARN_MIN_INTERVAL);
                if due {
                    warned.insert(rule.as_str(), now);
                    tracing::warn!(
                        ?source,
                        rule = rule.as_str(),
                        "frame leaving the VM dropped by the host-side filter"
                    );
                }
                false
            }
        }
    }

    /// Answer a lease announcement: enter the box under its declared rules.
    async fn learn(&self, label: &str, lease: Ipv4Addr) {
        match self.feed.egress_for(label).await {
            Ok(egress) => {
                self.rules
                    .write()
                    .expect("host rules lock poisoned")
                    .set_box(lease, egress.as_ref());
                tracing::info!(%label, %lease, "host-side rules entered for box");
            }
            Err(error) => {
                tracing::debug!(%label, %lease, %error, "lease announced for no known box");
            }
        }
    }
}

/// The relay between the socket libkrun dials and gvproxy's upstream socket,
/// deciding every frame that leaves the VM. Stops on [`stop`](Self::stop) or
/// drop.
#[must_use = "dropping HostFilter closes the socket libkrun dials"]
pub struct HostFilter {
    stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
    shared: Arc<Shared>,
}

impl HostFilter {
    /// Listen on `listen` (the socket libkrun dials for the shuttle port) and
    /// relay each connection to gvproxy on `upstream`, under `rules` grown
    /// from `feed`. Returns once the listener is bound; the relay runs on a
    /// dedicated thread.
    ///
    /// # Errors
    ///
    /// Returns the I/O error if the thread or its runtime cannot be started
    /// or `listen` cannot be bound.
    pub fn spawn(
        listen: PathBuf,
        upstream: PathBuf,
        rules: HostRules,
        feed: impl PolicyFeed,
    ) -> io::Result<Self> {
        let shared = Arc::new(Shared {
            rules: RwLock::new(rules),
            drops: Mutex::new(DropCounters::default()),
            warned: Mutex::new(BTreeMap::new()),
            feed: Box::new(feed),
        });
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<io::Result<()>>();
        let worker = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("minvmd-filter".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                runtime.block_on(async move {
                    let listener = match UnixListener::bind(&listen) {
                        Ok(l) => l,
                        Err(e) => {
                            let _ = ready_tx.send(Err(e));
                            return;
                        }
                    };
                    if ready_tx.send(Ok(())).is_err() {
                        return;
                    }
                    tokio::select! {
                        _ = stop_rx => {}
                        () = serve(listener, upstream, worker) => {}
                    }
                    let _ = std::fs::remove_file(&listen);
                });
            })?;
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                stop_tx: Some(stop_tx),
                thread: Some(thread),
                shared,
            }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                Err(io::Error::other(
                    "host filter thread exited before reporting readiness",
                ))
            }
        }
    }

    /// The rule table in force, as a snapshot.
    #[must_use]
    pub fn rules(&self) -> HostRules {
        self.shared
            .rules
            .read()
            .expect("host rules lock poisoned")
            .clone()
    }

    /// What the filter has dropped so far.
    #[must_use]
    pub fn drops(&self) -> DropCounters {
        self.shared
            .drops
            .lock()
            .expect("drop counters lock poisoned")
            .clone()
    }

    /// Stop relaying and join the thread.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            tracing::warn!("host filter thread panicked");
        }
    }
}

impl Drop for HostFilter {
    fn drop(&mut self) {
        self.shutdown();
    }
}

async fn serve(listener: UnixListener, upstream: PathBuf, shared: Arc<Shared>) {
    loop {
        let guest = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(error) => {
                tracing::warn!(%error, "host filter accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let upstream = upstream.clone();
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            if let Err(error) = relay_connection(guest, &upstream, shared).await {
                tracing::debug!(%error, "host filter connection ended");
            }
        });
    }
}

/// The largest HTTP head (request line and headers) accepted from the guest
/// before the connection is closed as misbehaving.
const MAX_HEAD: usize = 8 * 1024;
/// The largest control-request body the filter reads to learn from.
const MAX_CONTROL_BODY: usize = 64 * 1024;

/// One guest connection: read its HTTP request head, then relay it as a
/// frame stream (`POST /connect`) under the verdict, or as a control
/// exchange passed through, learning from a lease announcement on the way.
async fn relay_connection(
    mut guest: UnixStream,
    upstream: &Path,
    shared: Arc<Shared>,
) -> io::Result<()> {
    let mut head = Vec::with_capacity(256);
    let mut buf = [0u8; 512];
    let head_end = loop {
        if let Some(i) = find_header_end(&head) {
            break i;
        }
        if head.len() >= MAX_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request head exceeded the size cap before its headers ended",
            ));
        }
        let n = guest.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        head.extend_from_slice(&buf[..n]);
    };
    let mut switch = UnixStream::connect(upstream).await?;
    let (request_line, headers) = head[..head_end].split_at(
        head[..head_end]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(head_end, |i| i + 1),
    );
    let (method, path) = request_target(request_line);
    if method == "POST" && path == "/connect" {
        // Only the head goes up as-is: any frame bytes that arrived with it
        // are decided by the relay like every later one, never passed raw.
        switch.write_all(&head[..head_end]).await?;
        return relay_frames(guest, switch, &head[head_end..], &shared).await;
    }

    // A control request: take its body so a lease announcement can be read,
    // then pass everything through untouched. The announcement is learned on
    // its own task so the guest's request is never held behind the feed's
    // round trip back into the guest.
    let want = content_length(headers).unwrap_or(0).min(MAX_CONTROL_BODY);
    let mut body = head[head_end..].to_vec();
    while body.len() < want {
        let n = guest.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
    }
    if method == "POST" && path == "/services/dns/add" {
        for (label, lease) in dns_records(&body[..body.len().min(want)]) {
            let shared = Arc::clone(&shared);
            tokio::spawn(async move { shared.learn(&label, lease).await });
        }
    }
    switch.write_all(&head[..head_end]).await?;
    switch.write_all(&body).await?;
    tokio::io::copy_bidirectional(&mut guest, &mut switch).await?;
    Ok(())
}

/// The frame stream after `POST /connect`: guest → switch under the verdict,
/// switch → guest untouched. `carried` is what arrived with the request head.
async fn relay_frames(
    guest: UnixStream,
    switch: UnixStream,
    carried: &[u8],
    shared: &Shared,
) -> io::Result<()> {
    let (mut guest_rx, mut guest_tx) = guest.into_split();
    let (mut switch_rx, mut switch_tx) = switch.into_split();
    let carried = carried.to_vec();
    let egress = async move {
        let mut pending = carried;
        let mut len_buf = [0u8; 2];
        let mut frame = vec![0u8; max_frame()];
        loop {
            read_exact_carried(&mut guest_rx, &mut pending, &mut len_buf).await?;
            let n = usize::from(u16::from_le_bytes(len_buf));
            if n == 0 {
                continue;
            }
            if n > frame.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("guest frame length {n} exceeds max {}", frame.len()),
                ));
            }
            read_exact_carried(&mut guest_rx, &mut pending, &mut frame[..n]).await?;
            if shared.admit(&frame[..n]) {
                switch_tx.write_all(&len_buf).await?;
                switch_tx.write_all(&frame[..n]).await?;
            }
        }
    };
    let ingress = async move {
        tokio::io::copy(&mut switch_rx, &mut guest_tx)
            .await
            .map(|_| ())
    };
    tokio::select! {
        r = egress => end_of_stream(r),
        r = ingress => end_of_stream(r),
    }
}

/// A clean close on either side ends the relay without error.
fn end_of_stream(r: io::Result<()>) -> io::Result<()> {
    match r {
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(()),
        other => other,
    }
}

/// `read_exact` that first drains bytes already read past the request head.
async fn read_exact_carried<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    pending: &mut Vec<u8>,
    out: &mut [u8],
) -> io::Result<()> {
    let take = pending.len().min(out.len());
    out[..take].copy_from_slice(&pending[..take]);
    pending.drain(..take);
    if take < out.len() {
        reader.read_exact(&mut out[take..]).await?;
    }
    Ok(())
}

/// The method and path of an HTTP request line.
fn request_target(line: &[u8]) -> (&str, &str) {
    let line = std::str::from_utf8(line).unwrap_or("");
    let mut parts = line.split_ascii_whitespace();
    (parts.next().unwrap_or(""), parts.next().unwrap_or(""))
}

/// The index just past the `\r\n\r\n` that ends an HTTP head.
fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

/// The `Content-Length` header's value, case-insensitively.
fn content_length(headers: &[u8]) -> Option<usize> {
    std::str::from_utf8(headers).ok()?.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().ok())
            .flatten()
    })
}

/// The `(label, ip)` records of a `/services/dns/add` zone body: the guest
/// daemon's lease announcement for a box (gvproxy's `types.Zone`, whose
/// fields the guest writes lowercase and gvproxy itself capitalises).
fn dns_records(body: &[u8]) -> Vec<(String, Ipv4Addr)> {
    #[derive(Deserialize)]
    struct Zone {
        #[serde(alias = "Records", default)]
        records: Vec<Record>,
    }
    #[derive(Deserialize)]
    struct Record {
        #[serde(alias = "Name")]
        name: String,
        #[serde(alias = "IP", alias = "Ip")]
        ip: String,
    }
    serde_json_lenient::from_slice::<Zone>(body)
        .map(|zone| {
            zone.records
                .into_iter()
                .filter_map(|r| r.ip.parse().ok().map(|ip| (r.name, ip)))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;
    use sessions::core::net_verdict::{IPPROTO_TCP, IPPROTO_UDP};
    use tokio::sync::mpsc;

    const LEASE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);
    const CONNECT_REQUEST: &[u8] = b"POST /connect HTTP/1.0\r\nHost: localhost\r\n\r\n";

    /// An Ethernet/IPv4 frame with a minimal transport header and `tag` as
    /// its payload, so the switch side can tell frames apart.
    fn ipv4_frame(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, dst_port: u16, tag: u8) -> Vec<u8> {
        let mut f = vec![0u8; ETH_HDR];
        f[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        f.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x00, 64, proto, 0, 0,
        ]);
        f.extend_from_slice(&src.octets());
        f.extend_from_slice(&dst.octets());
        f.extend_from_slice(&40000u16.to_be_bytes());
        f.extend_from_slice(&dst_port.to_be_bytes());
        f.extend_from_slice(&[0u8; 16]);
        f.push(tag);
        f
    }

    fn arp_frame(sender: Ipv4Addr) -> Vec<u8> {
        let mut f = vec![0u8; ETH_HDR];
        f[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        f.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01]);
        f.extend_from_slice(&[0u8; 6]);
        f.extend_from_slice(&sender.octets());
        f.extend_from_slice(&[0u8; 10]);
        f
    }

    fn framed(frame: &[u8]) -> Vec<u8> {
        let mut out = u16::try_from(frame.len()).unwrap().to_le_bytes().to_vec();
        out.extend_from_slice(frame);
        out
    }

    fn policy(allow: &[&str]) -> EgressPolicy {
        EgressPolicy {
            allow_subnets: Some(allow.iter().map(ToString::to_string).collect()),
            allow_dns_hosts: None,
            allow_protocols: None,
            deny_subnets: None,
        }
    }

    /// A stand-in switch: accepts one connection, reads the `/connect` head,
    /// then sends every length-prefixed frame it receives down `tx`.
    fn stand_in_switch(sock: &Path) -> mpsc::UnboundedReceiver<Vec<u8>> {
        let listener = std::os::unix::net::UnixListener::bind(sock).unwrap();
        listener.set_nonblocking(true).unwrap();
        let listener = UnixListener::from_std(listener).unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while find_header_end(&head).is_none() {
                conn.read_exact(&mut byte).await.unwrap();
                head.push(byte[0]);
            }
            assert!(head.starts_with(b"POST /connect"), "{head:?}");
            loop {
                let mut len = [0u8; 2];
                if conn.read_exact(&mut len).await.is_err() {
                    return;
                }
                let mut frame = vec![0u8; usize::from(u16::from_le_bytes(len))];
                conn.read_exact(&mut frame).await.unwrap();
                if tx.send(frame).is_err() {
                    return;
                }
            }
        });
        rx
    }

    async fn recv_tag(rx: &mut mpsc::UnboundedReceiver<Vec<u8>>) -> Option<u8> {
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .ok()
            .flatten()
            .map(|f| *f.last().unwrap())
    }

    /// NET-081: a box's undeclared connection is dropped by the host-side
    /// helper before the switch sees it; its declared one reaches the switch.
    #[tokio::test]
    async fn host_side_rules_applied_outside_vm() {
        let tmp = tempfile::tempdir().unwrap();
        let upstream = tmp.path().join("up.sock");
        let listen = tmp.path().join("sw.sock");
        let mut at_switch = stand_in_switch(&upstream);

        let mut rules = HostRules::new(SwitchSubnet::default());
        rules.set_box(LEASE, Some(&policy(&["10.0.0.0/8"])));
        let filter = HostFilter::spawn(
            listen.clone(),
            upstream,
            rules,
            BTreeMap::<String, Option<EgressPolicy>>::new(),
        )
        .unwrap();

        let mut guest = UnixStream::connect(&listen).await.unwrap();
        guest.write_all(CONNECT_REQUEST).await.unwrap();
        let declared = ipv4_frame(LEASE, Ipv4Addr::new(10, 1, 2, 3), IPPROTO_TCP, 443, 1);
        let undeclared = ipv4_frame(LEASE, Ipv4Addr::new(93, 184, 216, 34), IPPROTO_TCP, 443, 2);
        let declared_again = ipv4_frame(LEASE, Ipv4Addr::new(10, 9, 9, 9), IPPROTO_UDP, 53, 3);
        for frame in [&declared, &undeclared, &declared_again] {
            guest.write_all(&framed(frame)).await.unwrap();
        }

        // The switch sees the declared frames, in order, and never the other.
        assert_eq!(recv_tag(&mut at_switch).await, Some(1));
        assert_eq!(recv_tag(&mut at_switch).await, Some(3));
        let drops = filter.drops();
        assert_eq!(drops.by_rule.get("allow_subnets"), Some(&1));
        assert_eq!(drops.by_source.get(&LEASE), Some(&1));
        assert_eq!(drops.total(), 1);
        drop(guest);
        filter.stop();
    }

    fn arb_leases() -> impl Strategy<Value = Vec<Ipv4Addr>> {
        proptest::collection::vec(any::<u32>().prop_map(Ipv4Addr::from), 0..=4)
    }

    proptest! {
        /// NET-081's failure case, as a property: for every frame leaving
        /// the VM whose source belongs to no box — IPv4 or ARP from an
        /// address that is neither a lease nor the node address, another
        /// ethertype, or bytes that read as no frame at all — the frame is
        /// dropped, whatever the resident boxes declare (here: everything).
        /// Frames from a lease or the node address are admitted, so the
        /// property is not satisfied by a filter that drops everything.
        #[test]
        fn unknown_source_default_deny(
            mut frame in proptest::collection::vec(any::<u8>(), 0..=60),
            leases in arb_leases(),
            src in any::<u32>(),
            shape in 0u8..4,
            pick in any::<prop::sample::Index>(),
        ) {
            let subnet = SwitchSubnet::default();
            let mut rules = HostRules::new(subnet);
            for lease in &leases {
                rules.set_box(*lease, None);
            }
            // Bias the bytes toward readable frames: an IPv4 or ARP frame
            // (from a known source half the time), or the raw bytes as they
            // came.
            let src = match shape {
                0 if !leases.is_empty() => leases[pick.index(leases.len())],
                1 => subnet.daemon_ip(),
                _ => Ipv4Addr::from(src),
            };
            if shape < 2 || frame.len() % 2 == 0 {
                frame = ipv4_frame(src, Ipv4Addr::new(1, 1, 1, 1), IPPROTO_TCP, 443, 0);
            } else if frame.len() % 3 == 0 {
                frame = arp_frame(src);
            }

            let source = match frame.get(12..14).map(|e| u16::from_be_bytes([e[0], e[1]])) {
                Some(ETHERTYPE_IPV4) => net_verdict::summarize_ipv4(&frame[ETH_HDR..]).map(|s| s.src),
                Some(ETHERTYPE_ARP) => arp_sender_ip(&frame),
                _ => None,
            };
            let known = source.is_some_and(|s| s == subnet.daemon_ip() || leases.contains(&s));
            match rules.decide(&frame) {
                HostVerdict::Admit => prop_assert!(known, "admitted {source:?} with leases {leases:?}"),
                HostVerdict::Drop { rule, source: claimed } => {
                    prop_assert!(!known || !matches!(rule, HostDrop::UnknownSource));
                    if rule == HostDrop::UnknownSource {
                        prop_assert_eq!(claimed, source);
                    }
                }
            }
            if !known {
                let dropped = matches!(rules.decide(&frame), HostVerdict::Drop { .. });
                prop_assert!(dropped, "unknown source {source:?} was not dropped");
            }
        }
    }

    /// The feed: a lease announcement on the relay enters the box under the
    /// daemon's rules for it, and an announcement for no box enters nothing.
    #[tokio::test]
    async fn lease_announcement_enters_box_from_feed() {
        let tmp = tempfile::tempdir().unwrap();
        let upstream = tmp.path().join("up.sock");
        let listen = tmp.path().join("sw.sock");
        // A stand-in control endpoint: answer any request with 200, without
        // closing first (the keep-alive shape the guest relies on).
        let control = UnixListener::bind(&upstream).unwrap();
        tokio::spawn(async move {
            loop {
                let (mut conn, _) = control.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = conn.read(&mut buf).await;
                    let _ = conn
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    let _ = conn.read(&mut buf).await;
                });
            }
        });
        let mut feed = BTreeMap::new();
        feed.insert("alpha".to_string(), Some(policy(&["10.0.0.0/8"])));
        feed.insert("alpha-task".to_string(), Some(policy(&["10.0.0.0/8"])));
        let filter = HostFilter::spawn(
            listen.clone(),
            upstream,
            HostRules::new(SwitchSubnet::default()),
            feed,
        )
        .unwrap();

        for (name, ip) in [
            ("alpha", "100.64.0.5"),
            ("alpha-task", "100.64.0.6"),
            ("ghost", "100.64.0.7"),
            ("host", "100.64.0.254"),
        ] {
            let body = format!(
                r#"{{"name":"min.internal.","records":[{{"name":"{name}","ip":"{ip}"}}]}}"#
            );
            let mut guest = UnixStream::connect(&listen).await.unwrap();
            guest
                .write_all(
                    format!(
                        "POST /services/dns/add HTTP/1.1\r\nHost: localhost\r\n\
                         Content-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let mut resp = [0u8; 64];
            let n = guest.read(&mut resp).await.unwrap();
            assert!(resp[..n].starts_with(b"HTTP/1.1 200"));
        }

        // The table fills off the request path; wait for it.
        let deadline = Instant::now() + Duration::from_secs(5);
        let rules = loop {
            let rules = filter.rules();
            if rules.boxes().count() == 2 || Instant::now() > deadline {
                break rules;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        let leases: Vec<_> = rules.boxes().map(|(l, _)| l).collect();
        assert_eq!(
            leases,
            vec![Ipv4Addr::new(100, 64, 0, 5), Ipv4Addr::new(100, 64, 0, 6)]
        );
        let declared = ipv4_frame(
            Ipv4Addr::new(100, 64, 0, 6),
            Ipv4Addr::new(10, 1, 1, 1),
            IPPROTO_TCP,
            80,
            0,
        );
        assert_eq!(rules.decide(&declared), HostVerdict::Admit);
        let undeclared = ipv4_frame(
            Ipv4Addr::new(100, 64, 0, 5),
            Ipv4Addr::new(1, 1, 1, 1),
            IPPROTO_TCP,
            80,
            0,
        );
        assert_eq!(
            rules.decide(&undeclared),
            HostVerdict::Drop {
                rule: HostDrop::Rule(DropRule::Undeclared),
                source: Some(Ipv4Addr::new(100, 64, 0, 5)),
            }
        );
        filter.stop();
    }

    /// NET-130: un-enrolled, the baseline set is the helper's built-in
    /// enumeration of categories, configurable on the host within them.
    #[test]
    fn unenrolled_baseline_set_from_helper_enumeration() {
        let subnet = SwitchSubnet::default();
        let built_in = BaselineSet::enumerate_with(|_| None, subnet);
        let categories: Vec<_> = built_in.entries.iter().map(|e| e.category).collect();
        assert_eq!(categories, BaselineCategory::ALL.to_vec());
        assert_eq!(
            built_in
                .members(BaselineCategory::Registry)
                .collect::<Vec<_>>(),
            [DEFAULT_REGISTRY]
        );
        assert_eq!(
            built_in
                .members(BaselineCategory::Cache)
                .collect::<Vec<_>>(),
            [DEFAULT_CACHE]
        );
        assert_eq!(
            built_in
                .members(BaselineCategory::Resolver)
                .collect::<Vec<_>>(),
            [format!("{}:53", subnet.dns_server())]
        );

        // The host configures a member within a category; the categories are
        // the same list, and nothing the host sets adds one.
        let configured = BaselineSet::enumerate_with(
            |var| match var {
                BASELINE_REGISTRY_ENV => Some(" registry.corp.example:8443 ".to_string()),
                BASELINE_CACHE_ENV => Some("cache.corp.example:443".to_string()),
                "MINVMD_BASELINE_TELEMETRY" => Some("collector.example:4317".to_string()),
                _ => None,
            },
            subnet,
        );
        let categories: Vec<_> = configured.entries.iter().map(|e| e.category).collect();
        assert_eq!(categories, BaselineCategory::ALL.to_vec());
        assert_eq!(
            configured
                .members(BaselineCategory::Registry)
                .collect::<Vec<_>>(),
            ["registry.corp.example:8443"]
        );
        assert_eq!(
            configured
                .members(BaselineCategory::Cache)
                .collect::<Vec<_>>(),
            ["cache.corp.example:443"]
        );
        assert!(
            !configured
                .entries
                .iter()
                .any(|e| e.destination.contains("collector")),
            "{configured:?}"
        );
        // The rendering the CLI shows names each category and its member.
        let json = serde_json_lenient::to_string(&configured).unwrap();
        for needle in [
            "\"registry\"",
            "registry.corp.example:8443",
            "\"cache\"",
            "\"resolver\"",
        ] {
            assert!(json.contains(needle), "{needle} missing from {json}");
        }
    }

    /// NET-130: the registry and cache are always members; the host chooses
    /// which, and an empty choice keeps the built-in one rather than
    /// removing the category.
    #[test]
    fn baseline_enumeration_always_carries_registry_and_cache() {
        let subnet = SwitchSubnet::default();
        for (registry, cache) in [
            (None, None),
            (Some(""), Some("")),
            (Some("   "), Some("\t")),
            (Some("registry.example:443"), None),
            (None, Some("cache.example:8443")),
        ] {
            let set = BaselineSet::enumerate_with(
                |var| match var {
                    BASELINE_REGISTRY_ENV => registry.map(str::to_string),
                    BASELINE_CACHE_ENV => cache.map(str::to_string),
                    _ => None,
                },
                subnet,
            );
            let registries: Vec<_> = set.members(BaselineCategory::Registry).collect();
            let caches: Vec<_> = set.members(BaselineCategory::Cache).collect();
            assert_eq!(registries.len(), 1, "{registry:?}: {set:?}");
            assert_eq!(caches.len(), 1, "{cache:?}: {set:?}");
            let expected_registry = registry
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(DEFAULT_REGISTRY);
            let expected_cache = cache
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(DEFAULT_CACHE);
            assert_eq!(registries[0], expected_registry);
            assert_eq!(caches[0], expected_cache);
        }
        // The process-env reader is the same enumeration.
        let from_env = BaselineSet::from_host_env();
        assert_eq!(from_env.members(BaselineCategory::Registry).count(), 1);
        assert_eq!(from_env.members(BaselineCategory::Cache).count(), 1);
    }

    #[test]
    fn drop_counters_cap_per_source_rows() {
        let mut counters = DropCounters::default();
        for i in 0..(DropCounters::MAX_SOURCES as u32 + 10) {
            counters.record(HostDrop::UnknownSource, Some(Ipv4Addr::from(i)));
        }
        assert_eq!(counters.by_source.len(), DropCounters::MAX_SOURCES);
        assert_eq!(counters.total(), DropCounters::MAX_SOURCES as u64 + 10);
    }

    #[test]
    fn control_parsing_reads_target_length_and_records() {
        assert_eq!(
            request_target(b"POST /connect HTTP/1.0\r\n"),
            ("POST", "/connect")
        );
        assert_eq!(request_target(b""), ("", ""));
        assert_eq!(
            content_length(b"Host: x\r\ncontent-LENGTH: 12\r\n"),
            Some(12)
        );
        assert_eq!(content_length(b"Host: x\r\n"), None);
        assert_eq!(find_header_end(b"A\r\n\r\nB"), Some(5));
        let records = dns_records(
            br#"{"Name":"min.internal.","Records":[{"Name":"a","IP":"100.64.0.3"},{"Name":"bad","IP":"nope"}]}"#,
        );
        assert_eq!(
            records,
            vec![("a".to_string(), Ipv4Addr::new(100, 64, 0, 3))]
        );
        assert!(dns_records(b"not json").is_empty());
    }
}
