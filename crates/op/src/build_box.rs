//! Build boxes: where a box's package builds run (NET-155), and what `min`
//! derives for them from the pinned commits (NET-165 to NET-168).
//!
//! A build for a box runs in a [`BuildBox`], a box of the `build` type. It has
//! a network of its own, or none, and never the host's. The build's source
//! fetch runs inside it, so the build box's egress decides the fetch, its
//! name lookups and its redirects. A build box opens its network only when it
//! needs one, and the [`BuildReach`] decides what that network is.
//!
//! [`build_grant_table`] is the trust root's half that reads the package
//! graph. Only `min`, outside the box host, calls it, on a graph it evaluated
//! itself. A host-side mirror, where one exists, serves sources at
//! [`BuildBox::fetch`]: that is the one place a source enters a build, so the
//! fetch through a mirror replaces the fetch process there (NET-155).

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::{SpecHash, SpecOrigin};
use graph::{BuildDep, BuildSpecRef, Graph, SourceFetch, Transitives};
use ot::OpTracker;

use crate::Error;

/// The hidden `minimald` subcommand that runs a build box's source fetch.
pub const BUILD_FETCH_SUBCOMMAND: &str = "__build-fetch";

/// The fetch process's output file, in the sandbox's output directory.
const FETCHED_FILE: &str = "fetched";

/// Where the fetch process writes [`FETCHED_FILE`], from its working directory:
/// the one directory the daemon reads a sandbox's outputs from.
const FETCH_TO: &str = "output/fetched";

/// Where the fetch process's program sits in the build box.
#[cfg(target_os = "linux")]
const FETCH_PROGRAM: &str = "/fetcher";

/// What the fetch process reads from the host: its program's libraries and
/// the trust roots. It reads no box's data.
#[cfg(target_os = "linux")]
const FETCH_HOST_PATHS: [&str; 6] = [
    "/usr",
    "/lib",
    "/lib64",
    "/etc/ssl",
    "/etc/ca-certificates",
    "/etc/pki",
];

/// What a build says when it needs the network and its box has none
/// (NET-155).
pub const NEEDS_NETWORK: &str = "the build needs the network and the box has none";

/// What a build says when it needs the network and the egress rules of its
/// box admit no destination (NET-155).
pub const NEEDS_NETWORK_RULES: &str =
    "the build needs the network and the egress rules of the box admit none";

/// The most processes one build box runs on its network at a time: the task
/// addresses its row holds.
const NETWORK_SLOTS: usize = 4;

/// Makes the network a build box attaches to. Each process gets a network of
/// its own, because a network holds the reservation of one sandbox at a time
/// and the dependency builds of one box can run at the same time.
#[derive(Clone)]
pub struct BuildNetwork {
    make: Arc<dyn Fn() -> Arc<dyn sandbox::Network> + Send + Sync>,
    slots: Arc<tokio::sync::Semaphore>,
}

impl BuildNetwork {
    /// A build network that `make` makes again for each process.
    pub fn new(make: impl Fn() -> Arc<dyn sandbox::Network> + Send + Sync + 'static) -> Self {
        Self {
            make: Arc::new(make),
            slots: Arc::new(tokio::sync::Semaphore::new(NETWORK_SLOTS)),
        }
    }

    /// A new network for one process.
    pub fn network(&self) -> Arc<dyn sandbox::Network> {
        (self.make)()
    }

    /// Waits for room on this network. A process holds the permit for as
    /// long as it runs, so a build never fails for want of a task address.
    pub(crate) async fn slot(&self) -> tokio::sync::OwnedSemaphorePermit {
        Arc::clone(&self.slots)
            .acquire_owned()
            .await
            .expect("the semaphore is never closed")
    }
}

impl std::fmt::Debug for BuildNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuildNetwork").finish_non_exhaustive()
    }
}

/// A future a [`BuildReach`] answers with.
pub type ReachFuture<'a, T> = std::pin::Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What one build box may reach. The host side decides it when the build box
/// asks, and a build box asks only when it needs the network.
pub trait BuildReach: Send + Sync + std::fmt::Debug {
    /// The build box's network, or `None` when its rules admit no
    /// destination.
    fn open(&self) -> ReachFuture<'_, Option<BuildNetwork>>;
    /// Whether the rules of an open network can admit the host `host`. This
    /// reads the rules and sends nothing.
    fn admits_source(&self, host: &str) -> bool;
    /// Whether the box the build runs for has no network at all, so a
    /// build box with no grant has none either.
    fn has_no_network(&self) -> bool {
        false
    }
    /// Ends the build box's network, opened or not. A grant stops here when
    /// the fetch stops or the build ends, whichever comes first for it.
    fn close(&self) -> ReachFuture<'_, ()>;
}

/// A reach fixed at construction, for a build box whose network is known.
#[derive(Debug)]
struct FixedReach(Option<BuildNetwork>);

impl BuildReach for FixedReach {
    fn open(&self) -> ReachFuture<'_, Option<BuildNetwork>> {
        let network = self.0.clone();
        Box::pin(async move { network })
    }

    fn admits_source(&self, _host: &str) -> bool {
        true
    }

    fn close(&self) -> ReachFuture<'_, ()> {
        Box::pin(async {})
    }
}

/// A build box: where one package's build and its source fetch run.
#[derive(Debug, Clone)]
pub struct BuildBox {
    /// The daemon's own program, which runs the fetch.
    pub fetch_program: PathBuf,
    reach: Arc<dyn BuildReach>,
    opened: Arc<tokio::sync::OnceCell<Option<BuildNetwork>>>,
}

/// The build boxes of one box (NET-155, NET-169).
pub trait BuildBoxes: Send + Sync + std::fmt::Debug {
    /// The build box for the build of `package`, whose declared dependencies
    /// are `packages`. `spec_hash` is the hash the host side looks up. `None`
    /// never looks: a patched build's spec is one the box can change, so the
    /// box's own rules decide it.
    fn build_box(
        &self,
        package: &str,
        packages: Vec<String>,
        spec_hash: Option<&SpecHash>,
    ) -> BuildBox;
    /// Tells the box's listing that this build started or ended.
    fn note_running(&self, _package: &str, _spec_hash: &SpecHash, _running: bool) {}
}

/// A build running in its build box, listed while it runs. [`Self::end`]
/// ends it: the build box's network, then its listing. Dropped before that,
/// as a task that is aborted drops it, it still ends: the listing at once,
/// and the network on a task of its own.
#[derive(Debug)]
pub struct BuildBoxRun {
    boxes: Option<Arc<dyn BuildBoxes>>,
    build_box: Option<BuildBox>,
    package: String,
    spec_hash: SpecHash,
}

impl BuildBoxRun {
    /// Lists the build of `package` as running in `build_box`.
    #[must_use]
    pub fn start(
        boxes: Option<Arc<dyn BuildBoxes>>,
        build_box: Option<BuildBox>,
        package: &str,
        spec_hash: SpecHash,
    ) -> Self {
        if let Some(boxes) = &boxes {
            boxes.note_running(package, &spec_hash, true);
        }
        Self {
            boxes,
            build_box,
            package: package.to_string(),
            spec_hash,
        }
    }

    /// Ends the build box's network, then its listing.
    pub async fn end(mut self) {
        if let Some(build_box) = self.build_box.take() {
            build_box.close().await;
        }
        self.unlist();
    }

    fn unlist(&mut self) {
        if let Some(boxes) = self.boxes.take() {
            boxes.note_running(&self.package, &self.spec_hash, false);
        }
    }
}

impl Drop for BuildBoxRun {
    fn drop(&mut self) {
        self.unlist();
        if let Some(build_box) = self.build_box.take()
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            runtime.spawn(async move { build_box.close().await });
        }
    }
}

/// The names of the packages `spec` declares it depends on: its build and
/// runtime dependencies, each once, by name.
#[must_use]
pub fn declared_packages(graph: &Graph, spec: &BuildSpecRef) -> Vec<String> {
    let build = graph.get(spec).expect("a member of the graph");
    let refs = build
        .build_deps
        .iter()
        .filter_map(|dep| match dep {
            BuildDep::Build(bsr) => Some(bsr),
            BuildDep::Subset(subset) => Some(&subset.from),
            BuildDep::Source(_) | BuildDep::Local { .. } => None,
        })
        .chain(build.runtime_deps.iter().map(|dep| dep.bsr()));
    let names: BTreeSet<String> = refs
        .filter_map(|bsr| graph.get(bsr).map(|dep| dep.name.clone()))
        .collect();
    names.into_iter().collect()
}

impl BuildBox {
    /// A build box whose network `reach` decides.
    #[must_use]
    pub fn new(fetch_program: PathBuf, reach: Arc<dyn BuildReach>) -> Self {
        Self {
            fetch_program,
            reach,
            opened: Arc::default(),
        }
    }

    /// A build box on `network`, already open.
    #[must_use]
    pub fn on_network(fetch_program: PathBuf, network: Option<BuildNetwork>) -> Self {
        let opened = tokio::sync::OnceCell::new_with(Some(network.clone()));
        Self {
            fetch_program,
            reach: Arc::new(FixedReach(network)),
            opened: Arc::new(opened),
        }
    }

    /// Opens the build box's network, once.
    pub async fn network(&self) -> Option<&BuildNetwork> {
        self.opened.get_or_init(|| self.reach.open()).await.as_ref()
    }

    /// The network, if an earlier [`Self::network`] opened one.
    #[must_use]
    pub fn opened(&self) -> Option<&BuildNetwork> {
        self.opened.get().and_then(Option::as_ref)
    }

    /// Ends the build box's network. From here on its processes run with
    /// none, whether it ever opened one or not.
    pub async fn close(&self) {
        self.reach.close().await;
    }

    /// The error of a build that needs the network this build box does not
    /// reach. The daemon names the package, the box and the next step.
    #[must_use]
    pub fn needs_network(&self) -> Error {
        Error::Other(anyhow::anyhow!(if self.reach.has_no_network() {
            NEEDS_NETWORK
        } else {
            NEEDS_NETWORK_RULES
        }))
    }

    /// The error of a fetch of `url` that this build box does not reach. It
    /// says what a download that could not connect says, with the reason,
    /// and nothing was sent.
    fn refused(&self, url: &str) -> Error {
        let reason = if self.reach.has_no_network() {
            common::NO_NETWORK
        } else {
            common::RULES_REFUSE
        };
        let parsed = url::Url::parse(url).ok();
        let host = parsed
            .as_ref()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_default();
        let port = parsed
            .as_ref()
            .and_then(url::Url::port_or_known_default)
            .unwrap_or(443);
        Error::Other(anyhow::anyhow!(
            "could not connect to {host}:{port}: {reason}"
        ))
    }

    /// Returns `url`'s file, from the download cache or from a fetch inside
    /// this build box. `filename` is the download cache's name for it.
    #[expect(
        clippy::too_many_arguments,
        reason = "each argument is one fact of the fetch the caller already holds"
    )]
    pub(crate) async fn fetch<SF: crate::SourceFetcher>(
        &self,
        package: &str,
        fetcher: &SF,
        url: &str,
        filename: &str,
        sha256: &str,
        opts: &crate::Options<'_>,
        op: &OpTracker,
    ) -> Result<PathBuf, Error> {
        if let Some(cached) = fetcher.cached(filename, sha256).map_err(Error::Other)? {
            return Ok(cached);
        }
        let Some(network) = self.network().await else {
            return Err(self.refused(url));
        };
        if !source_host(url).is_some_and(|host| self.reach.admits_source(&host)) {
            return Err(self.refused(url));
        }
        let dir = tempfile::tempdir_in(&opts.exec_base)
            .map_err(|e| Error::Other(anyhow::Error::from(e)))?;
        let slot = network.slot().await;
        self.run_fetch(package, network, url, sha256, dir.path(), opts)
            .await?;
        drop(slot);
        op.set_done();
        fetcher
            .adopt(filename, sha256, &dir.path().join(FETCHED_FILE))
            .map_err(Error::Other)
    }

    /// The fetch process's sandbox: an empty working directory, the daemon's
    /// program and what it reads from the host (NET-170).
    #[cfg(target_os = "linux")]
    fn fetch_config(&self, package: &str, network: &BuildNetwork) -> sandbox::config::Config {
        sandbox::config::Config::new(format!("fetch-{package}"))
            .with_isolated_wd(std::iter::empty())
            .with_read_only_host_paths(FETCH_HOST_PATHS.iter().map(PathBuf::from))
            .with_read_only_file(&self.fetch_program, FETCH_PROGRAM)
            .with_network(network.network())
    }

    /// Runs the fetch process in this build box, on `network`. The fetched
    /// file lands in `into`. The caller still checks its hash.
    #[cfg(target_os = "linux")]
    async fn run_fetch(
        &self,
        package: &str,
        network: &BuildNetwork,
        url: &str,
        sha256: &str,
        into: &Path,
        opts: &crate::Options<'_>,
    ) -> Result<(), Error> {
        let config = self.fetch_config(package, network);
        let config = match &opts.daemon_id {
            Some(id) => config.with_daemon_id(id.clone()),
            None => config,
        };
        let mut sandbox = config.build(&opts.exec_base, ()).await?;
        let mut stdout: Vec<u8> = Vec::new();
        let mut stderr: Vec<u8> = Vec::new();
        let ran = sandbox
            .run(
                vec![sandbox::config::Invocation {
                    executable: FETCH_PROGRAM.to_string(),
                    args: vec![
                        BUILD_FETCH_SUBCOMMAND.to_string(),
                        url.to_string(),
                        sha256.to_string(),
                        FETCH_TO.to_string(),
                    ],
                    envs: Default::default(),
                }],
                Some(&mut stdout),
                Some(&mut stderr),
            )
            .await;
        if let Err(e) = ran {
            let said = String::from_utf8_lossy(&stderr);
            let error = format!("{e:#}");
            let failure = fetch_failure(said.lines().last().unwrap_or_default(), &error);
            tracing::info!(
                package,
                error = %crate::specs::strip_urls(&error),
                "{failure}",
            );
            return Err(Error::Other(anyhow::anyhow!(failure)));
        }
        let glob = globset::Glob::new(FETCHED_FILE).map_err(|e| Error::Other(e.into()))?;
        let set = globset::GlobSet::new([glob]).map_err(|e| Error::Other(e.into()))?;
        sandbox.match_outputs_into(set, into)?;
        Ok(())
    }

    /// Sandbox execution is only available on Linux (hakoniwa).
    #[cfg(not(target_os = "linux"))]
    async fn run_fetch(
        &self,
        _package: &str,
        _network: &BuildNetwork,
        _url: &str,
        _sha256: &str,
        _into: &Path,
        _opts: &crate::Options<'_>,
    ) -> Result<(), Error> {
        Err(crate::sandbox_unsupported())
    }
}

/// What a failed source fetch says: the fetch process's own last line, as
/// the download wrote it. A download that could not connect names the host
/// and the port there. A process that wrote nothing, because it died before
/// it could, says the sandbox's `error` instead. Any URL either quotes loses
/// its credentials and its query.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn fetch_failure(said: &str, error: &str) -> String {
    let said = crate::specs::strip_urls(said.trim());
    if said.is_empty() {
        crate::specs::strip_urls(error)
    } else {
        said
    }
}

/// Whether the spec's build steps need the network: its own `needs.dns` and
/// `needs.internet`, or a dependency's.
#[must_use]
pub fn declared_needs(graph: &Graph, spec: &BuildSpecRef) -> (bool, bool) {
    let transitives = Transitives::new(graph, spec, true);
    let mut members: Vec<BuildSpecRef> = transitives
        .transitive_runtime_deps
        .keys()
        .copied()
        .collect();
    members.push(*spec);
    let mut needs = (false, false);
    for bsr in members {
        let deps = &graph
            .get(&bsr)
            .expect("a member of the graph")
            .abstract_deps;
        needs.0 |= deps.contains_key("dns");
        needs.1 |= deps.contains_key("internet");
    }
    needs
}

/// Whether a spec's origin earns build grants (NET-166): the one test of which
/// packages the table holds. An upstream or a sideload earns them, at the pin a
/// person set outside the box: `min` reads that pin from its own file, at the
/// box's creation, and nothing the box changes later reaches this test. A
/// Packages Directory package and an inline spec are ones a box can write.
#[must_use]
pub fn earns_grants(origin: &SpecOrigin) -> bool {
    matches!(origin, SpecOrigin::Repo(_))
}

/// The classes of [NET-166]: who wrote the package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageClass {
    /// It and its whole closure come from pinned upstream commits.
    Registry,
    /// Anything else.
    Workspace,
}

/// Every spec `spec` needs to build and to run: its build and runtime
/// dependencies and the build that breaks its cycle, transitively, and
/// itself.
fn closure(graph: &Graph, spec: &BuildSpecRef, into: &mut BTreeSet<BuildSpecRef>) {
    if !into.insert(*spec) {
        return;
    }
    let build = graph.get(spec).expect("a member of the graph");
    for dep in &build.build_deps {
        match dep {
            BuildDep::Build(bsr) => closure(graph, bsr, into),
            BuildDep::Subset(subset) => closure(graph, &subset.from, into),
            BuildDep::Source(_) | BuildDep::Local { .. } => {}
        }
    }
    for dep in &build.runtime_deps {
        closure(graph, dep.bsr(), into);
    }
    if let Some(breaker) = &build.replace_on_cycle {
        closure(graph, breaker, into);
    }
}

/// Classes `spec` (NET-166). The origin is the layer that defined each spec,
/// so a name a workspace shadows is workspace, and so is a registry package
/// over a workspace dependency, whose code runs in its build.
#[must_use]
pub fn package_class(graph: &Graph, spec: &BuildSpecRef) -> PackageClass {
    let mut members = BTreeSet::new();
    closure(graph, spec, &mut members);
    let all_earn = members.iter().all(|bsr| {
        let build = graph.get(bsr).expect("a member of the graph");
        earns_grants(&build.from)
    });
    if all_earn {
        PackageClass::Registry
    } else {
        PackageClass::Workspace
    }
}

/// The host a declared source URL is fetched from, if it is fetched at all.
fn source_host(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    match parsed.scheme() {
        "http" | "https" => parsed.host_str().map(str::to_ascii_lowercase),
        "gs" => Some(common::GCS_HOST.to_string()),
        _ => None,
    }
}

/// What the table holds for one spec: the mechanical transform of its
/// Package Build Spec into its build box's reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableGrant {
    /// The declared source URLs, each in the form it is fetched in.
    pub sources: Vec<String>,
    /// The build steps get open internet: `needs.dns` or `needs.internet`,
    /// on the package or in its closure (NET-168).
    pub internet: bool,
}

/// The build grant table of `graph` (NET-165), by spec hash in hex. `graph` is
/// the client's own evaluation, at the box's creation.
/// A spec with no source to fetch and no network to use has no entry: an empty
/// namespace is all it reaches. Nor has a spec the box could write
/// ([`package_class`]), which follows the box's own rules (NET-169).
#[must_use]
pub fn build_grant_table(graph: &Graph) -> BTreeMap<String, TableGrant> {
    let mut table = BTreeMap::new();
    for (bsr, build) in graph.iter() {
        if package_class(graph, &bsr) != PackageClass::Registry {
            continue;
        }
        let sources: Vec<String> = build
            .build_deps
            .iter()
            .filter_map(|dep| match dep {
                BuildDep::Source(source) => match &source.from {
                    SourceFetch::Web { url, .. } => fetched_form(url),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        let (dns, internet) = declared_needs(graph, &bsr);
        let internet = dns || internet;
        if sources.is_empty() && !internet {
            continue;
        }
        table.insert(
            graph.spec_hash(&bsr).0.to_hex().to_string(),
            TableGrant { sources, internet },
        );
    }
    table
}

/// The URL a declared source is fetched from in a build box.
fn fetched_form(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    match parsed.scheme() {
        "http" | "https" => Some(url.to_string()),
        "gs" => common::gcs_object_url(parsed.host_str()?, parsed.path()).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::repo_spec::Repo;
    use decode::Layer;

    fn repo_origin(url: &str, rev: &str) -> SpecOrigin {
        SpecOrigin::Repo(Repo::Git {
            url: url.to_string(),
            rev: rev.to_string(),
            tracking: None,
        })
    }

    /// One file of the pinned registry commit. A graph tells its layers
    /// apart by origin, so each layer of a fixture has one of its own.
    fn registry(file: u32) -> SpecOrigin {
        repo_origin(
            "https://github.com/gominimal/pkgs",
            &format!("c0ffee{file}"),
        )
    }

    fn workspace() -> SpecOrigin {
        SpecOrigin::LocalDir {
            given: "/workbench".into(),
            absolute: "/workbench".into(),
        }
    }

    fn package(name: &str, build_deps: &str, rest: &str) -> String {
        format!(
            "let {{BuildSpec, Source, Needs, upstream, ..}} = import \"minimal.ncl\" in
             {{ name = \"{name}\", build_deps = [{build_deps}], cmd = \"\", {rest} }} | BuildSpec"
        )
    }

    fn source(url: &str) -> String {
        format!("{{url = \"{url}\", sha256 = \"aa\"}} | Source")
    }

    /// A graph of one layer per `(ncl, origin)` pair, the first the most
    /// upstream, as `Graph::new_from_chain` ingests them.
    fn graph_of(layers: Vec<(String, SpecOrigin)>) -> Graph {
        layers
            .into_iter()
            .fold(Graph::new(), |graph, (ncl, origin)| {
                let mut layer = Layer::new_for_test(ncl).expect("the layer");
                layer.origin = origin;
                graph.ingest(layer).expect("the layer ingests")
            })
    }

    /// The registry's packages, all at the pinned commit.
    fn registry_graph() -> Graph {
        let web = source("https://downloads.example.org/a.tar.gz");
        let bucket = source("gs://minimal-staging-archives/b.tar.gz");
        let tool = source("https://downloads.example.org/c.tar.gz");
        graph_of(vec![
            (package("fetched", &web, ""), registry(1)),
            (package("bucket", &bucket, ""), registry(2)),
            (
                package("tooling", &tool, "needs = { internet = {} } | Needs,"),
                registry(3),
            ),
            (package("plain", "", ""), registry(4)),
            (
                package("over-fetched", "upstream \"fetched\"", ""),
                registry(5),
            ),
        ])
    }

    fn top(graph: &Graph, name: &str) -> BuildSpecRef {
        *graph.by_name(name).expect("the package")
    }

    fn hash_of(graph: &Graph, name: &str) -> String {
        graph.spec_hash(&top(graph, name)).0.to_hex().to_string()
    }

    /// NET-167: a registry package with no `needs` has its declared sources
    /// alone, a `gs://` source in the form it is fetched in, and no internet.
    #[test]
    fn registry_build_box_reaches_only_its_declared_hosts() {
        let graph = registry_graph();
        let table = build_grant_table(&graph);
        assert_eq!(
            table[&hash_of(&graph, "fetched")],
            TableGrant {
                sources: vec!["https://downloads.example.org/a.tar.gz".to_string()],
                internet: false,
            }
        );
        assert_eq!(
            table[&hash_of(&graph, "bucket")],
            TableGrant {
                sources: vec![
                    "https://storage.googleapis.com/minimal-staging-archives/b.tar.gz".to_string()
                ],
                internet: false,
            }
        );
    }

    /// NET-168: `needs.internet` and `needs.dns` each give the build steps
    /// the internet, and so does a `needs` in the build closure.
    #[test]
    fn registry_needs_internet_build_box_gets_internet() {
        let graph = graph_of(vec![
            (
                package("tooling", "", "needs = { internet = {} } | Needs,"),
                registry(1),
            ),
            (
                package("naming", "", "needs = { dns = {} } | Needs,"),
                registry(2),
            ),
            (
                package("over-naming", "upstream \"naming\"", ""),
                registry(3),
            ),
        ]);
        let table = build_grant_table(&graph);
        for name in ["tooling", "naming", "over-naming"] {
            assert!(table[&hash_of(&graph, name)].internet, "{name}");
        }
    }

    /// NET-165: a package with no source and no network has no entry.
    #[test]
    fn package_with_nothing_to_reach_has_no_entry() {
        let graph = registry_graph();
        let table = build_grant_table(&graph);
        assert!(!table.contains_key(&hash_of(&graph, "plain")));
    }

    /// NET-165: the table holds every package at the pinned commits, not only
    /// what a box declares, because `min add` in a running box looks up a
    /// package nothing declared. Each entry is keyed by spec hash alone, so a
    /// lookup carries no name, host or rule.
    #[test]
    fn build_table_reads_the_pinned_commit_only() {
        let graph = registry_graph();
        let table = build_grant_table(&graph);
        assert_eq!(table.len(), 3, "{table:?}");
        assert!(table.contains_key(&hash_of(&graph, "tooling")));
        assert!(!table.contains_key(&"0".repeat(64)));
    }

    /// NET-166: a package a project writes under a registry's name is not
    /// the registry's. The origin decides, so it has no entry, and its hash
    /// is not the registry's either.
    #[test]
    fn workspace_shadow_of_a_registry_name_is_workspace() {
        let planted = source("https://elsewhere.example/data");
        let graph = graph_of(vec![(package("fetched", &planted, ""), workspace())]);
        assert_eq!(
            package_class(&graph, &top(&graph, "fetched")),
            PackageClass::Workspace
        );
        assert!(build_grant_table(&graph).is_empty());

        let pinned = build_grant_table(&registry_graph());
        assert!(!pinned.contains_key(&hash_of(&graph, "fetched")));
    }

    /// NET-166: which origins earn grants is decided in one place. Any
    /// upstream or sideload does. A spec a box can write does not.
    #[test]
    fn an_origin_earns_grants_only_as_the_predicate_says() {
        assert!(earns_grants(&registry(1)));
        assert!(earns_grants(&repo_origin(
            "https://github.com/another/pkgs",
            "c0ffee"
        )));
        assert!(!earns_grants(&workspace()));
        assert!(!earns_grants(&SpecOrigin::Inline));
    }

    /// NET-166: `min` makes the table once, from the pin a person set outside
    /// the box. A box that edits `[upstream]` or its pin evaluates other specs,
    /// and their hashes are not in the table, however that edit reaches the
    /// build. Only a person's own creation of a box reads a new pin.
    #[test]
    fn a_box_editing_its_upstream_gets_no_grant() {
        let table = build_grant_table(&registry_graph());

        let elsewhere = source("https://elsewhere.example/a.tar.gz");
        let edited = graph_of(vec![(
            package("fetched", &elsewhere, ""),
            repo_origin("https://github.com/another/pkgs", "c0ffee"),
        )]);
        assert!(!table.contains_key(&hash_of(&edited, "fetched")));

        let same_host = source("https://downloads.example.org/other.tar.gz");
        let repinned = graph_of(vec![(package("fetched", &same_host, ""), registry(9))]);
        assert!(!table.contains_key(&hash_of(&repinned, "fetched")));

        // A spec the edit leaves identical is the spec the person pinned.
        let web = source("https://downloads.example.org/a.tar.gz");
        let unchanged = graph_of(vec![(package("fetched", &web, ""), registry(9))]);
        assert!(table.contains_key(&hash_of(&unchanged, "fetched")));
    }

    /// NET-166: a package over a dependency a box can write is a workspace
    /// package, because that dependency's code runs in its build.
    #[test]
    fn registry_package_over_a_workspace_dep_is_workspace() {
        let graph = graph_of(vec![
            (package("planted", "", ""), workspace()),
            (
                package("over-planted", "upstream \"planted\"", ""),
                registry(1),
            ),
        ]);
        assert_eq!(
            package_class(&graph, &top(&graph, "over-planted")),
            PackageClass::Workspace
        );
        assert!(build_grant_table(&graph).is_empty());
    }

    /// NET-155: the fetch process writes where the daemon reads outputs, and
    /// the output selection then finds that one file.
    #[test]
    fn the_fetched_file_is_a_sandbox_output() {
        let to = Path::new(FETCH_TO);
        assert_eq!(to.parent(), Some(Path::new("output")));
        assert_eq!(
            to.file_name().and_then(|name| name.to_str()),
            Some(FETCHED_FILE)
        );
    }

    /// NET-170: the fetch process's sandbox holds the daemon's program, the
    /// host's libraries and trust roots, and nothing of a box: no
    /// `/workbench`, no session home, no session secret.
    #[cfg(target_os = "linux")]
    #[test]
    fn build_box_carries_no_session_data() {
        let build_box = BuildBox::on_network("/usr/bin/minimald".into(), None);
        let network = BuildNetwork::new(|| Arc::new(sandbox::NoNet) as Arc<dyn sandbox::Network>);
        let config = build_box.fetch_config("pkg", &network);
        assert_eq!(
            config.read_only_host_paths,
            FETCH_HOST_PATHS.map(PathBuf::from)
        );
        assert_eq!(
            config.read_only_files,
            [(
                PathBuf::from("/usr/bin/minimald"),
                FETCH_PROGRAM.to_string()
            )]
        );
    }

    /// NET-155: a failed fetch's message keeps the error but strips the
    /// credentials and the query from any URL the error quotes.
    #[test]
    fn source_fetch_failure_strips_url_credentials() {
        assert_eq!(
            fetch_failure(
                "error sending request for url (https://user:secret@host/x?sig=abc)",
                "the sandbox's own error"
            ),
            "error sending request for url (https://host/x)"
        );
    }

    /// NET-155: a fetch process that wrote nothing fails with the sandbox's
    /// error, its URLs stripped too, never with an empty message.
    #[test]
    fn source_fetch_failure_with_no_output_keeps_the_sandbox_error() {
        assert_eq!(
            fetch_failure(
                "",
                "exec /fetcher failed for https://user:secret@host/x?sig=abc"
            ),
            "exec /fetcher failed for https://host/x"
        );
        assert_eq!(fetch_failure("  \n", "killed"), "killed");
    }

    /// NET-155: a build's own `needs` decide its network, and a `needs` in
    /// its build closure counts, until the registry lists its hosts.
    #[test]
    fn declared_needs_reads_the_spec_and_its_runtime_deps() {
        let graph = graph_of(vec![
            (
                package("tool", "", "needs = { dns = {} } | Needs,"),
                registry(1),
            ),
            (package("plain", "", ""), registry(2)),
            (
                package("over-tool", "", "runtime_deps = [upstream \"tool\"],"),
                registry(3),
            ),
        ]);
        assert_eq!(
            declared_needs(&graph, &top(&graph, "plain")),
            (false, false)
        );
        assert_eq!(declared_needs(&graph, &top(&graph, "tool")), (true, false));
        assert_eq!(
            declared_needs(&graph, &top(&graph, "over-tool")),
            (true, false)
        );
    }
}
