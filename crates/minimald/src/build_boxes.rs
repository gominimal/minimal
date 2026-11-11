//! The build boxes of a box (NET-155, NET-169): where its package builds run.
//!
//! A build for a box runs in a build box. When it needs the network it asks
//! the host side by spec hash alone (NET-165). The host side answers from the
//! table `min` filed at the box's creation, and a hash the table does not hold
//! follows the requesting box's own rules: a build box on one of the box's
//! task addresses, or no network at all when those rules admit nothing.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, OnceLock, PoisonError};

use tokio::sync::Mutex;

/// The build boxes running now, by requesting box id then package. A build
/// box keeps no record (BOX-186), so this is all that lists it (NET-171).
static RUNNING: LazyLock<
    std::sync::Mutex<HashMap<String, BTreeMap<String, minimald_rpc::RunningBuildBox>>>,
> = LazyLock::new(Default::default);

/// The build boxes running for the box `box_id`, by package.
pub(crate) fn running_build_boxes(box_id: &str) -> Vec<minimald_rpc::RunningBuildBox> {
    RUNNING
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(box_id)
        .map(|running| running.values().cloned().collect())
        .unwrap_or_default()
}

/// The daemon's own program, which a build box's fetch process runs. In the
/// VM a sandbox cannot exec the running binary's path, so it runs the staged
/// copy `nsenter` runs.
fn fetch_program() -> PathBuf {
    crate::nsenter::shim_exe()
        .map(std::path::Path::to_path_buf)
        .or_else(|| std::env::current_exe().ok())
        .unwrap_or_else(|| PathBuf::from("/proc/self/exe"))
}

/// The file a host with no VM keeps a box's table in, under the daemon's own
/// state, which no box can reach.
fn table_path(state_dir: &Path, id: boxes::SessionId) -> PathBuf {
    state_dir.join("build-tables").join(format!("{id}.json"))
}

/// Files a box's table on a host with no VM. The table is written to a
/// file of its own beside it, readable by this user alone, and renamed into
/// place, so a lookup reads the old table or the new one, whole.
pub(crate) fn file_table(
    state_dir: &Path,
    id: boxes::SessionId,
    table: &minimald_rpc::BuildGrantTable,
) -> std::io::Result<()> {
    use std::io::Write as _;

    let path = table_path(state_dir, id);
    let dir = path.parent().unwrap_or(state_dir);
    std::fs::create_dir_all(dir)?;
    let bytes = serde_json_lenient::to_vec(table).map_err(std::io::Error::other)?;
    let mut file = tempfile::NamedTempFile::new_in(dir)?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    file.persist(&path).map_err(|error| error.error)?;
    Ok(())
}

/// Reads the table filed for the box `id` on a host with no VM: `None` when
/// none was filed. A table that cannot be read or parsed is said as a warn
/// line and reads as none, so the build follows the box's own rules.
fn read_table(state_dir: &Path, id: boxes::SessionId) -> Option<minimald_rpc::BuildGrantTable> {
    let path = table_path(state_dir, id);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            tracing::warn!(
                box_id = %id,
                path = %path.display(),
                %error,
                "could not read the box's build table; its builds follow its own rules"
            );
            return None;
        }
    };
    match serde_json_lenient::from_slice(&bytes) {
        Ok(table) => Some(table),
        Err(error) => {
            tracing::warn!(
                box_id = %id,
                path = %path.display(),
                %error,
                "the box's build table does not parse; its builds follow its own rules"
            );
            None
        }
    }
}

/// Ends a box's table: the box is gone.
pub(crate) async fn drop_table(
    state_dir: &Path,
    id: boxes::SessionId,
    switch: &tokio::sync::Mutex<crate::net::SwitchClient>,
) {
    drop(std::fs::remove_file(table_path(state_dir, id)));
    let control = crate::box_actor::switch_control_of(switch).await;
    crate::net::listeners::drop_build_table(&control, id).await;
}

/// What the host side answered for one build.
#[derive(Debug, Clone)]
struct Granted {
    /// The row to close. Empty on a host with no VM, where the network ends
    /// with the process on it.
    row: String,
    egress: boxes::EgressPolicy,
}

#[derive(Debug)]
struct Shared {
    record: boxes::Record,
    switch: Arc<Mutex<crate::net::SwitchClient>>,
    deny_all_opt_out: bool,
    state_dir: PathBuf,
    /// The network of the builds on the box's own rules, which share its
    /// task addresses and so its room.
    requester: OnceLock<Option<op::BuildNetwork>>,
}

/// The build boxes of one box.
#[derive(Debug)]
pub(crate) struct BoxBuildBoxes(Arc<Shared>);

impl BoxBuildBoxes {
    /// The build boxes of the box `record`.
    pub(crate) fn new(
        record: boxes::Record,
        switch: Arc<Mutex<crate::net::SwitchClient>>,
        deny_all_opt_out: bool,
        state_dir: PathBuf,
    ) -> Self {
        Self(Arc::new(Shared {
            record,
            switch,
            deny_all_opt_out,
            state_dir,
            requester: OnceLock::new(),
        }))
    }
}

impl Shared {
    fn box_name(&self) -> String {
        record_name(&self.record)
    }

    /// The box's effective egress, `None` when it allows everything.
    fn requester_egress(&self) -> Option<boxes::EgressPolicy> {
        crate::box_actor::effective_egress_section(
            &self.record.policy,
            self.record.network,
            boxes::EGRESS_DEFAULT_PHASE,
            self.deny_all_opt_out,
        )
    }

    /// The network of a build on the box's own rules (NET-169). `None` when
    /// those rules admit no destination: a `none` box, a deny-all box, and
    /// so a build that needs the network is refused before any packet.
    fn requester_network(&self) -> Option<op::BuildNetwork> {
        self.requester
            .get_or_init(|| {
                if self.record.network == boxes::NetworkMode::NoNet {
                    return None;
                }
                let egress = self.requester_egress();
                if crate::net::classifier::verdict_of(egress.as_ref())
                    == sandbox::config::Verdict::Deny
                {
                    return None;
                }
                let record = self.record.clone();
                let switch = Arc::clone(&self.switch);
                Some(op::BuildNetwork::new(move || {
                    Arc::new(RequesterBuildNetwork {
                        inner: crate::net::provider::task_network_for(
                            boxes::NetworkMode::OwnIp,
                            &switch,
                            &format!("{}-build", record_name(&record)),
                            egress
                                .clone()
                                .map(|section| boxes::BoxPolicy::new(Some(section), None)),
                            record.task_addresses.clone(),
                        ),
                        record: record.clone(),
                        switch: Arc::clone(&switch),
                    }) as Arc<dyn sandbox::Network>
                }))
            })
            .clone()
    }

    /// Asks the host side about `spec_hash` (NET-165): the VM host daemon, or
    /// on a host with no VM the table this daemon holds.
    async fn ask_host(&self, spec_hash: &str) -> Option<(Granted, Vec<std::net::Ipv4Addr>)> {
        let control = crate::box_actor::switch_control_of(&self.switch).await;
        match crate::net::listeners::open_build_grant(&control, self.record.id, spec_hash).await {
            crate::net::listeners::BuildGrantAnswer::Opened(opened) => Some((
                Granted {
                    row: opened.grant_row,
                    egress: opened.egress,
                },
                opened.task_addresses,
            )),
            crate::net::listeners::BuildGrantAnswer::NoGrant => None,
            crate::net::listeners::BuildGrantAnswer::NoDoor => {
                let table = read_table(&self.state_dir, self.record.id)?;
                let grant = table.get(spec_hash)?;
                let hosts = if grant.internet {
                    std::collections::BTreeSet::new()
                } else {
                    common::source_hosts(&grant.sources).await
                };
                Some((
                    Granted {
                        row: String::new(),
                        egress: minimald_rpc::build_box_egress(&hosts, grant.internet),
                    },
                    Vec::new(),
                ))
            }
        }
    }
}

fn record_name(record: &boxes::Record) -> String {
    record.name.clone().unwrap_or_else(|| record.id.to_string())
}

/// The reach of one build box: a grant when the host side gives one, and
/// otherwise the box's own rules.
#[derive(Debug)]
struct BoxReach {
    shared: Arc<Shared>,
    package: String,
    /// The build's declared dependencies, for its Box Spec.
    packages: Vec<String>,
    spec_hash: Option<String>,
    granted: OnceLock<Granted>,
}

impl BoxReach {
    /// The network of a grant. Each process attaches at the row's addresses
    /// under the rules the host side answered with, and the row bounds them.
    fn granted_network(
        &self,
        egress: boxes::EgressPolicy,
        addresses: Vec<std::net::Ipv4Addr>,
    ) -> op::BuildNetwork {
        let switch = Arc::clone(&self.shared.switch);
        let name = format!("{}-build", self.package);
        op::BuildNetwork::new(move || {
            crate::net::provider::task_network_for(
                boxes::NetworkMode::OwnIp,
                &switch,
                &name,
                Some(boxes::BoxPolicy::new(Some(egress.clone()), None)),
                addresses.clone(),
            )
        })
    }
}

impl op::BuildReach for BoxReach {
    fn open(&self) -> op::ReachFuture<'_, Option<op::BuildNetwork>> {
        Box::pin(async move {
            let answer = match &self.spec_hash {
                Some(spec_hash) => self.shared.ask_host(spec_hash).await,
                None => None,
            };
            let Some((granted, addresses)) = answer else {
                let network = self.shared.requester_network();
                let egress = if network.is_some() {
                    self.shared.requester_egress()
                } else {
                    Some(no_egress())
                };
                self.log_spec(false, egress);
                return network;
            };
            self.log_spec(true, Some(granted.egress.clone()));
            note_reach(&self.shared.record.id.to_string(), &self.package, &granted);
            let network = self.granted_network(granted.egress.clone(), addresses);
            drop(self.granted.set(granted));
            Some(network)
        })
    }

    fn admits_source(&self, host: &str) -> bool {
        self.granted.get().is_some()
            || crate::net::dns_gate::admits_name(self.shared.requester_egress().as_ref(), host)
    }

    fn has_no_network(&self) -> bool {
        self.shared.record.network == boxes::NetworkMode::NoNet
    }

    fn close(&self) -> op::ReachFuture<'_, ()> {
        Box::pin(async move {
            note_no_network(&self.shared.record.id.to_string(), &self.package);
            let Some(granted) = self.granted.get().filter(|granted| !granted.row.is_empty()) else {
                return;
            };
            let control = crate::box_actor::switch_control_of(&self.shared.switch).await;
            crate::net::listeners::close_build_grant(&control, &granted.row).await;
        })
    }
}

/// An egress that admits no destination.
fn no_egress() -> boxes::EgressPolicy {
    minimald_rpc::build_box_egress(&std::collections::BTreeSet::new(), false)
}

impl BoxReach {
    /// Logs the build box's Box Spec, with the reach the host side decided.
    fn log_spec(&self, granted: bool, egress: Option<boxes::EgressPolicy>) {
        let spec = boxes::BuildBoxSpec::derive(
            self.shared.record.id,
            self.package.clone(),
            self.packages.clone(),
            egress,
        );
        tracing::info!(
            box_name = %self.shared.box_name(),
            granted,
            ?spec,
            "opened the network of a build box",
        );
    }
}

/// Shows the reach a running build box was granted (NET-171).
fn note_reach(box_id: &str, package: &str, granted: &Granted) {
    let mut all = RUNNING.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(running) = all.get_mut(box_id).and_then(|boxes| boxes.get_mut(package)) {
        running.egress = Some(granted.egress.clone());
        running.granted = true;
    }
}

/// Shows that a running build box has no network from here on (NET-171): its
/// steps run with no address.
fn note_no_network(box_id: &str, package: &str) {
    let mut all = RUNNING.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(running) = all.get_mut(box_id).and_then(|boxes| boxes.get_mut(package)) {
        running.no_network = true;
    }
}

impl op::BuildBoxes for BoxBuildBoxes {
    fn build_box(
        &self,
        package: &str,
        packages: Vec<String>,
        spec_hash: Option<&common::SpecHash>,
    ) -> op::BuildBox {
        op::BuildBox::new(
            fetch_program(),
            Arc::new(BoxReach {
                shared: Arc::clone(&self.0),
                package: package.to_string(),
                packages,
                spec_hash: spec_hash.map(|hash| hash.0.to_hex().to_string()),
                granted: OnceLock::new(),
            }),
        )
    }

    fn note_running(&self, package: &str, _spec_hash: &common::SpecHash, running: bool) {
        let box_id = self.0.record.id.to_string();
        let mut all = RUNNING.lock().unwrap_or_else(PoisonError::into_inner);
        if running {
            tracing::info!(box_name = %self.0.box_name(), package, "a build box started");
            all.entry(box_id).or_default().insert(
                package.to_string(),
                minimald_rpc::RunningBuildBox {
                    package: package.to_string(),
                    egress: self.0.requester_egress(),
                    granted: false,
                    no_network: false,
                },
            );
        } else if let Some(running) = all.get_mut(&box_id) {
            running.remove(package);
            if running.is_empty() {
                all.remove(&box_id);
            }
        }
    }
}

/// The network of one build on the box's own rules. Before each plan it asks,
/// as a task run does, whether the box's host-side row still stands, so the
/// build never attaches under another box's row.
struct RequesterBuildNetwork {
    record: boxes::Record,
    switch: Arc<Mutex<crate::net::SwitchClient>>,
    inner: Arc<dyn sandbox::Network>,
}

impl std::fmt::Debug for RequesterBuildNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequesterBuildNetwork")
            .field("box_id", &self.record.id)
            .finish_non_exhaustive()
    }
}

impl sandbox::Network for RequesterBuildNetwork {
    fn plan(&self) -> sandbox::PlanFuture<'_> {
        Box::pin(async move {
            crate::exec::ensure_task_rows_stand(&self.record, &self.switch)
                .await
                .map_err(sandbox::NetworkError::new)?;
            self.inner.plan().await
        })
    }

    fn attach(&self, spawned: sandbox::Spawned) -> sandbox::AttachFuture<'_> {
        self.inner.attach(spawned)
    }

    fn abandon(&self) -> sandbox::AbandonFuture<'_> {
        self.inner.abandon()
    }
}

/// The body of a build box's fetch process (`minimald __build-fetch <url>
/// <sha256> <file>`): downloads one URL into one file, in the namespace the
/// process runs in. The caller checks the hash again.
///
/// # Errors
///
/// The arguments are not three, or the download failed.
pub fn fetch_main(args: Vec<std::ffi::OsString>) -> Result<(), String> {
    let [url, sha256, out] = args.as_slice() else {
        return Err(format!(
            "{} takes a URL, a sha256 and a file",
            op::build_box::BUILD_FETCH_SUBCOMMAND
        ));
    };
    let (Some(url), Some(sha256)) = (url.to_str(), sha256.to_str()) else {
        return Err("the URL or the sha256 is not unicode".to_string());
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime
        .block_on(common::fetch_to_file(
            url,
            sha256,
            std::path::Path::new(out),
        ))
        .map_err(|e| format!("{e:#}"))
}

#[cfg(test)]
#[path = "build_boxes/tests.rs"]
mod tests;
