//! The client's half of build boxes (NET-165, NET-166): the trust root.
//!
//! At a box's creation `min` evaluates the project's upstreams on this machine,
//! at the pins in its own file, and makes the box's table. On a VM-backed host
//! the table goes to the VM host daemon on the host's control socket, which the
//! guest cannot write. On a host with no VM it goes to the daemon. A box asks by
//! spec hash alone, so nothing it changes later reaches the table.
//!
//! Nothing here stops an activation. A box with no table builds under its own
//! rules, and a refusal says so when a build needs more.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use minimald_rpc::{
    BoxControlReply, BoxControlRequest, BuildGrant, BuildGrantTable, Errorable,
    FileBuildTableRequest, PrepareBuildBoxes, PrepareBuildBoxesRequest, PrepareBuildBoxesResponse,
};

use crate::GlobalArgs;

/// The most bytes of grants in one filing: the host's control socket takes a
/// request line of at most 64 KiB, and a whole registry's table is longer.
const FILING_BYTES: usize = 48 * 1024;

/// The stack of the thread that evaluates the project: a whole registry
/// recurses past a runtime thread's stack.
const EVALUATION_STACK: usize = 128 * 1024 * 1024;

/// How long a start waits for the project's evaluation. An evaluation that
/// has to fetch an upstream can take longer, and the start does not wait for
/// it: the box gets no table, and its builds follow its own rules. Nothing
/// files that table later.
const EVALUATION_BOUND: std::time::Duration = std::time::Duration::from_secs(5);

/// What this activation knows about the box it prepares.
pub(crate) struct BuildBoxActivation<'a> {
    pub(crate) global: &'a GlobalArgs,
    pub(crate) session_id: boxes::SessionId,
    pub(crate) project_dir: PathBuf,
    /// The host's control socket, on a VM-backed host.
    pub(crate) control_sock: Option<PathBuf>,
    /// The task addresses of the box's own build row, if it has one.
    pub(crate) task_addresses: Vec<std::net::Ipv4Addr>,
    /// The box's network mode. A `none` box gets no table.
    pub(crate) network: boxes::NetworkMode,
}

/// Makes the box's table and hands it to the host side, before any process of
/// the box exists.
pub(crate) async fn prepare_build_boxes(
    client: &mut minimal_client::Client,
    activation: BuildBoxActivation<'_>,
) {
    prepare_build_boxes_with(activation, async |request| {
        client.oneshot_rpc::<PrepareBuildBoxes>(request).await
    })
    .await;
}

/// [`prepare_build_boxes`], with `send` to put the `PrepareBuildBoxes`
/// request to the daemon.
async fn prepare_build_boxes_with(
    activation: BuildBoxActivation<'_>,
    send: impl AsyncFnOnce(
        PrepareBuildBoxesRequest,
    ) -> anyhow::Result<Errorable<PrepareBuildBoxesResponse>>,
) {
    let started = std::time::Instant::now();
    let table = box_table(
        activation.network,
        EVALUATION_BOUND,
        table_of_project(&activation),
    )
    .await;
    tracing::info!(
        grants = table.len(),
        elapsed_ms = started.elapsed().as_millis(),
        "made the box's build table"
    );
    let table = hand_over(
        activation.control_sock.as_deref(),
        activation.session_id,
        activation.network == boxes::NetworkMode::NoNet,
        table,
    )
    .await;
    let prepared = send(PrepareBuildBoxesRequest {
        session_id: activation.session_id,
        task_addresses: activation.task_addresses,
        table,
    })
    .await;
    match prepared {
        Ok(Errorable::Ok(_)) => {}
        Ok(Errorable::Err { error }) => {
            tracing::info!(%error, "the daemon did not take the box's build table");
        }
        Err(error) => tracing::info!(error = %format!("{error:#}"), "could not reach the daemon"),
    }
}

/// Asks the VM host daemon to register the row of the builds of the box
/// `box_id` on `host` when the daemon reports the box has none (NET-169): a
/// host-address box an earlier `min` created, or one whose registration
/// failed at its start. The VM host daemon takes the row's rules from those
/// it holds for the box, and the daemon gets the row's addresses. No table is
/// filed: the box's builds follow its own rules. A box with a row, or one on
/// a host with no VM, asks nothing. Nothing here stops the command that
/// called it.
pub(crate) async fn register_missing_build_row(
    host: &crate::cmd::list::LocalHost,
    box_id: boxes::SessionId,
) {
    if host.provider != crate::cmd::list::LOCAL_MINVMD_PROVIDER {
        return;
    }
    let mut client = match super::address::box_host_client(host).await {
        Ok(client) => client,
        Err(error) => {
            tracing::info!(error = %format!("{error:#}"), "could not reach the daemon");
            return;
        }
    };
    let shown = match client
        .oneshot_rpc::<minimald_rpc::ShowBox>(minimald_rpc::ShowBoxRequest { id: box_id })
        .await
    {
        Ok(Errorable::Ok(shown)) => shown,
        Ok(Errorable::Err { error }) => {
            tracing::info!(%error, "could not read the box");
            return;
        }
        Err(error) => {
            tracing::info!(error = %format!("{error:#}"), "could not reach the daemon");
            return;
        }
    };
    register_missing_build_row_with(
        super::vm_host::control_sock_beside(&host.sock).as_deref(),
        box_id,
        &shown,
        async |request| client.oneshot_rpc::<PrepareBuildBoxes>(request).await,
    )
    .await;
}

/// [`register_missing_build_row`] for the box `shown`, with `control_sock`
/// the VM host daemon's and `send` to put the `PrepareBuildBoxes` request to
/// the daemon. Returns whether the row was registered.
async fn register_missing_build_row_with(
    control_sock: Option<&Path>,
    box_id: boxes::SessionId,
    shown: &minimald_rpc::ShowBoxResponse,
    send: impl AsyncFnOnce(
        PrepareBuildBoxesRequest,
    ) -> anyhow::Result<Errorable<PrepareBuildBoxesResponse>>,
) -> bool {
    let (true, Some(sock)) = (shown.missing_build_row, control_sock) else {
        return false;
    };
    let request = BoxControlRequest::RegisterBuildRow(minimald_rpc::RegisterBuildRowRequest {
        session_id: box_id,
    });
    let asked = minimal_client::box_registration::control_request_with_vm_host(sock, request);
    let task_addresses =
        match tokio::time::timeout(minimal_client::box_registration::BOX_CONTROL_TIMEOUT, asked)
            .await
        {
            Ok(Ok(BoxControlReply::Registered(registered))) => registered.task_addresses,
            Ok(Ok(reply)) => {
                tracing::info!(
                    ?reply,
                    "the VM host daemon registered no row for the box's builds"
                );
                return false;
            }
            Ok(Err(error)) => {
                tracing::info!(
                    error = %format!("{error:#}"),
                    "could not register the row of the box's builds"
                );
                return false;
            }
            Err(_elapsed) => {
                tracing::info!(
                    "the VM host daemon did not answer the registration of the row of the box's \
                     builds in time"
                );
                return false;
            }
        };
    if task_addresses.is_empty() {
        return false;
    }
    tracing::info!(box_id = %box_id, "registered the row of the box's builds");
    match send(PrepareBuildBoxesRequest {
        session_id: box_id,
        task_addresses,
        table: None,
    })
    .await
    {
        Ok(Errorable::Ok(_)) => {}
        Ok(Errorable::Err { error }) => {
            tracing::info!(%error, "the daemon did not take the addresses of the box's builds");
        }
        Err(error) => tracing::info!(error = %format!("{error:#}"), "could not reach the daemon"),
    }
    true
}

/// Hands `table` to the host side: on a VM-backed host, the VM host daemon
/// on `control_sock`, and the daemon gets none. On a host with no VM the
/// daemon gets it, returned here. For a box with `no_network`, the VM host
/// daemon gets no table, only the box's network mode.
async fn hand_over(
    control_sock: Option<&Path>,
    session_id: boxes::SessionId,
    no_network: bool,
    table: BuildGrantTable,
) -> Option<BuildGrantTable> {
    match control_sock {
        Some(sock) if no_network => {
            file_no_network_with_vm_host(sock, session_id).await;
            None
        }
        Some(sock) => {
            file_with_vm_host(
                sock,
                session_id,
                table,
                minimal_client::box_registration::BOX_CONTROL_TIMEOUT,
            )
            .await;
            None
        }
        None => Some(table),
    }
}

/// The table of a box whose network mode is `network`: none for a `none` box,
/// whose builds get no grant, and otherwise [`table_within`].
async fn box_table(
    network: boxes::NetworkMode,
    bound: std::time::Duration,
    evaluation: impl std::future::Future<Output = anyhow::Result<BuildGrantTable>>,
) -> BuildGrantTable {
    if network == boxes::NetworkMode::NoNet {
        return BuildGrantTable::new();
    }
    table_within(bound, evaluation).await
}

/// The table `evaluation` makes, or an empty one when it fails or takes
/// longer than `bound`. Either way the start goes on.
async fn table_within(
    bound: std::time::Duration,
    evaluation: impl std::future::Future<Output = anyhow::Result<BuildGrantTable>>,
) -> BuildGrantTable {
    match tokio::time::timeout(bound, evaluation).await {
        Ok(Ok(table)) => table,
        Ok(Err(error)) => {
            tracing::info!(error = %format!("{error:#}"), "could not evaluate the project's packages");
            BuildGrantTable::new()
        }
        Err(_elapsed) => {
            tracing::info!(
                bound = ?bound,
                "the evaluation of the project's packages took too long; the box's builds \
                 follow its own rules"
            );
            BuildGrantTable::new()
        }
    }
}

/// The table of the project at `activation.project_dir`, from `min`'s own
/// evaluation of it, for the target the box builds for: its hashes are the ones
/// the box asks with.
async fn table_of_project(activation: &BuildBoxActivation<'_>) -> anyhow::Result<BuildGrantTable> {
    let mut config = mctx::ConfigBuilder::new().with_repo_dir(&activation.project_dir);
    if let Some(dir) = &activation.global.minimal_dir {
        config = config.with_state_dir(dir).with_cache_dir(dir);
    }
    let config = config.build().context("configuring the evaluation")?;
    let (send, evaluated) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("build-table".to_string())
        .stack_size(EVALUATION_STACK)
        .spawn(move || {
            drop(send.send(evaluate_table(config)));
        })
        .context("starting the evaluation")?;
    evaluated.await.context("joining the evaluation")?
}

fn evaluate_table(config: mctx::Config) -> anyhow::Result<BuildGrantTable> {
    let mut ctx = mctx::Context::new(config).map_err(|e| anyhow::anyhow!("{e}"))?;
    let graph = ctx
        .graph_from_all_packages_with_target(common::Target::of_a_box())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(op::build_box::build_grant_table(&graph)
        .into_iter()
        .map(|(hash, grant)| {
            let grant = BuildGrant {
                sources: grant.sources,
                internet: grant.internet,
            };
            (hash, grant)
        })
        .collect())
}

/// Files `table` with the VM host daemon, waiting for its replies at most
/// `bound` in all. A part it refuses leaves those packages to the box's own
/// rules. A daemon that does not reply in time gets no further parts, and
/// the start goes on.
async fn file_with_vm_host(
    sock: &Path,
    session_id: boxes::SessionId,
    table: BuildGrantTable,
    bound: std::time::Duration,
) {
    let deadline = tokio::time::Instant::now() + bound;
    for table in filings(table) {
        let request = BoxControlRequest::FileBuildTable(FileBuildTableRequest {
            session_id,
            table,
            no_network: false,
        });
        let filed = minimal_client::box_registration::control_request_with_vm_host(sock, request);
        match tokio::time::timeout_at(deadline, filed).await {
            Ok(Ok(BoxControlReply::BuildTable { .. })) => {}
            Ok(Ok(reply)) => {
                tracing::info!(?reply, "the VM host daemon did not take a build table");
            }
            Ok(Err(error)) => {
                tracing::info!(error = %format!("{error:#}"), "could not file a build table");
            }
            Err(_elapsed) => {
                tracing::info!(
                    bound = ?bound,
                    "the VM host daemon did not answer the build table filing in time"
                );
                return;
            }
        }
    }
}

/// Files with the VM host daemon that the box `session_id` has the network
/// mode `none`, with no table, so it opens no grant for the box. A daemon
/// that does not answer in time is logged, and the start goes on.
async fn file_no_network_with_vm_host(sock: &Path, session_id: boxes::SessionId) {
    let request = BoxControlRequest::FileBuildTable(FileBuildTableRequest {
        session_id,
        table: BuildGrantTable::new(),
        no_network: true,
    });
    let filed = minimal_client::box_registration::control_request_with_vm_host(sock, request);
    match tokio::time::timeout(minimal_client::box_registration::BOX_CONTROL_TIMEOUT, filed).await {
        Ok(Ok(BoxControlReply::BuildTable { .. })) => {}
        Ok(Ok(reply)) => tracing::info!(?reply, "the VM host daemon did not take the box's mode"),
        Ok(Err(error)) => {
            tracing::info!(error = %format!("{error:#}"), "could not file the box's mode");
        }
        Err(_elapsed) => tracing::info!("the VM host daemon did not answer the box's mode in time"),
    }
}

/// `table` in parts, each under [`FILING_BYTES`] when written out.
fn filings(table: BuildGrantTable) -> Vec<BuildGrantTable> {
    let mut filings = Vec::new();
    let mut part = BuildGrantTable::new();
    let mut bytes = 0;
    for (hash, grant) in table {
        let size = hash.len()
            + 64
            + grant
                .sources
                .iter()
                .map(|source| source.len() + 3)
                .sum::<usize>();
        if bytes + size > FILING_BYTES && !part.is_empty() {
            filings.push(std::mem::take(&mut part));
            bytes = 0;
        }
        bytes += size;
        part.insert(hash, grant);
    }
    if !part.is_empty() {
        filings.push(part);
    }
    filings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NET-165: a whole registry's table reaches the host in parts that each
    /// fit its control socket's request line, and no grant is lost.
    #[test]
    fn a_long_table_files_under_the_request_line_limit() {
        let table: BuildGrantTable = (0..4000)
            .map(|at| {
                let grant = BuildGrant {
                    sources: vec![format!("https://downloads.example.org/{at}/pkg.tar.gz")],
                    internet: false,
                };
                (format!("{at:064x}"), grant)
            })
            .collect();
        let parts = filings(table.clone());
        assert!(parts.len() > 1);
        for part in &parts {
            let request = BoxControlRequest::FileBuildTable(FileBuildTableRequest {
                session_id: boxes::SessionId::mint(),
                table: part.clone(),
                no_network: false,
            });
            let line = serde_json_lenient::to_string(&request).unwrap();
            assert!(line.len() < 64 * 1024, "{}", line.len());
        }
        let joined: BuildGrantTable = parts.into_iter().flatten().collect();
        assert_eq!(joined, table);
    }

    /// NET-165: a start waits for the evaluation only up to its bound, and
    /// an evaluation that fails or runs past it leaves an empty table.
    #[tokio::test]
    async fn an_evaluation_past_its_bound_leaves_an_empty_table() {
        let bound = std::time::Duration::from_millis(50);
        let one: BuildGrantTable = [(
            "0".repeat(64),
            BuildGrant {
                sources: Vec::new(),
                internet: true,
            },
        )]
        .into();
        assert_eq!(
            table_within(bound, std::future::ready(Ok(one.clone()))).await,
            one
        );
        assert!(
            table_within(bound, std::future::ready(Err(anyhow::anyhow!("no graph"))))
                .await
                .is_empty()
        );
        let started = std::time::Instant::now();
        assert!(table_within(bound, std::future::pending()).await.is_empty());
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    fn one_grant() -> BuildGrantTable {
        [(
            "1".repeat(64),
            BuildGrant {
                sources: vec!["https://downloads.example.org/a.tar.gz".to_string()],
                internet: false,
            },
        )]
        .into()
    }

    /// A VM host on `sock` that answers each request with `reply` and keeps
    /// the requests it took.
    async fn fake_vm_host(
        sock: &Path,
        reply: BoxControlReply,
    ) -> std::sync::Arc<std::sync::Mutex<Vec<BoxControlRequest>>> {
        use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::UnixListener::bind(sock).unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let kept = std::sync::Arc::clone(&seen);
        let reply = serde_json_lenient::to_string(&reply).unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let mut lines = tokio::io::BufReader::new(stream);
                let mut line = String::new();
                if lines.read_line(&mut line).await.is_err() {
                    return;
                }
                kept.lock()
                    .unwrap()
                    .push(serde_json_lenient::from_str(line.trim()).unwrap());
                let mut writer = lines.into_inner();
                drop(writer.write_all(format!("{reply}\n").as_bytes()).await);
            }
        });
        seen
    }

    /// NET-165: on a VM-backed host the table goes to the VM host daemon and
    /// the daemon gets none. On a host with no VM the daemon gets it whole.
    #[tokio::test]
    async fn the_table_goes_to_the_vm_host_or_to_the_daemon() {
        let id = boxes::SessionId::mint();
        assert_eq!(
            hand_over(None, id, false, one_grant()).await,
            Some(one_grant())
        );

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        let seen = fake_vm_host(&sock, BoxControlReply::BuildTable { build_table: true }).await;
        assert_eq!(hand_over(Some(&sock), id, false, one_grant()).await, None);
        let seen = seen.lock().unwrap();
        let [BoxControlRequest::FileBuildTable(filed)] = seen.as_slice() else {
            panic!("one filing: {seen:?}");
        };
        assert_eq!(filed.session_id, id);
        assert_eq!(filed.table, one_grant());
    }

    /// NET-165: a VM host that cannot be reached leaves the box with no
    /// table, and the start goes on.
    #[tokio::test]
    async fn an_unreachable_vm_host_files_nothing_and_the_start_goes_on() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("absent.sock");
        assert_eq!(
            hand_over(Some(&sock), boxes::SessionId::mint(), false, one_grant()).await,
            None
        );
    }

    /// NET-165: a VM host that takes the filing and never answers holds the
    /// start only up to the filing's bound.
    #[tokio::test]
    async fn a_silent_vm_host_holds_the_filing_only_to_its_bound() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("silent.sock");
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        let held = tokio::spawn(async move {
            let mut open = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                open.push(stream);
            }
        });
        let started = std::time::Instant::now();
        file_with_vm_host(
            &sock,
            boxes::SessionId::mint(),
            one_grant(),
            std::time::Duration::from_millis(100),
        )
        .await;
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        held.abort();
    }

    /// NET-169: only a host-address box on a VM-backed host registers a
    /// row for its builds, and only when its rules admit something. The
    /// row carries the box's own egress and returns its task addresses. A
    /// refused registration leaves no row and the start goes on.
    #[tokio::test]
    async fn a_host_address_box_holds_a_build_row_on_its_own_rules() {
        let id = boxes::SessionId::mint();
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        let addresses = vec![std::net::Ipv4Addr::new(192, 168, 127, 40)];
        let seen = fake_vm_host(
            &sock,
            BoxControlReply::Registered(minimald_rpc::RegisteredBox {
                switch_address: std::net::Ipv4Addr::new(192, 168, 127, 39),
                loopback_address: std::net::Ipv4Addr::new(127, 0, 0, 39),
                box_id: boxes::BoxId::mint(),
                task_addresses: addresses.clone(),
            }),
        )
        .await;
        let hold = |sock: Option<&Path>, mode, declared: Option<boxes::EgressPolicy>| {
            let sock = sock.map(Path::to_path_buf);
            async move {
                crate::hold_requester_build_row(sock.as_deref(), id, mode, declared.as_ref(), false)
                    .await
            }
        };
        let listed = boxes::EgressPolicy {
            allow_subnets: Some(Vec::new()),
            allow_dns_hosts: Some(vec!["downloads.example.org".to_string()]),
            allow_protocols: None,
            deny_subnets: None,
        };

        assert!(
            hold(None, boxes::NetworkMode::HostNet, Some(listed.clone()))
                .await
                .is_empty()
        );
        assert!(
            hold(Some(&sock), boxes::NetworkMode::OwnIp, Some(listed.clone()))
                .await
                .is_empty()
        );
        assert!(
            hold(
                Some(&sock),
                boxes::NetworkMode::HostNet,
                Some(boxes::EgressPolicy::deny_all())
            )
            .await
            .is_empty()
        );
        assert!(seen.lock().unwrap().is_empty(), "nothing to register");

        assert_eq!(
            hold(
                Some(&sock),
                boxes::NetworkMode::HostNet,
                Some(listed.clone())
            )
            .await,
            addresses
        );
        let registered = seen.lock().unwrap().clone();
        let [BoxControlRequest::Register(request)] = registered.as_slice() else {
            panic!("one registration: {registered:?}");
        };
        assert_eq!(request.name, minimald_rpc::requester_build_row_name(id));
        assert_eq!(request.egress, Some(listed.clone()));
        assert!(!request.host_ip);

        let absent = dir.path().join("absent.sock");
        assert!(
            hold(Some(&absent), boxes::NetworkMode::HostNet, Some(listed))
                .await
                .is_empty()
        );
    }

    /// NET-165: a box with network mode `none` gets no table: its project
    /// is not evaluated, and the VM host daemon gets no table for it, only
    /// the box's mode.
    #[tokio::test]
    async fn a_box_with_no_network_files_no_table() {
        let bound = std::time::Duration::from_secs(5);
        let table = box_table(boxes::NetworkMode::NoNet, bound, async {
            panic!("a `none` box's project is not evaluated")
        })
        .await;
        assert!(table.is_empty());
        assert_eq!(
            box_table(
                boxes::NetworkMode::OwnIp,
                bound,
                std::future::ready(Ok(one_grant()))
            )
            .await,
            one_grant()
        );

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        let seen = fake_vm_host(&sock, BoxControlReply::BuildTable { build_table: true }).await;
        let id = boxes::SessionId::mint();
        assert_eq!(hand_over(Some(&sock), id, true, one_grant()).await, None);
        let seen = seen.lock().unwrap();
        let [BoxControlRequest::FileBuildTable(filed)] = seen.as_slice() else {
            panic!("one filing: {seen:?}");
        };
        assert_eq!(filed.session_id, id);
        assert!(filed.no_network);
        assert!(filed.table.is_empty(), "no table is filed");
    }

    /// NET-165: an empty table files nothing.
    #[test]
    fn an_empty_table_files_nothing() {
        assert!(filings(BuildGrantTable::new()).is_empty());
    }

    /// A project whose packages come from the `mctx` test packages, a
    /// directory upstream, so its evaluation reaches no network.
    fn fixture_project() -> tempfile::TempDir {
        let packages = Path::new(env!("CARGO_MANIFEST_DIR")).join("../mctx/testdata/fakepkgs");
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join("minimal.toml"),
            format!("[upstream]\ndir = {:?}\n", packages.display().to_string()),
        )
        .unwrap();
        project
    }

    fn activation<'a>(
        global: &'a GlobalArgs,
        project: &Path,
        control_sock: Option<PathBuf>,
        network: boxes::NetworkMode,
    ) -> BuildBoxActivation<'a> {
        BuildBoxActivation {
            global,
            session_id: boxes::SessionId::mint(),
            project_dir: project.to_path_buf(),
            control_sock,
            task_addresses: vec![std::net::Ipv4Addr::new(192, 168, 127, 40)],
            network,
        }
    }

    fn global_in(state: &Path) -> GlobalArgs {
        GlobalArgs {
            minimal_dir: Some(state.to_path_buf()),
            ..GlobalArgs::default()
        }
    }

    /// NET-165: `min` evaluates the project in its own directory. A project
    /// with no pinned upstream package holds no grant. A project file that
    /// does not parse is an error, so the box gets no table.
    #[tokio::test]
    async fn the_table_is_the_projects_own_evaluation() {
        let state = tempfile::tempdir().unwrap();
        let global = global_in(state.path());
        let project = fixture_project();
        let table = table_of_project(&activation(
            &global,
            project.path(),
            None,
            boxes::NetworkMode::HostNet,
        ))
        .await
        .expect("the project evaluates");
        assert!(table.is_empty(), "{table:?}");

        std::fs::write(project.path().join("minimal.toml"), "[upstream\n").unwrap();
        assert!(
            table_of_project(&activation(
                &global,
                project.path(),
                None,
                boxes::NetworkMode::HostNet,
            ))
            .await
            .is_err()
        );
    }

    /// NET-165: the daemon gets the box's task addresses and, on a host with
    /// no VM, its table. On a VM-backed host the table went to the VM host
    /// daemon, and the daemon gets none.
    #[tokio::test]
    async fn the_daemon_gets_the_addresses_and_the_native_table() {
        let state = tempfile::tempdir().unwrap();
        let global = global_in(state.path());
        let project = fixture_project();
        let sent = std::sync::Mutex::new(Vec::new());
        let stand_in = || {
            async |request: PrepareBuildBoxesRequest| {
                sent.lock().unwrap().push(request);
                Ok(Errorable::Ok(PrepareBuildBoxesResponse {}))
            }
        };

        let native = activation(&global, project.path(), None, boxes::NetworkMode::HostNet);
        let id = native.session_id;
        prepare_build_boxes_with(native, stand_in()).await;

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        fake_vm_host(&sock, BoxControlReply::BuildTable { build_table: true }).await;
        let on_vm = activation(
            &global,
            project.path(),
            Some(sock),
            boxes::NetworkMode::HostNet,
        );
        prepare_build_boxes_with(on_vm, stand_in()).await;

        let sent = sent.lock().unwrap();
        let [native, on_vm] = sent.as_slice() else {
            panic!("two requests: {sent:?}");
        };
        assert_eq!(native.session_id, id);
        assert_eq!(
            native.task_addresses,
            [std::net::Ipv4Addr::new(192, 168, 127, 40)]
        );
        assert_eq!(native.table, Some(BuildGrantTable::new()));
        assert_eq!(on_vm.table, None, "the VM host daemon has the table");
    }

    /// A read of the box `id`, with `missing` as the daemon reports it.
    fn shown(id: boxes::SessionId, missing: bool) -> minimald_rpc::ShowBoxResponse {
        let mut shown: minimald_rpc::ShowBoxResponse = serde_json_lenient::from_str(&format!(
            r#"{{"record":{{"box_id":"{id}","state":"running","project_root":"/project"}}}}"#
        ))
        .unwrap();
        shown.missing_build_row = missing;
        shown
    }

    /// NET-169: a host-address box that the daemon reports with no row for
    /// its builds asks the VM host daemon for one at its next start, naming
    /// the box and no rule, and files no table. The daemon gets the row's
    /// addresses and no table. A box with a row, or on a host with no VM,
    /// asks nothing.
    #[tokio::test]
    async fn a_box_with_no_build_row_registers_one_at_its_start() {
        let id = boxes::SessionId::mint();
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        let addresses = vec![std::net::Ipv4Addr::new(192, 168, 127, 40)];
        let seen = fake_vm_host(
            &sock,
            BoxControlReply::Registered(minimald_rpc::RegisteredBox {
                switch_address: std::net::Ipv4Addr::new(192, 168, 127, 39),
                loopback_address: std::net::Ipv4Addr::new(127, 0, 0, 39),
                box_id: boxes::BoxId::mint(),
                task_addresses: addresses.clone(),
            }),
        )
        .await;
        let sent = std::sync::Mutex::new(Vec::new());
        let stand_in = || {
            async |request: PrepareBuildBoxesRequest| {
                sent.lock().unwrap().push(request);
                Ok(Errorable::Ok(PrepareBuildBoxesResponse {}))
            }
        };

        assert!(
            !register_missing_build_row_with(Some(&sock), id, &shown(id, false), stand_in()).await
        );
        assert!(!register_missing_build_row_with(None, id, &shown(id, true), stand_in()).await);
        assert!(sent.lock().unwrap().is_empty());
        assert!(seen.lock().unwrap().is_empty());

        assert!(
            register_missing_build_row_with(Some(&sock), id, &shown(id, true), stand_in()).await
        );
        assert_eq!(
            *seen.lock().unwrap(),
            [BoxControlRequest::RegisterBuildRow(
                minimald_rpc::RegisterBuildRowRequest { session_id: id }
            )],
            "the VM host daemon is asked by box alone, and no table is filed"
        );
        let sent = sent.lock().unwrap();
        let [request] = sent.as_slice() else {
            panic!("one request: {sent:?}");
        };
        assert_eq!(request.session_id, id);
        assert_eq!(request.task_addresses, addresses);
        assert_eq!(request.table, None, "the daemon gets no table");
    }

    /// NET-169: a VM host daemon that holds no rules for the box registers
    /// no row, and the daemon is told nothing.
    #[tokio::test]
    async fn no_build_row_without_the_vm_hosts_rules() {
        let id = boxes::SessionId::mint();
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        fake_vm_host(
            &sock,
            BoxControlReply::Error {
                error: "no rules".to_string(),
            },
        )
        .await;
        let sent = std::sync::Mutex::new(Vec::new());
        let stand_in = async |request: PrepareBuildBoxesRequest| {
            sent.lock().unwrap().push(request);
            Ok(Errorable::Ok(PrepareBuildBoxesResponse {}))
        };
        assert!(
            !register_missing_build_row_with(Some(&sock), id, &shown(id, true), stand_in).await
        );
        assert!(sent.lock().unwrap().is_empty());
    }
}
