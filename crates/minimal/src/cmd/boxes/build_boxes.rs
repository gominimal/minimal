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
    BoxControlReply, BoxControlRequest, BuildGrant, BuildGrantTable, FileBuildTableRequest,
    PrepareBuildBoxes, PrepareBuildBoxesRequest,
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
/// it: the box gets no table, and its builds follow its own rules. Filing the
/// table after a timed-out evaluation is https://github.com/gominimal/minimal/issues/3728.
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
}

/// Makes the box's table and hands it to the host side, before any process of
/// the box exists.
pub(crate) async fn prepare_build_boxes(
    client: &mut minimal_client::Client,
    activation: BuildBoxActivation<'_>,
) {
    let started = std::time::Instant::now();
    let table = table_within(EVALUATION_BOUND, table_of_project(&activation)).await;
    tracing::info!(
        grants = table.len(),
        elapsed_ms = started.elapsed().as_millis(),
        "made the box's build table"
    );
    let table = hand_over(
        activation.control_sock.as_deref(),
        activation.session_id,
        table,
    )
    .await;
    let prepared = client
        .oneshot_rpc::<PrepareBuildBoxes>(PrepareBuildBoxesRequest {
            session_id: activation.session_id,
            task_addresses: activation.task_addresses,
            table,
        })
        .await;
    match prepared {
        Ok(minimald_rpc::Errorable::Ok(_)) => {}
        Ok(minimald_rpc::Errorable::Err { error }) => {
            tracing::info!(%error, "the daemon did not take the box's build table");
        }
        Err(error) => tracing::info!(error = %format!("{error:#}"), "could not reach the daemon"),
    }
}

/// Hands `table` to the host side: on a VM-backed host, the VM host daemon
/// on `control_sock`, and the daemon gets none. On a host with no VM the
/// daemon gets it, returned here.
async fn hand_over(
    control_sock: Option<&Path>,
    session_id: boxes::SessionId,
    table: BuildGrantTable,
) -> Option<BuildGrantTable> {
    match control_sock {
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
        let request =
            BoxControlRequest::FileBuildTable(FileBuildTableRequest { session_id, table });
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
        assert_eq!(hand_over(None, id, one_grant()).await, Some(one_grant()));

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        let seen = fake_vm_host(&sock, BoxControlReply::BuildTable { build_table: true }).await;
        assert_eq!(hand_over(Some(&sock), id, one_grant()).await, None);
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
            hand_over(Some(&sock), boxes::SessionId::mint(), one_grant()).await,
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

    /// NET-165: an empty table files nothing.
    #[test]
    fn an_empty_table_files_nothing() {
        assert!(filings(BuildGrantTable::new()).is_empty());
    }
}
