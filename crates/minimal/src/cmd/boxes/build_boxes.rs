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
    let table = match table_of_project(&activation).await {
        Ok(table) => table,
        Err(error) => {
            tracing::info!(error = %format!("{error:#}"), "could not evaluate the project's packages");
            BuildGrantTable::new()
        }
    };
    tracing::info!(
        grants = table.len(),
        elapsed_ms = started.elapsed().as_millis(),
        "made the box's build table"
    );
    let table = match &activation.control_sock {
        Some(sock) => {
            file_with_vm_host(sock, activation.session_id, table).await;
            None
        }
        None => Some(table),
    };
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

/// Files `table` with the VM host daemon. A part it refuses leaves those
/// packages to the box's own rules.
async fn file_with_vm_host(sock: &Path, session_id: boxes::SessionId, table: BuildGrantTable) {
    for table in filings(table) {
        let request =
            BoxControlRequest::FileBuildTable(FileBuildTableRequest { session_id, table });
        match minimal_client::box_registration::control_request_with_vm_host(sock, request).await {
            Ok(BoxControlReply::BuildTable { .. }) => {}
            Ok(reply) => tracing::info!(?reply, "the VM host daemon did not take a build table"),
            Err(error) => {
                tracing::info!(error = %format!("{error:#}"), "could not file a build table");
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

    /// NET-165: an empty table files nothing.
    #[test]
    fn an_empty_table_files_nothing() {
        assert!(filings(BuildGrantTable::new()).is_empty());
    }
}
