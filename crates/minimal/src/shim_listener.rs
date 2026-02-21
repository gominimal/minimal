//! HTTP metadata service for in-sandbox package addition (`min add`).
//!
//! Runs alongside the shell in a task sandbox. Serves an HTTP/JSON API that the
//! `/usr/bin/min` binary inside the sandbox calls, resolves packages via the DepGraph,
//! hardlinks them into the rootfs, computes env vars, and returns structured responses.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use graph::{BuildSpecRef, DepGraph, Transitives};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Debug, Serialize, Deserialize)]
pub struct AddRequest {
    pub packages: Vec<String>,
    #[serde(default)]
    pub ephemeral: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddResponse {
    pub status: String,
    #[serde(default)]
    pub added: Vec<String>,
    #[serde(default)]
    pub env: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PackageInfo {
    pub name: String,
    pub hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PackagesResponse {
    pub packages: Vec<PackageInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnvResponse {
    pub env: std::collections::HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MetaResponse {
    pub task_name: String,
    pub rootfs: String,
    pub mfile: Option<String>,
}

/// Handle to a running shim listener. Drop or call `shutdown()` to stop.
pub struct ShimHandle {
    thread: Option<std::thread::JoinHandle<()>>,
    shutdown_tx: Option<tokio::sync::watch::Sender<()>>,
}

impl ShimHandle {
    /// Signals the listener to stop and waits for the thread to finish.
    pub fn shutdown(mut self) {
        self.shutdown_tx.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for ShimHandle {
    fn drop(&mut self) {
        self.shutdown_tx.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Configuration for starting a shim listener.
pub struct ShimListenerConfig {
    /// Path to write the port file (e.g. /state/.min/port).
    pub port_file_path: PathBuf,
    /// The package dependency graph.
    pub graph: DepGraph,
    /// The local build artifact cache.
    pub cache: mctx::Cache,
    /// The mctx::Config for creating a build context if needed.
    pub mctx_config: mctx::Config,
    /// Path to the rootfs directory (base_dir/rootfs/).
    pub rootfs_path: PathBuf,
    /// Path to the state directory (visible inside sandbox as /state).
    pub state_dir: PathBuf,
    /// Path to the minimal.toml file for persistence.
    pub mfile_path: Option<PathBuf>,
    /// The task name (for updating minimal.toml).
    pub task_name: String,
    /// Set of BuildSpecRefs already present in the rootfs.
    pub initial_packages: HashSet<BuildSpecRef>,
}

/// Shared state for HTTP handlers.
struct AppState {
    config: ShimListenerConfig,
    present: Mutex<HashSet<BuildSpecRef>>,
}

/// Starts the shim listener on a background thread.
///
/// Binds to `127.0.0.1:0` (OS-assigned port), writes the port to `port_file_path`,
/// and returns a handle that can be used to shut down the listener.
pub fn start(config: ShimListenerConfig) -> ShimHandle {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());

    // Bind before spawning so we know the address
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("failed to bind TCP listener");
    let addr = listener.local_addr().expect("failed to get local addr");

    // Write port file
    if let Some(parent) = config.port_file_path.parent() {
        std::fs::create_dir_all(parent).expect("failed to create port file directory");
    }
    std::fs::write(&config.port_file_path, addr.port().to_string())
        .expect("failed to write port file");

    let port_file_path = config.port_file_path.clone();

    let state = Arc::new(AppState {
        present: Mutex::new(config.initial_packages.clone()),
        config,
    });

    let thread = std::thread::Builder::new()
        .name("shim-listener".to_string())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to create tokio runtime");

            rt.block_on(async move {
                let app = build_router(state);
                listener
                    .set_nonblocking(true)
                    .expect("failed to set non-blocking");
                let tcp_listener = tokio::net::TcpListener::from_std(listener)
                    .expect("failed to convert listener");

                info!("shim listener started on {}", addr);

                let mut shutdown_rx = shutdown_rx;
                axum::serve(tcp_listener, app)
                    .with_graceful_shutdown(async move {
                        let _ = shutdown_rx.changed().await;
                    })
                    .await
                    .expect("axum server error");

                // Cleanup port file
                let _ = std::fs::remove_file(&port_file_path);
                info!("shim listener stopped");
            });
        })
        .expect("failed to spawn shim listener thread");

    ShimHandle {
        thread: Some(thread),
        shutdown_tx: Some(shutdown_tx),
    }
}

async fn handle_add(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddRequest>,
) -> (StatusCode, Json<AddResponse>) {
    // Use spawn_blocking because process_add_impl may create a nested tokio
    // runtime via build_uncached.
    let resp = tokio::task::spawn_blocking(move || {
        let package_names: Vec<&str> = req.packages.iter().map(|s| s.as_str()).collect();
        let mut present = state.present.lock().unwrap();
        process_add_impl(package_names, req.ephemeral, &state.config, &mut present)
    })
    .await
    .unwrap();

    let status_code = if resp.status == "ok" {
        StatusCode::OK
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };

    (status_code, Json(resp))
}

async fn handle_packages(State(state): State<Arc<AppState>>) -> Json<PackagesResponse> {
    let present = state.present.lock().unwrap();
    let graph = &state.config.graph;

    let packages: Vec<PackageInfo> = present
        .iter()
        .filter_map(|bsr| {
            graph.get(bsr).map(|b| PackageInfo {
                name: b.name.clone(),
                hash: graph.spec_hash(bsr).0.to_string(),
            })
        })
        .collect();

    Json(PackagesResponse { packages })
}

async fn handle_env(State(state): State<Arc<AppState>>) -> Json<EnvResponse> {
    let present = state.present.lock().unwrap();
    let graph = &state.config.graph;

    let env = match graph.env_config_for_packages(present.iter()) {
        Ok(setup) => setup.env_vars.into_iter().collect(),
        Err(_) => Default::default(),
    };

    Json(EnvResponse { env })
}

async fn handle_meta(State(state): State<Arc<AppState>>) -> Json<MetaResponse> {
    Json(MetaResponse {
        task_name: state.config.task_name.clone(),
        rootfs: state.config.rootfs_path.to_string_lossy().into_owned(),
        mfile: state
            .config
            .mfile_path
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned()),
    })
}

fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/add", post(handle_add))
        .route("/v1/packages", get(handle_packages))
        .route("/v1/env", get(handle_env))
        .route("/v1/meta", get(handle_meta))
        .with_state(state)
}

fn process_add_impl(
    package_names: Vec<&str>,
    ephemeral: bool,
    config: &ShimListenerConfig,
    present: &mut HashSet<BuildSpecRef>,
) -> AddResponse {
    let graph = &config.graph;
    let cache = &config.cache;

    // Step 1: Resolve all requested package names to BuildSpecRefs
    let mut requested_bsrs = Vec::new();
    for name in &package_names {
        match graph.by_name(name) {
            Some(bsr) => requested_bsrs.push(*bsr),
            None => {
                return AddResponse {
                    status: "error".into(),
                    added: vec![],
                    env: Default::default(),
                    message: format!("unknown package: {}", name),
                };
            }
        }
    }

    // Step 2: Compute transitive runtime deps for all requested packages
    let transitive_deps = Transitives::for_toplevels(graph, requested_bsrs.clone(), false);

    // Step 3: Determine which packages are new (not already in rootfs)
    let new_deps: Vec<BuildSpecRef> = transitive_deps
        .keys()
        .filter(|bsr| !present.contains(bsr))
        .copied()
        .collect();

    if new_deps.is_empty() {
        // All packages already present - return current env config
        let env_result = graph.env_config_for_packages(requested_bsrs.iter());
        match env_result {
            Ok(setup) => {
                return AddResponse {
                    status: "ok".into(),
                    added: vec![],
                    env: setup.env_vars.into_iter().collect(),
                    message: format!("{} already present", package_names.join(", ")),
                };
            }
            Err(e) => {
                return AddResponse {
                    status: "error".into(),
                    added: vec![],
                    env: Default::default(),
                    message: format!("env config error: {}", e),
                };
            }
        }
    }

    // Step 4: Check cache and attempt to build/fetch uncached packages
    let mut uncached: Vec<BuildSpecRef> = Vec::new();
    for bsr in &new_deps {
        let hash = graph.spec_hash(bsr);
        if cache.read_dir(&hash).is_err() {
            uncached.push(*bsr);
        }
    }

    if !uncached.is_empty() {
        info!(
            "shim listener: building {} uncached packages",
            uncached.len()
        );
        match build_uncached(graph, &uncached, &config.mctx_config) {
            Ok(()) => {
                for bsr in &uncached {
                    let hash = graph.spec_hash(bsr);
                    if cache.read_dir(&hash).is_err() {
                        let name = graph.get(bsr).map(|b| b.name.as_str()).unwrap_or("unknown");
                        return AddResponse {
                            status: "error".into(),
                            added: vec![],
                            env: Default::default(),
                            message: format!("package '{}' could not be built or fetched", name),
                        };
                    }
                }
            }
            Err(e) => {
                return AddResponse {
                    status: "error".into(),
                    added: vec![],
                    env: Default::default(),
                    message: format!("build failed: {}", e),
                };
            }
        }
    }

    // Step 5: Hardlink new packages into rootfs
    let rootfs = &config.rootfs_path;
    let mut added_names = Vec::new();

    for bsr in &new_deps {
        let hash = graph.spec_hash(bsr);
        let cache_entry = match cache.read_dir(&hash) {
            Ok(entry) => entry,
            Err(e) => {
                let name = graph.get(bsr).map(|b| b.name.as_str()).unwrap_or("unknown");
                return AddResponse {
                    status: "error".into(),
                    added: vec![],
                    env: Default::default(),
                    message: format!("cache read failed for '{}': {}", name, e),
                };
            }
        };

        if let Err(e) = common::hardlink_dir_contents(cache_entry.path(), rootfs) {
            let name = graph.get(bsr).map(|b| b.name.as_str()).unwrap_or("unknown");
            return AddResponse {
                status: "error".into(),
                added: vec![],
                env: Default::default(),
                message: format!("hardlink failed for '{}': {}", name, e),
            };
        }

        let name = graph
            .get(bsr)
            .map(|b| b.name.clone())
            .unwrap_or_else(|| "unknown".to_string());
        added_names.push(name);
        present.insert(*bsr);
    }

    // Step 6: Compute env vars for newly added packages
    let env_result = graph.env_config_for_packages(new_deps.iter());
    let setup = match env_result {
        Ok(s) => s,
        Err(e) => {
            return AddResponse {
                status: "error".into(),
                added: vec![],
                env: Default::default(),
                message: format!("env config error: {}", e),
            };
        }
    };

    // Step 7: Create /state subdirectories
    for want_dir in &setup.state_dirs {
        let state_subdir = config.state_dir.join(want_dir);
        if let Err(e) = std::fs::create_dir_all(&state_subdir) {
            warn!("failed to create state dir {:?}: {}", state_subdir, e);
        }
    }

    // Step 8: Persist to minimal.toml if not ephemeral
    if !ephemeral && let Some(mfile_path) = &config.mfile_path {
        persist_packages_to_mfile(mfile_path, &config.task_name, &package_names);
    }

    // Step 9: Build response
    let msg = if added_names.len() == 1 {
        format!("Added {}", added_names[0])
    } else {
        format!(
            "Added {} and {} dependencies",
            package_names.join(", "),
            added_names.len().saturating_sub(package_names.len())
        )
    };

    AddResponse {
        status: "ok".into(),
        added: added_names,
        env: setup.env_vars.into_iter().collect(),
        message: msg,
    }
}

/// Attempts to build uncached packages by creating a fresh Context.
fn build_uncached(
    graph: &DepGraph,
    uncached: &[BuildSpecRef],
    mctx_config: &mctx::Config,
) -> Result<(), String> {
    // Create a mini tokio runtime for async build operations
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime creation failed: {}", e))?;

    rt.block_on(async {
        let mut ctx = mctx::Context::new(mctx_config.clone())
            .map_err(|e| format!("context creation failed: {}", e))?;

        // Create a graph scoped to the uncached packages
        let mut build_graph = graph.clone();
        build_graph.top_levels = uncached.to_vec();

        ctx.build_graph(&build_graph)
            .await
            .map_err(|e| format!("build failed: {}", e))
    })
}

/// Persists newly added packages to minimal.toml.
fn persist_packages_to_mfile(mfile_path: &Path, task_name: &str, packages: &[&str]) {
    use toml_edit::DocumentMut;

    let content = match std::fs::read_to_string(mfile_path) {
        Ok(c) => c,
        Err(e) => {
            warn!("failed to read minimal.toml for persistence: {}", e);
            return;
        }
    };

    let mut doc = match content.parse::<DocumentMut>() {
        Ok(d) => d,
        Err(e) => {
            warn!("failed to parse minimal.toml: {}", e);
            return;
        }
    };

    // Navigate to [tasks.<task_name>].packages
    let tasks = doc
        .entry("tasks")
        .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()));
    let task = tasks.as_table_mut().and_then(|t| {
        t.entry(task_name)
            .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()))
            .as_table_mut()
    });

    if let Some(task_table) = task {
        let existing = task_table
            .get("packages")
            .and_then(|p| p.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<HashSet<String>>()
            })
            .unwrap_or_default();

        let mut arr = task_table
            .get("packages")
            .and_then(|p| p.as_array())
            .cloned()
            .unwrap_or_default();

        for pkg in packages {
            if !existing.contains(*pkg) {
                arr.push(pkg.to_string());
            }
        }

        task_table.insert("packages", toml_edit::value(arr));

        if let Err(e) = std::fs::write(mfile_path, doc.to_string()) {
            warn!("failed to write minimal.toml: {}", e);
        } else {
            info!("persisted packages to minimal.toml");
        }
    } else {
        warn!(
            "could not find or create task '{}' in minimal.toml",
            task_name
        );
    }
}

/// The shell script injected into the rootfs at /usr/bin/min.
pub const MIN_SCRIPT: &str = r#"#!/bin/bash
PORT_FILE=/state/.min/port

if [ ! -f "$PORT_FILE" ]; then
  echo "error: not running in a managed minimal environment" >&2
  exit 1
fi
PORT=$(cat "$PORT_FILE")

case "$1" in
  add)
    shift
    ephemeral=false
    if [ "$1" = "--ephemeral" ]; then
      ephemeral=true; shift
    fi
    if [ $# -eq 0 ]; then
      echo "usage: min add [--ephemeral] <pkg> [pkg...]" >&2
      return 1
    fi
    exec 3<>/dev/tcp/127.0.0.1/$PORT
    printf 'add %s %s\n' "$ephemeral" "$*" >&3
    error=false
    while IFS= read -r line <&3; do
      case "$line" in
        "STATUS error") error=true ;;
        "ENV "*)  echo "export ${line#ENV }" ;;
        "MSG "*)  echo "${line#MSG }" >&2 ;;
      esac
    done
    exec 3<&-
    [ "$error" = true ] && return 1
    ;;
  *)
    echo "usage: min add [--ephemeral] <pkg> [pkg...]" >&2
    return 1
    ;;
esac
"#;

/// The bashrc snippet that wraps the min command with eval.
pub const BASHRC_SNIPPET: &str = r#"
# minimal: in-sandbox package addition
min() { eval "$(/usr/bin/min "$@")"; }
"#;

/// Injects the min script and bashrc snippet into the rootfs.
pub fn inject_shim_scripts(rootfs_path: &Path) -> Result<(), std::io::Error> {
    // Write /usr/bin/min
    let min_path = rootfs_path.join("usr/bin/min");
    if let Some(parent) = min_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&min_path, MIN_SCRIPT)?;

    // Make executable
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&min_path, std::fs::Permissions::from_mode(0o755))?;

    // Append to /etc/bashrc (or create it)
    let bashrc_path = rootfs_path.join("etc/bashrc");
    if let Some(parent) = bashrc_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut bashrc_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&bashrc_path)?;
    bashrc_file.write_all(BASHRC_SNIPPET.as_bytes())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cache::{Cache, EntryMeta, MetaInner};
    use decode::Layer;
    use graph::DepGraph;

    /// Helper: create a DepGraph and Cache with multiple test packages.
    ///
    /// Packages: zlib, expat, libffi, python (deps: zlib, expat, libffi), gcc, bash, coreutils.
    /// Each is populated in the cache with a dummy file under usr/lib/ or usr/bin/.
    fn make_test_env() -> (
        DepGraph,
        Cache<cache::LocalDir>,
        tempfile::TempDir,
        tempfile::TempDir,
    ) {
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache::at_dir(cache_dir.path()).unwrap();

        let layer = Layer::new_for_test(
            r#"
let {BuildSpec, Source, ..} = import "minimal.ncl" in

let zlib = {
    name = "zlib",
    inputs = [
        {url = "http://example.com/zlib.tar.gz", sha256 = "aabbcc"} | Source,
    ],
    cmd = "./build.sh",
} | BuildSpec
in
let expat = {
    name = "expat",
    inputs = [
        {url = "http://example.com/expat.tar.gz", sha256 = "ddeeff"} | Source,
    ],
    cmd = "./build.sh",
} | BuildSpec
in
let libffi = {
    name = "libffi",
    inputs = [
        {url = "http://example.com/libffi.tar.gz", sha256 = "112233"} | Source,
    ],
    cmd = "./build.sh",
} | BuildSpec
in
let python = {
    name = "python",
    inputs = [],
    runtime_deps = [zlib, expat, libffi],
    cmd = "./build.sh",
} | BuildSpec
in
let gcc = {
    name = "gcc",
    inputs = [
        {url = "http://example.com/gcc.tar.gz", sha256 = "445566"} | Source,
    ],
    cmd = "./build.sh",
} | BuildSpec
in
let bash = {
    name = "bash",
    inputs = [],
    runtime_deps = [gcc],
    cmd = "./build.sh",
} | BuildSpec
in
let coreutils = {
    name = "coreutils",
    inputs = [],
    runtime_deps = [gcc],
    cmd = "./build.sh",
} | BuildSpec
in
let findutils = {
    name = "findutils",
    inputs = [],
    runtime_deps = [gcc],
    cmd = "./build.sh",
} | BuildSpec
in
let sed = {
    name = "sed",
    inputs = [],
    runtime_deps = [gcc],
    cmd = "./build.sh",
} | BuildSpec
in
let make = {
    name = "make",
    inputs = [],
    runtime_deps = [gcc],
    cmd = "./build.sh",
} | BuildSpec
in
[zlib, expat, libffi, python, gcc, bash, coreutils, findutils, sed, make]
"#
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let graph = DepGraph::new().ingest(layer).unwrap();

        // Populate cache for each package
        for pkg_name in &[
            "zlib",
            "expat",
            "libffi",
            "python",
            "gcc",
            "bash",
            "coreutils",
            "findutils",
            "sed",
            "make",
        ] {
            let bsr = graph.by_name(pkg_name).unwrap();
            let hash = graph.spec_hash(bsr);
            let pending = cache.write_dir(&hash).unwrap();

            // Create a dummy file structure
            std::fs::create_dir_all(pending.path().join("usr/bin")).unwrap();
            std::fs::create_dir_all(pending.path().join("usr/lib")).unwrap();
            std::fs::write(
                pending.path().join("usr/bin").join(pkg_name),
                format!("#!/bin/sh\necho {}\n", pkg_name),
            )
            .unwrap();
            std::fs::write(
                pending
                    .path()
                    .join("usr/lib")
                    .join(format!("lib{}.so", pkg_name)),
                format!("fake lib for {}", pkg_name),
            )
            .unwrap();

            pending
                .finalize(EntryMeta {
                    inner: MetaInner::Spec(pkg_name.to_string()),
                    fetched: false,
                    ..Default::default()
                })
                .unwrap();
        }

        let rootfs_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(rootfs_dir.path().join("usr/bin")).unwrap();
        std::fs::create_dir_all(rootfs_dir.path().join("usr/lib")).unwrap();

        (graph, cache, cache_dir, rootfs_dir)
    }

    /// Helper: create a ShimListenerConfig from the test environment.
    fn make_config(
        graph: &DepGraph,
        cache: &Cache<cache::LocalDir>,
        rootfs_dir: &tempfile::TempDir,
        initial_packages: HashSet<BuildSpecRef>,
    ) -> (ShimListenerConfig, tempfile::TempDir, tempfile::TempDir) {
        let state_dir = tempfile::tempdir().unwrap();
        let mfile_dir = tempfile::tempdir().unwrap();
        let mfile_path = mfile_dir.path().join("minimal.toml");
        std::fs::write(
            &mfile_path,
            r#"[upstream]
repo = "https://example.com"

[tasks.shell]
exec = "bash -l"
packages = ["bash"]
"#,
        )
        .unwrap();

        let mctx_config = mctx::ConfigBuilder::new()
            .with_state_dir(state_dir.path().to_path_buf())
            .build()
            .unwrap();

        (
            ShimListenerConfig {
                port_file_path: state_dir.path().join(".min/port"),
                graph: graph.clone(),
                cache: cache.clone(),
                mctx_config,
                rootfs_path: rootfs_dir.path().to_path_buf(),
                state_dir: state_dir.path().to_path_buf(),
                mfile_path: Some(mfile_path),
                task_name: "shell".to_string(),
                initial_packages,
            },
            state_dir,
            mfile_dir,
        )
    }

    /// Helper: send a raw HTTP request and return the response body.
    fn http_request(port: u16, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
        use std::io::{Read, Write};
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();

        let body_bytes = body.unwrap_or("");
        let request = if body.is_some() {
            format!(
                "{} {} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                method,
                path,
                body_bytes.len(),
                body_bytes
            )
        } else {
            format!(
                "{} {} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                method, path
            )
        };
        stream.write_all(request.as_bytes()).unwrap();
        stream.flush().unwrap();

        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();

        // Parse HTTP status code and body
        let status_line = response.lines().next().unwrap_or("");
        let status_code: u16 = status_line
            .split_whitespace()
            .nth(1)
            .unwrap_or("0")
            .parse()
            .unwrap_or(0);

        let body_start = response.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
        let response_body = response[body_start..].to_string();

        (status_code, response_body)
    }

    #[test]
    fn test_http_add_single_package() {
        let (graph, cache, _cache_dir, rootfs_dir) = make_test_env();
        let (config, _state_dir, _mfile_dir) =
            make_config(&graph, &cache, &rootfs_dir, HashSet::new());

        let port_file = config.port_file_path.clone();
        let handle = start(config);

        let port: u16 = std::fs::read_to_string(&port_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();

        let body = r#"{"packages":["zlib"],"ephemeral":false}"#;
        let (status, resp_body) = http_request(port, "POST", "/v1/add", Some(body));
        assert_eq!(status, 200);

        let resp: AddResponse = serde_json::from_str(&resp_body).unwrap();
        assert_eq!(resp.status, "ok");
        assert!(resp.added.contains(&"zlib".to_string()));

        handle.shutdown();
    }

    #[test]
    fn test_http_get_packages() {
        let (graph, cache, _cache_dir, rootfs_dir) = make_test_env();
        let (config, _state_dir, _mfile_dir) =
            make_config(&graph, &cache, &rootfs_dir, HashSet::new());

        let port_file = config.port_file_path.clone();
        let handle = start(config);
        let port: u16 = std::fs::read_to_string(&port_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();

        // Add a package first
        let body = r#"{"packages":["zlib"]}"#;
        http_request(port, "POST", "/v1/add", Some(body));

        // Query packages
        let (status, resp_body) = http_request(port, "GET", "/v1/packages", None);
        assert_eq!(status, 200);

        let resp: PackagesResponse = serde_json::from_str(&resp_body).unwrap();
        assert!(resp.packages.iter().any(|p| p.name == "zlib"));

        handle.shutdown();
    }

    #[test]
    fn test_http_get_env() {
        let (graph, cache, _cache_dir, rootfs_dir) = make_test_env();
        let (config, _state_dir, _mfile_dir) =
            make_config(&graph, &cache, &rootfs_dir, HashSet::new());

        let port_file = config.port_file_path.clone();
        let handle = start(config);
        let port: u16 = std::fs::read_to_string(&port_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();

        let (status, _) = http_request(port, "GET", "/v1/env", None);
        assert_eq!(status, 200);

        handle.shutdown();
    }

    #[test]
    fn test_http_get_meta() {
        let (graph, cache, _cache_dir, rootfs_dir) = make_test_env();
        let (config, _state_dir, _mfile_dir) =
            make_config(&graph, &cache, &rootfs_dir, HashSet::new());

        let port_file = config.port_file_path.clone();
        let handle = start(config);
        let port: u16 = std::fs::read_to_string(&port_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();

        let (status, resp_body) = http_request(port, "GET", "/v1/meta", None);
        assert_eq!(status, 200);

        let resp: MetaResponse = serde_json::from_str(&resp_body).unwrap();
        assert_eq!(resp.task_name, "shell");

        handle.shutdown();
    }

    // ========== Test 1: Single package add (via HTTP) ==========
    #[test]
    fn test_add_single_package() {
        let (graph, cache, _cache_dir, rootfs_dir) = make_test_env();
        let (config, _state_dir, _mfile_dir) =
            make_config(&graph, &cache, &rootfs_dir, HashSet::new());

        let port_file = config.port_file_path.clone();
        let handle = start(config);
        let port: u16 = std::fs::read_to_string(&port_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();

        let body = r#"{"packages":["zlib"]}"#;
        let (status, resp_body) = http_request(port, "POST", "/v1/add", Some(body));
        assert_eq!(status, 200);
        let resp: AddResponse = serde_json::from_str(&resp_body).unwrap();
        assert_eq!(resp.status, "ok");
        assert!(resp.added.contains(&"zlib".to_string()));
        // Verify the file was hardlinked into rootfs
        assert!(rootfs_dir.path().join("usr/lib/libzlib.so").exists());

        handle.shutdown();
    }

    // ========== Test 2: Multiple packages at once ==========
    #[test]
    fn test_add_multiple_packages() {
        let (graph, cache, _cache_dir, rootfs_dir) = make_test_env();
        let (config, _state_dir, _mfile_dir) =
            make_config(&graph, &cache, &rootfs_dir, HashSet::new());

        let port_file = config.port_file_path.clone();
        let handle = start(config);
        let port: u16 = std::fs::read_to_string(&port_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();

        let body = r#"{"packages":["zlib","expat","libffi"]}"#;
        let (status, resp_body) = http_request(port, "POST", "/v1/add", Some(body));
        assert_eq!(status, 200);
        let resp: AddResponse = serde_json::from_str(&resp_body).unwrap();
        assert_eq!(resp.status, "ok");
        assert!(rootfs_dir.path().join("usr/lib/libzlib.so").exists());
        assert!(rootfs_dir.path().join("usr/lib/libexpat.so").exists());
        assert!(rootfs_dir.path().join("usr/lib/liblibffi.so").exists());

        handle.shutdown();
    }

    // ========== Test 3: Package with transitive dependencies ==========
    #[test]
    fn test_add_package_with_transitive_deps() {
        let (graph, cache, _cache_dir, rootfs_dir) = make_test_env();
        let (config, _state_dir, _mfile_dir) =
            make_config(&graph, &cache, &rootfs_dir, HashSet::new());

        let port_file = config.port_file_path.clone();
        let handle = start(config);
        let port: u16 = std::fs::read_to_string(&port_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();

        // python depends on zlib, expat, libffi
        let body = r#"{"packages":["python"]}"#;
        let (status, resp_body) = http_request(port, "POST", "/v1/add", Some(body));
        assert_eq!(status, 200);
        let resp: AddResponse = serde_json::from_str(&resp_body).unwrap();
        assert_eq!(resp.status, "ok");
        assert!(resp.added.contains(&"zlib".to_string()));
        assert!(resp.added.contains(&"expat".to_string()));
        assert!(resp.added.contains(&"libffi".to_string()));
        assert!(resp.added.contains(&"python".to_string()));
        // All should be hardlinked
        assert!(rootfs_dir.path().join("usr/lib/libzlib.so").exists());
        assert!(rootfs_dir.path().join("usr/lib/libexpat.so").exists());
        assert!(rootfs_dir.path().join("usr/lib/liblibffi.so").exists());
        assert!(rootfs_dir.path().join("usr/bin/python").exists());

        handle.shutdown();
    }

    // ========== Test 4: Already-present package (no-op) ==========
    #[test]
    fn test_add_already_present_package() {
        let (graph, cache, _cache_dir, rootfs_dir) = make_test_env();

        let mut initial = HashSet::new();
        initial.insert(*graph.by_name("zlib").unwrap());
        let (config, _state_dir, _mfile_dir) = make_config(&graph, &cache, &rootfs_dir, initial);

        let port_file = config.port_file_path.clone();
        let handle = start(config);
        let port: u16 = std::fs::read_to_string(&port_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();

        let body = r#"{"packages":["zlib"]}"#;
        let (status, resp_body) = http_request(port, "POST", "/v1/add", Some(body));
        assert_eq!(status, 200);
        let resp: AddResponse = serde_json::from_str(&resp_body).unwrap();
        assert_eq!(resp.status, "ok");
        assert!(resp.message.contains("already present"));

        handle.shutdown();
    }

    // ========== Test 5: Unknown package ==========
    #[test]
    fn test_add_unknown_package() {
        let (graph, cache, _cache_dir, rootfs_dir) = make_test_env();
        let (config, _state_dir, _mfile_dir) =
            make_config(&graph, &cache, &rootfs_dir, HashSet::new());

        let port_file = config.port_file_path.clone();
        let handle = start(config);
        let port: u16 = std::fs::read_to_string(&port_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();

        let body = r#"{"packages":["nonexistent_pkg"]}"#;
        let (status, resp_body) = http_request(port, "POST", "/v1/add", Some(body));
        assert_eq!(status, 422);
        let resp: AddResponse = serde_json::from_str(&resp_body).unwrap();
        assert_eq!(resp.status, "error");
        assert!(resp.message.contains("unknown package"));

        handle.shutdown();
    }

    // ========== Test 6: Ephemeral flag (no minimal.toml update) ==========
    #[test]
    fn test_add_ephemeral_does_not_persist() {
        let (graph, cache, _cache_dir, rootfs_dir) = make_test_env();
        let (config, _state_dir, _mfile_dir) =
            make_config(&graph, &cache, &rootfs_dir, HashSet::new());

        let mfile_path = config.mfile_path.clone().unwrap();
        let content_before = std::fs::read_to_string(&mfile_path).unwrap();

        let port_file = config.port_file_path.clone();
        let handle = start(config);
        let port: u16 = std::fs::read_to_string(&port_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();

        let body = r#"{"packages":["gcc"],"ephemeral":true}"#;
        let (status, resp_body) = http_request(port, "POST", "/v1/add", Some(body));
        assert_eq!(status, 200);
        let resp: AddResponse = serde_json::from_str(&resp_body).unwrap();
        assert_eq!(resp.status, "ok");

        // Verify minimal.toml was NOT modified
        let content_after = std::fs::read_to_string(&mfile_path).unwrap();
        assert_eq!(
            content_before, content_after,
            "minimal.toml should not be modified for ephemeral adds"
        );

        handle.shutdown();
    }

    // ========== Test 7: Non-ephemeral persists to minimal.toml ==========
    #[test]
    fn test_add_persists_to_mfile() {
        let (graph, cache, _cache_dir, rootfs_dir) = make_test_env();
        let (config, _state_dir, _mfile_dir) =
            make_config(&graph, &cache, &rootfs_dir, HashSet::new());

        let mfile_path = config.mfile_path.clone().unwrap();

        let port_file = config.port_file_path.clone();
        let handle = start(config);
        let port: u16 = std::fs::read_to_string(&port_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();

        let body = r#"{"packages":["gcc"]}"#;
        let (status, resp_body) = http_request(port, "POST", "/v1/add", Some(body));
        assert_eq!(status, 200);
        let resp: AddResponse = serde_json::from_str(&resp_body).unwrap();
        assert_eq!(resp.status, "ok");

        // Verify minimal.toml was updated with gcc
        let content_after = std::fs::read_to_string(&mfile_path).unwrap();
        assert!(
            content_after.contains("gcc"),
            "minimal.toml should contain gcc: {}",
            content_after
        );

        handle.shutdown();
    }

    // ========== Test 8: Partial overlap with already-present packages ==========
    #[test]
    fn test_add_partial_overlap() {
        let (graph, cache, _cache_dir, rootfs_dir) = make_test_env();

        // gcc is already present (so bash's transitive dep on gcc is satisfied)
        let mut initial = HashSet::new();
        initial.insert(*graph.by_name("gcc").unwrap());

        // Hardlink gcc into rootfs first
        let gcc_hash = graph.spec_hash(graph.by_name("gcc").unwrap());
        let gcc_entry = cache.read_dir(&gcc_hash).unwrap();
        common::hardlink_dir_contents(gcc_entry.path(), rootfs_dir.path()).unwrap();

        let (config, _state_dir, _mfile_dir) = make_config(&graph, &cache, &rootfs_dir, initial);

        let port_file = config.port_file_path.clone();
        let handle = start(config);
        let port: u16 = std::fs::read_to_string(&port_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();

        // bash depends on gcc, but gcc is already present
        let body = r#"{"packages":["bash"]}"#;
        let (status, resp_body) = http_request(port, "POST", "/v1/add", Some(body));
        assert_eq!(status, 200);
        let resp: AddResponse = serde_json::from_str(&resp_body).unwrap();
        assert_eq!(resp.status, "ok");
        assert!(resp.added.contains(&"bash".to_string()));
        // gcc should NOT be re-added
        assert!(
            !resp.added.contains(&"gcc".to_string()),
            "gcc should not be re-added: {:?}",
            resp.added
        );

        handle.shutdown();
    }

    // ========== Test 9: Sequential adds track state ==========
    #[test]
    fn test_sequential_adds_track_state() {
        let (graph, cache, _cache_dir, rootfs_dir) = make_test_env();
        let (config, _state_dir, _mfile_dir) =
            make_config(&graph, &cache, &rootfs_dir, HashSet::new());

        let port_file = config.port_file_path.clone();
        let handle = start(config);
        let port: u16 = std::fs::read_to_string(&port_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();

        // First add: gcc
        let body = r#"{"packages":["gcc"]}"#;
        let (status, resp_body) = http_request(port, "POST", "/v1/add", Some(body));
        assert_eq!(status, 200);
        let resp: AddResponse = serde_json::from_str(&resp_body).unwrap();
        assert_eq!(resp.status, "ok");
        assert!(resp.added.contains(&"gcc".to_string()));

        // Second add: bash (depends on gcc, which is now present)
        let body = r#"{"packages":["bash"]}"#;
        let (_, resp_body) = http_request(port, "POST", "/v1/add", Some(body));
        let resp: AddResponse = serde_json::from_str(&resp_body).unwrap();
        assert_eq!(resp.status, "ok");
        assert!(resp.added.contains(&"bash".to_string()));
        assert!(
            !resp.added.contains(&"gcc".to_string()),
            "gcc should not be re-added"
        );

        // Third add: gcc again (should be no-op)
        let body = r#"{"packages":["gcc"]}"#;
        let (_, resp_body) = http_request(port, "POST", "/v1/add", Some(body));
        let resp: AddResponse = serde_json::from_str(&resp_body).unwrap();
        assert_eq!(resp.status, "ok");
        assert!(resp.message.contains("already present"));

        handle.shutdown();
    }

    // ========== Test 10: HTTP protocol over TCP ==========
    #[test]
    fn test_http_wire_protocol() {
        let (graph, cache, _cache_dir, rootfs_dir) = make_test_env();
        let (config, _state_dir, _mfile_dir) =
            make_config(&graph, &cache, &rootfs_dir, HashSet::new());

        let port_file = config.port_file_path.clone();
        let handle = start(config);

        // Verify port file was written
        let port_str = std::fs::read_to_string(&port_file).unwrap();
        let port: u16 = port_str.trim().parse().unwrap();
        assert!(port > 0, "port should be non-zero");

        let body = r#"{"packages":["zlib"]}"#;
        let (status, resp_body) = http_request(port, "POST", "/v1/add", Some(body));
        assert_eq!(status, 200);
        let resp: AddResponse = serde_json::from_str(&resp_body).unwrap();
        assert_eq!(resp.status, "ok");

        // Verify hardlinking worked through the HTTP server
        assert!(
            rootfs_dir.path().join("usr/lib/libzlib.so").exists(),
            "zlib should be hardlinked into rootfs"
        );

        handle.shutdown();
    }

    #[test]
    fn test_inject_shim_scripts() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();

        inject_shim_scripts(&rootfs).unwrap();

        // Check /usr/bin/min exists and is executable
        let min_path = rootfs.join("usr/bin/min");
        assert!(min_path.exists());
        let metadata = std::fs::metadata(&min_path).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(metadata.permissions().mode() & 0o111, 0o111);

        // Check content
        let content = std::fs::read_to_string(&min_path).unwrap();
        assert!(content.contains("#!/bin/bash"));
        assert!(content.contains("/dev/tcp/"));

        // Check /etc/bashrc exists and contains snippet
        let bashrc = std::fs::read_to_string(rootfs.join("etc/bashrc")).unwrap();
        assert!(bashrc.contains("min()"));
        assert!(bashrc.contains("eval"));
    }

    #[test]
    fn test_persist_packages_to_mfile() {
        let tmp = tempfile::tempdir().unwrap();
        let mfile_path = tmp.path().join("minimal.toml");

        std::fs::write(
            &mfile_path,
            r#"[upstream]
repo = "https://example.com"

[tasks.shell]
exec = "bash -l"
packages = ["coreutils"]
"#,
        )
        .unwrap();

        persist_packages_to_mfile(&mfile_path, "shell", &["python", "gcc"]);

        let content = std::fs::read_to_string(&mfile_path).unwrap();
        assert!(content.contains("python"), "content: {}", content);
        assert!(content.contains("gcc"), "content: {}", content);
        assert!(content.contains("coreutils"), "content: {}", content);
    }

    #[test]
    fn test_persist_packages_no_duplicates() {
        let tmp = tempfile::tempdir().unwrap();
        let mfile_path = tmp.path().join("minimal.toml");

        std::fs::write(
            &mfile_path,
            r#"[upstream]
repo = "https://example.com"

[tasks.shell]
exec = "bash -l"
packages = ["coreutils", "python"]
"#,
        )
        .unwrap();

        persist_packages_to_mfile(&mfile_path, "shell", &["python"]);

        let content = std::fs::read_to_string(&mfile_path).unwrap();
        let doc: toml_edit::DocumentMut = content.parse().unwrap();
        let arr = doc["tasks"]["shell"]["packages"].as_array().unwrap();
        let python_count = arr.iter().filter(|v| v.as_str() == Some("python")).count();
        assert_eq!(python_count, 1, "python should appear exactly once");
    }

    #[test]
    fn test_persist_packages_new_task() {
        let tmp = tempfile::tempdir().unwrap();
        let mfile_path = tmp.path().join("minimal.toml");

        std::fs::write(
            &mfile_path,
            r#"[upstream]
repo = "https://example.com"

[tasks.shell]
exec = "bash -l"
"#,
        )
        .unwrap();

        persist_packages_to_mfile(&mfile_path, "shell", &["python"]);

        let content = std::fs::read_to_string(&mfile_path).unwrap();
        assert!(content.contains("python"), "content: {}", content);
    }

    #[test]
    fn test_min_script_content() {
        assert!(MIN_SCRIPT.contains("#!/bin/bash"));
        assert!(MIN_SCRIPT.contains("PORT_FILE=/state/.min/port"));
        assert!(MIN_SCRIPT.contains("/dev/tcp/127.0.0.1/"));
        assert!(MIN_SCRIPT.contains("add)"));
        assert!(MIN_SCRIPT.contains("--ephemeral"));
        assert!(MIN_SCRIPT.contains("STATUS error"));
        assert!(MIN_SCRIPT.contains("ENV "));
        assert!(MIN_SCRIPT.contains("MSG "));
    }

    #[test]
    fn test_bashrc_snippet_content() {
        assert!(BASHRC_SNIPPET.contains("min()"));
        assert!(BASHRC_SNIPPET.contains("eval"));
        assert!(BASHRC_SNIPPET.contains("/usr/bin/min"));
    }

    #[test]
    fn test_process_add_returns_structured_ok() {
        let (graph, cache, _cache_dir, rootfs_dir) = make_test_env();
        let (config, _state_dir, _mfile_dir) =
            make_config(&graph, &cache, &rootfs_dir, HashSet::new());
        let mut present = HashSet::new();

        let resp = process_add_impl(vec!["zlib"], false, &config, &mut present);
        assert_eq!(resp.status, "ok");
        assert!(resp.added.contains(&"zlib".to_string()));
        assert!(!resp.message.is_empty());
    }

    #[test]
    fn test_process_add_returns_structured_error() {
        let (graph, cache, _cache_dir, rootfs_dir) = make_test_env();
        let (config, _state_dir, _mfile_dir) =
            make_config(&graph, &cache, &rootfs_dir, HashSet::new());
        let mut present = HashSet::new();

        let resp = process_add_impl(vec!["nonexistent"], false, &config, &mut present);
        assert_eq!(resp.status, "error");
        assert!(resp.message.contains("unknown package"));
    }

    #[test]
    fn test_add_request_serde() {
        let req = AddRequest {
            packages: vec!["python".to_string(), "gcc".to_string()],
            ephemeral: false,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AddRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.packages, vec!["python", "gcc"]);
        assert!(!parsed.ephemeral);
    }

    #[test]
    fn test_add_response_serde() {
        let resp = AddResponse {
            status: "ok".to_string(),
            added: vec!["python".to_string()],
            env: std::collections::HashMap::from([("PATH".to_string(), "/usr/bin".to_string())]),
            message: "Added python".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        let parsed: AddResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.added, vec!["python"]);
    }
}
