//! Shared test harness for minimal integration tests.
//!
//! Spins up a real minimald `TestServer` listening on a UDS at the path
//! `minimal::client::resolve_socket_path` expects, so the CLI command
//! functions can connect to it as if it were a production daemon.

use minimal::GlobalArgs;

/// A running minimald test server plus the tempdir backing it.
///
/// The UDS socket is placed at `<tempdir>/providers/local-0/ssh.sock` so
/// that `resolve_socket_path(Some(tempdir), false)` finds it.
pub struct TestDaemon {
    /// The underlying minimald test server. Exposed so tests can create
    /// sessions directly via `server.state` or connect a `TestClient`.
    /// Not every test binary that includes this shared module uses it.
    #[allow(dead_code)]
    pub server: minimald::test_harness::TestServer,
    temp: tempfile::TempDir,
}

impl TestDaemon {
    /// Spin up a fresh daemon backed by an empty tempdir.
    pub async fn new() -> Self {
        let server = minimald::test_harness::TestServer::new().await;
        let temp = tempfile::TempDir::new().unwrap();

        let sock_dir = temp.path().join("providers/local-0");
        std::fs::create_dir_all(&sock_dir).unwrap();
        let sock = sock_dir.join("ssh.sock");
        server.listen_on_uds(&sock).await;

        Self { server, temp }
    }

    /// Build `GlobalArgs` pointing at this daemon's tempdir.
    pub fn global_args(&self) -> GlobalArgs {
        GlobalArgs {
            repo_dir: None,
            minimal_dir: Some(self.temp.path().to_path_buf()),
            config_dir: None,
            minvmd: false,
        }
    }
}

/// Convenience: spin up a daemon and return (daemon, global_args).
pub async fn setup() -> (TestDaemon, GlobalArgs) {
    let daemon = TestDaemon::new().await;
    let args = daemon.global_args();
    (daemon, args)
}
