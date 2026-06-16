use std::collections::BTreeMap;

pub mod cmd;
pub mod connection;
mod exec;
#[cfg(target_os = "linux")]
pub mod guest;
pub mod lifecycle;
pub mod rpc;
pub mod server;
mod session;
pub mod session_host;
mod sessions;
mod sftp;
pub mod state;
#[cfg(test)]
mod test_harness;

/// Env var that the client must set (via `env_request`) before the SFTP
/// subsystem request, naming which session the SFTP channel attaches to.
const MINIMAL_SESSION_ID_ENV: &str = "MINIMAL_SESSION_ID";

/// Represents the parameters of a requested PTY.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RequestedPty {
    char_sizes: (u32, u32),
    pixel_sizes: (u32, u32),
    term: String,
    modes: Vec<(russh::Pty, u32)>,
}

/// Represents the currently configured parameters for a channel being created.
#[derive(Debug)]
#[allow(dead_code)]
pub struct ChannelConfig {
    pub(crate) env_vars: BTreeMap<String, String>,
    pub(crate) pty: Option<RequestedPty>,
}
