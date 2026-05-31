use std::collections::BTreeMap;

pub mod connection;
pub mod rpc;
pub mod server;
mod session;
mod sessions;
mod sftp;
#[cfg(test)]
mod test_harness;

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
