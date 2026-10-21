//! The status document `min mirror status` reads over the host socket.

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Seconds since the Unix epoch now.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A failure with its time and cause.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Failure {
    pub at: u64,
    pub cause: String,
}

impl Failure {
    pub fn now(cause: &str) -> Self {
        Self {
            at: now_secs(),
            cause: cause.to_string(),
        }
    }
}

/// One cache origin the mirror contacted.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OriginStatus {
    pub last_contact: Option<u64>,
    pub last_failure: Option<Failure>,
}

/// One origin row, with its name.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OriginRow {
    pub origin: String,
    pub last_contact: Option<u64>,
    pub last_failure: Option<Failure>,
}

/// One branch head of a repository copy.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Head {
    pub name: String,
    pub commit: String,
}

/// One repository copy.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoStatus {
    pub slug: String,
    pub heads: Vec<Head>,
    pub refreshed_at: Option<u64>,
    pub last_failure: Option<Failure>,
}

/// The store's use against its budget.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Disk {
    pub used_bytes: u64,
    pub protected_bytes: u64,
    pub budget_bytes: u64,
}

/// The whole document.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Status {
    pub pid: u32,
    pub host_socket: String,
    pub door_socket: String,
    pub store: String,
    pub origins: Vec<OriginRow>,
    pub disk: Disk,
    pub repositories: Vec<RepoStatus>,
}
