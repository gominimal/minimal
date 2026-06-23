//! Session primitives: lifecycle hooks and loadouts that describe the runtime
//! shape of a Minimal session.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use paths::HostAbsPath;

pub mod client;
pub mod core;
pub mod store;
pub mod wire;

/// The network isolation mode for a `PTask` (session).
///
/// Defaults to [`NetworkMode::HostNet`] for backwards compatibility with
/// existing sessions that predate this field.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// No network namespace; all network syscalls fail or see no interfaces.
    NoNet,
    /// Share the host (or VM) network namespace. Current default.
    #[default]
    HostNet,
    /// Own IP via the gvproxy switch: new netns + tap + switch attachment.
    OwnIp,
}

/// An IP transport protocol, used in egress/ingress policy rules.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IpProto {
    Tcp,
    Udp,
    Icmp,
}

/// A session ID, a newtype over a UUID.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(Uuid);

impl SessionId {
    #[must_use]
    pub fn nil() -> Self {
        Self(Uuid::nil())
    }

    /// Parses the given UUID as a session ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the given string is not a UUID.
    pub fn parse_str(s: &str) -> Result<Self, uuid::Error> {
        Uuid::parse_str(s).map(Self)
    }
}

impl AsRef<Uuid> for SessionId {
    fn as_ref(&self) -> &Uuid {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The on-disk row/record pertaining to a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    /// Unique ID describing this session.
    #[serde(default = "SessionId::nil")]
    pub id: SessionId,
    /// The name a user assigned to this session, if
    /// one was specifically assigned.
    ///
    /// When no name was manually assigned, the user should
    /// be presented with a short name of the form:
    /// <user>-<project/repo-name>-<uuid-suffix>.
    pub name: Option<String>,

    /// The username of the creating user, at creation time.
    pub username: Option<String>,
    /// The absolute path upon which this session was built from.
    pub project_path: HostAbsPath,

    /// The network isolation mode for this session.
    ///
    /// Defaults to [`NetworkMode::HostNet`] when absent (existing sessions).
    #[serde(default)]
    pub network: NetworkMode,

    /// Free-form attributes.
    pub attrs: BTreeMap<String, String>,
}
