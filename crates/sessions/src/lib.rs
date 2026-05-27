//! Session primitives: lifecycle hooks and loadouts that describe the runtime
//! shape of a Minimal session.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::paths::HostAbsPath;

pub mod lifecyclehook;
pub mod loadout;
pub mod patches;
pub mod paths;
pub mod policy;
pub mod store;
pub mod vars;

/// The on-disk row/record pertaining to a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    /// Unique ID describing this session.
    pub id: Uuid,
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

    /// Free-form attributes.
    pub attrs: BTreeMap<String, String>,
}
