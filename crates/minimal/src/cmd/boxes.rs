//! The `min session` commands, one module per verb. The clap handlers stay
//! in `session.rs` and call into these modules.
//!
//! `cmd/mod.rs` mounts this file as `box_verbs`, not `boxes`: a `boxes`
//! module in `cmd` would shadow the `boxes` crate for every sibling that
//! reaches it through `use super::*`.

use super::*;

#[path = "boxes/attach.rs"]
mod attach;
#[path = "boxes/create.rs"]
mod create;
#[path = "boxes/exec.rs"]
mod exec;
#[path = "boxes/hooks.rs"]
mod hooks;
#[path = "boxes/lifecycle.rs"]
mod lifecycle;
#[path = "boxes/policy.rs"]
mod policy;
#[path = "boxes/vm_host.rs"]
mod vm_host;

pub(crate) use attach::*;
pub use create::*;
pub(crate) use exec::*;
pub(crate) use hooks::*;
pub(crate) use lifecycle::*;
pub use policy::*;
pub(crate) use vm_host::*;
