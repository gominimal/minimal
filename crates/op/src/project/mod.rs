//! Operations that create or refresh a project's `minimal.toml` and its
//! checkouts, based on an existing codebase.
//!
//! Unlike a [`crate::Runnable`], which builds cache artifacts against the
//! package [`Graph`], these operations inspect and mutate the project checkout
//! itself. The capabilities they need from the surrounding tooling (VCS
//! checkouts, graph construction, the on-disk `minimal.toml`) are abstracted
//! behind the [`ProjectEnv`] port, which `mctx` implements.

use std::path::Path;

use common::Target;
use graph::Graph;
use mfile::LinkConfig;

use crate::Error;

mod init;
mod update;

pub use init::{InitPlan, InitProject};
pub use update::{RevChange, UpdateProject, UpdateReport};

/// The environment a [`ProjectOp`] runs against: an existing (or to-be-created)
/// project checkout, its `minimal.toml`, and the VCS + graph machinery needed
/// to inspect it.
///
/// This is the project-setup counterpart to [`crate::Options`]. It is
/// implemented outside this crate (by `mctx`) so that `op` need not depend on
/// the higher-level context, VCS, or remote-cache machinery.
pub trait ProjectEnv {
    /// Root of the project checkout being configured.
    fn repo_dir(&self) -> &Path;

    /// The project's `minimal.toml`, if one exists yet.
    ///
    /// Returns `None` during a fresh `init`, before any `minimal.toml` has been
    /// written.
    fn minimal_file(&self) -> Option<&mfile::File>;

    /// Resolve `branch` of `repo` to its current commit, performing a
    /// checkout/fetch as needed.
    fn checkout_branch(&mut self, repo: &str, branch: &str) -> Result<String, Error>;

    /// Fetch/update every known checkout.
    fn update_checkouts(&mut self) -> Result<(), Error>;

    /// Build the full package graph from the given upstream `link`.
    fn graph_from_chain(&mut self, link: LinkConfig, target: Target) -> Result<Graph, Error>;

    /// Best-effort invalidation of any cached remote index, so the next
    /// operation performs a fresh fetch.
    fn invalidate_remote_index(&mut self);
}

/// An operation that creates or refreshes a project's `minimal.toml` and its
/// checkouts from an existing codebase.
///
/// This is the project-setup counterpart to [`crate::Runnable`].
pub trait ProjectOp {
    /// The value produced by running the operation.
    type Result: Sized;

    /// Run the operation against the given [`ProjectEnv`].
    fn run<E: ProjectEnv>(&mut self, env: &mut E) -> Result<Self::Result, Error>;
}
