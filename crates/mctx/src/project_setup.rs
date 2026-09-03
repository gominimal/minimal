//! [`ProjectSetup`]: the `mctx` adapter implementing [`op::ProjectEnv`].

use std::path::{Path, PathBuf};

use checkouts::{GitRef, ManagerHandle as VcsManagerHandle};
use common::Target;
use graph::Graph;
use mfile::LinkConfig;

use crate::{Config, DaemonContext, Error, MFileSearchStrategy};

/// The environment project-setup operations ([`op::InitProject`],
/// [`op::UpdateProject`]) run against.
///
/// Unlike [`Context`], this can be constructed without a `minimal.toml` on disk,
/// which `init` requires when bootstrapping a fresh project.
pub struct ProjectSetup {
    config: Config,
    vcs: VcsManagerHandle,
    stdlib_dir: PathBuf,
    mfile: Option<mfile::File>,
    repo_dir: PathBuf,
}

impl ProjectSetup {
    /// Builds an environment for `init`, loading a `minimal.toml` if one is
    /// already present (the user may be re-initializing).
    pub fn for_init(config: Config) -> Result<Self, Error> {
        let (vcs, _cache, stdlib_dir) = DaemonContext::sub_setup(&config)?;
        let strategy = match config.repo_dir_override() {
            Some(path) => MFileSearchStrategy::Override(path.to_path_buf()),
            None => MFileSearchStrategy::CurrentDirOnly,
        };
        let mfile = match strategy.find_mfile() {
            Ok(m) => Some(m),
            Err(Error::MFile(mfile::Error::NotFound)) => None,
            Err(e) => return Err(e),
        };
        let repo_dir = resolve_repo_dir(&config, mfile.as_ref())?;
        Ok(Self {
            config,
            vcs,
            stdlib_dir,
            mfile,
            repo_dir,
        })
    }

    /// Builds an environment from the parts of an existing [`Context`].
    pub(crate) fn from_parts(
        config: Config,
        vcs: VcsManagerHandle,
        stdlib_dir: PathBuf,
        mfile: mfile::File,
        repo_dir: PathBuf,
    ) -> Self {
        Self {
            config,
            vcs,
            stdlib_dir,
            mfile: Some(mfile),
            repo_dir,
        }
    }
}

/// Resolves the project root: the minimal file's repo, else the configured
/// override, else the current directory.
fn resolve_repo_dir(config: &Config, mfile: Option<&mfile::File>) -> Result<PathBuf, Error> {
    if let Some(p) = mfile.and_then(|m| m.repo_path()) {
        return Ok(p.to_path_buf());
    }
    if let Some(p) = config.repo_dir_override() {
        return Ok(p.to_path_buf());
    }
    std::env::current_dir().map_err(|e| Error::IO("Getting current directory", PathBuf::new(), e))
}

impl op::ProjectEnv for ProjectSetup {
    fn repo_dir(&self) -> &Path {
        &self.repo_dir
    }

    fn minimal_file(&self) -> Option<&mfile::File> {
        self.mfile.as_ref()
    }

    fn checkout_branch(&mut self, repo: &str, branch: &str) -> Result<String, op::Error> {
        self.vcs
            .checkout_of(repo, GitRef::Branch(branch.to_string()))
            .map(|(_dir, rev)| rev)
            .map_err(|e| op::Error::Other(anyhow::Error::from(e)))
    }

    fn update_checkouts(&mut self) -> Result<(), op::Error> {
        self.vcs
            .update()
            .map_err(|e| op::Error::Other(anyhow::Error::from(e)))
    }

    fn update_checkout(&mut self, remote: &str) -> Result<(), op::Error> {
        self.vcs
            .update_remote(remote)
            .map_err(|e| op::Error::Other(anyhow::Error::from(e)))
    }

    fn graph_from_chain(&mut self, link: LinkConfig, target: Target) -> Result<Graph, op::Error> {
        Graph::new_from_chain(
            self.vcs.clone(),
            &mut graph::LayerCacheDir(self.config.layer_cache_dir()),
            link,
            self.stdlib_dir.clone(),
            target,
        )
        .map_err(|e| op::Error::Other(anyhow::anyhow!("loading package graph: {e:?}")))
    }

    fn invalidate_remote_index(&mut self) {
        std::fs::remove_file(self.config.index_dir().join(rcache::INDEX_FILENAME)).ok();
    }
}
