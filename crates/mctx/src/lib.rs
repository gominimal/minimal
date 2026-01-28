//! Top-level API for minimal tooling.

use std::{fmt, path::PathBuf};

use anyhow::anyhow;
use checkouts::{GitRef, Manager as VcsManager};
use common::SpecOrigin;

mod error;
pub use error::Error;
mod config;
pub use config::{Config, ConfigBuilder, ConfigError};
use graph::DepGraph;

/// The local cache.
pub type Cache = cache::Cache<cache::LocalDir>;

/// A top-level context for operations in a minimal-configured repo.
#[derive(Debug)]
pub struct Context {
    config: Config,

    stdlib_dir: PathBuf,
    stdlib_origin: SpecOrigin,
    mfile: Option<mfile::File>,

    vcs: VcsManager,
    cache: Cache,
}

impl fmt::Display for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mctx{{")?;
        if let Some(p) = self
            .mfile
            .as_ref()
            .and_then(|f| f.dir_path().map(|p| p.to_path_buf()))
        {
            write!(f, " mfile repo at {} ", p.display())?;
        } else {
            write!(f, "{:?}", self.config)?;
        }
        write!(f, "}}")
    }
}

impl Context {
    /// Initializes a new context using the given configuration.
    pub fn new(config: Config) -> Result<Self, Error> {
        // Upsert dirs
        use std::fs::create_dir_all;
        create_dir_all(config.cache_dir()).map_err(|e| Error::setup_dirs(e, config.cache_dir()))?;
        create_dir_all(config.downloads_dir())
            .map_err(|e| Error::setup_dirs(e, config.downloads_dir()))?;
        create_dir_all(config.builds_base_dir())
            .map_err(|e| Error::setup_dirs(e, config.builds_base_dir()))?;
        create_dir_all(config.state_base_dir())
            .map_err(|e| Error::setup_dirs(e, config.state_base_dir()))?;
        create_dir_all(config.run_base_dir())
            .map_err(|e| Error::setup_dirs(e, config.run_base_dir()))?;
        create_dir_all(config.vcs_dir()).map_err(|e| Error::setup_dirs(e, config.vcs_dir()))?;

        // Initialize subsystems that are always present/used
        let mut vcs = VcsManager::new(config.vcs_dir())?;
        let cache = Cache::at_dir(config.cache_dir())
            .map_err(|e| Error::Other(anyhow!("initializing local cache: {}", e)))?;

        // Load the minimal file. All error are terminal except not found.
        let mfile = match config
            .repo_dir_override()
            .as_ref()
            .map(|d| mfile::File::from_dir(d.clone()))
            .unwrap_or_else(|| mfile::File::from_dir_recursive(std::env::current_dir().unwrap()))
        {
            Ok(mfile) => Some(mfile),
            Err(mfile::Error::NotFound) => None,
            Err(e) => {
                return Err(Error::MFile(e));
            }
        };

        // Figure out a path to the standard library. Roughly speaking this is loaded from:
        //  - Any override in the config
        //  - The minimal file, if one was found
        //  - The fallback `mfile::default_stdlib()`
        let (stdlib_dir, stdlib_origin) = {
            if let Some(dir) = config.stdlib_dir_override() {
                (dir.clone(), SpecOrigin::from_dir(dir))
            } else {
                let stdlib_link = if let Some(mfile) = &mfile {
                    &mfile.stdlib
                } else {
                    &mfile::default_stdlib()
                };
                let git_ref: GitRef = stdlib_link.into();
                let (dir, git_hash) = vcs.checkout_of(&stdlib_link.repo, git_ref.clone())?;
                (
                    dir,
                    SpecOrigin::Repo(git_ref.as_repo(stdlib_link.repo.clone(), git_hash)),
                )
            }
        };

        Ok(Self {
            config,
            stdlib_dir,
            stdlib_origin,
            mfile,
            vcs,
            cache,
        })
    }
}

/// Low-level API
impl Context {
    /// Returns a handle to the local cache.
    pub fn local_cache(&self) -> Cache {
        self.cache.clone()
    }
    /// Returns a path to the standard library, as well as info about where its from.
    pub fn stdlib_dir_and_origin(&self) -> (&PathBuf, &SpecOrigin) {
        (&self.stdlib_dir, &self.stdlib_origin)
    }

    /// Returns the minimal file loaded from disk.
    ///
    /// Its possible for some layers to not have a minimal file (i.e. 'pkgs'), these
    /// return `Error::MFile(mfile::Error::NotFound)`.
    pub fn minimal_file(&self) -> Result<&mfile::File, Error> {
        match &self.mfile {
            Some(mfile) => Ok(mfile),
            None => Err(Error::MFile(mfile::Error::NotFound)),
        }
    }

    /// Builds & returns the graph with the given packages specified as top levels.
    pub fn graph_from_package_names(&mut self, names: &[String]) -> Result<DepGraph, Error> {
        let mut graph = self.graph_from_all_packages()?;
        graph.top_levels = names
            .iter()
            .map(|n| match graph.by_name(n) {
                Some(bsr) => Ok(*bsr),
                None => Err(Error::Other(anyhow!("No such package: {}", n))),
            })
            .collect::<Result<_, _>>()?;

        Ok(graph)
    }

    /// Builds & returns a graph of all packages.
    pub fn graph_from_all_packages(&mut self) -> Result<DepGraph, Error> {
        let leaf_layer = match (&self.mfile, self.config.repo_dir_override()) {
            (Some(mfile), _) => SpecOrigin::from_dir(mfile.dir_path().unwrap()),
            (None, Some(d)) => SpecOrigin::from_dir(d),
            (None, None) => return Err(Error::MFile(mfile::Error::NotFound)),
        };

        DepGraph::new_from_chain(&mut self.vcs, leaf_layer, self.stdlib_dir.clone())
            .map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn init_no_mfile() {
        let state = tempdir().unwrap();
        let config = ConfigBuilder::new()
            .state_dir(state.path().to_path_buf())
            .repo_dir(
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("testdata")
                    .join("fakepkgs"),
            )
            .stdlib_dir(
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("../graph/minimal-ncl"),
            )
            .build()
            .unwrap();

        let mut ctx = Context::new(config).unwrap();
        assert!(
            ctx.graph_from_all_packages()
                .inspect_err(|e| {
                    if let Error::Graph(e) = e {
                        e.report_to_stderr();
                    }
                })
                .unwrap()
                .by_name("uroot")
                .is_some()
        );
    }
}
