use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use crate::{Error, Options, Runnable};
use common::mfile::{EnvPatches, PatchSetting};
use graph::{BuildSpecRef, TransitivesDep};

/// Considers the transitive deps & toplevels which are going into the a runnable environment, and constructs
/// scaffolding as nessessary.
///
/// Necessary dependencies are mapped into the given `opts.exec_base`, along with state wiring in `state_base_dir`.
/// Any additional file/dir mounts, as well as additional environment variables, are returned as `Ok((patches, env_vars))`.
pub struct EnvSetup<'a> {
    // The `/state` dir that should live between invocations. Call `mfile::File::env_state_dir` to get this value for a minimalfile environment.
    pub state_base_dir: &'a Path,
    pub top_levels: &'a Vec<BuildSpecRef>,
    pub transitives: &'a HashMap<BuildSpecRef, TransitivesDep>,
}

impl<'a> Runnable for EnvSetup<'a> {
    type Result = (EnvPatches, HashMap<String, String>);

    async fn run<'b>(&mut self, opts: &Options<'b>) -> Result<Self::Result, Error> {
        let mut patch = EnvPatches::default();
        let mut env_vars = HashMap::with_capacity(6);

        // Make sure the directories for storing durable state exist.
        std::fs::create_dir_all(self.state_base_dir.join("home")).map_err(anyhow::Error::from)?; // XDG_CONFIG_HOME ala ~/.config
        std::fs::create_dir_all(self.state_base_dir.join("data")).map_err(anyhow::Error::from)?; // XDG_DATA_HOME ala ~/.local/share
        std::fs::create_dir_all(self.state_base_dir.join("cache")).map_err(anyhow::Error::from)?; // XDG_CACHE_HOME  ala ~/.cache
        std::fs::create_dir_all(self.state_base_dir.join("state")).map_err(anyhow::Error::from)?; // XDG_STATE_HOME  ala ~/.local/state

        // Hardlink in the files which represent each dependency.
        for dep in self.transitives.keys() {
            common::hardlink_dir_contents(
                opts.cache
                    .read_dir(&opts.graph.spec_hash(dep))
                    .unwrap()
                    .path(),
                &opts.exec_base,
            )
            .map_err(anyhow::Error::from)?;
        }

        // Check attributes on each dependency to see if theres any additional env wiring.
        for dep in self.transitives.keys() {
            let attrs = &opts.graph.get(dep).unwrap().attrs;
            if let Some(dirs) = attrs.get("env_dir_mappings") {
                for mapping in dirs.as_list().unwrap() {
                    let mapping = mapping.as_map().unwrap();
                    patch.dir.insert(
                        mapping.get("path").unwrap().as_string().unwrap().clone(),
                        if *mapping.get("read_only").unwrap().as_bool().unwrap() {
                            PatchSetting::ReadOnly
                        } else {
                            PatchSetting::ReadWrite
                        },
                    );
                }
            }
            if let Some(dirs) = attrs.get("env_file_mappings") {
                for mapping in dirs.as_list().unwrap() {
                    let mapping = mapping.as_map().unwrap();
                    patch.file.insert(
                        mapping.get("path").unwrap().as_string().unwrap().clone(),
                        if *mapping.get("read_only").unwrap().as_bool().unwrap() {
                            PatchSetting::ReadOnly
                        } else {
                            PatchSetting::ReadWrite
                        },
                    );
                }
            }
            if let Some(dir) = attrs.get("env_state_wiring") {
                let mapping = dir.as_map().unwrap();
                let env_var = mapping.get("env_var").unwrap().as_string().unwrap().clone();
                let prefix = mapping.get("prefix").unwrap().as_string().unwrap().clone();
                let dir = self.state_base_dir.join(&prefix);
                std::fs::create_dir_all(&dir).map_err(anyhow::Error::from)?;
                env_vars.entry(env_var).or_insert_with(|| {
                    PathBuf::from("/state")
                        .join(dir.strip_prefix(self.state_base_dir).unwrap())
                        .to_str()
                        .unwrap()
                        .to_string()
                });
            }
        }

        // Create the state directory
        std::fs::create_dir_all(opts.exec_base.join("state")).map_err(anyhow::Error::from)?;

        env_vars.insert("XDG_CONFIG_HOME".to_string(), "/state/home".to_string());
        env_vars.insert("XDG_DATA_HOME".to_string(), "/state/data".to_string());
        env_vars.insert("XDG_CACHE_HOME".to_string(), "/state/cache".to_string());
        env_vars.insert("XDG_STATE_HOME".to_string(), "/state/state".to_string());

        Ok((patch, env_vars))
    }
}
