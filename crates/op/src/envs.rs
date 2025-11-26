use std::{
    collections::HashMap,
    env::home_dir,
    path::{Path, PathBuf},
};

use crate::{Error, Options, Runnable};
use common::mfile::{EnvPatches, PatchSetting};
use graph::{BuildSpecRef, TransitivesDep};

/// Considers the transitive deps & toplevels which are going into the a runnable environment, and constructs
/// scaffolding as necessary.
///
/// Necessary dependencies are mapped into the given `opts.exec_base`, along with state wiring in `state_base_dir`.
pub struct EnvSetup<'a> {
    /// The `/state` dir that should live between invocations.
    ///
    /// Call `mfile::File::env_state_dir` to get this value for a minimalfile environment.
    pub state_base_dir: &'a Path,

    /// The 'top level' packages that were called for in this environment.
    pub top_levels: &'a Vec<BuildSpecRef>,
    /// All packages that will be called for in this environment (transitive dependencies).
    ///
    /// Call `Transitives::for_toplevels` to get this list.
    pub transitives: &'a HashMap<BuildSpecRef, TransitivesDep>,

    /// The working directory to use for this environment.
    pub cwd: &'a Path,
    /// File/directory mounts in the environment, if any.
    pub patches: Option<&'a EnvPatches>,
    /// Environment variables, if any.
    pub env_vars: Option<&'a HashMap<String, String>>,
    /// The hostname to set in the environment, if any.
    pub hostname: Option<String>,
}

impl<'a> Runnable for EnvSetup<'a> {
    type Result = RunnableEnv;

    async fn run<'b>(&mut self, opts: &Options<'b>) -> Result<Self::Result, Error> {
        let mut patch = self.patches.cloned().unwrap_or_else(EnvPatches::default);
        let mut env_vars = self
            .env_vars
            .cloned()
            .unwrap_or_else(|| HashMap::with_capacity(12));
        // TODO: I think this means our env-vars take precedence, not ones from the minimalfile. Fix?

        // In rootfs: Create the cwd tree
        std::fs::create_dir_all(opts.exec_base.join(self.cwd)).map_err(anyhow::Error::from)?;
        // In durable statedir: Make sure the directories for some of the env-vars exist
        std::fs::create_dir_all(self.state_base_dir.join("home")).map_err(anyhow::Error::from)?; // XDG_CONFIG_HOME ala ~/.config
        std::fs::create_dir_all(self.state_base_dir.join("data")).map_err(anyhow::Error::from)?; // XDG_DATA_HOME ala ~/.local/share
        std::fs::create_dir_all(self.state_base_dir.join("cache")).map_err(anyhow::Error::from)?; // XDG_CACHE_HOME  ala ~/.cache
        std::fs::create_dir_all(self.state_base_dir.join("state")).map_err(anyhow::Error::from)?; // XDG_STATE_HOME  ala ~/.local/state

        // Check attributes on each dependency to see if theres any additional env wiring.
        let mut needs_dns = false;
        for dep in self.transitives.keys() {
            let b = opts.graph.get(dep).unwrap();
            if let Some(dirs) = b.attrs.get("env_dir_mappings") {
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
            if let Some(dirs) = b.attrs.get("env_file_mappings") {
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
            if let Some(dir) = b.attrs.get("env_state_wiring") {
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

            needs_dns |= b.abstract_deps.get("dns").is_some();
        }

        if needs_dns {
            common::synth_dns_config(&opts.exec_base).map_err(anyhow::Error::from)?;
        }

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

        // Iterate all file/dir patches and make sure their bind mounts exist, also check
        // the bind target paths and make empty dirs/files as necessary.
        for (dir, _opts) in patch.dir.iter() {
            let dir = if let Some(stripped) = dir.strip_prefix("~/") {
                home_dir().unwrap().join(stripped)
            } else {
                PathBuf::from(dir.clone())
            };

            // Create the dir if it doesnt exist
            if let Err(e) = std::fs::create_dir(&dir)
                && e.kind() != std::io::ErrorKind::AlreadyExists
            {
                return Err(anyhow::Error::from(e).into());
            }
            // Create the dir in the sandbox rootfs
            std::fs::create_dir_all(opts.exec_base.join(&dir)).map_err(anyhow::Error::from)?;
        }
        for (file, _opts) in patch.file.iter() {
            let file = if let Some(stripped) = file.strip_prefix("~/") {
                home_dir().unwrap().join(stripped)
            } else {
                PathBuf::from(file.clone())
            };

            // Create the file if it doesnt exist
            if !std::fs::exists(&file).map_err(anyhow::Error::from)? {
                std::fs::write(&file, if file.ends_with(".json") { "{}" } else { "" })
                    .map_err(anyhow::Error::from)?;
            }
            // Create the dir in the sandbox rootfs
            std::fs::create_dir_all(opts.exec_base.join(file.parent().unwrap()))
                .map_err(anyhow::Error::from)?;
        }

        // Create the state directory in the rootfs (the bind mount target)
        std::fs::create_dir_all(opts.exec_base.join("state")).map_err(anyhow::Error::from)?;

        // Env vars: State directories
        env_vars.insert("XDG_CONFIG_HOME".to_string(), "/state/home".to_string());
        env_vars.insert("XDG_DATA_HOME".to_string(), "/state/data".to_string());
        env_vars.insert("XDG_CACHE_HOME".to_string(), "/state/cache".to_string());
        env_vars.insert("XDG_STATE_HOME".to_string(), "/state/state".to_string());
        // Env vars: usual trash
        env_vars.insert(
            "PATH".to_string(),
            "/usr/bin:/bin:/usr/sbin:/sbin".to_string(),
        );
        env_vars.insert(
            "HOME".to_string(),
            std::env::var("HOME").unwrap_or("/state/home".to_string()),
        );
        env_vars.insert("LANG".to_string(), "en_US.utf8".to_string());
        env_vars.insert("LC_ALL".to_string(), "en_US.utf8".to_string());
        if let Ok(term) = std::env::var("TERM") {
            env_vars.insert("TERM".to_string(), term);
        }
        if let Ok(ct) = std::env::var("COLORTERM") {
            env_vars.insert("COLORTERM".to_string(), ct);
        }
        if let Ok(lsc) = std::env::var("LS_COLORS") {
            env_vars.insert("LS_COLORS".to_string(), lsc);
        }

        Ok(RunnableEnv {
            container: {
                let mut container = hakoniwa::Container::new();
                container
                    .rootfs(&opts.exec_base)
                    .map_err(anyhow::Error::from)?
                    .devfsmount("/dev")
                    .tmpfsmount("/tmp")
                    .bindmount_rw(self.cwd.to_str().unwrap(), self.cwd.to_str().unwrap())
                    .bindmount_rw(self.state_base_dir.to_str().unwrap(), "/state")
                    .symlink("/usr/bin", "/bin")
                    .symlink("/usr/lib", "/lib64");
                if let Some(hn) = &self.hostname {
                    let etc_hostname = opts.exec_base.join("etc").join("hostname");
                    if !std::fs::exists(&etc_hostname)? {
                        std::fs::write(etc_hostname, format!("{}\n", hn))?;
                    }
                    container.unshare(hakoniwa::Namespace::Uts);
                    container.hostname(hn);
                }
                container
            },

            cwd: self.cwd.to_path_buf(),
            patches: patch,
            env_vars,
        })
    }
}

/// Describes a successfully-configured runtime environment.
pub struct RunnableEnv {
    container: hakoniwa::Container,

    cwd: PathBuf,
    patches: EnvPatches,
    env_vars: HashMap<String, String>,
}

impl RunnableEnv {
    fn container(&self) -> Result<hakoniwa::Container, Error> {
        let mut container = self.container.clone();

        // Setup all the bind mounts that came through as patches
        for (dir, opts) in self.patches.dir.iter() {
            let dir = if let Some(stripped) = dir.strip_prefix("~/") {
                home_dir().unwrap().join(stripped)
            } else {
                PathBuf::from(dir.clone())
            };

            match opts {
                PatchSetting::ReadWrite => {
                    container.bindmount_rw(dir.to_str().unwrap(), dir.to_str().unwrap());
                }
                PatchSetting::ReadOnly => {
                    container.bindmount_ro(dir.to_str().unwrap(), dir.to_str().unwrap());
                }
            }
        }
        for (file, opts) in self.patches.file.iter() {
            let file = if let Some(stripped) = file.strip_prefix("~/") {
                home_dir().unwrap().join(stripped)
            } else {
                PathBuf::from(file.clone())
            };

            container.mount(
                file.to_str().unwrap(),
                file.to_str().unwrap(),
                "",
                match opts {
                    PatchSetting::ReadOnly => {
                        hakoniwa::MountOptions::BIND | hakoniwa::MountOptions::RDONLY
                    }
                    PatchSetting::ReadWrite => hakoniwa::MountOptions::BIND,
                },
            );
        }

        Ok(container)
    }

    pub fn command<I, S>(&self, program: &str, args: I) -> Result<hakoniwa::Command, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut command = self.container()?.command(program);
        command.args(args);
        command.current_dir(&self.cwd);
        self.env_vars.iter().for_each(|(var, val)| {
            command.env(var, val);
        });

        Ok(command)
    }
}
