//! Finding & reading the `minimal.toml` file.

use std::collections::HashMap;
use std::env;
use std::path::{Component, Path, PathBuf};

mod error;
pub use error::Error;
mod tasks;
pub use tasks::Task;

pub const MFILE_NAME: &str = "minimal.toml";

/// A value from serde that can either be a string, or an array of strings.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum StrOrList {
    Single(String),
    Multiple(Vec<String>),
}

/// Defines a link to an upper layer (repo which contains a minimal file).
///
/// This is typically the `[upstream]` or `[stdlib]` section of [File], describing the upstream or stdlib to use.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, Hash)]
pub struct LinkConfig {
    /// The URL passed to git to fetch the repository.
    pub repo: String,
    /// If set, the branch of the repo to track. `rev` is bumped to the HEAD of this branch on `minimal update`.
    pub branch: Option<String>,
    /// The pinned git commit hash to use for this link.
    ///
    /// TODO: Remove the `rev` alias ~feb, that was the old key.
    #[serde(alias = "rev")]
    pub locked_commit: Option<String>,
}

impl LinkConfig {
    pub fn as_spec_origin(&self) -> Option<common::SpecOrigin> {
        self.locked_commit.as_ref().map(|rev| {
            common::SpecOrigin::Repo(common::repo_spec::Repo::Git {
                url: self.repo.clone(),
                rev: rev.clone(),
                tracking: self
                    .branch
                    .as_ref()
                    .map(|b| common::repo_spec::GitRef::Branch(b.clone())),
            })
        })
    }
}

/// Describes options for how a directory or file is patched into some task environment.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum PatchSetting {
    #[default]
    #[serde(alias = "ro", alias = "read-only")]
    ReadOnly,
    #[serde(alias = "rw", alias = "read-write")]
    ReadWrite,
}

/// Describes the set of directories/files patched into a task environment, from the host environment.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct EnvPatches {
    /// The list of directories to be patched into the environment. Keys are expected to be path strings,
    /// either absolute paths are starting with the prefix `~/` to be rooted in the users home directory.
    #[serde(default, alias = "dirs")]
    pub dir: HashMap<String, PatchSetting>,
    /// The list of files to be patched into the environment. Keys are expected to be path strings,
    /// either absolute paths are starting with the prefix `~/` to be rooted in the users home directory.
    #[serde(default, alias = "files")]
    pub file: HashMap<String, PatchSetting>,
}

impl EnvPatches {
    /// Combines the given [EnvPatches] into `self`. If keys conflict, `other` takes precedence.
    pub fn union(&mut self, other: &Self) {
        self.dir
            .extend(other.dir.iter().map(|(k, v)| (k.clone(), v.clone())));
        self.file
            .extend(other.file.iter().map(|(k, v)| (k.clone(), v.clone())));
    }
}

/// Default settings applied to minimal's use in the repo and to objects in the mfile.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Defaults {
    /// The harness to use for this repo.
    #[serde(default)]
    pub harness: Option<String>,
    /// The default profile to use for tasks which don't set their own profile.
    #[serde(default)]
    pub profile: Option<String>,
    /// The default state_key to use for tasks which don't set their own state_key.
    #[serde(default)]
    pub state_key: Option<String>,
}

/// Describes the specific type of output being generated.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum OutputKind {
    #[default]
    #[serde(alias = "oci-image")]
    OciImage,
}

/// An output, defined in a `[outputs.<output_name>]` section of [File].
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Output {
    #[serde(alias = "type")]
    pub ty: OutputKind,
    #[serde(default)]
    pub packages: Vec<String>,

    #[serde(default)]
    pub entrypoint: Option<StrOrList>,
    #[serde(default)]
    pub cmd: Option<StrOrList>,
    #[serde(default, alias = "env_vars")]
    pub vars: HashMap<String, String>,
}

/// Which directory layout this layer/repo used for minimal configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Layout {
    /// The 'abridged' layout. The minimal file is located at `./{MFILE_NAME}`.
    ///
    /// If present, the packages directory is at ./packages.
    /// If present, the profiles directory is at ./profiles.
    /// If present, the harnesses directory is at ./harnesses.
    Root,
    /// The 'full' layout. The minimal file is located at `./.minimal/{MFILE_NAME}`.
    ///
    /// If present, the packages directory is at ./.minimal/packages.
    /// If present, the profiles directory is at ./.minimal/profiles.
    /// If present, the harnesses directory is at ./.minimal/harnesses.
    DotMinimal,
}

/// The loaded representation of the `minimal.toml` file.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct File {
    /// The previous link in the software supply chain.
    #[serde(alias = "base")]
    pub upstream: LinkConfig,
    /// What version of the standard library to use.
    #[serde(default = "default_stdlib")]
    pub stdlib: LinkConfig,
    /// Default harness, profile etc.
    #[serde(default, alias = "default")]
    pub defaults: Defaults,

    /// Task definitions, invoked with `minimal run <task name>`.
    #[serde(default)]
    pub tasks: HashMap<String, Task>,
    /// Output definitions.
    #[serde(default)]
    pub outputs: HashMap<String, Output>,

    /// Where the minimal file is located on disk, if it was loaded from disk.
    #[serde(skip)]
    mfile_path: Option<PathBuf>,
    /// What layout this repo/layer is using, if loaded from disk.
    #[serde(skip)]
    layout: Option<Layout>,
}

pub fn default_stdlib() -> LinkConfig {
    LinkConfig {
        repo: "https://github.com/gominimal/std".to_string(),
        branch: None,
        locked_commit: None,
    }
}

impl File {
    /// Searches from the given directory backwards to load the `minimal.toml` file.
    pub fn from_dir_recursive<P: AsRef<Path>>(dir: P) -> Result<Self, Error> {
        match Self::from_dir(&dir) {
            Ok(f) => Ok(f),
            Err(Error::NotFound) => {
                // Not found at this directory, try the parent
                if let Some(parent) = dir.as_ref().parent() {
                    // We don't traverse outside of a users HOME if its set.
                    if let Some(home) = env::home_dir()
                        && home == parent
                    {
                        return Err(Error::NotFound);
                    }

                    Self::from_dir_recursive(parent)
                } else {
                    Err(Error::NotFound)
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Loads the minimal file from the given directory path. The given
    /// directory must be a repository / minimalfile root.
    pub fn from_dir<P: AsRef<Path>>(dir: P) -> Result<Self, Error> {
        // Check for the minimal file at the directory root.
        let path = dir.as_ref().join(MFILE_NAME);
        match std::fs::read(&path) {
            Ok(file_data) => {
                let conflicting_path = dir.as_ref().join(".minimal").join(MFILE_NAME);
                if std::fs::exists(&conflicting_path)
                    .map_err(|e| Error::IO("stat", conflicting_path.clone(), e))?
                {
                    return Err(Error::ConflictingLayouts(vec![path, conflicting_path]));
                }

                let mut mfile: Self = toml::from_slice(&file_data).map_err(Error::Format)?;
                mfile.mfile_path = Some(path.to_path_buf());
                mfile.layout = Some(Layout::Root);
                return Ok(mfile);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::IO("minimal file", path, e)),
        };

        // Check for the minimal file at `./.minimal`.
        let path = dir.as_ref().join(".minimal").join(MFILE_NAME);
        match std::fs::read(&path) {
            Ok(file_data) => {
                let mut mfile: Self = toml::from_slice(&file_data).map_err(Error::Format)?;
                mfile.mfile_path = Some(path.to_path_buf());
                mfile.layout = Some(Layout::DotMinimal);
                Ok(mfile)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::NotFound),
            Err(e) => Err(Error::IO("minimal file", path, e)),
        }
    }

    /// Returns the path to the directory where the minimal file is located.
    pub fn dir_path(&self) -> Option<&Path> {
        match &self.mfile_path {
            None => None,
            Some(fname) => fname.parent(),
        }
    }
    /// Returns the path to the minimal file.
    pub fn file_path(&self) -> Option<&PathBuf> {
        self.mfile_path.as_ref()
    }
    /// Returns the layout this minimal file was on disk.
    pub fn layout(&self) -> Option<&Layout> {
        self.layout.as_ref()
    }
    /// Returns the path to the 'repo root', based on the detected layout when the minimal file was read from disk.
    pub fn repo_path(&self) -> Option<&Path> {
        match self.layout {
            None => None,
            Some(Layout::Root) => self.dir_path(),
            Some(Layout::DotMinimal) => self.dir_path().and_then(|p| p.parent()),
        }
    }

    /// Returns the task of the given name, if one exists. Default settings for unset fields such as profile have
    /// been applied to the returned object.
    pub fn task(&self, name: &str) -> Option<Task> {
        self.tasks.get(name).map(|t| {
            let mut task = t.clone();
            if let Some(default_profile) = &self.defaults.profile
                && task.profile.is_none()
            {
                task.profile = Some(default_profile.clone());
            }
            if let Some(default_state_key) = &self.defaults.state_key
                && task.state_key.is_none()
            {
                task.state_key = Some(default_state_key.clone());
            }
            task
        })
    }

    /// Returns the path to the durable state directory for the given key.
    ///
    /// None is returned if the location of the minimal file on disk is not known.
    pub fn state_dir<P: AsRef<Path>>(&self, state_key: &str, env_base_dir: P) -> Option<PathBuf> {
        self.dir_path().map(|mfile_dir| {
            let hd = env::home_dir();

            let (start_marker, components) = if let Some(home) = &hd
                && mfile_dir.starts_with(home)
            {
                (
                    '~',
                    mfile_dir.strip_prefix(hd.unwrap()).unwrap().components(),
                )
            } else {
                ('-', mfile_dir.components())
            };

            env_base_dir
                .as_ref()
                .join(format!(
                    "{}{}",
                    start_marker,
                    components
                        .filter(|c| matches!(c, Component::Normal(_)))
                        .map(|c| c.as_os_str().to_str().unwrap())
                        .map(|c| c.replace("-", "--"))
                        .collect::<Vec<_>>()
                        .join("-")
                ))
                .join(state_key)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use tempfile::tempdir;

    #[test]
    fn deserialize_smoketest() {
        let mf: File = toml::from_str(indoc! {
            r#"
            [upstream]
            repo = "https://github.com/gominimal/pkgs"
            branch = "main"

            [tasks.test]
            state_key = "test"
            patch.dir."~/.claude" = "read-write"
            packages = ["base", "go"]
            cmd = "go test ./..."

            [outputs.test]
            type = "oci-image"
            packages = ["bash", "go"]
            entrypoint = "/bin/sh"
            "#
        })
        .unwrap();

        assert_eq!(
            mf,
            File {
                upstream: LinkConfig {
                    repo: "https://github.com/gominimal/pkgs".to_string(),
                    branch: Some("main".to_string()),
                    locked_commit: None,
                },
                stdlib: default_stdlib(),
                defaults: Default::default(),
                tasks: [(
                    "test".to_string(),
                    Task {
                        state_key: Some("test".to_string()),
                        profile: None,
                        vars: HashMap::new(),
                        patch: EnvPatches {
                            dir: [("~/.claude".to_string(), PatchSetting::ReadWrite)].into(),
                            file: HashMap::new()
                        },
                        packages: vec!["base".to_string(), "go".to_string()],
                        cmd: "go test ./...".to_string(),
                        inherit_cwd: false,
                    }
                )]
                .into(),
                outputs: [(
                    "test".to_string(),
                    Output {
                        ty: OutputKind::OciImage,
                        packages: vec!["bash".to_string(), "go".to_string()],
                        cmd: None,
                        entrypoint: Some(StrOrList::Single("/bin/sh".to_string())),
                        vars: HashMap::new(),
                    }
                )]
                .into(),
                mfile_path: None,
                layout: None,
            }
        )
    }

    #[test]
    fn from_dir_abridged() {
        let dir = tempdir().unwrap();

        // write `minimal.toml`.
        std::fs::write(
            dir.path().join(MFILE_NAME),
            indoc! {
                r#"
            [base]
            repo = "https://github.com/gominimal/pkgs"
            branch = "main"
            "#
            },
        )
        .unwrap();

        // test from `./`, also check if `from` is set
        let mfile = File::from_dir_recursive(dir.path());
        assert!(
            matches!(
                mfile,
                Ok(File {
                    mfile_path: Some(_),
                    layout: Some(Layout::Root),
                    ..
                })
            ),
            "unexpected mfile {:?}",
            mfile
        );
        assert_eq!(mfile.unwrap().dir_path().unwrap(), dir.path());

        std::fs::create_dir(dir.path().join("nested")).unwrap();
        assert!(File::from_dir_recursive(dir.path().join("nested")).is_ok()); // test from `./nested`
    }

    #[test]
    fn from_dir_full() {
        let dir = tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".minimal")).unwrap();

        // write `minimal.toml`.
        std::fs::write(
            dir.path().join(".minimal").join(MFILE_NAME),
            indoc! {
                r#"
            [base]
            repo = "https://github.com/gominimal/pkgs"
            branch = "main"
            "#
            },
        )
        .unwrap();

        // test from `./`, also check if `from` is set
        let mfile = File::from_dir_recursive(dir.path());
        assert!(
            matches!(
                mfile,
                Ok(File {
                    mfile_path: Some(_),
                    layout: Some(Layout::DotMinimal),
                    ..
                })
            ),
            "unexpected mfile {:?}",
            mfile
        );
        assert_eq!(
            mfile.unwrap().dir_path().unwrap(),
            dir.path().join(".minimal")
        );

        std::fs::create_dir(dir.path().join("nested")).unwrap();
        assert!(File::from_dir_recursive(dir.path().join("nested")).is_ok()); // test from `./nested`
    }

    #[test]
    fn task_cmd_and_args() {
        let t: Task = toml::from_str(indoc! {
            r#"
            env = "test"
            cmd = "go test ./..."
            "#
        })
        .unwrap();
        assert_eq!(
            t.cmd_and_args(),
            (
                "/bin/go".to_string(),
                vec!["test".to_string(), "./...".to_string()]
            )
        );
    }

    #[test]
    fn env_patches_union() {
        let mut slf: EnvPatches = toml::from_str(indoc! {
            r#"
            dir."slf" = "read-write"
            dir."~/.claude" = "read-write"
            "#
        })
        .unwrap();
        let other = EnvPatches {
            dir: HashMap::from_iter([
                ("~/.claude".to_string(), PatchSetting::ReadOnly),
                ("other".to_string(), PatchSetting::ReadOnly),
            ]),
            ..Default::default()
        };

        slf.union(&other);

        assert_eq!(
            slf,
            EnvPatches {
                dir: [
                    ("~/.claude".to_string(), PatchSetting::ReadOnly),
                    ("slf".to_string(), PatchSetting::ReadWrite),
                    ("other".to_string(), PatchSetting::ReadOnly),
                ]
                .into(),
                file: HashMap::new()
            }
        );
    }
}
