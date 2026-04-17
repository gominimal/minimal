//! Finding & reading the `minimal.toml` file.

use std::collections::HashMap;
use std::env::{self, home_dir};
use std::path::{Component, Path, PathBuf};

mod error;
pub use error::Error;
mod tasks;
use serde::{Deserializer, Serializer};
pub use tasks::{Task, TaskAction};

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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, Hash)]
#[serde(untagged)]
pub enum LinkConfig {
    Git {
        /// The URL passed to git to fetch the repository.
        repo: String,
        /// If set, the branch of the repo to track. `rev` is bumped to the HEAD of this branch on `minimal update`.
        branch: Option<String>,
        /// The pinned git commit hash to use for this link.
        locked_commit: Option<String>,
    },
    Dir {
        dir: String,
    },
}

impl Default for LinkConfig {
    fn default() -> Self {
        LinkConfig::Git {
            repo: String::default(),
            branch: None,
            locked_commit: None,
        }
    }
}

impl LinkConfig {
    /// Represents this [LinkConfig] as a [common::SpecOrigin], if possible.
    ///
    /// This method returns `None` for git links with no `locked_commit` set.
    pub fn as_spec_origin(&self) -> Option<common::SpecOrigin> {
        match self {
            LinkConfig::Git {
                repo,
                branch,
                locked_commit,
            } => locked_commit.as_ref().map(|rev| {
                common::SpecOrigin::Repo(common::repo_spec::Repo::Git {
                    url: repo.clone(),
                    rev: rev.clone(),
                    tracking: branch
                        .as_ref()
                        .map(|b| common::repo_spec::GitRef::Branch(b.clone())),
                })
            }),
            LinkConfig::Dir { dir } => Some(common::SpecOrigin::from_dir(dir)),
        }
    }

    pub fn as_url(&self) -> Option<&String> {
        match self {
            LinkConfig::Dir { .. } => None,
            LinkConfig::Git { repo, .. } => Some(repo),
        }
    }
    pub fn as_branch(&self) -> Option<&String> {
        match self {
            LinkConfig::Git {
                branch: Some(branch),
                ..
            } => Some(branch),
            _ => None,
        }
    }

    fn fixup_relative<P: AsRef<Path>>(&mut self, mfile_path: P) {
        if let (LinkConfig::Dir { dir }, Some(parent_dir)) = (self, mfile_path.as_ref().parent()) {
            if !dir.starts_with("/") {
                let new = parent_dir.join(&dir);
                *dir = new.to_str().unwrap().to_string();
            }
        }
    }
}

/// Describes the upstream, the previous link in the software supply chain.
///
/// The top-most link will not have an upstream, so this may not be set in all layers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct Upstream {
    #[serde(flatten)]
    pub link: LinkConfig,

    #[serde(default, alias = "sideload")]
    sideloads: Vec<Sideload>,
}

impl Upstream {
    fn fixup_relative<P: AsRef<Path>>(&mut self, mfile_path: P) {
        self.link.fixup_relative(mfile_path);
    }
}

impl AsRef<LinkConfig> for Upstream {
    fn as_ref(&self) -> &LinkConfig {
        &self.link
    }
}

/// A sideload configured in this repo.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct Sideload {
    #[serde(flatten)]
    link: LinkConfig,
    #[serde(default)]
    params: Option<toml::Table>,
}

/// The value of a declared environment variable. Either a literal value
/// or the symbolic variant `{ inherit = true }`, meaning to read it from the parent process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvVarValue {
    Value(String),
    Inherit,
}

impl<'de> serde::Deserialize<'de> for EnvVarValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::{self, MapAccess, Visitor};
        struct VarVisitor;
        impl<'de> Visitor<'de> for VarVisitor {
            type Value = EnvVarValue;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a string or {{ inherit = true }}")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<EnvVarValue, E> {
                Ok(EnvVarValue::Value(v.to_owned()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<EnvVarValue, E> {
                Ok(EnvVarValue::Value(v))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<EnvVarValue, A::Error> {
                let key: String = map
                    .next_key()?
                    .ok_or_else(|| de::Error::custom("empty map"))?;
                if key != "inherit" {
                    return Err(de::Error::unknown_field(&key, &["inherit"]));
                }
                let val: bool = map.next_value()?;
                if !val {
                    return Err(de::Error::custom("`inherit` must be true"));
                }
                if map.next_key::<String>()?.is_some() {
                    return Err(de::Error::custom("unexpected extra fields"));
                }
                Ok(EnvVarValue::Inherit)
            }
        }
        d.deserialize_any(VarVisitor)
    }
}

impl serde::Serialize for EnvVarValue {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            EnvVarValue::Value(v) => s.serialize_str(v),
            EnvVarValue::Inherit => {
                use serde::ser::SerializeMap;
                let mut map = s.serialize_map(Some(1))?;
                map.serialize_entry("inherit", &true)?;
                map.end()
            }
        }
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

impl From<EnvPatches> for Vec<common::FsMapping> {
    fn from(val: EnvPatches) -> Self {
        let h = home_dir().unwrap();
        let map_path = |path: String| {
            if let Some(stripped) = path.strip_prefix("~/") {
                h.join(stripped).to_str().unwrap().to_string()
            } else {
                path
            }
        };

        val.dir
            .into_iter()
            .map(|(path, settings)| common::FsMapping {
                host_path: map_path(path),
                sandbox_path: None, // use host
                create_if_missing: true,
                is_file: false,
                read_only: match settings {
                    PatchSetting::ReadOnly => true,
                    PatchSetting::ReadWrite => false,
                },
            })
            .chain(
                val.file
                    .into_iter()
                    .map(|(path, settings)| common::FsMapping {
                        host_path: map_path(path),
                        sandbox_path: None, // use host
                        create_if_missing: true,
                        is_file: true,
                        read_only: match settings {
                            PatchSetting::ReadOnly => true,
                            PatchSetting::ReadWrite => false,
                        },
                    }),
            )
            .collect()
    }
}

/// Default settings applied to minimal's use in the repo and to objects in the mfile.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct Defaults {
    /// The default profile to use for tasks which don't set their own profile.
    #[serde(default)]
    pub profile: Option<String>,
    /// The default state_key to use for tasks which don't set their own state_key.
    #[serde(default)]
    pub state_key: Option<String>,

    /// Any fields which are not understood by this version of minimal.
    #[serde(flatten)]
    pub extra: HashMap<String, toml::Value>,
}

impl Eq for Defaults {}

/// Configuration for the harness applied to this repository.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct Harness {
    #[serde(alias = "use")]
    pub name: String,
    /// Additional build_packages needed by this repo.
    #[serde(default)]
    pub build_packages: Vec<String>,
    /// Additional runtime_packages needed by this repo.
    #[serde(default)]
    pub runtime_packages: Vec<String>,

    /// Any fields which are not understood by this version of minimal.
    #[serde(flatten)]
    pub extra: HashMap<String, toml::Value>,
}

impl Eq for Harness {}

/// Describes the specific type of output being generated.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum OutputKind {
    #[default]
    #[serde(alias = "oci-image")]
    OciImage,
}

/// An output, defined in a `[outputs.<output_name>]` section of [File].
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
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

    /// Target architecture for OCI images. Defaults to "amd64".
    /// Common values: "amd64", "arm64"
    #[serde(default)]
    pub arch: Option<String>,

    /// Any fields which are not understood by this version of minimal.
    #[serde(flatten)]
    extra: HashMap<String, toml::Value>,
}

/// Configuration for the standard library.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Stdlib {
    #[serde(alias = "min_version")]
    pub minimum_version: Option<String>,
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
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct File {
    /// The previous link in the software supply chain.
    #[serde(alias = "base")]
    pub upstream: Option<Upstream>,
    /// The schema for any parameters which configure this layer.
    pub params: Option<args::ArgsSpec>,

    /// Default profile, state_key etc.
    #[serde(default, alias = "default")]
    pub defaults: Defaults,
    /// The harness configured on this repository, if any.
    #[serde(default)]
    pub harness: Option<Harness>,

    /// Task definitions, invoked with `minimal run <task name>`.
    #[serde(default)]
    pub tasks: HashMap<String, Task>,
    /// Output definitions.
    #[serde(default)]
    pub outputs: HashMap<String, Output>,
    /// Configuration relevant to the standard library.
    #[serde(default)]
    pub stdlib: Stdlib,

    /// Any fields which are not understood by this version of minimal.
    #[serde(flatten)]
    extra: HashMap<String, toml::Value>,

    /// Where the minimal file is located on disk, if it was loaded from disk.
    #[serde(skip)]
    mfile_path: Option<PathBuf>,
    /// What layout this repo/layer is using, if loaded from disk.
    #[serde(skip)]
    layout: Option<Layout>,
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

    /// Helper to finish initialization of the structure after being deserialized.
    fn init_toml(mut self, path: &PathBuf, layout: Layout) -> Result<Self, Error> {
        self.mfile_path = Some(path.to_path_buf());
        self.layout = Some(layout);
        if let Some(u) = self.upstream.as_mut() {
            u.fixup_relative(path);
            for sideload in u.sideloads.iter_mut() {
                sideload.link.fixup_relative(path);
            }
        }
        // Parameters, if set, must declare defaults.
        if let Some(params) = &self.params {
            for (n, s) in params.0.iter() {
                if s.default.is_none() {
                    return Err(Error::MissingParamDefault(n.clone()));
                }
            }
        }
        self.warn_unknown_fields();
        Ok(self)
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

                return Self::init_toml(
                    toml::from_slice(&file_data).map_err(Error::Format)?,
                    &path,
                    Layout::Root,
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::IO("minimal file", path, e)),
        };

        // Check for the minimal file at `./.minimal`.
        let path = dir.as_ref().join(".minimal").join(MFILE_NAME);
        match std::fs::read(&path) {
            Ok(file_data) => Self::init_toml(
                toml::from_slice(&file_data).map_err(Error::Format)?,
                &path,
                Layout::DotMinimal,
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::NotFound),
            Err(e) => Err(Error::IO("minimal file", path, e)),
        }
    }

    // Creates a synthetic minimal file not backed on the filesystem.
    //
    // DO NOT USE unless you know what you are doing.
    pub fn synthetic(upstream: LinkConfig) -> Self {
        Self {
            upstream: Some(Upstream {
                link: upstream,
                sideloads: vec![],
            }),
            ..Default::default()
        }
    }

    fn warn_unknown_fields(&self) {
        let mut was_unknown_fields = false;
        if !self.extra.is_empty() {
            tracing::warn!(
                "unknown fields in {}: {}",
                MFILE_NAME,
                self.extra.keys().cloned().collect::<Vec<_>>().join(",")
            );
            was_unknown_fields = true;
        }
        if !self.defaults.extra.is_empty() {
            tracing::warn!(
                "unknown fields in [defaults] section of {}: {}",
                MFILE_NAME,
                self.defaults
                    .extra
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(",")
            );
            was_unknown_fields = true;
        }
        if let Some(harness) = &self.harness
            && !harness.extra.is_empty()
        {
            tracing::warn!(
                "unknown fields in [harness] section of {}: {}",
                MFILE_NAME,
                harness.extra.keys().cloned().collect::<Vec<_>>().join(",")
            );
            was_unknown_fields = true;
        }

        for (task_name, task) in &self.tasks {
            if !task.extra.is_empty() {
                tracing::warn!(
                    "unknown fields in task {}: {}",
                    task_name,
                    task.extra.keys().cloned().collect::<Vec<_>>().join(",")
                );
                was_unknown_fields = true;
            }
        }
        for (output_name, output) in &self.outputs {
            if !output.extra.is_empty() {
                tracing::warn!(
                    "unknown fields in output {}: {}",
                    output_name,
                    output.extra.keys().cloned().collect::<Vec<_>>().join(",")
                );
                was_unknown_fields = true;
            }
        }

        if was_unknown_fields {
            tracing::warn!("help: do you need to update to a newer version of minimal?");
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
    ///
    /// The returned task will not have had any string interpolations applied.
    pub fn task(&self, name: &str) -> Option<Task> {
        self.tasks.get(name).map(|t| {
            let mut task = t.clone();
            self.hydrate_task_defaults(&mut task);
            task
        })
    }

    /// Applies additional settings to hydrate a task, namely:
    ///  - default profile if set (and not set on the task)
    ///  - default state_key if set (and not set on the task)
    ///  - additional build_packages & runtime_packages set on the harness
    ///
    /// The returned task will not have had any string interpolations applied.
    pub fn hydrate_task_defaults(&self, task: &mut Task) {
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
        if let Some(harness) = &self.harness {
            task.packages.extend(
                harness
                    .build_packages
                    .iter()
                    .chain(harness.runtime_packages.iter())
                    .filter(|p| !task.packages.contains(p))
                    .cloned()
                    .collect::<Vec<_>>(),
            );
        }
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
    use crate::tasks::TaskAction;

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

            [params]
            str = "string"
            some_enum = {type = "[a,b]", default = "b"}

            [tasks.test]
            state_key = "test"
            patch.dir."~/.claude" = "read-write"
            packages = ["base", "go"]
            exec = "go test ./..."

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
                upstream: Some(Upstream {
                    link: LinkConfig::Git {
                        repo: "https://github.com/gominimal/pkgs".to_string(),
                        branch: Some("main".to_string()),
                        locked_commit: None,
                    },
                    sideloads: vec![]
                }),
                params: Some(args::ArgsSpec(HashMap::from([
                    (
                        "str".to_string(),
                        args::ArgSpec {
                            spec: args::ArgSchema::Scalar(args::PrimitiveSpec::String),
                            help: None,
                            default: None,
                        }
                    ),
                    (
                        "some_enum".to_string(),
                        args::ArgSpec {
                            spec: args::ArgSchema::Enum(["a".to_string(), "b".to_string()].into()),
                            help: None,
                            default: Some("b".to_string()),
                        }
                    ),
                ]))),
                defaults: Default::default(),
                harness: None,
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
                        action: TaskAction::exec_from_str("go test ./..."),
                        inherit_cwd: false,
                        interactive: false,
                        args: Default::default(),
                        extra: HashMap::new(),
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
                        arch: None,
                        extra: HashMap::new(),
                    }
                )]
                .into(),
                stdlib: Default::default(),
                extra: HashMap::new(),
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

    #[test]
    fn output_arch_defaults_to_none() {
        let mf: File = toml::from_str(indoc! {
            r#"
            [outputs.image]
            type = "oci-image"
            "#
        })
        .unwrap();
        assert_eq!(mf.outputs["image"].arch, None);
    }

    #[test]
    fn output_arch_parses_arm64() {
        let mf: File = toml::from_str(indoc! {
            r#"
            [outputs.image]
            type = "oci-image"
            arch = "arm64"
            "#
        })
        .unwrap();
        assert_eq!(mf.outputs["image"].arch, Some("arm64".to_string()));
    }

    #[test]
    fn output_arch_parses_amd64() {
        let mf: File = toml::from_str(indoc! {
            r#"
            [outputs.image]
            type = "oci-image"
            arch = "amd64"
            "#
        })
        .unwrap();
        assert_eq!(mf.outputs["image"].arch, Some("amd64".to_string()));
    }

    #[test]
    fn output_with_arch_and_other_fields() {
        let mf: File = toml::from_str(indoc! {
            r#"
            [outputs.app]
            type = "oci-image"
            arch = "arm64"
            packages = ["base", "openssl"]
            entrypoint = "/app/server"
            vars = { PORT = "8080" }
            "#
        })
        .unwrap();
        let output = &mf.outputs["app"];
        assert_eq!(output.arch, Some("arm64".to_string()));
        assert_eq!(output.packages, vec!["base", "openssl"]);
        assert_eq!(
            output.entrypoint,
            Some(StrOrList::Single("/app/server".to_string()))
        );
        assert_eq!(output.vars["PORT"], "8080");
    }
}
