//! Finding & reading the `minimal.toml` file.

use std::collections::{BTreeMap, HashMap};
use std::env::{self, home_dir};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

mod error;
pub use error::Error;
mod package_composable;
pub use package_composable::{PackageComposable, PackageFsMapping, StateWiring};
mod project_composable;
pub use project_composable::ProjectComposable;
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
        if let (LinkConfig::Dir { dir }, Some(parent_dir)) = (self, mfile_path.as_ref().parent())
            && !dir.starts_with("/")
        {
            let new = parent_dir.join(&dir);
            *dir = new.to_str().unwrap().to_string();
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
    pub fn from_link(link: LinkConfig) -> Self {
        Self {
            link,
            sideloads: vec![],
        }
    }

    fn fixup_relative<P: AsRef<Path>>(&mut self, mfile_path: P) {
        self.link.fixup_relative(mfile_path);
    }

    pub fn sideloads(&self) -> &[Sideload] {
        &self.sideloads
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
    params: Option<HashMap<String, args::DiskArg>>,
}

impl Sideload {
    pub fn link(&self) -> &LinkConfig {
        &self.link
    }

    pub fn params(&self) -> Option<&HashMap<String, args::DiskArg>> {
        self.params.as_ref()
    }
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
    /// Removed feature, emits warning if set.
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

/// Configuration for the stack applied to this repository.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct Stack {
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

impl Eq for Stack {}

/// Per-project session block. Contributes to sessions activated on
/// this project — same primitives as
/// [`sessions::core::loadout::Loadout`] (packages, vars, patches,
/// lifecycle hooks), scoped to the project rather than the user.
///
/// Where a loadout says "what this developer wants everywhere"
/// (their editor, their shell rc, their preferred `EDITOR`), a
/// project session block says "what every session working on this
/// codebase needs" (the toolchain everyone builds with, shared
/// project config, env vars derived from the checkout). Patch
/// sources typically resolve inside the repo, not the user's
/// dotfiles.
///
/// Unlike a loadout, a session block has no name or description:
/// there's at most one per mfile and it's identified by the project
/// path. Contribution semantics (source tagging as
/// [`sessions::core::source::Source::Project`], policy gating) land
/// with the `ProjectComposable` that will consume this in a later
/// step.
///
/// # Example
///
/// ```toml
/// [session]
/// # Toolchain every contributor builds with.
/// packages = ["rustc", "cargo", "postgresql-client"]
///
/// # Config that lives in the repo, patched into the sandbox.
/// patches = [
///     { dest = "~/.cargo/config.toml", source = "config/cargo.toml" },
///     { dest = "~/.psqlrc",            source = "config/psqlrc" },
/// ]
///
/// [session.vars]
/// # Applies uniformly to every developer's session.
/// RUST_LOG          = "info"
/// CARGO_TERM_COLOR  = "always"
/// # Inherit if set, fall back to the local-dev default otherwise.
/// DATABASE_URL      = { inherit = true, default = "postgres://localhost/dev" }
///
/// # Warm the incremental compile cache the first time a session
/// # comes up. Best-effort; failures don't tank activation.
/// [[session.lifecycle_hooks]]
/// on_activate = { type = "inline", value = "cargo check --workspace >/dev/null 2>&1 || true" }
/// ```
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct Session {
    /// Packages to bring into the session, alongside the client's
    /// loadout packages.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packages: Vec<String>,
    /// Variables with POSIX-shaped names — the common case.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub vars:
        BTreeMap<sessions::core::primitives::StrictVarName, sessions::core::primitives::VarValue>,
    /// Variables with Linux-permissive names — explicit opt-in for
    /// the rare case a non-POSIX name is necessary.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vars_lenient: Vec<sessions::core::primitives::LenientVarEntry>,
    /// Patches contributed by this project.
    #[serde(
        default,
        skip_serializing_if = "sessions::core::primitives::Patches::is_empty"
    )]
    pub patches: sessions::core::primitives::Patches,
    /// Scripts run at session-level transition points, in
    /// declaration order (concatenated with any hooks from the
    /// client's loadout).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lifecycle_hooks: Vec<sessions::core::lifecyclehook::LifecycleHook>,

    /// Any fields which are not understood by this version of minimal.
    #[serde(flatten)]
    pub extra: HashMap<String, toml::Value>,
}

// No `impl Eq for Session`: the `extra: HashMap<String, toml::Value>`
// field means we can't honestly promise reflexivity, because
// `toml::Value::Float(NaN)` participates in `PartialEq` but breaks
// `x == x`. `Session` stays `PartialEq` only; no downstream API
// requires `Eq`.

impl Session {
    /// Returns true iff no primitive-carrying field on the session
    /// is populated. Used by downstream callers (e.g. daemon-side
    /// composable construction) to decide whether a synthesized
    /// [`Session`] has anything worth materializing.
    ///
    /// `extra` is ignored — unknown fields don't count as
    /// contributions.
    ///
    /// The exhaustive `let Self { ... } = self` destructure in the
    /// body is what makes this drift-proof: if a sixth primitive
    /// lands on [`Session`], the pattern fails to compile until it's
    /// added here. Naming the method is orthogonal — kept as
    /// `is_empty` because that's the idiomatic Rust name for the
    /// contract.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        let Self {
            packages,
            vars,
            vars_lenient,
            patches,
            lifecycle_hooks,
            extra: _,
        } = self;
        packages.is_empty()
            && vars.is_empty()
            && vars_lenient.is_empty()
            && patches.is_empty()
            && lifecycle_hooks.is_empty()
    }
}

/// Describes the specific type of output being generated, along with any
/// fields which are only meaningful for that output type.
///
/// Serialized with an internal `type` tag (e.g. `type = "oci-image"`), so
/// fields like `entrypoint`/`cmd`/`vars` can only be set on the `OciImage`
/// variant — setting them with any other `type` is a deserialization error.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum OutputKind {
    /// An output representing a container image.
    OciImage {
        #[serde(default)]
        entrypoint: Option<StrOrList>,
        #[serde(default)]
        cmd: Option<StrOrList>,
        #[serde(default, alias = "env_vars")]
        vars: HashMap<String, String>,
    },

    /// An output representing a file extracted from some packages.
    RawFile { path: String },
}

impl Default for OutputKind {
    fn default() -> Self {
        OutputKind::OciImage {
            entrypoint: None,
            cmd: None,
            vars: HashMap::new(),
        }
    }
}

/// Flat intermediate used to deserialize [Output]. Combining
/// `#[serde(flatten)]` on a tagged enum with a `#[serde(flatten)]` catch-all
/// `extra` map causes serde to duplicate variant fields into both
/// destinations, so we deserialize into a flat struct and then validate &
/// route fields into the proper [OutputKind] variant in [TryFrom].
#[derive(serde::Deserialize)]
struct OutputRaw {
    #[serde(rename = "type")]
    ty: Option<String>,

    #[serde(default)]
    packages: Vec<String>,
    #[serde(default)]
    arch: Option<String>,

    #[serde(default)]
    entrypoint: Option<StrOrList>,
    #[serde(default)]
    cmd: Option<StrOrList>,
    #[serde(default, alias = "env_vars")]
    vars: HashMap<String, String>,

    #[serde(default)]
    path: String,

    #[serde(flatten)]
    extra: HashMap<String, toml::Value>,
}

/// An output, defined in a `[outputs.<output_name>]` section of [File].
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(try_from = "OutputRaw")]
pub struct Output {
    #[serde(flatten)]
    pub kind: OutputKind,

    #[serde(default)]
    pub packages: Vec<String>,

    /// Target architecture for OCI images. Defaults to "amd64".
    /// Common values: "amd64", "arm64"
    #[serde(default)]
    pub arch: Option<String>,

    /// Any fields which are not understood by this version of minimal.
    #[serde(flatten)]
    extra: HashMap<String, toml::Value>,
}

impl Output {
    /// The target to build this output for. Arch precedence: `arch_override` >
    /// the `arch` field > the host. The OS is always Linux.
    pub fn target(
        &self,
        arch_override: Option<&str>,
    ) -> Result<common::Target, common::target::ArchParseError> {
        let arch = match arch_override.or(self.arch.as_deref()) {
            Some(s) => s.parse()?,
            None => common::Target::host().arch().clone(),
        };
        Ok(common::Target::new(arch, common::target::OS::Linux))
    }

    /// The graph top levels for this output; `base` when it names no packages.
    pub fn top_levels(&self) -> Vec<String> {
        if self.packages.is_empty() {
            vec!["base".to_string()]
        } else {
            self.packages.clone()
        }
    }
}

impl TryFrom<OutputRaw> for Output {
    type Error = String;

    fn try_from(raw: OutputRaw) -> Result<Self, Self::Error> {
        let ty = raw.ty.as_deref().unwrap_or("oci-image");
        let kind = match ty {
            "oci-image" => {
                for (field, set) in [("path", !raw.path.is_empty())] {
                    if set {
                        return Err(format!(
                            "field `{field}` is not valid for outputs with type = \"oci-image\""
                        ));
                    }
                }

                OutputKind::OciImage {
                    entrypoint: raw.entrypoint,
                    cmd: raw.cmd,
                    vars: raw.vars,
                }
            }
            "raw-file" => {
                for (field, set) in [
                    ("entrypoint", raw.entrypoint.is_some()),
                    ("cmd", raw.cmd.is_some()),
                    ("vars", !raw.vars.is_empty()),
                ] {
                    if set {
                        return Err(format!(
                            "field `{field}` is not valid for outputs with type = \"raw-file\""
                        ));
                    }
                }
                let path = if raw.path.is_empty() {
                    Err("field `path` is required for outputs with type = \"raw-file\"".to_string())
                } else {
                    Ok(raw.path)
                }?;
                OutputKind::RawFile { path }
            }
            other => {
                return Err(format!(
                    "unknown output type {other:?}, expected \"oci-image\" or \"raw-file\""
                ));
            }
        };
        Ok(Output {
            kind,
            packages: raw.packages,
            arch: raw.arch,
            extra: raw.extra,
        })
    }
}

/// Configuration for the standard library.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Stdlib {
    #[serde(alias = "min_version")]
    pub minimum_version: Option<String>,
}

/// The `[cache]` section: how this project reads the shared remote cache.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct CacheSettings {
    /// Which index object the cache reader loads. Defaults to
    /// [`IndexSourceMode::Auto`].
    pub index_source: Option<IndexSourceMode>,
    /// How many times a transient artifact-fetch failure is retried
    /// (exponential backoff). Defaults to the reader's built-in value.
    pub fetch_retries: Option<u32>,
}

/// Selects which remote-cache index object the reader loads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IndexSourceMode {
    /// The upstream pin's per-commit index snapshot when it exists, falling
    /// back to the global root index when it doesn't.
    Auto,
    /// The per-commit snapshot only; a missing snapshot is an error.
    Pinned,
    /// The global root index only.
    Root,
    /// The union of the per-commit *closure* snapshots of the pinned chain.
    /// Asymmetric by design: the upstream's closure is required (it is the
    /// signed catalog — missing is an error), while each sideload's closure
    /// is unioned best-effort — a sideload not covered by build
    /// infrastructure publishes no closure, is skipped with a log line, and
    /// its specs resolve locally. Distinct from [`Self::Pinned`] in both the
    /// object read (`<commit>.closure.shisha`, the bounded signed catalog,
    /// vs `<commit>.shisha`, a byte copy of the whole root index) and in
    /// covering sideload closures at their own pins.
    Closure,
}

impl std::str::FromStr for IndexSourceMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "auto" => Ok(Self::Auto),
            "pinned" => Ok(Self::Pinned),
            "root" => Ok(Self::Root),
            "closure" => Ok(Self::Closure),
            other => Err(format!(
                "unknown index source {other:?} (expected \"auto\", \"pinned\", \"root\" or \"closure\")"
            )),
        }
    }
}

/// How the remote-cache reader should locate its index. Resolved centrally
/// from the project file and its upstream pin ([`File::cache_config`]) so the
/// fetch layer follows instructions without policy of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheConfig {
    /// Read the global mutable root index.
    GlobalIndex,
    /// Read the immutable per-commit snapshot `object`; if it doesn't exist,
    /// fall back to the global root index.
    CommitIndex { object: String },
    /// Read the immutable per-commit snapshot `object`; if it doesn't exist,
    /// fail rather than fall back.
    CommitIndexOnly { object: String },
    /// Read and union the immutable per-commit closure snapshots. The
    /// upstream's closure is required (it is the signed catalog); sideload
    /// closures are best-effort — a sideload repo not covered by build
    /// infrastructure publishes no index, and its specs resolve locally.
    CommitClosures {
        upstream: String,
        sideloads: Vec<String>,
    },
}

/// Object key of the per-commit index snapshot for a repo + commit:
/// `<host>/<owner>/<repo>/<commit>.shisha`, matching the publisher's keying.
pub fn commit_index_object(repo_url: &str, commit_sha: &str) -> String {
    format!("{}/{commit_sha}.shisha", repo_slug(repo_url))
}

/// Object key of the per-commit *closure* snapshot (the bounded catalog at a
/// commit): `<host>/<owner>/<repo>/<commit>.closure.shisha`.
pub fn commit_closure_object(repo_url: &str, commit_sha: &str) -> String {
    format!("{}/{commit_sha}.closure.shisha", repo_slug(repo_url))
}

/// Stable `host/owner/repo` slug for a repo URL: query/fragment, scheme,
/// credentials, trailing `/` and any `.git` suffix stripped; scp-like syntax
/// (`git@host:owner/repo`) normalized to `host/owner/repo`.
fn repo_slug(repo_url: &str) -> String {
    let url = match repo_url.find(['?', '#']) {
        Some(idx) => &repo_url[..idx],
        None => repo_url,
    };
    let rest = match url.split_once("://") {
        Some((_, rest)) => {
            // Credentials end at the first `@` in the authority. Path
            // components may legitimately contain `@` and are preserved.
            let authority_end = rest.find('/').unwrap_or(rest.len());
            match rest[..authority_end].find('@') {
                Some(at) => &rest[at + 1..],
                None => rest,
            }
        }
        None => match (url.find('@'), url.find(':')) {
            // scp-like `user@host:path` -> `host/path`
            (Some(at), Some(colon)) if at < colon => {
                return repo_slug(&format!("{}/{}", &url[at + 1..colon], &url[colon + 1..]));
            }
            _ => url,
        },
    };
    let trimmed = rest.trim_end_matches('/');
    trimmed.strip_suffix(".git").unwrap_or(trimmed).to_string()
}

/// Which directory layout this layer/repo used for minimal configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Layout {
    /// The 'abridged' layout. The minimal file is located at `./{MFILE_NAME}`.
    ///
    /// If present, the packages directory is at ./packages.
    /// If present, the stacks directory is at ./stacks.
    Root,
    /// The 'full' layout. The minimal file is located at `./.minimal/{MFILE_NAME}`.
    ///
    /// If present, the packages directory is at ./.minimal/packages.
    /// If present, the stacks directory is at ./.minimal/stacks.
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

    /// Default state_key etc.
    #[serde(default, alias = "default")]
    pub defaults: Defaults,
    /// The stack configured on this repository, if any.
    ///
    /// TODO: Remove `harness` alias after July 2026.
    #[serde(default, alias = "harness")]
    pub stack: Option<Stack>,

    /// Task definitions, invoked with `minimal run <task name>`.
    #[serde(default)]
    pub tasks: HashMap<String, Task>,
    /// Output definitions.
    #[serde(default)]
    pub outputs: HashMap<String, Output>,
    /// Configuration relevant to the standard library.
    #[serde(default)]
    pub stdlib: Stdlib,
    /// How this project reads the shared remote cache.
    #[serde(default)]
    pub cache: CacheSettings,
    /// Project-level session contribution: packages, vars, patches,
    /// and lifecycle hooks that apply to every session activated on
    /// this project. Consumed by the `ProjectComposable` at
    /// `CreateSession` time.
    pub session: Option<Session>,

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
    /// Parses a `minimal.toml` from raw bytes — the pure, filesystem-free core
    /// of [`File::from_dir`], exposed for fuzzing (crates/mfile/fuzz) and tests.
    pub fn from_toml_bytes(bytes: &[u8]) -> Result<Self, Error> {
        toml::from_slice(bytes).map_err(Error::Format)
    }

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
        self.validate()?;
        Ok(self)
    }

    /// Post-deserialize invariants: every declared param has a `default`,
    /// unknown top-level fields are logged. Runs inside [`Self::init_toml`]
    /// for the disk-load path, and is exposed publicly for the wire-load
    /// path — an mfile arriving over the wire has already been through
    /// serde but skipped this pass, and a peer that trusts the mfile
    /// without running these checks would let a `[params.X]` without a
    /// default fall through to graph construction, where the missing
    /// default surfaces as a much later, much less actionable error.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingParamDefault`] if any `[params.X]` entry has
    /// no `default` field.
    pub fn validate(&self) -> Result<(), Error> {
        if let Some(params) = &self.params {
            for (n, s) in params.0.iter() {
                if s.default.is_none() {
                    return Err(Error::MissingParamDefault(n.clone()));
                }
            }
        }
        self.warn_unknown_fields();
        Ok(())
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
        if let Some(p) = &self.defaults.profile {
            tracing::warn!("[defaults]profile = \"{p}\" defined, profiles were removed in 0.5.1");
        }
        if let Some(stack) = &self.stack
            && !stack.extra.is_empty()
        {
            tracing::warn!(
                "unknown fields in [stack] section of {}: {}",
                MFILE_NAME,
                stack.extra.keys().cloned().collect::<Vec<_>>().join(",")
            );
            was_unknown_fields = true;
        }
        if let Some(session) = &self.session
            && !session.extra.is_empty()
        {
            tracing::warn!(
                "unknown fields in [session] section of {}: {}",
                MFILE_NAME,
                session.extra.keys().cloned().collect::<Vec<_>>().join(",")
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
            if let Some(p) = &task.profile {
                tracing::warn!(
                    "[tasks.{task_name}]profile = \"{p}\" defined, profiles were removed in 0.5.1"
                );
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

    /// Iterates the tasks defined in the minimal file.
    pub fn iter_tasks(&self) -> impl Iterator<Item = (&String, &Task)> {
        self.tasks.iter()
    }

    /// Applies additional settings to hydrate a task, namely:
    ///  - default profile if set (and not set on the task)
    ///  - default state_key if set (and not set on the task)
    ///  - additional build_packages & runtime_packages set on the stack
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
        if let Some(stack) = &self.stack {
            task.packages.extend(
                stack
                    .build_packages
                    .iter()
                    .chain(stack.runtime_packages.iter())
                    .filter(|p| !task.packages.contains(p))
                    .cloned()
                    .collect::<Vec<_>>(),
            );
        }
    }

    /// Encodes a path component for use in a flat directory name.
    ///
    /// Escapes `-` as `--` so that `-` can be used as a component separator.
    /// Non-UTF8 bytes are preserved as-is.
    fn encode_component(s: &OsStr) -> OsString {
        let mut out = Vec::with_capacity(s.len());
        for &b in s.as_bytes() {
            if b == b'-' {
                out.push(b'-');
            }
            out.push(b);
        }
        OsString::from_vec(out)
    }

    /// Helper method for state_dir to simplify unit testing
    fn state_dir_from_path<P: AsRef<Path>>(
        state_key: &str,
        env_base_dir: P,
        home_dir: Option<&Path>,
        mfile_dir: &Path,
    ) -> PathBuf {
        let (start_marker, components) = home_dir
            .map(|home| mfile_dir.strip_prefix(home))
            .and_then(|r| r.ok())
            .map(|p| ('~', p.components()))
            .unwrap_or_else(|| ('-', mfile_dir.components()));

        let mut tail = OsString::new();
        for (i, c) in components
            .filter_map(|c| match c {
                Component::Normal(s) => Some(Self::encode_component(s)),
                _ => None,
            })
            .enumerate()
        {
            if i > 0 {
                tail.push("-");
            }
            tail.push(&c);
        }

        let mut dir_name = OsString::from(start_marker.to_string());
        dir_name.push(&tail);
        env_base_dir.as_ref().join(dir_name).join(state_key)
    }

    /// Returns the path to a durable state directory for this project.
    ///
    /// The directory is derived from the path to the project's `minimal.toml`,
    /// encoded into a single flat directory name under `env_base_dir`:
    ///
    /// - Path components are joined with `-`, with literal `-` escaped as `--`.
    /// - Paths under the user's home directory are prefixed with `~`.
    /// - All other paths are prefixed with `-`.
    ///
    /// For example, `~/src/my-project` with state key `"env"` becomes:
    ///   `<env_base_dir>/~src-my--project/env`
    ///
    /// Returns `None` if the location of the minimal file on disk is not known.
    /// Returns the path to the durable state directory for the given key.
    ///
    /// None is returned if the location of the minimal file on disk is not known.
    pub fn state_dir<P: AsRef<Path>>(&self, state_key: &str, env_base_dir: P) -> Option<PathBuf> {
        self.dir_path().map(|mfile_dir| {
            Self::state_dir_from_path(
                state_key,
                env_base_dir,
                env::home_dir().as_deref(),
                mfile_dir,
            )
        })
    }

    /// Resolves how the remote-cache reader should locate its index:
    /// `[cache] index_source` (or `override_mode`, which wins when set —
    /// typically an environment variable) applied to the upstream pin.
    ///
    /// `auto`, the default, selects the upstream pin's per-commit snapshot
    /// with root fallback, degrading to the root index when there is no git
    /// upstream or no locked commit.
    pub fn cache_config(
        &self,
        override_mode: Option<IndexSourceMode>,
    ) -> Result<CacheConfig, String> {
        let mode = override_mode
            .or(self.cache.index_source)
            .unwrap_or(IndexSourceMode::Auto);

        let snapshot = self.upstream.as_ref().and_then(|u| match &u.link {
            LinkConfig::Git {
                repo,
                locked_commit: Some(commit),
                ..
            } => Some(commit_index_object(repo, commit)),
            _ => None,
        });

        match (mode, snapshot) {
            (IndexSourceMode::Root, _) => Ok(CacheConfig::GlobalIndex),
            (IndexSourceMode::Auto, Some(object)) => Ok(CacheConfig::CommitIndex { object }),
            (IndexSourceMode::Auto, None) => Ok(CacheConfig::GlobalIndex),
            (IndexSourceMode::Pinned, Some(object)) => Ok(CacheConfig::CommitIndexOnly { object }),
            (IndexSourceMode::Pinned, None) => Err(
                "index_source \"pinned\" requires a git upstream with a locked_commit".to_string(),
            ),
            (IndexSourceMode::Closure, _) => {
                let Some(u) = self.upstream.as_ref() else {
                    return Err(
                        "index_source \"closure\" requires a git upstream with a locked_commit"
                            .to_string(),
                    );
                };
                let LinkConfig::Git {
                    repo,
                    locked_commit: Some(commit),
                    ..
                } = &u.link
                else {
                    return Err(
                        "index_source \"closure\" requires a git upstream with a locked_commit"
                            .to_string(),
                    );
                };
                // Sideloads in declaration order; links without a locked
                // commit (or backed by a directory) have no remote presence
                // and contribute nothing.
                let sideloads = u
                    .sideloads()
                    .iter()
                    .filter_map(|s| match s.link() {
                        LinkConfig::Git {
                            repo,
                            locked_commit: Some(commit),
                            ..
                        } => Some(commit_closure_object(repo, commit)),
                        _ => None,
                    })
                    .collect();
                Ok(CacheConfig::CommitClosures {
                    upstream: commit_closure_object(repo, commit),
                    sideloads,
                })
            }
        }
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
                stack: None,
                tasks: [(
                    "test".to_string(),
                    Task {
                        state_key: Some("test".to_string()),
                        profile: None,
                        description: None,
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
                        kind: OutputKind::OciImage {
                            entrypoint: Some(StrOrList::Single("/bin/sh".to_string())),
                            cmd: None,
                            vars: HashMap::new(),
                        },
                        packages: vec!["bash".to_string(), "go".to_string()],
                        arch: None,
                        extra: HashMap::new(),
                    }
                )]
                .into(),
                stdlib: Default::default(),
                cache: Default::default(),
                session: None,
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
    fn output_target_arch_precedence() {
        let pinned = Output {
            arch: Some("arm64".to_string()),
            ..Default::default()
        };
        assert_eq!(
            pinned.target(Some("amd64")).unwrap().arch(),
            &common::target::Arch::Amd64,
            "the override must beat the output's own arch"
        );
        assert_eq!(
            pinned.target(None).unwrap().arch(),
            &common::target::Arch::Arm64,
            "without an override the output's arch is used"
        );
        assert_eq!(
            Output::default().target(None).unwrap().arch(),
            common::Target::host().arch(),
            "with neither set, the host's arch is used"
        );
    }

    #[test]
    fn output_target_os_is_always_linux() {
        assert_eq!(
            Output::default().target(None).unwrap().os(),
            &common::target::OS::Linux
        );
    }

    #[test]
    fn output_target_rejects_an_unknown_arch() {
        let err = Output::default()
            .target(Some("s390x"))
            .expect_err("s390x is not a supported architecture");
        assert!(
            err.to_string().contains("s390x"),
            "the error should name the offending input, got {err}"
        );
    }

    #[test]
    fn output_top_levels_default_to_base() {
        assert_eq!(Output::default().top_levels(), vec!["base".to_string()]);

        let explicit = Output {
            packages: vec!["openssl".to_string()],
            ..Default::default()
        };
        assert_eq!(explicit.top_levels(), vec!["openssl".to_string()]);
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
        let OutputKind::OciImage {
            entrypoint, vars, ..
        } = &output.kind
        else {
            panic!("expected OciImage, got {:?}", output.kind);
        };
        assert_eq!(
            entrypoint,
            &Some(StrOrList::Single("/app/server".to_string()))
        );
        assert_eq!(vars["PORT"], "8080");
    }

    #[test]
    fn output_raw_file() {
        let mf: File = toml::from_str(indoc! {
            r#"
            [outputs.bash-bin]
            type = "raw-file"
            arch = "amd64"
            path = "/usr/bin/bash"
            "#
        })
        .unwrap();
        assert_eq!(mf.outputs["bash-bin"].arch, Some("amd64".to_string()));
        assert_eq!(
            mf.outputs["bash-bin"].kind,
            OutputKind::RawFile {
                path: "/usr/bin/bash".to_string()
            }
        );
    }

    #[test]
    fn raw_file_must_configure_path() {
        let toml_str = "[outputs.f]\ntype = \"raw-file\"\n".to_string();
        let err = toml::from_str::<File>(&toml_str).expect_err("expected error");
        assert!(
            err.to_string()
                .contains("field `path` is required for outputs with type = \"raw-file\""),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn raw_file_rejects_oci_image_fields() {
        for field in ["entrypoint = \"/x\"", "cmd = \"/x\"", "vars.X = \"y\""] {
            let toml_str = format!("[outputs.f]\ntype = \"raw-file\"\n{field}\n",);
            let err = toml::from_str::<File>(&toml_str)
                .expect_err(&format!("expected error for `{field}` on raw-file"));
            assert!(
                err.to_string()
                    .contains("not valid for outputs with type = \"raw-file\""),
                "unexpected error: {err}"
            );
        }
    }

    #[test]
    fn unknown_output_type_is_rejected() {
        let err = toml::from_str::<File>(indoc! {
            r#"
            [outputs.f]
            type = "weird"
            "#
        })
        .expect_err("expected error for unknown output type");
        assert!(
            err.to_string().contains("unknown output type"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn encode_component_no_dashes() {
        assert_eq!(File::encode_component(OsStr::new("foo")), "foo");
    }

    #[test]
    fn encode_component_with_dashes() {
        assert_eq!(
            File::encode_component(OsStr::new("my-project")),
            "my--project"
        );
    }

    #[test]
    fn encode_component_all_dashes() {
        assert_eq!(File::encode_component(OsStr::new("---")), "------");
    }

    #[test]
    fn encode_component_empty() {
        assert_eq!(File::encode_component(OsStr::new("")), "");
    }

    #[test]
    fn encode_component_non_utf8_preserved() {
        let input = OsStr::from_bytes(b"hello\x80world");
        assert_eq!(File::encode_component(input).as_bytes(), b"hello\x80world");
    }

    #[test]
    fn encode_component_non_utf8_with_dashes() {
        let input = OsStr::from_bytes(b"he-llo\x80wor-ld");
        assert_eq!(
            File::encode_component(input).as_bytes(),
            b"he--llo\x80wor--ld"
        );
    }

    #[test]
    fn state_dir_under_home() {
        let result = File::state_dir_from_path(
            "env",
            "/tmp/state",
            Some(Path::new("/home/user")),
            Path::new("/home/user/src/my-project"),
        );
        assert_eq!(result, Path::new("/tmp/state/~src-my--project/env"));
    }

    #[test]
    fn state_dir_outside_home() {
        let result = File::state_dir_from_path(
            "cache",
            "/tmp/state",
            Some(Path::new("/home/user")),
            Path::new("/opt/builds/foo"),
        );
        assert_eq!(result, Path::new("/tmp/state/-opt-builds-foo/cache"));
    }

    #[test]
    fn state_dir_no_home() {
        let result =
            File::state_dir_from_path("env", "/tmp/state", None, Path::new("/opt/builds/foo"));
        assert_eq!(result, Path::new("/tmp/state/-opt-builds-foo/env"));
    }

    #[test]
    fn state_dir_nested_dashes() {
        let result = File::state_dir_from_path(
            "env",
            "/tmp/state",
            Some(Path::new("/home/user")),
            Path::new("/home/user/my-org/my-project"),
        );
        assert_eq!(result, Path::new("/tmp/state/~my--org-my--project/env"));
    }

    #[test]
    fn state_dir_single_component() {
        let result = File::state_dir_from_path(
            "env",
            "/tmp/state",
            Some(Path::new("/home/user")),
            Path::new("/home/user/project"),
        );
        assert_eq!(result, Path::new("/tmp/state/~project/env"));
    }

    #[test]
    fn state_dir_home_is_mfile_dir() {
        let result = File::state_dir_from_path(
            "env",
            "/tmp/state",
            Some(Path::new("/home/user")),
            Path::new("/home/user"),
        );
        assert_eq!(result, Path::new("/tmp/state/~/env"));
    }

    /// A minimal.toml without a `[session]` block deserializes with
    /// `session: None`; the field is opt-in so existing mfiles keep
    /// working unchanged.
    #[test]
    fn session_absent_parses_as_none() {
        let mf: File = toml::from_str(indoc! {
            r#"
            [upstream]
            repo = "https://github.com/gominimal/pkgs"
            "#
        })
        .unwrap();
        assert!(mf.session.is_none());
    }

    /// An empty `[session]` block parses as `Some(Session::default())`
    /// — no primitives contributed, but the block is present. Guards
    /// against a regression where an empty header errors instead of
    /// producing the identity contribution.
    #[test]
    fn session_empty_block_parses_as_default() {
        let mf: File = toml::from_str(indoc! {
            r#"
            [session]
            "#
        })
        .unwrap();
        let session = mf.session.expect("empty block still produces Some");
        assert_eq!(session, Session::default());
    }

    /// `Session::is_empty` returns true for
    /// `Session::default()` and false once any primitive-carrying
    /// field is populated. Guards downstream callers (e.g.
    /// daemon-side composables) that use it to decide whether to
    /// materialize an empty composable.
    #[test]
    fn session_is_empty_returns_true_for_default_and_false_when_populated() {
        let empty = Session::default();
        assert!(empty.is_empty());

        let with_pkg = Session {
            packages: vec!["ripgrep".into()],
            ..Session::default()
        };
        assert!(!with_pkg.is_empty());
    }

    /// A populated `[session]` block round-trips every primitive
    /// domain a loadout carries — packages, strict vars, patches,
    /// lifecycle hooks — through the mfile's schema. The example
    /// content is deliberately project-flavored (build toolchain,
    /// in-repo config paths, uniform build env) to reflect the
    /// intended use, but the assertions only check shape. Vars-
    /// lenient coverage lives in the sessions crate's loadout tests
    /// since the wire form is identical.
    #[test]
    fn session_populated_block_parses_every_primitive() {
        let mf: File = toml::from_str(indoc! {
            r#"
            [session]
            packages = ["rustc", "cargo", "postgresql-client"]
            patches = [
                { dest = "~/.cargo/config.toml", source = "config/cargo.toml" },
                { dest = "~/.psqlrc",            source = "config/psqlrc" },
            ]

            [session.vars]
            RUST_LOG         = "info"
            CARGO_TERM_COLOR = "always"
            DATABASE_URL     = { inherit = true, default = "postgres://localhost/dev" }

            [[session.lifecycle_hooks]]
            on_activate = { type = "inline", value = "cargo check --workspace >/dev/null 2>&1 || true" }
            "#
        })
        .unwrap();
        let session = mf.session.expect("populated block parses");
        assert_eq!(
            session.packages,
            vec!["rustc", "cargo", "postgresql-client"]
        );
        assert_eq!(session.vars.len(), 3);
        assert_eq!(session.patches.len(), 2);
        assert_eq!(session.lifecycle_hooks.len(), 1);
    }

    /// Unknown fields inside `[session]` land in `extra` for the
    /// `warn_unknown_fields` pass to report at load-time, matching
    /// how `[stack]` and `[defaults]` handle forward-compat.
    #[test]
    fn session_unknown_field_lands_in_extra() {
        let mf: File = toml::from_str(indoc! {
            r#"
            [session]
            packages = ["rustc"]
            weird_new_thing = "future"
            "#
        })
        .unwrap();
        let session = mf.session.expect("populated block parses");
        assert!(session.extra.contains_key("weird_new_thing"));
    }

    #[test]
    fn repo_slug_normalizes_common_url_forms() {
        for url in [
            "https://github.com/gominimal/pkgs",
            "https://github.com/gominimal/pkgs.git",
            "https://github.com/gominimal/pkgs/",
            "https://oauth2:tok@github.com/gominimal/pkgs.git",
            "ssh://git@github.com/gominimal/pkgs.git",
            "git@github.com:gominimal/pkgs.git",
            "https://github.com/gominimal/pkgs?ref=x#frag",
        ] {
            assert_eq!(repo_slug(url), "github.com/gominimal/pkgs", "{url}");
        }
    }

    #[test]
    fn cache_config_resolves_modes_against_the_pin() {
        const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
        let pinned: File = toml::from_str(&format!(
            "[upstream]\nrepo = \"https://github.com/gominimal/pkgs\"\nlocked_commit = \"{SHA}\"\n"
        ))
        .unwrap();
        let object = format!("github.com/gominimal/pkgs/{SHA}.shisha");

        // Default is auto: snapshot with fallback.
        assert_eq!(
            pinned.cache_config(None).unwrap(),
            CacheConfig::CommitIndex {
                object: object.clone()
            }
        );
        // Override wins over the (unset) file setting.
        assert_eq!(
            pinned.cache_config(Some(IndexSourceMode::Root)).unwrap(),
            CacheConfig::GlobalIndex
        );
        assert_eq!(
            pinned.cache_config(Some(IndexSourceMode::Pinned)).unwrap(),
            CacheConfig::CommitIndexOnly { object }
        );

        // No locked commit: auto degrades to the root index, pinned errors.
        let unpinned: File =
            toml::from_str("[upstream]\nrepo = \"https://github.com/gominimal/pkgs\"\n").unwrap();
        assert_eq!(
            unpinned.cache_config(None).unwrap(),
            CacheConfig::GlobalIndex
        );
        assert!(
            unpinned
                .cache_config(Some(IndexSourceMode::Pinned))
                .is_err()
        );
    }

    #[test]
    fn cache_config_reads_the_file_setting_and_override_beats_it() {
        const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
        let mf: File = toml::from_str(&format!(
            r#"
            [upstream]
            repo = "https://github.com/gominimal/pkgs"
            locked_commit = "{SHA}"

            [cache]
            index_source = "root"
            fetch_retries = 5
            "#
        ))
        .unwrap();
        assert_eq!(mf.cache.fetch_retries, Some(5));
        assert_eq!(mf.cache.index_source, Some(IndexSourceMode::Root));
        assert_eq!(mf.cache_config(None).unwrap(), CacheConfig::GlobalIndex);
        assert_eq!(
            mf.cache_config(Some(IndexSourceMode::Pinned)).unwrap(),
            CacheConfig::CommitIndexOnly {
                object: format!("github.com/gominimal/pkgs/{SHA}.shisha")
            }
        );
    }

    #[test]
    fn cache_config_closure_unions_pinned_links_and_skips_the_rest() {
        const UP: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const SIDE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let mf: File = toml::from_str(&format!(
            r#"
            [upstream]
            repo = "https://github.com/gominimal/pkgs"
            locked_commit = "{UP}"

            [[upstream.sideload]]
            repo = "https://github.com/acme/extra"
            locked_commit = "{SIDE}"

            [[upstream.sideload]]
            dir = "/tmp/local-overlay"

            [[upstream.sideload]]
            repo = "https://github.com/acme/unpinned"
            "#
        ))
        .unwrap();
        // Required upstream, then pinned sideloads in declaration order; the
        // dir and unpinned links have no remote presence.
        assert_eq!(
            mf.cache_config(Some(IndexSourceMode::Closure)).unwrap(),
            CacheConfig::CommitClosures {
                upstream: format!("github.com/gominimal/pkgs/{UP}.closure.shisha"),
                sideloads: vec![format!("github.com/acme/extra/{SIDE}.closure.shisha")],
            }
        );

        // An unpinned upstream is a loud error — even with a pinned sideload:
        // the upstream closure is the required (signed) catalog.
        let unpinned: File = toml::from_str(&format!(
            r#"
            [upstream]
            repo = "https://github.com/gominimal/pkgs"

            [[upstream.sideload]]
            repo = "https://github.com/acme/extra"
            locked_commit = "{SIDE}"
            "#
        ))
        .unwrap();
        assert!(
            unpinned
                .cache_config(Some(IndexSourceMode::Closure))
                .is_err()
        );

        // The env-override spelling parses.
        assert_eq!(
            "closure".parse::<IndexSourceMode>().unwrap(),
            IndexSourceMode::Closure
        );
    }

    /// The demo project under `crates/sessions/example_project` must
    /// stay parseable as a real `File`, hooks and all.
    ///
    /// It is documentation people copy from, and nothing else reads it,
    /// so without this it can rot silently. Lifecycle hooks make that
    /// sharper: `LifecycleHookBuilder` and `HookScriptRepr` both deny
    /// unknown fields, so a misspelled key there is a hard parse error
    /// rather than a quietly-ignored line.
    #[test]
    fn example_project_parses_with_its_lifecycle_hooks() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../sessions/example_project/minimal.toml"
        );
        let src = std::fs::read_to_string(path).expect("example project is readable");
        let file: File = toml::from_str(&src).expect("example project must parse as an mfile");

        let session = file
            .session
            .expect("the example declares a [session] block");
        assert_eq!(session.lifecycle_hooks.len(), 1);
        let hook = &session.lifecycle_hooks[0];
        // All four transitions, so each can be exercised from the demo.
        assert!(hook.on_activate().is_some());
        assert!(hook.on_attach().is_some());
        assert!(hook.on_detach().is_some());
        assert!(hook.on_destroy().is_some());
        assert!(hook.description().is_some());
    }
}
