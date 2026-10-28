//! Finding & reading the `minimal.toml` file.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::hash::{Hash, Hasher};
use std::io::Write as _;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Component, Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

mod error;
pub use error::Error;
mod package_composable;
pub use package_composable::{PackageComposable, PackageFsMapping, StateWiring};
mod project_composable;
pub use project_composable::ProjectComposable;
pub mod spec;
mod tasks;
use serde::{Deserializer, Serializer};
pub use tasks::{Task, TaskAction};

pub const MFILE_NAME: &str = "minimal.toml";

/// Overrides how many seconds an edit of `minimal.toml` waits for another
/// command's lock before it fails.
const MFILE_LOCK_TIMEOUT_ENV: &str = "MINIMAL_MFILE_LOCK_TIMEOUT_SECS";

/// How long [`File::edit_exclusively`] waits for the lock: 60 s, or the
/// whole seconds in [`MFILE_LOCK_TIMEOUT_ENV`]. An edit holds the lock only
/// for a read and a write, so a longer wait means a stuck holder.
fn mfile_lock_timeout() -> Duration {
    lock_timeout_from(env::var(MFILE_LOCK_TIMEOUT_ENV).ok().as_deref())
}

/// Parses a [`MFILE_LOCK_TIMEOUT_ENV`] value. A value that is not a whole
/// number of seconds above zero ("1.5", "60s", "0") warns and waits the
/// default 60 s, since 0 would fail every contended edit at once.
fn lock_timeout_from(value: Option<&str>) -> Duration {
    const DEFAULT: Duration = Duration::from_secs(60);
    let Some(value) = value else {
        return DEFAULT;
    };
    match value.trim().parse::<u64>() {
        Ok(secs) if secs > 0 => Duration::from_secs(secs),
        _ => {
            tracing::warn!(
                "{MFILE_LOCK_TIMEOUT_ENV}={value:?} is not a whole number of seconds above 0; \
                 waiting {}s for the minimal.toml lock",
                DEFAULT.as_secs()
            );
            DEFAULT
        }
    }
}

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
    pub dir: BTreeMap<String, PatchSetting>,
    /// The list of files to be patched into the environment. Keys are expected to be path strings,
    /// either absolute paths are starting with the prefix `~/` to be rooted in the users home directory.
    #[serde(default, alias = "files")]
    pub file: BTreeMap<String, PatchSetting>,
}

/// Why a `~/`-rooted patch path had no home directory to expand against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HomeUnusable {
    /// No home directory is known at all — `HOME` is unset.
    Unset,
    /// A home is known but is no place to put a patched-in file: a relative
    /// path, one that isn't valid UTF-8, or `/`, which is what a daemon
    /// running as pid 1 inside the guest reports.
    NotAHome(PathBuf),
}

/// A patch path rooted at `~/` whose home could not be resolved.
///
/// Carries the declaration verbatim — still `~/`-rooted — so the caller can
/// name the offending entry, and the package that contributed it, back to
/// the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchHomeError {
    /// The path exactly as it was declared.
    pub declared: String,
    /// What was wrong with the home it would have expanded against.
    pub home: HomeUnusable,
}

impl std::fmt::Display for PatchHomeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cannot map `{}` into the environment: ", self.declared)?;
        match &self.home {
            HomeUnusable::Unset => write!(
                f,
                "`HOME` is unset, so there is no home directory to expand `~/` against"
            ),
            HomeUnusable::NotAHome(home) => write!(
                f,
                "the home directory is `{}`, which is not somewhere a file can be patched in \
                 (a daemon running as pid 1 sees `HOME=/`)",
                home.display()
            ),
        }
    }
}

impl std::error::Error for PatchHomeError {}

impl EnvPatches {
    /// Combines the given [EnvPatches] into `self`. If keys conflict, `other` takes precedence.
    pub fn union(&mut self, other: &Self) {
        self.dir
            .extend(other.dir.iter().map(|(k, v)| (k.clone(), v.clone())));
        self.file
            .extend(other.file.iter().map(|(k, v)| (k.clone(), v.clone())));
    }

    /// Lowers these patches into sandbox filesystem mappings, expanding
    /// `~/`-rooted paths against `home`.
    ///
    /// `home` is the home directory of the environment being built, which is
    /// not necessarily the running process's: `minimald` is pid 1 inside the
    /// guest with `HOME=/`, and expanding against that put package-declared
    /// files such as `~/.claude.json` at the root of a read-only rootfs,
    /// where creating them fails with `EROFS` (#1204). A `~/` path with no
    /// usable home is an error here rather than a write into `/`.
    ///
    /// Mappings come back in a deterministic order — directories then files,
    /// each sorted by declared path — so the sandbox applies them the same
    /// way every run and a caller reporting the first failure names the same
    /// entry every run.
    pub fn to_fs_mappings(
        &self,
        home: Option<&Path>,
    ) -> Result<Vec<common::FsMapping>, PatchHomeError> {
        let mut mappings = Vec::with_capacity(self.dir.len() + self.file.len());
        for (is_file, entries) in [(false, &self.dir), (true, &self.file)] {
            for (path, settings) in entries {
                mappings.push(common::FsMapping {
                    host_path: Self::expand_home(path, home)?,
                    sandbox_path: None, // use host
                    create_if_missing: matches!(settings, PatchSetting::ReadWrite),
                    is_file,
                    read_only: matches!(settings, PatchSetting::ReadOnly),
                });
            }
        }
        Ok(mappings)
    }

    /// Resolves one declared patch path against `home`: `~/`-rooted paths are
    /// expanded, anything else is returned as-is.
    ///
    /// Exposed alongside [`to_fs_mappings`](Self::to_fs_mappings) so a caller
    /// holding the declarations can map an expanded path back to the entry it
    /// came from — the sandbox only ever sees the expanded form, and an error
    /// about `/home/dev/.claude.json` is only actionable once it can be tied
    /// to the `~/.claude.json` some package declared.
    pub fn expand_home(path: &str, home: Option<&Path>) -> Result<String, PatchHomeError> {
        let Some(stripped) = path.strip_prefix("~/") else {
            return Ok(path.to_string());
        };
        let home = match home {
            None => HomeUnusable::Unset,
            Some(h) => match Self::usable_home(h) {
                // UTF-8 by construction — `usable_home` only returns a path
                // it has already round-tripped through `to_str`.
                Some(h) => return Ok(format!("{}/{stripped}", h.to_str().unwrap())),
                None => HomeUnusable::NotAHome(h.to_path_buf()),
            },
        };
        Err(PatchHomeError {
            declared: path.to_string(),
            home,
        })
    }

    /// Normalizes `home` and hands it back only if it is somewhere a
    /// patched-in file could actually live: absolute, valid UTF-8, and naming
    /// at least one directory below `/`.
    ///
    /// The test is on normalized [`Component`]s rather than the literal
    /// string. `/`, `//` and `/.` all denote the filesystem root, so a
    /// string-exact `home != "/"` check passes the latter two straight
    /// through and reconstitutes the very `/.claude.json` this guard exists
    /// to prevent (#1204). Normalizing also collapses duplicate separators
    /// and trailing `/` and `/.` segments, so `/home/dev/`, `/home//dev` and
    /// `/home/dev/.` all expand identically.
    fn usable_home(home: &Path) -> Option<PathBuf> {
        if !home.is_absolute() {
            return None;
        }
        let normalized: PathBuf = home.components().collect();
        let names_a_directory = normalized
            .components()
            .any(|c| matches!(c, Component::Normal(_)));
        (names_a_directory && normalized.to_str().is_some()).then_some(normalized)
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
/// [`boxes::core::loadout::Loadout`] (packages, vars, patches,
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
/// [`boxes::core::source::Source::Project`], policy gating) land
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
    pub vars: BTreeMap<boxes::core::primitives::StrictVarName, boxes::core::primitives::VarValue>,
    /// Variables with Linux-permissive names — explicit opt-in for
    /// the rare case a non-POSIX name is necessary.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vars_lenient: Vec<boxes::core::primitives::LenientVarEntry>,
    /// Patches contributed by this project.
    #[serde(
        default,
        skip_serializing_if = "boxes::core::primitives::Patches::is_empty"
    )]
    pub patches: boxes::core::primitives::Patches,
    /// Scripts run at session-level transition points, in
    /// declaration order (concatenated with any hooks from the
    /// client's loadout).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lifecycle_hooks: Vec<boxes::core::lifecyclehook::LifecycleHook>,
    /// `[session.network]`: the box's network settings this file owns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<SessionNetwork>,
    /// `[session.secrets.<VAR>]`: the credential grants, by the environment
    /// variable each one lands in. A project cannot set
    /// `acknowledge_full_breadth_unenrolled` here: the reader ignores it with
    /// a warning, because only the client configuration accepts full
    /// breadth (BEP-057).
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "boxes::core::bep::deserialize_project_secrets"
    )]
    pub secrets: boxes::core::bep::SecretGrants,

    /// Any fields which are not understood by this version of minimal.
    #[serde(flatten)]
    pub extra: HashMap<String, toml::Value>,
}

/// The `[session.network]` table: the UDP 443 stance and the Box Egress
/// Proxy settings.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionNetwork {
    /// `[session.network] quic443`: the box's stance on UDP to port 443.
    /// `None` reads as `auto`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic443: Option<boxes::core::bep::Quic443>,
    /// `[session.network.bep]`: steering, `proxy_env`, `no_proxy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bep: Option<boxes::core::bep::BepSettings>,
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
            // Proxy settings and grants are box policy, not composition
            // primitives: the client carries them on the box's policy.
            network: _,
            secrets: _,
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
        vars: BTreeMap<String, String>,
    },

    /// An output representing a file extracted from some packages.
    RawFile { path: String },
}

impl Default for OutputKind {
    fn default() -> Self {
        OutputKind::OciImage {
            entrypoint: None,
            cmd: None,
            vars: BTreeMap::new(),
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
    vars: BTreeMap<String, String>,

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
                if !raw.path.is_empty() {
                    return Err(
                        "field `path` is not valid for outputs with type = \"oci-image\""
                            .to_string(),
                    );
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
    /// Per pinned chain link (upstream + each pinned sideload), the first
    /// available of: the sealed per-commit *closure* (the curated, bounded
    /// catalog), then the per-commit byte-copy snapshot, then — for the
    /// upstream only — the global root index. Falls back to the root index
    /// outright when there is no git upstream or no locked commit.
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
    /// The `auto` chain: per pinned link, try the sealed closure first,
    /// then the byte-copy snapshot; the upstream additionally falls back
    /// to the root index (each hop logged — the byte-copy is the
    /// UNCURATED copy of the root at publish time, so reading it should
    /// leave a trace; see the 2026-08-17 dangling-index incident).
    /// Sideload links that resolve nothing are skipped best-effort.
    AutoChain {
        upstream: ChainLink,
        sideloads: Vec<ChainLink>,
    },
}

/// One pinned chain link's candidate index objects, most-curated first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainLink {
    /// `<repo>/<commit>.closure.shisha` — the sealed, bounded catalog.
    pub closure: String,
    /// `<repo>/<commit>.shisha` — the byte-copy of the root at publish.
    pub snapshot: String,
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
    /// `[harness]`, the pre-v0.5.0 name of this table, no longer parses: it
    /// errors at load, so an old config has to rename the table.
    #[serde(default)]
    pub stack: Option<Stack>,

    /// Task definitions, invoked with `minimal run <task name>`.
    // CodeRabbit flagged this `HashMap` -> `BTreeMap` swap as a breaking API
    // change requiring a compatibility/versioning step. That step would apply
    // only if external consumers construct or depend on the concrete field
    // type. They don't: the workspace sets `package.publish = false` (root
    // `Cargo.toml`), so `mfile` is never published to crates.io — every
    // consumer is an in-workspace path dependency, and all of them compile
    // green on this branch. Declined; nothing to version.
    #[serde(default)]
    pub tasks: BTreeMap<String, Task>,
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
    /// Hash of the bytes that produced this `File`, when loaded from disk.
    /// Used to dedup warnings per (path, content) without re-reading the
    /// file, which could have been replaced between parse and validate.
    #[serde(skip)]
    content_hash: Option<u64>,
    /// What layout this repo/layer is using, if loaded from disk.
    #[serde(skip)]
    layout: Option<Layout>,
}

/// Maps a key that is unknown at the top level of an mfile to the nesting
/// path where it is actually valid, when there is one. `lifecycle_hooks` is
/// top-level in a loadout but nests under `[session]` in a project mfile, so a
/// user who lifts the documented loadout snippet lands it here; the correct
/// path is more useful than the blanket upgrade advice.
fn misplaced_top_level_key(key: &str) -> Option<&'static str> {
    match key {
        "lifecycle_hooks" => Some("[[session.lifecycle_hooks]]"),
        _ => None,
    }
}

/// Hash the raw bytes of an mfile so warning dedup can key on the content
/// that actually produced the parsed `File`, rather than re-reading the path
/// (which may have been replaced between parse and validate).
fn hash_bytes(bytes: &[u8]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

impl File {
    /// Parses a `minimal.toml` from raw bytes — the pure, filesystem-free core
    /// of [`File::from_dir`], exposed for fuzzing (crates/mfile/fuzz) and tests.
    pub fn from_toml_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::parse(bytes, None)
    }

    /// Deserializes `minimal.toml` bytes, mapping serde's opaque untagged
    /// `LinkConfig` failure to [`Error::LinkConfig`], which names the keys a
    /// link table must set and where the bad table is, instead of quoting
    /// serde's internal enum name.
    fn parse(bytes: &[u8], path: Option<&Path>) -> Result<Self, Error> {
        toml::from_slice(bytes).map_err(|e| {
            if !e.message().contains("untagged enum LinkConfig") {
                return Error::Format(e);
            }
            let start = e.span().map(|s| s.start.min(bytes.len()));
            let line = start.map(|s| bytes[..s].iter().filter(|b| **b == b'\n').count() + 1);
            // The nearest table header at or above the bad table's line.
            let table = start.and_then(|s| {
                let line_end = bytes[s..]
                    .iter()
                    .position(|b| *b == b'\n')
                    .map_or(bytes.len(), |p| s + p);
                String::from_utf8_lossy(&bytes[..line_end])
                    .lines()
                    .rev()
                    .map(str::trim)
                    .find(|l| l.starts_with('['))
                    .map(|l| l.split_once('#').map_or(l, |(h, _)| h).trim().to_string())
            });
            Error::LinkConfig {
                path: path.map(Path::to_path_buf),
                line,
                table,
                source: Box::new(e),
            }
        })
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
    fn init_toml(
        mut self,
        path: &PathBuf,
        layout: Layout,
        content_hash: u64,
    ) -> Result<Self, Error> {
        self.mfile_path = Some(path.to_path_buf());
        self.layout = Some(layout);
        self.content_hash = Some(content_hash);
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
    /// no `default` field, [`Error::HarnessTable`] if the file names the
    /// pre-v0.5.0 `harness` key, or [`Error::MultipleTaskActions`] if a task
    /// sets more than one action key.
    pub fn validate(&self) -> Result<(), Error> {
        if let Some(params) = &self.params {
            for (n, s) in params.0.iter() {
                if s.default.is_none() {
                    return Err(Error::MissingParamDefault(n.clone()));
                }
            }
        }
        // `[harness]` stopped parsing in v0.5.0 and now lands in `extra`,
        // setting no stack: the toolchain its name promised is silently
        // absent, and the gap only surfaces much later, as a bare
        // `linker 'cc' not found` from a build inside the session. Refuse
        // the load here, at the config, where the fix is still visible.
        if self.extra.contains_key("harness") {
            return Err(Error::HarnessTable(self.mfile_path.clone()));
        }
        // serde takes one action key as `task.action` and leaves any other in
        // `task.extra`. Refuse the task here, before `warn_unknown_fields`
        // would misreport the extra action key as unknown and suggest an
        // upgrade.
        for (task_name, task) in &self.tasks {
            let extra_actions = TaskAction::KEYS
                .iter()
                .filter(|k| task.extra.contains_key(**k))
                .map(|k| k.to_string());
            let keys: Vec<String> = std::iter::once(task.action.key().to_string())
                .chain(extra_actions)
                .collect();
            if keys.len() > 1 {
                return Err(Error::MultipleTaskActions(task_name.clone(), keys));
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
                    Self::parse(&file_data, Some(&path))?,
                    &path,
                    Layout::Root,
                    hash_bytes(&file_data),
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::IO("minimal file", path, e)),
        };

        // Check for the minimal file at `./.minimal`.
        let path = dir.as_ref().join(".minimal").join(MFILE_NAME);
        match std::fs::read(&path) {
            Ok(file_data) => Self::init_toml(
                Self::parse(&file_data, Some(&path))?,
                &path,
                Layout::DotMinimal,
                hash_bytes(&file_data),
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::NotFound),
            Err(e) => Err(Error::IO("minimal file", path, e)),
        }
    }

    /// Read-modify-write `minimal.toml` under an exclusive lock, so
    /// concurrent `min` commands cannot lose each other's edits.
    ///
    /// The lock is an advisory `flock` on the directory that holds the
    /// file's canonical path. Every process that edits the file shares it,
    /// whatever its `HOME`, and every spelling of the path (relative,
    /// absolute, through a symlink) resolves to one directory. Nothing is
    /// written into the project tree. It is held for the whole
    /// read-edit-write sequence; the content is re-read **inside** the
    /// lock, so every serialized writer sees the previous writer's result.
    /// The write itself is atomic (temp file + rename), so a concurrent
    /// reader never sees a torn file and cannot write a partial view back.
    ///
    /// Where the filesystem refuses a `flock` on a directory (NFS), the
    /// lock is a file in the per-user Minimal state directory
    /// (`<state>/minimal/mfile-locks/`), named by a hash of the canonical
    /// path. That lock only excludes processes that share the state
    /// directory. The lock is best-effort. The edit runs unlocked after one
    /// warning, still with the atomic write, when neither lock can be had.
    /// Errors reading or writing `path` itself still fail the edit. A wait
    /// for the lock that outlasts 60 s (or `MINIMAL_MFILE_LOCK_TIMEOUT_SECS`)
    /// fails the edit, so a stuck holder cannot block it forever. An edit
    /// made inside a session VM does not exclude one made on the host. The
    /// rename keeps the file's mode, but not its owner, ACLs or extended
    /// attributes: restoring the owner needs a `chown` the caller is usually
    /// not privileged for, and ACLs and xattrs have no portable Rust API, so
    /// the replacement is documented as dropping them rather than half-keeping
    /// them per platform (review on PR #2302, lib.rs:1249).
    ///
    /// The `edit` closure receives the current content (`None` if the
    /// file does not exist yet) and returns `Ok(Some(new))` to write,
    /// `Ok(None)` to leave the file untouched, or an error to abort
    /// without writing.
    pub fn edit_exclusively<E>(
        path: &Path,
        edit: impl FnOnce(Option<&str>) -> Result<Option<String>, E>,
    ) -> Result<(), E>
    where
        E: From<Error>,
    {
        let lock_dir = paths::try_minimal_state_dir()
            .map(|state| AsRef::<Path>::as_ref(&state).join("mfile-locks"));
        Self::edit_exclusively_in(lock_dir.as_deref(), mfile_lock_timeout(), path, edit)
    }

    /// [`File::edit_exclusively`] with the lock directory passed in, so
    /// tests do not write to the real state directory. `None` means the
    /// state directory could not be resolved, and the edit runs unlocked.
    fn edit_exclusively_in<E>(
        lock_dir: Option<&Path>,
        timeout: Duration,
        path: &Path,
        edit: impl FnOnce(Option<&str>) -> Result<Option<String>, E>,
    ) -> Result<(), E>
    where
        E: From<Error>,
    {
        // Resolve symlinks so the lock key and the atomic replace both
        // target the real file: `persist` would otherwise replace the
        // symlink entry itself. A file that does not exist yet is keyed
        // by its canonical parent, so `min init` shares the lock with the
        // edits that follow it. A dangling symlink is refused: the replace
        // would swap the link entry for a regular file, and following it
        // would create a file wherever the link points.
        let path = match std::fs::canonicalize(path) {
            Ok(p) => p,
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    && std::fs::symlink_metadata(path).is_ok_and(|m| m.is_symlink()) =>
            {
                let target = std::fs::read_link(path).unwrap_or_default();
                let e = std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!(
                        "symlink to {0}, which does not exist; create {0} or replace the link \
                         with a file",
                        target.display()
                    ),
                );
                return Err(Error::IO("resolving", path.to_path_buf(), e).into());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let parent = path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new("."));
                match (std::fs::canonicalize(parent), path.file_name()) {
                    (Ok(p), Some(name)) => p.join(name),
                    _ => path.to_path_buf(),
                }
            }
            Err(e) => return Err(Error::IO("resolving", path.to_path_buf(), e).into()),
        };
        let path = path.as_path();
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));

        // Held until this function returns, so across the write below.
        let _lock = Self::lock_for(lock_dir, path, timeout)?;

        let content = match std::fs::read_to_string(path) {
            Ok(s) => Some(s),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(Error::IO("reading", path.to_path_buf(), e).into()),
        };

        match edit(content.as_deref())? {
            None => Ok(()),
            Some(new) => {
                // The existing file's mode, which the replace keeps.
                let existing = match std::fs::metadata(path) {
                    Ok(meta) => Some(meta.permissions()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                    Err(e) => return Err(Error::IO("statting", path.to_path_buf(), e).into()),
                };
                // Over an existing file, the temp starts owner-only and takes
                // that file's mode just before the rename, so a private file
                // is never exposed through the temp. A new file gets 0o666
                // less the umask (open(2) applies it), as std::fs::write gave.
                let mut builder = tempfile::Builder::new();
                builder.permissions(std::fs::Permissions::from_mode(if existing.is_some() {
                    0o600
                } else {
                    0o666
                }));
                let mut tmp = match builder.tempfile_in(&parent) {
                    Ok(t) => t,
                    Err(e) => return Err(Error::IO("creating temp", path.to_path_buf(), e).into()),
                };
                if let Err(e) = tmp.write_all(new.as_bytes()) {
                    return Err(Error::IO("writing temp", path.to_path_buf(), e).into());
                }
                if let Err(e) = tmp.as_file().sync_all() {
                    return Err(Error::IO("syncing temp", path.to_path_buf(), e).into());
                }
                if let Some(perms) = existing
                    && let Err(e) = std::fs::set_permissions(tmp.path(), perms)
                {
                    return Err(Error::IO("setting permissions", path.to_path_buf(), e).into());
                }
                // Replacing by rename needs only write access to the parent
                // directory, so a read-only minimal.toml no longer fails the
                // edit the way std::fs::write did. A writability probe here
                // could not restore the old error faithfully — it would also
                // reject an edit a user runs through sudo, and the fix belongs
                // with the atomic write as a whole — so it is deferred with
                // the maintainer's sign-off on PR #2302 (lib.rs:1306), not
                // patched in isolation.
                match tmp.persist(path) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(Error::IO("replacing", path.to_path_buf(), e.error).into()),
                }
            }
        }
    }

    /// Takes the exclusive lock for the canonical `path`, saying so on
    /// stderr before it waits for another process to release it.
    ///
    /// The lock is a `flock` on the directory that holds `path`, so every
    /// process that edits the file shares it, whatever its `HOME`. Where
    /// the filesystem refuses a `flock` on a directory (NFS answers
    /// `EBADF`), the lock falls back to a file in `lock_dir`, named by a
    /// hash of `path`. `None` means neither lock can be had: it warns once
    /// and the caller edits unlocked. A wait longer than `timeout` fails,
    /// so a stuck holder cannot block an edit forever.
    fn lock_for(
        lock_dir: Option<&Path>,
        path: &Path,
        timeout: Duration,
    ) -> Result<Option<std::fs::File>, Error> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        match std::fs::File::open(parent) {
            Ok(dir) => match Self::wait_for_directory_lock(&dir, path, timeout) {
                Ok(()) => return Ok(Some(dir)),
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    return Err(Error::IO("locking", path.to_path_buf(), e));
                }
                Err(e) => tracing::debug!(
                    "cannot lock directory {} ({e}); using the state-directory lock",
                    parent.display()
                ),
            },
            Err(e) => tracing::debug!(
                "cannot open directory {} ({e}); using the state-directory lock",
                parent.display()
            ),
        }

        let Some(lock_dir) = lock_dir else {
            tracing::warn!(
                "cannot find the Minimal state directory (is HOME set?); editing {} without \
                 the lock",
                path.display()
            );
            return Ok(None);
        };
        use sha2::Digest as _;
        let digest = sha2::Sha256::digest(path.as_os_str().as_bytes());
        let name: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
        let lock_path = lock_dir.join(format!("{name}.lock"));

        if let Err(e) = std::fs::create_dir_all(lock_dir) {
            tracing::warn!(
                "cannot create lock directory {} ({e}); editing {} without the lock",
                lock_dir.display(),
                path.display()
            );
            return Ok(None);
        }
        let file = match std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
        {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(
                    "cannot open lock {} ({e}); editing {} without the lock",
                    lock_path.display(),
                    path.display()
                );
                return Ok(None);
            }
        };

        match Self::wait_for_lock(&file, path, timeout) {
            Ok(()) => Ok(Some(file)),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                Err(Error::IO("locking", path.to_path_buf(), e))
            }
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::EBADF | libc::ENOLCK | libc::EOPNOTSUPP | libc::ENOSYS)
                ) || e.raw_os_error() == Some(libc::ENOTSUP) =>
            {
                tracing::warn!(
                    "cannot lock {} ({e}); editing {} without the lock",
                    lock_path.display(),
                    path.display()
                );
                Ok(None)
            }
            Err(e) => Err(Error::IO("locking", lock_path, e)),
        }
    }

    /// [`File::wait_for_lock`] on the directory that holds `path`. Tests can
    /// make it fail with `EBADF`, as NFS does, through
    /// `tests::REFUSE_DIRECTORY_FLOCK`, to reach the state-directory lock.
    fn wait_for_directory_lock(
        dir: &std::fs::File,
        path: &Path,
        timeout: Duration,
    ) -> std::io::Result<()> {
        #[cfg(test)]
        if tests::REFUSE_DIRECTORY_FLOCK.get() {
            return Err(std::io::Error::from_raw_os_error(libc::EBADF));
        }
        Self::wait_for_lock(dir, path, timeout)
    }

    /// Takes `file`'s exclusive `flock`, polling with backoff. It says once
    /// on stderr that it waits for `path`, and gives up with
    /// [`std::io::ErrorKind::TimedOut`] after `timeout`.
    fn wait_for_lock(file: &std::fs::File, path: &Path, timeout: Duration) -> std::io::Result<()> {
        let deadline = Instant::now() + timeout;
        let mut backoff = Duration::from_millis(10);
        let mut said = false;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(()),
                Err(std::fs::TryLockError::WouldBlock) => {}
                Err(std::fs::TryLockError::Error(e)) => return Err(e),
            }
            if !said {
                eprintln!(
                    "waiting for another command to finish editing {}",
                    path.display()
                );
                said = true;
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "another command kept this file locked for {}s. It may be run by \
                         another user. Stop that command and run this one again, or set \
                         {MFILE_LOCK_TIMEOUT_ENV} to wait longer",
                        timeout.as_secs()
                    ),
                ));
            }
            std::thread::sleep(backoff.min(deadline - now));
            backoff = (backoff * 2).min(Duration::from_secs(1));
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
        // One command decodes the same file several times; without this a
        // single load prints each warning once per decode. Surface them only
        // the first time a given path is validated in this process.
        //
        // The dedup key is (path, content) rather than path alone: a
        // long-lived process (notably `minimald`) re-reads and re-validates
        // the workspace `minimal.toml` on every session bring-up, and keying
        // on path alone would permanently silence the warning after the first
        // decode — even if the user edits the file and breaks it again. The
        // content hash collapses the repeated decodes of an unchanged file
        // while still re-warning when the file is edited or re-broken.
        //
        // The hash is computed from the bytes that produced `self` (see
        // `hash_bytes`), not re-read from disk here: re-reading could hash a
        // replacement file written between parse and validate, and then a
        // later validation of that replacement would be wrongly suppressed.
        if let (Some(path), Some(content_hash)) = (&self.mfile_path, self.content_hash) {
            static WARNED_FILES: LazyLock<Mutex<HashSet<(PathBuf, u64)>>> =
                LazyLock::new(|| Mutex::new(HashSet::new()));
            if !WARNED_FILES
                .lock()
                .unwrap()
                .insert((path.clone(), content_hash))
            {
                return;
            }
        }

        let mut was_unknown_fields = false;
        if !self.extra.is_empty() {
            // A key that is valid at another nesting level is not really
            // unknown; point at the correct path instead of the generic
            // upgrade hint, which cannot fix it.
            // BEP-037: a project cannot set secret-store rules. The table is
            // ignored with its own warning, not the generic unknown-field one.
            boxes::core::bep::warn_project_store_rules(self.extra.keys().map(String::as_str));
            let mut unknown = Vec::new();
            for key in self
                .extra
                .keys()
                .filter(|key| *key != boxes::core::bep::STORE_RULES_TABLE)
            {
                match misplaced_top_level_key(key) {
                    Some(correct) => tracing::warn!(
                        "{key} is unknown at the top level of {MFILE_NAME}; did you mean {correct}?"
                    ),
                    None => unknown.push(key.clone()),
                }
            }
            if !unknown.is_empty() {
                tracing::warn!("unknown fields in {}: {}", MFILE_NAME, unknown.join(","));
                was_unknown_fields = true;
            }
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
            tracing::warn!(
                "[defaults]profile = \"{p}\" defined, but profiles were removed in 0.5.1; move its packages to each task's [tasks.<name>] packages (or [stack] build_packages / runtime_packages, which apply to every task)"
            );
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
            boxes::core::bep::warn_project_store_rules(session.extra.keys().map(String::as_str));
            let unknown: Vec<&str> = session
                .extra
                .keys()
                .map(String::as_str)
                .filter(|key| *key != boxes::core::bep::STORE_RULES_TABLE)
                .collect();
            if !unknown.is_empty() {
                tracing::warn!(
                    "unknown fields in [session] section of {}: {}",
                    MFILE_NAME,
                    unknown.join(",")
                );
                was_unknown_fields = true;
            }
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
                    "[tasks.{task_name}]profile = \"{p}\" defined, but profiles were removed in 0.5.1; move its packages to [tasks.{task_name}] packages"
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
    ///  - repo-wide `[params]` as args, unless the task declares an arg of the same name
    ///
    /// The returned task will not have had any string interpolations applied.
    pub fn hydrate_task_defaults(&self, task: &mut Task) {
        if let Some(params) = &self.params {
            for (name, spec) in &params.0 {
                task.args
                    .0
                    .entry(name.clone())
                    .or_insert_with(|| spec.clone());
            }
        }
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
            (IndexSourceMode::Auto, Some(_)) => {
                // Pinned auto: the full per-link chain. `snapshot` above
                // proves the upstream pin exists; rebuild both objects per
                // link here (closure first — the curated catalog).
                let u = self.upstream.as_ref().expect("pinned auto has an upstream");
                let LinkConfig::Git {
                    repo,
                    locked_commit: Some(commit),
                    ..
                } = &u.link
                else {
                    unreachable!("snapshot presence implies a locked git upstream");
                };
                let sideloads = u
                    .sideloads()
                    .iter()
                    .filter_map(|sl| match sl.link() {
                        LinkConfig::Git {
                            repo,
                            locked_commit: Some(commit),
                            ..
                        } => Some(ChainLink {
                            closure: commit_closure_object(repo, commit),
                            snapshot: commit_index_object(repo, commit),
                        }),
                        _ => None,
                    })
                    .collect();
                Ok(CacheConfig::AutoChain {
                    upstream: ChainLink {
                        closure: commit_closure_object(repo, commit),
                        snapshot: commit_index_object(repo, commit),
                    },
                    sideloads,
                })
            }
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
    use std::sync::Arc;
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
                        vars: BTreeMap::new(),
                        patch: EnvPatches {
                            dir: [("~/.claude".to_string(), PatchSetting::ReadWrite)].into(),
                            file: BTreeMap::new()
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
                            vars: BTreeMap::new(),
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
                content_hash: None,
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
            dir: BTreeMap::from_iter([
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
                file: BTreeMap::new()
            }
        );
    }

    /// `~/` expands against the home the caller passes, not the ambient
    /// process's, and absolute paths are left alone. Directories come before
    /// files, each sorted by declared path.
    #[test]
    fn to_fs_mappings_expands_against_the_given_home() {
        let patches = EnvPatches {
            dir: [("~/.claude".to_string(), PatchSetting::ReadWrite)].into(),
            file: [
                ("~/.claude.json".to_string(), PatchSetting::ReadOnly),
                ("/etc/hosts".to_string(), PatchSetting::ReadOnly),
            ]
            .into(),
        };

        let mappings = patches
            .to_fs_mappings(Some(Path::new("/home/dev")))
            .expect("a real home expands");

        assert_eq!(
            mappings
                .iter()
                .map(|m| (m.host_path.as_str(), m.is_file, m.read_only))
                .collect::<Vec<_>>(),
            vec![
                ("/home/dev/.claude", false, false),
                ("/etc/hosts", true, true),
                ("/home/dev/.claude.json", true, true),
            ]
        );
    }

    /// Regression guard for #1204: `minimald` runs as pid 1 inside the guest
    /// with `HOME=/`, and expanding a package-declared `~/.claude.json`
    /// against that used to produce `/.claude.json` — a create against the
    /// guest's read-only rootfs, failing with `EROFS`. Refuse it instead, and
    /// name the path as declared so the caller can point at the package.
    #[test]
    fn to_fs_mappings_refuses_a_root_home() {
        let patches = EnvPatches {
            file: [("~/.claude.json".to_string(), PatchSetting::ReadWrite)].into(),
            ..Default::default()
        };

        let err = patches
            .to_fs_mappings(Some(Path::new("/")))
            .expect_err("`/` is not a home directory");

        assert_eq!(
            err,
            PatchHomeError {
                declared: "~/.claude.json".to_string(),
                home: HomeUnusable::NotAHome(PathBuf::from("/")),
            }
        );
        assert!(
            err.to_string().contains("~/.claude.json"),
            "the error must name the unexpanded path, got {err}"
        );
    }

    /// Every spelling of the filesystem root is refused, not just the literal
    /// `"/"`. A string-exact guard let `//` and `/.` through — both are
    /// absolute, both compare unequal to `"/"`, and both then expanded
    /// `~/.claude.json` right back to `/.claude.json`, reproducing #1204 with
    /// a `HOME` a shell or a `WORKDIR /` image could plausibly set.
    #[test]
    fn to_fs_mappings_refuses_every_spelling_of_root() {
        let patches = EnvPatches {
            file: [("~/.claude.json".to_string(), PatchSetting::ReadWrite)].into(),
            ..Default::default()
        };

        for home in ["//", "/.", "///", "/./."] {
            assert_eq!(
                patches
                    .to_fs_mappings(Some(Path::new(home)))
                    .unwrap_err()
                    .home,
                HomeUnusable::NotAHome(PathBuf::from(home)),
                "`HOME={home}` names the filesystem root and must be refused"
            );
        }
    }

    /// A home that does name a directory expands the same however it is
    /// spelled: trailing separators, doubled separators and `.` segments are
    /// normalized away rather than passed into the mapping.
    #[test]
    fn to_fs_mappings_normalizes_the_home_it_expands_against() {
        let patches = EnvPatches {
            file: [("~/.claude.json".to_string(), PatchSetting::ReadWrite)].into(),
            ..Default::default()
        };

        for home in ["/home/dev", "/home/dev/", "/home//dev", "/home/./dev/."] {
            let mappings = patches.to_fs_mappings(Some(Path::new(home))).unwrap();
            assert_eq!(
                mappings[0].host_path, "/home/dev/.claude.json",
                "`HOME={home}` should expand like `/home/dev`"
            );
        }
    }

    /// A relative `HOME` is no home either — expanding against it would make
    /// the mapping depend on whatever directory the daemon happens to be in.
    #[test]
    fn to_fs_mappings_refuses_a_relative_home() {
        let patches = EnvPatches {
            file: [("~/.claude.json".to_string(), PatchSetting::ReadWrite)].into(),
            ..Default::default()
        };

        assert_eq!(
            patches
                .to_fs_mappings(Some(Path::new("home/dev")))
                .unwrap_err()
                .home,
            HomeUnusable::NotAHome(PathBuf::from("home/dev")),
        );
    }

    /// An unset `HOME` is an error too, where it used to panic on
    /// `home_dir().unwrap()`. Paths that never mention `~/` still resolve —
    /// no home is needed for those.
    #[test]
    fn to_fs_mappings_without_a_home() {
        let tilde = EnvPatches {
            dir: [("~/.cache".to_string(), PatchSetting::ReadWrite)].into(),
            ..Default::default()
        };
        assert_eq!(
            tilde.to_fs_mappings(None).unwrap_err(),
            PatchHomeError {
                declared: "~/.cache".to_string(),
                home: HomeUnusable::Unset,
            }
        );

        let absolute = EnvPatches {
            dir: [("/var/cache".to_string(), PatchSetting::ReadWrite)].into(),
            ..Default::default()
        };
        assert_eq!(
            absolute
                .to_fs_mappings(None)
                .expect("absolute paths need no home")
                .len(),
            1
        );
    }

    /// Two [`EnvPatches`] holding the same entries inserted in opposite
    /// orders lower to the same mapping sequence and serialize identically:
    /// the order comes off the sorted map, not off insertion, so the sandbox
    /// setup and any serialized patch table are stable from run to run.
    #[test]
    fn to_fs_mappings_and_serialization_are_insertion_order_independent() {
        let mut forward = EnvPatches::default();
        for k in ["~/a", "~/b", "~/c"] {
            forward.dir.insert(k.to_string(), PatchSetting::ReadOnly);
        }
        for k in ["/x", "/y", "/z"] {
            forward.file.insert(k.to_string(), PatchSetting::ReadWrite);
        }

        let mut reverse = EnvPatches::default();
        for k in ["~/c", "~/b", "~/a"] {
            reverse.dir.insert(k.to_string(), PatchSetting::ReadOnly);
        }
        for k in ["/z", "/y", "/x"] {
            reverse.file.insert(k.to_string(), PatchSetting::ReadWrite);
        }

        let seq = |p: &EnvPatches| {
            p.to_fs_mappings(Some(Path::new("/home/dev")))
                .unwrap()
                .into_iter()
                .map(|m| m.host_path)
                .collect::<Vec<_>>()
        };
        assert_eq!(seq(&forward), seq(&reverse));
        assert_eq!(
            toml::to_string(&forward).unwrap(),
            toml::to_string(&reverse).unwrap()
        );
    }

    /// A read-only mapping consumes a source that must already exist, so it is
    /// never fabricated; only read-write mappings may create a missing path.
    #[test]
    fn to_fs_mappings_derives_create_if_missing_from_the_mode() {
        let patches = EnvPatches {
            dir: [
                ("/ro-dir".to_string(), PatchSetting::ReadOnly),
                ("/rw-dir".to_string(), PatchSetting::ReadWrite),
            ]
            .into(),
            file: [
                ("/ro-file".to_string(), PatchSetting::ReadOnly),
                ("/rw-file".to_string(), PatchSetting::ReadWrite),
            ]
            .into(),
        };

        let mappings = patches.to_fs_mappings(None).unwrap();
        let flags = mappings
            .iter()
            .map(|m| (m.host_path.as_str(), m.create_if_missing))
            .collect::<Vec<_>>();

        assert_eq!(
            flags,
            vec![
                ("/ro-dir", false),
                ("/rw-dir", true),
                ("/ro-file", false),
                ("/rw-file", true),
            ]
        );
    }

    /// Repo-wide `[params]` reach every task as defaulted args, and a task
    /// arg of the same name shadows the repo param.
    #[test]
    fn task_inherits_repo_params_as_args() {
        let mf: File = toml::from_str(indoc! {
            r#"
            [params]
            greeting = { type = "string", default = "hi" }
            name = { type = "string", default = "repo" }

            [tasks.useparam]
            bash = "echo %{greeting} %{name}"
            args.name = { type = "string", default = "task" }
            "#
        })
        .unwrap();

        let task = mf.task("useparam").unwrap();
        assert_eq!(
            task.args.0.get("greeting"),
            Some(&args::ArgSpec {
                spec: args::ArgSchema::Scalar(args::PrimitiveSpec::String),
                help: None,
                default: Some("hi".to_string()),
            })
        );
        assert_eq!(
            task.args.0.get("name").and_then(|a| a.default.as_deref()),
            Some("task"),
            "a task arg must not be replaced by a repo param of the same name"
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

    /// `OutputKind::OciImage` serializes its `vars` in key order regardless of
    /// insertion order, so the same declaration emits the same bytes run to
    /// run rather than following a `HashMap`'s per-process iteration order.
    #[test]
    fn oci_image_vars_serialize_in_key_order() {
        let serialize = |keys: [&str; 3]| {
            let mut kind = OutputKind::default();
            let OutputKind::OciImage { vars, .. } = &mut kind else {
                unreachable!("default output kind is OciImage");
            };
            for k in keys {
                vars.insert(k.to_string(), "v".to_string());
            }
            toml::to_string(&kind).unwrap()
        };
        assert_eq!(serialize(["A", "B", "C"]), serialize(["C", "B", "A"]));
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
    /// lenient coverage lives in the `boxes` crate's loadout tests
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

    /// `quic443` is a `[session.network]` setting: it loads there, and the
    /// `[session.network.bep]` table refuses it as an unknown field.
    #[test]
    fn session_network_quic443_loads() {
        let mf: File = toml::from_str(indoc! {
            r#"
            [session.network]
            quic443 = "auto"
            "#
        })
        .unwrap();
        let network = mf
            .session
            .and_then(|session| session.network)
            .expect("network table parses");
        assert_eq!(network.quic443, Some(boxes::core::bep::Quic443::Auto));
        assert!(network.bep.is_none());

        let err = toml::from_str::<File>(indoc! {
            r#"
            [session.network.bep]
            quic443 = "auto"
            "#
        })
        .expect_err("quic443 is not a [network.bep] field");
        assert!(err.to_string().contains("quic443"), "{err}");
    }

    /// BEP-057: a project's `[session.secrets]` acknowledgement loads, is
    /// dropped, and leaves the grants beside it intact.
    #[test]
    fn session_secrets_drop_project_acknowledgement() {
        let mf: File = toml::from_str(indoc! {
            r#"
            [session.secrets]
            acknowledge_full_breadth_unenrolled = true

            [session.secrets.GH_TOKEN]
            source = "broker"
            scopes = ["github:repo:read"]
            "#
        })
        .unwrap();
        let secrets = mf.session.expect("session parses").secrets;
        assert_eq!(secrets.keys().collect::<Vec<_>>(), ["GH_TOKEN"]);
    }

    #[test]
    fn top_level_lifecycle_hooks_points_at_the_session_path() {
        assert_eq!(
            misplaced_top_level_key("lifecycle_hooks"),
            Some("[[session.lifecycle_hooks]]")
        );
        assert_eq!(misplaced_top_level_key("genuinely_unknown"), None);
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

        // Default is auto: the per-link chain — sealed closure first, then
        // the byte-copy snapshot, then (upstream only) the root.
        assert_eq!(
            pinned.cache_config(None).unwrap(),
            CacheConfig::AutoChain {
                upstream: ChainLink {
                    closure: format!("github.com/gominimal/pkgs/{SHA}.closure.shisha"),
                    snapshot: object.clone(),
                },
                sideloads: vec![],
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

    /// The demo project under `crates/boxes/example_project` must
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
            "/../boxes/example_project/minimal.toml"
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

    /// The once-per-path warning dedup must key on (path, content), not path
    /// alone: a long-lived process re-validates the same file repeatedly, and
    /// an edited file must re-warn. This test drives `warn_unknown_fields`
    /// through the public `validate` path and counts the emitted warnings.
    #[test]
    fn warn_unknown_fields_rewarns_when_file_content_changes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(MFILE_NAME);

        let capture = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);

        let write = |contents: &str| {
            std::fs::write(&path, contents).unwrap();
            let file = File::from_dir(dir.path()).unwrap();
            file.validate().unwrap();
        };

        // First decode of a file with an unknown field warns once.
        write("[unknown_top_level]\nkey = \"v\"\n");
        assert_eq!(count_unknown_warnings(&capture), 1);

        // Re-validating the unchanged file does not warn again.
        write("[unknown_top_level]\nkey = \"v\"\n");
        assert_eq!(count_unknown_warnings(&capture), 1);

        // Editing the file (new content) re-warns.
        write("[unknown_top_level]\nkey = \"v\"\nother = \"w\"\n");
        assert_eq!(count_unknown_warnings(&capture), 2);

        drop(guard);
    }

    /// `[harness]` is the pre-v0.5.0 name of `[stack]` and no longer parses:
    /// a file that still uses it is refused at load — before any build runs
    /// and misses its toolchain — and pointed at the rename. The refusal
    /// names the offending file, so a layer pulled from upstream can be
    /// located without re-reading every candidate.
    #[test]
    fn harness_table_no_longer_parses() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join(MFILE_NAME), "[harness]\nuse = \"rust\"\n").unwrap();

        let err = File::from_dir(dir.path()).unwrap_err();
        let path = dir.path().join(MFILE_NAME);
        assert!(
            matches!(&err, Error::HarnessTable(Some(p)) if *p == path),
            "{err:?}"
        );
        let msg = err.to_string();
        assert!(msg.contains("Replace it with a `[stack]` table"), "{msg}");
        assert!(msg.starts_with(&path.display().to_string()), "{msg}");
    }

    /// The pre-v0.5.0 `harness` key can also arrive as a bare string, not a
    /// table; it lands in `extra` all the same and is refused identically.
    #[test]
    fn harness_scalar_key_is_refused_like_the_table() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join(MFILE_NAME), "harness = \"rust\"\n").unwrap();

        let err = File::from_dir(dir.path()).unwrap_err();
        let path = dir.path().join(MFILE_NAME);
        assert!(
            matches!(&err, Error::HarnessTable(Some(p)) if *p == path),
            "{err:?}"
        );
        let msg = err.to_string();
        assert!(msg.contains("the `harness` key"), "{msg}");
        assert!(msg.contains("`name = \"x\"` under `[stack]`"), "{msg}");
        assert!(msg.starts_with(&path.display().to_string()), "{msg}");
    }

    /// A file parsed without a path (the wire/fuzz entry point) is still
    /// refused, with wording that stands on its own without one.
    #[test]
    fn harness_key_without_a_path_names_no_file() {
        let file = File::from_toml_bytes(b"harness = \"rust\"\n").unwrap();
        let err = file.validate().expect_err("`harness` must be refused");

        assert!(matches!(err, Error::HarnessTable(None)), "{err:?}");
        let msg = err.to_string();
        assert!(msg.starts_with("the `harness` key"), "{msg}");
    }

    /// A task with two action keys is refused with an error naming the task
    /// and both keys, instead of running one and calling the other unknown.
    #[test]
    fn task_with_two_actions_is_refused() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join(MFILE_NAME),
            "[tasks.both]\nexec = [\"echo\", \"from-exec\"]\nbash = \"echo from-bash\"\n",
        )
        .unwrap();

        let capture = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        let err = File::from_dir(dir.path()).expect_err("two actions must be refused");
        drop(guard);

        assert!(matches!(err, Error::MultipleTaskActions(..)), "{err:?}");
        let msg = err.to_string();
        assert!(
            msg.starts_with("task `both` sets more than one action ("),
            "{msg}"
        );
        assert!(msg.contains("exec") && msg.contains("bash"), "{msg}");
        assert!(msg.ends_with("); set exactly one"), "{msg}");
        let out = capture.contents();
        assert!(!out.contains("unknown fields in task"), "{out}");
        assert!(!out.contains("update to a newer version"), "{out}");
    }

    #[test]
    fn task_with_one_action_passes_validate() {
        for action in [
            "exec = [\"echo\", \"hi\"]",
            "bash = \"echo hi\"",
            "echo = \"hi\"",
            "cmdcmd = [\"gen\"]",
        ] {
            let file: File = toml::from_str(&format!("[tasks.one]\n{action}\n")).unwrap();
            file.validate().unwrap_or_else(|e| panic!("{action}: {e}"));
            assert!(file.tasks["one"].extra.is_empty(), "{action}");
        }
    }

    /// BEP-037: a project's `[secret-store-rules]` table, at the top level
    /// or under `[session]`, is ignored with its own warning, not the
    /// generic unknown-field one.
    #[test]
    fn project_store_rules_are_ignored_with_warning() {
        for body in [
            "[secret-store-rules.claude]\nupstream = [\"api.anthropic.com\"]\nheader = \"x-api-key\"\n",
            "[session.secret-store-rules.claude]\nupstream = [\"api.anthropic.com\"]\n",
        ] {
            let dir = tempdir().unwrap();
            std::fs::write(dir.path().join(MFILE_NAME), body).unwrap();
            let capture = CaptureWriter::default();
            let subscriber = tracing_subscriber::fmt()
                .with_writer(capture.clone())
                .with_ansi(false)
                .finish();
            let guard = tracing::subscriber::set_default(subscriber);
            File::from_dir(dir.path()).expect("the file still reads");
            drop(guard);
            let out = capture.contents();
            assert!(
                out.contains(boxes::core::bep::PROJECT_STORE_RULES_IGNORED),
                "{body}: {out}"
            );
            assert_eq!(count_unknown_warnings(&capture), 0, "{body}: {out}");
        }
    }

    fn count_unknown_warnings(capture: &CaptureWriter) -> usize {
        capture
            .contents()
            .lines()
            .filter(|line| line.contains("unknown fields in"))
            .count()
    }

    /// Minimal `MakeWriter` that records formatted tracing output into a
    /// shared buffer so tests can assert on emitted warnings.
    #[derive(Clone)]
    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl CaptureWriter {
        fn default() -> Self {
            Self(Arc::new(Mutex::new(Vec::new())))
        }

        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
        type Writer = CaptureWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CaptureWriter(self.0.clone())
        }
    }

    /// One lock directory for the whole test process, so tests never write
    /// to the real state directory; lock files are keyed by each test's
    /// own temp path, so tests do not contend.
    static TEST_LOCK_DIR: LazyLock<tempfile::TempDir> = LazyLock::new(|| tempdir().unwrap());

    thread_local! {
        /// Makes this thread's directory `flock` fail with `EBADF`, as NFS
        /// answers, so a test reaches the state-directory lock.
        pub(super) static REFUSE_DIRECTORY_FLOCK: std::cell::Cell<bool> =
            const { std::cell::Cell::new(false) };
    }

    /// Runs `f` with this thread's directory `flock` refused.
    fn with_directory_flock_refused<T>(f: impl FnOnce() -> T) -> T {
        REFUSE_DIRECTORY_FLOCK.set(true);
        let out = f();
        REFUSE_DIRECTORY_FLOCK.set(false);
        out
    }

    const TEST_TIMEOUT: Duration = Duration::from_secs(60);

    fn edit_in_test(
        path: &Path,
        edit: impl FnOnce(Option<&str>) -> Result<Option<String>, Error>,
    ) -> Result<(), Error> {
        File::edit_exclusively_in(Some(TEST_LOCK_DIR.path()), TEST_TIMEOUT, path, edit)
    }

    #[test]
    fn edit_exclusively_serializes_writers() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(MFILE_NAME);
        std::fs::write(&path, "[stack]\nname = \"base\"\n").unwrap();

        let writers: Vec<String> = (0..8).map(|i| format!("k{i} = {i}\n")).collect();
        std::thread::scope(|s| {
            for line in &writers {
                let path = &path;
                s.spawn(move || {
                    edit_in_test(path, |content| {
                        let Some(mut content) = content.map(str::to_string) else {
                            panic!("minimal.toml vanished under the lock");
                        };
                        content.push_str(line);
                        Ok(Some(content))
                    })
                    .unwrap();
                });
            }
        });

        let final_content = std::fs::read_to_string(&path).unwrap();
        for line in &writers {
            assert!(
                final_content.contains(line),
                "lost edit `{line:?}`; file:\n{final_content}"
            );
        }
    }

    #[test]
    fn edit_exclusively_never_exposes_a_torn_write() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(MFILE_NAME);
        std::fs::write(&path, "[stack]\nname = \"base\"\n").unwrap();

        std::thread::scope(|s| {
            s.spawn(|| {
                for i in 0..64 {
                    edit_in_test(&path, |content| {
                        let mut content = content
                            .expect("minimal.toml vanished under the lock")
                            .to_string();
                        content.push_str(&format!("k{i} = {i}\n"));
                        Ok(Some(content))
                    })
                    .unwrap();
                }
            });
            s.spawn(|| {
                for _ in 0..512 {
                    // The atomic-replace write means every read observes
                    // either the old or the new file — never a truncated
                    // prefix of one, which `std::fs::write` in place can
                    // produce. A torn write leaves a partial table that
                    // fails to parse as a whole document.
                    let content = std::fs::read_to_string(&path).unwrap();
                    toml::from_str::<toml::Value>(&content).unwrap_or_else(|e| {
                        panic!("torn read: {e}; content: {content:?}");
                    });
                }
            });
        });
    }

    #[test]
    fn link_missing_repo_and_dir_names_the_fields() {
        let err = File::from_toml_bytes(indoc! {b"
            [upstream]
            branch = \"main\"
        "})
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("`repo`"), "message: {msg}");
        assert!(msg.contains("`dir`"), "message: {msg}");
        assert!(msg.contains("[upstream]"), "message: {msg}");
    }

    /// A sideload missing `repo`/`dir` is mapped too, and the message
    /// points at the sideload's table rather than at `[upstream]`. Also
    /// pins the serde wording the mapping matches on.
    #[test]
    fn sideload_missing_repo_and_dir_names_the_table_and_line() {
        let err = File::from_toml_bytes(indoc! {b"
            [upstream]
            repo = \"https://example.com/pkgs.git\"

            [[upstream.sideload]]
            dir = \"../local\"

            [[upstream.sideload]]
            branch = \"main\"
        "})
        .unwrap_err();
        assert!(
            matches!(err, Error::LinkConfig { .. }),
            "not mapped to LinkConfig: {err:?}"
        );
        let msg = err.to_string();
        assert!(msg.contains("`repo`"), "message: {msg}");
        assert!(msg.contains("[[upstream.sideload]]"), "message: {msg}");
        assert!(msg.contains("line 7"), "message: {msg}");
        assert!(!msg.contains("untagged"), "message: {msg}");
    }

    /// A second editor waits while the lock is held, including one that
    /// names the file through a symlink: both spellings share one lock.
    #[test]
    #[cfg(unix)]
    fn edit_exclusively_waits_for_the_holder_across_spellings() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(MFILE_NAME);
        std::fs::write(&path, "[stack]\nname = \"base\"\n").unwrap();
        let link = dir.path().join("link.toml");
        std::os::unix::fs::symlink(&path, &link).unwrap();

        let held = File::lock_for(
            Some(TEST_LOCK_DIR.path()),
            &std::fs::canonicalize(&path).unwrap(),
            TEST_TIMEOUT,
        )
        .unwrap()
        .expect("flock is supported on the test filesystem");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::scope(|s| {
            s.spawn(|| {
                edit_in_test(&link, |content| Ok(content.map(|c| format!("{c}k = 1\n")))).unwrap();
                tx.send(()).unwrap();
            });
            assert!(
                rx.recv_timeout(std::time::Duration::from_millis(300))
                    .is_err(),
                "the edit ran while another holder had the lock"
            );
            drop(held);
            rx.recv_timeout(std::time::Duration::from_secs(30))
                .expect("the edit runs once the lock is released");
        });
        assert!(std::fs::read_to_string(&path).unwrap().contains("k = 1"));
    }

    #[test]
    fn edit_exclusively_creates_a_missing_file_at_the_requested_path() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(MFILE_NAME);

        edit_in_test(&path, |content| {
            assert!(content.is_none(), "a missing file reads as None");
            Ok(Some("[stack]\nname = \"base\"\n".to_string()))
        })
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "[stack]\nname = \"base\"\n"
        );
    }

    #[test]
    #[cfg(unix)]
    fn edit_exclusively_follows_a_symlink_instead_of_replacing_it() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("real.toml");
        std::fs::write(&target, "[stack]\nname = \"base\"\n").unwrap();
        let link = dir.path().join(MFILE_NAME);
        std::os::unix::fs::symlink(&target, &link).unwrap();

        edit_in_test(&link, |content| {
            let mut content = content.expect("target vanished").to_string();
            content.push_str("k = \"v\"\n");
            Ok(Some(content))
        })
        .unwrap();

        assert!(
            std::fs::symlink_metadata(&link)
                .expect("symlink entry vanished")
                .file_type()
                .is_symlink(),
            "the edit replaced the symlink entry itself"
        );
        let content = std::fs::read_to_string(&target).unwrap();
        assert!(content.contains("k = \"v\""), "content: {content}");
    }

    #[test]
    fn edit_exclusively_refuses_a_dangling_symlink() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("missing.toml");
        let link = dir.path().join(MFILE_NAME);
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = edit_in_test(&link, |_| Ok(Some("k = \"v\"\n".to_string()))).unwrap_err();

        assert_eq!(
            err.to_string(),
            format!(
                "resolving I/O error at path {0}: symlink to {1}, which does not exist; \
                 create {1} or replace the link with a file",
                link.display(),
                target.display()
            )
        );
        assert!(
            std::fs::symlink_metadata(&link).unwrap().is_symlink(),
            "the edit replaced the dangling symlink"
        );
        assert!(!target.exists(), "the edit created the link's target");
    }

    #[test]
    fn edit_exclusively_gives_a_new_file_the_mode_fs_write_would() {
        // Compare with a file std::fs::write creates under the same umask;
        // setting the umask here would race the other test threads.
        let dir = tempdir().unwrap();
        let reference = dir.path().join("reference");
        std::fs::write(&reference, "").unwrap();
        let expected = std::fs::metadata(&reference).unwrap().permissions().mode() & 0o777;
        let path = dir.path().join(MFILE_NAME);

        edit_in_test(&path, |_| Ok(Some("k = \"v\"\n".to_string()))).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, expected,
            "mode {mode:o}, std::fs::write gives {expected:o}"
        );
        if expected & 0o022 == 0 {
            assert_eq!(
                mode & 0o022,
                0,
                "a new file is group/world-writable: {mode:o}"
            );
        }
    }

    #[test]
    fn edit_exclusively_keeps_a_private_file_private() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(MFILE_NAME);
        std::fs::write(&path, "k = \"v\"\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        edit_in_test(&path, |_| Ok(Some("k = \"w\"\n".to_string()))).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode {mode:o}");
    }

    #[test]
    fn edit_exclusively_leaves_no_files_beside_minimal_toml() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(MFILE_NAME);
        std::fs::write(&path, "[stack]\nname = \"base\"\n").unwrap();

        edit_in_test(&path, |content| {
            let mut content = content.expect("minimal.toml vanished").to_string();
            content.push_str("k = \"v\"\n");
            Ok(Some(content))
        })
        .unwrap();

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![OsString::from(MFILE_NAME)]);
    }

    /// Edits `minimal.toml` in a fresh directory with `lock_dir` as the
    /// lock directory and asserts the write landed.
    fn assert_edit_lands_with_lock_dir(lock_dir: Option<&Path>) {
        let dir = tempdir().unwrap();
        let path = dir.path().join(MFILE_NAME);

        File::edit_exclusively_in::<Error>(lock_dir, TEST_TIMEOUT, &path, |content| {
            assert!(content.is_none());
            Ok(Some("k = \"v\"\n".to_string()))
        })
        .unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "k = \"v\"\n");
    }

    #[test]
    fn edit_exclusively_lands_when_the_lock_dir_cannot_be_created() {
        // A lock directory beneath a regular file cannot be created, even
        // by root (ENOTDIR), like a state dir on a read-only filesystem.
        let state = tempdir().unwrap();
        let blocker = state.path().join("not-a-dir");
        std::fs::write(&blocker, "").unwrap();
        assert_edit_lands_with_lock_dir(Some(&blocker.join("mfile-locks")));
    }

    #[test]
    fn edit_exclusively_lands_when_the_lock_dir_is_read_only() {
        // An existing read-only lock directory: the lock file cannot be
        // opened (EACCES), unless the test runs as root, which locks.
        let state = tempdir().unwrap();
        let lock_dir = state.path().join("mfile-locks");
        std::fs::create_dir(&lock_dir).unwrap();
        std::fs::set_permissions(&lock_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        assert_edit_lands_with_lock_dir(Some(&lock_dir));
        std::fs::set_permissions(&lock_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn edit_exclusively_lands_without_a_state_dir() {
        assert_edit_lands_with_lock_dir(None);
    }

    #[test]
    fn edit_exclusively_excludes_editors_with_different_state_dirs() {
        // minimald and a CLI with another HOME resolve different state
        // directories. The directory lock still makes them exclude.
        let dir = tempdir().unwrap();
        let path = std::fs::canonicalize(dir.path()).unwrap().join(MFILE_NAME);
        let other_state = tempdir().unwrap();
        let _held = File::lock_for(Some(other_state.path()), &path, TEST_TIMEOUT)
            .unwrap()
            .expect("flock is supported on the test filesystem");

        let err = File::edit_exclusively_in::<Error>(
            Some(TEST_LOCK_DIR.path()),
            Duration::from_millis(200),
            &path,
            |_| Ok(Some("k = \"v\"\n".to_string())),
        )
        .unwrap_err();
        assert!(
            !path.exists(),
            "the edit ran while another holder had the lock"
        );
        assert!(
            err.to_string().contains(MFILE_LOCK_TIMEOUT_ENV),
            "error: {err}"
        );
    }

    #[test]
    fn edit_exclusively_gives_up_when_the_holder_never_releases() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(MFILE_NAME);
        std::fs::write(&path, "k = 1\n").unwrap();
        let _held = File::lock_for(
            Some(TEST_LOCK_DIR.path()),
            &std::fs::canonicalize(&path).unwrap(),
            TEST_TIMEOUT,
        )
        .unwrap()
        .expect("flock is supported on the test filesystem");

        let start = Instant::now();
        let err = File::edit_exclusively_in::<Error>(
            Some(TEST_LOCK_DIR.path()),
            Duration::from_millis(200),
            &path,
            |_| Ok(Some("k = 2\n".to_string())),
        )
        .unwrap_err();
        assert!(start.elapsed() < Duration::from_secs(10));
        assert!(matches!(err, Error::IO("locking", ..)), "error: {err:?}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "k = 1\n");
    }

    #[test]
    fn edit_exclusively_falls_back_to_the_state_dir_lock_when_the_directory_flock_is_refused() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(MFILE_NAME);
        std::fs::write(&path, "k = 1\n").unwrap();
        let state = tempdir().unwrap();
        let lock_dir = state.path().join("mfile-locks");

        // The fallback lock is taken: the edit lands and leaves its lock
        // file, named by the path's hash, in the state directory.
        with_directory_flock_refused(|| {
            File::edit_exclusively_in::<Error>(Some(&lock_dir), TEST_TIMEOUT, &path, |c| {
                assert_eq!(c, Some("k = 1\n"));
                Ok(Some("k = 2\n".to_string()))
            })
        })
        .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "k = 2\n");
        let locks: Vec<_> = std::fs::read_dir(&lock_dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(locks.len(), 1, "lock files: {locks:?}");
        assert_eq!(locks[0].extension(), Some(OsStr::new("lock")));

        // And it excludes: while another holder has that lock file, the
        // edit waits for it and times out without writing.
        let held = std::fs::OpenOptions::new()
            .write(true)
            .open(&locks[0])
            .unwrap();
        held.lock().unwrap();
        let err = with_directory_flock_refused(|| {
            File::edit_exclusively_in::<Error>(
                Some(&lock_dir),
                Duration::from_millis(200),
                &path,
                |_| Ok(Some("k = 3\n".to_string())),
            )
        })
        .unwrap_err();
        assert!(matches!(err, Error::IO("locking", ..)), "error: {err:?}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "k = 2\n");
    }

    #[test]
    fn lock_timeout_takes_whole_seconds_and_warns_on_anything_else() {
        let capture = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);

        assert_eq!(lock_timeout_from(None), Duration::from_secs(60));
        assert_eq!(lock_timeout_from(Some("5")), Duration::from_secs(5));
        assert!(capture.contents().is_empty(), "{}", capture.contents());
        for bad in ["1.5", "60s", "0", ""] {
            assert_eq!(lock_timeout_from(Some(bad)), Duration::from_secs(60));
            assert!(
                capture
                    .contents()
                    .contains(&format!("{MFILE_LOCK_TIMEOUT_ENV}={bad:?}")),
                "no warning for {bad:?}: {}",
                capture.contents()
            );
        }
        assert!(capture.contents().contains("waiting 60s"));

        drop(guard);
    }

    #[test]
    fn edit_exclusively_still_fails_when_the_target_cannot_be_written() {
        let dir = tempdir().unwrap();
        let blocker = dir.path().join("not-a-dir");
        std::fs::write(&blocker, "").unwrap();
        let path = blocker.join(MFILE_NAME);

        let err = File::edit_exclusively_in::<Error>(None, TEST_TIMEOUT, &path, |_| {
            Ok(Some("k = \"v\"\n".to_string()))
        })
        .unwrap_err();
        assert!(matches!(err, Error::IO(..)), "error: {err:?}");
    }
}
