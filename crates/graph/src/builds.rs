//! Types describing build specifications in the dependency graph.

use crate::{BuildSpecRef, Graph};
use common::{SpecOrigin, SubsetSpec, Target};
use decode::builds;
use nickel_lang_core::term::IndexMap;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

pub use decode::{AttrValue, StrPos};

/// A map with ordered iteration semantics - we need this for stable spec hashes.
type OutputMap = IndexMap<String, BuildOutput>;

/// A description of pulling source code regardless of form.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SourceFetch {
    Web {
        url: String,
        sha256: String,
        url_pos: Option<StrPos>,
        sha256_pos: Option<StrPos>,
    },
    Local {
        full_path: PathBuf,
        filename: String,
        file_hash: blake3::Hash,
    },
}

impl From<builds::SourceFetch> for SourceFetch {
    fn from(value: builds::SourceFetch) -> Self {
        match value {
            builds::SourceFetch::Web {
                url,
                sha256,
                url_pos,
                sha256_pos,
            } => SourceFetch::Web {
                url,
                sha256,
                url_pos,
                sha256_pos,
            },
            builds::SourceFetch::Local {
                full_path,
                filename,
                file_hash,
            } => SourceFetch::Local {
                full_path,
                filename,
                file_hash,
            },
        }
    }
}

/// A description of source code thats used as an input.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SourceInput {
    pub from: SourceFetch,
    pub extract: bool,
    pub strip_prefix: Option<String>,
}

impl From<builds::SourceInput> for SourceInput {
    fn from(value: builds::SourceInput) -> Self {
        Self {
            from: value.from.into(),
            extract: value.extract,
            strip_prefix: value.strip_prefix,
        }
    }
}

/// A dependency on some of the outputs of a build-spec.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubsetInput {
    pub from: BuildSpecRef,
    pub outputs: SmallVec<[String; 4]>,
}

impl SubsetInput {
    /// Constructs a new [SubsetInput], except using the given build instead.
    pub fn override_build(&self, bsr: BuildSpecRef) -> Self {
        Self {
            from: bsr,
            ..self.clone()
        }
    }

    pub fn as_spec(&self, graph: &Graph) -> SubsetSpec {
        SubsetSpec::new_single(&graph.spec_hash(&self.from), self.outputs.to_vec())
    }
}

impl From<(BuildSpecRef, HashSet<String>)> for SubsetInput {
    fn from(value: (BuildSpecRef, HashSet<String>)) -> Self {
        let (from, outputs) = value;
        let mut outputs: SmallVec<[String; 4]> = outputs.into_iter().collect();
        outputs.sort();
        outputs.dedup();
        Self { from, outputs }
    }
}

/// An input to a build spec.
///
/// Each entry in a build-spec's `build_deps` array corresponds to one [BuildDep].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum BuildDep {
    Build(BuildSpecRef),
    Source(SourceInput),
    HostPath(PathBuf),
    Local {
        full_path: PathBuf,
        filename: String,
        file_hash: blake3::Hash,
    },
    Subset(SubsetInput),
}

#[allow(dead_code)]
impl BuildDep {
    /// Returns the underlying build-spec reference if this value was the Build variant.
    pub(crate) fn as_build(&self) -> Option<&BuildSpecRef> {
        match self {
            BuildDep::Build(bsr) => Some(bsr),
            _ => None,
        }
    }
}

/// An output from a build.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(dead_code)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum BuildOutput {
    /// This output describes shared libraries matched with the given glob.
    Library { glob: String, allow_data: bool },
    /// This output describes data files matched with the given glob.
    Data {
        glob: String,
        allow_executable: bool,
    },
    /// This output describes binaries matched with the given glob.
    Binary {
        glob: String,
        allow_missing_interpreter: bool,
    },
}

impl BuildOutput {
    pub fn glob(&self) -> &String {
        match self {
            BuildOutput::Binary {
                glob,
                allow_missing_interpreter: _,
            } => glob,
            BuildOutput::Data {
                glob,
                allow_executable: _,
            } => glob,
            BuildOutput::Library {
                glob,
                allow_data: _,
            } => glob,
        }
    }
}

/// A runtime dependency declared on a build-spec.
///
/// Each entry in a build-spec's `runtime_deps` array corresponds to one [RuntimeDep].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RuntimeDep {
    /// A direct runtime dependency on the build-spec described by the contained reference.
    Build(BuildSpecRef),
    /// A direct runtime dependency on a subset of the outputs of some other build-spec.
    Subset(SubsetInput),
}

impl RuntimeDep {
    /// Returns the build spec that the runtime dependency ultimately depends on.
    pub fn bsr(&self) -> &BuildSpecRef {
        match self {
            RuntimeDep::Build(bsr) => bsr,
            RuntimeDep::Subset(SubsetInput { from, .. }) => from,
        }
    }
}

/// A unit test defined on a build spec.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SpecTest {
    /// The test needs to run in the build sandbox, rather than standalone.
    pub build_test: bool,
    /// Additional dependencies needed for the test.
    pub deps: Option<SmallVec<[BuildSpecRef; 6]>>,
    /// The tests commands.
    pub cmds: Vec<Vec<String>>,
}

/// Definition of a package in the dependency graph.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct BuildSpec {
    /// The human-readable name declared on the build spec.
    pub name: String,
    /// The system this build-spec is meant to run on. Defaults to amd64 Linux.
    pub target: Target,
    /// This spec was marked as a prebuilt - no computation, fetch the output from an archive directly.
    pub(crate) prebuilt: bool,

    /// The build commands declared on the build spec.
    pub cmds: Vec<Vec<String>>,
    /// Any arguments to the build command, ultimately passed as environment variables.
    pub build_args: Option<IndexMap<String, String>>,

    /// The dependencies needed to execute the build spec.
    pub build_deps: SmallVec<[BuildDep; 10]>,
    /// The dependencies needed to run outputs of this build spec, as well as possibly needed
    /// during the build.
    pub runtime_deps: SmallVec<[RuntimeDep; 8]>,
    /// The 'needs' (abstract dependencies) defined on the build-spec.
    pub abstract_deps: IndexMap<String, AttrValue>,
    /// The named outputs (and match patterns) produced by executing this build spec.
    pub outputs: OutputMap,

    /// An alternative build spec to use to break cycles in resolving dependencies on this build spec.
    pub replace_on_cycle: Option<BuildSpecRef>,

    /// The attributes defined on the build-spec.
    pub attrs: IndexMap<String, AttrValue>,

    /// Any unit tests defined on the build-spec.
    pub tests: Option<IndexMap<String, SpecTest>>,

    /// Identifies the collection of build-specs where this was defined.
    pub from: Arc<SpecOrigin>,
}

impl BuildSpec {
    /// Returns true if the build-spec represents a fetch of files but no actual computation.
    pub fn is_pure_prebuilt(&self) -> bool {
        self.prebuilt
    }

    /// Returns true if the build-spec represents a rollup of runtime_deps but no substance or computation of its own.
    pub fn is_pure_collection(&self) -> bool {
        self.build_deps.is_empty()
            && (self.cmds.is_empty()
                || (self.cmds.len() == 1
                    && (self.cmds[0].is_empty() || self.cmds[0][0].is_empty())))
    }

    /// Returns the upstream version, if set on the package.
    pub fn upstream_version(&self) -> Option<&String> {
        if let Some(AttrValue::String(s, _)) = self.attrs.get("upstream_version") {
            Some(s)
        } else {
            None
        }
    }
}
