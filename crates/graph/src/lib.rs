//! The in-memory, semantic graph of software which make up a minimal environment.
use common::{SpecHash, SpecOrigin};
use serde::{Deserialize, Serialize};

/// An error during construction or processing of the dependency graph.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Error {
    /// An error occurred during decoding.
    Decode(decode::Error),
    /// A subset depended on an output that doesnt exist.
    NoSuchOutput {
        output: String,
        from: (BuildSpecRef, String),
        build: (BuildSpecRef, String),
    },
    /// A package existed that shadowed an existing package.
    ConflictingPackage {
        from: (BuildSpecRef, String),
        build: (BuildSpecRef, String),
    },
    /// A profile with a certain name was requested, but did not exist.
    NoSuchProfile { name: String },
    /// A harness with a certain name was requested, but did not exist.
    NoSuchHarness { name: String },
    /// A profile has the same name as a profile in a higher layer, but did not extend it.
    ConflictingProfile { name: String },
    /// A harness has the same name as a harness in a higher layer.
    ConflictingHarness { name: String },
    /// A package with a certain name was requested, but not found in the graph.
    NoSuchPkg { name: String },
    /// Failed to load the source code for an upstream.
    Fetch(String),
    /// A layer declared a git upstream, but did not lock it to a commit.
    UpstreamNotPinned {
        upstream: String,
        at_layer: SpecOrigin,
    },
}

impl Error {
    /// Writes a human-friendly error to the given terminal.
    pub fn report_to(&self, writer: &mut dyn codespan_reporting::term::termcolor::WriteColor) {
        match self {
            Error::Decode(e) => e.report_to(writer),
            Error::NoSuchOutput {
                from,
                output,
                build: _,
            } => writeln!(
                writer,
                "Error: subset referenced output '{}' on '{}' which does not exist",
                output, from.1,
            )
            .unwrap(),
            Error::NoSuchProfile { name } => {
                writeln!(writer, "Error: profile '{}' does not exist", name,).unwrap()
            }
            Error::NoSuchHarness { name } => {
                writeln!(writer, "Error: harness '{}' does not exist", name,).unwrap()
            }
            Error::ConflictingProfile { name } => writeln!(
                writer,
                "Error: profile '{}' already exists - if you want to extend it, set 'from_profile'",
                name,
            )
            .unwrap(),
            Error::ConflictingHarness { name } => {
                writeln!(writer, "Error: harness '{}' already exists", name,).unwrap()
            }
            Error::ConflictingPackage { from, .. } => {
                writeln!(writer, "Error: package '{}' already exists", from.1,).unwrap()
            }
            Error::NoSuchPkg { name } => {
                writeln!(writer, "Error: package '{}' does not exist", name,).unwrap()
            }
            Error::Fetch(e) => {
                writeln!(writer, "Error: failed to fetch upstream layer: {}", e).unwrap()
            }
            Error::UpstreamNotPinned { upstream, at_layer } => writeln!(
                writer,
                "Error: the layer {:?} declares an upstream '{}' but does not pin it to a commit",
                at_layer, upstream
            )
            .unwrap(),
        }
    }

    /// Writes a human-friendly representation of the error to standard out.
    pub fn report_to_stderr(&self) {
        use codespan_reporting::term::termcolor::{ColorChoice, StandardStream};
        self.report_to(&mut StandardStream::stderr(ColorChoice::Auto).lock());
    }
}

impl From<decode::Error> for Error {
    fn from(e: decode::Error) -> Self {
        Self::Decode(e)
    }
}

/// A reference to some other [BuildSpec] in a [DepGraph].
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BuildSpecRef(pub(crate) generational_arena::Index);

impl BuildSpecRef {
    /// Returns the index of the BuildSpec in the arena.
    ///
    /// This effectively erases the type and all generation-safety: do not use unless you
    /// know what youre doing.
    pub fn index(&self) -> usize {
        self.0.into_raw_parts().0
    }
}

mod builds;
pub use builds::{
    BuildDep, BuildOutput, BuildSpec, RuntimeDep, SourceFetch, SourceInput, SpecTest, SubsetInput,
};

mod env_setup;
pub use env_setup::SetupForPackages;

mod graph;
pub use graph::{Graph, LayerCacheDir};

pub mod wire;

mod spec_hasher;
pub use spec_hasher::SpecHasher;

mod planner;
pub use planner::Dep as PlannerDep;
pub use planner::{BinProvider, ExecPlan, PlanErr};

mod transitives;
pub use transitives::Dep as TransitivesDep;
pub use transitives::Transitives;
