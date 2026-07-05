//! The in-memory, semantic graph of software which make up a minimal environment.
use std::collections::HashSet;

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
    /// A stack with a certain name was requested, but did not exist.
    NoSuchStack { name: String },
    /// A profile has the same name as a profile in a higher layer, but did not extend it.
    ConflictingProfile { name: String },
    /// A stack has the same name as a stack in a higher layer.
    ConflictingStack { name: String },
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
            Error::NoSuchStack { name } => {
                writeln!(writer, "Error: stack '{}' does not exist", name,).unwrap()
            }
            Error::ConflictingProfile { name } => writeln!(
                writer,
                "Error: profile '{}' already exists - if you want to extend it, set 'from_profile'",
                name,
            )
            .unwrap(),
            Error::ConflictingStack { name } => {
                writeln!(writer, "Error: stack '{}' already exists", name,).unwrap()
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

/// A reference to some other [BuildSpec] in a [Graph].
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

/// Something which indicates what builds are done + useable from some cache.
pub trait BinProvider: std::fmt::Debug + Send {
    fn exists(&self, bsr: &BuildSpecRef) -> bool;
}

impl BinProvider for () {
    fn exists(&self, _bsr: &BuildSpecRef) -> bool {
        false
    }
}

impl<BP: BinProvider + ?Sized> BinProvider for Box<BP> {
    fn exists(&self, bsr: &BuildSpecRef) -> bool {
        self.as_ref().exists(bsr)
    }
}

impl<BP1: BinProvider, BP2: BinProvider> BinProvider for (BP1, BP2) {
    fn exists(&self, bsr: &BuildSpecRef) -> bool {
        self.0.exists(bsr) || self.1.exists(bsr)
    }
}

impl<BP1: BinProvider, BP2: BinProvider, BP3: BinProvider> BinProvider for (BP1, BP2, BP3) {
    fn exists(&self, bsr: &BuildSpecRef) -> bool {
        self.0.exists(bsr) || self.1.exists(bsr) || self.2.exists(bsr)
    }
}

/// A wrapper for types implementing [BinProvider] that pretends specific specs are never cached.
#[derive(Debug)]
pub struct MaskingBinProvider<BP: BinProvider> {
    p: BP,
    masked: HashSet<BuildSpecRef>,
}

impl<BP: BinProvider> MaskingBinProvider<BP> {
    pub fn new<I: IntoIterator<Item = R>, R: Into<BuildSpecRef>>(provider: BP, mask: I) -> Self {
        Self {
            p: provider,
            masked: mask.into_iter().map(|e| e.into()).collect(),
        }
    }

    pub fn into_inner(self) -> BP {
        self.p
    }
}

impl<BP: BinProvider> BinProvider for MaskingBinProvider<BP> {
    fn exists(&self, bsr: &BuildSpecRef) -> bool {
        if self.masked.contains(bsr) {
            false
        } else {
            self.p.exists(bsr)
        }
    }
}

mod builds;
pub use builds::{
    BuildDep, BuildOutput, BuildSpec, RuntimeDep, SourceFetch, SourceInput, SpecTest, SubsetInput,
};

mod env_setup;
pub use env_setup::SetupForPackages;

mod graph;
pub use graph::{CycleBreakError, Graph};

mod loader;
pub use loader::{ChainLoader, LayerCache, LayerCacheDir, SourceProvider};

pub mod wire;

mod spec_hasher;
pub use spec_hasher::SpecHasher;

mod planner;
pub use planner::Dep as PlannerDep;
pub use planner::{ExecPlan, PlanErr};

mod transitives;
pub use transitives::Dep as TransitivesDep;
pub use transitives::Transitives;
