use common::SpecHash;

/// An error during construction or processing of the dependency graph.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Error {
    /// An error occurred during decoding.
    Decode(decode::Error),
}

impl Error {
    /// Writes a human-friendly error to the given terminal.
    pub fn report_to(&self, writer: &mut dyn codespan_reporting::term::termcolor::WriteColor) {
        match self {
            Error::Decode(e) => e.report_to(writer),
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

mod spec_hasher;
pub use spec_hasher::SpecHasher;

pub mod dep_graph;
pub use dep_graph::{
    BuildOutput, BuildSpec, BuildSpecInput, BuildSpecRef, DepGraph, RuntimeDep, SourceInput,
    SubsetInput,
};

pub mod planner;
pub use planner::{BinProvider, ExecPlan, PlanErr};

mod transitives;
pub use transitives::Transitives;
