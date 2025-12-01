use common::SpecHash;

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
    /// A profile has the same name as a profile in a higher layer, but did not extend it.
    ConflictingProfile { name: String },
    /// A package with a certain name was requested, but not found in the graph.
    NoSuchPkg { name: String },
    /// Failed to load the source code for an upstream.
    Fetch(String),
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
            Error::ConflictingProfile { name } => writeln!(
                writer,
                "Error: profile '{}' already exists - if you want to extend it, set 'from_profile'",
                name,
            )
            .unwrap(),
            Error::NoSuchPkg { name } => {
                writeln!(writer, "Error: package '{}' does not exist", name,).unwrap()
            }
            Error::Fetch(e) => {
                writeln!(writer, "Error: failed to fetch upstream layer: {}", e).unwrap()
            }
            Error::ConflictingPackage { from, .. } => {
                writeln!(writer, "Error: package '{}' already exists", from.1,).unwrap()
            }
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
pub use transitives::Dep as TransitivesDep;
pub use transitives::Transitives;
