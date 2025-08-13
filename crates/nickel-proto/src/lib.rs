use crate::spec_schema::ObjTy;
use nickel_lang_core::position::TermPos;

/// An error during processing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Error {
    SpecError(SpecError),
    UnexpectedObject {
        got: ObjTy,
        want: ObjTy,
        pos: TermPos,
    },
}

impl Error {
    pub fn report_to_stderr(&self) {
        use Error::*;
        match self {
            SpecError(se) => se.report_to_stderr(),
            UnexpectedObject { got, want, pos: _ } => {
                use nickel_lang_core::error::{report::report, Diagnostic};
                use nickel_lang_core::files::Files;
                let mut files = Files::new();

                let diagnostic = Diagnostic::error().with_message(format!(
                    "unexpected object: found {:?} when looking for {:?}",
                    got, want
                ));

                report(
                    &mut files,
                    diagnostic,
                    nickel_lang_core::error::report::ErrorFormat::Text,
                    nickel_lang_core::error::report::ColorOpt::Auto,
                );
            }
        }
    }
}

impl From<SpecError> for Error {
    fn from(e: SpecError) -> Self {
        Self::SpecError(e)
    }
}

/// A hash describing the object (specification hash), as well as everything it is dependent on.
///
/// This hash should change if any semantics change, but stay the same for anything immaterial (i.e, should
/// not change with comments, line numbers, locations in different files etc).
#[allow(dead_code)]
trait SpecHash {
    fn spec_hash(&self, _: &DepGraph) -> blake3::Hash;
}

mod spec_reader;
pub use spec_reader::{SpecError, SpecReader, SpecReaderOptions};

mod spec_schema;

pub mod dep_graph;
pub use dep_graph::{BuildOutput, BuildSpec, BuildSpecInput, DepGraph};

pub(crate) mod term_hasher;
