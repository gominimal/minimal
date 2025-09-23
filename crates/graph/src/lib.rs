use crate::spec_schema::ObjTy;
use nickel_lang_core::files::Files;
use nickel_lang_core::position::TermPos;

use common::SpecHash;

/// An error during construction or processing of the dependency graph.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Error {
    /// An error occurred during nickel processing or evaluation.
    SpecError(SpecError),
    /// An object was used in a context where it is not valid.
    UnexpectedObject {
        files: Files,
        got: ObjTy,
        want: ObjTy,
        pos: TermPos,
    },
    /// An object was missing a field that was required.
    MissingField {
        files: Files,
        obj: ObjTy,
        pos: TermPos,
        field: &'static str,
    },
    /// An object which was expected to be a build-spec was missing annotation
    /// with a unique ID (see [SpecReader]).
    MissingID(Files, TermPos),
    /// An object which was expected to have a type hint but it was not found.
    ///
    /// A field named `ty` is set from application of a type from the minimal-ncl library.
    MissingTy(Files, TermPos),
    /// The output of a build-spec was referenced, but no such output exists.
    NoSuchOutput {
        files: Files,
        pos: TermPos,
        output: String,
    },
}

impl Error {
    /// Writes a human-friendly error to the given terminal.
    pub fn report_to(&self, writer: &mut dyn codespan_reporting::term::termcolor::WriteColor) {
        use nickel_lang_core::error::{report::report_with, Diagnostic, Label};
        use nickel_lang_core::files::FileId;
        use nickel_lang_core::position::RawSpan;
        use Error::*;

        /// Create a primary label from a span.
        fn primary(span: &RawSpan) -> Label<FileId> {
            Label::primary(span.src_id, span.start.to_usize()..span.end.to_usize())
        }

        /// Create a secondary label from a span.
        #[allow(dead_code)]
        fn secondary(span: &RawSpan) -> Label<FileId> {
            Label::secondary(span.src_id, span.start.to_usize()..span.end.to_usize())
        }

        match self {
            SpecError(se) => se.report_to_stderr(),
            UnexpectedObject {
                files,
                got,
                want,
                pos,
            } => {
                let mut files = files.clone();
                let diagnostic = Diagnostic::error().with_message(format!(
                    "unexpected record: found {:?} when looking for {:?}",
                    got, want
                ));
                let diagnostic = if let Some(pos) = pos.into_opt() {
                    diagnostic
                        .with_label(primary(&pos))
                        .with_message("at this record")
                } else {
                    diagnostic
                };

                report_with(
                    writer,
                    &mut files,
                    diagnostic,
                    nickel_lang_core::error::report::ErrorFormat::Text,
                );
            }
            MissingID(files, pos) => {
                let mut files = files.clone();
                let diagnostic =
                    Diagnostic::error().with_message("record was not declared a build spec");
                let diagnostic = if let Some(pos) = pos.into_opt() {
                    diagnostic.with_label(primary(&pos))
                } else {
                    diagnostic
                };

                report_with(
                    writer,
                    &mut files,
                    diagnostic,
                    nickel_lang_core::error::report::ErrorFormat::Text,
                );
            }
            MissingTy(files, pos) => {
                let mut files = files.clone();
                let diagnostic = Diagnostic::error().with_message("record was not given a type");
                let diagnostic = if let Some(pos) = pos.into_opt() {
                    diagnostic.with_label(primary(&pos))
                } else {
                    diagnostic
                };
                let diagnostic = diagnostic.with_note("Perhaps you meant to apply ('|' operator) a type such as BuildSpec, OutputLib, Source, etc etc");

                report_with(
                    writer,
                    &mut files,
                    diagnostic,
                    nickel_lang_core::error::report::ErrorFormat::Text,
                );
            }
            Error::MissingField {
                files,
                obj,
                pos,
                field,
            } => {
                let mut files = files.clone();
                let diagnostic = Diagnostic::error().with_message(format!(
                    "missing field {} for record of type {:?}",
                    field, obj
                ));
                let diagnostic = if let Some(pos) = pos.into_opt() {
                    diagnostic.with_label(primary(&pos))
                } else {
                    diagnostic
                };

                report_with(
                    writer,
                    &mut files,
                    diagnostic,
                    nickel_lang_core::error::report::ErrorFormat::Text,
                );
            }
            Error::NoSuchOutput { files, pos, output } => {
                let mut files = files.clone();
                let diagnostic = Diagnostic::error()
                    .with_message(format!("no such output '{}' on parent build spec", output));
                let diagnostic = if let Some(pos) = pos.into_opt() {
                    diagnostic.with_label(primary(&pos))
                } else {
                    diagnostic
                };

                report_with(
                    writer,
                    &mut files,
                    diagnostic,
                    nickel_lang_core::error::report::ErrorFormat::Text,
                );
            }
        }
    }

    /// Writes a human-friendly representation of the error to standard out.
    pub fn report_to_stderr(&self) {
        use codespan_reporting::term::termcolor::{ColorChoice, StandardStream};
        self.report_to(&mut StandardStream::stderr(ColorChoice::Auto).lock());
    }
}

impl From<SpecError> for Error {
    fn from(e: SpecError) -> Self {
        Self::SpecError(e)
    }
}

mod spec_hasher;
pub use spec_hasher::SpecHasher;

mod spec_reader;
pub use spec_reader::{SpecError, SpecReader, SpecReaderOptions};

mod spec_schema;

pub mod dep_graph;
pub use dep_graph::{
    BuildOutput, BuildSpec, BuildSpecInput, BuildSpecRef, DepGraph, RuntimeDep, SourceInput,
    SubsetInput,
};

mod planner;
pub use planner::{BinProvider, ExecPlan};

mod transitives;
pub use transitives::Transitives;
