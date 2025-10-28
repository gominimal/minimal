//! Error types for the decode crate.

use crate::ObjTy;
use nickel_lang_core::error::Error as NclError;
use nickel_lang_core::files::Files;
use nickel_lang_core::position::TermPos;
use std::fmt;

/// Errors that can occur when decoding nickel layers.
#[derive(Debug)]
pub enum Error {
    /// An I/O error occurred.
    IO(std::io::Error),
    /// An error parsing, typechecking, or evaluating Nickel.
    Nickel(Box<(Files, NclError)>),
    /// A generic error with a custom message.
    Other(String),

    /// An object which was expected to have a type hint but it was not found.
    ///
    /// A field named `ty` is set from application of a type from the minimal-ncl library.
    MissingTy(Files, TermPos),
    /// An object was missing a field that was required.
    MissingField {
        files: Files,
        obj: ObjTy,
        pos: TermPos,
        field: &'static str,
    },
    /// An object was used in a context where it is not valid.
    UnexpectedObject {
        files: Files,
        got: ObjTy,
        want: ObjTy,
        pos: TermPos,
    },
    /// An object which was expected to be a build-spec was missing annotation
    /// with a unique ID (see [crate::load::Loader]).
    MissingID(Files, TermPos),
    /// The output of a build-spec was referenced, but no such output exists.
    NoSuchOutput {
        files: Files,
        pos: TermPos,
        output: String,
    },
    /// A target string was expected, but the given string was invalid.
    InvalidTarget {
        files: Files,
        pos: TermPos,
        got: String,
    },
}

impl Error {
    /// Creates a new error with a custom message.
    pub fn other<S: Into<String>>(msg: S) -> Self {
        Error::Other(msg.into())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::IO(e) => write!(f, "I/O error: {}", e),
            Error::Nickel(boxed) => write!(f, "nickel: {:?}", boxed.1),
            Error::Other(e) => write!(f, "other: {}", e),
            Error::MissingTy(_files, at) => write!(f, "missing ty: object defined at {:?}", at),
            Error::MissingField {
                obj, pos, field, ..
            } => write!(
                f,
                "missing field {} on object {:?} defined at {:?}",
                field, obj, pos
            ),
            Error::MissingID(_files, pos) => {
                write!(f, "missing build-spec ID on object defined at {:?}", pos)
            }
            Error::UnexpectedObject { got, want, pos, .. } => write!(
                f,
                "unexpected object at {:?}: saw object of type {:?}, expected {:?}",
                pos, got, want
            ),
            Error::NoSuchOutput { pos, output, .. } => {
                write!(f, "no such output {}: defined at {:?}", output, pos)
            }
            Error::InvalidTarget { pos, got, .. } => {
                write!(f, "invalid target string {}: defined at {:?}", got, pos)
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IO(e) => Some(e),
            _ => None,
        }
    }
}

impl Error {
    /// Writes a human-friendly error to the given terminal.
    pub fn report_to(&self, writer: &mut dyn codespan_reporting::term::termcolor::WriteColor) {
        use Error::*;
        use nickel_lang_core::error::{Diagnostic, Label, report::report_with};
        use nickel_lang_core::files::FileId;
        use nickel_lang_core::position::RawSpan;

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
            IO(e) => write!(writer, "IO Error: {}", e).unwrap(),
            Other(msg) => write!(writer, "Error: {}", msg).unwrap(),

            Nickel(boxed) => {
                let mut files = boxed.0.clone();
                report_with(
                    writer,
                    &mut files,
                    boxed.1.clone(),
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
            Error::InvalidTarget { files, pos, got } => {
                let mut files = files.clone();
                let diagnostic =
                    Diagnostic::error().with_message(format!("'{}' is not a valid target", got));
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
