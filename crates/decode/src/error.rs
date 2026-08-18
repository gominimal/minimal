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
    /// Some packages which were requested were not found.
    PackagesNotFound { packages: Vec<String> },
    /// A newer version of the standard library is needed.
    StdlibOutdated {
        need_version: String,
        needed_by: String,
        current_version: String,
    },
    /// An attribute value was nested deeper than the supported limit.
    ///
    /// Construction is depth-capped at the trust boundary: unbounded nesting
    /// would otherwise abort the process with an uncatchable stack overflow
    /// during evaluation instead of surfacing a recoverable error.
    AttrTooDeep { max_depth: usize },
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
impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Self::Other(e.to_string())
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
            Error::PackagesNotFound { packages } => {
                write!(f, "packages not found: {}", packages.join(","))
            }
            Error::StdlibOutdated {
                need_version,
                needed_by,
                current_version,
            } => write!(
                f,
                "stdlib out of date: need={},got={},needed_by={}",
                need_version, current_version, needed_by
            ),
            Error::AttrTooDeep { max_depth } => write!(
                f,
                "attribute value nested too deeply: exceeds the maximum depth of {}",
                max_depth
            ),
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
            IO(e) => writeln!(writer, "IO Error: {}", e).unwrap(),
            Other(msg) => writeln!(writer, "Error: {}", msg).unwrap(),
            PackagesNotFound { packages } => {
                writeln!(writer, "Error: packages not found: {}", packages.join(",")).unwrap()
            }

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
            Error::StdlibOutdated {
                need_version,
                needed_by,
                current_version,
            } => {
                writeln!(
                    writer,
                    "Error: newer version of the standard library needed"
                )
                .unwrap();
                writeln!(writer).unwrap();
                writeln!(writer, "have: \"{}\"", current_version).unwrap();
                writeln!(writer, "needed: \"{}\"", need_version).unwrap();
                writeln!(writer, "needed by: {}", needed_by).unwrap();
                writeln!(writer).unwrap();
                writeln!(writer, "help: try updating your Minimal installation").unwrap();
            }
            Error::AttrTooDeep { max_depth } => writeln!(
                writer,
                "Error: attribute value nested too deeply (maximum depth is {})",
                max_depth
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

#[cfg(test)]
mod tests {
    use super::*;
    use codespan_reporting::term::termcolor::Buffer;

    fn capture(err: &Error) -> String {
        let mut buf = Buffer::no_color();
        err.report_to(&mut buf);
        String::from_utf8(buf.into_inner()).unwrap()
    }

    #[test]
    fn io_error_contains_prefix() {
        let e = Error::IO(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file missing",
        ));
        let out = capture(&e);
        assert!(
            out.contains("IO Error:"),
            "expected 'IO Error:' in: {out:?}"
        );
        assert!(out.contains("file missing"), "expected message in: {out:?}");
    }

    #[test]
    fn other_error_contains_message() {
        let e = Error::Other("something went wrong".into());
        let out = capture(&e);
        assert!(out.contains("Error:"), "expected 'Error:' in: {out:?}");
        assert!(
            out.contains("something went wrong"),
            "expected message in: {out:?}"
        );
    }

    #[test]
    fn packages_not_found_lists_package_names() {
        let e = Error::PackagesNotFound {
            packages: vec!["foo".into(), "bar".into()],
        };
        let out = capture(&e);
        assert!(
            out.contains("packages not found"),
            "expected phrase in: {out:?}"
        );
        assert!(out.contains("foo"), "expected 'foo' in: {out:?}");
        assert!(out.contains("bar"), "expected 'bar' in: {out:?}");
    }

    #[test]
    fn stdlib_outdated_contains_versions() {
        let e = Error::StdlibOutdated {
            need_version: "2.0.0".into(),
            needed_by: "some-pkg".into(),
            current_version: "1.0.0".into(),
        };
        let out = capture(&e);
        assert!(
            out.contains("newer version of the standard library needed"),
            "expected headline in: {out:?}"
        );
        assert!(out.contains("2.0.0"), "expected needed version in: {out:?}");
        assert!(
            out.contains("1.0.0"),
            "expected current version in: {out:?}"
        );
        assert!(out.contains("some-pkg"), "expected needed_by in: {out:?}");
    }

    #[test]
    fn missing_ty_contains_error_message() {
        let e = Error::MissingTy(Files::default(), TermPos::None);
        let out = capture(&e);
        assert!(
            out.contains("record was not given a type"),
            "expected message in: {out:?}"
        );
    }

    #[test]
    fn missing_field_contains_field_name() {
        let e = Error::MissingField {
            files: Files::default(),
            obj: ObjTy::Builder,
            pos: TermPos::None,
            field: "my_field",
        };
        let out = capture(&e);
        assert!(out.contains("my_field"), "expected field name in: {out:?}");
    }

    #[test]
    fn missing_id_contains_error_message() {
        let e = Error::MissingID(Files::default(), TermPos::None);
        let out = capture(&e);
        assert!(
            out.contains("record was not declared a build spec"),
            "expected message in: {out:?}"
        );
    }

    #[test]
    fn unexpected_object_contains_type_names() {
        let e = Error::UnexpectedObject {
            files: Files::default(),
            got: ObjTy::Source,
            want: ObjTy::Builder,
            pos: TermPos::None,
        };
        let out = capture(&e);
        assert!(
            out.contains("unexpected record"),
            "expected 'unexpected record' in: {out:?}"
        );
        assert!(out.contains("Source"), "expected 'Source' in: {out:?}");
        assert!(out.contains("Builder"), "expected 'Builder' in: {out:?}");
    }

    #[test]
    fn no_such_output_contains_output_name() {
        let e = Error::NoSuchOutput {
            files: Files::default(),
            pos: TermPos::None,
            output: "my_output".into(),
        };
        let out = capture(&e);
        assert!(
            out.contains("my_output"),
            "expected output name in: {out:?}"
        );
        assert!(
            out.contains("no such output"),
            "expected 'no such output' in: {out:?}"
        );
    }

    #[test]
    fn invalid_target_contains_target_string() {
        let e = Error::InvalidTarget {
            files: Files::default(),
            pos: TermPos::None,
            got: "bad-target".into(),
        };
        let out = capture(&e);
        assert!(
            out.contains("bad-target"),
            "expected target string in: {out:?}"
        );
        assert!(
            out.contains("not a valid target"),
            "expected 'not a valid target' in: {out:?}"
        );
    }

    #[test]
    fn nickel_error_renders_diagnostic() {
        // A Nickel contract violation loaded through the decoder surfaces as
        // `Error::Nickel`. `report_to` must render its underlying Nickel
        // diagnostic to the writer rather than emitting nothing.
        let err = crate::Layer::new_for_test(
            "let {Attrs, ..} = import \"minimal.ncl\" in {unknown_attr = \"a\"} | Attrs"
                .to_string(),
        )
        .expect_err("a contract violation should fail to load");
        assert!(
            matches!(err, Error::Nickel(_)),
            "expected Error::Nickel, got {err:?}"
        );

        let out = capture(&err);
        assert!(
            !out.is_empty(),
            "expected a rendered diagnostic, got empty output"
        );
        assert!(
            out.contains("error"),
            "expected an error diagnostic in: {out:?}"
        );
    }

    /// Every variant test above passes `TermPos::None`, so they exercise only
    /// the unlabeled branch of `report_to`. When a variant instead carries a
    /// real source position, `report_to` must attach a primary label and render
    /// the offending source span — the user-facing "point at the code" output.
    ///
    /// Loading a bare record with no type annotation surfaces `Error::MissingTy`
    /// carrying the record's real span, so its report must include both the
    /// diagnostic message and the offending source rendered under the label.
    #[test]
    fn report_renders_source_span_for_positioned_error() {
        let err = crate::Layer::new_for_test("{ foo = 1 }".to_string())
            .expect_err("a record without a type annotation should fail to decode");
        let Error::MissingTy(_, pos) = &err else {
            panic!("expected Error::MissingTy, got {err:?}");
        };
        assert!(
            pos.into_opt().is_some(),
            "expected a real source position so the primary-label branch runs, got {pos:?}"
        );

        let out = capture(&err);
        assert!(
            out.contains("record was not given a type"),
            "expected the diagnostic message in: {out:?}"
        );
        assert!(
            out.contains("foo"),
            "expected the offending source rendered under the label in: {out:?}"
        );
    }
}
