//! The machinery for evaluating build specs.

#![allow(clippy::result_large_err)]

use nickel_lang_core::cache::CacheError;
use nickel_lang_core::error::Error as NclError;
use nickel_lang_core::files::Files;
use nickel_lang_core::identifier::LocIdent;
use nickel_lang_core::term::{RichTerm, Term};
use nickel_lang_core::typ::TypeF;
use nickel_lang_core::{error::NullReporter, eval::cache::CacheImpl, program::Program};
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum SpecError {
    IO(io::Error),
    Nickel(Files, NclError),
    AnnotationFailed,
}

impl SpecError {
    pub fn report_to_stderr(&self) {
        use nickel_lang_core::error::report::report;
        use SpecError::*;

        match self {
            IO(e) => eprintln!("IO Error: {}", e),
            AnnotationFailed => eprintln!("Annotation failed"),
            Nickel(files, e) => {
                let mut files = files.clone();
                report(
                    &mut files,
                    e.clone(),
                    nickel_lang_core::error::report::ErrorFormat::Text,
                    nickel_lang_core::error::report::ColorOpt::Auto,
                );
            }
        }
    }
}

impl From<io::Error> for SpecError {
    fn from(e: io::Error) -> Self {
        Self::IO(e)
    }
}

/// Configuration for where to find nickel files.
///
/// Use `SpecReaderOptions::for_test()` in tests.
pub struct SpecReaderOptions {
    /// Where on the filesystem the minimal base library (i.e. minimal.ncl) is located.
    pub minimal_lib_path: PathBuf,
}

#[cfg(test)]
impl SpecReaderOptions {
    pub fn for_test() -> Self {
        Self {
            minimal_lib_path: std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                .join("minimal-ncl"),
        }
    }
}

/// Evaluates a universe of nickel files which describe minimal build specifications.
pub struct SpecReader {
    p: Program<CacheImpl>,
}

impl SpecReader {
    /// Processes the resulting build-spec universe, given options and literal source representing the top level.
    pub fn new<S: Into<String>>(src: S, opts: &SpecReaderOptions) -> Result<Self, SpecError> {
        let mut program = Program::new_from_source(
            io::Cursor::new(src.into()),
            "toplevel",
            std::io::stderr(),
            NullReporter {},
        )?;
        program.add_import_paths([&opts.minimal_lib_path].iter());

        program
            .typecheck(nickel_lang_core::typecheck::TypecheckMode::Walk)
            .map_err(|e| SpecError::Nickel(program.files(), e))?;

        let mut out = Self { p: program };
        out.annotate()?;
        Ok(out)
    }

    /// Processes the resulting build-spec universe, given options and a path to a packages directory.
    pub fn new_with_all_pkgs<P: AsRef<Path>>(
        pkg_dir: P,
        opts: &SpecReaderOptions,
    ) -> Result<Self, SpecError> {
        let mut src = String::with_capacity(2048);
        src.push_str("[\n");

        fn visit_dirs(src: &mut String, dir: &Path) -> Result<(), SpecError> {
            if dir.is_dir() {
                for entry in std::fs::read_dir(dir)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_dir() {
                        visit_dirs(src, &path)?;
                    } else if entry.file_name().to_string_lossy().ends_with("build.ncl") {
                        src.push_str("  import \"");
                        src.push_str(path.to_str().unwrap());
                        src.push_str("\",\n");
                    }
                }
            }
            Ok(())
        }
        visit_dirs(&mut src, pkg_dir.as_ref())?;
        src.push(']');

        let mut program = Program::new_from_source(
            io::Cursor::new(src),
            "toplevel",
            std::io::stderr(),
            NullReporter {},
        )?;
        program.add_import_paths([&opts.minimal_lib_path].iter());

        program
            .typecheck(nickel_lang_core::typecheck::TypecheckMode::Walk)
            .map_err(|e| SpecError::Nickel(program.files(), e))?;

        let mut out = Self { p: program };
        out.annotate()?;
        Ok(out)
    }

    /// Processes the resulting build-spec universe, given options and a path to source representing the top level.
    pub fn new_with_path<P: Into<OsString>>(
        src: P,
        opts: &SpecReaderOptions,
    ) -> Result<Self, SpecError> {
        let mut program = Program::new_from_file(src, std::io::stderr(), NullReporter {})?;
        program.add_import_paths([&opts.minimal_lib_path].iter());

        program
            .typecheck(nickel_lang_core::typecheck::TypecheckMode::Walk)
            .map_err(|e| SpecError::Nickel(program.files(), e))?;

        let mut out = Self { p: program };
        out.annotate()?;
        Ok(out)
    }

    /// Walks the AST to find unique build-spec declarations, annotating them with a unique ID.
    fn annotate(&mut self) -> Result<(), SpecError> {
        use nickel_lang_core::traverse::{Traverse as _, TraverseOrder};

        let mut id: u64 = 0;
        let mut traversal = |rt: RichTerm| -> Result<RichTerm, CacheError<()>> {
            if let Term::Annotated(annotation, inner) = rt.as_ref() {
                let is_buildspec = annotation.contracts.iter().any(|lt| {
                    if let TypeF::Contract(c) = &lt.typ.typ {
                        if let Term::Var(v) = c.as_ref() {
                            v.label() == "BuildSpec"
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                });

                if is_buildspec {
                    let new_inner = match inner.term.as_ref().clone() {
                        Term::RecRecord(mut record_data, includes, dyn_fields, deps) => {
                            if record_data
                                .fields
                                .get(&LocIdent::new("__magic_buildspec_id"))
                                .is_none()
                            {
                                record_data.fields.insert(
                                    LocIdent::new("__magic_buildspec_id"),
                                    RichTerm::from(Term::ForeignId(id)).into(),
                                );
                                id += 1;
                            }
                            Term::RecRecord(record_data, includes, dyn_fields, deps).into()
                        }
                        Term::Record(mut record_data) => {
                            if record_data
                                .fields
                                .get(&LocIdent::new("__magic_buildspec_id"))
                                .is_none()
                            {
                                record_data.fields.insert(
                                    LocIdent::new("__magic_buildspec_id"),
                                    RichTerm::from(Term::ForeignId(id)).into(),
                                );
                                id += 1;
                            }
                            Term::Record(record_data).into()
                        }
                        _ => unreachable!(),
                    };
                    return Ok(Term::Annotated(annotation.clone(), new_inner).into());
                }
            }

            Ok(rt)
        };

        self.p
            .custom_transform(|_cache, rt| rt.traverse(&mut traversal, TraverseOrder::TopDown))
            .map_err(|_| SpecError::AnnotationFailed)
    }

    pub fn finish(self) -> Result<(RichTerm, Program<CacheImpl>), SpecError> {
        let Self { mut p, .. } = self;
        let root_term = p
            .eval_record_spine()
            .map_err(|e| SpecError::Nickel(p.files(), e))?;

        Ok((root_term, p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    #[test]
    fn load_and_typecheck() {
        let _sr = SpecReader::new("{}".to_string(), &SpecReaderOptions::for_test()).unwrap();
    }

    #[test]
    fn simple() {
        let err = SpecReader::new(
            indoc! {
                "
                let {BuildSpec} = import \"minimal.ncl\" in
                {
	        		toplevel = {
	        			name = \"smol ol buildspec\"
	        		} | BuildSpec
        		}"
            }
            .to_string(),
            &SpecReaderOptions::for_test(),
        )
        .err();

        // So we can see the actual error when the test fails
        err.iter().for_each(|e| e.report_to_stderr());

        assert!(err.is_none(), "got err = {:?}, want None", err);
    }
}
