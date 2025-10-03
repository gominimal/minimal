//! The machinery for evaluating build specs.

#![allow(clippy::result_large_err)]

use nickel_lang_core::cache::TermCacheError;
use nickel_lang_core::error::Error as NclError;
use nickel_lang_core::files::Files;
use nickel_lang_core::identifier::LocIdent;
use nickel_lang_core::term::{RichTerm, Term};
use nickel_lang_core::typ::TypeF;
use nickel_lang_core::{error::NullReporter, eval::cache::CacheImpl, program::Program};
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

/// Errors that can occur while processing a nickel universe through a [SpecReader].
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum SpecError {
    IO(io::Error),
    Nickel(Files, NclError),
    AnnotationFailed(String),
}

impl SpecError {
    pub fn report_to_stderr(&self) {
        use SpecError::*;
        use nickel_lang_core::error::report::report;

        match self {
            IO(e) => eprintln!("IO Error: {}", e),
            AnnotationFailed(msg) => eprintln!("Annotation failed: {}", msg),
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

macro_rules! annotate_record {
    ($record:expr, $buildspec_id_ident:expr, $id:expr, $rt:expr, ($inner:expr, $files:expr, $minimal_lib_path:expr),) => {
        // Skip annotation for any part of the minimal library.
        if $inner
            .pos
            .src_id()
            .map(|file_id| {
                let file_path = $files.name(file_id);
                file_path
                    .to_str()
                    .map(|s| s.starts_with($minimal_lib_path))
                    .unwrap_or(false)
            })
            .unwrap_or(false)
        {
            return Ok($rt);
        } else {
            match $record {
                Term::RecRecord(mut record_data, includes, dyn_fields, deps) => {
                    if record_data.fields.get(&$buildspec_id_ident).is_some() {
                        return Ok($rt);
                    }
                    record_data.fields.insert(
                        LocIdent::new("__magic_buildspec_id"),
                        RichTerm::from(Term::ForeignId($id)).into(),
                    );
                    $id += 1;
                    Term::RecRecord(record_data, includes, dyn_fields, deps).into()
                }
                Term::Record(mut record_data) => {
                    if record_data.fields.get(&$buildspec_id_ident).is_some() {
                        return Ok($rt);
                    }
                    record_data.fields.insert(
                        LocIdent::new("__magic_buildspec_id"),
                        RichTerm::from(Term::ForeignId($id)).into(),
                    );
                    $id += 1;
                    Term::Record(record_data).into()
                }
                _ => unreachable!("record type was {:?}", $record),
            }
        }
    };
}

/// Evaluates a universe of nickel files which describe minimal build specifications.
pub struct SpecReader {
    p: Program<CacheImpl>,
    minimal_lib_path: PathBuf,
    last_id: u64,
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
        program
            .compile()
            .map_err(|e| SpecError::Nickel(program.files(), e))?;

        let mut out = Self {
            p: program,
            last_id: 0,
            minimal_lib_path: opts.minimal_lib_path.canonicalize()?,
        };
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
        program
            .compile()
            .map_err(|e| SpecError::Nickel(program.files(), e))?;

        let mut out = Self {
            p: program,
            last_id: 0,
            minimal_lib_path: opts.minimal_lib_path.canonicalize()?,
        };
        out.annotate()?;
        Ok(out)
    }

    /// Processes the build-spec universe with a top level using the named packages, given options and a path to a packages directory.
    pub fn new_with_pkgs<P: AsRef<Path>>(
        packages: &[String],
        pkg_dir: P,
        opts: &SpecReaderOptions,
    ) -> Result<Self, SpecError> {
        let mut src = String::with_capacity(2048);
        src.push_str("[\n");
        for name in packages {
            src.push_str(&format!(
                "  import \"{}/{}/build.ncl\",\n",
                pkg_dir.as_ref().to_str().unwrap(),
                name.as_str()
            ));
        }
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
        program
            .compile()
            .map_err(|e| SpecError::Nickel(program.files(), e))?;

        let mut out = Self {
            p: program,
            last_id: 0,
            minimal_lib_path: opts.minimal_lib_path.canonicalize()?,
        };
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
        program
            .compile()
            .map_err(|e| SpecError::Nickel(program.files(), e))?;

        let mut out = Self {
            p: program,
            last_id: 0,
            minimal_lib_path: opts.minimal_lib_path.canonicalize()?,
        };
        out.annotate()?;
        Ok(out)
    }

    /// Walks the AST to find unique build-spec declarations, annotating them with a unique ID.
    fn annotate(&mut self) -> Result<(), SpecError> {
        use nickel_lang_core::traverse::{Traverse as _, TraverseOrder};

        let files = self.p.files();
        let minimal_lib_path = self.minimal_lib_path.to_str().unwrap();

        let mut id: u64 = self.last_id;
        let buildspec_id_ident = LocIdent::new("__magic_buildspec_id");
        let mut traversal = |rt: RichTerm| -> Result<RichTerm, TermCacheError<()>> {
            // Explicit declaration: { ... } | BuildSpec
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
                    return Ok(Term::Annotated(
                        annotation.clone(),
                        annotate_record!(
                            inner.term.as_ref().clone(),
                            buildspec_id_ident,
                            id,
                            rt,
                            (inner, files, minimal_lib_path),
                        ),
                    )
                    .into());
                }
            }

            // Function-based declaration: build { ... }
            if let Term::App(func, arg) = rt.as_ref() {
                let is_build_decl = if let Term::Var(v) = func.as_ref() {
                    v.label() == "build"
                } else {
                    false
                };

                if is_build_decl {
                    return Ok(Term::App(
                        func.clone(),
                        annotate_record!(
                            arg.term.as_ref().clone(),
                            buildspec_id_ident,
                            id,
                            rt,
                            (arg, files, minimal_lib_path),
                        ),
                    )
                    .into());
                }
            }

            Ok(rt)
        };

        let result = self
            .p
            .custom_transform(0, |_cache, rt| {
                rt.traverse(&mut traversal, TraverseOrder::TopDown)
            })
            .map_err(|e| SpecError::AnnotationFailed(format!("{:?}", e)));
        self.last_id = id;
        result
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
    fn smoketest() {
        let sr = SpecReader::new(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in
                {
	        		toplevel = {
	        			name = \"smol ol buildspec\"
	        		} | BuildSpec
        		}"
            }
            .to_string(),
            &SpecReaderOptions::for_test(),
        );

        // So we can see the actual error when the test fails
        sr.as_ref().err().iter().for_each(|e| {
            e.report_to_stderr();
            panic!();
        });

        let sr = sr.unwrap();
        assert_eq!(sr.last_id, 1); // single increment for one build spec
    }

    #[test]
    fn anotates_build_fn() {
        let sr = SpecReader::new(
            indoc! {
                "
                let {build, ..} = import \"minimal.ncl\" in
                {
                    toplevel = build {
                        name = \"smol ol buildspec\",
                        inputs = [
                            build { name = \"swiggity swooty\" },
                        ],
                    }
                }"
            }
            .to_string(),
            &SpecReaderOptions::for_test(),
        );

        // So we can see the actual error when the test fails
        sr.as_ref().err().iter().for_each(|e| {
            e.report_to_stderr();
            panic!();
        });

        let sr = sr.unwrap();
        assert_eq!(sr.last_id, 2); // two build specs
    }
}
