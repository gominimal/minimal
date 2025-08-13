//! The machinery for evaluating build specs.

#![allow(clippy::result_large_err)]

use nickel_lang_core::error::Error as NclError;
use nickel_lang_core::files::Files;
use nickel_lang_core::term::RichTerm;
use nickel_lang_core::{error::NullReporter, eval::cache::CacheImpl, program::Program};
use std::io;
use std::path::PathBuf;

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum SpecError {
    IO(io::Error),
    Nickel(Files, NclError),
}

impl SpecError {
    pub fn report_to_stderr(&self) {
        use nickel_lang_core::error::report::report;
        use SpecError::*;

        match self {
            IO(e) => eprintln!("IO Error: {}", e),
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
    /// Processes the resulting build-spec universe, given options and source representing the top level.
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
        Ok(Self { p: program })
    }

    pub fn finish(self) -> Result<RichTerm, SpecError> {
        let Self { mut p, .. } = self;
        p.eval_full_for_export()
            .map_err(|e| SpecError::Nickel(p.files(), e))
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
