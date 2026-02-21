//! First phase of evaluating a layer of build specs - parsing and annotation.

#![allow(clippy::result_large_err)]

use crate::Error;
use common::{SpecOrigin, Target};

use nickel_lang_core::cache::TermCacheError;
use nickel_lang_core::identifier::LocIdent;
use nickel_lang_core::term::{RichTerm, Term};
use nickel_lang_core::typ::TypeF;
use nickel_lang_core::{error::NullReporter, eval::cache::CacheImpl, program::Program};
use std::io;
use std::path::{Path, PathBuf};

/// Configuration for loading a layer (of Nickel files).
///
/// Use `LoadOptions::for_test()` in tests.
pub struct LoadOptions {
    /// Where on the filesystem the minimal base library (i.e. minimal.ncl) is located.
    pub minimal_lib_path: PathBuf,
    /// A description of where the top-level layer/repo was sourced from.
    pub from: SpecOrigin,
    /// The target we are loading for.
    pub target: Target,
}

impl LoadOptions {
    pub fn for_test() -> Self {
        Self {
            from: SpecOrigin::Inline,
            minimal_lib_path: std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                .join("minimal-ncl"),
            target: Target::default(),
        }
    }

    pub fn for_target(&self) -> &Target {
        &self.target
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
                    .map(|s| {
                        s.starts_with($minimal_lib_path)
                            || if let Ok(md) = std::env::var("CARGO_MANIFEST_DIR") {
                                (s.contains("minimal-ncl/")
                                    && s.contains("crates")
                                    && s.starts_with(&md))
                            } else {
                                false
                            }
                    })
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

fn build_decls_in_dir<P: AsRef<Path>>(
    dir: P,
    with_names: Option<&[String]>,
) -> Result<Vec<PathBuf>, Error> {
    let mut out = if let Some(names) = &with_names {
        Vec::with_capacity(names.len())
    } else {
        Vec::with_capacity(128)
    };

    if dir.as_ref().exists() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let meta = entry.metadata()?;
            let path = entry.path();
            if meta.is_dir() {
                let build_path = path.join("build.ncl");
                if build_path.exists() {
                    match with_names {
                        Some(names) => {
                            if names.iter().any(|n| path.ends_with(n)) {
                                out.push(build_path);
                            }
                        }
                        None => {
                            out.push(build_path);
                        }
                    };
                }
            }
        }
    }

    // Detect if any requested package was missing.
    if let Some(names) = &with_names
        && names.len() > out.len()
    {
        return Err(Error::PackagesNotFound {
            packages: names
                .iter()
                .filter(|n| out.iter().any(|p| p.ends_with(format!("{}/build.ncl", n))))
                .cloned()
                .collect(),
        });
    }

    Ok(out)
}

/// Evaluates a single layer of nickel files which describe minimal build specifications.
pub(crate) struct Loader {
    p: Program<CacheImpl>,
    from: SpecOrigin,
    minimal_lib_path: PathBuf,
    last_id: u64,

    #[allow(dead_code)]
    generated_lib_dir: tempfile::TempDir,
}

impl Loader {
    /// Processes literal source representing a top-level collection of objects.
    pub fn new<S: Into<String>>(src: S, opts: &LoadOptions) -> Result<Self, Error> {
        let generated_lib_dir = tempfile::TempDir::new()?;
        std::fs::write(generated_lib_dir.path().join("__injected_config__.ncl"), {
            let mut out = Vec::with_capacity(128);
            out.extend(b"{target = {os = ");
            out.extend(opts.for_target().os().as_nickel_literal());
            out.extend(b",arch = ");
            out.extend(opts.for_target().arch().as_nickel_literal());
            out.extend(b"}}");
            out
        })?;

        let mut program = Program::new_from_sources(
            [(io::Cursor::new(src.into()), "toplevel")],
            std::io::stderr(),
            NullReporter {},
        )?;

        program.add_import_paths([&opts.minimal_lib_path, generated_lib_dir.path()].iter());

        program
            .typecheck(nickel_lang_core::typecheck::TypecheckMode::Walk)
            .map_err(|e| Error::Nickel(Box::new((program.files(), e))))?;
        program
            .compile()
            .map_err(|e| Error::Nickel(Box::new((program.files(), e))))?;

        let mut out = Self {
            p: program,
            from: opts.from.clone(),
            last_id: 0,
            minimal_lib_path: opts.minimal_lib_path.canonicalize()?,
            generated_lib_dir,
        };
        out.annotate()?;
        Ok(out)
    }

    /// Loads all build decls in the given directory following the standard directory layout.
    pub fn new_with_all_pkgs<P: AsRef<Path>>(
        layer_dir: P,
        opts: &LoadOptions,
    ) -> Result<Self, Error> {
        let mut src = String::with_capacity(2048);
        src.push_str("let {layer, ..} = import \"minimal.ncl\" in\n");
        src.push_str("layer {\n");
        src.push_str("\tbuilds = [\n");
        for pb in build_decls_in_dir(layer_dir.as_ref().join("packages"), None)?.into_iter() {
            src.push_str("\t\timport \"");
            src.push_str(pb.to_str().unwrap());
            src.push_str("\",\n");
        }
        src.push_str("\t],\n");

        match std::fs::read_dir(layer_dir.as_ref().join("profiles")) {
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(e.into());
                }
            }
            Ok(d) => {
                src.push_str("\tprofiles = [\n");
                for e in d {
                    let e = e?;
                    if e.file_type()?.is_dir() {
                        src.push_str("  import \"");
                        src.push_str(e.path().to_str().unwrap());
                        src.push_str("/profile.ncl\",\n");
                    }
                }
                src.push_str("\t],\n");
            }
        }
        match std::fs::read_dir(layer_dir.as_ref().join("harnesses")) {
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(e.into());
                }
            }
            Ok(d) => {
                src.push_str("\tharnesses = [\n");
                for e in d {
                    let e = e?;
                    if e.file_type()?.is_dir() {
                        src.push_str("  import \"");
                        src.push_str(e.path().to_str().unwrap());
                        src.push_str("/harness.ncl\",\n");
                    }
                }
                src.push_str("\t],\n");
            }
        }

        src.push('}');

        Self::new(src, opts)
    }

    /// Walks the AST to find unique build-spec declarations, annotating them with a unique ID.
    fn annotate(&mut self) -> Result<(), Error> {
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
            .custom_transform(1, |_cache, rt| {
                rt.traverse(&mut traversal, TraverseOrder::TopDown)
            })
            .map_err(|e| Error::Other(format!("annotation: {:?}", e)));
        self.last_id = id;
        result
    }

    /// Destroys the loader, returning the outputs of processing (the nickel tree, where it came from).
    pub fn finish(self) -> Result<(RichTerm, Program<CacheImpl>, SpecOrigin), Error> {
        let Self { mut p, from, .. } = self;
        let root_term = p
            .eval_record_spine()
            .map_err(|e| Error::Nickel(Box::new((p.files(), e))))?;

        Ok((root_term, p, from))
    }
}

#[cfg(test)]
mod tests {
    use crate::eval_if_closure;

    use super::*;
    use indoc::indoc;

    #[test]
    fn build_decls_in_dir_simple() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Create multiple package directories
        for pkg_name in &["package-a", "package-b", "package-c"] {
            let pkg_dir = temp_dir.path().join(pkg_name);
            std::fs::create_dir(&pkg_dir).unwrap();
            std::fs::write(pkg_dir.join("build.ncl"), "test content").unwrap();
        }

        let result = build_decls_in_dir(temp_dir.path(), None).unwrap();

        assert_eq!(result.len(), 3);
        assert!(result.iter().any(|p| p.ends_with("package-a/build.ncl")));
        assert!(result.iter().any(|p| p.ends_with("package-b/build.ncl")));
        assert!(result.iter().any(|p| p.ends_with("package-c/build.ncl")));
    }

    #[test]
    fn build_decls_in_dir_ignores_non_other_files() {
        let temp_dir = tempfile::tempdir().unwrap();
        let pkg_dir = temp_dir.path().join("test-package");
        std::fs::create_dir(&pkg_dir).unwrap();

        // Create build.ncl and other files
        std::fs::write(pkg_dir.join("build.ncl"), "test content").unwrap();
        std::fs::write(pkg_dir.join("build.sh"), "#!/bin/bash").unwrap();
        std::fs::write(pkg_dir.join("readme.md"), "# README").unwrap();
        std::fs::write(pkg_dir.join("other.ncl"), "other nickel file").unwrap();

        let result = build_decls_in_dir(temp_dir.path(), None).unwrap();

        assert_eq!(result.len(), 1);
        assert!(result[0].ends_with("build.ncl"));
    }

    #[test]
    fn build_decls_in_dir_filtered() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Create multiple packages
        for pkg_name in &["package-a", "package-b", "package-c"] {
            let pkg_dir = temp_dir.path().join(pkg_name);
            std::fs::create_dir(&pkg_dir).unwrap();
            std::fs::write(pkg_dir.join("build.ncl"), "test content").unwrap();
        }

        let result = build_decls_in_dir(temp_dir.path(), Some(&["package-b".to_string()])).unwrap();

        assert_eq!(result.len(), 1);
        assert!(result[0].ends_with("package-b/build.ncl"));
    }

    #[test]
    fn loader_empty() {
        let _sr = Loader::new("{}".to_string(), &LoadOptions::for_test()).unwrap();
    }

    #[test]
    fn loader_injects_config() {
        let _sr = Loader::new(
            "{c = import \"__injected_config__.ncl\"}".to_string(),
            &LoadOptions::for_test(),
        )
        .unwrap();
    }

    #[test]
    fn loader_smoketest() {
        let sr = Loader::new(
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
            &LoadOptions::for_test(),
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
    fn loader_annotates_build_fn() {
        let sr = Loader::new(
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
            &LoadOptions::for_test(),
        );

        // So we can see the actual error when the test fails
        sr.as_ref().err().iter().for_each(|e| {
            e.report_to_stderr();
            panic!();
        });

        let sr = sr.unwrap();
        assert_eq!(sr.last_id, 2); // two build specs
    }

    #[test]
    fn loader_new_with_all_pkgs() {
        let temp_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp_dir.path().join("packages")).unwrap();
        std::fs::create_dir(temp_dir.path().join("profiles")).unwrap();
        std::fs::create_dir(temp_dir.path().join("harnesses")).unwrap();

        // Create multiple packages
        for pkg_name in &["package-a", "package-b", "package-c"] {
            let pkg_dir = temp_dir.path().join("packages").join(pkg_name);
            std::fs::create_dir(&pkg_dir).unwrap();
            std::fs::write(
                pkg_dir.join("build.ncl"),
                indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in
                {
	        		name = \"NAMEE\"
	        	} | BuildSpec
				"
                }
                .to_string()
                .replace("NAMEE", pkg_name),
            )
            .unwrap();
        }

        // Make a profile called rust
        let profile_dir = temp_dir.path().join("profiles").join("rust");
        std::fs::create_dir(&profile_dir).unwrap();
        std::fs::write(
            profile_dir.join("profile.ncl"),
            indoc! {
            "
            let {profile, ..} = import \"minimal.ncl\" in
            profile {
        		name = \"rust\"
        	}
			"
            },
        )
        .unwrap();
        // Make a harness called rust
        let harness_dir = temp_dir.path().join("harnesses").join("rust");
        std::fs::create_dir(&harness_dir).unwrap();
        std::fs::write(
            harness_dir.join("harness.ncl"),
            indoc! {
            "
            let {harness, ..} = import \"minimal.ncl\" in
            harness {
        		name = \"rust\"
        	}
			"
            },
        )
        .unwrap();

        let sr = Loader::new_with_all_pkgs(temp_dir.path(), &LoadOptions::for_test());
        // So we can see the actual error when the test fails
        sr.as_ref().err().iter().for_each(|e| {
            e.report_to_stderr();
            panic!();
        });

        let mut sr = sr.unwrap();
        assert_eq!(sr.last_id, 3); // three build specs

        if let Term::Record(rd) = sr.p.eval().unwrap().as_ref() {
            // Check a field 'profiles' was an array with one object
            assert!(matches!(
                eval_if_closure(
                    &rd.get_value_with_ctrs(&LocIdent::new("profiles"))
                        .unwrap()
                        .unwrap(),
                    &mut sr.p,
                )
                .unwrap()
                .as_ref(),
                Term::Array(a, _attrs) if a.len() == 1,
            ));

            // Check a field 'harnesses' was an array with one object
            assert!(matches!(
                eval_if_closure(
                    &rd.get_value_with_ctrs(&LocIdent::new("harnesses"))
                        .unwrap()
                        .unwrap(),
                    &mut sr.p,
                )
                .unwrap()
                .as_ref(),
                Term::Array(a, _attrs) if a.len() == 1,
            ));
        }
    }
}
