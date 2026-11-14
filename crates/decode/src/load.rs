//! First phase of evaluating a layer of build specs - parsing and annotation.

#![allow(clippy::result_large_err)]

use crate::Error;
use common::{SpecOrigin, Target};

use nickel_lang_core::cache::{TermCacheError, normalize_abs_path, normalize_path};
use nickel_lang_core::eval::value::{NickelValue, RecordData};
use nickel_lang_core::files::Files;
use nickel_lang_core::identifier::{Ident, LocIdent};
use nickel_lang_core::program::BuilderError;
use nickel_lang_core::term::Term;
use nickel_lang_core::typ::TypeF;
use nickel_lang_core::{
    error::NullReporter,
    eval::cache::CacheImpl,
    program::{Program, ProgramBuilder},
};
use regex::Regex;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::OsStr;
use std::hash::Hash;
use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;

/// Configuration for loading a layer (of Nickel files).
///
/// Use `LoadOptions::for_test()` in tests.
#[derive(Debug)]
pub struct LoadOptions {
    /// Where on the filesystem the minimal base library (i.e. minimal.ncl) is located.
    pub minimal_lib_path: PathBuf,
    /// A description of where the layer/repo was sourced from.
    pub from: SpecOrigin,
    /// The target we are loading for.
    pub target: Target,
    /// The parameters being passed to the layer during evaluation.
    pub params: Option<HashMap<String, args::DiskArg>>,
    /// When set, the canonical root of the layer: every file the program
    /// loads must lie under it or under the minimal library, or loading fails
    /// with [Error::ImportOutside]. Loading a layer from its directory sets
    /// it to that directory. It does not take part in
    /// [LoadOptions::input_hash].
    pub confine_to: Option<PathBuf>,
}

impl LoadOptions {
    pub fn for_test() -> Self {
        Self {
            from: SpecOrigin::Inline,
            minimal_lib_path: std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                .join("minimal-ncl"),
            target: Target::default(),
            params: None,
            confine_to: None,
        }
    }

    /// Returns the [Target] this layer is evaluated for.
    pub fn for_target(&self) -> &Target {
        &self.target
    }

    /// Computes a hash that describes the inputs to layer evaluation. Layer
    /// evaluation (i.e. eval nickel => structs) is deterministic, so an
    /// input hash should correspond 1:1 with the result of [Loader::finish].
    pub fn input_hash_to<H: std::hash::Hasher>(&self, state: &mut H) {
        self.from.hash(state);
        self.target.hash(state);
        if let Some(params) = &self.params {
            state.write(b"params");
            let keys: BTreeSet<_> = params.keys().cloned().collect();
            for k in keys.into_iter() {
                k.hash(state);
                params.get(&k).unwrap().hash(state);
            }
        }
    }

    /// Computes a hash that describes the inputs to layer evaluation. Layer
    /// evaluation (i.e. eval nickel => structs) is deterministic, so an
    /// input hash should correspond 1:1 with the result of [Loader::finish].
    pub fn input_hash(&self) -> blake3::Hash {
        struct Blake3StdHasher(blake3::Hasher);

        impl std::hash::Hasher for Blake3StdHasher {
            fn write(&mut self, bytes: &[u8]) {
                self.0.update(bytes);
            }
            fn finish(&self) -> u64 {
                panic!("unreachable")
            }
        }

        let mut hasher = Blake3StdHasher(blake3::Hasher::new());
        hasher.0.update(&[crate::FORMAT_VERSION]);
        self.input_hash_to(&mut hasher);
        hasher.0.finalize()
    }
}

macro_rules! annotate_record {
    ($val:expr, $buildspec_id_ident:expr, $id:expr, $orig_val:expr, ($inner:expr, $files:expr, $pos_table:expr, $minimal_lib_path:expr),) => {
        // Skip annotation for any part of the minimal library.
        if {
            let inner_pos = $inner.pos($pos_table);
            inner_pos
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
        } {
            return Ok($orig_val);
        } else {
            // In the new API, pre-evaluation records are Term::RecRecord
            match $val {
                Term::RecRecord(mut rec_data) => {
                    if rec_data.record.fields.get(&$buildspec_id_ident).is_some() {
                        return Ok($orig_val);
                    }
                    rec_data.record.fields.insert(
                        LocIdent::new("__magic_buildspec_id"),
                        NickelValue::foreign_id_posless($id).into(),
                    );
                    $id += 1;
                    NickelValue::term_posless(Term::RecRecord(rec_data))
                }
                // A build-spec annotation can sit on a non-record term (e.g. an
                // unresolved `Term::Var` when the upstream pkgs checkout is
                // absent). Leave such terms unannotated rather than aborting;
                // evaluation then surfaces a real error instead of a panic.
                _ => return Ok($orig_val),
            }
        }
    };
}

/// Enumerates the list of package `build.ncl` within a `packages/` directory.
///
/// Partitioning of the packages list by name (i.e.: `a/abseil/build.ncl`) is handled
/// automatically.
pub fn build_decls_in_dir<P: AsRef<Path>>(dir: P) -> Result<Vec<PathBuf>, std::io::Error> {
    fn walk_dir_inner<P: AsRef<Path>>(
        out: &mut Vec<PathBuf>,
        is_toplevel: bool,
        dir: P,
    ) -> Result<(), std::io::Error> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let meta = entry.metadata()?;
            let path = entry.path();
            if meta.is_dir() {
                let build_path = path.join("build.ncl");
                if build_path.exists() {
                    out.push(build_path);
                }

                // Handle partitioning, i.e. `a/abseil/build.ncl` or `ab/abseil/build.ncl`.
                if is_toplevel
                    && let Some(fname) = entry.file_name().to_str()
                    && (fname.len() == 1
                        || fname.len() == 2
                            && fname
                                .chars()
                                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
                {
                    walk_dir_inner(out, false, path)?;
                }
            }
        }
        Ok(())
    }

    let mut out = Vec::with_capacity(512);
    if dir.as_ref().exists() {
        walk_dir_inner(&mut out, true, dir)?;
    }

    Ok(out)
}

/// Matches an `import "…"` expression in Nickel source; group 1 is the
/// string's body, escapes still in place.
static IMPORT_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bimport\s*"((?:[^"\\]|\\.)*)""#).expect("the import pattern is valid")
});

/// Undoes the Nickel string escapes a path can plausibly hold (`\"`, `\\`,
/// `\%`). Any other escape is kept as written; the check after loading
/// covers a path this gets wrong.
fn unescape_import(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some(e @ ('"' | '\\' | '%')) => out.push(e),
            Some(e) => {
                out.push('\\');
                out.push(e);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// Refuses, before Nickel reads anything, an import that reaches outside the
/// layer.
///
/// `entries` are the files the generated toplevel imports; `root` is the
/// canonical layer directory; `lib_path` is the minimal library directory as
/// Nickel is given it. Each entry, and every `.ncl` file inside the layer
/// that they import (transitively), is read and each `import "…"` in it is
/// resolved the way Nickel resolves it: against the importing file's
/// directory first, then the minimal library. An absolute import is refused
/// outright. A relative one, `..` included, must land (symlinks resolved)
/// under `root` or under the minimal library. An import that resolves to no
/// file is left for Nickel to report.
///
/// Packages import their siblings as `../<name>/build.ncl`, so `..` itself
/// is not refused: where the path lands is what counts.
///
/// The scan is lexical and can miss an import (the check after loading,
/// [confine_files_read], backs it up), and it can over-match: an
/// `import "…"` inside a comment or a string is checked too.
///
/// Public so that a caller building its own Nickel program over a layer's
/// files confines it the same way: this before the program reads anything,
/// [confine_files_read] after it has typechecked and compiled.
pub fn confine_imports(entries: &[PathBuf], root: &Path, lib_path: &Path) -> Result<(), Error> {
    let lib = lib_path.canonicalize().ok();
    let outside = |file: &Path, import: &str| Error::ImportOutside {
        file: Some(file.to_path_buf()),
        import: import.to_string(),
        root: root.to_path_buf(),
    };

    // Files still to scan, each by the normalized path Nickel names it by:
    // Nickel resolves a relative import against that path's directory, not
    // against the symlink-resolved one.
    let mut todo: Vec<PathBuf> = Vec::with_capacity(entries.len());
    for entry in entries {
        let named = normalize_path(entry.as_path())?;
        match named.canonicalize() {
            Ok(canon) if canon.starts_with(root) => todo.push(named),
            Ok(_) => return Err(outside(root, &entry.to_string_lossy())),
            // A missing entry is Nickel's to report.
            Err(_) => {}
        }
    }

    let mut visited: HashSet<PathBuf> = HashSet::new();
    while let Some(named) = todo.pop() {
        let Ok(canon) = named.canonicalize() else {
            continue;
        };
        if !visited.insert(canon.clone()) {
            continue;
        }
        // The file is inside the layer; if it cannot be read as text, Nickel
        // reports that itself.
        let Ok(text) = std::fs::read_to_string(&canon) else {
            continue;
        };
        let dir = named.parent().map(Path::to_path_buf).unwrap_or_default();

        for cap in IMPORT_PATH.captures_iter(&text) {
            let Some(raw) = cap.get(1) else {
                continue;
            };
            let import = unescape_import(raw.as_str());
            let rel = Path::new(&import);
            if rel.is_absolute()
                || rel
                    .components()
                    .any(|c| matches!(c, Component::RootDir | Component::Prefix(_)))
            {
                return Err(outside(&named, &import));
            }

            // Nickel takes the first candidate it can read.
            let mut candidates = vec![normalize_abs_path(&dir.join(rel))];
            if let Ok(in_lib) = normalize_path(lib_path.join(rel)) {
                candidates.push(in_lib);
            }
            let found = candidates.into_iter().find_map(|c| {
                let canon = c.canonicalize().ok()?;
                std::fs::metadata(&canon)
                    .ok()?
                    .is_file()
                    .then_some((c, canon))
            });
            let Some((import_named, import_canon)) = found else {
                continue;
            };

            if import_canon.starts_with(root) {
                if import_named.extension().is_some_and(|e| e == "ncl") {
                    todo.push(import_named);
                }
            } else if !lib.as_deref().is_some_and(|l| import_canon.starts_with(l)) {
                return Err(outside(&named, &import));
            }
        }
    }
    Ok(())
}

/// The canonical root a layer at `layer_dir` is confined to (see
/// [LoadOptions::confine_to]). A layer directory that does not exist has no
/// files to confine; its normalized path stands in as the root.
pub fn layer_root(layer_dir: &Path) -> Result<PathBuf, Error> {
    match layer_dir.canonicalize() {
        Ok(root) => Ok(root),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(normalize_path(layer_dir)?),
        Err(e) => Err(e.into()),
    }
}

/// Refuses a Nickel program that has read a file from disk outside `root`
/// (canonical, see [layer_root]) and the minimal library at `lib_path`.
///
/// This is the check after loading that backs up [confine_imports]. Run it
/// once the program has typechecked and compiled, and also when either
/// fails, before reporting that failure: then a foreign file is reported as
/// outside the layer rather than quoted in a diagnostic. The refusal is an
/// [Error::ImportOutside] naming the file, never its content.
pub fn confine_files_read(files: &Files, root: &Path, lib_path: &Path) -> Result<(), Error> {
    let lib = lib_path.canonicalize().ok();
    match first_file_outside(files, root, lib.as_deref()) {
        Some(path) => Err(Error::ImportOutside {
            file: None,
            import: path.to_string_lossy().into_owned(),
            root: root.to_path_buf(),
        }),
        None => Ok(()),
    }
}

/// Returns the first file in `files` read from disk outside `root` and the
/// minimal library (`lib`, canonical), if any.
///
/// Nickel names every file it reads from disk by its absolute normalized
/// path. Its in-memory sources (the generated `toplevel`, the Nickel
/// standard library modules, its own `<generated …>` snippets) have names
/// that are not absolute paths, and are skipped.
fn first_file_outside(files: &Files, root: &Path, lib: Option<&Path>) -> Option<PathBuf> {
    let stdlib: HashSet<&OsStr> = files.stdlib_modules().map(|id| files.name(id)).collect();
    for name in files.filenames() {
        let path = Path::new(name);
        if stdlib.contains(name) || name == "toplevel" || !path.is_absolute() {
            continue;
        }
        let resolved = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        if resolved.starts_with(root) || lib.is_some_and(|l| resolved.starts_with(l)) {
            continue;
        }
        return Some(path.to_path_buf());
    }
    None
}

/// Evaluates a single layer of nickel files which describe minimal build specifications.
pub(crate) struct Loader {
    p: Program<CacheImpl>,
    from: SpecOrigin,
    for_target: Target,
    minimal_lib_path: PathBuf,
    last_id: u64,
}

/// Name of the initial-env variable that exposes the target & layer parameters
/// to nickel code (see `config.ncl` in the stdlib).
pub(crate) const INJECTED_CONFIG_VAR: &str = "__minimal_injected_config";

fn build_injected_config(target: &Target, args: Option<&args::ArgsSet>) -> NickelValue {
    let target_val = NickelValue::record_posless(RecordData::with_field_values([
        (
            LocIdent::new("os"),
            NickelValue::enum_tag_posless(LocIdent::new(target.os().as_nickel_str())),
        ),
        (
            LocIdent::new("arch"),
            NickelValue::enum_tag_posless(LocIdent::new(target.arch().as_nickel_str())),
        ),
    ]));
    let args_val = match args {
        None => NickelValue::record_posless(RecordData::default()),
        Some(set) => NickelValue::record_posless(RecordData::with_field_values(
            set.iter()
                .map(|(name, v)| (LocIdent::new(name), v.to_nickel())),
        )),
    };
    NickelValue::record_posless(RecordData::with_field_values([
        (LocIdent::new("target"), target_val),
        (LocIdent::new("args"), args_val),
    ]))
}

impl Loader {
    /// Processes literal source representing a top-level collection of objects.
    pub(crate) fn new<S: Into<String>>(
        src: S,
        args: Option<&args::ArgsSet>,
        opts: &LoadOptions,
    ) -> Result<Self, Error> {
        let injected = build_injected_config(opts.for_target(), args);

        let mut program: Program<CacheImpl> = ProgramBuilder::new()
            .add_source(std::io::Cursor::new(src.into()), "toplevel")
            .add_import_paths([&opts.minimal_lib_path].iter())
            .extend_initial_env(vec![(Ident::new(INJECTED_CONFIG_VAR), injected)])
            .with_reporter(NullReporter {})
            .with_trace(std::io::stderr())
            .build()
            .map_err(|e| match e {
                BuilderError::NoInputs => unreachable!(),
                BuilderError::Io { path: _, error } => Error::IO(error),
            })?;

        // Nickel reads every import while typechecking. The confinement check
        // below runs after that read, so on its own it cannot keep a foreign
        // file's bytes out of a parse diagnostic: the scan before loading
        // ([confine_imports], run by [Loader::new_with_all_pkgs]) does that.
        // This check is the backstop for what the scan cannot see, such as an
        // escaped quote or a string form its pattern does not match. It runs
        // on the failure paths too, so a foreign file that fails to parse is
        // reported as outside the layer rather than quoted.
        let confine = |program: &Program<CacheImpl>| -> Result<(), Error> {
            match opts.confine_to.as_deref() {
                Some(root) => confine_files_read(&program.files(), root, &opts.minimal_lib_path),
                None => Ok(()),
            }
        };
        if let Err(e) = program.typecheck(nickel_lang_core::typecheck::TypecheckMode::Walk) {
            confine(&program)?;
            return Err(Error::Nickel(Box::new((program.files(), e))));
        }
        if let Err(e) = program.compile() {
            confine(&program)?;
            return Err(Error::Nickel(Box::new((program.files(), e))));
        }
        confine(&program)?;

        let mut out = Self {
            p: program,
            from: opts.from.clone(),
            for_target: opts.for_target().clone(),
            last_id: 0,
            minimal_lib_path: opts.minimal_lib_path.canonicalize()?,
        };
        out.annotate()?;
        Ok(out)
    }

    /// Loads all build decls in the given directory following the standard directory layout.
    pub fn new_with_all_pkgs<P: AsRef<Path>>(
        layer_dir: P,
        args: Option<&args::ArgsSet>,
        opts: &LoadOptions,
    ) -> Result<Self, Error> {
        // Every file the generated toplevel imports; see [confine_imports].
        let mut entries: Vec<PathBuf> = Vec::new();
        let mut src = String::with_capacity(2048);
        src.push_str("let {layer, ..} = import \"minimal.ncl\" in\n");
        src.push_str("layer {\n");
        src.push_str("\tbuilds = [\n");
        for pb in build_decls_in_dir(layer_dir.as_ref().join("packages"))?.into_iter() {
            src.push_str("\t\timport \"");
            src.push_str(pb.to_str().unwrap());
            src.push_str("\",\n");
            entries.push(pb);
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
                        entries.push(e.path().join("profile.ncl"));
                    }
                }
                src.push_str("\t],\n");
            }
        }
        src.push_str("\tstacks = [\n");
        match std::fs::read_dir(layer_dir.as_ref().join("stacks")) {
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(e.into());
                }
            }
            Ok(d) => {
                for e in d {
                    let e = e?;
                    if e.file_type()?.is_dir() {
                        src.push_str("  import \"");
                        src.push_str(e.path().to_str().unwrap());
                        src.push_str("/stack.ncl\",\n");
                        entries.push(e.path().join("stack.ncl"));
                    }
                }
            }
        }
        src.push_str("\t],\n");

        src.push_str("\tcontainers = [\n");
        match std::fs::read_dir(layer_dir.as_ref().join("containers")) {
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(e.into());
                }
            }
            Ok(d) => {
                for e in d {
                    let e = e?;
                    if e.file_type()?.is_dir() {
                        src.push_str("  import \"");
                        src.push_str(e.path().to_str().unwrap());
                        src.push_str("/spec.ncl\",\n");
                        entries.push(e.path().join("spec.ncl"));
                    }
                }
            }
        }
        src.push_str("\t],\n");

        src.push('}');

        // The layer's own files may import each other and the minimal
        // library, and nothing else.
        let root = layer_root(layer_dir.as_ref())?;
        confine_imports(&entries, &root, &opts.minimal_lib_path)?;

        let confined = LoadOptions {
            minimal_lib_path: opts.minimal_lib_path.clone(),
            from: opts.from.clone(),
            target: opts.target.clone(),
            params: opts.params.clone(),
            confine_to: Some(root),
        };
        Self::new(src, args, &confined)
    }

    /// Walks the AST to find unique build-spec declarations, annotating them with a unique ID.
    fn annotate(&mut self) -> Result<(), Error> {
        use nickel_lang_core::traverse::{Traverse as _, TraverseOrder};

        let files = self.p.files();
        let pos_table = self.p.pos_table().clone();
        let minimal_lib_path = self.minimal_lib_path.to_str().unwrap();

        let mut id: u64 = self.last_id;
        let buildspec_id_ident = LocIdent::new("__magic_buildspec_id");
        let mut traversal = |val: NickelValue| -> Result<NickelValue, TermCacheError<()>> {
            // We need to inspect the Term inside NickelValue for unevaluated AST
            if let Some(term) = val.as_term() {
                // Explicit declaration: { ... } | BuildSpec
                if let Term::Annotated(ref annotation_data) = *term {
                    let is_buildspec = annotation_data.annot.contracts.iter().any(|lt| {
                        if let TypeF::Contract(c) = &lt.typ.typ {
                            matches!(c.as_term(), Some(Term::Var(v)) if v.label() == "BuildSpec")
                        } else {
                            false
                        }
                    });

                    if is_buildspec && let Some(inner_term) = annotation_data.inner.as_term() {
                        let annotated = Term::Annotated(nickel_lang_core::term::AnnotatedData {
                            annot: annotation_data.annot.clone(),
                            inner: annotate_record!(
                                inner_term.clone(),
                                buildspec_id_ident,
                                id,
                                val,
                                (&annotation_data.inner, &files, &pos_table, minimal_lib_path),
                            ),
                        });
                        return Ok(NickelValue::term(annotated, val.pos_idx()));
                    }
                }

                // Function-based declaration: build { ... }
                if let Term::App(ref app_data) = *term {
                    let is_build_decl = matches!(
                        app_data.head.as_term(),
                        Some(Term::Var(v)) if v.label() == "build"
                    );

                    if is_build_decl && let Some(arg_term) = app_data.arg.as_term() {
                        let app = Term::App(nickel_lang_core::term::AppData {
                            head: app_data.head.clone(),
                            arg: annotate_record!(
                                arg_term.clone(),
                                buildspec_id_ident,
                                id,
                                val,
                                (&app_data.arg, &files, &pos_table, minimal_lib_path),
                            ),
                        });
                        return Ok(NickelValue::term(app, val.pos_idx()));
                    }
                }
            }

            Ok(val)
        };

        let result = self
            .p
            .custom_transform(1, |_cache, _pos_table, val| {
                val.traverse(&mut traversal, TraverseOrder::TopDown)
            })
            .map_err(|e| Error::Other(format!("annotation: {:?}", e)));
        self.last_id = id;
        result
    }

    /// Destroys the loader, returning the outputs of processing (the nickel tree, where it came from).
    pub fn finish(self) -> Result<(NickelValue, Program<CacheImpl>, SpecOrigin, Target), Error> {
        let Self {
            mut p,
            from,
            for_target,
            ..
        } = self;
        let root_term = p
            .eval_record_spine()
            .map_err(|e| Error::Nickel(Box::new((p.files(), e))))?;

        Ok((root_term, p, from, for_target))
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

        let result = build_decls_in_dir(temp_dir.path()).unwrap();

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

        let result = build_decls_in_dir(temp_dir.path()).unwrap();

        assert_eq!(result.len(), 1);
        assert!(result[0].ends_with("build.ncl"));
    }

    #[test]
    fn build_decls_in_dir_partitioned() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Create multiple package directories
        for pkg_name in &["p/package-a", "e/effo"] {
            let pkg_dir = temp_dir.path().join(pkg_name);
            std::fs::create_dir_all(&pkg_dir).unwrap();
            std::fs::write(pkg_dir.join("build.ncl"), "test content").unwrap();
        }

        let result = build_decls_in_dir(temp_dir.path()).unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.iter().any(|p| p.ends_with("p/package-a/build.ncl")));
        assert!(result.iter().any(|p| p.ends_with("e/effo/build.ncl")));
    }

    #[test]
    fn loader_empty() {
        let _sr = Loader::new("{}".to_string(), None, &LoadOptions::for_test()).unwrap();
    }

    #[test]
    fn loader_injects_config() {
        let args = {
            let schema: args::ArgsSpec = toml::from_str("a = \"string\"").unwrap();
            schema
                .from_deserialized(&HashMap::from_iter([(
                    "a".to_string(),
                    args::DiskArg::String("hi".to_string()),
                )]))
                .unwrap()
        };
        let _sr = Loader::new(
            "{c = __minimal_injected_config}".to_string(),
            Some(&args),
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
            None,
            &LoadOptions::for_test(),
        );

        // So we can see the actual error when the test fails
        if let Some(e) = sr.as_ref().err().iter().next() {
            e.report_to_stderr();
            panic!();
        }

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
                        build_deps = [
                            build { name = \"swiggity swooty\" },
                        ],
                    }
                }"
            }
            .to_string(),
            None,
            &LoadOptions::for_test(),
        );

        // So we can see the actual error when the test fails
        if let Some(e) = sr.as_ref().err().iter().next() {
            e.report_to_stderr();
            panic!();
        }

        let sr = sr.unwrap();
        assert_eq!(sr.last_id, 2); // two build specs
    }

    #[test]
    fn loader_annotates_buildspec_via_var() {
        // A build spec whose annotated term is a variable reference (Term::Var)
        // rather than an inline record must not abort the annotate pass. This is
        // the shape decode meets when the upstream pkgs checkout is absent.
        let sr = Loader::new(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in
                let spec = { name = \"via var\" } in
                {
                    toplevel = spec | BuildSpec
                }"
            }
            .to_string(),
            None,
            &LoadOptions::for_test(),
        );

        // So we can see the actual error when the test fails
        if let Some(e) = sr.as_ref().err().iter().next() {
            e.report_to_stderr();
            panic!();
        }

        sr.unwrap();
    }

    const SECRET: &str = "secret-marker-xyz";

    /// A layer at `<dir>/layer` (with an empty `profiles`, which the layer
    /// contract requires) whose package `p` has `build.ncl` = `build`.
    /// Returns the layer directory.
    fn layer_with_package(dir: &Path, build: &str) -> PathBuf {
        let layer = dir.join("layer");
        let pkg = layer.join("packages").join("p");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::create_dir_all(layer.join("profiles")).unwrap();
        std::fs::write(pkg.join("build.ncl"), build).unwrap();
        layer
    }

    /// The import an [Error::ImportOutside] names, and everything the error
    /// prints (its `Display` and its rendered report).
    fn import_refusal(res: Result<Loader, Error>) -> (Option<PathBuf>, String, String) {
        let err = match res {
            Ok(_) => panic!("expected the import to be refused"),
            Err(err) => err,
        };
        let (file, import) = match &err {
            Error::ImportOutside { file, import, .. } => (file.clone(), import.clone()),
            other => {
                other.report_to_stderr();
                panic!("expected Error::ImportOutside, got {other:?}");
            }
        };
        let mut buf = codespan_reporting::term::termcolor::Buffer::no_color();
        err.report_to(&mut buf);
        let text = format!("{err}\n{}", String::from_utf8_lossy(buf.as_slice()));
        (file, import, text)
    }

    fn load_ok(res: Result<Loader, Error>) -> Loader {
        res.unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("load failed: {e}");
        })
    }

    #[test]
    fn package_importing_an_absolute_host_path_is_refused_before_reading_it() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret.txt");
        std::fs::write(&secret, SECRET).unwrap();
        let layer = layer_with_package(
            dir.path(),
            &format!(
                "let {{BuildSpec, ..}} = import \"minimal.ncl\" in\n\
                 let leak = import \"{}\" in\n\
                 {{ name = \"p\" }} | BuildSpec\n",
                secret.to_str().unwrap()
            ),
        );

        let (file, import, text) = import_refusal(Loader::new_with_all_pkgs(
            &layer,
            None,
            &LoadOptions::for_test(),
        ));
        assert!(
            file.is_some_and(|f| f.ends_with("packages/p/build.ncl")),
            "{text}"
        );
        assert_eq!(import, secret.to_str().unwrap());
        assert!(!text.contains(SECRET), "{text}");
    }

    #[test]
    fn package_importing_up_out_of_the_layer_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("outside.ncl"), SECRET).unwrap();
        // packages/p -> packages -> layer -> the directory holding the layer.
        let layer = layer_with_package(
            dir.path(),
            "let {BuildSpec, ..} = import \"minimal.ncl\" in\n\
             let leak = import \"../../../outside.ncl\" in\n\
             { name = \"p\" } | BuildSpec\n",
        );

        let (_file, import, text) = import_refusal(Loader::new_with_all_pkgs(
            &layer,
            None,
            &LoadOptions::for_test(),
        ));
        assert_eq!(import, "../../../outside.ncl");
        assert!(!text.contains(SECRET), "{text}");
    }

    #[cfg(unix)]
    #[test]
    fn package_importing_through_a_symlink_out_of_the_layer_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("helper.ncl"), SECRET).unwrap();
        let layer = layer_with_package(
            dir.path(),
            "let {BuildSpec, ..} = import \"minimal.ncl\" in\n\
             let leak = import \"./lib/helper.ncl\" in\n\
             { name = \"p\" } | BuildSpec\n",
        );
        std::os::unix::fs::symlink(&elsewhere, layer.join("packages/p/lib")).unwrap();

        let (_file, import, text) = import_refusal(Loader::new_with_all_pkgs(
            &layer,
            None,
            &LoadOptions::for_test(),
        ));
        assert_eq!(import, "./lib/helper.ncl");
        assert!(!text.contains(SECRET), "{text}");
    }

    /// A helper inside the package, a sibling package reached with `..`, and
    /// the minimal library all stay importable.
    #[test]
    fn package_imports_inside_the_layer_still_load() {
        let dir = tempfile::tempdir().unwrap();
        let layer = layer_with_package(
            dir.path(),
            "let {BuildSpec, ..} = import \"minimal.ncl\" in\n\
             let helper = import \"./lib/helper.ncl\" in\n\
             let q = import \"../q/build.ncl\" in\n\
             { name = helper.name, build_deps = [q] } | BuildSpec\n",
        );
        let lib = layer.join("packages/p/lib");
        std::fs::create_dir_all(&lib).unwrap();
        std::fs::write(lib.join("helper.ncl"), "{ name = \"p\" }\n").unwrap();
        let q = layer.join("packages/q");
        std::fs::create_dir_all(&q).unwrap();
        std::fs::write(
            q.join("build.ncl"),
            "let {BuildSpec, ..} = import \"minimal.ncl\" in\n{ name = \"q\" } | BuildSpec\n",
        )
        .unwrap();

        let loader = load_ok(Loader::new_with_all_pkgs(
            &layer,
            None,
            &LoadOptions::for_test(),
        ));
        load_ok_finish(loader);
    }

    fn load_ok_finish(loader: Loader) {
        if let Err(e) = loader.finish() {
            e.report_to_stderr();
            panic!("finish failed: {e}");
        }
    }

    /// The check after loading, on its own: an inline source (which the scan
    /// before loading never sees) importing a file outside `confine_to`.
    #[test]
    fn confine_to_refuses_a_file_loaded_from_outside() {
        let dir = tempfile::tempdir().unwrap();
        let outside = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("testdata/local_input.ncl");
        let opts = LoadOptions {
            confine_to: Some(dir.path().canonicalize().unwrap()),
            ..LoadOptions::for_test()
        };

        let (file, import, text) = import_refusal(Loader::new(
            format!("import \"{}\"", outside.to_str().unwrap()),
            None,
            &opts,
        ));
        assert!(file.is_none(), "{text}");
        assert!(import.ends_with("testdata/local_input.ncl"), "{text}");
    }

    /// When the foreign file fails to parse, the check after loading still
    /// reports it as outside the layer, not as a parse error quoting it.
    #[test]
    fn confine_to_reports_an_unparsable_foreign_file_without_quoting_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("layer");
        std::fs::create_dir_all(&root).unwrap();
        let secret = dir.path().join("secret.ncl");
        std::fs::write(&secret, format!("{SECRET} ) {{ not nickel")).unwrap();
        let opts = LoadOptions {
            confine_to: Some(root.canonicalize().unwrap()),
            ..LoadOptions::for_test()
        };

        let (_file, _import, text) = import_refusal(Loader::new(
            format!("import \"{}\"", secret.to_str().unwrap()),
            None,
            &opts,
        ));
        assert!(!text.contains(SECRET), "{text}");
    }

    /// Without `confine_to` (inline test sources), nothing is confined.
    #[test]
    fn no_confine_to_leaves_absolute_imports_alone() {
        let path = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("testdata/local_input.ncl");
        load_ok(Loader::new(
            format!("import \"{}\"", path.to_str().unwrap()),
            None,
            &LoadOptions::for_test(),
        ));
    }

    #[test]
    fn unescape_import_undoes_path_escapes_only() {
        assert_eq!(unescape_import(r#"a\"b"#), "a\"b");
        assert_eq!(unescape_import(r"a\\b"), r"a\b");
        assert_eq!(unescape_import(r"a\%b"), "a%b");
        assert_eq!(unescape_import(r"a\nb"), r"a\nb");
        assert_eq!(unescape_import("plain/path.ncl"), "plain/path.ncl");
    }

    #[test]
    fn loader_new_with_all_pkgs() {
        let temp_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp_dir.path().join("packages")).unwrap();
        std::fs::create_dir(temp_dir.path().join("profiles")).unwrap();
        std::fs::create_dir(temp_dir.path().join("stacks")).unwrap();
        std::fs::create_dir(temp_dir.path().join("containers")).unwrap();

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
        // Make a stack called rust
        let harness_dir = temp_dir.path().join("stacks").join("rust");
        std::fs::create_dir(&harness_dir).unwrap();
        std::fs::write(
            harness_dir.join("stack.ncl"),
            indoc! {
            "
            let {stack, ..} = import \"minimal.ncl\" in
            stack {
        		name = \"rust\"
        	}
			"
            },
        )
        .unwrap();

        // Make a container called web
        let container_dir = temp_dir.path().join("containers").join("web");
        std::fs::create_dir(&container_dir).unwrap();
        std::fs::write(
            container_dir.join("spec.ncl"),
            indoc! {
            "
            let {container, ..} = import \"minimal.ncl\" in
            container {
        		name = \"web\",
        		packages = [\"glibc\"],
        	}
			"
            },
        )
        .unwrap();

        let sr = Loader::new_with_all_pkgs(temp_dir.path(), None, &LoadOptions::for_test());
        // So we can see the actual error when the test fails
        if let Some(e) = sr.as_ref().err().iter().next() {
            e.report_to_stderr();
            panic!();
        }

        let mut sr = sr.unwrap();
        assert_eq!(sr.last_id, 3); // three build specs

        let eval_result = sr.p.eval().unwrap();
        if let Some(rd) = eval_result.as_record().and_then(|c| c.into_opt()) {
            // Check a field 'profiles' was an array with one object
            let profiles_val = eval_if_closure(
                &rd.get_value_with_ctrs(&LocIdent::new("profiles"))
                    .unwrap()
                    .unwrap(),
                &mut sr.p,
            )
            .unwrap();
            assert!(profiles_val.as_array().map(|a| a.len()).unwrap_or(0) == 1,);

            // Check a field 'stacks' was an array with one object
            let stacks_val = eval_if_closure(
                &rd.get_value_with_ctrs(&LocIdent::new("stacks"))
                    .unwrap()
                    .unwrap(),
                &mut sr.p,
            )
            .unwrap();
            assert!(stacks_val.as_array().map(|a| a.len()).unwrap_or(0) == 1,);

            // Check a field 'containers' was an array with one object
            let containers_val = eval_if_closure(
                &rd.get_value_with_ctrs(&LocIdent::new("containers"))
                    .unwrap()
                    .unwrap(),
                &mut sr.p,
            )
            .unwrap();
            assert!(containers_val.as_array().map(|a| a.len()).unwrap_or(0) == 1,);
        }
    }
}
