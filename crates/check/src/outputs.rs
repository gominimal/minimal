use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use super::Error;
use crate::{CheckCache, CheckCtx, CheckResult, CheckVerdict};
use anyhow::anyhow;
use common::target::Arch;
use graph::{BuildOutput, BuildSpecRef, Graph, Transitives};
use lcache::{CacheErr, DirCacheEntry, LocalDir};
use object::Object;
use ot::OpTracker;
use tokio::sync::RwLockReadGuard;

pub(crate) struct OutputTypesValid;

impl crate::GraphBasedChecker for OutputTypesValid {
    async fn check(
        self,
        ctx: &CheckCtx,
        pkg: String,
        _package_dir: &Path,
        graph: RwLockReadGuard<'_, Graph>,
        _ot: Option<OpTracker>,
    ) -> Result<CheckResult, Error> {
        let cache = ctx.cache.clone();
        let mut result = CheckResult {
            verdict: CheckVerdict::Skip,
            check: "output types valid".into(),
            err: vec![],
        };
        if ctx
            .skip_checkers
            .contains(&"output types valid".to_string())
        {
            return Ok(result);
        }

        let bsr = match graph.by_name(&pkg) {
            Some(b) => *b,
            None => {
                return Ok(result); // skip, we need the build
            }
        };
        let build = graph.get(&bsr).unwrap();
        let spec_hash = graph.spec_hash(&bsr);
        let cached_build = if let Ok(cached_build) = cache.read_dir(&spec_hash) {
            cached_build
        } else {
            return Ok(result); // skip, we need the cached build
        };

        result.verdict = CheckVerdict::Pass;
        for (name, output) in &build.outputs {
            let glob = output.glob();
            for path in ctx
                .check_cache
                .match_files_for_glob(cached_build.path(), glob)?
                .iter()
            {
                let data = std::fs::read(path)
                    .map_err(|e| Error::IO("reading output file", path.to_path_buf(), e))?;
                match (object::File::parse(&*data), output) {
                    (Ok(f), BuildOutput::Binary { .. } | BuildOutput::Library { .. }) => {
                        match (f.architecture(), graph.target().arch()) {
                            (object::Architecture::Aarch64, Arch::Arm64) => {}
                            (object::Architecture::X86_64, Arch::Amd64) => {}
                            (elf_arch, graph_arch) => {
                                result.verdict = CheckVerdict::Fail;
                                result.err.push(format!(
                                    "output \"{}\": {} has an ELF arch of {:?}, expected {:?}",
                                    name,
                                    path.strip_prefix(cached_build.path()).unwrap().display(),
                                    elf_arch,
                                    graph_arch,
                                ));
                            }
                        };
                    }
                    (Err(_), BuildOutput::Data { .. }) => {}
                    (
                        Ok(_),
                        BuildOutput::Data {
                            allow_executable: true,
                            ..
                        },
                    ) => {}
                    (Ok(_), BuildOutput::Data { .. }) => {
                        result.verdict = CheckVerdict::Fail;
                        result.err.push(format!(
                            "data output \"{}\" matched binary/library file {}",
                            name,
                            path.strip_prefix(cached_build.path()).unwrap().display()
                        ));
                    }
                    (
                        Err(e),
                        BuildOutput::Library {
                            allow_data: true, ..
                        },
                    ) if format!("{}", e) == "Unknown file magic"
                        || format!("{}", e) == "Could not read file magic" => {}
                    (Err(e), BuildOutput::Binary { .. } | BuildOutput::Library { .. }) => {
                        if matches!(output, BuildOutput::Binary { .. }) && data.starts_with(b"#!") {
                            // Special case for binaries - its valid for it to be a #! executable.
                        } else if matches!(output, BuildOutput::Library { .. })
                            && object::read::archive::ArchiveFile::parse(&*data).is_ok()
                        {
                            // Special case for libraries - its valid for it to be a .a archive object.
                        } else {
                            result.verdict = CheckVerdict::Fail;
                            result.err.push(format!(
                                "executable output \"{}\": {} is malformed (parsing error: {})",
                                name,
                                path.strip_prefix(cached_build.path()).unwrap().display(),
                                e,
                            ));
                        }
                    }
                }
            }
        }

        Ok(result)
    }
}

pub(crate) struct MissingRuntimeDeps;

impl crate::GraphBasedChecker for MissingRuntimeDeps {
    async fn check(
        self,
        ctx: &CheckCtx,
        pkg: String,
        _package_dir: &Path,
        graph: RwLockReadGuard<'_, Graph>,
        _ot: Option<OpTracker>,
    ) -> Result<CheckResult, Error> {
        let check_cache = ctx.check_cache.clone();
        let cache = ctx.cache.clone();
        let mut result = CheckResult {
            verdict: CheckVerdict::Skip,
            check: "missing runtime_deps".into(),
            err: vec![],
        };
        if ctx
            .skip_checkers
            .contains(&"missing runtime_deps".to_string())
        {
            return Ok(result);
        }

        let bsr = match graph.by_name(&pkg) {
            Some(b) => *b,
            None => {
                return Ok(result); // skip, we need the build
            }
        };

        // Clone the graph and release the read lock so other checkers can proceed.
        let graph = std::ops::Deref::deref(&graph).clone();

        tokio::task::spawn_blocking(move || {
            (move || -> Result<CheckResult, Error> {
            let build = graph.get(&bsr).unwrap();
            let spec_hash = graph.spec_hash(&bsr);
            let cached_build = if let Ok(cached_build) = cache.read_dir(&spec_hash) {
                cached_build
            } else {
                return Ok(result); // skip, we need the cached build
            };

            // We also need the builds of all the runtime_deps
            let transitives = Transitives::new(&graph, &bsr, false)
                .transitive_runtime_deps
                .keys()
                .to_owned()
                .map(|dep| Ok::<_, CacheErr>((*dep, cache.read_dir(&graph.spec_hash(dep))?)))
                .collect::<Result<Vec<_>, _>>();
            let deps: Vec<(BuildSpecRef, DirCacheEntry<LocalDir>)> = match transitives {
                Ok(mut t) => {
                    // We need to consider imports from libraries in the current package as well
                    t.push((bsr, cache.read_dir(&spec_hash).unwrap()));
                    t
                }
                Err(_) => {
                    return Ok(result); // skip, we need the cached build of all runtime_deps
                }
            };

            result.verdict = CheckVerdict::Pass;

            // Collect:
            //  - the ELF imports that each file in each bin/lib output wants.
            //  - the interpreter of any executable scripts
            let mut all_imports: HashMap<String, HashMap<(&String, PathBuf), HashSet<String>>> =
                HashMap::with_capacity(1024);
            let mut script_interpreters: HashMap<PathBuf, (String, String)> =
                HashMap::with_capacity(32);
            for (name, output) in &build.outputs {
                let glob = output.glob();
                for path in check_cache.match_files_for_glob(cached_build.path(), glob)?.iter() {
                    let data = std::fs::read(path)
                        .map_err(|e| Error::IO("reading output file", path.to_path_buf(), e))?;
                    if let (Ok(elf), BuildOutput::Binary { .. } | BuildOutput::Library { .. }) =
                        (object::File::parse(&*data), output)
                        && let Ok(imports) = elf.imports()
                    {
                        let path_in_build = path.strip_prefix(cached_build.path()).unwrap();
                        for import in imports.iter() {
                            let lib = String::from_utf8(import.library().to_vec()).unwrap();
                            let symbol = String::from_utf8(import.name().to_vec()).unwrap();
                            if lib.is_empty() {
                                continue;
                            }

                            match all_imports.get_mut(&lib) {
                                None => {
                                    all_imports.insert(
                                        lib,
                                        HashMap::from_iter(
                                            [(
                                                (name, path_in_build.to_path_buf()),
                                                [symbol].into(),
                                            )],
                                        ),
                                    );
                                }
                                Some(syms_by_output_files) => {
                                    let k = (name, path_in_build.to_path_buf());
                                    match syms_by_output_files.get_mut(&k) {
                                        None => {
                                            syms_by_output_files.insert(k, [symbol].into());
                                        }
                                        Some(syms) => {
                                            syms.insert(symbol);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if let BuildOutput::Binary {
                        glob: _,
                        allow_missing_interpreter: false,
                    } = output
                        && data.starts_with(b"#!")
                        && let Some(newline_idx) = data.iter().position(|c| c == &b'\n')
                    {
                        // NOTE: most Linux kernels (and many Unix systems) treat everything after #!
                        // up to the first space as the interpreter, and everything after the first space
                        // as a single argument. So we just collect everything after the shebang up to
                        // the first space (or, newline).
                        let interpreter = String::from_utf8(data[2..newline_idx].to_vec())
                            .map_err(|e| Error::Other(e.into()))?
                            .trim_start()
                            .split(" ")
                            .next()
                            .unwrap()
                            .to_string();
                        script_interpreters.insert(
                            path.strip_prefix(cached_build.path())
                                .unwrap()
                                .to_path_buf(),
                            (name.clone(), interpreter),
                        );
                    }
                }
            }
            for (needed_lib, outputs) in &all_imports {
                match find_lib_in_deps(&check_cache, needed_lib, &deps)? {
                    Some((idx, lib_path)) => {
                        // There was a library, check that all the symbols we need are present.
                        match check_cache.lib_symbols(deps[idx].0, deps[idx].1.path(), &lib_path) {
                            Ok(avail_symbols) => {
                                let missing_symbols: Vec<&String> = outputs
                                    .values()
                                    .flatten()
                                    .filter(|sym| !avail_symbols.contains(*sym))
                                    .collect();

                                if !missing_symbols.is_empty() {
                                    result.err.push(format!(
                                        "executable dependency '{}' at {}:{} missing symbols: {}. Needed by {}",
                                        needed_lib,
                                        graph.get(&deps[idx].0).unwrap().name,
                                        lib_path.display(),
                                        missing_symbols.into_iter().cloned().collect::<Vec<_>>().join(", "),
                                        outputs
                                            .keys()
                                            .map(|(_output, path)| path.display().to_string())
                                            .collect::<Vec<_>>()
                                            .join(", ")
                                    ));
                                    result.verdict = CheckVerdict::Fail;
                                }
                            }
                            Err(e) => {
                                result.err.push(format!(
                                    "executable dependency '{}' mapped to invalid executable {}:{} ({}). Needed by {}",
                                    needed_lib,
                                    graph.get(&deps[idx].0).unwrap().name,
                                    lib_path.display(),
                                    e,
                                    outputs
                                        .keys()
                                        .map(|(_output, path)| path.display().to_string())
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                ));
                                result.verdict = CheckVerdict::Fail;
                            }
                        }
                    }
                    None => {
                        result.err.push(format!(
                            "executable dependency '{}' not in runtime deps, needed by {}",
                            needed_lib,
                            outputs
                                .keys()
                                .map(|(_output, path)| path.display().to_string())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ));
                        result.verdict = CheckVerdict::Fail;
                    }
                }
            }

            // Lets also check that all binary outputs which are scripts (i.e. start with a shebang) declare a runtime
            // dep providing the interpreter.
            for (bin_path, (output_name, interpreter)) in script_interpreters.into_iter() {
                let interpreter = interpreter.trim_start_matches("/");

                let satisfied = deps.iter().any(|(_bsr, cache_dir)| {
                    if cache_dir.path().join(interpreter).exists() {
                        return true;
                    }
                    if let Some(rest) = interpreter.strip_prefix("bin/")
                        && cache_dir.path().join("usr/bin").join(rest).exists()
                    {
                        return true;
                    }

                    false
                });

                if !satisfied {
                    result.err.push(format!(
                        "interpreter '{}' not in runtime deps, needed by script {} (output {})",
                        interpreter,
                        bin_path.display(),
                        output_name,
                    ));
                    result.verdict = CheckVerdict::Fail;
                }
            }

            Ok(result)
            })().map_err(|e| format!("{e}"))
        })
        .await
        .map_err(|e| Error::Other(anyhow!(e)))?
        .map_err(|e| Error::Other(anyhow!(e)))
    }
}

fn find_lib_in_deps(
    check_cache: &CheckCache,
    lib: &str,
    deps: &[(BuildSpecRef, DirCacheEntry<LocalDir>)],
) -> Result<Option<(usize, PathBuf)>, Error> {
    let glob = if lib.starts_with("/") {
        lib.to_string()
    } else {
        String::from("**/") + lib
    };

    for (i, (_bsr, dep_files)) in deps.iter().enumerate() {
        let base = dep_files.path();

        if let Some(candidate) = check_cache
            .match_files_for_glob(dep_files.path(), &glob)?
            .first()
        {
            return Ok(Some((
                i,
                candidate.strip_prefix(base).unwrap().to_path_buf(),
            )));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CheckCtx, CheckVerdict, GraphBasedChecker};
    use decode::Layer;
    use graph::Graph;
    use lcache::{Cache, EntryMeta, MetaInner};
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    /// Builds a minimal `CheckCtx` backed by a real `Cache<LocalDir>` rooted at
    /// `cache_dir`.  The directory must already exist before calling this helper.
    fn make_ctx(cache_dir: &std::path::Path, skip_checkers: Vec<String>) -> CheckCtx {
        let cache = Cache::at_dir(cache_dir).expect("Cache::at_dir");
        CheckCtx::new(
            vec![],
            skip_checkers,
            false,
            None,
            cache_dir.to_path_buf(),
            cache,
            None,
        )
    }

    /// Returns a unique temporary directory path under the system temp dir,
    /// creating it on disk so that `Cache::at_dir` (which calls `canonicalize`)
    /// succeeds.
    fn make_tmp_dir(suffix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "check_outputs_test_{}_{suffix}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create test tmp dir");
        dir
    }

    /// When "missing runtime_deps" appears in `skip_checkers`, the checker must
    /// return `CheckVerdict::Skip` immediately without inspecting the graph or
    /// the cache.
    #[tokio::test]
    async fn missing_runtime_deps_skip_via_skip_checkers() {
        let tmpdir = make_tmp_dir("skip_checkers");
        let ctx = make_ctx(&tmpdir, vec!["missing runtime_deps".to_string()]);

        let graph = Arc::new(RwLock::new(Graph::new()));
        let guard = graph.read().await;
        let result = MissingRuntimeDeps
            .check(&ctx, "any-pkg".to_string(), &tmpdir, guard, None)
            .await
            .expect("check should not error");

        assert!(
            matches!(result.verdict, CheckVerdict::Skip),
            "expected Skip when checker is in skip_checkers, got {:?}",
            result.verdict
        );

        std::fs::remove_dir_all(&tmpdir).expect("cleanup test tmp dir");
    }

    /// When the package name is not present in the graph, the checker must
    /// return `CheckVerdict::Skip` (it has nothing to check against).
    #[tokio::test]
    async fn missing_runtime_deps_skip_package_not_in_graph() {
        let tmpdir = make_tmp_dir("no_pkg");
        let ctx = make_ctx(&tmpdir, vec![]);

        let graph = Arc::new(RwLock::new(Graph::new()));
        let guard = graph.read().await;
        let result = MissingRuntimeDeps
            .check(
                &ctx,
                "nonexistent-package".to_string(),
                &tmpdir,
                guard,
                None,
            )
            .await
            .expect("check should not error");

        assert!(
            matches!(result.verdict, CheckVerdict::Skip),
            "expected Skip when package is absent from graph, got {:?}",
            result.verdict
        );

        std::fs::remove_dir_all(&tmpdir).expect("cleanup test tmp dir");
    }

    /// Serializes the `CARGO_MANIFEST_DIR` redirect in `graph_with_pkg` so
    /// concurrent ingesting tests never race on the process environment.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Ingests a single inline-Nickel package into a fresh graph and returns it
    /// wrapped for the checker. The package declares no runtime deps, so its
    /// transitive runtime-dep set is empty.
    ///
    /// `Layer::new_for_test` resolves `import "minimal.ncl"` relative to
    /// `CARGO_MANIFEST_DIR/minimal-ncl`, a directory the `check` crate does not
    /// ship. We point the variable at the `stdlib` crate (which owns the
    /// canonical `minimal-ncl`) for the duration of the parse, mirroring the
    /// redirect used by the `minimal` crate's tests.
    fn graph_with_pkg(nickel: &str) -> Arc<RwLock<Graph>> {
        let stdlib = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../stdlib")
            .canonicalize()
            .expect("stdlib crate dir must exist");
        let layer = {
            let _guard = ENV_LOCK.lock().expect("env lock");
            // SAFETY: every test that mutates CARGO_MANIFEST_DIR does so while
            // holding ENV_LOCK, and no other code in this test binary reads the
            // variable, so this set never races with another thread's access.
            unsafe {
                std::env::set_var("CARGO_MANIFEST_DIR", &stdlib);
            }
            Layer::new_for_test(nickel.to_string()).expect("parse test layer")
        };
        let graph = Graph::new().ingest(layer).expect("ingest test layer");
        Arc::new(RwLock::new(graph))
    }

    /// When the package exists in the graph but its build artifacts were never
    /// committed to the cache, the checker has nothing to inspect and must
    /// return `Skip` rather than erroring or failing.
    #[tokio::test]
    async fn missing_runtime_deps_skip_when_build_not_cached() {
        let tmpdir = make_tmp_dir("no_cached_build");
        let ctx = make_ctx(&tmpdir, vec![]);

        let graph = graph_with_pkg(
            r#"
            let {BuildSpec, OutputData, ..} = import "minimal.ncl" in
            {
                name = "uncached",
                build_deps = [],
                cmd = "",
                outputs = { out = {glob = "out"} | OutputData },
            } | BuildSpec
            "#,
        );
        let guard = graph.read().await;
        let result = MissingRuntimeDeps
            .check(&ctx, "uncached".to_string(), &tmpdir, guard, None)
            .await
            .expect("check should not error when the build is uncached");

        assert!(
            matches!(result.verdict, CheckVerdict::Skip),
            "expected Skip when the package build is absent from the cache, got {:?}",
            result.verdict
        );

        std::fs::remove_dir_all(&tmpdir).expect("cleanup test tmp dir");
    }

    /// A package whose only output is plain data (not an ELF object) imports no
    /// executable dependency, so the checker must report `Pass` with no errors.
    #[tokio::test]
    async fn missing_runtime_deps_pass_when_outputs_have_no_elf_imports() {
        let tmpdir = make_tmp_dir("pass_no_imports");
        let ctx = make_ctx(&tmpdir, vec![]);

        let graph = graph_with_pkg(
            r#"
            let {BuildSpec, OutputData, ..} = import "minimal.ncl" in
            {
                name = "datapkg",
                build_deps = [],
                cmd = "",
                outputs = { doc = {glob = "readme.txt"} | OutputData },
            } | BuildSpec
            "#,
        );

        // Fake a completed build: a single non-ELF data file. The checker should
        // collect no imports and no script interpreters from it.
        let spec_hash = {
            let g = graph.read().await;
            g.spec_hash(g.by_name("datapkg").expect("pkg in graph"))
        };
        let pending = ctx.cache.write_dir(&spec_hash).expect("write cache dir");
        std::fs::write(
            pending.path().join("readme.txt"),
            b"just some text, not an ELF binary",
        )
        .expect("write output file");
        pending
            .finalize(EntryMeta {
                inner: MetaInner::Spec("datapkg".to_string()),
                ..Default::default()
            })
            .expect("finalize cache entry");

        let guard = graph.read().await;
        let result = MissingRuntimeDeps
            .check(&ctx, "datapkg".to_string(), &tmpdir, guard, None)
            .await
            .expect("check should not error");

        assert!(
            matches!(result.verdict, CheckVerdict::Pass),
            "expected Pass when no output imports an executable dependency, got {:?} (errors: {:?})",
            result.verdict,
            result.err
        );
        assert!(
            result.err.is_empty(),
            "expected no errors on the Pass path, got {:?}",
            result.err
        );

        std::fs::remove_dir_all(&tmpdir).expect("cleanup test tmp dir");
    }

    /// A binary output that is a shebang script must declare a runtime dep that
    /// provides its interpreter. When no dep does, the checker must `Fail` and
    /// name the missing interpreter.
    #[tokio::test]
    async fn missing_runtime_deps_fails_when_script_interpreter_absent() {
        let tmpdir = make_tmp_dir("missing_interp");
        let ctx = make_ctx(&tmpdir, vec![]);

        let graph = graph_with_pkg(
            r#"
            let {BuildSpec, OutputBin, ..} = import "minimal.ncl" in
            {
                name = "scriptpkg",
                build_deps = [],
                cmd = "",
                outputs = {
                    bin = {glob = "run.sh", allow_missing_interpreter = false} | OutputBin,
                },
            } | BuildSpec
            "#,
        );

        // Fake a completed build whose only output is a shebang script whose
        // interpreter (/bin/sh) is provided by no runtime dependency.
        let spec_hash = {
            let g = graph.read().await;
            g.spec_hash(g.by_name("scriptpkg").expect("pkg in graph"))
        };
        let pending = ctx.cache.write_dir(&spec_hash).expect("write cache dir");
        std::fs::write(pending.path().join("run.sh"), b"#!/bin/sh\necho hi\n")
            .expect("write output file");
        pending
            .finalize(EntryMeta {
                inner: MetaInner::Spec("scriptpkg".to_string()),
                ..Default::default()
            })
            .expect("finalize cache entry");

        let guard = graph.read().await;
        let result = MissingRuntimeDeps
            .check(&ctx, "scriptpkg".to_string(), &tmpdir, guard, None)
            .await
            .expect("check should not error");

        assert!(
            matches!(result.verdict, CheckVerdict::Fail),
            "expected Fail when a script interpreter is not in runtime deps, got {:?}",
            result.verdict
        );
        assert!(
            result
                .err
                .iter()
                .any(|e| e.contains("interpreter") && e.contains("bin/sh")),
            "expected an error naming the missing interpreter, got {:?}",
            result.err
        );

        std::fs::remove_dir_all(&tmpdir).expect("cleanup test tmp dir");
    }
}
