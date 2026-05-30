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
    use lcache::Cache;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    /// A minimal RAII temp-directory that does not require the `tempfile` crate.
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(label: &str) -> Self {
            use std::time::{SystemTime, UNIX_EPOCH};
            let ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos();
            let path = std::env::temp_dir().join(format!(
                "check-test-{}-{}-{}",
                label,
                std::process::id(),
                ns,
            ));
            std::fs::create_dir_all(&path).expect("create tmp dir");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Returns a `CheckCtx` with a fresh cache and an empty `Graph` wrapped in an
    /// `Arc<RwLock<>>`, plus the lock guard needed by `GraphBasedChecker::check`.
    async fn make_ctx_with_graph(
        cache_root: &Path,
        skip_checkers: Vec<String>,
    ) -> (
        CheckCtx,
        Arc<RwLock<Graph>>,
        tokio::sync::RwLockReadGuard<'static, Graph>,
    ) {
        // Leak the Arc so we can return a 'static guard.  The memory is reclaimed
        // when the process exits (tests are short-lived).
        let graph_arc: Arc<RwLock<Graph>> = Arc::new(RwLock::new(Graph::new()));
        // SAFETY: the Arc is never dropped (intentional for test scaffolding); the
        // RwLock is valid for the process lifetime, so the returned guard is sound.
        let static_arc: &'static RwLock<Graph> = unsafe { &*Arc::as_ptr(&graph_arc) };
        let guard = static_arc.read().await;

        let cache = Cache::at_dir(cache_root).expect("cache init");
        let ctx = CheckCtx::new(
            vec![],
            skip_checkers,
            false,
            None,
            PathBuf::from("/dev/null"),
            cache,
            None,
        );
        (ctx, graph_arc, guard)
    }

    /// When `"missing runtime_deps"` is listed in `skip_checkers`, the checker must
    /// return `Skip` immediately without inspecting the graph or cache.
    #[tokio::test]
    async fn skip_checkers_bypasses_runtime_deps_check() {
        let tmp = TmpDir::new("skip-checkers");
        let (ctx, _arc, guard) =
            make_ctx_with_graph(tmp.path(), vec!["missing runtime_deps".to_string()]).await;

        let result = MissingRuntimeDeps
            .check(&ctx, "any-pkg".into(), Path::new("/dev/null"), guard, None)
            .await
            .unwrap();

        assert!(
            matches!(result.verdict, CheckVerdict::Skip),
            "expected Skip when checker is disabled, got {:?}",
            result.verdict
        );
    }

    /// A package name that is not registered in the graph must yield `Skip`.
    /// The checker cannot inspect a build it has no knowledge of.
    #[tokio::test]
    async fn unknown_package_name_returns_skip() {
        let tmp = TmpDir::new("unknown-pkg");
        let (ctx, _arc, guard) = make_ctx_with_graph(tmp.path(), vec![]).await;

        let result = MissingRuntimeDeps
            .check(
                &ctx,
                "no-such-package".into(),
                Path::new("/dev/null"),
                guard,
                None,
            )
            .await
            .unwrap();

        assert!(
            matches!(result.verdict, CheckVerdict::Skip),
            "expected Skip for unknown package, got {:?}",
            result.verdict
        );
    }
}
