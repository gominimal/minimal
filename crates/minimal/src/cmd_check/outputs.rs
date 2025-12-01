use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use super::{CheckResult, CheckVerdict};
use crate::{Context, Error};
use cache::{CacheErr, DirCacheEntry, LocalDir};
use graph::{BuildOutput, BuildSpecRef, DepGraph, Transitives};
use object::{Object, ObjectSymbol};

pub(crate) fn output_types_valid(
    pkg: &str,
    all_graph: &Option<DepGraph>,
    _fix: bool,
    ctx: &mut Context,
) -> Result<CheckResult, Error> {
    let mut result = CheckResult {
        verdict: CheckVerdict::Skip,
        check: "output types valid",
        err: vec![],
    };

    let all_graph = if let Some(all_graph) = all_graph {
        all_graph
    } else {
        return Ok(result); // skip, we need the full graph
    };

    let bsr = match all_graph.by_name(pkg) {
        Some(b) => *b,
        None => {
            return Ok(result); // skip, we need the build
        }
    };
    let build = all_graph.get(&bsr).unwrap();
    let cache = ctx.local_cache();
    let spec_hash = all_graph.spec_hash(&bsr);
    let cached_build = if let Ok(cached_build) = cache.read_dir(&spec_hash) {
        cached_build
    } else {
        return Ok(result); // skip, we need the cached build
    };

    result.verdict = CheckVerdict::Pass;
    for (name, output) in &build.outputs {
        let glob = match output {
            BuildOutput::Binary { glob }
            | BuildOutput::Library { glob }
            | BuildOutput::Data { glob } => glob,
        };
        for path in common::match_files_for_glob(cached_build.path(), glob)?.into_iter() {
            let data = std::fs::read(&path).map_err(anyhow::Error::from)?;
            match (object::File::parse(&*data), output) {
                (Ok(_), BuildOutput::Binary { .. } | BuildOutput::Library { .. }) => {}
                (Err(_), BuildOutput::Data { .. }) => {}
                (Ok(_), BuildOutput::Data { .. }) => {
                    result.verdict = CheckVerdict::Fail;
                    result.err.push(format!(
                        "data output \"{}\" matched binary/library file {}",
                        name,
                        path.strip_prefix(cached_build.path()).unwrap().display()
                    ));
                }
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

pub(crate) fn missing_runtime_deps(
    pkg: &str,
    all_graph: &Option<DepGraph>,
    _fix: bool,
    ctx: &mut Context,
) -> Result<CheckResult, Error> {
    let mut result = CheckResult {
        verdict: CheckVerdict::Skip,
        check: "missing runtime_deps",
        err: vec![],
    };

    let all_graph = if let Some(all_graph) = all_graph {
        all_graph
    } else {
        return Ok(result); // skip, we need the full graph
    };

    let bsr = match all_graph.by_name(pkg) {
        Some(b) => *b,
        None => {
            return Ok(result); // skip, we need the build
        }
    };
    let build = all_graph.get(&bsr).unwrap();
    let cache = ctx.local_cache();
    let spec_hash = all_graph.spec_hash(&bsr);
    let cached_build = if let Ok(cached_build) = cache.read_dir(&spec_hash) {
        cached_build
    } else {
        return Ok(result); // skip, we need the cached build
    };

    // We also need the builds of all the runtime_deps
    let transitives = Transitives::new(all_graph, &bsr, false)
        .transitive_runtime_deps
        .keys()
        .to_owned()
        .map(|dep| Ok::<_, CacheErr>((*dep, cache.read_dir(&all_graph.spec_hash(dep))?)))
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

    // Collect the ELF imports that each file in each bin/lib output wants.
    let mut all_imports: HashMap<String, HashMap<(&String, PathBuf), HashSet<String>>> =
        HashMap::with_capacity(1024);
    for (name, output) in &build.outputs {
        let glob = match output {
            BuildOutput::Binary { glob }
            | BuildOutput::Library { glob }
            | BuildOutput::Data { glob } => glob,
        };
        for path in common::match_files_for_glob(cached_build.path(), glob)?.into_iter() {
            let data = std::fs::read(&path).map_err(anyhow::Error::from)?;
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
                                    [((name, path_in_build.to_path_buf()), [symbol].into())]
                                        .into_iter(),
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
        }
    }
    for (needed_lib, outputs) in &all_imports {
        match find_lib_in_deps(needed_lib, &deps)? {
            Some((idx, lib_path)) => {
                // There was a library, check that all the symbols we need are present.
                let data = std::fs::read(deps[idx].1.path().join(&lib_path))
                    .map_err(anyhow::Error::from)?;
                match object::File::parse(&*data) {
                    Ok(elf) => {
                        // Valid executable, lets check all the imported symbols are present as exports.
                        let avail_symbols: HashSet<String> = elf
                            .exports()
                            .unwrap()
                            .iter()
                            .map(|e| String::from_utf8(e.name().to_vec()).unwrap())
                            .chain(elf.dynamic_symbols().map(|s| s.name().unwrap().to_string()))
                            .collect();
                        let missing_symbols: Vec<&String> = outputs
                            .values()
                            .flatten()
                            .filter(|sym| !avail_symbols.contains(*sym))
                            .collect();

                        if !missing_symbols.is_empty() {
                            result.err.push(format!(
                                "executable dependency '{}' at {}:{} missing symbols: {}. Needed by {}",
                                needed_lib,
                                all_graph.get(&deps[idx].0).unwrap().name,
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
                            all_graph.get(&deps[idx].0).unwrap().name,
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

        //println!("{}: {:?}", needed_lib, outputs);
    }

    Ok(result)
}

fn find_lib_in_deps(
    lib: &String,
    deps: &[(BuildSpecRef, DirCacheEntry<LocalDir>)],
) -> Result<Option<(usize, PathBuf)>, Error> {
    let glob = if lib.starts_with("/") {
        lib.to_string()
    } else {
        String::from("**/") + lib
    };

    for (i, (_bsr, dep_files)) in deps.iter().enumerate() {
        let base = dep_files.path();

        if let Some(candidate) = (common::match_files_for_glob(dep_files.path(), &glob)?)
            .into_iter()
            .next()
        {
            return Ok(Some((
                i,
                candidate.strip_prefix(base).unwrap().to_path_buf(),
            )));
        }
    }

    Ok(None)
}
