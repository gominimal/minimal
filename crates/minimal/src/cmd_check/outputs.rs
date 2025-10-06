use std::path::{Path, PathBuf};

use super::{CheckResult, CheckVerdict};
use crate::{Error, GlobalArgs};
use cache::{DirCacheEntry, LocalDir};
use graph::{BuildOutput, DepGraph};

pub(crate) fn output_types_valid(
    pkg: &String,
    all_graph: &Option<DepGraph>,
    _fix: bool,
    globals: &GlobalArgs,
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

    let bsr = match all_graph.by_name(pkg).next() {
        Some(b) => b,
        None => {
            return Ok(result); // skip, we need the build
        }
    };
    let build = all_graph.get(&bsr).unwrap();
    let cache = globals.cache().map_err(anyhow::Error::from)?;
    let spec_hash = all_graph.spec_hash(&bsr);
    let cached_build = if let Ok(cached_build) = cache.read_dir(&spec_hash) {
        cached_build
    } else {
        return Ok(result); // skip, we need the cached build
    };

    result.verdict = CheckVerdict::Pass;
    for (name, output) in &build.outputs {
        for path in match_paths_for_output(&cached_build, output)?.into_iter() {
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

fn match_paths_for_output(
    cached_build: &DirCacheEntry<LocalDir>,
    output: &BuildOutput,
) -> Result<Vec<PathBuf>, Error> {
    let mut results = Vec::new();

    let matcher = globset::GlobBuilder::new(match output {
        BuildOutput::Binary { glob }
        | BuildOutput::Library { glob }
        | BuildOutput::Data { glob } => glob,
    })
    .literal_separator(true)
    .empty_alternates(true)
    .build()
    .map_err(anyhow::Error::from)?
    .compile_matcher();

    // Walk the filesystem starting from root_dir
    fn walk_dir(
        dir: &Path,
        root_dir: &Path,
        matcher: &globset::GlobMatcher,
        results: &mut Vec<PathBuf>,
    ) -> Result<(), Error> {
        let entries = std::fs::read_dir(dir).map_err(anyhow::Error::from)?;

        for entry in entries {
            let entry = entry.map_err(anyhow::Error::from)?;

            let path = entry.path();
            let subset = path.strip_prefix(root_dir).unwrap();
            if path.is_file() && matcher.is_match(subset) {
                results.push(path);
            } else if path.is_dir() {
                // Recursively walk subdirectories
                walk_dir(&path, root_dir, matcher, results)?;
            }
        }

        Ok(())
    }

    let root_dir = cached_build.path();
    walk_dir(root_dir, root_dir, &matcher, &mut results)?;
    Ok(results)
}
