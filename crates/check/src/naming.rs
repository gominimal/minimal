use super::Error;
use crate::{CheckResult, CheckVerdict};
use graph::{BuildOutput, Graph};
use lcache::{Cache, LocalDir};
use ot::OpTracker;
use tokio::sync::RwLockReadGuard;

pub(crate) struct SpecNameMatchesDir;

impl crate::GraphBasedChecker for SpecNameMatchesDir {
    async fn check(
        self,
        skip_checkers: &[String],
        _fix: bool,
        pkg: String,
        graph: RwLockReadGuard<'_, Graph>,
        _cache: Cache<LocalDir>,
        _ot: Option<OpTracker>,
    ) -> Result<CheckResult, Error> {
        let mut result = CheckResult {
            verdict: CheckVerdict::Skip,
            check: "spec name matches dir",
            err: vec![],
        };
        if skip_checkers.contains(&"spec name matches dir".to_string()) {
            return Ok(result);
        }

        let bsr = match graph.by_name(&pkg) {
            None => {
                result.verdict = CheckVerdict::Fail;
                return Ok(result);
            }
            Some(bsr) => bsr,
        };
        result.verdict = if graph.get(bsr).unwrap().name == pkg.as_str() {
            CheckVerdict::Pass
        } else {
            CheckVerdict::Fail
        };

        Ok(result)
    }
}

pub(crate) struct SpecNameValid;

impl crate::GraphBasedChecker for SpecNameValid {
    async fn check(
        self,
        skip_checkers: &[String],
        _fix: bool,
        pkg: String,
        _graph: RwLockReadGuard<'_, Graph>,
        _cache: Cache<LocalDir>,
        _ot: Option<OpTracker>,
    ) -> Result<CheckResult, Error> {
        let mut result = CheckResult {
            verdict: CheckVerdict::Skip,
            check: "spec name valid",
            err: vec![],
        };
        if skip_checkers.contains(&"spec name valid".to_string()) {
            return Ok(result);
        }

        result.verdict = if pkg.chars().all(|x| {
            (x.is_ascii_alphanumeric() && (!x.is_alphabetic() || x.is_ascii_lowercase()))
                || x == '_'
                || x == '-'
                || x == '.'
        }) {
            CheckVerdict::Pass
        } else {
            result
                .err
                .push("Only lowercase a-z,0-9,-,., and _ allowed".to_string());
            CheckVerdict::Fail
        };

        Ok(result)
    }
}

pub(crate) struct CycleBreakerNaming;

impl crate::GraphBasedChecker for CycleBreakerNaming {
    async fn check(
        self,
        skip_checkers: &[String],
        _fix: bool,
        pkg: String,
        graph: RwLockReadGuard<'_, Graph>,
        _cache: Cache<LocalDir>,
        _ot: Option<OpTracker>,
    ) -> Result<CheckResult, Error> {
        let mut result = CheckResult {
            verdict: CheckVerdict::Skip,
            check: "cycle breaker naming",
            err: vec![],
        };
        if skip_checkers.contains(&"cycle breaker naming".to_string()) {
            return Ok(result);
        }

        let bsr = match graph.by_name(&pkg) {
            Some(b) => *b,
            None => {
                return Ok(result); // skip, we need the build
            }
        };
        let build = graph.get(&bsr).unwrap();

        result.verdict = if let Some(replace_on_cycle) = build.replace_on_cycle {
            let cycle_breaker = graph.get(&replace_on_cycle).unwrap();
            if cycle_breaker.name != format!("{} (prebuilt)", &pkg) {
                result.err.push(format!(
                    "cycle breaker should be named '{} (prebuilt)' instead if '{}'",
                    pkg, cycle_breaker.name
                ));
                CheckVerdict::Fail
            } else {
                CheckVerdict::Pass
            }
        } else {
            CheckVerdict::Pass
        };

        Ok(result)
    }
}

pub(crate) struct OutputNaming;

impl crate::GraphBasedChecker for OutputNaming {
    async fn check(
        self,
        skip_checkers: &[String],
        _fix: bool,
        pkg: String,
        graph: RwLockReadGuard<'_, Graph>,
        _cache: Cache<LocalDir>,
        _ot: Option<OpTracker>,
    ) -> Result<CheckResult, Error> {
        let mut result = CheckResult {
            verdict: CheckVerdict::Skip,
            check: "output naming",
            err: vec![],
        };
        if skip_checkers.contains(&"output naming".to_string()) {
            return Ok(result);
        }

        let bsr = match graph.by_name(&pkg) {
            Some(b) => *b,
            None => {
                return Ok(result); // skip, we need the build
            }
        };
        let build = graph.get(&bsr).unwrap();

        result.verdict = CheckVerdict::Pass;
        for (name, output) in &build.outputs {
            match output {
                BuildOutput::Binary {
                    glob,
                    allow_missing_interpreter: _,
                } if glob == "usr/bin/*" || glob == "usr/bin/**" || glob == "usr/bin/**/*" => {
                    if name != "bins" {
                        result.err.push(format!(
                                "{}: binary output {}: catch-all binary outputs should be named 'bins' by convention",
                                pkg, name
                            ));
                    }
                }
                BuildOutput::Library {
                    glob,
                    allow_data: _,
                } if glob == "usr/lib/*" || glob == "usr/lib/**" || glob == "usr/lib/**/*" => {
                    if name != "libs" {
                        result.err.push(format!(
                                "{}: library output '{}': catch-all library outputs should be named 'libs' by convention",
                                pkg, name
                            ));
                    }
                }
                _ => {}
            }
        }

        if !result.err.is_empty() {
            result.verdict = CheckVerdict::Fail;
        }
        Ok(result)
    }
}

pub(crate) struct EnumerateBins;

impl crate::GraphBasedChecker for EnumerateBins {
    async fn check(
        self,
        skip_checkers: &[String],
        _fix: bool,
        pkg: String,
        graph: RwLockReadGuard<'_, Graph>,
        cache: Cache<LocalDir>,
        _ot: Option<OpTracker>,
    ) -> Result<CheckResult, Error> {
        let mut result = CheckResult {
            verdict: CheckVerdict::Skip,
            check: "enumerate bins",
            err: vec![],
        };
        if skip_checkers.contains(&"enumerate bins".to_string()) {
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
        let bins_dir = cached_build.path().join("usr/bin");
        if !bins_dir.exists() {
            return Ok(result);
        }

        let mut collected_bins = std::fs::read_dir(&bins_dir)
            .map_err(|e| Error::IO("listing bins", bins_dir.clone(), e))?
            .map(|e| match e {
                Err(e) => Err(e),
                Ok(e) => Ok(e.file_name().to_str().unwrap().to_string()),
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Error::IO("stat binary", bins_dir, e))?;

        let has_bins_wildcard = build.outputs.iter().any(|o| {
            matches!(o.1, BuildOutput::Binary { glob, allow_missing_interpreter: _ }
            if glob == "usr/bin/*" || glob == "usr/bin/**" || glob == "usr/bin/**/*")
        });
        if !has_bins_wildcard {
            // Not part of the problem.
            return Ok(result);
        }

        // Retain only bins in `collected_bins` which don't have a corresponding output.
        collected_bins.retain(|b| {
            !build
                .outputs
                .iter()
                .any(|(name, o)| b == name && matches!(o, BuildOutput::Binary { .. }))
        });

        if collected_bins.len() > 6 || collected_bins.is_empty() {
            // We don't yell about enumerating bins if theres TONS of them.
            return Ok(result);
        }

        // Whats left are binaries that need to be made OutputBin entries.
        result.err.push(format!(
            "when theres only a few binaries, they should be enumerated explicitly as their own output. Found: {}",
            collected_bins.join(",")
        ));
        result.verdict = CheckVerdict::Fail;
        Ok(result)
    }
}
