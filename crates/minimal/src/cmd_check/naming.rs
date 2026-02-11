use super::{CheckResult, CheckVerdict};
use crate::Error;
use cache::{Cache, LocalDir};
use graph::{BuildOutput, DepGraph};
use tokio::sync::RwLockReadGuard;

pub struct SpecNameMatchesDir;

impl super::GraphBasedChecker for SpecNameMatchesDir {
    async fn check(
        self,
        skip_checkers: &[String],
        _fix: bool,
        pkg: String,
        graph: RwLockReadGuard<'_, DepGraph>,
        _cache: Cache<LocalDir>,
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

pub struct SpecNameValid;

impl super::GraphBasedChecker for SpecNameValid {
    async fn check(
        self,
        skip_checkers: &[String],
        _fix: bool,
        pkg: String,
        _graph: RwLockReadGuard<'_, DepGraph>,
        _cache: Cache<LocalDir>,
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

pub struct CycleBreakerNaming;

impl super::GraphBasedChecker for CycleBreakerNaming {
    async fn check(
        self,
        skip_checkers: &[String],
        _fix: bool,
        pkg: String,
        graph: RwLockReadGuard<'_, DepGraph>,
        _cache: Cache<LocalDir>,
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

pub struct OutputNaming;

impl super::GraphBasedChecker for OutputNaming {
    async fn check(
        self,
        skip_checkers: &[String],
        _fix: bool,
        pkg: String,
        graph: RwLockReadGuard<'_, DepGraph>,
        _cache: Cache<LocalDir>,
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
                BuildOutput::Binary { glob }
                    if glob == "usr/bin/*" || glob == "usr/bin/**" || glob == "usr/bin/**/*" =>
                {
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
