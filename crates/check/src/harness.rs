use super::Error;
use crate::CheckVerdict;
use cache::{Cache, LocalDir};
use decode::Harness;
use graph::Graph;
use nickel_lang_core::eval::cache::CacheImpl;
use nickel_lang_core::identifier::LocIdent;
use nickel_lang_core::program::Program;
use nickel_lang_core::term::Term;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::CheckResult;

pub(crate) async fn check_harness(
    harness: String,
    all_graph: Option<Arc<RwLock<Graph>>>,
    fix: bool,
    skip_checkers: Vec<String>,
    harnesses_dir: PathBuf,
    stdlib_dir: PathBuf,
    cache: Cache<LocalDir>,
) -> Result<Vec<CheckResult>, Error> {
    let mut out = Vec::new();

    use nickel_lang_core::error::report::report_as_str;
    use nickel_lang_core::{error::NullReporter, eval::cache::CacheImpl, program::Program};

    let program_res = Program::new_from_source(
        std::io::Cursor::new(format!(
            "import \"{}\"",
            harnesses_dir
                .join(&harness)
                .join("harness.ncl")
                .as_os_str()
                .to_str()
                .unwrap()
        )),
        "toplevel",
        std::io::stderr(),
        NullReporter {},
    );

    let mut program: Program<CacheImpl> = match program_res {
        Ok(p) => p,
        Err(e) => {
            return Ok(vec![CheckResult::parse_failure(format!(
                "loading failed: {}",
                e
            ))]);
        }
    };
    program.add_import_paths([stdlib_dir.clone()].iter());

    if let Err(e) = program.typecheck(nickel_lang_core::typecheck::TypecheckMode::Walk) {
        return Ok(vec![CheckResult::parse_failure(report_as_str(
            &mut program.files(),
            e,
            nickel_lang_core::error::report::ColorOpt::Never,
        ))]);
    }
    if let Err(e) = program.compile() {
        return Ok(vec![CheckResult::parse_failure(report_as_str(
            &mut program.files(),
            e,
            nickel_lang_core::error::report::ColorOpt::Never,
        ))]);
    }

    out.push(check_harness_name(
        harness.clone(),
        all_graph.clone(),
        fix,
        skip_checkers.clone(),
        harnesses_dir.clone(),
        &mut program,
        cache.clone(),
    )?);
    out.push(check_harness_packages_valid(
        harness.clone(),
        all_graph.clone(),
        fix,
        skip_checkers.clone(),
        harnesses_dir.clone(),
        &mut program,
        cache.clone(),
    )?);
    out.push(check_project_matcher_regexes(
        harness.clone(),
        all_graph.clone(),
        fix,
        skip_checkers.clone(),
        harnesses_dir.clone(),
        &mut program,
        cache.clone(),
    )?);
    out.push(check_project_matcher_predicates(
        harness.clone(),
        all_graph.clone(),
        fix,
        skip_checkers.clone(),
        harnesses_dir.clone(),
        &mut program,
        cache.clone(),
    )?);
    use crate::FileBasedChecker;
    out.push(crate::ImportLineCheck.check(
        &skip_checkers,
        fix,
        &harness,
        &harnesses_dir.join(&harness),
        &stdlib_dir,
    )?);
    out.push(crate::FmtCheck.check(
        &skip_checkers,
        fix,
        &harness,
        &harnesses_dir.join(&harness),
        &stdlib_dir,
    )?);
    Ok(out)
}

fn check_harness_name(
    harness: String,
    _all_graph: Option<Arc<RwLock<Graph>>>,
    _fix: bool,
    skip_checkers: Vec<String>,
    _harnesses_dir: PathBuf,
    program: &mut Program<CacheImpl>,
    _cache: Cache<LocalDir>,
) -> Result<CheckResult, Error> {
    if skip_checkers.contains(&"harness name matches dir".to_string()) {
        return Ok(CheckResult::harness_name_skip());
    }

    let tree = match program.eval_full() {
        Ok(t) => t,
        Err(e) => {
            return Err(Error::Graph(Box::new(graph::Error::Decode(
                decode::Error::Nickel(Box::new((program.files(), e))),
            ))));
        }
    };

    // If we got this far, the nickel AST compiled fine, so lets try and pull out the harness name.
    if let Term::Record(rd) = tree.as_ref()
        && let Ok(Some(Some(s))) = rd
            .get_value_with_ctrs(&LocIdent::new("name"))
            .map(|rt| rt.map(|t| t.term.to_nickel_string()))
    {
        if s.as_str() == harness {
            return Ok(CheckResult::harness_name_pass());
        } else {
            return Ok(CheckResult::harness_name_fail(format!(
                "harness defined in {}/harness.ncl has name {}",
                harness,
                s.as_str()
            )));
        }
    }
    Ok(CheckResult::harness_name_fail(
        "failed reading name from nickel object".to_string(),
    ))
}

fn check_harness_packages_valid(
    _harness: String,
    all_graph: Option<Arc<RwLock<Graph>>>,
    _fix: bool,
    skip_checkers: Vec<String>,
    _harnesses_dir: PathBuf,
    program: &mut Program<CacheImpl>,
    _cache: Cache<LocalDir>,
) -> Result<CheckResult, Error> {
    let mut out = CheckResult {
        check: "packages valid",
        verdict: CheckVerdict::Skip,
        err: vec![],
    };
    if skip_checkers.contains(&"packages valid".to_string()) {
        return Ok(out);
    }

    let tree = match program.eval_full() {
        Ok(t) => t,
        Err(e) => {
            return Err(Error::Graph(Box::new(graph::Error::Decode(
                decode::Error::Nickel(Box::new((program.files(), e))),
            ))));
        }
    };

    out.verdict = CheckVerdict::Pass;
    match Harness::from_term(&tree, program) {
        Ok(h) => {
            if let Some(g) = all_graph.as_ref()
                && let Ok(g) = g.try_read()
            {
                for pkg in &h.build_packages {
                    if g.by_name(pkg).is_none() {
                        out.verdict = CheckVerdict::Fail;
                        out.err
                            .push(format!("build package \"{}\" does not exist", pkg));
                    }
                }
                for pkg in &h.runtime_packages {
                    if g.by_name(pkg).is_none() {
                        out.verdict = CheckVerdict::Fail;
                        out.err
                            .push(format!("runtime package \"{}\" does not exist", pkg));
                    }
                }

                for matcher in h.matches_project_if_any.iter().flatten() {
                    for pkg in matcher
                        .build_package_matchers
                        .keys()
                        .chain(matcher.runtime_package_matchers.keys())
                    {
                        if g.by_name(pkg).is_none() {
                            out.verdict = CheckVerdict::Fail;
                            out.err.push(format!(
                                "predicate for package \"{}\" which does not exist",
                                pkg
                            ));
                        }
                    }
                }
            }
        }
        Err(e) => {
            out.verdict = CheckVerdict::Fail;
            out.err.push(format!("failed loading harness: {}", e));
        }
    };

    Ok(out)
}

fn check_project_matcher_regexes(
    _harness: String,
    _all_graph: Option<Arc<RwLock<Graph>>>,
    _fix: bool,
    skip_checkers: Vec<String>,
    _harnesses_dir: PathBuf,
    program: &mut Program<CacheImpl>,
    _cache: Cache<LocalDir>,
) -> Result<CheckResult, Error> {
    if skip_checkers.contains(&"project_matchers regexes".to_string()) {
        return Ok(CheckResult::harness_regexes_skip());
    }

    let tree = match program.eval_full() {
        Ok(t) => t,
        Err(e) => {
            return Err(Error::Graph(Box::new(graph::Error::Decode(
                decode::Error::Nickel(Box::new((program.files(), e))),
            ))));
        }
    };

    match Harness::from_term(&tree, program) {
        Ok(h) => {
            let mut out = CheckResult::harness_regexes_pass();
            for matcher in h.matches_project_if_any.iter().flatten() {
                for (fname, regex_str) in &matcher.file_regexes {
                    if regex_str == "*" {
                        continue;
                    }
                    if let Err(e) = regex::bytes::Regex::new(regex_str) {
                        out.verdict = CheckVerdict::Fail;
                        out.err.push(format!(
                            "invalid regex \"{}\" to match file {}: {}",
                            regex_str, fname, e
                        ));
                    }
                }
            }

            Ok(out)
        }
        Err(e) => Ok(CheckResult::harness_regexes_fail(format!(
            "failed loading harness: {}",
            e
        ))),
    }
}

fn check_project_matcher_predicates(
    _harness: String,
    _all_graph: Option<Arc<RwLock<Graph>>>,
    _fix: bool,
    skip_checkers: Vec<String>,
    _harnesses_dir: PathBuf,
    program: &mut Program<CacheImpl>,
    _cache: Cache<LocalDir>,
) -> Result<CheckResult, Error> {
    if skip_checkers.contains(&"project_matchers predicates".to_string()) {
        return Ok(CheckResult::harness_predicates_skip());
    }

    let tree = match program.eval_full() {
        Ok(t) => t,
        Err(e) => {
            return Err(Error::Graph(Box::new(graph::Error::Decode(
                decode::Error::Nickel(Box::new((program.files(), e))),
            ))));
        }
    };

    match Harness::from_term(&tree, program) {
        Ok(h) => {
            let mut out = CheckResult::harness_predicates_pass();
            for matcher in h.matches_project_if_any.iter().flatten() {
                for (fname, predicate_str) in &matcher.file_predicates {
                    if let Err(e) = common::jq::Expression::parse(predicate_str) {
                        out.verdict = CheckVerdict::Fail;
                        out.err.push(format!(
                            "invalid jq filter \"{}\" to match file {}: {:?}",
                            predicate_str, fname, e.err
                        ));
                    }
                }

                for (fname, predicate_str) in matcher
                    .build_package_matchers
                    .values()
                    .chain(matcher.runtime_package_matchers.values())
                    .flatten()
                    .flat_map(|p| p.file_predicates.iter())
                {
                    if let Err(e) = common::jq::Expression::parse(predicate_str) {
                        out.verdict = CheckVerdict::Fail;
                        out.err.push(format!(
                            "invalid jq filter \"{}\" to match file {}: {:?}",
                            predicate_str, fname, e.err
                        ));
                    }
                }
            }

            Ok(out)
        }
        Err(e) => Ok(CheckResult::harness_predicates_fail(format!(
            "failed loading harness: {}",
            e
        ))),
    }
}
