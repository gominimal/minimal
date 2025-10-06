use super::{CheckResult, CheckVerdict};
use crate::{Error, GlobalArgs};
use graph::DepGraph;

pub(crate) fn package_spec_name_matches_dir(
    pkg: &String,
    _all_graph: &Option<DepGraph>,
    _fix: bool,
    globals: &GlobalArgs,
) -> Result<CheckResult, Error> {
    let mut result = CheckResult {
        verdict: CheckVerdict::Skip,
        check: "spec name matches dir",
        err: vec![],
    };

    result.verdict = match globals.graph_from_package_name(pkg) {
        Ok(graph) => {
            if graph.get(&graph.top_levels[0]).unwrap().name == *pkg {
                CheckVerdict::Pass
            } else {
                CheckVerdict::Fail
            }
        }
        Err(_) => CheckVerdict::Skip,
    };

    Ok(result)
}

pub(crate) fn package_name(
    pkg: &String,
    all_graph: &Option<DepGraph>,
    _fix: bool,
    _globals: &GlobalArgs,
) -> Result<CheckResult, Error> {
    let mut result = CheckResult {
        verdict: CheckVerdict::Skip,
        check: "spec name valid",
        err: vec![],
    };

    result.verdict = if pkg.chars().all(|x| {
        (x.is_ascii_alphanumeric() && (!x.is_alphabetic() || x.is_ascii_lowercase()))
            || x == '_'
            || x == '-'
            || x == '.'
    }) {
        if all_graph
            .as_ref()
            .map(|g| g.by_name(pkg).count())
            .unwrap_or(1)
            != 1
        {
            result
                .err
                .push("Multiple build-specs exist with the same name".to_string());
            CheckVerdict::Fail
        } else {
            CheckVerdict::Pass
        }
    } else {
        result
            .err
            .push("Only lowercase a-z,0-9,-,., and _ allowed".to_string());
        CheckVerdict::Fail
    };

    Ok(result)
}

pub(crate) fn cycle_breaker_naming(
    pkg: &String,
    _all_graph: &Option<DepGraph>,
    _fix: bool,
    globals: &GlobalArgs,
) -> Result<CheckResult, Error> {
    let mut result = CheckResult {
        verdict: CheckVerdict::Skip,
        check: "cycle breaker naming",
        err: vec![],
    };

    result.verdict = match globals.graph_from_package_name(pkg) {
        Ok(graph) => {
            let build = graph.get(&graph.top_levels[0]).unwrap();
            if let Some(replace_on_cycle) = build.replace_on_cycle {
                let cycle_breaker = graph.get(&replace_on_cycle).unwrap();
                if cycle_breaker.name != format!("{} (prebuilt)", pkg) {
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
            }
        }
        Err(_) => CheckVerdict::Skip,
    };

    Ok(result)
}
