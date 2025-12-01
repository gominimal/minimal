use super::{CheckResult, CheckVerdict};
use crate::{Context, Error};
use graph::{BuildOutput, DepGraph};

pub(crate) fn package_spec_name_matches_dir(
    pkg: &str,
    _all_graph: &Option<DepGraph>,
    _fix: bool,
    ctx: &mut Context,
) -> Result<CheckResult, Error> {
    let mut result = CheckResult {
        verdict: CheckVerdict::Skip,
        check: "spec name matches dir",
        err: vec![],
    };

    result.verdict = match ctx.graph_from_package_names(&[pkg.to_string()]) {
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
    pkg: &str,
    _all_graph: &Option<DepGraph>,
    _fix: bool,
    _ctx: &mut Context,
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
        CheckVerdict::Pass
    } else {
        result
            .err
            .push("Only lowercase a-z,0-9,-,., and _ allowed".to_string());
        CheckVerdict::Fail
    };

    Ok(result)
}

pub(crate) fn cycle_breaker_naming(
    pkg: &str,
    all_graph: &Option<DepGraph>,
    _fix: bool,
    _ctx: &mut Context,
) -> Result<CheckResult, Error> {
    let mut result = CheckResult {
        verdict: CheckVerdict::Skip,
        check: "cycle breaker naming",
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

    result.verdict = if let Some(replace_on_cycle) = build.replace_on_cycle {
        let cycle_breaker = all_graph.get(&replace_on_cycle).unwrap();
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
    };

    Ok(result)
}

pub(crate) fn output_naming(
    pkg: &str,
    all_graph: &Option<DepGraph>,
    _fix: bool,
    _ctx: &mut Context,
) -> Result<CheckResult, Error> {
    let mut result = CheckResult {
        verdict: CheckVerdict::Skip,
        check: "output naming",
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
            BuildOutput::Library { glob }
                if glob == "usr/lib/*" || glob == "usr/lib/**" || glob == "usr/lib/**/*" =>
            {
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
