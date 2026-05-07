use super::Error;
use crate::{CheckCtx, CheckResult, CheckVerdict};
use decode::Stack;
use nickel_lang_core::eval::cache::CacheImpl;
use nickel_lang_core::identifier::LocIdent;
use nickel_lang_core::program::Program;
use ot::{OpTracker, Operation};
use std::path::PathBuf;

pub(crate) async fn check_stack(
    stack: String,
    ctx: &CheckCtx,
    stacks_dir: PathBuf,
) -> Result<Vec<CheckResult>, Error> {
    let check_op = OpTracker::new_with_root(&ctx.ot).with_op(Operation::Check {
        kind: ot::CheckKind::CheckStacks,
        name: stack.clone(),
    });
    let mut out = Vec::new();

    use nickel_lang_core::error::report::report_as_str;
    use nickel_lang_core::{error::NullReporter, eval::cache::CacheImpl, program::Program};

    // TODO: Transitioning from 'harness' => 'stack', remove after May 2026
    let program_res = if stacks_dir.join(&stack).join("harness.ncl").exists() {
        Program::new_from_source(
            std::io::Cursor::new(format!(
                "import \"{}\"",
                stacks_dir
                    .join(&stack)
                    .join("harness.ncl")
                    .as_os_str()
                    .to_str()
                    .unwrap()
            )),
            "toplevel",
            std::io::stderr(),
            NullReporter {},
        )
    } else {
        Program::new_from_source(
            std::io::Cursor::new(format!(
                "import \"{}\"",
                stacks_dir
                    .join(&stack)
                    .join("stack.ncl")
                    .as_os_str()
                    .to_str()
                    .unwrap()
            )),
            "toplevel",
            std::io::stderr(),
            NullReporter {},
        )
    };

    let mut program: Program<CacheImpl> = match program_res {
        Ok(p) => p,
        Err(e) => {
            return Ok(vec![CheckResult::parse_failure(format!(
                "loading failed: {}",
                e
            ))]);
        }
    };
    program.add_import_paths([ctx.stdlib_dir.clone()].iter());

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

    out.push(check_stack_name(stack.clone(), ctx, &mut program)?);
    out.push(check_stack_packages_valid(ctx, &mut program)?);
    out.push(check_project_matcher_regexes(ctx, &mut program)?);
    out.push(check_project_matcher_predicates(ctx, &mut program)?);
    use crate::FileBasedChecker;
    out.push(crate::ImportLineCheck.check(
        ctx,
        &stack,
        &stacks_dir.join(&stack),
        Some(check_op.clone()),
    )?);
    out.push(crate::FmtCheck.check(
        ctx,
        &stack,
        &stacks_dir.join(&stack),
        Some(check_op.clone()),
    )?);

    Ok(out)
}

fn check_stack_name(
    stack: String,
    ctx: &CheckCtx,
    program: &mut Program<CacheImpl>,
) -> Result<CheckResult, Error> {
    if ctx
        .skip_checkers
        .contains(&"stack name matches dir".to_string())
    {
        return Ok(CheckResult::stack_name_skip());
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
    if let Some(rd) = tree.as_record().and_then(|c| c.into_opt())
        && let Ok(Some(s)) = rd
            .get_value_with_ctrs(&LocIdent::new("name"))
            .map(|rt| rt.and_then(|t| t.to_nickel_string()))
    {
        if s.as_str() == stack {
            return Ok(CheckResult::stack_name_pass());
        } else {
            return Ok(CheckResult::stack_name_fail(format!(
                "stack defined in {}/stack.ncl has name {}",
                stack,
                s.as_str()
            )));
        }
    }
    Ok(CheckResult::stack_name_fail(
        "failed reading name from nickel object".to_string(),
    ))
}

fn check_stack_packages_valid(
    ctx: &CheckCtx,
    program: &mut Program<CacheImpl>,
) -> Result<CheckResult, Error> {
    let mut out = CheckResult {
        check: "packages valid".into(),
        verdict: CheckVerdict::Skip,
        err: vec![],
    };
    if ctx.skip_checkers.contains(&"packages valid".to_string()) {
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
    match Stack::from_term(&tree, program) {
        Ok(h) => {
            if let Some(g) = ctx.graph.as_ref()
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
            out.err.push(format!("failed loading stack: {}", e));
        }
    };

    Ok(out)
}

fn check_project_matcher_regexes(
    ctx: &CheckCtx,
    program: &mut Program<CacheImpl>,
) -> Result<CheckResult, Error> {
    if ctx
        .skip_checkers
        .contains(&"project_matchers regexes".to_string())
    {
        return Ok(CheckResult::stack_regexes_skip());
    }

    let tree = match program.eval_full() {
        Ok(t) => t,
        Err(e) => {
            return Err(Error::Graph(Box::new(graph::Error::Decode(
                decode::Error::Nickel(Box::new((program.files(), e))),
            ))));
        }
    };

    match Stack::from_term(&tree, program) {
        Ok(h) => {
            let mut out = CheckResult::stack_regexes_pass();
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
        Err(e) => Ok(CheckResult::stack_regexes_fail(format!(
            "failed loading stack: {}",
            e
        ))),
    }
}

fn check_project_matcher_predicates(
    ctx: &CheckCtx,
    program: &mut Program<CacheImpl>,
) -> Result<CheckResult, Error> {
    if ctx
        .skip_checkers
        .contains(&"project_matchers predicates".to_string())
    {
        return Ok(CheckResult::stack_predicates_skip());
    }

    let tree = match program.eval_full() {
        Ok(t) => t,
        Err(e) => {
            return Err(Error::Graph(Box::new(graph::Error::Decode(
                decode::Error::Nickel(Box::new((program.files(), e))),
            ))));
        }
    };

    match Stack::from_term(&tree, program) {
        Ok(h) => {
            let mut out = CheckResult::stack_predicates_pass();
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
        Err(e) => Ok(CheckResult::stack_predicates_fail(format!(
            "failed loading stack: {}",
            e
        ))),
    }
}
