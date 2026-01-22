use crate::Error;
use cache::{Cache, LocalDir};
use graph::DepGraph;
use nickel_lang_core::eval::cache::CacheImpl;
use nickel_lang_core::identifier::LocIdent;
use nickel_lang_core::program::Program;
use nickel_lang_core::term::Term;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::CheckResult;

pub(super) async fn check_harness(
    harness: String,
    all_graph: Option<Arc<Mutex<DepGraph>>>,
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
    program.add_import_paths([stdlib_dir].iter());

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
        harness,
        all_graph,
        fix,
        skip_checkers,
        harnesses_dir,
        &mut program,
        cache,
    )?);
    Ok(out)
}

fn check_harness_name(
    harness: String,
    _all_graph: Option<Arc<Mutex<DepGraph>>>,
    _fix: bool,
    skip_checkers: Vec<String>,
    _harnesses_dir: PathBuf,
    program: &mut Program<CacheImpl>,
    _cache: Cache<LocalDir>,
) -> Result<CheckResult, Error> {
    if skip_checkers.contains(&"harness name matches dir".to_string()) {
        return Ok(CheckResult::harness_name_skip());
    }

    // If we got this far, the nickel AST compiled fine, so lets try and pull out the harness name.
    if let Term::Record(rd) = program.eval_full().unwrap().as_ref()
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
