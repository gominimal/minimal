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

pub(super) async fn check_profile(
    profile: String,
    all_graph: Option<Arc<Mutex<DepGraph>>>,
    fix: bool,
    skip_checkers: Vec<String>,
    profiles_dir: PathBuf,
    stdlib_dir: PathBuf,
    cache: Cache<LocalDir>,
) -> Result<Vec<CheckResult>, Error> {
    let mut out = Vec::new();

    use nickel_lang_core::error::report::report_as_str;
    use nickel_lang_core::{error::NullReporter, eval::cache::CacheImpl, program::Program};

    let program_res = Program::new_from_source(
        std::io::Cursor::new(format!(
            "import \"{}\"",
            profiles_dir
                .join(&profile)
                .join("profile.ncl")
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

    out.push(check_profile_name(
        profile,
        all_graph,
        fix,
        skip_checkers,
        profiles_dir,
        &mut program,
        cache,
    )?);
    Ok(out)
}

fn check_profile_name(
    profile: String,
    _all_graph: Option<Arc<Mutex<DepGraph>>>,
    _fix: bool,
    skip_checkers: Vec<String>,
    _profiles_dir: PathBuf,
    program: &mut Program<CacheImpl>,
    _cache: Cache<LocalDir>,
) -> Result<CheckResult, Error> {
    if skip_checkers.contains(&"profile name matches dir".to_string()) {
        return Ok(CheckResult::profile_name_skip());
    }

    // If we got this far, the nickel AST compiled fine, so lets try and pull out the profile name.
    if let Term::Record(rd) = program.eval_full().unwrap().as_ref()
        && let Ok(Some(Some(s))) = rd
            .get_value_with_ctrs(&LocIdent::new("name"))
            .map(|rt| rt.map(|t| t.term.to_nickel_string()))
    {
        if s.as_str() == profile {
            return Ok(CheckResult::profile_name_pass());
        } else {
            return Ok(CheckResult::profile_name_fail(format!(
                "profile defined in {}/profile.ncl has name {}",
                profile,
                s.as_str()
            )));
        }
    }
    Ok(CheckResult::profile_name_fail(
        "failed reading name from nickel object".to_string(),
    ))
}
