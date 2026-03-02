use super::Error;
use crate::{CheckResult, CheckVerdict, FileBasedChecker};
use cache::{Cache, LocalDir};
use decode::Profile;
use graph::DepGraph;
use nickel_lang_core::error::report::report_as_str;
use nickel_lang_core::eval::cache::CacheImpl;
use nickel_lang_core::identifier::LocIdent;
use nickel_lang_core::program::Program;
use nickel_lang_core::term::Term;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

pub(crate) async fn check_profile(
    profile: String,
    all_graph: Option<Arc<RwLock<DepGraph>>>,
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

    out.push(check_profile_parses(
        profile.clone(),
        all_graph.clone(),
        fix,
        skip_checkers.clone(),
        profiles_dir.clone(),
        &mut program,
        cache.clone(),
    )?);
    out.push(check_profile_name(
        profile.clone(),
        all_graph,
        fix,
        skip_checkers.clone(),
        profiles_dir.clone(),
        &mut program,
        cache,
    )?);
    out.push(crate::ImportLineCheck.check(
        &skip_checkers,
        fix,
        &profile,
        &profiles_dir.join(&profile),
        &stdlib_dir,
    )?);
    out.push(crate::FmtCheck.check(
        &skip_checkers,
        fix,
        &profile,
        &profiles_dir.join(&profile),
        &stdlib_dir,
    )?);
    Ok(out)
}

fn check_profile_parses(
    _profile: String,
    _all_graph: Option<Arc<RwLock<DepGraph>>>,
    _fix: bool,
    skip_checkers: Vec<String>,
    _profiles_dir: PathBuf,
    program: &mut Program<CacheImpl>,
    _cache: Cache<LocalDir>,
) -> Result<CheckResult, Error> {
    let mut out = CheckResult {
        check: "profile parses",
        err: vec![],
        verdict: CheckVerdict::Pass,
    };

    if skip_checkers.contains(&"profile parses".to_string()) {
        out.verdict = CheckVerdict::Skip;
        return Ok(out);
    }

    let tree = match program.eval_full() {
        Ok(t) => t,
        Err(e) => {
            out.verdict = CheckVerdict::Fail;
            out.err.push(report_as_str(
                &mut program.files(),
                e,
                nickel_lang_core::error::report::ColorOpt::Never,
            ));
            return Ok(out);
        }
    };

    if let Err(e) = Profile::from_term(&tree, program) {
        out.verdict = CheckVerdict::Fail;
        match e {
            decode::Error::Nickel(b) => {
                let (files, e) = *b;
                out.err.push(report_as_str(
                    &mut files.clone(),
                    e,
                    nickel_lang_core::error::report::ColorOpt::Never,
                ));
            }
            _ => {
                out.err.push(format!("error when decoding profile: {}", e));
            }
        }
    }

    Ok(out)
}

fn check_profile_name(
    profile: String,
    _all_graph: Option<Arc<RwLock<DepGraph>>>,
    _fix: bool,
    skip_checkers: Vec<String>,
    _profiles_dir: PathBuf,
    program: &mut Program<CacheImpl>,
    _cache: Cache<LocalDir>,
) -> Result<CheckResult, Error> {
    if skip_checkers.contains(&"profile name matches dir".to_string()) {
        return Ok(CheckResult::profile_name_skip());
    }

    let tree = match program.eval_full() {
        Ok(t) => t,
        Err(e) => {
            return Err(Error::Graph(Box::new(graph::Error::Decode(
                decode::Error::Nickel(Box::new((program.files(), e))),
            ))));
        }
    };

    // If we got this far, the nickel AST compiled fine, so lets try and pull out the profile name.
    if let Term::Record(rd) = tree.as_ref()
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
