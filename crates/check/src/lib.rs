//! Implements `minimal check` logic - for linting Minimal configuration including
//! `minimal.toml`, packages, profiles, and harnesses.
//!
//! Run checkers using [`run_checks`].

#![allow(clippy::result_large_err)]

use anyhow::anyhow;
use futures::stream::FuturesUnordered;
use graph::Graph;
use lcache::{Cache, CacheErr, LocalDir};
use op::{Options, Runnable, StandaloneTest};
use ot::{OpTracker, Operation};
use regex::Regex;
use std::cmp::Ordering;
use std::fmt;
use std::fmt::Display;
use std::future::Future;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use tokio::sync::{RwLock, RwLockReadGuard};

/// A shared buffer that implements [`tokio::io::AsyncWrite`], allowing captured
/// output to be retrieved after the writer is consumed.
#[derive(Clone)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl SharedBuf {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }

    fn into_string(self) -> String {
        let buf = match Arc::try_unwrap(self.0) {
            Ok(mutex) => mutex.into_inner().unwrap(),
            Err(arc) => arc.lock().unwrap().clone(),
        };
        String::from_utf8_lossy(&buf).into_owned()
    }
}

impl tokio::io::AsyncWrite for SharedBuf {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.0.lock().unwrap().extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

mod harness;
mod naming;
mod outputs;
mod profile;

use outputs::{MissingRuntimeDeps, OutputTypesValid};

/// The errors possible when running checkers.
#[derive(Debug)]
pub enum Error {
    IO(&'static str, PathBuf, std::io::Error),
    Graph(Box<graph::Error>),
    Other(anyhow::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::IO(ctx, path, e) => {
                write!(f, "{} I/O error at path {}: {}", ctx, path.display(), e)
            }
            Error::Graph(e) => write!(f, "graph: {:?}", e),
            Error::Other(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IO(_, _, e) => Some(e),
            Error::Graph(_e) => None,
            Error::Other(_e) => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum CheckVerdict {
    Fail,
    Fixed,
    Skip,
    Pass,
}

impl Display for CheckVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckVerdict::Fail => write!(f, "Fail"),
            CheckVerdict::Fixed => write!(f, "Fixed"),
            CheckVerdict::Skip => write!(f, "Skip"),
            CheckVerdict::Pass => write!(f, "Pass"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CheckResult {
    pub check: &'static str,
    pub verdict: CheckVerdict,
    pub err: Vec<String>,
}

impl CheckResult {
    pub(crate) fn parse_failure(msg: String) -> Self {
        CheckResult {
            check: "parse",
            verdict: CheckVerdict::Fail,
            err: vec![msg],
        }
    }

    pub(crate) fn profile_name_skip() -> Self {
        CheckResult {
            check: "profile name matches dir",
            verdict: CheckVerdict::Skip,
            err: vec![],
        }
    }

    pub(crate) fn profile_name_pass() -> Self {
        CheckResult {
            check: "profile name matches dir",
            verdict: CheckVerdict::Pass,
            err: vec![],
        }
    }

    pub(crate) fn profile_name_fail(msg: String) -> Self {
        CheckResult {
            check: "profile name matches dir",
            verdict: CheckVerdict::Fail,
            err: vec![msg],
        }
    }

    pub(crate) fn harness_name_skip() -> Self {
        CheckResult {
            check: "harness name matches dir",
            verdict: CheckVerdict::Skip,
            err: vec![],
        }
    }
    pub(crate) fn harness_name_pass() -> Self {
        CheckResult {
            check: "harness name matches dir",
            verdict: CheckVerdict::Pass,
            err: vec![],
        }
    }
    pub(crate) fn harness_name_fail(msg: String) -> Self {
        CheckResult {
            check: "harness name matches dir",
            verdict: CheckVerdict::Fail,
            err: vec![msg],
        }
    }

    pub(crate) fn harness_regexes_skip() -> Self {
        CheckResult {
            check: "project_matchers regexes",
            verdict: CheckVerdict::Skip,
            err: vec![],
        }
    }
    pub(crate) fn harness_regexes_pass() -> Self {
        CheckResult {
            check: "project_matchers regexes",
            verdict: CheckVerdict::Pass,
            err: vec![],
        }
    }
    pub(crate) fn harness_regexes_fail(msg: String) -> Self {
        CheckResult {
            check: "project_matchers regexes",
            verdict: CheckVerdict::Fail,
            err: vec![msg],
        }
    }

    pub(crate) fn harness_predicates_skip() -> Self {
        CheckResult {
            check: "project_matchers predicates",
            verdict: CheckVerdict::Skip,
            err: vec![],
        }
    }
    pub(crate) fn harness_predicates_pass() -> Self {
        CheckResult {
            check: "project_matchers predicates",
            verdict: CheckVerdict::Pass,
            err: vec![],
        }
    }
    pub(crate) fn harness_predicates_fail(msg: String) -> Self {
        CheckResult {
            check: "project_matchers predicates",
            verdict: CheckVerdict::Fail,
            err: vec![msg],
        }
    }
}

/// The specific object check results are about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckObj {
    Package(String),
    Harness(String),
    Profile(String),
}

impl Display for CheckObj {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckObj::Package(n) => write!(f, "package: {}", n),
            CheckObj::Harness(n) => write!(f, "harness: {}", n),
            CheckObj::Profile(n) => write!(f, "profile: {}", n),
        }
    }
}

/// A future that resolves to a heading (e.g. "package: foo") and check results.
pub type CheckFuture =
    std::pin::Pin<Box<dyn Future<Output = (CheckObj, Result<Vec<CheckResult>, Error>)> + Send>>;

/// Runs checkers, returning a [`FuturesUnordered`] that yields results as each check completes.
///
/// If `None` is given for a `packages_dir`, `profiles_dir`, or `harnesses_dir`, the corresponding
/// class of checkers are skipped.
#[allow(clippy::too_many_arguments)]
pub fn run_checks(
    packages_dir: Option<PathBuf>,
    profiles_dir: Option<PathBuf>,
    harnesses_dir: Option<PathBuf>,
    stdlib_dir: PathBuf,
    filter_names: &[String],
    graph: Option<Graph>,
    cache: Cache<LocalDir>,
    fix: bool,
    skip_checkers: &[String],
    ot: Option<OpTracker>,
) -> Result<FuturesUnordered<CheckFuture>, Error> {
    let graph_hnd = graph.map(|g| Arc::new(RwLock::new(g)));
    let skip_checkers_owned = skip_checkers.to_vec();
    let filter_names_owned = filter_names.to_vec();

    let results = if let Some(packages_dir) = packages_dir {
        package_check_futures(
            packages_dir,
            filter_names_owned.clone(),
            graph_hnd.clone(),
            skip_checkers_owned.clone(),
            stdlib_dir.clone(),
            cache.clone(),
            fix,
            ot.clone(),
        )?
    } else {
        vec![]
    };

    let profile_results = if let Some(profiles_dir) = profiles_dir {
        profile_check_futures(
            profiles_dir,
            filter_names_owned.clone(),
            graph_hnd.clone(),
            skip_checkers_owned.clone(),
            stdlib_dir.clone(),
            cache.clone(),
            fix,
            ot.clone(),
        )?
    } else {
        vec![]
    };

    let harness_results = if let Some(harnesses_dir) = harnesses_dir {
        harness_check_futures(
            harnesses_dir,
            filter_names_owned,
            graph_hnd,
            skip_checkers_owned,
            stdlib_dir,
            cache,
            fix,
            ot,
        )?
    } else {
        vec![]
    };

    Ok(results
        .into_iter()
        .chain(profile_results)
        .chain(harness_results)
        .collect::<FuturesUnordered<_>>())
}

#[allow(clippy::too_many_arguments)]
fn package_check_futures(
    packages_dir: PathBuf,
    filter_names: Vec<String>,
    graph_hnd: Option<Arc<RwLock<Graph>>>,
    skip_checkers: Vec<String>,
    stdlib_dir: PathBuf,
    cache: Cache<LocalDir>,
    fix: bool,
    ot: Option<OpTracker>,
) -> Result<Vec<CheckFuture>, Error> {
    let package_dirs = match decode::build_decls_in_dir(&packages_dir) {
        Ok(i) => i,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(Error::IO("reading package dirs", packages_dir.clone(), e)),
    }
    .into_iter()
    // Filter based on any given filter names
    .filter_map(|fpath| {
        let dir = fpath.parent().unwrap();
        let pkg = dir.file_name().unwrap().to_str().unwrap().to_string();
        if filter_names.is_empty() || filter_names.contains(&pkg) {
            Some((pkg, dir.to_path_buf()))
        } else {
            None
        }
    });

    Ok(package_dirs
        .into_iter()
        .map::<CheckFuture, _>(move |(pkg, dir)| {
            let graph_hnd = graph_hnd.clone();
            let skip_checkers = skip_checkers.clone();
            let stdlib_dir = stdlib_dir.clone();
            let cache = cache.clone();
            let ot = ot.clone();
            Box::pin(async move {
                let result = check_package(
                    pkg.clone(),
                    dir,
                    graph_hnd,
                    fix,
                    skip_checkers,
                    stdlib_dir,
                    cache,
                    ot,
                );
                (CheckObj::Package(pkg), result.await)
            })
        })
        .collect::<Vec<_>>())
}

#[allow(clippy::too_many_arguments)]
fn profile_check_futures(
    profiles_dir: PathBuf,
    filter_names: Vec<String>,
    graph_hnd: Option<Arc<RwLock<Graph>>>,
    skip_checkers: Vec<String>,
    stdlib_dir: PathBuf,
    cache: Cache<LocalDir>,
    fix: bool,
    ot: Option<OpTracker>,
) -> Result<Vec<CheckFuture>, Error> {
    let dirs: Vec<std::ffi::OsString> = match std::fs::read_dir(&profiles_dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(Error::IO("reading profile dirs", profiles_dir.clone(), e)),
        Ok(dirs) => dirs
            .filter_map(|e| match e {
                Err(e) => Some(Err(e)),
                Ok(e) => {
                    if !e.file_type().unwrap().is_dir() {
                        None
                    } else {
                        Some(Ok(e.file_name()))
                    }
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Error::IO("listing profiles", profiles_dir.clone(), e))?
            .into_iter()
            // Filter based on any given filter names
            .filter_map(|dir| {
                let n = dir.as_os_str().to_str().unwrap().to_string();
                if filter_names.is_empty() || filter_names.contains(&n) {
                    Some(dir)
                } else {
                    None
                }
            })
            .collect(),
    };

    Ok(dirs
        .into_iter()
        .map::<CheckFuture, _>(move |pd| {
            let graph_hnd = graph_hnd.clone();
            let skip_checkers = skip_checkers.clone();
            let stdlib_dir = stdlib_dir.clone();
            let cache = cache.clone();
            let profiles_dir = profiles_dir.clone();
            let ot = ot.clone();

            Box::pin(async move {
                (
                    CheckObj::Profile(pd.to_str().unwrap().to_string()),
                    profile::check_profile(
                        pd.to_str().unwrap().to_string(),
                        graph_hnd,
                        fix,
                        skip_checkers.clone(),
                        profiles_dir,
                        stdlib_dir,
                        cache,
                        ot,
                    )
                    .await,
                )
            })
        })
        .collect())
}

#[allow(clippy::too_many_arguments)]
fn harness_check_futures(
    harnesses_dir: PathBuf,
    filter_names: Vec<String>,
    graph_hnd: Option<Arc<RwLock<Graph>>>,
    skip_checkers: Vec<String>,
    stdlib_dir: PathBuf,
    cache: Cache<LocalDir>,
    fix: bool,
    ot: Option<OpTracker>,
) -> Result<Vec<CheckFuture>, Error> {
    let dirs: Vec<std::ffi::OsString> = match std::fs::read_dir(&harnesses_dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(Error::IO("reading harness dirs", harnesses_dir.clone(), e)),
        Ok(dirs) => dirs
            .filter_map(|e| match e {
                Err(e) => Some(Err(e)),
                Ok(e) => {
                    if !e.file_type().unwrap().is_dir() {
                        None
                    } else {
                        Some(Ok(e.file_name()))
                    }
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Error::IO("listing harnesses", harnesses_dir.clone(), e))?
            .into_iter()
            // Filter based on any given filter names
            .filter_map(|dir| {
                let n = dir.as_os_str().to_str().unwrap().to_string();
                if filter_names.is_empty() || filter_names.contains(&n) {
                    Some(dir)
                } else {
                    None
                }
            })
            .collect(),
    };

    Ok(dirs
        .into_iter()
        .map::<CheckFuture, _>(move |pd| {
            let graph_hnd = graph_hnd.clone();
            let skip_checkers = skip_checkers.clone();
            let stdlib_dir = stdlib_dir.clone();
            let cache = cache.clone();
            let harnesses_dir = harnesses_dir.clone();
            let ot = ot.clone();

            Box::pin(async move {
                (
                    CheckObj::Harness(pd.to_str().unwrap().to_string()),
                    harness::check_harness(
                        pd.to_str().unwrap().to_string(),
                        graph_hnd,
                        fix,
                        skip_checkers.clone(),
                        harnesses_dir,
                        stdlib_dir,
                        cache,
                        ot,
                    )
                    .await,
                )
            })
        })
        .collect())
}

#[allow(clippy::too_many_arguments)]
async fn check_package(
    pkg: String,
    package_dir: PathBuf,
    all_graph: Option<Arc<RwLock<Graph>>>,
    fix: bool,
    skip_checkers: Vec<String>,
    stdlib_dir: PathBuf,
    cache: Cache<LocalDir>,
    ot: Option<OpTracker>,
) -> Result<Vec<CheckResult>, Error> {
    let check_op = OpTracker::new_with_root(&ot).with_op(Operation::Check {
        kind: ot::CheckKind::CheckPackages,
        name: pkg.clone(),
    });

    let mut out = Vec::new();

    if let Some(graph) = all_graph {
        // Run all graph-based checkers concurrently. Errors are converted
        // to String at the boundary so the results are Send.
        macro_rules! run_checker {
            ($checker:expr) => {
                async {
                    $checker
                        .check(
                            &skip_checkers,
                            fix,
                            pkg.clone(),
                            package_dir.as_ref(),
                            graph.read().await,
                            cache.clone(),
                            Some(check_op.clone()),
                        )
                        .await
                        .map_err(|e| format!("{e}"))
                }
            };
        }

        let (r1, r2, r3, r4, r5, r6, r7, r8, r9, r10) = tokio::join!(
            run_checker!(naming::SpecNameMatchesDir),
            run_checker!(naming::SpecNameValid),
            run_checker!(naming::CycleBreakerNaming),
            run_checker!(naming::OutputNaming),
            run_checker!(naming::EnumerateBins),
            run_checker!(OutputTypesValid),
            run_checker!(MissingRuntimeDeps),
            run_checker!(BuildScriptIsExecutable),
            run_checker!(BuildScriptDisallowedPatterns),
            run_checker!(StandaloneTestCheck),
        );
        for r in [r1, r2, r3, r4, r5, r6, r7, r8, r9, r10] {
            out.push(r.map_err(|e| Error::Other(anyhow!(e)))?);
        }
    }

    // Run file-based checkers in a separate thread as they're computation-heavy
    let file_based_results = {
        let skip_checkers = skip_checkers.clone();
        let pkg = pkg.clone();
        let stdlib_dir = stdlib_dir.clone();

        tokio::task::spawn_blocking(move || {
            let file_based: Vec<Box<dyn FileBasedChecker>> = vec![
                Box::new(ParseCheck),
                Box::new(ImportLineCheck),
                Box::new(AdjacentImportCheck),
                Box::new(FmtCheck),
            ];

            let mut results = Vec::new();
            for mut c in file_based.into_iter() {
                let check_result = c
                    .as_mut()
                    .check(
                        &skip_checkers,
                        fix,
                        &pkg,
                        &package_dir,
                        &stdlib_dir,
                        Some(check_op.clone()),
                    )
                    .map_err(|e| format!("{:?}", e))?;
                results.push(check_result);
            }
            Ok::<Vec<CheckResult>, String>(results)
        })
        .await
        .map_err(|s| Error::Other(anyhow::Error::from(s)))?
        .map_err(|e| Error::Other(anyhow!(e)))?
    };

    out.extend(file_based_results);

    Ok(out)
}

/// A checker which checks a package by looking at its files. These checkers
/// are run serially.
pub(crate) trait FileBasedChecker: Send {
    fn check(
        &mut self,
        skip_checkers: &[String],
        fix: bool,
        pkg: &str,
        pkg_dir: &Path,
        stdlib_dir: &Path,
        ot: Option<OpTracker>,
    ) -> Result<CheckResult, Error>;
}

/// A checker which checks a package by looking at its representation in the graph.
/// These checkers are run in parallel.
#[allow(clippy::too_many_arguments)]
pub(crate) trait GraphBasedChecker {
    async fn check(
        self,
        skip_checkers: &[String],
        fix: bool,
        pkg: String,
        package_dir: &Path,
        graph: RwLockReadGuard<'_, Graph>,
        cache: Cache<LocalDir>,
        ot: Option<OpTracker>,
    ) -> Result<CheckResult, Error>;
}

/// A [FileBasedChecker] that check the build.ncl file parses.
struct ParseCheck;

impl FileBasedChecker for ParseCheck {
    fn check(
        &mut self,
        skip_checkers: &[String],
        _fix: bool,
        _pkg: &str,
        pkg_dir: &Path,
        stdlib_dir: &Path,
        _ot: Option<OpTracker>,
    ) -> Result<CheckResult, Error> {
        if skip_checkers.contains(&"parse".to_string()) {
            return Ok(CheckResult {
                check: "parse",
                verdict: CheckVerdict::Skip,
                err: vec![],
            });
        }

        use nickel_lang_core::error::report::report_as_str;
        use nickel_lang_core::{error::NullReporter, eval::cache::CacheImpl, program::Program};

        let program_res = Program::new_from_source(
            std::io::Cursor::new(format!(
                "import \"{}\"",
                pkg_dir.join("build.ncl").as_os_str().to_str().unwrap()
            )),
            "toplevel",
            std::io::stderr(),
            NullReporter {},
        );

        let mut program: Program<CacheImpl> = match program_res {
            Ok(p) => p,
            Err(e) => {
                return Ok(CheckResult {
                    check: "parse",
                    verdict: CheckVerdict::Fail,
                    err: vec![format!("{}", e)],
                });
            }
        };

        let generated_lib_dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            generated_lib_dir.path().join("__injected_config__.ncl"),
            b"{target = {arch = 'Amd64, os = 'Linux}}",
        )
        .unwrap();
        program.add_import_paths([stdlib_dir, generated_lib_dir.path()].iter());

        if let Err(e) = program.typecheck(nickel_lang_core::typecheck::TypecheckMode::Walk) {
            return Ok(CheckResult {
                check: "parse",
                verdict: CheckVerdict::Fail,
                err: vec![report_as_str(
                    &mut program.files(),
                    e,
                    nickel_lang_core::error::report::ColorOpt::Never,
                )],
            });
        }
        if let Err(e) = program.compile() {
            return Ok(CheckResult {
                check: "parse",
                verdict: CheckVerdict::Fail,
                err: vec![report_as_str(
                    &mut program.files(),
                    e,
                    nickel_lang_core::error::report::ColorOpt::Never,
                )],
            });
        }

        drop(generated_lib_dir);
        Ok(CheckResult {
            check: "parse",
            verdict: CheckVerdict::Pass,
            err: vec![],
        })
    }
}

static MINIMAL_IMPORT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"let\s*\{\s*([^}]+)\s*\}\s*=\s*import\s+"minimal\.ncl"\s+in"#)
        .expect("Invalid regex pattern")
});

pub(crate) struct ImportLineCheck;

impl FileBasedChecker for ImportLineCheck {
    fn check(
        &mut self,
        skip_checkers: &[String],
        fix: bool,
        _pkg: &str,
        pkg_dir: &Path,
        _stdlib_dir: &Path,
        _ot: Option<OpTracker>,
    ) -> Result<CheckResult, Error> {
        let mut result = CheckResult {
            verdict: CheckVerdict::Pass,
            check: "import line",
            err: vec![],
        };
        if skip_checkers.contains(&"import line".to_string()) {
            result.verdict = CheckVerdict::Skip;
            return Ok(result);
        }

        for e in std::fs::read_dir(pkg_dir)
            .map_err(|e| Error::IO("reading nickel dir", pkg_dir.to_path_buf(), e))?
        {
            let e =
                e.map_err(|e| Error::IO("enumerating nickel file", pkg_dir.to_path_buf(), e))?;
            if e.file_type().unwrap().is_dir() {
                continue;
            }
            let name = e.file_name();
            if !name.to_str().unwrap().ends_with(".ncl") {
                continue;
            }

            let file_contents = String::from_utf8(
                std::fs::read(e.path()).map_err(|e2| Error::IO("reading nickel", e.path(), e2))?,
            )
            .map_err(|e2| Error::Other(anyhow!("decoding nickel file as utf8: {}", e2)))?;

            if let Some(captures) = &MINIMAL_IMPORT_REGEX.captures(&file_contents) {
                let overall = captures.get(0).unwrap();
                let identifiers_str = captures.get(1).unwrap().as_str();

                // Split by comma and clean up whitespace, filter out ".."
                let identifiers: Vec<&str> = identifiers_str
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty() && *s != "..")
                    .collect();

                // Filter identifiers which arent used, if not in fix mode then report
                let rest = &file_contents[overall.end()..];
                let used_identifiers = identifiers
                    .iter()
                    .filter_map(|ident| {
                        if !rest.contains(ident) {
                            if !fix {
                                result.err.push(format!(
                                    "{}: {} imported but not used",
                                    name.to_str().unwrap(),
                                    ident
                                ));
                            }
                            None
                        } else {
                            Some(*ident)
                        }
                    })
                    .collect::<Vec<_>>();

                let mut sorted_identifiers = used_identifiers.clone();
                sorted_identifiers.sort_by(|a, b| {
                    let a_is_lower = a.chars().next().unwrap_or('\0').is_ascii_lowercase();
                    let b_is_lower = b.chars().next().unwrap_or('\0').is_ascii_lowercase();

                    match (a_is_lower, b_is_lower) {
                        // Both lowercase or both uppercase - use normal string comparison
                        (true, true) | (false, false) => a.cmp(b),
                        // a is lowercase, b is uppercase - a comes first
                        (true, false) => Ordering::Less,
                        // a is uppercase, b is lowercase - b comes first
                        (false, true) => Ordering::Greater,
                    }
                });

                if !fix && sorted_identifiers != used_identifiers {
                    result.err.push(format!(
                        "{}: identifiers not in canonical order",
                        name.to_str().unwrap()
                    ));
                }
                if fix
                    && (sorted_identifiers != used_identifiers || identifiers != used_identifiers)
                {
                    let fixed = format!(
                        "let {{ {}, .. }} = import \"minimal.ncl\" in",
                        sorted_identifiers.join(", ")
                    );
                    let mut new_file_contents = file_contents.clone();
                    new_file_contents.replace_range(overall.start()..overall.end(), &fixed);
                    std::fs::write(e.path(), new_file_contents)
                        .map_err(|e2| Error::IO("writing fixed nickel", e.path(), e2))?;
                    result.verdict = CheckVerdict::Fixed;
                }
            }
        }

        if !result.err.is_empty() {
            result.verdict = CheckVerdict::Fail;
        }
        Ok(result)
    }
}

pub(crate) struct FmtCheck;

impl FileBasedChecker for FmtCheck {
    fn check(
        &mut self,
        skip_checkers: &[String],
        fix: bool,
        _pkg: &str,
        pkg_dir: &Path,
        _stdlib_dir: &Path,
        _ot: Option<OpTracker>,
    ) -> Result<CheckResult, Error> {
        let mut result = CheckResult {
            verdict: CheckVerdict::Skip,
            check: "fmt",
            err: vec![],
        };
        if skip_checkers.contains(&"fmt".to_string()) {
            return Ok(result);
        }

        for e in std::fs::read_dir(pkg_dir)
            .map_err(|e| Error::IO("reading nickel dir", pkg_dir.to_path_buf(), e))?
        {
            let e =
                e.map_err(|e| Error::IO("enumerating nickel file", pkg_dir.to_path_buf(), e))?;
            if e.file_type().unwrap().is_dir() {
                continue;
            }
            let name = e.file_name();
            if !name.to_str().unwrap().ends_with(".ncl") {
                continue;
            }

            let data =
                std::fs::read(e.path()).map_err(|e2| Error::IO("reading nickel", e.path(), e2))?;
            let mut out: Vec<u8> = Vec::with_capacity(2048);

            match nickel_lang_core::format::format(&data[..], &mut out) {
                Err(e) => {
                    result.err.push(format!(
                        "formatting {} failed: {:?}",
                        name.to_str().unwrap(),
                        e
                    ));
                    result.verdict = CheckVerdict::Skip;
                }
                Ok(()) => {
                    if data != out {
                        if fix {
                            std::fs::write(e.path(), out)
                                .map_err(|e2| Error::IO("writing fixed nickel", e.path(), e2))?;
                            result.verdict = CheckVerdict::Fixed;
                        } else {
                            result.verdict = CheckVerdict::Fail;
                        }
                    } else {
                        result.verdict = CheckVerdict::Pass;
                    }
                }
            }
        }

        Ok(result)
    }
}

struct StandaloneTestCheck;

impl GraphBasedChecker for StandaloneTestCheck {
    async fn check(
        self,
        skip_checkers: &[String],
        _fix: bool,
        pkg: String,
        _package_dir: &Path,
        graph: RwLockReadGuard<'_, Graph>,
        cache: Cache<LocalDir>,
        ot: Option<OpTracker>,
    ) -> Result<CheckResult, Error> {
        let mut result = CheckResult {
            verdict: CheckVerdict::Skip,
            check: "standalone tests",
            err: vec![],
        };
        if skip_checkers.contains(&"standalone tests".to_string()) {
            return Ok(result);
        }

        let bsr = match graph.by_name(&pkg) {
            Some(b) => *b,
            None => {
                return Ok(result); // skip, we need the build
            }
        };
        let build = graph.get(&bsr).unwrap().clone();

        result.verdict = CheckVerdict::Pass;
        if let Some(tests) = build.tests {
            let graph2 = graph.deref().clone();
            drop(graph);
            result = tokio::task::spawn(async move {
                let mut result = result;
                for (name, test) in tests {
                    if test.build_test {
                        continue; // We only do standalone tests here
                    }
                    let temp_dir = cache.temp_dir().map_err(anyhow::Error::from)?;

                    let stdout_buf = SharedBuf::new();
                    let stderr_buf = SharedBuf::new();
                    let mut t = StandaloneTest {
                        spec: &bsr,
                        test_name: name.as_str(),
                        stdout_writer: Some(Box::new(stdout_buf.clone())),
                        stderr_writer: Some(Box::new(stderr_buf.clone())),
                    };
                    let opts = Options {
                        cache: cache.clone(),
                        exec_base: temp_dir.path().to_path_buf(),
                        graph: &graph2,
                        ot: ot.clone(),
                    };

                    match t.run(&opts).await {
                        Ok(errors) => {
                            if !errors.is_empty() {
                                result.verdict = CheckVerdict::Fail;
                                errors.iter().for_each(|e| {
                                    result.err.push(format!(
                                        "{}: {} {} had exit code {}",
                                        name,
                                        e.program,
                                        e.args.join(" "),
                                        e.exit_code
                                    ))
                                });
                                let stdout = stdout_buf.into_string();
                                let stderr = stderr_buf.into_string();
                                if !stdout.is_empty() {
                                    result.err.push(format!("stdout:\n{}", stdout));
                                }
                                if !stderr.is_empty() {
                                    result.err.push(format!("stderr:\n{}", stderr));
                                }
                            }
                        }
                        Err(op::Error::Cache(CacheErr::NotFound)) => {
                            result.verdict = CheckVerdict::Skip;
                            return Ok(result);
                        }
                        Err(e) => {
                            return Err(anyhow::Error::from(e)
                                .context(format!("running tests for spec {}", build.name))
                                .context(format!("failed setup for test {}", name)));
                        }
                    }
                }
                Ok::<_, anyhow::Error>(result)
            })
            .await
            .map_err(|e| Error::Other(anyhow::Error::from(e)))?
            .map_err(Error::Other)?;
        }

        Ok(result)
    }
}

static ADJACENT_IMPORT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"let\s+(\w+)\s+=\s+import\s+"\.\.\/([^\/]+)\/[^"]+"\s+in"#)
        .expect("Invalid regex pattern")
});

struct AdjacentImportCheck;

impl FileBasedChecker for AdjacentImportCheck {
    fn check(
        &mut self,
        skip_checkers: &[String],
        _fix: bool,
        _pkg: &str,
        pkg_dir: &Path,
        _stdlib_dir: &Path,
        _ot: Option<OpTracker>,
    ) -> Result<CheckResult, Error> {
        let mut result = CheckResult {
            verdict: CheckVerdict::Pass,
            check: "adjacent import",
            err: vec![],
        };
        if skip_checkers.contains(&"adjacent import".to_string()) {
            result.verdict = CheckVerdict::Skip;
            return Ok(result);
        }

        for e in std::fs::read_dir(pkg_dir)
            .map_err(|e| Error::IO("reading nickel dir", pkg_dir.to_path_buf(), e))?
        {
            let e =
                e.map_err(|e| Error::IO("enumerating nickel file", pkg_dir.to_path_buf(), e))?;
            if e.file_type().unwrap().is_dir() {
                continue;
            }
            let name = e.file_name();
            if !name.to_str().unwrap().ends_with(".ncl") {
                continue;
            }

            let file_contents = String::from_utf8(
                std::fs::read(e.path()).map_err(|e2| Error::IO("reading nickel", e.path(), e2))?,
            )
            .map_err(|e2| Error::Other(anyhow!("decoding nickel file as utf8: {}", e2)))?;

            for captures in ADJACENT_IMPORT_REGEX.captures_iter(&file_contents) {
                let end_idx = captures.get_match().end();
                let identifier = captures.get(1).unwrap().as_str();
                let folder = captures.get(2).unwrap().as_str();

                if identifier != folder {
                    result.err.push(format!(
                        "{}: identifier '{}' doesn't match folder '{}' in import",
                        name.to_str().unwrap(),
                        identifier,
                        folder
                    ));
                    result.verdict = CheckVerdict::Fail;
                }

                if let Some((_before, after)) = file_contents.split_at_checked(end_idx)
                    && !after.contains(identifier)
                {
                    result.err.push(format!(
                        "{}: adjacent package '{}' imported but not used",
                        name.to_str().unwrap(),
                        identifier,
                    ));
                    result.verdict = CheckVerdict::Fail;
                }
            }
        }

        Ok(result)
    }
}

/// Regexes that build scripts are audited against. If any match, the check fails.
static BUILD_SCRIPT_AUDIT_REGEXES: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        (
            Regex::new(r"\btar\s+-?xf\b").unwrap(),
            "use 'tar -xof' instead of 'tar -xf' to extract archives in build scripts",
        ),
        (
            Regex::new(r"(?m)^(?:[^/#\n][^\n]*)?\bSOURCE_DATE_EPOCH\s*=\s*0").unwrap(),
            "SOURCE_DATE_EPOCH=0 is already set by the build sandbox",
        ),
        (
            Regex::new(r"(?m)^(?:[^/#\n][^\n]*)?\bPYTHONHASHSEED\s*=\s*0").unwrap(),
            "PYTHONHASHSEED=0 is already set by the build sandbox",
        ),
    ]
});

struct BuildScriptDisallowedPatterns;

impl GraphBasedChecker for BuildScriptDisallowedPatterns {
    async fn check(
        self,
        skip_checkers: &[String],
        _fix: bool,
        pkg: String,
        _package_dir: &Path,
        graph: RwLockReadGuard<'_, Graph>,
        _cache: Cache<LocalDir>,
        _ot: Option<OpTracker>,
    ) -> Result<CheckResult, Error> {
        let mut result = CheckResult {
            verdict: CheckVerdict::Skip,
            check: "build script disallowed-patterns",
            err: vec![],
        };
        if skip_checkers.contains(&"build script disallowed-patterns".to_string()) {
            return Ok(result);
        }

        let bsr = match graph.by_name(&pkg) {
            None => return Ok(result),
            Some(bsr) => bsr,
        };
        let build = graph.get(bsr).unwrap();
        result.verdict = CheckVerdict::Pass;

        // Check inline build commands.
        for cmd in &build.cmds {
            let cmd_str = cmd.join(" ");
            for (regex, msg) in BUILD_SCRIPT_AUDIT_REGEXES.iter() {
                if regex.is_match(&cmd_str) {
                    result.verdict = CheckVerdict::Fail;
                    result.err.push(format!("build cmd '{}': {}", cmd_str, msg));
                }
            }
        }

        // Check contents of local build script files.
        for dep in &build.build_deps {
            if let graph::BuildDep::Local {
                full_path,
                filename,
                ..
            } = dep
            {
                let contents = match std::fs::read_to_string(full_path) {
                    Ok(c) => c,
                    Err(e) => {
                        result.verdict = CheckVerdict::Fail;
                        result
                            .err
                            .push(format!("failed to read build script {}: {}", filename, e));
                        continue;
                    }
                };

                for (regex, msg) in BUILD_SCRIPT_AUDIT_REGEXES.iter() {
                    for m in regex.find_iter(&contents) {
                        result.verdict = CheckVerdict::Fail;
                        let line_num = contents[..m.start()].lines().count() + 1;
                        result
                            .err
                            .push(format!("{} line {}: {}", filename, line_num, msg));
                    }
                }
            }
        }

        Ok(result)
    }
}

struct BuildScriptIsExecutable;

impl GraphBasedChecker for BuildScriptIsExecutable {
    async fn check(
        self,
        skip_checkers: &[String],
        _fix: bool,
        pkg: String,
        _package_dir: &Path,
        graph: RwLockReadGuard<'_, Graph>,
        _cache: Cache<LocalDir>,
        _ot: Option<OpTracker>,
    ) -> Result<CheckResult, Error> {
        let mut result = CheckResult {
            verdict: CheckVerdict::Skip,
            check: "build scripts are executable",
            err: vec![],
        };
        if skip_checkers.contains(&"build scripts are executable".to_string()) {
            return Ok(result);
        }

        let bsr = match graph.by_name(&pkg) {
            None => {
                return Ok(result); // skip
            }
            Some(bsr) => bsr,
        };
        let build = graph.get(bsr).unwrap();
        result.verdict = CheckVerdict::Pass;

        let local_build_deps = build
            .build_deps
            .iter()
            .filter_map(|i| match i {
                graph::BuildDep::Local {
                    full_path,
                    filename,
                    file_hash: _,
                } => Some((full_path.clone(), filename.clone())),
                _ => None,
            })
            .collect::<Vec<_>>();

        for cmd in &build.cmds {
            if cmd.is_empty() {
                continue;
            }
            if let Some(exec) = &cmd[0].strip_prefix("./")
                && let Some((path, name)) =
                    local_build_deps.iter().find(|(_path, name)| name == exec)
            {
                match std::fs::metadata(path) {
                    Err(e) => {
                        result.verdict = CheckVerdict::Fail;
                        result
                            .err
                            .push(format!("failed stat for build script {}: {}", name, e));
                    }
                    Ok(s) => {
                        use std::os::unix::fs::PermissionsExt;
                        if s.is_dir() {
                            result.verdict = CheckVerdict::Fail;
                            result
                                .err
                                .push(format!("build script {} is a directory", name));
                        } else if (s.permissions().mode() & 0o111) == 0 {
                            result.verdict = CheckVerdict::Fail;
                            result.err.push(format!(
                                "build script {} is not executable: got mode={:#o}",
                                name,
                                s.permissions().mode() & 0x0fff
                            ));
                        }
                    }
                }
            }
        }

        Ok(result)
    }
}
