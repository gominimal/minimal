use crate::cmd_check::outputs::{MissingRuntimeDeps, OutputTypesValid};
use crate::{Context, Error, PackagesArg};
use anyhow::anyhow;
use cache::{Cache, CacheErr, LocalDir};
use graph::DepGraph;

use codespan_reporting::term::termcolor::{
    Color, ColorChoice, ColorSpec, StandardStream, WriteColor,
};
use op::{Options, Runnable, StandaloneTest};
use regex::Regex;
use std::cmp::Ordering;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

mod naming;
mod outputs;

#[derive(clap::Args)]
pub struct CheckArgs {
    /// Attempt to fix any issues
    #[arg(short, long, default_value_t = false)]
    fix: bool,

    #[command(flatten)]
    packages: PackagesArg,

    /// Checker names to skip, comma-separated
    #[arg(short, long, alias="skip", value_delimiter=',', num_args=0..)]
    skip_checkers: Option<Vec<String>>,
}

pub async fn cmd_check(args: CheckArgs, ctx: &mut Context) -> Result<(), Error> {
    let all_graph = ctx.graph_from_all_packages();
    let packages_dir = ctx.upstream_dir_and_origin()?.0.join("packages");

    if args.fix && packages_dir.strip_prefix(ctx.paths().vcs_dir()).is_ok() {
        return Err(anyhow!("--fix can only be used when --upstream-dir is specified").into());
    }

    let packages_dirs = std::fs::read_dir(packages_dir)
        .map_err(anyhow::Error::from)?
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
        .map_err(anyhow::Error::from)?;

    let upstream_dir = ctx.upstream_dir_and_origin()?.0;
    let iter = packages_dirs
        .into_iter()
        // Filter based on the packages argument
        .filter_map(|pkg| {
            let want_pkgs = args.packages.names();
            let pkg = pkg.to_str().unwrap().to_string();
            if want_pkgs.is_empty() || want_pkgs.contains(&pkg) {
                Some(pkg)
            } else {
                None
            }
        })
        .map(|pkg| {
            let packages_dir = upstream_dir.join("packages");
            let stdlib_dir = ctx.stdlib_dir();

            let result = check_package(
                pkg.clone(),
                all_graph.as_ref().ok(),
                args.fix,
                args.skip_checkers.clone().unwrap_or_default(),
                packages_dir,
                stdlib_dir,
                ctx.local_cache(),
            );
            (pkg, result)
        });

    let mut had_error = false;
    let mut stdout = StandardStream::stdout(ColorChoice::Auto);
    for (pkg, result) in iter {
        stdout.set_color(ColorSpec::new().set_fg(None)).unwrap();
        let result = result.await?;
        stdout.set_color(ColorSpec::new().set_fg(None)).unwrap();

        writeln!(&mut stdout, "\npackage: {}", pkg).unwrap();
        for check in result {
            write!(&mut stdout, "{}...", check.check).unwrap();
            match check.verdict {
                CheckVerdict::Fail => {
                    had_error = true;
                    stdout
                        .set_color(ColorSpec::new().set_fg(Some(Color::Red)))
                        .unwrap();
                    writeln!(&mut stdout, "Fail").unwrap();
                }
                CheckVerdict::Fixed => {
                    stdout
                        .set_color(ColorSpec::new().set_fg(Some(Color::Blue)))
                        .unwrap();
                    writeln!(&mut stdout, "Fixed").unwrap();
                }
                CheckVerdict::Skip => {
                    stdout
                        .set_color(ColorSpec::new().set_fg(Some(Color::Yellow)))
                        .unwrap();
                    writeln!(&mut stdout, "Skip").unwrap();
                }
                CheckVerdict::Pass => {
                    stdout
                        .set_color(ColorSpec::new().set_fg(Some(Color::Green)))
                        .unwrap();
                    writeln!(&mut stdout, "Pass").unwrap();
                }
            }
            stdout.set_color(ColorSpec::new().set_fg(None)).unwrap();

            for err in check.err {
                writeln!(&mut stdout, "\t{}", err).unwrap();
            }
        }
    }

    match had_error {
        true => Err(anyhow::anyhow!("One or more checkers reported a failure").into()),
        false => match all_graph {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        },
    }
}

#[derive(Debug, Clone)]
enum CheckVerdict {
    Fail,
    Fixed,
    Skip,
    Pass,
}

#[derive(Debug, Clone)]
struct CheckResult {
    check: &'static str,
    verdict: CheckVerdict,
    err: Vec<String>,
}

async fn check_package(
    pkg: String,
    all_graph: Option<&DepGraph>,
    fix: bool,
    skip_checkers: Vec<String>,
    packages_dir: PathBuf,
    stdlib_dir: PathBuf,
    cache: Cache<LocalDir>,
) -> Result<Vec<CheckResult>, Error> {
    let mut out = Vec::new();

    if let Some(graph) = all_graph {
        out.push(
            naming::SpecNameMatchesDir
                .check(&skip_checkers, fix, pkg.clone(), graph, cache.clone())
                .await?,
        );
        out.push(
            naming::SpecNameValid
                .check(&skip_checkers, fix, pkg.clone(), graph, cache.clone())
                .await?,
        );
        out.push(
            naming::CycleBreakerNaming
                .check(&skip_checkers, fix, pkg.clone(), graph, cache.clone())
                .await?,
        );
        out.push(
            naming::OutputNaming
                .check(&skip_checkers, fix, pkg.clone(), graph, cache.clone())
                .await?,
        );
        out.push(
            OutputTypesValid
                .check(&skip_checkers, fix, pkg.clone(), graph, cache.clone())
                .await?,
        );
        out.push(
            MissingRuntimeDeps
                .check(&skip_checkers, fix, pkg.clone(), graph, cache.clone())
                .await?,
        );
        out.push(
            StandaloneTestCheck
                .check(&skip_checkers, fix, pkg.clone(), graph, cache.clone())
                .await?,
        );
    }

    let file_based: Vec<Box<dyn FileBasedChecker>> = vec![
        Box::new(ParseCheck),
        Box::new(ImportLineCheck),
        Box::new(FmtCheck),
    ];
    for mut c in file_based.into_iter() {
        let check_result = c.as_mut().check(
            &skip_checkers,
            fix,
            &pkg,
            &packages_dir.join(&pkg),
            &stdlib_dir,
        )?;
        out.push(check_result);
    }

    Ok(out)
}

/// A checker which checks a package by looking at its files. These checkers
/// are run serially.
trait FileBasedChecker {
    fn check(
        &mut self,
        skip_checkers: &[String],
        fix: bool,
        pkg: &str,
        pkg_dir: &Path,
        stdlib_dir: &Path,
    ) -> Result<CheckResult, Error>;
}

/// A checker which checks a package by looking at its representation in the graph.
/// These checkers are run in parallel.
trait GraphBasedChecker {
    async fn check(
        self,
        skip_checkers: &[String],
        fix: bool,
        pkg: String,
        graph: &DepGraph,
        cache: Cache<LocalDir>,
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
        program.add_import_paths([stdlib_dir].iter());

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

struct ImportLineCheck;

impl FileBasedChecker for ImportLineCheck {
    fn check(
        &mut self,
        skip_checkers: &[String],
        fix: bool,
        _pkg: &str,
        pkg_dir: &Path,
        _stdlib_dir: &Path,
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

        for e in std::fs::read_dir(pkg_dir).map_err(anyhow::Error::from)? {
            let e = e.map_err(anyhow::Error::from)?;
            if e.file_type().unwrap().is_dir() {
                continue;
            }
            let name = e.file_name();
            if !name.to_str().unwrap().ends_with(".ncl") {
                continue;
            }

            let file_contents =
                String::from_utf8(std::fs::read(e.path()).map_err(anyhow::Error::from)?)
                    .map_err(anyhow::Error::from)?;

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
                    std::fs::write(e.path(), new_file_contents).map_err(anyhow::Error::from)?;
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

struct FmtCheck;

impl FileBasedChecker for FmtCheck {
    fn check(
        &mut self,
        skip_checkers: &[String],
        fix: bool,
        _pkg: &str,
        pkg_dir: &Path,
        _stdlib_dir: &Path,
    ) -> Result<CheckResult, Error> {
        let mut result = CheckResult {
            verdict: CheckVerdict::Skip,
            check: "fmt",
            err: vec![],
        };
        if skip_checkers.contains(&"fmt".to_string()) {
            return Ok(result);
        }

        for e in std::fs::read_dir(pkg_dir).map_err(anyhow::Error::from)? {
            let e = e.map_err(anyhow::Error::from)?;
            if e.file_type().unwrap().is_dir() {
                continue;
            }
            let name = e.file_name();
            if !name.to_str().unwrap().ends_with(".ncl") {
                continue;
            }

            let data = std::fs::read(e.path()).map_err(anyhow::Error::from)?;
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
                            std::fs::write(e.path(), out).map_err(anyhow::Error::from)?;
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
        graph: &DepGraph,
        cache: Cache<LocalDir>,
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
        let build = graph.get(&bsr).unwrap();

        result.verdict = CheckVerdict::Pass;
        if let Some(tests) = &build.tests {
            for (name, test) in tests {
                if test.build_test {
                    continue; // We only do standalone tests here
                }
                let temp_dir = cache.temp_dir().map_err(anyhow::Error::from)?;

                let mut t = StandaloneTest {
                    spec: &bsr,
                    test_name: name.as_str(),
                };
                let opts = Options {
                    cache: cache.clone(),
                    exec_base: temp_dir.path().to_path_buf(),
                    graph,
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
                        }
                    }
                    Err(op::Error::Cache(CacheErr::NotFound)) => {
                        result.verdict = CheckVerdict::Skip;
                        return Ok(result);
                    }
                    Err(e) => {
                        return Err(anyhow::Error::from(e)
                            .context(format!("running tests for spec {}", build.name))
                            .context(format!("failed setup for test {}", name))
                            .into());
                    }
                }
            }
        }

        Ok(result)
    }
}
