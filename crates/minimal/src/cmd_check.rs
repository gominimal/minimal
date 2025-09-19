use crate::{Error, GlobalArgs, PackagesArg};
use graph::DepGraph;

#[derive(clap::Args)]
pub struct CheckArgs {
    /// Attempt to fix any issues
    #[arg(short, long, default_value_t = false)]
    fix: bool,

    #[command(flatten)]
    packages: PackagesArg,
}

pub fn cmd_check(args: CheckArgs, globals: &GlobalArgs) -> Result<(), Error> {
    let all_graph = match globals.graph_from_all_packages() {
        Ok(g) => Some(g),
        Err(_) => None,
    };
    let packages_dir = globals.packages_dir();

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

    let iter = packages_dirs
        .into_iter()
        // Filter based on the packages argument
        .filter_map(|pkg| {
            let want_pkgs = args.packages.names();
            let pkg = pkg.to_str().unwrap().to_string();
            if want_pkgs.len() == 0 {
                Some(pkg)
            } else {
                if want_pkgs.contains(&pkg) {
                    Some(pkg)
                } else {
                    None
                }
            }
        })
        .map(|pkg| {
            let result = check_package(&pkg, &all_graph, args.fix, globals);
            (pkg, result)
        });

    use codespan_reporting::term::termcolor::{
        Color, ColorChoice, ColorSpec, StandardStream, WriteColor,
    };
    use std::io::Write;
    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    for (pkg, result) in iter {
        let result = result?;

        stdout.set_color(ColorSpec::new().set_fg(None)).unwrap();
        writeln!(&mut stdout, "\npackage: {}", pkg).unwrap();
        for check in result {
            write!(&mut stdout, "{}...", check.check).unwrap();
            match check.verdict {
                CheckVerdict::Fail => {
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

            if let Some(err) = check.err {
                writeln!(&mut stdout, "\t{}", err).unwrap();
            }
        }
    }

    Ok(())
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
    err: Option<String>,
}

fn check_package_parses(
    pkg: &String,
    _all_graph: &Option<DepGraph>,
    _fix: bool,
    globals: &GlobalArgs,
) -> Result<CheckResult, Error> {
    let mut result = CheckResult {
        verdict: CheckVerdict::Skip,
        check: "parse",
        err: None,
    };

    result.verdict = match globals.graph_from_package_name(pkg) {
        Ok(_) => CheckVerdict::Pass,
        Err(e) => {
            result.err = Some(format!("{:?}", e));
            CheckVerdict::Fail
        }
    };

    Ok(result)
}

fn check_package_spec_name_matches_dir(
    pkg: &String,
    _all_graph: &Option<DepGraph>,
    _fix: bool,
    globals: &GlobalArgs,
) -> Result<CheckResult, Error> {
    let mut result = CheckResult {
        verdict: CheckVerdict::Skip,
        check: "spec name matches dir",
        err: None,
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

fn check_package_name(
    pkg: &String,
    all_graph: &Option<DepGraph>,
    _fix: bool,
    _globals: &GlobalArgs,
) -> Result<CheckResult, Error> {
    let mut result = CheckResult {
        verdict: CheckVerdict::Skip,
        check: "spec name valid",
        err: None,
    };

    result.verdict = if pkg.chars().all(|x| {
        (x.is_ascii_alphanumeric() && (!x.is_alphabetic() || x.is_ascii_lowercase()))
            || x == '_'
            || x == '-'
    }) {
        if all_graph
            .as_ref()
            .map(|g| g.by_name(pkg).count())
            .unwrap_or(1)
            != 1
        {
            result.err = Some("Multiple build-specs exist with the same name".to_string());
            CheckVerdict::Fail
        } else {
            CheckVerdict::Pass
        }
    } else {
        result.err = Some("Only lowercase a-z,0-9,-, and _ allowed".to_string());
        CheckVerdict::Fail
    };

    Ok(result)
}

fn cycle_breaker_naming(
    pkg: &String,
    _all_graph: &Option<DepGraph>,
    _fix: bool,
    globals: &GlobalArgs,
) -> Result<CheckResult, Error> {
    let mut result = CheckResult {
        verdict: CheckVerdict::Skip,
        check: "cycle breaker naming",
        err: None,
    };

    result.verdict = match globals.graph_from_package_name(pkg) {
        Ok(graph) => {
            let build = graph.get(&graph.top_levels[0]).unwrap();
            if let Some(replace_on_cycle) = build.replace_on_cycle {
                let cycle_breaker = graph.get(&replace_on_cycle).unwrap();
                if cycle_breaker.name != format!("{} (prebuilt)", pkg) {
                    result.err = Some(format!(
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

fn check_package_fmt(
    pkg: &String,
    _all_graph: &Option<DepGraph>,
    fix: bool,
    globals: &GlobalArgs,
) -> Result<CheckResult, Error> {
    let mut result = CheckResult {
        verdict: CheckVerdict::Skip,
        check: "fmt",
        err: None,
    };

    let base = globals.packages_dir().join(pkg);
    for e in std::fs::read_dir(base).map_err(anyhow::Error::from)? {
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
                result.err = Some(format!(
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

fn check_package(
    pkg: &String,
    all_graph: &Option<DepGraph>,
    fix: bool,
    globals: &GlobalArgs,
) -> Result<Vec<CheckResult>, Error> {
    Ok(vec![
        check_package_parses(pkg, all_graph, fix, globals)?,
        check_package_spec_name_matches_dir(pkg, all_graph, fix, globals)?,
        check_package_name(pkg, all_graph, fix, globals)?,
        cycle_breaker_naming(pkg, all_graph, fix, globals)?,
        check_package_fmt(pkg, all_graph, fix, globals)?,
    ])
}
