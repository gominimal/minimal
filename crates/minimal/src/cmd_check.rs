use crate::{Error, GlobalArgs, PackagesArg};
use graph::DepGraph;
use std::cmp::Ordering;

use regex::Regex;
use std::sync::LazyLock;

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

            for err in check.err {
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
    err: Vec<String>,
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
        err: vec![],
    };

    result.verdict = match globals.graph_from_package_name(pkg) {
        Ok(_) => CheckVerdict::Pass,
        Err(e) => {
            result.err.push(format!("{:?}", e));
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

fn check_package_name(
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

fn cycle_breaker_naming(
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

static MINIMAL_IMPORT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"let\s*\{\s*([^}]+)\s*\}\s*=\s*import\s+"minimal\.ncl"\s+in"#)
        .expect("Invalid regex pattern")
});

fn check_minimal_import_line(
    pkg: &String,
    _all_graph: &Option<DepGraph>,
    fix: bool,
    globals: &GlobalArgs,
) -> Result<CheckResult, Error> {
    let mut result = CheckResult {
        verdict: CheckVerdict::Pass,
        check: "import line",
        err: vec![],
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

        let file_contents =
            String::from_utf8(std::fs::read(e.path()).map_err(anyhow::Error::from)?)
                .map_err(anyhow::Error::from)?;

        if let Some(captures) = (&*MINIMAL_IMPORT_REGEX).captures(&file_contents) {
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
            if fix && (sorted_identifiers != used_identifiers || identifiers != used_identifiers) {
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

fn check_package_fmt(
    pkg: &String,
    _all_graph: &Option<DepGraph>,
    fix: bool,
    globals: &GlobalArgs,
) -> Result<CheckResult, Error> {
    let mut result = CheckResult {
        verdict: CheckVerdict::Skip,
        check: "fmt",
        err: vec![],
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
        check_minimal_import_line(pkg, all_graph, fix, globals)?,
        check_package_fmt(pkg, all_graph, fix, globals)?,
    ])
}
