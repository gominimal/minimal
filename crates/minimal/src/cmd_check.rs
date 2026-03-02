use crate::PackagesArg;
use anyhow::anyhow;
use check::CheckVerdict;
use codespan_reporting::term::termcolor::{
    Color, ColorChoice, ColorSpec, StandardStream, WriteColor,
};
use mctx::{Context, Error};
use std::io::Write;

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
    let all_graph = args.packages.resolve(ctx);
    if let Ok(g) = all_graph.as_ref()
        && ctx.use_remote_cache()
    {
        ctx.download_if_available(g, g.top_levels.iter().cloned())
            .await?;
    }

    let upstream_dir = ctx.minimal_file().dir_path().unwrap().to_path_buf();
    let packages_dir = upstream_dir.join("packages");
    let stdlib_dir = ctx.stdlib_dir();

    if args.fix && packages_dir.strip_prefix(ctx.vcs_dir()).is_ok() {
        return Err(Error::Other(anyhow!(
            "--fix can only be used on a local repository"
        )));
    }

    let (graph, graph_err) = match all_graph {
        Err(e) => (None, Some(e)),
        Ok(g) => (Some(g), None),
    };

    let skip_checkers = args.skip_checkers.unwrap_or_default();
    let package_names = args.packages.names();

    let results = check::run_checks(
        packages_dir,
        upstream_dir.join("profiles"),
        upstream_dir.join("harnesses"),
        stdlib_dir.to_path_buf(),
        &package_names,
        graph,
        ctx.local_cache(),
        args.fix,
        &skip_checkers,
    )
    .await?;

    let mut had_error = false;
    let mut stdout = StandardStream::stdout(ColorChoice::Auto);

    for (heading, checks) in &results {
        stdout.reset().unwrap();
        stdout.set_color(ColorSpec::new().set_fg(None)).unwrap();

        writeln!(&mut stdout, "\n{}", heading).unwrap();
        for check in checks {
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

            for err in &check.err {
                writeln!(&mut stdout, "\t{}", err).unwrap();
            }
        }
    }

    match had_error {
        true => Err(Error::Other(anyhow!(
            "One or more checkers reported a failure"
        ))),
        false => match graph_err {
            None => Ok(()),
            Some(e) => Err(e),
        },
    }
}
