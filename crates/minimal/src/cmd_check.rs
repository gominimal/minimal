use anyhow::anyhow;
use check::{CheckCtx, CheckVerdict};
use codespan_reporting::term::termcolor::{Buffer, Color, ColorSpec, WriteColor};
use futures::stream::StreamExt;
use mctx::{Context, Error};
use std::io::{IsTerminal, Write};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(clap::Args)]
pub struct CheckArgs {
    /// Attempt to fix any issues
    #[arg(short, long, default_value_t = false)]
    fix: bool,

    #[command(flatten)]
    kind: CheckKind,

    /// Checker names to skip, comma-separated
    #[arg(short, long, alias="skip", value_delimiter=',', num_args=0..)]
    skip_checkers: Option<Vec<String>>,

    /// Object names to filter
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args=0..)]
    filter_names: Vec<String>,
}

#[derive(clap::Args, Debug, Default, PartialEq, Eq)]
#[group(required = false, multiple = true)]
pub struct CheckKind {
    /// Check packages defined in the codebase
    #[arg(long)]
    packages: bool,

    /// Check stacks defined in the codebase
    #[arg(long)]
    stacks: bool,

    /// Check profiles defined in the codebase
    #[arg(long)]
    profiles: bool,
}

impl CheckKind {
    fn check_packages(&self) -> bool {
        self == &CheckKind::default() || self.packages
    }
    fn check_stacks(&self) -> bool {
        self == &CheckKind::default() || self.stacks
    }
    fn check_profiles(&self) -> bool {
        self == &CheckKind::default() || self.profiles
    }
}

pub async fn cmd_check(args: CheckArgs, ctx: &mut Context) -> Result<(), Error> {
    if args
        .filter_names
        .first()
        .map(|s| s == "-p")
        .unwrap_or(false)
    {
        return Err(Error::Other(anyhow!(
            "-p is no longer supported (check has new flags/arguments)"
        )));
    }

    let all_graph = ctx.graph_from_all_packages();

    // Download packages if the graph compiles + we are going to check packages.
    if let Ok(g) = all_graph.as_ref()
        && ctx.use_remote_cache()
        && args.kind.check_packages()
    {
        ctx.download_if_available(
            g,
            if args.filter_names.is_empty() {
                g.from_origin(&ctx.repo_origin()).collect()
            } else {
                g.top_levels
                    .iter()
                    .filter(|bsr| args.filter_names.contains(&g.get(bsr).unwrap().name))
                    .cloned()
                    .collect::<Vec<_>>()
            },
        )
        .await?;
    }

    let upstream_dir = ctx.minimal_file().dir_path().unwrap().to_path_buf();
    if args.fix && upstream_dir.strip_prefix(ctx.vcs_dir()).is_ok() {
        return Err(Error::Other(anyhow!(
            "--fix can only be used on a local repository"
        )));
    }

    let (graph, graph_err) = match all_graph {
        Err(e) => (None, Some(e)),
        Ok(g) => (Some(g), None),
    };

    let check_ctx = CheckCtx::new(
        args.filter_names.clone(),
        args.skip_checkers.unwrap_or_default(),
        args.fix,
        graph.map(|g| Arc::new(RwLock::new(g))),
        ctx.stdlib_dir().to_path_buf(),
        ctx.local_cache(),
        None,
    );

    let mut checks_stream = check::run_checks(
        if args.kind.check_packages() {
            Some(upstream_dir.join("packages"))
        } else {
            None
        },
        if args.kind.check_profiles() {
            Some(upstream_dir.join("profiles"))
        } else {
            None
        },
        if args.kind.check_stacks() {
            Some(upstream_dir.join("stacks"))
        } else {
            None
        },
        check_ctx,
    )?;

    let mut had_error = false;
    let use_color = std::io::stdin().is_terminal();

    while let Some((heading, result)) = checks_stream.next().await {
        let checks = result?;
        let mut stdout: Buffer = match use_color {
            true => Buffer::ansi(),
            false => Buffer::no_color(),
        };
        stdout.reset().unwrap();
        stdout.set_color(ColorSpec::new().set_fg(None)).unwrap();

        writeln!(&mut stdout, "{}", heading).unwrap();
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
                writeln!(&mut stdout, "\t{}", err.replace("\n", "\n\t")).unwrap();
            }
        }

        stdout
            .set_color(ColorSpec::new().set_reset(true).set_fg(None))
            .unwrap();
        writeln!(&mut stdout, "\n").unwrap();
        ot::StdoutWriter::new()
            .write_all(stdout.as_slice())
            .unwrap();
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
