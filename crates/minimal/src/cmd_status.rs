use crate::{Context, Error};
use codespan_reporting::term::termcolor::{
    Color, ColorChoice, ColorSpec, StandardStream, WriteColor,
};
use common::SpecOrigin;
use dirs::home_dir;
use graph::Graph;
use std::io::Write;
use std::path::Path;

#[derive(clap::Args)]
pub struct StatusArgs {}

pub async fn cmd_status(_args: StatusArgs, ctx: &mut Context) -> Result<(), Error> {
    let harness = ctx.minimal_file().harness.as_ref().map(|h| h.name.clone());

    let s = StandardStream::stdout(ColorChoice::Auto);
    let mut writer = s.lock();

    writer.set_color(ColorSpec::new().set_fg(None)).unwrap();
    if let Some(harness) = harness {
        writeln!(writer, "Using harness {}", harness).unwrap();
    }

    let graph = ctx.graph_from_all_packages()?;
    print_supply_chain(graph.software_supply_chain(), &mut writer)?;
    print_tasks(ctx, &graph, &mut writer)?;

    Ok(())
}

fn print_tasks(ctx: &mut Context, graph: &Graph, writer: &mut dyn WriteColor) -> Result<(), Error> {
    writer.set_color(ColorSpec::new().set_fg(None)).unwrap();
    writeln!(writer).unwrap();
    writeln!(writer, "Tasks:").unwrap();

    for (name, source) in ctx.iter_tasks(graph).into_iter() {
        writer
            .set_color(ColorSpec::new().set_fg(None).set_bold(true))
            .unwrap();

        write!(writer, "  ").unwrap();
        write!(writer, "{name}").unwrap();
        writer.set_color(ColorSpec::new().set_fg(None)).unwrap();
        match source {
            mctx::TaskSource::MFile => {}
            mctx::TaskSource::Harness(harness_name) => {
                write!(writer, " (provided by {harness_name} harness)").unwrap()
            }
        }
        writeln!(writer).unwrap();
    }
    Ok(())
}

fn print_supply_chain(chain: &[SpecOrigin], writer: &mut dyn WriteColor) -> Result<(), Error> {
    writer.set_color(ColorSpec::new().set_fg(None)).unwrap();
    writeln!(writer).unwrap();
    writeln!(writer, "Software supply chain:").unwrap();

    for (i, layer) in chain.iter().enumerate() {
        writer
            .set_color(ColorSpec::new().set_fg(Some(Color::Blue)).set_bold(true))
            .unwrap();
        if i == 0 {
            write!(writer, "  ").unwrap();
        } else if i + 1 < chain.len() {
            write!(writer, "  ├─ ").unwrap();
        } else {
            write!(writer, "  └─ ").unwrap();
        }

        print_origin(layer, writer, i == 0)?;
    }
    Ok(())
}

fn print_origin(
    origin: &SpecOrigin,
    writer: &mut dyn WriteColor,
    first: bool,
) -> Result<(), Error> {
    let newline = |writer: &mut dyn WriteColor| {
        writer
            .set_color(ColorSpec::new().set_fg(Some(Color::Blue)).set_bold(true))
            .unwrap();
        write!(writer, "  │    {}", if first { "" } else { " " }).unwrap();
        writer.set_color(ColorSpec::new().set_fg(None)).unwrap();
    };

    writer
        .set_color(ColorSpec::new().set_fg(None).set_bold(true))
        .unwrap();

    match origin {
        SpecOrigin::LocalDir { absolute, .. } => {
            write!(writer, "Local codebase ").unwrap();
            writer.set_color(ColorSpec::new().set_fg(None)).unwrap();
            writeln!(writer, "{}", path_str(absolute)).unwrap();
        }
        SpecOrigin::Repo(r) => match r {
            common::repo_spec::Repo::Git { url, rev, tracking } => {
                if let Some(sub) = url.strip_prefix("https://github.com/") {
                    write!(writer, "GitHub Registry ").unwrap();

                    writer.set_color(ColorSpec::new().set_fg(None)).unwrap();
                    writeln!(writer, "{}", sub).unwrap();
                } else {
                    writeln!(writer, "Git Registry    ").unwrap();

                    writer.set_color(ColorSpec::new().set_fg(None)).unwrap();
                    writeln!(writer, "{}", url).unwrap();
                }

                if let Some(tracking) = tracking {
                    newline(writer);
                    write!(writer, "Tracking: ").unwrap();
                    match tracking {
                        common::repo_spec::GitRef::Branch(b) => {
                            write!(writer, "branch {}", b).unwrap()
                        }
                        common::repo_spec::GitRef::Tag(t) => write!(writer, "tag {}", t).unwrap(),
                    };
                    writeln!(writer).unwrap();
                }

                newline(writer);
                writeln!(writer, "Pinned to: {}", rev).unwrap();
            }
        },
        SpecOrigin::Inline => {
            writeln!(writer, "<unknown>").unwrap();
        }
    }

    Ok(())
}

fn path_str(input_path: &Path) -> String {
    match home_dir() {
        Some(p) if input_path.strip_prefix(&p).is_ok() => {
            format!(
                "~/{}",
                input_path.strip_prefix(p).unwrap().to_str().unwrap()
            )
        }
        _ => input_path.to_str().unwrap().to_string(),
    }
}
