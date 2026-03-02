use std::path::PathBuf;
use std::{env, fmt};

use common::SpecOrigin;
use graph::{DepGraph, PlanErr};

/// The errors possible when driving top-level minimal APIs.
#[derive(Debug)]
pub enum Error {
    Config(super::ConfigError),
    IO(&'static str, PathBuf, std::io::Error),
    Format(toml::de::Error),
    MFile(mfile::Error),
    Graph(Box<graph::Error>),

    Plan(Box<(DepGraph, PlanErr)>),
    Other(anyhow::Error),
}

impl Error {
    /// Writes a human-friendly error to the given terminal or buffer.
    pub fn report_to(&self, writer: &mut dyn codespan_reporting::term::termcolor::WriteColor) {
        match self {
            Error::Plan(b) => {
                let (graph, err) = b.as_ref();
                match err {
                    PlanErr::Cycles(cycles) => {
                        writeln!(
                            writer,
                            "Planning failed: unable to progress with unresolvable dependency cycles"
                        ).unwrap();
                        writeln!(writer, "Cycles:").unwrap();
                        for c in cycles {
                            writeln!(
                                writer,
                                "\t{}",
                                c.iter()
                                    .map(|bsr| graph.get(bsr).unwrap().name.clone())
                                    .collect::<Vec<_>>()
                                    .join(" -> "),
                            )
                            .unwrap()
                        }
                    }
                }
            }
            Error::Graph(e) => {
                match &**e {
                    // Slightly better error message if the upstream is not pinned, and this
                    // error occurred on the top-level repo.
                    graph::Error::UpstreamNotPinned {
                        upstream,
                        at_layer: SpecOrigin::LocalDir { absolute, .. },
                    } if env::current_dir()
                        .map(|d| absolute.starts_with(d))
                        .unwrap_or(false) =>
                    {
                        writeln!(writer, "Error: upstream defined but not pinned to a commit")
                            .unwrap();
                        writeln!(writer).unwrap();
                        writeln!(writer, "> minimal.toml").unwrap();
                        writeln!(writer, "[upstream]").unwrap();
                        writeln!(writer, "repo = \"{}\"", upstream).unwrap();
                        writeln!(
                            writer,
                            "locked_commit = <pinned commit hash>\t# missing field"
                        )
                        .unwrap();
                        writeln!(writer).unwrap();
                        writeln!(writer, "help: try running `minimal update`").unwrap();
                    }
                    _ => e.report_to(writer),
                }
            }
            _ => writeln!(writer, "{}", self).unwrap(),
        }
    }
    pub fn report_to_stderr(&self) {
        use codespan_reporting::term::termcolor::{ColorChoice, StandardStream};
        self.report_to(&mut StandardStream::stderr(ColorChoice::Auto).lock());
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(e) => write!(f, "config error: {}", e),
            Error::IO(ctx, path, e) => {
                write!(f, "{} I/O error at path {}: {}", ctx, path.display(), e)
            }
            Error::Format(e) => write!(f, "invalid TOML: {}", e),
            Error::MFile(e) => write!(f, "{}: {}", mfile::MFILE_NAME, e),
            Error::Graph(e) => write!(f, "graph: {:?}", e),
            Error::Plan(e) => {
                let (graph, PlanErr::Cycles(c)) = e.as_ref();
                {
                    write!(
                        f,
                        "Planning failed: unable to progress with unresolvable dependency cycles"
                    )?;
                    write!(f, "Cycles:")?;
                    for c in c.iter() {
                        write!(
                            f,
                            "\t{}",
                            c.iter()
                                .map(|bsr| graph.get(bsr).unwrap().name.clone())
                                .collect::<Vec<_>>()
                                .join(" -> "),
                        )?;
                    }
                    Ok(())
                }
            }
            Error::Other(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Config(e) => Some(e),
            Error::IO(_, _, e) => Some(e),
            Error::Format(e) => Some(e),
            Error::MFile(e) => Some(e),
            Error::Graph(_e) => None,
            Error::Plan(_) => None,
            Error::Other(_e) => None,
        }
    }
}

impl Error {
    /// Constructs an error wrapping an IO error when trying to create necessary directories.
    pub(crate) fn setup_dirs(e: std::io::Error, erroring_path: PathBuf) -> Self {
        Self::IO("directory setup", erroring_path, e)
    }
}

impl From<checkouts::Error> for Error {
    fn from(value: checkouts::Error) -> Self {
        match value {
            checkouts::Error::IO(e) => Self::IO("vcs", PathBuf::new(), e),
            checkouts::Error::Other(e) => Self::Other(anyhow::anyhow!(e)),
            checkouts::Error::GitCommandFailed { command, stderr } => Self::Other(anyhow::anyhow!(
                "unexpected: git command '{}' failed: {}",
                command,
                stderr
            )),
            checkouts::Error::InvalidPath => {
                Self::Other(anyhow::anyhow!("vcs: invalid remote path"))
            }
            checkouts::Error::StatefileInvalid(e) => {
                Self::Other(anyhow::anyhow!("vcs: failed parsing state file: {}", e))
            }
        }
    }
}

impl From<graph::Error> for Error {
    fn from(value: graph::Error) -> Self {
        Error::Graph(Box::new(value))
    }
}

impl From<super::ConfigError> for Error {
    fn from(value: super::ConfigError) -> Self {
        Error::Config(value)
    }
}

impl From<orchestrator::Error> for Error {
    fn from(value: orchestrator::Error) -> Self {
        match value {
            orchestrator::Error::IO(e) => Self::IO("vcs", PathBuf::new(), e),
            orchestrator::Error::Other(e) => Self::Other(anyhow::anyhow!(e)),
            orchestrator::Error::Cache(e) => Self::Other(anyhow::anyhow!(e)), // TODO: better error
            orchestrator::Error::Sandbox(e) => Self::Other(anyhow::anyhow!(e)), // TODO: better error
            orchestrator::Error::Plan(graph, e) => Self::Plan(Box::new((graph, e))),
        }
    }
}

impl From<check::Error> for Error {
    fn from(value: check::Error) -> Self {
        match value {
            check::Error::IO(s, p, e) => Self::IO(s, p, e),
            check::Error::Other(e) => Self::Other(e),
            check::Error::Graph(e) => Self::Graph(e),
        }
    }
}
