use std::fmt;
use std::path::PathBuf;

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
    pub fn report_to_stderr(&self) {
        match self {
            Error::Graph(e) => e.report_to_stderr(),
            Error::Plan(b) => {
                let (graph, err) = b.as_ref();
                match err {
                    PlanErr::Cycles(cycles) => {
                        eprintln!(
                            "Planning failed: unable to progress with unresolvable dependency cycles"
                        );
                        eprintln!("Cycles:");
                        for c in cycles {
                            eprintln!(
                                "\t{}",
                                c.iter()
                                    .map(|bsr| graph.get(bsr).unwrap().name.clone())
                                    .collect::<Vec<_>>()
                                    .join(" -> "),
                            )
                        }
                    }
                }
            }
            _ => eprintln!("{}", self),
        }
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
            orchestrator::Error::Plan(graph, e) => Self::Plan(Box::new((graph, e))),
        }
    }
}
