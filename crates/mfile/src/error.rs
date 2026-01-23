use std::fmt;
use std::path::PathBuf;

use crate::MFILE_NAME;

/// The errors possible when working with the minimal file.
#[derive(Debug)]
pub enum Error {
    IO(&'static str, PathBuf, std::io::Error),
    Format(toml::de::Error),
    NotFound,
    ConflictingLayouts(Vec<PathBuf>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::IO(ctx, path, e) => {
                write!(f, "{} I/O error at path {}: {}", ctx, path.display(), e)
            }
            Error::Format(e) => write!(f, "invalid TOML: {}", e),
            Error::NotFound => write!(f, "{} not found", MFILE_NAME),
            Error::ConflictingLayouts(paths) => write!(
                f,
                "multiple minimal configurations detected at [{}]. Remove the erroneous one.",
                paths
                    .iter()
                    .map(|p| p.as_os_str().to_str().unwrap())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IO(_, _, e) => Some(e),
            Error::Format(e) => Some(e),
            Error::NotFound => None,
            Error::ConflictingLayouts(_) => None,
        }
    }
}
