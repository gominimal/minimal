use std::fmt;
use std::path::PathBuf;

/// The errors possible when working with the minimal file.
#[derive(Debug)]
pub enum Error {
    IO(&'static str, PathBuf, std::io::Error),
    Format(toml::de::Error),
    NotFound,
    ConflictingLayouts(Vec<PathBuf>),
    MissingParamDefault(String),
    /// A task sets more than one action key: the task name, then the keys.
    MultipleTaskActions(String, Vec<String>),
    /// The file names the pre-v0.5.0 `harness` key, which sets no
    /// stack: the named stack is silently absent, and the missing
    /// toolchain surfaces much later as a bare linker error. Carries
    /// the path of the offending file when it is known.
    HarnessTable(Option<PathBuf>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::IO(ctx, path, e) => {
                write!(f, "{} I/O error at path {}: {}", ctx, path.display(), e)
            }
            Error::Format(e) => write!(f, "invalid TOML: {}", e),
            Error::NotFound => write!(f, "not found"),
            Error::ConflictingLayouts(paths) => write!(
                f,
                "multiple minimal configurations detected at [{}]. Remove the erroneous one.",
                paths
                    .iter()
                    .map(|p| p.as_os_str().to_str().unwrap())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Error::MissingParamDefault(e) => {
                write!(f, "invalid parameter: `{}` does not define a default", e)
            }
            Error::MultipleTaskActions(task, keys) => write!(
                f,
                "task `{}` sets more than one action ({}); set exactly one",
                task,
                keys.join(", ")
            ),
            Error::HarnessTable(path) => {
                if let Some(path) = path {
                    write!(f, "{}: ", path.display())?;
                }
                write!(
                    f,
                    "the `harness` key (the pre-v0.5.0 name of `stack`) is \
                     no longer accepted: it sets no stack, so its toolchain \
                     would be missing. Replace it with a `[stack]` table: \
                     rename a `[harness]` table, and write `harness = \"x\"` \
                     as `name = \"x\"` under `[stack]`.",
                )
            }
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
            Error::MissingParamDefault(_) => None,
            Error::MultipleTaskActions(..) => None,
            Error::HarnessTable(_) => None,
        }
    }
}
