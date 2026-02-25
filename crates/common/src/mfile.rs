//! Finding & reading the `minimal.toml` file.

use std::path::{Path, PathBuf};
use std::{env, fmt};

const MFILE_NAME: &str = "minimal.toml";

/// The errors possible when working with the minimal file.
#[derive(Debug)]
pub enum Error {
    IO(&'static str, PathBuf, std::io::Error),
    Format(toml::de::Error),
    NotFound,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::IO(ctx, path, e) => {
                write!(f, "{} I/O error at path {}: {}", ctx, path.display(), e)
            }
            Error::Format(e) => write!(f, "invalid TOML: {}", e),
            Error::NotFound => write!(f, "not found"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IO(_, _, e) => Some(e),
            Error::Format(e) => Some(e),
            Error::NotFound => None,
        }
    }
}

/// The `[base]` section of [File], describing the upstream to use.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Base {
    pub repo: String,
    pub branch: Option<String>,
}

/// The loaded representation of the `minimal.toml` file.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct File {
    pub base: Base,

    #[serde(skip)]
    from: Option<PathBuf>,
}

impl File {
    /// Searches from the given directory backwards to load the `minimal.toml` file.
    pub fn from_dir<P: AsRef<Path>>(dir: P) -> Result<Self, Error> {
        let path = dir.as_ref().join(MFILE_NAME);
        match std::fs::read(&path) {
            Ok(b) => {
                let mut mfile: Self = toml::from_slice(&b).map_err(Error::Format)?;
                mfile.from = Some(path.to_path_buf());
                Ok(mfile)
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    // Not found at this directory, try the parent
                    if let Some(parent) = dir.as_ref().parent() {
                        // We don't traverse outside of a users HOME if its set.
                        if let Some(home) = env::home_dir()
                            && home == parent
                        {
                            return Err(Error::NotFound);
                        }

                        Self::from_dir(parent)
                    } else {
                        Err(Error::NotFound)
                    }
                } else {
                    Err(Error::IO("read", path, e))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use tempfile::tempdir;

    #[test]
    fn deserialize_smoketest() {
        let mf: File = toml::from_str(indoc! {
            r#"
            [base]
            repo = "https://github.com/gominimal/pkgs"
            branch = "main"
            "#
        })
        .unwrap();

        assert_eq!(
            mf,
            File {
                base: Base {
                    repo: "https://github.com/gominimal/pkgs".to_string(),
                    branch: Some("main".to_string()),
                },
                from: None,
            }
        )
    }

    #[test]
    fn from_dir() {
        let dir = tempdir().unwrap();

        // write `minimal.toml`.
        std::fs::write(
            dir.path().join(MFILE_NAME),
            indoc! {
                r#"
            [base]
            repo = "https://github.com/gominimal/pkgs"
            branch = "main"
            "#
            },
        )
        .unwrap();

        // test from `./`, also check if `from` is set
        assert!(matches!(
            File::from_dir(dir.path()),
            Ok(File { from: Some(_), .. })
        ));

        std::fs::create_dir(dir.path().join("nested")).unwrap();
        assert!(File::from_dir(dir.path().join("nested")).is_ok()); // test from `./nested`
    }
}
