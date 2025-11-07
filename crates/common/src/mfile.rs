//! Finding & reading the `minimal.toml` file.

use std::collections::HashMap;
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

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum PatchSetting {
    #[default]
    #[serde(alias = "ro", alias = "read-only")]
    ReadOnly,
    #[serde(alias = "rw", alias = "read-write")]
    ReadWrite,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct EnvPatches {
    #[serde(default, alias = "dirs")]
    pub dir: HashMap<String, PatchSetting>,
    #[serde(default, alias = "files")]
    pub file: HashMap<String, PatchSetting>,
}

/// An environment, defined in a `[envs.<env_name>]` section of [File].
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Env {
    #[serde(default)]
    pub packages: Vec<String>,
    #[serde(default, alias = "env_vars")]
    pub vars: HashMap<String, String>,
    #[serde(default, alias = "patches")]
    pub patch: EnvPatches,
}

/// A task, defined in a `[tasks.<task_name>]` section of [File].
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Task {
    /// The name of the environment to use.
    pub env: String,
    /// The command invocation to use.
    pub cmd: String,
    /// Whether to use the current working directory of the invocation, instead
    /// of the default which is the directory containing the minimal file.
    #[serde(default)]
    pub inherit_cwd: bool,
}

impl Task {
    /// returns the program this task exec's, and the args to use.
    pub fn cmd_and_args(&self) -> (String, Vec<String>) {
        let mut cmd = shlex::Shlex::new(self.cmd.trim());
        let mut exec = cmd.next().unwrap();
        if !(exec.starts_with("/") || exec.starts_with("./")) {
            exec = format!("/bin/{}", exec);
        }

        (exec, cmd.collect())
    }
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum OutputKind {
    #[default]
    #[serde(alias = "oci-image")]
    OciImage,
}

/// An output, defined in a `[outputs.<output_name>]` section of [File].
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Output {
    #[serde(alias = "type")]
    pub ty: OutputKind,
    #[serde(default)]
    pub packages: Vec<String>,

    #[serde(default)]
    pub entrypoint: Option<String>,
    #[serde(default, alias = "env_vars")]
    pub vars: HashMap<String, String>,
}

/// The loaded representation of the `minimal.toml` file.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct File {
    pub base: Base,
    #[serde(default)]
    pub envs: HashMap<String, Env>,
    #[serde(default)]
    pub tasks: HashMap<String, Task>,
    #[serde(default)]
    pub outputs: HashMap<String, Output>,

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

    /// Returns the path to the directory where the minimal file is located.
    pub fn dir_path(&self) -> Option<&Path> {
        match &self.from {
            None => None,
            Some(fname) => fname.parent(),
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

            [envs.test]
            patch.dir."~/.claude" = "read-write"
            packages = ["base", "go"]

            [tasks.test]
            env = "test"
            cmd = "go test ./..."

            [outputs.test]
            type = "oci-image"
            packages = ["bash", "go"]
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
                envs: [(
                    "test".to_string(),
                    Env {
                        packages: vec!["base".to_string(), "go".to_string()],
                        vars: HashMap::new(),
                        patch: EnvPatches {
                            dir: [("~/.claude".to_string(), PatchSetting::ReadWrite)].into(),
                            file: HashMap::new()
                        },
                    }
                )]
                .into(),
                tasks: [(
                    "test".to_string(),
                    Task {
                        env: "test".to_string(),
                        cmd: "go test ./...".to_string(),
                        inherit_cwd: false,
                    }
                )]
                .into(),
                outputs: [(
                    "test".to_string(),
                    Output {
                        ty: OutputKind::OciImage,
                        packages: vec!["bash".to_string(), "go".to_string()],
                        entrypoint: None,
                        vars: HashMap::new(),
                    }
                )]
                .into(),
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
        let mfile = File::from_dir(dir.path());
        assert!(matches!(mfile, Ok(File { from: Some(_), .. })));
        assert_eq!(mfile.unwrap().dir_path().unwrap(), dir.path());

        std::fs::create_dir(dir.path().join("nested")).unwrap();
        assert!(File::from_dir(dir.path().join("nested")).is_ok()); // test from `./nested`
    }

    #[test]
    fn task_cmd_and_args() {
        let t: Task = toml::from_str(indoc! {
            r#"
            env = "test"
            cmd = "go test ./..."
            "#
        })
        .unwrap();
        assert_eq!(
            t.cmd_and_args(),
            (
                "/bin/go".to_string(),
                vec!["test".to_string(), "./...".to_string()]
            )
        );
    }
}
