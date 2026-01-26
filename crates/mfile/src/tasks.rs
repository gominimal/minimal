use super::EnvPatches;
use std::collections::HashMap;

/// A task, defined in a `[tasks.<task_name>]` section of [File].
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Task {
    /// Indicates that this task should share durable state with other tasks with the same key.
    #[serde(default)]
    pub state_key: Option<String>,
    /// Load packages, environment variables etc from the given profile.
    #[serde(default)]
    pub profile: Option<String>,

    /// The command invocation to use.
    pub cmd: String,

    /// Additional packages to be present in the sandbox this task executes in.
    #[serde(default)]
    pub packages: Vec<String>,
    /// Environment variables to set on the process this task launches.
    #[serde(default, alias = "env_vars")]
    pub vars: HashMap<String, String>,
    /// Files/directories to be patched into the sandbox this task executes in.
    #[serde(default, alias = "patches")]
    pub patch: EnvPatches,

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
