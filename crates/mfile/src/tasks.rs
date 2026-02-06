use super::{EnvPatches, StrOrList};
use std::collections::HashMap;

/// A task, defined in a `[tasks.<task_name>]` section of [File].
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct Task {
    /// Indicates that this task should share durable state with other tasks with the same key.
    #[serde(default)]
    pub state_key: Option<String>,
    /// Load packages, environment variables etc from the given profile.
    #[serde(default)]
    pub profile: Option<String>,

    /// What to do when the task runs.
    #[serde(flatten)]
    pub action: TaskAction,

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

    /// Any fields which are not understood by this version of minimal.
    #[serde(flatten)]
    pub extra: HashMap<String, toml::Value>,
}

impl Task {
    /// Returns the program this task exec's, and the args to use.
    ///
    /// Only the Exec and Bash variants are supported. For all other actions,
    /// this method returns None.
    pub fn exec_and_args(&self) -> Option<(String, Vec<String>)> {
        let maybe_make_abs = |exec: &str| -> String {
            if !(exec.starts_with("/") || exec.starts_with("./")) {
                format!("/bin/{}", exec)
            } else {
                exec.to_string()
            }
        };

        match &self.action {
            TaskAction::Exec(StrOrList::Single(s)) => Some({
                let mut cmd = shlex::Shlex::new(s.trim());
                let exec = cmd.next().unwrap();
                (maybe_make_abs(&exec), cmd.collect())
            }),
            TaskAction::Exec(StrOrList::Multiple(v)) => Some(match v.len() {
                0 => ("".to_string(), vec![]),
                1 => (maybe_make_abs(&v[0]), vec![]),
                _ => (maybe_make_abs(&v[0]), v[1..].to_vec()),
            }),
            TaskAction::Bash(cmd) => {
                Some(("/bin/bash".to_string(), vec!["-c".to_string(), cmd.clone()]))
            }
            TaskAction::CmdCmd(_) => None,
        }
    }
}

/// The core action the task takes when it runs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TaskAction {
    /// Executes the given program and arguments.
    Exec(StrOrList),
    /// Executes the given bash script.
    Bash(String),
    /// Execute the given program & arguments to generate the list
    /// of commands to run.
    ///
    /// The invoked program should return each command to run on stdout,
    /// one invocation per line.
    CmdCmd(Vec<String>),
}

impl Default for TaskAction {
    fn default() -> Self {
        TaskAction::Exec(StrOrList::Single(String::new()))
    }
}

impl TaskAction {
    /// Constructs a [TaskAction] that represents the execve of the given string.
    pub fn exec_from_str(s: &str) -> Self {
        Self::Exec(StrOrList::Single(s.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    #[test]
    fn exec_str() {
        let t: Task = toml::from_str(indoc! {
            r#"
            env = "test"
            exec = "go test ./..."
            "#
        })
        .unwrap();
        assert_eq!(
            t.exec_and_args(),
            Some((
                "/bin/go".to_string(),
                vec!["test".to_string(), "./...".to_string()]
            ))
        );
    }
    #[test]
    fn exec_list() {
        let t: Task = toml::from_str(indoc! {
            r#"
            env = "test"
            exec = ["go", "test", "./..."]
            "#
        })
        .unwrap();
        assert_eq!(
            t.exec_and_args(),
            Some((
                "/bin/go".to_string(),
                vec!["test".to_string(), "./...".to_string()]
            ))
        );
    }

    #[test]
    fn bash_str() {
        let t: Task = toml::from_str(indoc! {
            r#"
            env = "test"
            bash = "go test ./... || echo failed"
            "#
        })
        .unwrap();
        assert_eq!(
            t.exec_and_args(),
            Some((
                "/bin/bash".to_string(),
                vec!["-c".to_string(), "go test ./... || echo failed".to_string()]
            ))
        );
    }
}
