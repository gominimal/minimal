use super::{EnvPatches, EnvVarValue, StrOrList};
use crate::args::TaskArgs;
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
    pub vars: HashMap<String, EnvVarValue>,
    /// Files/directories to be patched into the sandbox this task executes in.
    #[serde(default, alias = "patches")]
    pub patch: EnvPatches,

    /// Whether to use the current working directory of the invocation, instead
    /// of the default which is the directory containing the minimal file.
    #[serde(default)]
    pub inherit_cwd: bool,

    /// Whether the task expects a TTY, such as TUI applications.
    #[serde(default)]
    pub interactive: bool,

    /// Typed schema of named arguments this task accepts.
    #[serde(default)]
    pub args: TaskArgs,

    /// Any fields which are not understood by this version of minimal.
    #[serde(flatten)]
    pub extra: HashMap<String, toml::Value>,
}

impl Task {
    /// Returns a clone of this task with all action strings mapped through `f`,
    /// enabling interpolation of task parameters (e.g. nickel `%{name}` expansion).
    pub fn map_exec_strings<E>(
        &self,
        mut f: impl FnMut(&str) -> Result<String, E>,
    ) -> Result<Task, E> {
        let action = match &self.action {
            TaskAction::Exec(StrOrList::Single(s)) => TaskAction::Exec(StrOrList::Single(f(s)?)),
            TaskAction::Exec(StrOrList::Multiple(v)) => TaskAction::Exec(StrOrList::Multiple(
                v.iter().map(|s| f(s)).collect::<Result<Vec<_>, _>>()?,
            )),
            TaskAction::Bash(cmd) => TaskAction::Bash(f(cmd)?),
            TaskAction::CmdCmd(argv) => {
                TaskAction::CmdCmd(argv.iter().map(|s| f(s)).collect::<Result<Vec<_>, _>>()?)
            }
        };
        Ok(Task {
            action,
            ..self.clone()
        })
    }

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

    #[test]
    fn interpolate_action_exec_single() {
        let t: Task = toml::from_str(indoc! {
            r#"
            exec = "go test ./pkg"
            "#
        })
        .unwrap();
        let t2 = t
            .map_exec_strings(|s| Ok::<_, ()>(s.to_uppercase()))
            .unwrap();
        assert_eq!(
            t2.action,
            TaskAction::Exec(StrOrList::Single("GO TEST ./PKG".to_string()))
        );
    }

    #[test]
    fn interpolate_action_exec_list() {
        let t: Task = toml::from_str(indoc! {
            r#"
            exec = ["go", "test", "./pkg"]
            "#
        })
        .unwrap();
        let t2 = t
            .map_exec_strings(|s| Ok::<_, ()>(s.to_uppercase()))
            .unwrap();
        assert_eq!(
            t2.action,
            TaskAction::Exec(StrOrList::Multiple(vec![
                "GO".to_string(),
                "TEST".to_string(),
                "./PKG".to_string(),
            ]))
        );
    }

    #[test]
    fn map_exec_strings_unchanged() {
        let t: Task = toml::from_str(indoc! {
            r#"
            bash = "echo hello"
            "#
        })
        .unwrap();
        let t2 = t
            .map_exec_strings(|s| Ok::<_, ()>(s.to_uppercase()))
            .unwrap();
        assert_eq!(t2.action, TaskAction::Bash("ECHO HELLO".to_string()));
    }

    #[test]
    fn inherit_env_var() {
        let t: Task = toml::from_str(indoc! {
            r#"
            env_vars.my_var = { inherit = true }
            exec = ["go", "test", "./..."]
            "#
        })
        .unwrap();
        assert_eq!(t.vars.get("my_var"), Some(&EnvVarValue::Inherit),);
    }

    /// Tests the interpolation path used by task_invocations when parsed_args is Some:
    /// parse args → build VarCtx → map_exec_strings.
    #[test]
    fn map_exec_strings_with_parsed_args() {
        let t: Task = toml::from_str(indoc! {
            r#"
            exec = "echo %{greeting} %{name}"
            args.greeting = "string"
            args.name = "string"
            "#
        })
        .unwrap();

        let parsed = t.args.parse("--greeting hello --name world").unwrap();
        let table = parsed.as_table().unwrap();
        let var_ctx =
            common::ncl_eval::VarCtx::new(table.iter().map(|(k, v)| (k.as_str(), v.clone())));
        let t2 = t
            .map_exec_strings(|s| {
                var_ctx
                    .eval_string(s)
                    .map_err(|e| format!("nickel eval failed: {:?}", e))
            })
            .unwrap();
        assert_eq!(
            t2.action,
            TaskAction::Exec(StrOrList::Single("echo hello world".to_string()))
        );
    }
}
