use mctx::{Context, Error};
use mfile::{StrOrList, Task, TaskAction};
use tracing::trace;

use crate::cmd_run::run_task;

/// Host env vars passed through into the shell by default.
const DEFAULT_PASSTHROUGH: &[&str] = &[
    "USER",
    "LOGNAME",
    "EDITOR",
    "VISUAL",
    "TZ",
    "LANG",
    "SSH_AUTH_SOCK",
];

#[derive(Debug, clap::Args)]
pub struct ShellArgs {
    /// Additional packages to make available in the shell, comma-separated.
    #[arg(short, long, value_delimiter = ',')]
    packages: Option<Vec<String>>,

    /// Environment variables to pass through from the host.
    /// Use `-e VAR` to forward the host value, or `-e VAR=VALUE` to set explicitly.
    #[arg(short = 'e', long = "env")]
    env: Vec<String>,

    /// Do not pass through the default set of host environment variables.
    #[arg(long)]
    pure: bool,
}

pub async fn cmd_shell(args: ShellArgs, ctx: &mut Context) -> Result<(), Error> {
    trace!("cmd_shell");

    let graph = ctx.graph_from_all_packages()?;

    let (mut task, graph) = match ctx.task(graph, "shell")? {
        Some((t, g)) => (t, g),
        None => {
            // No [tasks.shell] defined — construct a synthetic task.
            let graph = ctx.graph_from_all_packages()?;
            let repo_origin = ctx.repo_origin()?;
            let packages: Vec<String> = graph
                .from_origin(&repo_origin)
                .filter_map(|bsr| graph.get(&bsr))
                .map(|spec| spec.name.clone())
                .collect();

            let mut task = Task {
                action: TaskAction::Exec(StrOrList::Single("bash -l".to_string())),
                packages,
                inherit_cwd: true,
                state_key: Some("shell".to_string()),
                ..Default::default()
            };

            // Override packages if the user specified --packages.
            if let Some(pkgs) = args.packages {
                task.packages = pkgs;
            }

            (task, graph)
        }
    };

    // Pass through default host env vars (unless --pure).
    if !args.pure {
        for key in DEFAULT_PASSTHROUGH {
            if let Ok(val) = std::env::var(key) {
                task.vars.entry(key.to_string()).or_insert(val);
            }
        }
    }

    // Pass through user-specified env vars (--env / -e).
    for spec in &args.env {
        if let Some((key, val)) = spec.split_once('=') {
            task.vars.insert(key.to_string(), val.to_string());
        } else if let Ok(val) = std::env::var(spec) {
            task.vars.insert(spec.clone(), val);
        }
    }

    // Inject shell marker (preserving user overrides).
    task.vars
        .entry("MINIMAL_SHELL".to_string())
        .or_insert_with(|| "1".to_string());

    // Build PS1 with the real user and hostname baked in, since the
    // sandbox has no /etc/passwd and its UTS hostname is the state_key.
    let user = std::env::var("USER").unwrap_or_default();
    let hostname = host_hostname();
    task.vars
        .entry("PS1".to_string())
        .or_insert_with(|| format!("(minimal) {}@{}:\\w\\$ ", user, hostname));

    run_task(&task, graph, ctx).await
}

/// Returns the machine hostname, best-effort.
fn host_hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "minimal".to_string())
}
