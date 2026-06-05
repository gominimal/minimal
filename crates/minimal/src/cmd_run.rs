use anyhow::anyhow;
use common::Target;
use graph::Graph;
use mctx::{Config, Context, Error};
use tracing::trace;

/// Specifies which task to run.
#[derive(Debug, Clone)]
pub enum RunVariant {
    /// Run a task by name from `minimal.toml`.
    ByName { task_name: String },
    /// Run a task specified inline via upstream and task-spec strings.
    BySpec {
        upstream: mfile::LinkConfig,
        task_spec: Box<mfile::Task>,
    },
}

#[derive(Debug)]
pub struct RunArgs {
    pub variant: RunVariant,
    /// Additional arguments to pass to the task, parsed according to the task's args schema.
    pub task_args: Vec<String>,
}

impl clap::FromArgMatches for RunArgs {
    fn from_arg_matches(matches: &clap::ArgMatches) -> Result<Self, clap::Error> {
        let upstream = matches.get_one::<String>("upstream").cloned();
        let task_spec = matches.get_one::<String>("task_spec").cloned();
        let task_name = matches.get_one::<String>("task_name").cloned();
        let task_args: Vec<String> = matches
            .get_many::<String>("task_args")
            .unwrap_or_default()
            .cloned()
            .collect();

        let variant = match (task_name, upstream, task_spec) {
            (Some(name), None, None) => RunVariant::ByName { task_name: name },
            (None, Some(ups), Some(spec)) => {
                let upstream: mfile::LinkConfig = serde_json::from_str(&ups).map_err(|e| {
                    clap::Error::raw(
                        clap::error::ErrorKind::ValueValidation,
                        format!("invalid --upstream JSON: {e}\n"),
                    )
                })?;
                let task: mfile::Task = serde_json::from_str(&spec).map_err(|e| {
                    clap::Error::raw(
                        clap::error::ErrorKind::ValueValidation,
                        format!("invalid --task-spec JSON: {e}\n"),
                    )
                })?;
                RunVariant::BySpec {
                    upstream,
                    task_spec: Box::new(task),
                }
            }
            (None, Some(_), None) | (None, None, Some(_)) => {
                return Err(clap::Error::raw(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    "--upstream and --task-spec must both be provided\n",
                ));
            }
            (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
                return Err(clap::Error::raw(
                    clap::error::ErrorKind::ArgumentConflict,
                    "cannot use <task_name> with --upstream/--task-spec\n",
                ));
            }
            (None, None, None) => {
                return Err(clap::Error::raw(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    "either <task_name> or --upstream/--task-spec is required\n",
                ));
            }
        };

        Ok(RunArgs { variant, task_args })
    }

    fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches) -> Result<(), clap::Error> {
        *self = Self::from_arg_matches(matches)?;
        Ok(())
    }
}

impl clap::Args for RunArgs {
    fn augment_args(cmd: clap::Command) -> clap::Command {
        cmd.trailing_var_arg(true)
            .override_usage(
                "minimal run [OPTIONS] <task_name> [task_args]...\n       \
                 minimal run [OPTIONS] --upstream <upstream> --task-spec <task_spec> [task_args]...",
            )
            .arg(
                clap::Arg::new("task_name")
                    .help("Name of the task to run (from minimal.toml)")
                    .conflicts_with_all(["upstream", "task_spec"])
                    .value_parser(clap::builder::NonEmptyStringValueParser::new()),
            )
            .arg(
                clap::Arg::new("upstream")
                    .long("upstream")
                    .help("JSON stanza specifying the software supply chain")
                    .long_help(
                        "JSON stanza specifying the software supply chain. Must be used with --task-spec.\n\n\
                         Example:\n  \
                         '{\"repo\": \"https://github.com/gominimal/pkgs\", \"branch\": \"main\", \"locked_commit\": \"abc\"}'",
                    )
                    .requires("task_spec")
                    .value_parser(clap::builder::NonEmptyStringValueParser::new()),
            )
            .arg(
                clap::Arg::new("task_spec")
                    .long("task-spec")
                    .help("JSON stanza specifying a task.")
                    .long_help(
                        "JSON stanza specifying a task. Must be used with --upstream.\n\n\
                         Example:\n  \
                         '{\"exec\": \"echo hello\", \"packages\": [\"coreutils\"]}'",
                    )
                    .requires("upstream")
                    .value_parser(clap::builder::NonEmptyStringValueParser::new()),
            )
            .arg(
                clap::Arg::new("task_args")
                    .help("Additional arguments to pass to the task")
                    .trailing_var_arg(true)
                    .allow_hyphen_values(true)
                    .num_args(..),
            )
    }

    fn augment_args_for_update(cmd: clap::Command) -> clap::Command {
        Self::augment_args(cmd)
    }
}

pub async fn cmd_run(args: RunArgs, ctx: &mut Context) -> Result<(), Error> {
    trace!("cmd_run");

    match args.variant {
        RunVariant::ByName { task_name } => {
            let graph = ctx.graph_from_all_packages()?;
            let (task, graph) = match ctx.task(graph, &task_name)? {
                None => return Err(Error::Other(anyhow!("no such task: {}", task_name))),
                Some((t, g)) => (t, g),
            };

            let parsed_args = if !task.args.is_empty() {
                Some(
                    task.args
                        .parse_argv_named(&format!("minimal run {}", task_name), &args.task_args)
                        .map_err(|e| {
                            e.print().unwrap();
                            Error::Other(anyhow!(
                                "task {} called with invalid arguments",
                                task_name
                            ))
                        })?,
                )
            } else {
                None
            };

            run_task(&task_name, &task, parsed_args, graph, ctx).await
        }
        RunVariant::BySpec { .. } => {
            unreachable!("BySpec variant should be handled before Context::new via cmd_run_by_spec")
        }
    }
}

/// Handles `minimal run --upstream ... --task-spec ...` without requiring a minimal.toml.
/// Called before Context::new in main, similar to how `cmd_init` is handled.
pub async fn cmd_run_by_spec(
    mut upstream: mfile::LinkConfig,
    task: Box<mfile::Task>,
    task_args: Vec<String>,
    config: Config,
) -> Result<(), Error> {
    trace!("cmd_run_by_spec");
    super::enforce_science_mode()?;

    let (mut vcs, cache, stdlib_dir) = Context::sub_setup(&config)?;

    // We let the upstream omit locked_commit, in which case we fetch the latest
    // and use that.
    if let mfile::LinkConfig::Git {
        repo,
        branch: Some(b),
        locked_commit,
    } = &mut upstream
        && locked_commit.is_none()
    {
        vcs.update()?;
        *locked_commit = Some(
            vcs.checkout_of(&repo.clone(), checkouts::GitRef::Branch(b.clone()))?
                .1,
        );
    }

    let mut ctx = Context::new_from_parts(
        config
            .into_builder()
            .with_vcs_manager(vcs.clone())
            .with_repo_dir(std::env::current_dir().unwrap())
            .build()
            .unwrap(),
        mfile::File::synthetic(upstream.clone()),
        vcs,
        cache,
        stdlib_dir.clone(),
    );

    let graph = Graph::new_from_chain(
        ctx.vcs_manager(),
        &mut graph::LayerCacheDir(ctx.layer_cache_dir()),
        upstream,
        stdlib_dir,
        Target::host(),
    )?;

    let parsed_args = if !task.args.is_empty() {
        Some(
            task.args
                .parse_argv_named("minimal run --task-spec ... ", &task_args)
                .map_err(|e| {
                    e.print().unwrap();
                    Error::Other(anyhow!("task called with invalid arguments",))
                })?,
        )
    } else {
        None
    };

    run_task("task", &task, parsed_args, graph, &mut ctx).await
}

pub async fn run_task(
    task_name: &str,
    task: &mfile::Task,
    parsed_args: Option<args::ArgsSet>,
    mut graph: Graph,
    ctx: &mut Context,
) -> Result<(), Error> {
    let mut env = ctx
        .make_env(
            task_name,
            &mut graph,
            if task.inherit_cwd {
                Some(std::env::current_dir().unwrap())
            } else {
                None
            },
            task.state_key.as_ref(),
            Some(&task.patch),
            Some(&task.vars),
            task.packages.clone(),
        )
        .await?;

    // Resolve the invocations to run from the task definition.
    let (_interactive, invocations) = env.task_invocations(task, parsed_args.as_ref()).await?;

    let container = env
        .container()
        .map_err(|e| Error::Other(anyhow!("building container failed: {}", e)))?;
    for (i, inv) in invocations.iter().enumerate() {
        let mut cmd = env
            .command(&container, &inv.executable, inv.args.iter())
            .map_err(|e| Error::Other(anyhow!("building command failed: {}", e)))?;
        let status = cmd
            .spawn()
            .map_err(|e| Error::Other(anyhow!("command launch failed: {}", e)))?
            .wait()
            .map_err(|e| Error::Other(anyhow!("command failed: {}", e)))?;
        if !status.success() {
            return Err(Error::Execution {
                idx: i,
                code: status.code,
                reason: status.reason,
                stderr: String::new(),
                stdout: String::new(),
            });
        }
    }

    Ok(())
}
