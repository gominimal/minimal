use anyhow::anyhow;
use common::Target;
use graph::Graph;
use mctx::{Config, Context, Error};
use tracing::{trace, warn};

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
                let upstream: mfile::LinkConfig =
                    serde_json_lenient::from_str(&ups).map_err(|e| {
                        clap::Error::raw(
                            clap::error::ErrorKind::ValueValidation,
                            format!("invalid --upstream JSON: {e}\n"),
                        )
                    })?;
                let task: mfile::Task = serde_json_lenient::from_str(&spec).map_err(|e| {
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
                "mip run [OPTIONS] <task_name> [task_args]...\n       \
                 mip run [OPTIONS] --upstream <upstream> --task-spec <task_spec> [task_args]...",
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
                        .parse_argv_named(&format!("mip run {task_name}"), &args.task_args)
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

            let task = gate_task_patches(&task_name, task, ctx)?;
            run_task(&task_name, &task, parsed_args, graph, ctx).await
        }
        RunVariant::BySpec { .. } => {
            unreachable!("BySpec variant should be handled before Context::new via cmd_run_by_spec")
        }
    }
}

/// The `[patches]` gate for the task `mip run <task>` names (inbox#1128):
/// [`mctx::gate_task_patches`], the one gate a task run by name passes, here
/// and in a nested `run <task>` over the sandbox's channel. `mip` builds its
/// config with a [`crate::patch_gate::UserPolicyGate`] (see `base_config`),
/// so the task's entries are judged against the user's `user_policy.toml`.
/// An entry an `ignore` rule dropped is named in a warning.
///
/// Only the named-task lane is gated here: the project file is the untrusted
/// input. A `--task-spec` is typed by the user on the command line.
fn gate_task_patches(
    task_name: &str,
    task: mfile::Task,
    ctx: &Context,
) -> Result<mfile::Task, Error> {
    let gated = mctx::gate_task_patches(ctx, task_name, task)?;
    if let Some(notice) = gated.ignored_notice(task_name) {
        // on stderr, not a log record: a `RUST_LOG=error` filter would hide the one line that says the
        // task runs without a mount it asked for; the nested run sends the same notice as a `msg:` line
        eprintln!("{notice}");
    }
    Ok(gated.task)
}

/// Handles `mip run --upstream ... --task-spec ...` without requiring a minimal.toml.
/// Called before Context::new in main, similar to how `cmd_init` is handled.
pub async fn cmd_run_by_spec(
    mut upstream: mfile::LinkConfig,
    task: Box<mfile::Task>,
    task_args: Vec<String>,
    config: Config,
) -> Result<(), Error> {
    trace!("cmd_run_by_spec");
    super::enforce_science_mode()?;

    let (mut vcs, cache, stdlib_dir) = mctx::DaemonContext::sub_setup(&config)?;

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
                .parse_argv_named("mip run --task-spec ... ", &task_args)
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
    // Preflight (advisory): every build sandbox starts by unsharing an
    // unprivileged user namespace, forked from this process with no exec in
    // between — so this process's own privileges and AppArmor label are what
    // the kernel will check. On a restricted host (stock Ubuntu 24.04+ with
    // an unconfined mip) that denial otherwise surfaces only when the first
    // spawn dies writing /proc/self/uid_map, with nothing useful in the log.
    // Warn once at the start of the first task run instead, with the fix —
    // the cause's own, spelled by `sandbox` for this binary: the installer's
    // profile attaches to minimald alone, so mip's AppArmor remedy is the
    // loader with `--path` for this mip, never `min finalize-install`.
    if let Some(restriction) = sandbox::user_namespaces_restriction() {
        let bin = std::env::current_exe()
            .ok()
            .and_then(|p| p.to_str().map(str::to_owned))
            .unwrap_or_else(|| "<path to this mip binary>".to_string());
        warn!(
            reason = %restriction,
            fix = restriction.remedy(sandbox::RemedyTarget::Mip {
                bin: &bin,
                data_dir: paths::minimal_data_dir().as_str(),
            }),
            docs = "https://docs.minimal.dev/reference/linux-host-setup",
            "builds will fail to start: this host refuses the unprivileged user \
             namespace every build sandbox needs"
        );
    }

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
            // `mip` runs on the user's own host, where the sandbox mirrors
            // host paths, so `~` means the invoking user's home.
            mctx::PatchHome::Ambient,
        )
        .await?;

    // Resolve the invocations to run from the task definition.
    let (_interactive, invocations) = env.task_invocations(task, parsed_args.as_ref()).await?;

    for (i, inv) in invocations.iter().enumerate() {
        // One launch per invocation, as `sandbox::run_with_cancel` does: a
        // spawn is what gets a namespace, so each needs its own plan.
        let planned = env.plan_launch().await?;
        let container = env
            .container(planned.plan())
            .map_err(|e| Error::Other(anyhow!("building container failed: {}", e)))?;
        let mut cmd = env
            .invocation_command(&container, inv)
            .map_err(|e| Error::Other(anyhow!("building command failed: {}", e)))?;
        let mut child = cmd
            .spawn()
            .map_err(|e| Error::Other(anyhow!("command launch failed: {}", e)))?;
        let guard = match planned
            .attach(sandbox::Spawned::from_child(&mut child))
            .await
        {
            Ok(guard) => guard,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e.into());
            }
        };
        let status = child
            .wait()
            .map_err(|e| Error::Other(anyhow!("command failed: {}", e)));
        guard.teardown().await;
        let status = status?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patch_gate::UserPolicyGate;
    use mctx::{ConfigBuilder, TaskPatchPolicy};
    use std::sync::Arc;

    /// `mip run <task>` judges the task's patches before it builds anything
    /// (inbox#1128, scenario 812's shape): a task whose `patch.dir` the user
    /// policy denies is refused with the policy text. This goes through
    /// `cmd_run` itself, so it fails if the call to the gate is dropped.
    #[test]
    fn mip_run_refuses_a_task_whose_patch_the_policy_denies() {
        let state = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let policy_file = cfg.path().join("user_policy.toml");
        std::fs::write(
            &policy_file,
            "[patches]\ndeny = [\"/min-test-1128-denied\", \"/min-test-1128-denied/**\"]\n",
        )
        .unwrap();
        let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        let config = ConfigBuilder::new()
            .with_state_dir(state.path().to_path_buf())
            .with_repo_dir(manifest_dir.join("../mctx/testdata/patchrepo"))
            .with_stdlib_dir(manifest_dir.join("../stdlib/minimal-ncl"))
            .with_no_fetch(true)
            .with_task_patch_policy(TaskPatchPolicy::Gated(Arc::new(UserPolicyGate::at(
                policy_file.clone(),
            ))))
            .build()
            .unwrap();
        let mut ctx = Context::new(config).unwrap();

        let args = RunArgs {
            variant: RunVariant::ByName {
                task_name: "peek-denied".to_string(),
            },
            task_args: vec![],
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(cmd_run(args, &mut ctx))
            .expect_err("a denied patch must refuse the run");
        let text = format!("{err}");
        assert!(text.contains("policy denied"), "{text}");
        assert!(text.contains("/min-test-1128-denied"), "{text}");
        assert!(text.contains(policy_file.to_str().unwrap()), "{text}");
    }
}
