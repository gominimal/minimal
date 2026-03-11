//! Command to execute a task on a remote build server.

use std::borrow::Cow;
use std::collections::HashMap;

use anyhow::anyhow;
use mctx::{Context, Error};
use remote_client::{Client, RemoteArgs, Worktree};
use tracing::trace;

#[derive(Debug, clap::Args)]
pub struct RexecArgs {
    /// Address of the remote execution server (e.g. http://localhost:50051)
    #[arg(long)]
    pub addr: String,

    /// Use an ephemeral (empty) working directory instead of the repository
    #[arg(long, default_value_t = false)]
    pub ephemeral: bool,

    /// Packages to make available in the remote environment
    #[arg(long, short, required = true, num_args = 1..)]
    pub packages: Vec<String>,

    /// Command and arguments to execute
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true, num_args = 1..)]
    pub args: Vec<String>,
}

pub async fn cmd_rexec(args: RexecArgs, ctx: &mut Context) -> Result<(), Error> {
    trace!("cmd_rexec");
    let graph = ctx.graph_from_package_names(args.packages.clone())?;

    let mut client = Client::connect(&args.addr, &graph)
        .await
        .map_err(|e| Error::Other(anyhow!("failed to connect to {}: {}", args.addr, e)))?;

    let worktree = if args.ephemeral {
        Worktree::Ephemeral
    } else {
        Worktree::Dir(Cow::Borrowed(ctx.repo_dir()))
    };

    let env = client
        .make_env(worktree)
        .await
        .map_err(|e| Error::Other(anyhow!("failed to create remote environment: {:?}", e)))?;

    let remote_args = RemoteArgs {
        packages: args.packages,
        args: args.args,
        env_vars: HashMap::new(),
    };

    let exit_code = client
        .exec(
            &env,
            &remote_args,
            Some(&mut tokio::io::stdout()),
            Some(&mut tokio::io::stderr()),
        )
        .await
        .map_err(|e| Error::Other(anyhow!("remote exec failed: {:?}", e)))?;

    if exit_code != 0 {
        return Err(Error::Other(anyhow!(
            "remote command exited with code {}",
            exit_code
        )));
    }

    Ok(())
}
