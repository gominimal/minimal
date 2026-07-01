//! Command to build packages on a remote build server.

use anyhow::anyhow;
use mctx::{Context, Error};
use remote_client::Client;
use tracing::trace;

#[derive(Debug, clap::Args)]
pub struct RemoteBuildArgs {
    /// Address of the remote build server (e.g. http://localhost:50051)
    #[arg(long)]
    pub addr: String,

    /// Enable verbose build output
    #[arg(long, default_value_t = false)]
    pub verbose: bool,

    /// Commit successful builds to the cache on the remote server
    #[arg(long, default_value_t = false)]
    pub commit: bool,

    /// Build all named packages, even if they are already available
    #[arg(long, default_value_t = false)]
    pub rebuild: bool,

    /// Packages to build
    #[arg(long, short, required = true, num_args = 1..)]
    pub packages: Vec<String>,
}

pub async fn cmd_remote_build(args: RemoteBuildArgs, ctx: &mut Context) -> Result<(), Error> {
    trace!("cmd_remote_build");
    let graph = ctx.graph_from_package_names(args.packages)?;

    let mut client = Client::connect(&args.addr, &graph)
        .await
        .map_err(|e| Error::Other(anyhow!("failed to connect to {}: {}", args.addr, e)))?;

    client
        .build(
            args.verbose,
            args.commit,
            args.rebuild,
            Some("minimal-staging-cache".to_string()),
            None,
        )
        .await
        .map_err(|e| Error::Other(anyhow!("remote build failed: {:?}", e)))?;

    Ok(())
}
