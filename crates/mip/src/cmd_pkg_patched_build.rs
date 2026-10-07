use crate::{Context, Error};
use anyhow::anyhow;
use op::{PatchedBuild, Runnable};

#[derive(Debug, clap::Args)]
pub struct PkgPatchedBuildArgs {
    package: String,
}

pub async fn cmd_pkg_patched_build(
    args: PkgPatchedBuildArgs,
    ctx: &mut Context,
) -> Result<(), Error> {
    crate::enforce_science_mode()?;

    let graph = ctx.graph_from_package_names([args.package])?;
    let cache = ctx.local_cache();

    let remote_storage = ctx.remote_storage().await.unwrap();

    let remote_cache = if ctx.use_remote_cache() {
        // `{:#}` keeps the cause visible, since `Error::Other` displays with `{}`.
        Some(ctx.remote_cache(false, false).await.map_err(|e| {
            Error::Other(anyhow!(
                "{:#}",
                mctx::remote_cache_setup_error(e, Some("pass --no-fetch to build without it"))
            ))
        })?)
    } else {
        None
    };

    let bsr = graph.top_levels[0];

    let output_base = ctx.builds_base_dir();
    std::fs::create_dir_all(&output_base).ok();
    let res = PatchedBuild {
        spec: &bsr,
        remote_fetcher: &remote_storage,
        stdout_writer: Some(Box::new(common::TracingWriter::stdout())),
        stderr_writer: Some(Box::new(common::TracingWriter::stderr())),
        remote_cache: remote_cache.as_ref(),
    }
    .run(&op::Options {
        cache,
        graph: &graph,
        exec_base: output_base,
        ot: ctx.op_tracker(),
        daemon_id: ctx.daemon_id(),
    })
    .await
    .map_err(|e| Error::Other(anyhow!("build failed: {}", e)))?;

    res.outputs.finalize(res.meta).unwrap();
    println!("Written to cache with hash {}", graph.spec_hash(&bsr).0);

    Ok(())
}
