use crate::{Context, Error, PackagesArg};
use graph::Transitives;

#[derive(clap::Args)]
pub struct UploadArgs {
    #[command(flatten)]
    packages: PackagesArg,
}

pub async fn cmd_upload_cache(args: UploadArgs, ctx: &mut Context) -> Result<(), Error> {
    let graph = args.packages.graph(ctx)?;
    let cache = ctx.local_cache();

    let upload_bsrs: Vec<_> = Transitives::for_toplevels(&graph, graph.top_levels.to_vec(), false);

    let mut remote_cache = ctx.remote_cache().await.unwrap();

    for bsr in &upload_bsrs {
        let build = graph.get(bsr).unwrap();
        let bsh = graph.spec_hash(bsr);

        let is_cached = cache.read_dir(&bsh).is_ok();
        if is_cached {
            eprintln!("Uploading {} [{}]", build.name, bsh.0.to_hex());
            remote_cache.upload(&bsh, &cache).await.unwrap();
        } else {
            eprintln!(
                "Skipping unbuilt package {} [{}]",
                build.name,
                bsh.0.to_hex()
            );
        }
    }

    remote_cache.finish_uploads().await.unwrap();

    Ok(())
}
