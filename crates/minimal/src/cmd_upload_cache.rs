use crate::{Error, GlobalArgs, PackagesArg};
use graph::Transitives;

#[derive(clap::Args)]
pub struct UploadArgs {
    #[command(flatten)]
    packages: PackagesArg,
}

pub async fn cmd_upload_cache(args: UploadArgs, globals: &GlobalArgs) -> Result<(), Error> {
    let graph = args.packages.graph(globals)?;
    let cache = globals.cache().map_err(anyhow::Error::from)?;

    let upload_bsrs: Vec<_> = Transitives::for_toplevels(&graph, graph.top_levels.to_vec(), false);

    let mut remote_cache = globals.remote_cache().await.unwrap();

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
