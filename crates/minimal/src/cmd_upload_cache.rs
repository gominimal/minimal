use crate::{Context, Error, PackagesArg};
use common::archive;
use graph::{BuildSpecRef, Transitives};

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

    use rayon::prelude::*;
    let uploadables: Vec<(BuildSpecRef, (std::fs::File, [u8; 32]))> = upload_bsrs
        .par_iter()
        .filter_map(|bsr| {
            let build = graph.get(bsr).unwrap();
            let bsh = graph.spec_hash(bsr);
            let cache_hnd = cache.read_dir(&bsh);
            if let Ok(cache_dir) = cache_hnd {
                let span = tracing::info_span!(
                    "compress_outputs",
                    "indicatif.pb_show" = tracing::field::Empty,
                    "build" = build.name,
                );
                let _enter = span.enter();

                Some((*bsr, archive::compress_dir(cache_dir.path()).unwrap()))
            } else {
                eprintln!(
                    "Skipping unbuilt package {} [{}]",
                    build.name,
                    bsh.0.to_hex()
                );
                None
            }
        })
        .collect();

    for (bsr, (tar_file, sha256)) in uploadables.into_iter() {
        let build = graph.get(&bsr).unwrap();
        let bsh = graph.spec_hash(&bsr);
        eprintln!("Uploading {} [{}]", build.name, bsh.0.to_hex());
        remote_cache.upload(&bsh, (tar_file, sha256)).await.unwrap();
    }
    remote_cache.finish_uploads().await.unwrap();

    Ok(())
}
