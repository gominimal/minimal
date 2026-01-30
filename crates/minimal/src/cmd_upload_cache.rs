use crate::PackagesArg;
use common::archive;
use graph::Transitives;
use mctx::{Context, Error};
use std::sync::mpsc::channel;
use tracing::info;

#[derive(clap::Args)]
pub struct UploadArgs {
    #[command(flatten)]
    packages: PackagesArg,
}

pub async fn cmd_upload_cache(args: UploadArgs, ctx: &mut Context) -> Result<(), Error> {
    let graph = ctx.graph_from_package_names(args.packages.names())?;
    let cache = ctx.local_cache();

    let upload_bsrs: Vec<_> = Transitives::for_toplevels(&graph, graph.top_levels.to_vec(), false)
        .into_keys()
        .collect();

    let graph = &graph;
    let handle = tokio::runtime::Handle::current();
    std::thread::scope(move |s| {
        let (tx, rx) = channel();

        use rayon::prelude::*;
        s.spawn(move || {
            upload_bsrs
                .par_iter()
                .filter_map(|bsr| {
                    let build = graph.get(bsr).unwrap();
                    let bsh = graph.spec_hash(bsr);
                    let cache_hnd = cache.read_dir(&bsh);
                    if let Ok(cache_dir) = cache_hnd {
                        let span = tracing::info_span!(
                            "compress",
                            "indicatif.pb_show" = tracing::field::Empty,
                            "build" = build.name,
                        );
                        let _enter = span.enter();

                        Some((
                            *bsr,
                            archive::compress_dir(cache_dir.path(), Some(16)).unwrap(),
                        ))
                    } else {
                        info!(
                            "Skipping unbuilt package {} [{}]",
                            build.name,
                            bsh.0.to_hex()
                        );
                        None
                    }
                })
                .for_each_with(tx, |tx, data| tx.send(data).unwrap());
        });

        s.spawn(move || {
            let mut remote_cache = handle.block_on(ctx.remote_cache(true)).unwrap();
            for (bsr, (tar_file, sha256)) in rx {
                let build = graph.get(&bsr).unwrap();
                let bsh = graph.spec_hash(&bsr);
                if handle
                    .block_on(remote_cache.upload(&bsh, (tar_file, sha256)))
                    .unwrap()
                {
                    info!("Uploaded {} [{}]", build.name, bsh.0.to_hex());
                } else {
                    info!("{} [{}] is up to date", build.name, bsh.0.to_hex());
                }
            }
            handle.block_on(remote_cache.finish_uploads()).unwrap();
        })
        .join()
        .unwrap();
    });

    Ok(())
}
