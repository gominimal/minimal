use std::sync::mpsc::channel;

use crate::{Context, Error, PackagesArg};
use common::archive;
use futures::executor::block_on;
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

    let graph = &graph;
    std::thread::scope(move |s| {
        let mut remote_cache = block_on(ctx.remote_cache()).unwrap();
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
                            archive::compress_dir(cache_dir.path(), Some(20)).unwrap(),
                        ))
                    } else {
                        eprintln!(
                            "Skipping unbuilt package {} [{}]",
                            build.name,
                            bsh.0.to_hex()
                        );
                        None
                    }
                })
                .for_each_with(tx, |tx, data| tx.send(data).unwrap())
        });

        s.spawn(move || {
            for (bsr, (tar_file, sha256)) in rx {
                let build = graph.get(&bsr).unwrap();
                let bsh = graph.spec_hash(&bsr);
                if block_on(remote_cache.upload(&bsh, (tar_file, sha256))).unwrap() {
                    eprintln!("Uploaded {} [{}]", build.name, bsh.0.to_hex());
                } else {
                    eprintln!("{} [{}] is up to date", build.name, bsh.0.to_hex());
                }
            }

            block_on(remote_cache.finish_uploads()).unwrap();
        });
    });

    Ok(())
}
