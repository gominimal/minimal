use crate::{Error, GlobalArgs, PackagesArg};
use cache::RemoteCache;
use google_cloud_storage::client::Storage;
use graph::Transitives;

#[derive(clap::Args)]
pub struct UploadArgs {
    #[command(flatten)]
    packages: PackagesArg,
}

pub async fn cmd_upload_cache(args: UploadArgs, globals: &GlobalArgs) -> Result<(), Error> {
    let graph = args.packages.graph(globals)?;
    let cache = globals.cache().map_err(anyhow::Error::from)?;

    let mut upload_bsrs: Vec<_> = graph
        .top_levels
        .iter()
        .map(|base| Transitives::new(&graph, base, false))
        .flat_map(|t| {
            t.transitive_runtime_deps
                .keys()
                .map(|bsr| bsr.clone())
                .collect::<Vec<_>>()
        })
        .chain(graph.top_levels.iter().map(|bsr| bsr.clone()))
        .collect();
    upload_bsrs.sort();
    upload_bsrs.dedup();

    let mut remote_cache = RemoteCache::new_with_gcs_bucket(
        Storage::builder()
            .build()
            .await
            .map_err(anyhow::Error::from)?,
        "minimal-staging-cache",
    )
    .await
    .unwrap();

    for bsr in &upload_bsrs {
        let build = graph.get(bsr).unwrap();
        let bsh = graph.spec_hash(bsr);

        let is_cached = cache.read_dir(&bsh).is_ok();
        if is_cached {
            eprintln!("Uploading {} [{}]", build.name, bsh.0.to_hex());
            remote_cache.upload(&bsh, &cache).await.unwrap();
        } else {
            eprintln!(
                "Skipping unbuild package {} [{}]",
                build.name,
                bsh.0.to_hex()
            );
        }
    }

    remote_cache.finish_uploads().await.unwrap();

    Ok(())
}
