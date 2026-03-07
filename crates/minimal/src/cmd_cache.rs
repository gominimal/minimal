use std::{
    collections::HashSet,
    time::{Duration, SystemTime},
};

use anyhow::anyhow;

use crate::{Context, Error};

#[derive(Debug, clap::Subcommand)]
pub enum CacheArgs {
    Clean {
        #[arg(long, value_parser = parse_duration, default_value = "14d")]
        older_than: Duration,
    },
}

fn parse_duration(arg: &str) -> Result<std::time::Duration, anyhow::Error> {
    if let Some(v) = arg.strip_suffix("d") {
        let days: u64 = v.parse().map_err(|e| anyhow!("parsing days: {}", e))?;
        Ok(std::time::Duration::from_hours(24 * days))
    } else if let Some(v) = arg.strip_suffix("h") {
        let hours: u64 = v.parse().map_err(|e| anyhow!("parsing hours: {}", e))?;
        Ok(std::time::Duration::from_hours(hours))
    } else if let Some(v) = arg.strip_suffix("m") {
        let minutes: u64 = v.parse().map_err(|e| anyhow!("parsing minutes: {}", e))?;
        Ok(std::time::Duration::from_mins(minutes))
    } else {
        Err(anyhow!("invalid duration: {}", arg))
    }
}

pub async fn cmd_cache(args: CacheArgs, ctx: &mut Context) -> Result<(), Error> {
    let graph = ctx.graph_from_all_packages()?;
    let need_objs = ctx
        .scaffolding_packages()?
        .into_iter()
        .map(|bsr| graph.spec_hash(&bsr))
        .collect::<HashSet<_>>();

    let cache = ctx.local_cache();
    let rt = cache.atimes().unwrap();
    let candidates = cache.iter_entries().filter_map(|e| {
        if need_objs.contains(&e) {
            None
        } else {
            let last_use = rt.last_read(&e);
            Some((e, last_use))
        }
    });

    let now = SystemTime::now();
    match args {
        CacheArgs::Clean { older_than } => {
            let cutoff = now.checked_sub(older_than).unwrap();
            for (spec_hash, last_used) in candidates {
                if last_used.is_none() || last_used.as_ref().unwrap() < &cutoff {
                    let ident = if let Ok(meta) = cache.read_meta(&spec_hash) {
                        format!("{} [{}]", meta.inner, spec_hash.0)
                    } else {
                        format!("Object [{}]", spec_hash.0)
                    };

                    println!("Deleting {}", ident);
                    cache
                        .invalidate_dir(&spec_hash)
                        .map_err(|e| Error::Other(anyhow!(e)))?;
                }
            }
        }
    }

    Ok(())
}
