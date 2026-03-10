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

    for sandbox in std::fs::read_dir(ctx.builds_base_dir())
        .map_err(|e| Error::IO("reading sandboxes dir", ctx.builds_base_dir(), e))?
    {
        let entry = sandbox.map_err(|e| Error::IO("sandbox entry", ctx.builds_base_dir(), e))?;
        cleanup_stale("sandbox", entry)?;
    }
    for task in std::fs::read_dir(ctx.tasks_base_dir())
        .map_err(|e| Error::IO("reading tasks dir", ctx.tasks_base_dir(), e))?
    {
        let entry = task.map_err(|e| Error::IO("task entry", ctx.tasks_base_dir(), e))?;
        cleanup_stale("task", entry)?;
    }
    for at in std::fs::read_dir(ctx.cache_base_dir().join("temp"))
        .map_err(|e| Error::IO("reading artifact temp dir", ctx.tasks_base_dir(), e))?
    {
        let entry = at.map_err(|e| Error::IO("artifact temp entry", ctx.tasks_base_dir(), e))?;
        cleanup_stale("tempdir", entry)?;
    }

    Ok(())
}

fn cleanup_stale(kind: &str, entry: std::fs::DirEntry) -> Result<(), Error> {
    let name = entry.file_name();
    let s = name.to_str().unwrap();
    if s.contains("-")
        && let Some(pid_str) = s.rsplit('-').next()
        && let Ok(false) = std::fs::exists(format!("/proc/{}", pid_str))
    {
        // No such proc entry, therefore PID dead. Clean up directory.
        println!("Cleaning up stale {} {}", kind, s);
        std::fs::remove_dir_all(entry.path())
            .map_err(|e| Error::IO("rm stale sandbox", entry.path(), e))?;
    }

    Ok(())
}
