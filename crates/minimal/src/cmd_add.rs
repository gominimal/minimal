//! Command to add packages as a dependency.

use std::time::SystemTime;

use anyhow::anyhow;
use cache::{EntryMeta, MetaInner};
use graph::Transitives;
use mctx::{Context, Error};
use toml_edit::{Array, DocumentMut, Item, TableLike, Value};

#[derive(clap::Args)]
pub struct AddArgs {
    #[command(flatten)]
    pub kind: AddKind,

    /// Packages to add, comma-separated
    #[arg(value_delimiter=',', num_args=0..)]
    pub packages: Vec<String>,
}

#[derive(clap::Args, Debug)]
#[group(required = false, multiple = false)]
pub struct AddKind {
    /// Add as a runtime dependency - your program needs this package anywhere it runs
    #[arg(long)]
    runtime: bool,

    /// Add as a tool - made available in your development shell
    #[arg(long, alias = "shell")]
    tool: bool,
}

pub async fn cmd_add(args: AddArgs, ctx: &mut Context) -> Result<(), Error> {
    // Side-effect of making sure the named packages exist.
    let graph = ctx.graph_from_package_names(args.packages.clone())?;

    let mfile = ctx.minimal_file()?;
    let mfile_path = mfile.file_path().cloned();

    if mfile_path.is_none() {
        return Err(Error::Other(anyhow!(
            "Cannot add dependency - no minimal.toml located."
        )));
    }
    let mfile_path = mfile_path.unwrap();

    let toml = std::fs::read_to_string(&mfile_path)
        .map_err(|e| Error::IO("reading minimal.toml for add", mfile_path.to_path_buf(), e))?;
    let mut doc = toml
        .parse::<DocumentMut>()
        .map_err(|e| Error::Other(anyhow!("parsing minimal.toml: {}", e)))?;

    match args.kind {
        AddKind {
            runtime: true,
            tool: true,
        } => unreachable!(),
        // Build-time dependency
        AddKind {
            runtime: false,
            tool: false,
        } => {
            if let Some(h) = doc["harness"].as_table_mut() {
                upsert_toml_packages_list(h, "build_packages", &args.packages);
                println!(
                    "Added [{}] to harness.build_packages",
                    args.packages.join(",")
                );
            } else {
                return Err(Error::Other(anyhow!(
                    "could not find [harness] in minimal.toml: needed for update"
                )));
            }
        }
        // Run-time dependency
        AddKind {
            runtime: true,
            tool: false,
        } => {
            if let Some(h) = doc["harness"].as_table_mut() {
                upsert_toml_packages_list(h, "runtime_packages", &args.packages);
                println!(
                    "Added [{}] to harness.runtime_packages",
                    args.packages.join(",")
                );
            } else {
                return Err(Error::Other(anyhow!(
                    "could not find [harness] in minimal.toml: needed for update"
                )));
            }
        }
        // Tool
        AddKind {
            runtime: false,
            tool: true,
        } => {
            if let Some(tasks) = doc.get_mut("tasks")
                && let Some(shell) = tasks.get_mut("shell")
            {
                upsert_toml_packages_list(
                    shell.as_table_mut().unwrap(),
                    "packages",
                    &args.packages,
                );
                println!(
                    "Added [{}] to tasks.shell.packages",
                    args.packages.join(",")
                );
            } else {
                return Err(Error::Other(anyhow!(
                    "could not find [tasks.shell] in minimal.toml: needed for update"
                )));
            }
        }
    }

    std::fs::write(&mfile_path, doc.to_string())
        .map_err(|e| Error::Other(anyhow::Error::from(e)))?;

    // Make sure we have those packages locally!
    let cache = ctx.local_cache();
    let rc = ctx.remote_cache(false, true).await.unwrap();
    let mut task_set = tokio::task::JoinSet::new();
    let fetch_start = SystemTime::now();
    for (bsr, _depinfo) in Transitives::for_toplevels(&graph, graph.top_levels.clone(), false) {
        let b = graph.get(&bsr).unwrap();
        let name = b.name.clone();
        let origin = b.from.as_ref().clone();
        let spec_hash = graph.spec_hash(&bsr);
        if let Err(cache::CacheErr::NotFound) = cache.read_dir(&spec_hash)
            && rc.exists(&spec_hash)
        {
            let rc_clone = rc.clone(); // TODO: This is trash
            let cache_clone = cache.clone();
            task_set.spawn(async move {
                rc_clone
                    .materialize(&spec_hash, &cache_clone, &name)
                    .await
                    .map(|(t, d)| {
                        (
                            d,
                            EntryMeta {
                                inner: MetaInner::Spec(name),
                                fetched: true,
                                fetch_ms: Some(t.as_millis() as usize),
                                origin: Some(origin),
                                ..Default::default()
                            },
                        )
                    })
            });
        }
    }

    // Wait for all materialization tasks to complete, committing each pending dir
    // to the cache as it is finished being staged
    while let Some(result) = task_set.join_next().await {
        let (pending_dir, meta) = result
            .unwrap()
            .map_err(|e| Error::Other(anyhow::Error::from(e)))?;
        pending_dir.finalize(meta).unwrap();
    }
    tracing::trace!("package fetch took {:?}", fetch_start.elapsed());

    Ok(())
}

fn upsert_toml_packages_list<T: TableLike>(t: &mut T, key: &str, upsert: &[String]) {
    if let Some(bp) = t.get_mut(key) {
        let mut existing: Vec<_> = bp
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i.as_str().unwrap())
            .collect();

        upsert.iter().for_each(|p| {
            if !existing.contains(&p.as_str()) {
                existing.push(p);
            }
        });
        *bp = Item::Value(Value::Array(Array::from_iter(existing)));
    } else {
        t.insert(key, Item::Value(Value::Array(Array::from_iter(upsert))));
    }
}
