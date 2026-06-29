use crate::{Context, Error};
use op::{ProjectOp, UpdateProject};

#[derive(clap::Args)]
pub struct UpdateArgs {}

pub async fn cmd_update(_args: UpdateArgs, ctx: &mut Context) -> Result<(), Error> {
    // Refresh upstream/sideload checkouts and re-pin them in the minimal file.
    let mut env = ctx.project_setup();
    let report = UpdateProject.run(&mut env)?;

    if report.migrated_harness {
        println!("Renamed `[harness]` to its new name `[stack]`");
    }
    if let Some(c) = &report.upstream {
        println!(
            "Upstream {}:{} updated from {} to {}",
            c.repo,
            c.branch,
            c.from.as_deref().unwrap_or("<unpinned>"),
            c.to,
        );
    }
    for c in &report.sideloads {
        println!(
            "Sideload {}:{} updated from {} to {}",
            c.repo,
            c.branch,
            c.from.as_deref().unwrap_or("<unpinned>"),
            c.to,
        );
    }

    // Enumerate all the reachable transitive packages and make sure we download
    // any we are missing but are available remotely. This is a separate step
    // from the minimal-file refresh above.
    *ctx = ctx.cloned_reinit()?;
    let graph = ctx.graph_from_all_packages()?;
    let ensure_pkgs = ctx.scaffolding_packages()?;
    ctx.download_if_available(&graph, ensure_pkgs).await?;

    Ok(())
}
