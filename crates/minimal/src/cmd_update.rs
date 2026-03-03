use crate::{Context, Error};

#[derive(clap::Args)]
pub struct UpdateArgs {}

pub async fn cmd_update(_args: UpdateArgs, ctx: &mut Context) -> Result<(), Error> {
    let mfile = ctx.minimal_file();
    let mfile_path = mfile.file_path().cloned();

    let upstream: Option<(String, Option<String>, Option<String>)> = match mfile.upstream.as_ref() {
        Some(mfile::LinkConfig::Git {
            repo,
            branch,
            locked_commit,
        }) => Some((repo.clone(), branch.clone(), locked_commit.clone())),
        Some(mfile::LinkConfig::Dir { .. }) => None,
        None => None,
    };

    // best effort, yeet any cached remote index so a fresh fetch occurs
    std::fs::remove_file(ctx.index_dir().join(rcache::INDEX_FILENAME)).ok();

    let vcs = ctx.vcs_manager();
    vcs.update()
        .map_err(|e| Error::Other(anyhow::Error::from(e)))?;

    // If tracking branch for upstream is specified, check out the new commit
    let new_up_rev = if let Some((repo, Some(b), commit)) = &upstream {
        let new_git_ref = vcs
            .checkout_of(repo, checkouts::GitRef::Branch(b.clone()))?
            .1;
        if Some(&new_git_ref) != commit.as_ref() {
            Some(new_git_ref)
        } else {
            None
        }
    } else {
        None
    };

    // If theres a minimal file on disk, and theres at least one new rev, write the revs to the minimal file.
    if let Some(p) = mfile_path
        && new_up_rev.is_some()
    {
        use toml_edit::{DocumentMut, value};
        let toml = std::fs::read_to_string(&p)
            .map_err(|e| Error::IO("reading minimal.toml for update", p.to_path_buf(), e))?;
        let mut doc = toml
            .parse::<DocumentMut>()
            .map_err(|e| Error::Other(anyhow::Error::from(e)))?;

        // Update upstream
        if let Some(new_rev) = new_up_rev {
            doc["upstream"]["locked_commit"] = value(new_rev.clone());

            println!(
                "Upstream {}:{} updated from {} to {}",
                upstream.as_ref().unwrap().0,
                upstream.as_ref().unwrap().1.as_ref().unwrap(),
                match upstream.as_ref().unwrap().2.clone() {
                    Some(r) => r,
                    None => "<unpinned>".to_string(),
                },
                new_rev
            )
        }

        std::fs::write(p, doc.to_string()).map_err(|e| Error::Other(anyhow::Error::from(e)))?;
    }

    // Enumerate all the reachable transitive packages and
    // make sure we download any we are missing but are available
    // remotely.
    *ctx = ctx.cloned_reinit()?;
    let graph = ctx.graph_from_all_packages()?;
    let ensure_pkgs = ctx.scaffolding_packages()?;
    ctx.download_if_available(&graph, ensure_pkgs).await?;

    Ok(())
}
