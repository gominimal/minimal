use crate::{Context, Error};

#[derive(clap::Args)]
pub struct UpdateArgs {}

pub async fn cmd_update(_args: UpdateArgs, ctx: &mut Context) -> Result<(), Error> {
    let mfile = ctx.minimal_file();
    let mfile_path = mfile.file_path().cloned();

    let upstream: Option<(String, Option<String>, Option<String>)> =
        match mfile.upstream.as_ref().map(|u| &u.link) {
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

    let mut vcs = ctx.vcs_manager();
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

    // Update all the sideloads, if present
    let sideload_updates = if let Some(sideloads) = mfile.upstream.as_ref().map(|u| u.sideloads()) {
        sideloads
            .iter()
            .map(|s| match s.link() {
                mfile::LinkConfig::Git {
                    repo,
                    branch: Some(branch),
                    locked_commit,
                } => {
                    let new_git_ref = vcs
                        .checkout_of(repo, checkouts::GitRef::Branch(branch.clone()))?
                        .1;
                    if Some(&new_git_ref) != locked_commit.as_ref() {
                        Ok(Some(new_git_ref))
                    } else {
                        Ok(None)
                    }
                }
                _ => Ok(None),
            })
            .collect::<Result<Vec<_>, Error>>()?
    } else {
        vec![]
    };

    // If theres a minimal file on disk, and theres at least one new rev, write the revs to the minimal file.
    if let Some(p) = mfile_path
        && (new_up_rev.is_some() || sideload_updates.iter().any(|u| u.is_some()))
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

        // Update sideloads
        for (i, rev) in sideload_updates.into_iter().enumerate() {
            if let Some(new_rev) = rev {
                println!(
                    "Sideload {}:{} updated from {} to {}",
                    doc["upstream"]["sideload"][i]["repo"].as_str().unwrap(),
                    doc["upstream"]["sideload"][i]["branch"].as_str().unwrap(),
                    doc["upstream"]["sideload"][i]
                        .get("locked_commit")
                        .and_then(|s| s.as_str())
                        .unwrap_or("<unpinned>"),
                    new_rev
                );

                doc["upstream"]["sideload"][i]["locked_commit"] = value(new_rev.clone());
            }
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
