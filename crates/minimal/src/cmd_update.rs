use crate::{Context, Error};

#[derive(clap::Args)]
pub struct UpdateArgs {}

pub async fn cmd_update(_args: UpdateArgs, ctx: &mut Context) -> Result<(), Error> {
    let mfile = ctx.minimal_file()?;
    let mfile_path = mfile.file_path().cloned();

    let upstream: Option<(String, Option<String>, Option<String>)> = match &mfile.upstream {
        mfile::LinkConfig::Dir { .. } => None,
        mfile::LinkConfig::Git {
            repo,
            branch,
            locked_commit,
        } => Some((repo.clone(), branch.clone(), locked_commit.clone())),
    };
    let stdlib: Option<(String, Option<String>, Option<String>)> = match &mfile.stdlib {
        mfile::LinkConfig::Dir { .. } => None,
        mfile::LinkConfig::Git {
            repo,
            branch,
            locked_commit,
        } => Some((repo.clone(), branch.clone(), locked_commit.clone())),
    };

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
    // If tracking branch for stdlib is specified, determine the new git rev it points to.
    let new_std_rev = if let Some((repo, Some(b), commit)) = &stdlib {
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
        && (new_up_rev.is_some() || new_std_rev.is_some())
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
            if let Some(t) = doc["upstream"].as_table_like_mut() {
                t.remove("rev"); // Old name, safe to remove ~feb
            }

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
        // Update stdlib, if it was different.
        if let Some(new_rev) = new_std_rev {
            doc["stdlib"]["locked_commit"] = value(new_rev.clone());
            if let Some(t) = doc["stdlib"].as_table_like_mut() {
                t.remove("rev"); // Old name, safe to remove ~feb
            }

            println!(
                "Stdlib {}:{} updated from {} to {}",
                stdlib.as_ref().unwrap().0,
                stdlib.as_ref().unwrap().1.as_ref().unwrap(),
                match stdlib.as_ref().unwrap().2.clone() {
                    Some(r) => r,
                    None => "<unpinned>".to_string(),
                },
                new_rev
            )
        }

        std::fs::write(p, doc.to_string()).map_err(|e| Error::Other(anyhow::Error::from(e)))?;
    }

    Ok(())
}
