use crate::{Context, Error};

#[derive(clap::Args)]
pub struct UpdateArgs {}

pub async fn cmd_update(_args: UpdateArgs, ctx: &mut Context) -> Result<(), Error> {
    let (mfile_path, (up_remote, up_branch, up_ref), (std_remote, std_branch, std_ref)) = {
        let mfile = ctx.minimal_file()?;
        let upstream = &mfile.upstream;
        let stdlib = &mfile.stdlib;
        (
            mfile.file_path().cloned(),
            (
                upstream.repo.clone(),
                upstream.branch.to_owned(),
                upstream.rev.to_owned(),
            ),
            (
                stdlib.repo.clone(),
                stdlib.branch.to_owned(),
                stdlib.rev.to_owned(),
            ),
        )
    };

    let vcs = ctx.vcs_manager();
    vcs.update()
        .map_err(|e| Error::Other(anyhow::Error::from(e)))?;

    // If tracking branch for upstream is specified, determine the new git rev it points to.
    let new_up_rev = if let Some(b) = &up_branch {
        Some(
            vcs.checkout_of(&up_remote, checkouts::GitRef::Branch(b.clone()))
                .map_err(|e| Error::Other(anyhow::Error::from(e)))?
                .1,
        )
    } else {
        None
    };
    // If tracking branch for stdlib is specified, determine the new git rev it points to.
    let new_std_rev = if let Some(b) = &std_branch {
        Some(
            vcs.checkout_of(&std_remote, checkouts::GitRef::Branch(b.clone()))
                .map_err(|e| Error::Other(anyhow::Error::from(e)))?
                .1,
        )
    } else {
        None
    };

    // If theres a minimal file on disk, write the revs to the minimal file.
    if let Some(p) = mfile_path {
        use toml_edit::{DocumentMut, value};
        let toml = std::fs::read_to_string(&p).map_err(|e| Error::Other(anyhow::Error::from(e)))?;
        let mut doc = toml
            .parse::<DocumentMut>()
            .map_err(|e| Error::Other(anyhow::Error::from(e)))?;
        let mut did_update = false;

        // Update upstream, if it was different.
        if let Some(new_rev) = new_up_rev
            && Some(&new_rev) != up_ref.as_ref()
        {
            doc["upstream"]["rev"] = value(new_rev.clone());
            did_update = true;

            println!(
                "Upstream {}:{} updated from {} to {}",
                up_remote,
                up_branch.unwrap(),
                match up_ref {
                    Some(r) => r,
                    None => "<unpinned>".to_string(),
                },
                new_rev
            )
        }
        // Update stdlib, if it was different.
        if let Some(new_rev) = new_std_rev
            && Some(&new_rev) != std_ref.as_ref()
        {
            doc["stdlib"]["rev"] = value(new_rev.clone());
            did_update = true;

            println!(
                "Stdlib {}:{} updated from {} to {}",
                std_remote,
                std_branch.unwrap(),
                match std_ref {
                    Some(r) => r,
                    None => "<unpinned>".to_string(),
                },
                new_rev
            )
        }

        if did_update {
            std::fs::write(p, doc.to_string()).map_err(|e| Error::Other(anyhow::Error::from(e)))?;
        }
    }

    Ok(())
}
