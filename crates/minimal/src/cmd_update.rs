use crate::{Context, Error};

#[derive(clap::Args)]
pub struct UpdateArgs {}

pub async fn cmd_update(_args: UpdateArgs, ctx: &mut Context) -> Result<(), Error> {
    let (mfile_path, up_remote, up_branch, up_ref) = {
        let mfile = ctx.minimal_file()?;
        let upstream = &mfile.upstream;
        (
            mfile.file_path().cloned(),
            upstream.repo.clone(),
            upstream.branch.to_owned(),
            upstream.rev.to_owned(),
        )
    };

    let vcs = ctx.vcs_manager();
    vcs.update()
        .map_err(|e| Error::Other(anyhow::Error::from(e)))?;

    // If theres a minimal file on disk, write the hash of the resulting
    // checkout to the minimal file.
    if let Some(p) = mfile_path {
        let branch = up_branch.unwrap_or("main".to_string());
        let new_rev = vcs
            .checkout_of(&up_remote, checkouts::GitRef::Branch(branch.clone()))
            .map_err(|e| Error::Other(anyhow::Error::from(e)))?
            .1;

        // Only update if there resulting git revision is different.
        if Some(&new_rev) != up_ref.as_ref() {
            use toml_edit::{DocumentMut, value};
            let toml =
                std::fs::read_to_string(&p).map_err(|e| Error::Other(anyhow::Error::from(e)))?;
            let mut doc = toml
                .parse::<DocumentMut>()
                .map_err(|e| Error::Other(anyhow::Error::from(e)))?;
            doc["upstream"]["rev"] = value(new_rev.clone());

            std::fs::write(p, doc.to_string()).map_err(|e| Error::Other(anyhow::Error::from(e)))?;

            match &up_ref {
                None => println!("Upstream {}:{} now at {}", up_remote, branch, new_rev),
                Some(prev_rev) => println!(
                    "Upstream {}:{} updated from {} to {}",
                    up_remote, branch, prev_rev, new_rev
                ),
            }
        }
    }

    Ok(())
}
