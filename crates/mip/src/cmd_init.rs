//! Command to initialize a minimal file based on matching the source tree to a valid harness.

use std::io::Write;

use mctx::{Config, Error, ProjectSetup};
use op::{InitProject, ProjectOp};

#[derive(clap::Args)]
pub struct InitArgs {
    /// Skip confirmation, writing configuration based on auto-detection
    #[arg(long, short, default_value_t = false)]
    yes: bool,
}

pub async fn cmd_init(args: InitArgs, config: Config) -> Result<(), Error> {
    let mut env = ProjectSetup::for_init(config)?;
    let plan = InitProject.run(&mut env)?;

    // -- Confirmation prompt (unless --yes) --
    if !args.yes {
        let verb = if plan.toml_path.exists() {
            "overwrite"
        } else {
            "create"
        };
        eprintln!("\nWill {verb} {}:\n", plan.toml_path.display());
        eprintln!("---");
        eprint!("{}", plan.content);
        eprintln!("---");
        eprintln!();
        eprint!("Continue? [Y/n] ");
        std::io::stderr().flush().ok();

        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| Error::Other(anyhow::anyhow!("reading stdin: {}", e)))?;
        let trimmed = input.trim();
        if !(trimmed.eq_ignore_ascii_case("y")
            || trimmed.eq_ignore_ascii_case("yes")
            || trimmed.is_empty())
        {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    // Write under the same lock and atomic rename `min init`, `min add` and
    // `min update` use, so a concurrent edit is neither lost nor torn. `mip
    // init` has always overwritten an existing file, so it keeps doing that;
    // whether the file existed under the lock decides Created vs Updated.
    let mut existed = false;
    mfile::File::edit_exclusively::<Error>(&plan.toml_path, |content| {
        existed = content.is_some();
        Ok(Some(plan.content.clone()))
    })
    .map_err(|e| {
        Error::Other(anyhow::anyhow!(
            "writing {}: {}",
            plan.toml_path.display(),
            e
        ))
    })?;

    let verb = if existed { "Updated" } else { "Created" };
    eprintln!("{verb} {}", plan.toml_path.display());
    eprintln!();
    eprintln!("Next steps:");
    eprintln!("  mip update      # pin package versions");
    eprintln!("  mip run shell   # enter development shell");
    if plan.matched {
        eprintln!("  mip build       # build the project");
    }

    Ok(())
}
