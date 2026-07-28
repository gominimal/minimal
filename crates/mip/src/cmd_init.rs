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
        eprintln!("\nWill create {}:\n", plan.toml_path.display());
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

    std::fs::write(&plan.toml_path, &plan.content).map_err(|e| {
        Error::Other(anyhow::anyhow!(
            "writing {}: {}",
            plan.toml_path.display(),
            e
        ))
    })?;

    eprintln!("Created {}", plan.toml_path.display());
    eprintln!();
    eprintln!("Next steps:");
    eprintln!("  mip update      # pin package versions");
    eprintln!("  mip run shell   # enter development shell");
    if plan.matched {
        eprintln!("  mip build       # build the project");
    }

    Ok(())
}
