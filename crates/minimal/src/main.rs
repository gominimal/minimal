use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

mod run;

mod cmd_build;
use cmd_build::{BuildArgs, cmd_build};

#[derive(Parser)]
#[command(name = "minimal")]
#[command(about = "A minimal package manager")]
enum Cli {
    Build(BuildArgs),
}

pub fn load_cache(
    cache_dir: Option<PathBuf>,
) -> Result<cache::Cache<cache::LocalDir>, std::io::Error> {
    cache::Cache::at_dir(cache_dir.unwrap_or_else(|| {
        let dir = dirs::cache_dir().unwrap().join("minimal-builds");
        match std::fs::create_dir(&dir) {
            Ok(_) => {}
            Err(e) => {
                if e.kind() != std::io::ErrorKind::AlreadyExists {
                    panic!("failed to create build cache dir: {}", e);
                }
            }
        };
        dir
    }))
}

fn main() -> build_sandbox::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug")))
        .init();

    match Cli::parse() {
        Cli::Build(args) => cmd_build(args),
    }
}
