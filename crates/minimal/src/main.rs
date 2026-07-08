//! The minimal CLI which pairs/talks-with minimald.

use clap::Parser;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[tokio::main]
async fn main() -> Result<(), ()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("info")
            .add_directive("topiary=off".parse().unwrap())
            .add_directive("libcgroups=off".parse().unwrap())
    });

    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(ot::StdoutWriter::new))
        .with(filter)
        .init();

    let cli = minimal::Cli::parse();

    if let Err(e) = minimal::run(cli).await {
        eprintln!("error: {e:#}");
        return Err(());
    }
    Ok(())
}
