pub mod config;
pub mod error;
pub mod executor;
pub mod output;

pub use config::BuildConfig;
pub use error::{BuildSandboxError as Error, Result};
pub use executor::BuildExecutor;
pub use output::OutputValidator;

use tracing::info;

pub struct BuildResult {
    pub exit_code: i32,
    pub outputs: Vec<std::path::PathBuf>,
}

pub fn run_build(
    config: &BuildConfig,
    output_dir: &std::path::Path,
    verbose: bool,
) -> Result<BuildResult> {
    info!("Starting build execution");
    let executor = BuildExecutor::new()?;
    let build_result = executor.execute(config, verbose)?;

    let outputs = if config.debug_shell {
        info!("Debug mode: skipping output validation");
        Vec::new()
    } else {
        let outputs = OutputValidator::validate_and_collect(
            config,
            executor.output_staging_dir(),
            output_dir,
            verbose,
        )?;
        info!(
            "Build completed with exit code {}, {} outputs",
            build_result.exit_code,
            outputs.len()
        );
        outputs
    };

    Ok(BuildResult {
        exit_code: build_result.exit_code,
        outputs,
    })
}
