pub mod config;
pub mod error;
pub mod executor;
pub mod output;

pub use config::BuildConfig;
pub use error::{BuildSandboxError as Error, Result};
pub use executor::BuildExecutor;
pub use output::OutputValidator;

pub struct BuildResult {
    pub exit_code: i32,
    pub outputs: Vec<std::path::PathBuf>,
}

#[tracing::instrument(skip_all, fields(name = config.name, indicatif.pb_show))]
pub async fn run_build(
    config: &BuildConfig,
    output_dir: &std::path::Path,
    spongebob_client: &mut spongebob::SpongeBob,
) -> Result<BuildResult> {
    let executor = BuildExecutor::new()?;
    let exit_code = executor.execute(config, spongebob_client).await?;

    let outputs =
        OutputValidator::validate_and_collect(config, &executor.output_staging_dir(), output_dir)?;

    Ok(BuildResult { exit_code, outputs })
}
