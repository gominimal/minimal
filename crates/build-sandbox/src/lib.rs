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
    pub spongebob_url: Option<String>,
}

/// Run a build in a sandboxed environment
///
/// # Parameters
/// * `config` - Build configuration including inputs, outputs, and build script
/// * `cache_dest_dir` - Final destination in cache where successful build outputs are stored
/// * `sandbox_base_dir` - Base directory for creating temporary build sandboxes
#[tracing::instrument(skip_all, fields(name = config.name, indicatif.pb_show))]
pub async fn run_build(
    config: &BuildConfig,
    cache_dest_dir: &std::path::Path,
    spongebob_invocation: &mut Option<spongebob::SpongeBobInvocation>,
    sandbox_base_dir: std::path::PathBuf,
) -> Result<BuildResult> {
    let executor = BuildExecutor::new(sandbox_base_dir, config.name.clone())?;
    let (exit_code, spongebob_url) = executor.execute(config, spongebob_invocation).await?;

    let outputs = OutputValidator::validate_and_collect(
        config,
        &executor.output_staging_dir(),
        cache_dest_dir,
    )?;

    Ok(BuildResult {
        exit_code,
        outputs,
        spongebob_url,
    })
}
