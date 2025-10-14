pub mod config;
pub mod error;
#[cfg(target_os = "linux")]
pub mod executor;
#[cfg(not(target_os = "linux"))]
#[path = "executor_stub.rs"]
pub mod executor;
pub mod output;

pub use config::{BuildConfig, Input};
pub use error::{BuildSandboxError as Error, Result};
pub use executor::BuildExecutor;
pub use output::OutputValidator;

pub struct BuildResult {
    pub exit_code: i32,
    pub outputs: Vec<std::path::PathBuf>,
}

/// Run a build in a sandboxed environment
///
/// # Parameters
/// * `config` - Build configuration including inputs, outputs, and build script
/// * `cache_dest_dir` - Final destination in cache where successful build outputs are stored
/// * `event_bus` - Event bus for emitting build events
/// * `invocation_id` - Invocation ID for this build session
/// * `sandbox_base_dir` - Base directory for creating temporary build sandboxes
/// * `target_id` - Unique identifier for the target being built
#[tracing::instrument(skip_all, fields(name = config.name, indicatif.pb_show))]
pub async fn run_build(
    config: &BuildConfig,
    cache_dest_dir: &std::path::Path,
    event_bus: &build_events::BuildEventBus,
    invocation_id: &str,
    sandbox_base_dir: std::path::PathBuf,
    target_id: &str,
) -> Result<BuildResult> {
    let executor = BuildExecutor::new(sandbox_base_dir, config.name.clone())?;
    let exit_code = executor
        .execute(config, event_bus, invocation_id, target_id)
        .await?;

    let outputs = OutputValidator::validate_and_collect(
        config,
        &executor.output_staging_dir(),
        cache_dest_dir,
    )?;

    Ok(BuildResult {
        exit_code,
        outputs,
    })
}
