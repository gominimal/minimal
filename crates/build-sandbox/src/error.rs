use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum BuildSandboxError {
    #[error("Config error: {0}")]
    Config(#[from] ConfigError),

    #[error("Execution error: {0}")]
    Execution(#[from] ExecutionError),

    #[error("Output error: {0}")]
    Output(#[from] OutputError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Invalid executable path: {path}")]
    InvalidExecutable { path: PathBuf },

    #[error("Invalid input path: {path}")]
    InvalidInput { path: PathBuf },

    #[error("Invalid dependency path: {path}")]
    InvalidDependency { path: PathBuf },
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error(
        "Build command failed with exit code {code}\n  Temp directory: {temp_dir}\n  Check stderr: cat {temp_dir}/stderr"
    )]
    BuildFailed { code: i32, temp_dir: PathBuf },

    #[error("Container execution failed: {message}")]
    SandboxFailed { message: String },

    #[error("Failed to create temporary directory")]
    TempDirCreation,

    #[error("File operation failed: {operation} on {path}: {source}")]
    FileOperation {
        operation: String,
        path: String,
        source: std::io::Error,
    },

    #[error("Failed to link {source} to {destination}: {error}")]
    HardLinkFailed {
        source: String,
        destination: String,
        #[source]
        error: std::io::Error,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum OutputError {
    #[error(
        "Missing output file: {path}\n  Staging directory: {staging_dir}\n  Debug with: ls -la {staging_dir}\n  Files found: {files_found:?}"
    )]
    MissingOutput {
        path: PathBuf,
        staging_dir: PathBuf,
        files_found: Vec<String>,
    },

    #[error("Glob pattern error: {pattern}")]
    GlobPattern { pattern: String },

    #[error("File operation failed: {message}")]
    FileOperation { message: String },
}

pub type Result<T> = std::result::Result<T, BuildSandboxError>;
