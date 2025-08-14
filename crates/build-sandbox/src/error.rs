use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum BuildSandboxError {
    #[error("Config error: {0}")]
    Config(#[from] ConfigError),

    #[error("Sandbox error: {0}")]
    Sandbox(#[from] SandboxError),

    #[error("Execution error: {0}")]
    Execution(#[from] ExecutionError),

    #[error("Output error: {0}")]
    Output(#[from] OutputError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Failed to parse JSON configuration: {0}")]
    JsonParse(serde_json::Error),

    #[error("Configuration file not found: {path}")]
    FileNotFound { path: PathBuf },

    #[error("Invalid executable path: {path}")]
    InvalidExecutable { path: PathBuf },

    #[error("Invalid input path: {path}")]
    InvalidInput { path: PathBuf },

    #[error("Invalid dependency path: {path}")]
    InvalidDependency { path: PathBuf },
}

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("Failed to create sandbox policy")]
    PolicyCreation,

    #[error("Failed to detect path type: {path}")]
    PathTypeDetection { path: PathBuf },

    #[error("Unsupported platform")]
    UnsupportedPlatform,
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error("Build command failed with exit code {code}")]
    BuildFailed { code: i32 },

    #[error("Sandbox execution failed: {message}")]
    SandboxFailed { message: String },

    #[error("Failed to create temporary directory")]
    TempDirCreation,

    #[error("Failed to spawn process: {context}")]
    ProcessSpawn { context: String },

    #[error("File operation failed: {operation} on {path}: {source}")]
    FileOperation {
        operation: String,
        path: String,
        source: std::io::Error,
    },

    #[error("Failed to copy {source} to {destination}: {error}")]
    CopyFailed {
        source: String,
        destination: String,
        #[source]
        error: std::io::Error,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum OutputError {
    #[error("Missing output file: {path}")]
    MissingOutput { path: PathBuf },

    #[error("Glob pattern error: {pattern}")]
    GlobPattern { pattern: String },
}

pub type Result<T> = std::result::Result<T, BuildSandboxError>;
