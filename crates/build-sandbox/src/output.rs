use glob::glob;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::config::BuildConfig;
use crate::error::{OutputError, Result};

pub struct OutputValidator;

impl OutputValidator {
    pub fn validate_and_collect(
        config: &BuildConfig,
        staging_dir: &Path,
        final_output_dir: &Path,
        _verbose: bool,
    ) -> Result<Vec<PathBuf>> {
        let mut collected_outputs = Vec::new();

        info!("Validating {} output patterns", config.outputs.len());
        // Create final output directory if it doesn't exist
        fs::create_dir_all(final_output_dir).map_err(|_| OutputError::MissingOutput {
            path: final_output_dir.to_path_buf(),
        })?;

        let mut found_files = Vec::new();
        for output_pattern in &config.outputs {
            let resolved_outputs = Self::resolve_output_pattern(output_pattern, staging_dir)?;

            if resolved_outputs.is_empty() {
                return Err(OutputError::MissingOutput {
                    path: PathBuf::from(output_pattern),
                }
                .into());
            }

            found_files.extend(resolved_outputs);
        }

        // Copy enumerated output files to final destination
        for output_file in &found_files {
            let relative_path =
                output_file
                    .strip_prefix(staging_dir)
                    .map_err(|_| OutputError::MissingOutput {
                        path: output_file.clone(),
                    })?;
            let dest_path = final_output_dir.join(relative_path);

            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent).map_err(|_| OutputError::MissingOutput {
                    path: dest_path.clone(),
                })?;
            }

            fs::copy(output_file, &dest_path).map_err(|_| OutputError::MissingOutput {
                path: dest_path.clone(),
            })?;

            info!(
                "Copied {} to {}",
                output_file.display(),
                dest_path.display()
            );
            collected_outputs.push(dest_path);
        }

        Self::warn_about_leftover_files(staging_dir, &found_files)?;

        Ok(collected_outputs)
    }

    fn warn_about_leftover_files(staging_dir: &Path, enumerated_files: &[PathBuf]) -> Result<()> {
        let mut all_files = Vec::new();
        Self::collect_all_files(staging_dir, &mut all_files)?;

        let leftover_files: Vec<&PathBuf> = all_files
            .iter()
            .filter(|file| !enumerated_files.contains(file))
            .collect();

        if !leftover_files.is_empty() {
            warn!(
                "Found {} files in staging directory that were not part of enumerated outputs:",
                leftover_files.len()
            );
            for file in leftover_files {
                let relative_path = file.strip_prefix(staging_dir).unwrap_or(file);
                warn!("  {}", relative_path.display());
            }
        }

        Ok(())
    }

    fn collect_all_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        for entry in fs::read_dir(dir).map_err(|_| OutputError::GlobPattern {
            pattern: dir.to_string_lossy().to_string(),
        })? {
            let entry = entry.map_err(|_| OutputError::GlobPattern {
                pattern: dir.to_string_lossy().to_string(),
            })?;
            let path = entry.path();

            if path.is_file() {
                files.push(path);
            } else if path.is_dir() {
                Self::collect_all_files(&path, files)?;
            }
        }
        Ok(())
    }

    fn resolve_output_pattern(pattern: &str, search_dir: &Path) -> Result<Vec<PathBuf>> {
        let search_pattern = if Path::new(pattern).is_absolute() {
            pattern.to_string()
        } else {
            search_dir.join(pattern).to_string_lossy().to_string()
        };

        if pattern.contains('*') || pattern.contains('?') || pattern.contains('[') {
            Self::resolve_glob_pattern(&search_pattern)
        } else {
            Self::resolve_literal_pattern(&search_pattern)
        }
    }

    fn resolve_glob_pattern(pattern: &str) -> Result<Vec<PathBuf>> {
        let mut results = Vec::new();

        match glob(pattern) {
            Ok(paths) => {
                for entry in paths {
                    match entry {
                        Ok(path) => {
                            if path.is_file() {
                                results.push(path);
                            }
                        }
                        Err(_) => {
                            return Err(OutputError::GlobPattern {
                                pattern: pattern.to_string(),
                            }
                            .into());
                        }
                    }
                }
            }
            Err(_) => {
                return Err(OutputError::GlobPattern {
                    pattern: pattern.to_string(),
                }
                .into());
            }
        }

        Ok(results)
    }

    fn resolve_literal_pattern(pattern: &str) -> Result<Vec<PathBuf>> {
        let path = PathBuf::from(pattern);

        if path.exists() && path.is_file() {
            Ok(vec![path])
        } else {
            Ok(vec![])
        }
    }
}
