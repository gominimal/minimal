use common::FdSynchronizer;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{error, warn};

use crate::config::BuildConfig;
use crate::error::{OutputError, Result};

pub struct OutputValidator;

impl OutputValidator {
    /// Validate build outputs and copy them from staging to final cache location
    ///
    /// # Parameters
    /// * `config` - Build configuration containing expected output patterns
    /// * `staging_dir` - Temporary directory where build wrote its outputs
    /// * `cache_dest_dir` - Final cache directory where validated outputs are stored
    #[tracing::instrument(skip(config))]
    pub fn validate_and_collect(
        config: &BuildConfig,
        staging_dir: &Path,
        cache_dest_dir: &Path,
    ) -> Result<Vec<PathBuf>> {
        let mut collected_outputs = Vec::new();

        // Create final output directory if it doesn't exist
        fs::create_dir_all(cache_dest_dir).map_err(|e| OutputError::FileOperation {
            message: format!(
                "Failed to create output directory {}: {}",
                cache_dest_dir.display(),
                e
            ),
        })?;

        let mut found_files = Vec::new();
        for output_pattern in &config.outputs {
            let resolved_outputs = Self::resolve_output_pattern(output_pattern, staging_dir)?;

            if resolved_outputs.is_empty() {
                let files_found = Self::collect_staging_dir_files(staging_dir)?;

                error!(
                    pattern = %output_pattern,
                    staging_dir = %staging_dir.display(),
                    files_found = ?files_found,
                    "Output pattern matched no files"
                );

                return Err(OutputError::MissingOutput {
                    path: PathBuf::from(output_pattern),
                    staging_dir: staging_dir.to_path_buf(),
                    files_found,
                }
                .into());
            }

            found_files.extend(resolved_outputs);
        }
        found_files.sort();
        found_files.dedup();

        // Copy enumerated output files to final destination
        let l = FdSynchronizer::lock_writing_files();
        for output_file in &found_files {
            let relative_path =
                output_file
                    .strip_prefix(staging_dir)
                    .map_err(|_| OutputError::FileOperation {
                        message: format!(
                            "Failed to strip prefix from output file {}",
                            output_file.display()
                        ),
                    })?;
            let dest_path = cache_dest_dir.join(relative_path);

            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent).map_err(|e| OutputError::FileOperation {
                    message: format!(
                        "Failed to create parent directory {}: {}",
                        parent.display(),
                        e
                    ),
                })?;
            }

            if let Ok(link) = fs::read_link(output_file) {
                let referenced_path = output_file.parent().unwrap().join(&link).canonicalize()?;
                if referenced_path.starts_with(staging_dir) {
                    // Symlink points to another output - safe to transcribe as a symlink.
                    std::os::unix::fs::symlink(&link, &dest_path).map_err(|e| {
                        OutputError::FileOperation {
                            message: format!(
                                "Failed to symlink {} to {}: {}",
                                dest_path.display(),
                                link.display(),
                                e
                            ),
                        }
                    })?;
                } else {
                    return Err(OutputError::FileOperation {
                        message: format!(
                            "unhandled: symlink target {} from {}",
                            link.display(),
                            dest_path.display()
                        ),
                    }
                    .into());
                }
            } else {
                fs::copy(output_file, &dest_path).map_err(|e| OutputError::FileOperation {
                    message: format!(
                        "Failed to copy {} to {}: {}",
                        output_file.display(),
                        dest_path.display(),
                        e
                    ),
                })?;
            }

            collected_outputs.push(dest_path);
        }
        drop(l);

        // Self::warn_about_leftover_files(staging_dir, &found_files)?;

        Ok(collected_outputs)
    }

    // fn warn_about_leftover_files(staging_dir: &Path, enumerated_files: &[PathBuf]) -> Result<()> {
    //     let mut all_files = Vec::new();
    //     Self::collect_all_files(staging_dir, &mut all_files)?;

    //     let leftover_files: Vec<&PathBuf> = all_files
    //         .iter()
    //         .filter(|file| !enumerated_files.contains(file))
    //         .collect();

    //     if !leftover_files.is_empty() {
    //         warn!(
    //             "Found {} files in staging directory that were not part of enumerated outputs:",
    //             leftover_files.len()
    //         );
    //         for file in leftover_files {
    //             let relative_path = file.strip_prefix(staging_dir).unwrap_or(file);
    //             warn!("  {}", relative_path.display());
    //         }
    //     }

    //     Ok(())
    // }

    fn collect_staging_dir_files(staging_dir: &Path) -> Result<Vec<String>> {
        let mut files = Vec::new();
        if let Ok(entries) = fs::read_dir(staging_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let relative_path = path
                    .strip_prefix(staging_dir)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();

                if path.is_file() {
                    files.push(format!("file: {}", relative_path));
                } else if path.is_dir() {
                    files.push(format!("dir: {}", relative_path));
                }
            }
        }
        // Limit to first 20 entries to avoid overwhelming output
        files.truncate(20);
        Ok(files)
    }

    // fn collect_all_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    //     for entry in fs::read_dir(dir).map_err(|_| OutputError::GlobPattern {
    //         pattern: dir.to_string_lossy().to_string(),
    //     })? {
    //         let entry = entry.map_err(|_| OutputError::GlobPattern {
    //             pattern: dir.to_string_lossy().to_string(),
    //         })?;
    //         let path = entry.path();

    //         if path.is_file() {
    //             files.push(path);
    //         } else if path.is_dir() {
    //             Self::collect_all_files(&path, files)?;
    //         }
    //     }
    //     Ok(())
    // }

    fn resolve_output_pattern(pattern: &str, search_dir: &Path) -> Result<Vec<PathBuf>> {
        if pattern.contains('*') || pattern.contains('?') || pattern.contains('[') {
            Self::resolve_glob_pattern(pattern, search_dir)
        } else {
            let search_pattern = if Path::new(pattern).is_absolute() {
                pattern.to_string()
            } else {
                search_dir.join(pattern).to_string_lossy().to_string()
            };

            Self::resolve_literal_pattern(&search_pattern)
        }
    }

    fn resolve_glob_pattern<P: AsRef<Path>>(pattern: &str, root_dir: P) -> Result<Vec<PathBuf>> {
        let mut results = Vec::new();

        let matcher = globset::GlobBuilder::new(pattern)
            .literal_separator(true)
            .empty_alternates(true)
            .build()
            .map_err(|_| OutputError::GlobPattern {
                pattern: pattern.to_string(),
            })?
            .compile_matcher();

        // Walk the filesystem starting from root_dir
        fn walk_dir(
            dir: &Path,
            root_dir: &Path,
            matcher: &globset::GlobMatcher,
            results: &mut Vec<PathBuf>,
        ) -> Result<()> {
            let entries = fs::read_dir(dir).map_err(|_| OutputError::GlobPattern {
                pattern: dir.to_string_lossy().to_string(),
            })?;

            for entry in entries {
                let entry = entry.map_err(|_| OutputError::GlobPattern {
                    pattern: dir.to_string_lossy().to_string(),
                })?;

                let path = entry.path();
                let subset = path.strip_prefix(root_dir).unwrap();
                if path.is_file() && matcher.is_match(subset) {
                    results.push(path);
                } else if path.is_dir() {
                    // Recursively walk subdirectories
                    walk_dir(&path, root_dir, matcher, results)?;
                }
            }

            Ok(())
        }

        walk_dir(root_dir.as_ref(), root_dir.as_ref(), &matcher, &mut results)?;
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
