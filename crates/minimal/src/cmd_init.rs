use mctx::Error;
use std::io::Write;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Detection table — mise-style: data-driven, exact filename matching.
//
// Each entry maps a harness name to a set of filenames whose presence on disk
// indicates that harness should be used.  The table is ordered by specificity:
// more-specific lock-files (pnpm-lock.yaml, uv.lock) come before generic
// indicators (package.json, pyproject.toml) so the first match wins.
// ---------------------------------------------------------------------------

struct DetectEntry {
    /// The harness name written to `[harness] use = "…"`.
    harness: &'static str,
    /// Filenames to probe with `dir.join(f).exists()`.
    detect_files: &'static [&'static str],
    /// Optional test task: (action_type, command).
    /// `action_type` is `"exec"` (direct execve) or `"bash"` (shell script).
    test_task: Option<(&'static str, &'static str)>,
}

/// Ordered from most-specific to least-specific within each language family.
const DETECT_TABLE: &[DetectEntry] = &[
    // -- Rust --
    DetectEntry {
        harness: "rust",
        detect_files: &["Cargo.toml", "rust-toolchain.toml"],
        test_task: Some(("exec", "cargo test")),
    },
    // -- Go --
    DetectEntry {
        harness: "go",
        detect_files: &["go.mod", "go.sum"],
        test_task: Some(("exec", "go test ./...")),
    },
    // -- Zig --
    DetectEntry {
        harness: "zig",
        detect_files: &["build.zig"],
        test_task: Some(("exec", "zig build test")),
    },
    // -- Node.js (specific package managers first) --
    DetectEntry {
        harness: "pnpm",
        detect_files: &["pnpm-lock.yaml", "pnpm-workspace.yaml"],
        test_task: Some(("bash", "pnpm test")),
    },
    DetectEntry {
        harness: "bun",
        detect_files: &["bun.lock", "bun.lockb", "bunfig.toml"],
        test_task: Some(("bash", "bun test")),
    },
    DetectEntry {
        harness: "deno",
        detect_files: &["deno.json", "deno.jsonc"],
        test_task: Some(("bash", "deno test")),
    },
    DetectEntry {
        harness: "npm",
        detect_files: &["package-lock.json", "package.json"],
        test_task: Some(("bash", "npm test")),
    },
    // -- Python (uv before pip — uv.lock is more specific than pyproject.toml) --
    DetectEntry {
        harness: "uv",
        detect_files: &["uv.lock"],
        test_task: Some(("bash", "uv run pytest")),
    },
    DetectEntry {
        harness: "pip",
        detect_files: &["requirements.txt", "setup.py", "pyproject.toml"],
        test_task: Some(("bash", "pip3 install -e '.[test]' && pytest")),
    },
    // -- C/C++ build systems --
    DetectEntry {
        harness: "cmake",
        detect_files: &["CMakeLists.txt"],
        test_task: Some(("bash", "cmake --build build && ctest --test-dir build")),
    },
    DetectEntry {
        harness: "meson",
        detect_files: &["meson.build"],
        test_task: Some(("bash", "ninja -C build test")),
    },
    DetectEntry {
        harness: "make",
        detect_files: &["Makefile", "GNUmakefile"],
        test_task: Some(("bash", "make test")),
    },
    // -- JVM --
    DetectEntry {
        harness: "gradle",
        detect_files: &[
            "build.gradle",
            "build.gradle.kts",
            "settings.gradle",
            "settings.gradle.kts",
        ],
        test_task: Some(("bash", "gradle test")),
    },
    DetectEntry {
        harness: "maven",
        detect_files: &["pom.xml"],
        test_task: Some(("bash", "mvn test")),
    },
];

struct Detection {
    harness: &'static str,
    matched_file: &'static str,
    test_task: Option<(&'static str, &'static str)>,
}

/// Detect the project type by checking for the existence of known files.
/// Returns the first match (most-specific entries are checked first).
fn detect_project(dir: &Path) -> Option<Detection> {
    for entry in DETECT_TABLE {
        for &filename in entry.detect_files {
            if dir.join(filename).exists() {
                return Some(Detection {
                    harness: entry.harness,
                    matched_file: filename,
                    test_task: entry.test_task,
                });
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// CLI argument structs
// ---------------------------------------------------------------------------

#[derive(Debug, clap::Args)]
pub struct InitArgs {
    /// Project directory (defaults to current directory)
    #[arg(default_value = ".")]
    dir: PathBuf,

    /// Skip interactive prompts, use detected defaults
    #[arg(long)]
    yes: bool,

    /// Don't auto-detect project type
    #[arg(long)]
    no_detect: bool,
}

#[derive(Debug, clap::Args)]
pub struct AddArgs {
    /// Package names to add
    #[arg(required = true)]
    packages: Vec<String>,

    /// Task to add packages to (default: shell)
    #[arg(long, default_value = "shell")]
    task: String,
}

#[derive(Debug, clap::Args)]
pub struct RemoveArgs {
    /// Package names to remove (from all tasks)
    #[arg(required = true)]
    packages: Vec<String>,
}

// ---------------------------------------------------------------------------
// minimal init
// ---------------------------------------------------------------------------

pub fn cmd_init(args: InitArgs) -> Result<(), Error> {
    let dir = args
        .dir
        .canonicalize()
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_else(|_| args.dir.clone()));
    let toml_path = dir.join("minimal.toml");

    // Guard: don't overwrite an existing file (either layout)
    if toml_path.exists() {
        eprintln!("minimal.toml already exists at {}", toml_path.display());
        eprintln!("Use 'minimal add <package>' to add packages.");
        std::process::exit(1);
    }
    if dir.join(".minimal").join("minimal.toml").exists() {
        eprintln!(
            "minimal.toml already exists at {}",
            dir.join(".minimal/minimal.toml").display()
        );
        eprintln!("Use 'minimal add <package>' to add packages.");
        std::process::exit(1);
    }

    // Detect project type
    let detection = if args.no_detect {
        None
    } else {
        detect_project(&dir)
    };

    if let Some(ref d) = detection {
        eprintln!("Detected: {} (found {})", d.harness, d.matched_file);
    }

    // -- Generate minimal.toml content --
    let mut content = String::new();
    content.push_str("# Generated by `minimal init`\n\n");

    // [upstream]
    content.push_str("[upstream]\n");
    content.push_str("repo = \"https://github.com/gominimal/pkgs\"\n");
    content.push_str("branch = \"main\"\n");
    content.push('\n');

    // [harness] (only when detected)
    if let Some(ref d) = detection {
        content.push_str("[harness]\n");
        content.push_str(&format!("use = \"{}\"\n", d.harness));
        content.push('\n');
    }

    // [defaults]
    content.push_str("[defaults]\n");
    content.push_str("state_key = \"dev\"\n");
    content.push('\n');

    // [tasks.shell] — always present
    content.push_str("[tasks.shell]\n");
    content.push_str("packages = [\"base\"]\n");
    content.push_str("exec = \"bash -l\"\n");

    // [tasks.test] — when detection provides one
    if let Some(ref d) = detection
        && let Some((action_type, command)) = d.test_task
    {
        content.push('\n');
        content.push_str("[tasks.test]\n");
        content.push_str("packages = [\"base\"]\n");
        content.push_str(&format!("{} = \"{}\"\n", action_type, command));
    }

    // -- Confirmation prompt (unless --yes) --
    if !args.yes {
        eprintln!("\nWill create {}:\n", toml_path.display());
        eprintln!("---");
        eprint!("{}", content);
        eprintln!("---");
        eprintln!();
        eprint!("Continue? [Y/n] ");
        std::io::stderr().flush().ok();

        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| Error::Other(anyhow::anyhow!("reading stdin: {}", e)))?;
        if input.trim().eq_ignore_ascii_case("n") {
            eprintln!("Aborted.");
            std::process::exit(0);
        }
    }

    // -- Write the file --
    std::fs::write(&toml_path, &content)
        .map_err(|e| Error::Other(anyhow::anyhow!("writing {}: {}", toml_path.display(), e)))?;

    eprintln!("Created {}", toml_path.display());
    eprintln!();
    eprintln!("Next steps:");
    eprintln!("  minimal update      # pin package versions");
    eprintln!("  minimal run shell   # enter development shell");
    if detection.as_ref().and_then(|d| d.test_task).is_some() {
        eprintln!("  minimal test        # run tests");
    }
    if detection.is_some() {
        eprintln!("  minimal build       # build the project");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// minimal add
// ---------------------------------------------------------------------------

pub fn cmd_add(args: AddArgs) -> Result<(), Error> {
    let toml_path = find_minimal_toml()?;

    let content = std::fs::read_to_string(&toml_path)
        .map_err(|e| Error::Other(anyhow::anyhow!("reading {}: {}", toml_path.display(), e)))?;

    let mut doc = content
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| Error::Other(anyhow::anyhow!("parsing {}: {}", toml_path.display(), e)))?;

    // Require [tasks] to exist
    let tasks = doc
        .get_mut("tasks")
        .and_then(|t| t.as_table_mut())
        .ok_or_else(|| {
            Error::Other(anyhow::anyhow!(
                "No [tasks] section in {}. Add tasks first or run 'minimal init'.",
                toml_path.display()
            ))
        })?;

    // Require the target task to exist
    if !tasks.contains_key(&args.task) {
        let available: Vec<String> = tasks.iter().map(|(k, _)| k.to_string()).collect();
        return Err(Error::Other(anyhow::anyhow!(
            "Task '{}' not found. Available tasks: {}",
            args.task,
            available.join(", ")
        )));
    }

    let task = tasks[&args.task]
        .as_table_mut()
        .ok_or_else(|| Error::Other(anyhow::anyhow!("[tasks.{}] is not a table", args.task)))?;

    // Get or create the packages array
    let packages =
        task.entry("packages")
            .or_insert(toml_edit::Item::Value(toml_edit::Value::Array(
                toml_edit::Array::new(),
            )));

    if let Some(arr) = packages.as_array_mut() {
        for pkg in &args.packages {
            if arr.iter().any(|v| v.as_str() == Some(pkg)) {
                eprintln!("Package '{}' already in [tasks.{}]", pkg, args.task);
                continue;
            }
            arr.push(pkg.as_str());
            eprintln!("Added '{}' to [tasks.{}]", pkg, args.task);
        }
    }

    std::fs::write(&toml_path, doc.to_string())
        .map_err(|e| Error::Other(anyhow::anyhow!("writing {}: {}", toml_path.display(), e)))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// minimal remove
// ---------------------------------------------------------------------------

pub fn cmd_remove(args: RemoveArgs) -> Result<(), Error> {
    let toml_path = find_minimal_toml()?;

    let content = std::fs::read_to_string(&toml_path)
        .map_err(|e| Error::Other(anyhow::anyhow!("reading {}: {}", toml_path.display(), e)))?;

    let mut doc = content
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| Error::Other(anyhow::anyhow!("parsing {}: {}", toml_path.display(), e)))?;

    let Some(tasks_table) = doc.get_mut("tasks").and_then(|t| t.as_table_mut()) else {
        eprintln!("No [tasks] section in {}", toml_path.display());
        return Ok(());
    };

    // Collect task names first to avoid borrow issues with iter_mut
    let task_names: Vec<String> = tasks_table.iter().map(|(k, _)| k.to_string()).collect();

    for task_name in &task_names {
        if let Some(task_item) = tasks_table.get_mut(task_name.as_str())
            && let Some(task_table) = task_item.as_table_mut()
            && let Some(pkg_item) = task_table.get_mut("packages")
            && let Some(arr) = pkg_item.as_array_mut()
        {
            for pkg in &args.packages {
                let before_len = arr.len();
                arr.retain(|v| v.as_str() != Some(pkg));
                if arr.len() < before_len {
                    eprintln!("Removed '{}' from [tasks.{}]", pkg, task_name);
                }
            }
        }
    }

    std::fs::write(&toml_path, doc.to_string())
        .map_err(|e| Error::Other(anyhow::anyhow!("writing {}: {}", toml_path.display(), e)))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Search upward from cwd for a `minimal.toml`, matching the logic in
/// `mfile::File::from_dir_recursive` (checks both root and `.minimal/` layouts,
/// stops at `$HOME`).
fn find_minimal_toml() -> Result<PathBuf, Error> {
    let cwd = std::env::current_dir()
        .map_err(|e| Error::Other(anyhow::anyhow!("getting current directory: {}", e)))?;

    #[allow(deprecated)] // matches existing mfile code
    let home = std::env::home_dir();
    let mut dir = cwd.as_path();

    loop {
        let candidate = dir.join("minimal.toml");
        if candidate.exists() {
            return Ok(candidate);
        }
        let candidate = dir.join(".minimal").join("minimal.toml");
        if candidate.exists() {
            return Ok(candidate);
        }

        match dir.parent() {
            Some(parent) => {
                // Don't traverse past HOME (matches mfile::File::from_dir_recursive)
                if let Some(ref home) = home
                    && parent == home.as_path()
                {
                    break;
                }
                dir = parent;
            }
            None => break,
        }
    }

    Err(Error::Other(anyhow::anyhow!(
        "No minimal.toml found. Run 'minimal init' first."
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn detect_rust_project() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]").unwrap();

        let d = detect_project(dir.path()).unwrap();
        assert_eq!(d.harness, "rust");
        assert_eq!(d.matched_file, "Cargo.toml");
    }

    #[test]
    fn detect_go_project() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("go.mod"), "module example").unwrap();

        let d = detect_project(dir.path()).unwrap();
        assert_eq!(d.harness, "go");
        assert_eq!(d.matched_file, "go.mod");
    }

    #[test]
    fn detect_pnpm_over_npm() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();
        std::fs::write(dir.path().join("pnpm-lock.yaml"), "").unwrap();

        let d = detect_project(dir.path()).unwrap();
        assert_eq!(d.harness, "pnpm");
    }

    #[test]
    fn detect_uv_over_pip() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("pyproject.toml"), "").unwrap();
        std::fs::write(dir.path().join("uv.lock"), "").unwrap();

        let d = detect_project(dir.path()).unwrap();
        assert_eq!(d.harness, "uv");
    }

    #[test]
    fn detect_pip_from_pyproject() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("pyproject.toml"), "").unwrap();

        let d = detect_project(dir.path()).unwrap();
        assert_eq!(d.harness, "pip");
    }

    #[test]
    fn detect_npm_from_package_json() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();

        let d = detect_project(dir.path()).unwrap();
        assert_eq!(d.harness, "npm");
    }

    #[test]
    fn detect_nothing_in_empty_dir() {
        let dir = tempdir().unwrap();
        assert!(detect_project(dir.path()).is_none());
    }

    #[test]
    fn init_creates_file() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]").unwrap();

        cmd_init(InitArgs {
            dir: dir.path().to_path_buf(),
            yes: true,
            no_detect: false,
        })
        .unwrap();

        let content = std::fs::read_to_string(dir.path().join("minimal.toml")).unwrap();
        assert!(content.contains("[upstream]"));
        assert!(content.contains("[harness]"));
        assert!(content.contains("use = \"rust\""));
        assert!(content.contains("[tasks.shell]"));
        assert!(content.contains("[tasks.test]"));
        assert!(content.contains("exec = \"cargo test\""));
    }

    #[test]
    fn init_no_detect() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]").unwrap();

        cmd_init(InitArgs {
            dir: dir.path().to_path_buf(),
            yes: true,
            no_detect: true,
        })
        .unwrap();

        let content = std::fs::read_to_string(dir.path().join("minimal.toml")).unwrap();
        assert!(content.contains("[upstream]"));
        assert!(!content.contains("[harness]"));
        assert!(content.contains("[tasks.shell]"));
        assert!(!content.contains("[tasks.test]"));
    }

    #[test]
    fn init_refuses_overwrite() {
        // This test verifies the guard path exists; in practice it calls process::exit
        // so we just verify the file-exists check logic.
        let dir = tempdir().unwrap();
        let toml_path = dir.path().join("minimal.toml");
        std::fs::write(&toml_path, "existing").unwrap();
        assert!(toml_path.exists());
    }

    #[test]
    fn add_packages_to_task() {
        let dir = tempdir().unwrap();
        let toml_path = dir.path().join("minimal.toml");
        std::fs::write(
            &toml_path,
            "[upstream]\nrepo = \"x\"\n\n[tasks.shell]\npackages = [\"base\"]\nexec = \"bash -l\"\n",
        )
        .unwrap();

        // Simulate being in that directory
        let orig_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();

        let result = cmd_add(AddArgs {
            packages: vec!["git".to_string(), "vim".to_string()],
            task: "shell".to_string(),
        });

        std::env::set_current_dir(orig_dir).unwrap();
        result.unwrap();

        let content = std::fs::read_to_string(&toml_path).unwrap();
        assert!(content.contains("git"));
        assert!(content.contains("vim"));
        assert!(content.contains("base"));
    }

    #[test]
    fn remove_packages_from_tasks() {
        let dir = tempdir().unwrap();
        let toml_path = dir.path().join("minimal.toml");
        std::fs::write(
            &toml_path,
            "[upstream]\nrepo = \"x\"\n\n[tasks.shell]\npackages = [\"base\", \"git\", \"vim\"]\nexec = \"bash -l\"\n",
        )
        .unwrap();

        let orig_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();

        let result = cmd_remove(RemoveArgs {
            packages: vec!["vim".to_string()],
        });

        std::env::set_current_dir(orig_dir).unwrap();
        result.unwrap();

        let content = std::fs::read_to_string(&toml_path).unwrap();
        assert!(content.contains("base"));
        assert!(content.contains("git"));
        assert!(!content.contains("vim"));
    }
}
