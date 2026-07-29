//! Convention-discovered gate for the completions the release ships.
//!
//! `release.yml`'s "Generate completions" step runs the freshly built `mip` /
//! `min` / `minimald` binaries, but only on a dispatched release — so a breaking
//! CLI change cleared every PR gate and only surfaced an hour into a release,
//! taking the GCS upload, the GitHub Release and `stage-installer` with it
//! (#1035; the `completions <shell>` → `completions print <shell>` split shipped
//! that way for twenty days, #1009/#1034).
//!
//! `.github/workflows/` is frozen and CODEOWNER-gated, so the release job cannot
//! grow a gate of its own. Instead the generation moved into
//! `scripts/gen-completions.sh`, which the release job calls and this test also
//! calls — against `target/debug` rather than the release artifacts. The release
//! path and the pre-merge gate are the same code, so they cannot drift; this is
//! the reviewed-code extension point CI schedules over (docs/ci-strategy.md
//! §10). `release_job_calls_the_generator` holds the other half: the workflow
//! has to keep calling the helper rather than inlining the commands again.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/common; the workspace root is two up.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root two levels above crates/common")
        .to_path_buf()
}

/// The directory cargo built this test into (`<target>/<profile>/deps/..`),
/// which is also where the binaries under test land. Derived rather than
/// assumed so a custom `CARGO_TARGET_DIR` or profile still resolves — cargo
/// exports neither to the test process.
fn bin_dir() -> PathBuf {
    std::env::current_exe()
        .expect("test binary path")
        .parent()
        .and_then(|deps| deps.parent())
        .expect("<target>/<profile> two levels above the test binary")
        .to_path_buf()
}

/// The binaries the release generates completions for. `minimald` is left out
/// on macOS, where its sandbox stack does not build (the platform matrix in
/// AGENTS.md); the Linux lanes cover all three.
fn binaries() -> Vec<&'static str> {
    if cfg!(target_os = "linux") {
        vec!["mip", "min", "minimald"]
    } else {
        vec!["mip", "min"]
    }
}

/// Build any binary the workspace test build did not leave behind — cargo only
/// links a package's bin when something selects it, so `mip` (no `tests/` dir)
/// is often absent. `--workspace --bin`, not `-p <package> --bin`: selecting the
/// whole workspace resolves features exactly as the test build did, so this is a
/// link or a no-op instead of a rebuild of every shared dependency under a
/// narrower feature set. Building rather than skipping keeps the gate from
/// quietly covering nothing.
fn ensure_built(root: &Path, bin_dir: &Path, names: &[&str]) {
    for name in names {
        let exe = bin_dir.join(name);
        if exe.exists() {
            continue;
        }
        let status = Command::new("cargo")
            .args(["build", "--locked", "--workspace", "--bin", name])
            .current_dir(root)
            .status()
            .unwrap_or_else(|e| panic!("failed to run cargo build --bin {name}: {e}"));
        assert!(status.success(), "cargo build --bin {name} failed");
        assert!(
            exe.exists(),
            "cargo built {name} but {} is missing",
            exe.display()
        );
    }
}

/// Whether `body` registers completions for the command `name`, in whichever
/// form clap emitted: the static (aot) generator and the dynamic (env) shim
/// `min` prints differ in flag spelling, but both name the command.
fn registers(shell: &str, name: &str, body: &str) -> bool {
    body.lines().any(|line| {
        let words: Vec<&str> = line.split_whitespace().collect();
        match shell {
            "bash" => words.first() == Some(&"complete") && words.last() == Some(&name),
            "zsh" => words.first() == Some(&"#compdef") && words.contains(&name),
            "fish" => words
                .windows(2)
                .any(|w| (w[0] == "-c" || w[0] == "--command") && w[1] == name),
            _ => false,
        }
    })
}

#[test]
fn release_completions_generate_and_register_their_command() {
    let root = repo_root();
    let bin_dir = bin_dir();
    let names = binaries();
    ensure_built(&root, &bin_dir, &names);

    let out = std::env::temp_dir().join(format!("release-completions-{}", std::process::id()));
    let _ = fs::remove_dir_all(&out);

    let output = Command::new("bash")
        .arg(root.join("scripts/gen-completions.sh"))
        .arg(&out)
        .args(&names)
        .env("BIN_DIR", &bin_dir)
        .current_dir(&root)
        .output()
        .expect("failed to run scripts/gen-completions.sh");
    assert!(
        output.status.success(),
        "scripts/gen-completions.sh failed\n--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // A completion file a shell will not autoload is as broken as one that
    // failed to generate, and exits 0 all the same: assert each one registers
    // the command its own filename says it completes.
    for name in &names {
        for (shell, file) in [
            ("bash", (*name).to_string()),
            ("zsh", format!("_{name}")),
            ("fish", format!("{name}.fish")),
        ] {
            let path = out.join(shell).join(&file);
            let body = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
            assert!(
                registers(shell, name, &body),
                "{shell}/{file} does not register the command `{name}` it is autoloaded for",
            );
        }
    }

    fs::remove_dir_all(&out).ok();
}

#[test]
fn release_job_calls_the_generator() {
    let workflow = repo_root().join(".github/workflows/release.yml");
    let body = fs::read_to_string(&workflow)
        .unwrap_or_else(|e| panic!("reading {}: {e}", workflow.display()));

    assert!(
        body.contains("scripts/gen-completions.sh"),
        "release.yml does not call scripts/gen-completions.sh, so its completion \
         invocations are unexercised until a release is dispatched — the gap #1035 \
         is about. Point the \"Generate completions\" step at the helper.",
    );
    assert!(
        !body.contains("> artifacts/completions/"),
        "release.yml inlines completion invocations again; they belong in \
         scripts/gen-completions.sh, which this test exercises pre-merge.",
    );
}
