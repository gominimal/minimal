//! `min completions` — the shell integration, printed or installed.
//!
//! Two verbs over one artifact, the registration shim:
//!
//! - [`cmd_print`] writes it to stdout, for `source <(min completions print
//!   bash)` and for anyone piping it somewhere of their own choosing.
//! - [`cmd_install`] writes it to the file each shell already looks in, with
//!   the bookkeeping that used to live only in `scripts/install.sh` (R9.3):
//!   per-shell target path, atomic write, unwritable-dir tolerance, zsh
//!   `zcompdump` invalidation. That logic was unreachable for anyone who did
//!   not install through `curl | sh`; now the installer calls this instead of
//!   carrying its own copy, and reads the paths it prints on stdout — one per
//!   line — into its install record.
//!
//! Distinct from `completion.rs`, which is the runtime completion engine the
//! installed shim calls back into.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use clap_complete::Shell;

/// The shells [`cmd_install`] knows a destination for.
///
/// Narrower than what [`cmd_print`] accepts: installing needs a file the shell
/// autoloads on its own, and these are the three with a standard, user-level
/// one — the same three `scripts/install.sh` has always written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum InstallShell {
    Bash,
    Zsh,
    Fish,
}

impl InstallShell {
    /// Every installable shell, in the order a bare `install` walks them.
    const ALL: [Self; 3] = [Self::Bash, Self::Zsh, Self::Fish];

    /// The name clap_complete's shell registry knows this shell by.
    fn name(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
        }
    }

    /// The file this shell autoloads `min`'s registration from.
    ///
    /// The three paths `scripts/install.sh` computes (R9.3), resolved by the
    /// same rules: `${XDG_DATA_HOME:-$HOME/.local/share}` and
    /// `${XDG_CONFIG_HOME:-$HOME/.config}`. Deliberately not
    /// [`dirs::data_dir`] — on macOS that is `~/Library/Application Support`,
    /// where no shell looks.
    fn target(self) -> Result<PathBuf, anyhow::Error> {
        Ok(match self {
            Self::Bash => {
                xdg_home("XDG_DATA_HOME", ".local/share")?.join("bash-completion/completions/min")
            }
            // `_min`, not `min`: zsh autoloads a function file named for the
            // command it completes, underscore-prefixed.
            Self::Zsh => xdg_home("XDG_DATA_HOME", ".local/share")?.join("zsh/completions/_min"),
            Self::Fish => xdg_home("XDG_CONFIG_HOME", ".config")?.join("fish/completions/min.fish"),
        })
    }
}

/// Print the shell integration for `shell` on stdout.
///
/// This is a *registration* shim, not a completion table: a dozen lines that
/// teach the shell to ask `min` itself what to complete, rather than the
/// thousand-line static script this used to emit. That indirection is the
/// whole point — session names and IDs only exist at runtime, so a table
/// baked at install time cannot contain them (see `completion.rs`).
///
/// The shim calls `min` by bare name so it resolves through `PATH` — an
/// upgrade that moves the binary keeps working, and the installer puts its
/// bindir on `PATH` in the same breath as writing this file.
pub fn cmd_print(shell: Shell) -> Result<(), anyhow::Error> {
    let shim = render(&shell.to_string())?;
    std::io::stdout()
        .write_all(&shim)
        .context("write shell integration to stdout")
}

/// Install the shell integration for `shells` (all of [`InstallShell::ALL`]
/// when empty), printing each path actually written on stdout, one per line.
///
/// Those paths are the contract with `scripts/install.sh`: it records what we
/// print so `--uninstall` can undo it. Nothing else goes to stdout.
///
/// Best-effort per shell, exactly as the installer was: a shell that could not
/// be installed for is a warning on stderr, not a failure. When this runs at
/// the end of an install the binaries are already correctly in place, and one
/// unwritable shared directory must not make the run look failed.
pub fn cmd_install(shells: &[InstallShell]) -> Result<(), anyhow::Error> {
    let targets = if shells.is_empty() {
        &InstallShell::ALL[..]
    } else {
        shells
    };

    let mut stdout = std::io::stdout().lock();
    for shell in targets {
        match install_one(*shell) {
            Ok(path) => writeln!(stdout, "{}", path.display())
                .context("write installed completion path to stdout")?,
            Err(err) => eprintln!("warning: {err:#}"),
        }
    }
    Ok(())
}

/// Install one shell's registration, returning the path written.
fn install_one(shell: InstallShell) -> Result<PathBuf, anyhow::Error> {
    let target = shell
        .target()
        .with_context(|| format!("failed to install {} completions", shell.name()))?;
    let dir = target
        .parent()
        .with_context(|| format!("{} has no parent directory", target.display()))?;

    // bash has no completion search path of its own: the file below is read
    // only by the separate bash-completion project's loader. Writing it where
    // nothing will source it is the silent no-op this skips — a warning, not a
    // failure, exactly as an unwritable dir is handled above.
    if shell == InstallShell::Bash && !bash_completion_present() {
        anyhow::bail!(
            "skipping bash completions: no bash-completion loader found on this system, \
             so nothing would source {} (install bash-completion >= 2.0, then re-run)",
            dir.display()
        );
    }

    let tmp = tmp_sibling(&target);

    // Probe that the directory is writable BEFORE generating anything: these
    // are shared, user-owned locations that can pre-exist unwritable (a
    // root-owned `~/.config/fish/completions`, say), and there is no point
    // rendering a shim we cannot place. The probe file is the temp sibling the
    // atomic write needs anyway.
    std::fs::create_dir_all(dir)
        .and_then(|()| std::fs::File::create(&tmp))
        // The io error itself is deliberately dropped: "Permission denied" on a
        // path the user never named is noise next to the directory that needs
        // fixing, and the installer has always reported this case that way.
        .map_err(|_| {
            anyhow::anyhow!(
                "failed to install {} completions ({} is not writable)",
                shell.name(),
                dir.display()
            )
        })?;

    let shim = render(shell.name())?;
    // Written to the sibling and renamed over the destination, so a completing
    // shell never sources a half-written file.
    if let Err(err) = std::fs::write(&tmp, &shim).and_then(|()| std::fs::rename(&tmp, &target)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow::anyhow!(
            "failed to install {} completions ({}: {err})",
            shell.name(),
            target.display()
        ));
    }

    if shell == InstallShell::Zsh {
        // The file is only ever autoloaded if its directory is on `$fpath`
        // before `compinit`, which is a property of the user's startup, not
        // something writing the file establishes. Point them at the one line
        // that fixes it whenever we cannot confirm the directory is already there.
        if !zsh_dir_on_fpath(dir) {
            eprintln!(
                "note: zsh loads {} only when its directory is on $fpath before compinit; \
                 add `fpath+=({})` to your ~/.zshrc if `min` completions do not appear",
                target.display(),
                dir.display()
            );
        }
        drop_zcompdump();
    }
    Ok(target)
}

/// Render the registration shim for `shell` (a clap_complete shell name).
fn render(shell: &str) -> Result<Vec<u8>, anyhow::Error> {
    let shells = clap_complete::env::Shells::builtins();
    let completer = shells
        .completer(shell)
        .with_context(|| format!("no shell integration for `{shell}`"))?;

    let mut out = Vec::new();
    completer
        .write_registration(crate::COMPLETE_VAR, "min", "min", "min", &mut out)
        .context("render shell integration")?;
    Ok(out)
}

/// `<target>.tmp.<pid>` — the installer's temp-file name, kept identical so a
/// leftover from either writer looks the same on disk.
fn tmp_sibling(target: &Path) -> PathBuf {
    let mut tmp = target.as_os_str().to_owned();
    tmp.push(format!(".tmp.{}", std::process::id()));
    PathBuf::from(tmp)
}

/// Drop a pre-existing `compinit` dump after (re)writing zsh's completion file.
///
/// compinit's staleness check is only (zsh version, completion-file count),
/// which cannot see `_min` change when the count happens to stay equal — so a
/// dump can keep trusting its stale contents, and "restart your shell" does not
/// fix it. The dump is a pure, regenerable cache, so dropping it just forces a
/// real rescan on the next zsh startup. Best-effort: a dump we cannot remove is
/// not a failed install.
fn drop_zcompdump() {
    let Some(dump) = zcompdump_path() else { return };
    if dump.exists() && std::fs::remove_file(&dump).is_ok() {
        eprintln!("cleared compinit dump cache {}", dump.display());
    }
}

/// `${ZDOTDIR:-$HOME}/.zcompdump`, the path zsh's `compinit` caches to.
fn zcompdump_path() -> Option<PathBuf> {
    let base = env_non_empty("ZDOTDIR").or_else(|| env_non_empty("HOME"))?;
    Some(PathBuf::from(base).join(".zcompdump"))
}

/// `$<var>` when set and non-empty, else `$HOME/<fallback>` — the `${VAR:-…}`
/// resolution `scripts/install.sh` uses for the completion dirs.
fn xdg_home(var: &str, fallback: &str) -> Result<PathBuf, anyhow::Error> {
    if let Some(value) = env_non_empty(var) {
        return Ok(PathBuf::from(value));
    }
    let home = env_non_empty("HOME").with_context(|| format!("neither ${var} nor $HOME is set"))?;
    Ok(PathBuf::from(home).join(fallback))
}

/// The value of `var` when it is set to something non-empty. An empty variable
/// counts as unset, matching the shell's `${VAR:-default}`.
fn env_non_empty(var: &str) -> Option<std::ffi::OsString> {
    std::env::var_os(var).filter(|value| !value.is_empty())
}

/// Whether the bash-completion project's loader is installed on this system.
///
/// `$BASH_COMPLETION_USER_DIR` is only ever set once that loader is sourced, so
/// its presence is a positive signal; otherwise probe the standard locations
/// the project's init script ships to across Linux and Homebrew.
fn bash_completion_present() -> bool {
    if env_non_empty("BASH_COMPLETION_USER_DIR").is_some() {
        return true;
    }
    const LOADERS: [&str; 7] = [
        "/usr/share/bash-completion/bash_completion",
        "/etc/bash_completion",
        "/etc/profile.d/bash_completion.sh",
        "/usr/local/share/bash-completion/bash_completion",
        "/usr/local/etc/profile.d/bash_completion.sh",
        "/opt/homebrew/share/bash-completion/bash_completion",
        "/opt/homebrew/etc/profile.d/bash_completion.sh",
    ];
    LOADERS.iter().any(|loader| Path::new(loader).exists())
}

/// Whether `dir` is on zsh's `$fpath`, as far as this process can tell. zsh ties
/// the `fpath` array to the exported-when-set `FPATH` scalar; when a setup
/// exports it we can check membership, otherwise the interactive shell's fpath
/// is invisible here, so report `false` and let the caller emit its hint.
fn zsh_dir_on_fpath(dir: &Path) -> bool {
    env_non_empty("FPATH").is_some_and(|fpath| fpath_contains(&fpath, dir))
}

/// Whether the `:`-separated `fpath` scalar has `dir` as an entry.
fn fpath_contains(fpath: &std::ffi::OsStr, dir: &Path) -> bool {
    std::env::split_paths(fpath).any(|entry| entry == dir)
}

#[cfg(test)]
mod tests {
    use super::fpath_contains;
    use std::ffi::OsString;
    use std::path::Path;

    #[test]
    fn fpath_membership_is_exact() {
        let fpath = OsString::from("/a:/home/u/.local/share/zsh/completions:/b");
        let dir = Path::new("/home/u/.local/share/zsh/completions");
        assert!(fpath_contains(&fpath, dir));
        // A parent of the completions dir is not the completions dir.
        assert!(!fpath_contains(
            &fpath,
            Path::new("/home/u/.local/share/zsh")
        ));
        assert!(!fpath_contains(&OsString::from("/a:/b"), dir));
    }
}
