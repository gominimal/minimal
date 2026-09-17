//! Which shell a session's interactive attach starts, and with what argv.
//!
//! A session's shell used to be bash, always. It is now whatever the
//! composition's `SHELL` names — when that names one of the shells this
//! daemon knows how to start *and* the session actually has it installed.
//! Anything else falls back to bash, which every session has
//! ([`crate::env`] force-adds it to the graph's top levels).
//!
//! `SHELL` is **declared, not sniffed**: it comes from a loadout's or a
//! project's `[vars]`, through the composition and the launcher's env
//! layering. Nothing here reads the environment of the terminal the
//! client ran in.
//!
//! # Why a fixed table
//!
//! Each shell needs its own argv, because each reaches the daemon's
//! per-attach `TERM` refresh a different way (see
//! [`install_attach_env_hooks`](crate::env)): bash is pointed at the
//! daemon's rc on the command line, zsh/fish/nushell find a hook the
//! daemon dropped at their own vendor integration point, and the POSIX
//! tier finds it through `$ENV`. A shell outside the table has no hook
//! to reach, so starting it would produce a session whose `TERM` goes
//! stale on re-attach — and the set is bounded anyway by the shell
//! packages the registry ships.

use std::path::Path;

/// A shell this daemon can start, as named by `SHELL`'s file name.
struct KnownShell {
    /// The binary's name — the file name of the `SHELL` value, and the
    /// name it is installed under in `/usr/bin`.
    binary: &'static str,
    /// The package that installs it. Not always the binary's name:
    /// nushell installs `nu`, and `sh` is a symlink the `bash` package
    /// ships. Used to tell the user what to install.
    package: &'static str,
    /// Argv after the program itself.
    args: &'static [&'static str],
    /// A `PS1` in *this shell's* prompt syntax, for shells that cannot
    /// read the bash-syntax one `sandbox2` sets as the session default
    /// (`crates/sandbox2/src/config.rs`). `None` means that default is
    /// already right — bash's own, and `sh`'s, since `sh` is bash — or
    /// that the shell ignores `PS1` altogether, as fish and nushell do.
    ///
    /// Only applied when nothing composed a `PS1`: a loadout that sets
    /// its own prompt keeps it.
    prompt: Option<&'static str>,
}

/// Every shell the daemon will start, keyed by binary name.
///
/// Deliberately closed. Kept in step with the two things that bound it:
/// the shell packages the registry ships (`bash`, `zsh`, `fish`,
/// `nushell` — `sh` rides along as a symlink from `bash`), and the
/// attach-env hooks `crate::env::install_attach_env_hooks` installs.
/// Growing one without the other leaves a shell that either can't be
/// installed or can't refresh its terminal.
const KNOWN_SHELLS: &[KnownShell] = &[
    KnownShell {
        binary: "bash",
        package: "bash",
        // `--rcfile` rather than `-l`: this build of bash has no
        // `/etc/bash.bashrc`, so the daemon's per-attach environment
        // hook has no shell-owned integration point to live in and must
        // be named on the argv — and bash consults `--rcfile` only for
        // an interactive *non-login* shell. `--noprofile` suppresses
        // every file `-l` would have read, so a session bash reads
        // nothing but the daemon's own rc (a user `~/.bashrc` stays
        // unread, as it always has). `-i` is explicit rather than
        // inferred from the pty.
        args: &[
            "--noprofile",
            "--rcfile",
            crate::env::ATTACH_ENV_BASH_RC,
            "-i",
        ],
        // The session default is already bash's own syntax.
        prompt: None,
    },
    KnownShell {
        binary: "zsh",
        package: "zsh",
        // The hook lives in `/etc/zsh/zshrc`, which zsh reads for an
        // interactive shell on its own. No `--no-rcs` here: unlike bash
        // — whose rc suppression predates this and is preserved — a user
        // who asks for zsh is asking for their zsh, `~/.zshrc` included.
        args: &["-i"],
        // zsh does not speak bash's `\[…\]`/`\u@\h` prompt escapes —
        // handed the session default it prints them literally. Same
        // prompt, zsh's syntax. A `~/.zshrc` that sets its own `PROMPT`
        // still wins: it runs after this.
        prompt: Some("%F{green}%n@%m%f:%F{blue}%~%f%# "),
    },
    KnownShell {
        binary: "fish",
        package: "fish",
        // Hook: `usr/share/fish/vendor_conf.d/`, which fish reads itself.
        args: &["-i"],
        // fish builds its prompt from `fish_prompt`, never `PS1`.
        prompt: None,
    },
    KnownShell {
        binary: "nu",
        package: "nushell",
        // Hook: `usr/share/nushell/vendor/autoload/`. No `-i`: nushell
        // has no such flag and is interactive when given no script.
        args: &[],
        // nushell builds its prompt from `PROMPT_COMMAND`-shaped config
        // of its own, never `PS1`.
        prompt: None,
    },
    KnownShell {
        binary: "sh",
        // The `bash` package ships `/usr/bin/sh` as a symlink to bash,
        // so this is installed in every session — bash in POSIX mode.
        package: "bash",
        // Hook: `$ENV`, the one startup file POSIX defines, which the
        // launcher baseline points at a daemon-owned file.
        args: &["-i"],
        // This is bash, so the bash-syntax session default applies:
        // POSIX mode changes the grammar, not the prompt escapes.
        prompt: None,
    },
];

/// The shell started when `SHELL` names nothing usable. Always present:
/// `crate::env` force-adds the `bash` package to every session.
const DEFAULT_SHELL: &str = "bash";

/// Where a session's binaries live. Packages build `--prefix=/usr`, and
/// the generic rootfs has no `/bin`, so this is the only directory worth
/// probing — the same rule
/// [`sandbox2::Sandbox::command`] applies when it resolves a bare
/// program name.
const BIN_DIR: &str = "usr/bin";

/// The shell to spawn for an interactive attach.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ShellChoice {
    /// Absolute in-sandbox path of the shell binary.
    pub(crate) program: String,
    /// Argv after the program.
    pub(crate) args: &'static [&'static str],
    /// Set when `SHELL` asked for something else and this is bash
    /// standing in: a ready-to-print sentence saying which shell was
    /// asked for, why it wasn't started, and how to get it. `None` on
    /// every path where the user got what they asked for — including
    /// the common one where they asked for nothing.
    pub(crate) fallback: Option<String>,
    /// A `PS1` to set for this shell, when the session default would be
    /// unreadable in it. See [`KnownShell::prompt`]; the caller applies
    /// it only if nothing composed a `PS1` of its own.
    pub(crate) prompt: Option<&'static str>,
}

impl ShellChoice {
    /// The default: bash, exactly as sessions started before `SHELL` was
    /// consulted at all.
    fn bash(fallback: Option<String>) -> Self {
        let bash = KNOWN_SHELLS
            .iter()
            .find(|s| s.binary == DEFAULT_SHELL)
            .expect("the default shell is in the table");
        Self {
            program: format!("/{BIN_DIR}/{}", bash.binary),
            args: bash.args,
            fallback,
            prompt: bash.prompt,
        }
    }
}

/// Resolve the shell to start from the session's composed `SHELL`.
///
/// `requested` is the value as written — typically an absolute path from
/// the host the loadout was authored on (`/opt/homebrew/bin/fish`,
/// `/run/current-system/sw/bin/zsh`). Only its file name is meaningful
/// here: the path itself describes a filesystem the sandbox has never
/// seen. `rootfs` is the assembled session rootfs, which is what makes
/// "is it installed" answerable.
pub(crate) fn resolve(requested: Option<&str>, rootfs: &Path) -> ShellChoice {
    let Some(requested) = requested.map(str::trim).filter(|s| !s.is_empty()) else {
        return ShellChoice::bash(None);
    };

    // A `SHELL` naming a directory (`/bin/`), a bare `..`, or a NUL is
    // not a shell; treat it the way an unknown shell is treated rather
    // than joining it onto a path.
    let name = Path::new(requested)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.contains('\0'))
        .unwrap_or_default();

    let Some(shell) = KNOWN_SHELLS.iter().find(|s| s.binary == name) else {
        return ShellChoice::bash(Some(format!(
            "SHELL names `{requested}`, which is not a shell minimal can start \
             (bash, zsh, fish, nu, sh) — starting bash instead.",
        )));
    };

    // `exists` follows symlinks on purpose: `/usr/bin/sh` is one, into
    // the same directory's `bash`.
    if !rootfs.join(BIN_DIR).join(shell.binary).exists() {
        return ShellChoice::bash(Some(format!(
            "SHELL names `{requested}`, which is not installed in this session — \
             starting bash instead. Add it with: min add --session {}",
            shell.package,
        )));
    }

    ShellChoice {
        program: format!("/{BIN_DIR}/{}", shell.binary),
        args: shell.args,
        fallback: None,
        prompt: shell.prompt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A rootfs carrying `bash` (which every session has) plus whichever
    /// other shells a case needs. `sh` is a symlink into it, the way the
    /// `bash` package ships it.
    fn rootfs_with(shells: &[&str]) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join(BIN_DIR);
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("bash"), "").unwrap();
        std::os::unix::fs::symlink("bash", bin.join("sh")).unwrap();
        for shell in shells {
            std::fs::write(bin.join(shell), "").unwrap();
        }
        tmp
    }

    /// The default path, unchanged from before `SHELL` was read: bash,
    /// with the rc that carries the per-attach `TERM` hook, and no
    /// notice to print.
    #[test]
    fn no_shell_var_starts_bash() {
        let rootfs = rootfs_with(&[]);
        let choice = resolve(None, rootfs.path());
        assert_eq!(choice.program, "/usr/bin/bash");
        assert_eq!(
            choice.args,
            [
                "--noprofile",
                "--rcfile",
                crate::env::ATTACH_ENV_BASH_RC,
                "-i"
            ],
        );
        assert_eq!(choice.fallback, None);
    }

    /// An installed shell is started, with the argv its own attach-env
    /// hook needs.
    #[test]
    fn an_installed_shell_is_started() {
        let rootfs = rootfs_with(&["fish"]);
        let choice = resolve(Some("/usr/bin/fish"), rootfs.path());
        assert_eq!(choice.program, "/usr/bin/fish");
        assert_eq!(choice.args, ["-i"]);
        assert_eq!(choice.fallback, None);
    }

    /// Only the file name is read. A loadout is authored on a host, so
    /// its `SHELL` names a path on *that* host — `/opt/homebrew/bin` and
    /// the Nix store are the common shapes, and neither exists in a
    /// session.
    #[test]
    fn a_host_path_resolves_by_its_file_name() {
        let rootfs = rootfs_with(&["fish"]);
        for requested in [
            "/opt/homebrew/bin/fish",
            "/run/current-system/sw/bin/fish",
            "fish",
        ] {
            let choice = resolve(Some(requested), rootfs.path());
            assert_eq!(choice.program, "/usr/bin/fish", "requested: {requested}");
            assert_eq!(choice.fallback, None, "requested: {requested}");
        }
    }

    /// `sh` resolves through the symlink the `bash` package ships, so it
    /// needs no package of its own — and it is bash in POSIX mode, which
    /// reaches the attach-env through `$ENV` rather than the rc.
    #[test]
    fn sh_resolves_through_the_symlink() {
        let rootfs = rootfs_with(&[]);
        let choice = resolve(Some("/bin/sh"), rootfs.path());
        assert_eq!(choice.program, "/usr/bin/sh");
        assert_eq!(choice.args, ["-i"]);
        assert_eq!(choice.fallback, None);
    }

    /// A known shell that isn't installed falls back, and the notice
    /// names the package to install rather than leaving the user to
    /// guess.
    #[test]
    fn a_known_shell_that_is_absent_falls_back_naming_its_package() {
        let rootfs = rootfs_with(&[]);
        let choice = resolve(Some("/usr/bin/zsh"), rootfs.path());
        assert_eq!(choice.program, "/usr/bin/bash");
        let notice = choice.fallback.expect("an absent shell must be reported");
        assert!(notice.contains("/usr/bin/zsh"), "got: {notice}");
        assert!(notice.contains("min add --session zsh"), "got: {notice}");
    }

    /// The package name is not always the binary name: nushell installs
    /// `nu`, so `min add --session nu` would fail. The notice has to
    /// name the package.
    #[test]
    fn the_notice_names_the_package_not_the_binary() {
        let rootfs = rootfs_with(&[]);
        let notice = resolve(Some("nu"), rootfs.path())
            .fallback
            .expect("an absent shell must be reported");
        assert!(
            notice.contains("min add --session nushell"),
            "got: {notice}"
        );
    }

    /// Nushell takes no interactive flag — it is interactive when given
    /// no script, and `-i` would be a parse error.
    #[test]
    fn nushell_is_started_with_no_args() {
        let rootfs = rootfs_with(&["nu"]);
        let choice = resolve(Some("/usr/bin/nu"), rootfs.path());
        assert_eq!(choice.program, "/usr/bin/nu");
        assert!(choice.args.is_empty());
    }

    /// A shell outside the table falls back even when a binary of that
    /// name is sitting in the rootfs: without an attach-env hook its
    /// `TERM` would go stale on every re-attach.
    #[test]
    fn an_unknown_shell_falls_back_even_when_present() {
        let rootfs = rootfs_with(&["elvish"]);
        let choice = resolve(Some("/usr/bin/elvish"), rootfs.path());
        assert_eq!(choice.program, "/usr/bin/bash");
        let notice = choice.fallback.expect("an unknown shell must be reported");
        assert!(notice.contains("elvish"), "got: {notice}");
        assert!(notice.contains("bash, zsh, fish, nu, sh"), "got: {notice}");
    }

    /// Values that name no file at all take the unknown-shell path
    /// rather than reaching the filesystem.
    #[test]
    fn malformed_values_fall_back() {
        let rootfs = rootfs_with(&[]);
        for requested in ["", "   ", "/", "/bin/", ".."] {
            let choice = resolve(Some(requested), rootfs.path());
            assert_eq!(
                choice.program, "/usr/bin/bash",
                "`{requested}` should not start anything but bash",
            );
        }
    }

    /// zsh cannot read the bash-syntax `PS1` that `sandbox2` sets as the
    /// session default — handed it, zsh prints the escapes as text
    /// (`\[\033[01;32m\]\u@\h…` on the prompt line). It gets the same
    /// prompt in its own grammar instead.
    #[test]
    fn zsh_gets_a_prompt_in_its_own_syntax() {
        let rootfs = rootfs_with(&["zsh"]);
        let prompt = resolve(Some("/usr/bin/zsh"), rootfs.path())
            .prompt
            .expect("zsh cannot use the bash-syntax default");
        assert!(
            !prompt.contains(r"\u") && !prompt.contains(r"\["),
            "a zsh prompt must not carry bash escapes: {prompt}",
        );
        assert!(prompt.contains("%n@%m"), "got: {prompt}");
    }

    /// bash and `sh` are the same binary, and the session default is
    /// already written in their syntax — neither may be handed an
    /// override, or a user staring at bash would see a prompt this
    /// module invented rather than the one the sandbox sets.
    #[test]
    fn bash_and_sh_keep_the_session_default_prompt() {
        let rootfs = rootfs_with(&[]);
        for requested in [None, Some("/usr/bin/bash"), Some("/bin/sh")] {
            assert_eq!(
                resolve(requested, rootfs.path()).prompt,
                None,
                "requested: {requested:?}",
            );
        }
    }

    /// fish and nushell build their prompts from their own config and
    /// never read `PS1`, so there is nothing to override.
    #[test]
    fn shells_that_ignore_ps1_get_no_prompt() {
        let rootfs = rootfs_with(&["fish", "nu"]);
        for requested in ["fish", "nu"] {
            assert_eq!(
                resolve(Some(requested), rootfs.path()).prompt,
                None,
                "requested: {requested}",
            );
        }
    }

    /// Every entry has to be startable and reportable: a binary the
    /// table can't find in `/usr/bin`, or a package name that isn't the
    /// one `min add` takes, would surface as a broken session or a
    /// misleading notice.
    #[test]
    fn the_table_is_self_consistent() {
        let names: Vec<&str> = KNOWN_SHELLS.iter().map(|s| s.binary).collect();
        assert!(
            names.contains(&DEFAULT_SHELL),
            "the fallback must be listed"
        );
        for shell in KNOWN_SHELLS {
            assert!(!shell.binary.is_empty());
            assert!(!shell.package.is_empty());
            assert!(
                !shell.binary.contains('/'),
                "`{}` is joined onto a path and must be one component",
                shell.binary,
            );
        }
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "duplicate binary in the table");
    }
}
