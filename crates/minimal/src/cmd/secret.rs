//! `min secret set | list | rm`: secrets in the host's native store, by
//! identifier (BEP-050 to BEP-053).
//!
//! `set` reads the value from the terminal or from standard input, never
//! from an argument or an environment variable, and prints only the
//! identifier. The item's access control lets the proxy binary read it
//! without a prompt (BEP-051, `bep::store`). `list` prints metadata and no
//! value. Each `set` and `rm` logs one info line with the store and the
//! identifier, never the value.

use std::io::{IsTerminal as _, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use bep::store::{HostStore, NATIVE_STORE, SecretStore, proxy_binary_path, valid_id};
use boxes::core::bep::{StoreAction, StoreRuleConfig, StoreRules};
use zeroize::Zeroizing;

use crate::{GlobalArgs, SecretListArgs, SecretRmArgs, SecretSetArgs};

/// The refusal of a value given on the command line. The task pins this
/// text (BEP-050).
pub(crate) const VALUE_ARGUMENT_REFUSED: &str = "min secret set reads the value from the terminal or standard input, never from an argument or an environment flag.";

/// Where `set` reads the value from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueSource {
    /// Standard input is a terminal: prompt, with no echo.
    Terminal,
    /// Standard input is a pipe or a file.
    Stdin,
    /// Standard input is closed, or is `/dev/null`.
    Absent,
}

/// The source of the value for this process.
fn detect_source() -> ValueSource {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return ValueSource::Terminal;
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsFd as _;
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
        let Ok(fd) = stdin.as_fd().try_clone_to_owned() else {
            return ValueSource::Absent;
        };
        let Ok(meta) = std::fs::File::from(fd).metadata() else {
            return ValueSource::Absent;
        };
        if meta.file_type().is_char_device()
            && std::fs::metadata("/dev/null").is_ok_and(|null| null.rdev() == meta.rdev())
        {
            return ValueSource::Absent;
        }
    }
    ValueSource::Stdin
}

/// The proxy binary that the item's access control names.
fn proxy_path() -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe().context("could not find the path of this `min` program")?;
    Ok(proxy_binary_path(
        std::env::var_os(bep::store::PROXY_BIN_ENV).as_deref(),
        &exe,
    ))
}

/// `min secret set`.
pub fn cmd_secret_set(_global: &GlobalArgs, args: SecretSetArgs) -> anyhow::Result<()> {
    // The refusals that need no store run first, so a value typed on the
    // command line is refused before anything else happens.
    refuse_set_args(&args)?;
    let source = detect_source();
    run_set(
        &HostStore,
        &args,
        &proxy_path()?,
        source,
        &mut || read_terminal(&args.id),
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
    )
}

/// Prompt on the terminal, with no echo.
fn read_terminal(id: &str) -> anyhow::Result<Zeroizing<String>> {
    let value = inquire::Password::new(&format!("Value for {id}:"))
        .without_confirmation()
        .prompt()
        .context("min secret set did not read the value from the terminal")?;
    Ok(Zeroizing::new(value))
}

/// The refusals of `set` that come from its arguments alone.
fn refuse_set_args(args: &SecretSetArgs) -> anyhow::Result<()> {
    if args.value.is_some() || args.env.is_some() {
        bail!("{VALUE_ARGUMENT_REFUSED}");
    }
    check_id(&args.id)?;
    check_store(args.store.as_deref())?;
    Ok(())
}

fn check_id(id: &str) -> anyhow::Result<()> {
    if !valid_id(id) {
        bail!(
            "`{id}` is not a name a secret can have. Use 1 to {} letters, digits, `.`, `_` and `-`, not starting with `-`.",
            bep::store::MAX_ID_LEN
        );
    }
    Ok(())
}

/// Refuse every store but the host's native one.
fn check_store(store: Option<&str>) -> anyhow::Result<()> {
    match store {
        None | Some(NATIVE_STORE) => Ok(()),
        Some("gatehouse") => bail!(
            "min secret refused --store gatehouse. Secrets for the Gatehouse store are deposited with Gatehouse, not on this host. Run the command without --store to use the host keychain."
        ),
        Some(other) => bail!(
            "min secret does not know the store `{other}`. The one store on this host is `{NATIVE_STORE}`. Run the command without --store to use it."
        ),
    }
}

/// `set` against `store`: the refusals, then the read, then the write.
pub(crate) fn run_set(
    store: &dyn SecretStore,
    args: &SecretSetArgs,
    proxy: &Path,
    source: ValueSource,
    terminal: &mut dyn FnMut() -> anyhow::Result<Zeroizing<String>>,
    stdin: &mut dyn Read,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    refuse_set_args(args)?;
    if !proxy.is_file() {
        bail!(
            "min secret set did not read the value: the Box Egress Proxy program is not at {}. \
             Only that program can read the stored secret without a prompt. \
             Set {} to the path of the `bep` program, and run the command again.",
            proxy.display(),
            bep::store::PROXY_BIN_ENV
        );
    }
    let value = match source {
        ValueSource::Absent => bail!(
            "min secret set has no value to store: there is no terminal, and standard input is empty. \
             Pipe the value in, as in `printf %s \"$VALUE\" | min secret set {}`.",
            args.id
        ),
        ValueSource::Terminal => terminal()?,
        ValueSource::Stdin => {
            let mut text = Zeroizing::new(String::new());
            stdin
                .read_to_string(&mut text)
                .context("min secret set did not read standard input")?;
            // One trailing line break is the end of the input, not part of
            // the value.
            let end = text
                .strip_suffix("\r\n")
                .or_else(|| text.strip_suffix('\n'))
                .map_or(text.len(), str::len);
            text.truncate(end);
            text
        }
    };
    if value.is_empty() {
        bail!(
            "min secret set stored nothing: the value is empty. Run the command again and give a value."
        );
    }
    store
        .set(&args.id, value.as_bytes(), proxy)
        .with_context(|| format!("min secret set did not store {}", args.id))?;
    tracing::info!(store = store.name(), id = %args.id, "secret stored");
    writeln!(out, "{}", args.id)?;
    Ok(())
}

/// `min secret list`.
pub fn cmd_secret_list(global: &GlobalArgs, args: SecretListArgs) -> anyhow::Result<()> {
    check_store(args.store.as_deref())?;
    let (_, rules) = crate::config::read_client_config_and_store_rules(global)?;
    run_list(
        &HostStore,
        &rules,
        &proxy_path()?,
        &mut std::io::stdout().lock(),
    )
}

/// The rule in `rules` that registers the item `id` of `store`.
fn rule_for<'r>(rules: &'r StoreRules, store: &str, id: &str) -> Option<&'r StoreRuleConfig> {
    rules
        .get(id)
        .filter(|rule| rule.store.as_deref().unwrap_or(NATIVE_STORE) == store)
}

/// `list` against `store`, with the rules of the client configuration.
pub(crate) fn run_list(
    store: &dyn SecretStore,
    rules: &StoreRules,
    proxy: &Path,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let items = store
        .list(proxy)
        .context("min secret list did not read the store")?;
    if items.is_empty() {
        writeln!(out, "No secrets in the {} store.", store.name())?;
        return Ok(());
    }
    for (n, item) in items.iter().enumerate() {
        if n > 0 {
            writeln!(out)?;
        }
        let rule = rule_for(rules, store.name(), &item.id);
        let (upstream, injection) = match rule {
            Some(rule) => (rule.upstream.join(", "), injection(rule)),
            None => (
                "none (no [secret-store-rules] rule)".to_owned(),
                "none".to_owned(),
            ),
        };
        let consent = match rule.and_then(|r| r.action) {
            None => "none",
            Some(StoreAction::Allow) => "allow",
            Some(StoreAction::Ask) => "ask",
            Some(StoreAction::Deny) => "deny",
        };
        let access = if item.proxy_access {
            format!("yes, {}", proxy.display())
        } else {
            "no".to_owned()
        };
        writeln!(out, "{}", item.id)?;
        writeln!(out, "  store:                 {}", store.name())?;
        writeln!(out, "  upstream:              {upstream}")?;
        writeln!(out, "  injection:             {injection}")?;
        writeln!(out, "  consent:               {consent}")?;
        writeln!(out, "  proxy reads it freely: {access}")?;
    }
    Ok(())
}

/// The injection form of `rule`, as the list shows it.
fn injection(rule: &StoreRuleConfig) -> String {
    match (&rule.header, &rule.basic_auth) {
        (Some(header), _) => match &rule.prefix {
            Some(prefix) => format!("header {header}, prefix {prefix:?}"),
            None => format!("header {header}"),
        },
        (None, Some(field)) => format!("basic auth {field}"),
        (None, None) => "none".to_owned(),
    }
}

/// `min secret rm`.
pub fn cmd_secret_rm(_global: &GlobalArgs, args: SecretRmArgs) -> anyhow::Result<()> {
    run_rm(&HostStore, &args, &mut std::io::stdout().lock())
}

/// `rm` against `store`.
pub(crate) fn run_rm(
    store: &dyn SecretStore,
    args: &SecretRmArgs,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    check_id(&args.id)?;
    check_store(args.store.as_deref())?;
    let removed = store
        .remove(&args.id)
        .with_context(|| format!("min secret rm did not remove {}", args.id))?;
    if !removed {
        bail!(
            "There is no secret named {} in the {} store. Run `min secret list` to see the stored names.",
            args.id,
            store.name()
        );
    }
    tracing::info!(store = store.name(), id = %args.id, "secret removed");
    writeln!(out, "Removed {} from the {} store.", args.id, store.name())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bep::store::{MemorySecretStore, keychain_add_line};
    use clap::Parser as _;

    fn set_args(argv: &[&str]) -> SecretSetArgs {
        let mut full = vec!["min", "secret", "set"];
        full.extend_from_slice(argv);
        match crate::Cli::try_parse_from(full).expect("parses").command {
            Some(crate::Command::Secret(crate::SecretArgs {
                command: crate::SecretCommand::Set(args),
            })) => args,
            _ => panic!("not secret set"),
        }
    }

    /// A proxy binary that exists.
    fn proxy() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bep");
        std::fs::write(&path, b"").unwrap();
        (dir, path)
    }

    fn no_terminal() -> anyhow::Result<Zeroizing<String>> {
        panic!("the terminal was read")
    }

    struct PanicRead;
    impl Read for PanicRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("standard input was read")
        }
    }

    fn set_from_stdin(
        store: &MemorySecretStore,
        argv: &[&str],
        proxy: &Path,
        input: &str,
    ) -> (anyhow::Result<()>, String) {
        let mut out = Vec::new();
        let result = run_set(
            store,
            &set_args(argv),
            proxy,
            ValueSource::Stdin,
            &mut no_terminal,
            &mut input.as_bytes(),
            &mut out,
        );
        (result, String::from_utf8(out).unwrap())
    }

    #[test]
    fn secret_set_stores_in_keychain_and_prints_id_only() {
        let (_dir, proxy) = proxy();
        let store = MemorySecretStore::default();
        let (result, out) = set_from_stdin(&store, &["claude"], &proxy, "sk-ant-secret\n");
        result.unwrap();
        assert_eq!(out, "claude\n");
        assert!(!out.contains("sk-ant-secret"));
        assert_eq!(
            store.value("claude").as_deref(),
            Some(&b"sk-ant-secret"[..])
        );
        assert_eq!(store.name(), "keychain");

        // From the terminal too, and `--store keychain` is the same store.
        let mut out = Vec::new();
        run_set(
            &store,
            &set_args(&["claude", "--store", "keychain"]),
            &proxy,
            ValueSource::Terminal,
            &mut || Ok(Zeroizing::new("typed".to_owned())),
            &mut PanicRead,
            &mut out,
        )
        .unwrap();
        assert_eq!(out, b"claude\n");
        assert_eq!(store.value("claude").as_deref(), Some(&b"typed"[..]));
    }

    #[test]
    fn secret_set_refuses_value_argument_and_env_flag() {
        let (_dir, proxy) = proxy();
        for argv in [
            &["claude", "sk-ant-secret"][..],
            &["claude", "--env", "ANTHROPIC_API_KEY"][..],
            &["claude", "--from-env", "ANTHROPIC_API_KEY"][..],
        ] {
            let store = MemorySecretStore::default();
            let mut out = Vec::new();
            let err = run_set(
                &store,
                &set_args(argv),
                &proxy,
                ValueSource::Stdin,
                &mut no_terminal,
                &mut PanicRead,
                &mut out,
            )
            .expect_err("refused");
            assert_eq!(format!("{err:#}"), VALUE_ARGUMENT_REFUSED, "{argv:?}");
            assert!(out.is_empty());
            assert!(store.value("claude").is_none());
        }
        // The process entry refuses before it looks at standard input.
        let err = refuse_set_args(&set_args(&["claude", "v"])).expect_err("refused");
        assert_eq!(err.to_string(), VALUE_ARGUMENT_REFUSED);
    }

    #[test]
    fn secret_set_without_tty_or_stdin_fails_immediately() {
        let (_dir, proxy) = proxy();
        let store = MemorySecretStore::default();
        let mut out = Vec::new();
        let err = run_set(
            &store,
            &set_args(&["claude"]),
            &proxy,
            ValueSource::Absent,
            &mut no_terminal,
            &mut PanicRead,
            &mut out,
        )
        .expect_err("no source");
        assert!(format!("{err:#}").contains("no terminal"), "{err:#}");
        assert!(store.value("claude").is_none());

        // Standard input that ends at once stores nothing either.
        let (result, out) = set_from_stdin(&store, &["claude"], &proxy, "");
        assert!(format!("{:#}", result.expect_err("empty")).contains("empty"));
        assert!(out.is_empty());
        assert!(store.value("claude").is_none());
    }

    #[test]
    fn secret_set_refuses_gatehouse_store() {
        let (_dir, proxy) = proxy();
        let store = MemorySecretStore::default();
        let mut out = Vec::new();
        let err = run_set(
            &store,
            &set_args(&["claude", "--store", "gatehouse"]),
            &proxy,
            ValueSource::Stdin,
            &mut no_terminal,
            &mut PanicRead,
            &mut out,
        )
        .expect_err("refused");
        let text = format!("{err:#}");
        assert!(text.contains("--store gatehouse"), "{text}");
        assert!(text.contains("not on this host"), "{text}");
        assert!(store.value("claude").is_none());
        let mut out = Vec::new();
        let rm = SecretRmArgs {
            id: "claude".into(),
            store: Some("gatehouse".into()),
        };
        assert!(run_rm(&store, &rm, &mut out).is_err());
    }

    #[test]
    fn secret_list_shows_metadata_without_values() {
        let (_dir, proxy) = proxy();
        let store = MemorySecretStore::default();
        set_from_stdin(&store, &["claude"], &proxy, "sk-ant-one")
            .0
            .unwrap();
        set_from_stdin(&store, &["linear"], &proxy, "lin-two")
            .0
            .unwrap();
        set_from_stdin(&store, &["sentry"], &proxy, "sen-three")
            .0
            .unwrap();
        // An item whose access control no longer names the proxy.
        store.set_trusted("sentry", vec![PathBuf::from("/Applications/Other.app")]);
        let rules: StoreRules = toml::from_str(
            r#"
            [claude]
            upstream = ["api.anthropic.com"]
            header = "Authorization"
            prefix = "Bearer "
            action = "ask"

            [linear]
            store = "onepassword"
            upstream = ["mcp.linear.app"]
            basic_auth = "password"
            "#,
        )
        .unwrap();
        let mut out = Vec::new();
        run_list(&store, &rules, &proxy, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        for value in ["sk-ant-one", "lin-two", "sen-three"] {
            assert!(!out.contains(value), "{out}");
        }
        let expected = format!(
            "claude
  store:                 keychain
  upstream:              api.anthropic.com
  injection:             header Authorization, prefix \"Bearer \"
  consent:               ask
  proxy reads it freely: yes, {p}

linear
  store:                 keychain
  upstream:              none (no [secret-store-rules] rule)
  injection:             none
  consent:               none
  proxy reads it freely: yes, {p}

sentry
  store:                 keychain
  upstream:              none (no [secret-store-rules] rule)
  injection:             none
  consent:               none
  proxy reads it freely: no
",
            p = proxy.display()
        );
        assert_eq!(out, expected);

        let mut out = Vec::new();
        run_list(&MemorySecretStore::default(), &rules, &proxy, &mut out).unwrap();
        assert_eq!(out, b"No secrets in the keychain store.\n");
    }

    #[test]
    fn secret_rm_removes_item() {
        let (_dir, proxy) = proxy();
        let store = MemorySecretStore::default();
        set_from_stdin(&store, &["claude"], &proxy, "v").0.unwrap();
        let args = SecretRmArgs {
            id: "claude".into(),
            store: None,
        };
        let mut out = Vec::new();
        run_rm(&store, &args, &mut out).unwrap();
        assert_eq!(out, b"Removed claude from the keychain store.\n");
        assert!(store.value("claude").is_none());
        assert!(store.list(&proxy).unwrap().is_empty());
        // A second remove finds nothing, and says so.
        let err = run_rm(&store, &args, &mut Vec::new()).expect_err("absent");
        assert!(err.to_string().contains("no secret named claude"), "{err}");
    }

    #[test]
    fn secret_item_acl_admits_proxy_only() {
        let (_dir, proxy) = proxy();
        let store = MemorySecretStore::default();
        set_from_stdin(&store, &["claude"], &proxy, "v").0.unwrap();
        assert!(store.reads_without_prompt("claude", &proxy));
        assert!(!store.reads_without_prompt("claude", Path::new("/usr/bin/security")));
        assert!(!store.reads_without_prompt("claude", &proxy.with_file_name("min")));

        // The keychain line names the proxy as the one trusted application,
        // without `-A` (any application), and carries the value only as hex.
        let line = keychain_add_line("claude", b"sk-ant", &proxy).unwrap();
        let words: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(words.iter().filter(|w| **w == "-T").count(), 1, "{line}");
        assert!(
            line.contains(&format!("-T \"{}\"", proxy.display())),
            "{line}"
        );
        assert!(!words.contains(&"-A"), "{line}");
        // An update in place keeps the old access control, so no `-U`.
        assert!(!words.contains(&"-U"), "{line}");
        assert!(!line.contains("sk-ant"), "{line}");
        assert!(line.trim_end().ends_with("-X 736b2d616e74"), "{line}");
        assert!(keychain_add_line("claude", b"v", Path::new("/a\"b/bep")).is_err());

        // A listing reads the entry back from `security dump-keychain -a`.
        let dump = format!(
            "keychain: \"/Users/me/Library/Keychains/login.keychain-db\"
class: \"genp\"
attributes:
    \"acct\"<blob>=\"claude\"
    \"svce\"<blob>=\"dev.minimal.secret\"
access: 2 entries
    entry 0:
        authorizations (1): acl_change
        applications: <null>
    entry 1:
        authorizations (6): decrypt derive export_clear export_wrapped mac sign
        don't-require-password
        description: Minimal secret claude
        applications (1):
            0: {p} (OK)
keychain: \"/Users/me/Library/Keychains/login.keychain-db\"
class: \"genp\"
attributes:
    \"acct\"<blob>=\"other\"
    \"svce\"<blob>=\"dev.minimal.secret\"
access: 1 entries
    entry 0:
        authorizations (6): decrypt derive export_clear export_wrapped mac sign
        applications (1):
            0: /usr/bin/security (OK)
keychain: \"/Users/me/Library/Keychains/login.keychain-db\"
class: \"genp\"
attributes:
    \"acct\"<blob>=\"github\"
    \"svce\"<blob>=\"dev.minimal.github-sign-in\"
",
            p = proxy.display()
        );
        let items = bep::store::parse_dump(&dump, &proxy);
        assert_eq!(
            items,
            vec![
                bep::store::ItemInfo {
                    id: "claude".into(),
                    proxy_access: true
                },
                bep::store::ItemInfo {
                    id: "other".into(),
                    proxy_access: false
                },
            ]
        );
    }

    #[test]
    fn secret_set_refuses_when_proxy_binary_absent() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("bep");
        let store = MemorySecretStore::default();
        let mut out = Vec::new();
        let err = run_set(
            &store,
            &set_args(&["claude"]),
            &missing,
            ValueSource::Stdin,
            &mut no_terminal,
            &mut PanicRead,
            &mut out,
        )
        .expect_err("refused");
        let text = format!("{err:#}");
        assert!(text.contains(&missing.display().to_string()), "{text}");
        assert!(text.contains("did not read the value"), "{text}");
        assert!(store.value("claude").is_none());

        // The path is `bep` beside `min`, or the variable's path.
        let exe = Path::new("/opt/minimal/bin/min");
        assert_eq!(
            proxy_binary_path(None, exe),
            PathBuf::from("/opt/minimal/bin/bep")
        );
        assert_eq!(
            proxy_binary_path(Some(std::ffi::OsStr::new("")), exe),
            PathBuf::from("/opt/minimal/bin/bep")
        );
        assert_eq!(
            proxy_binary_path(Some(std::ffi::OsStr::new("/x/bep")), exe),
            PathBuf::from("/x/bep")
        );
    }
}
