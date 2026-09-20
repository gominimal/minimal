//! `min secret`: the values this host holds for a box to reference.
//!
//! A box never holds a referenced value: it receives a short-lived handle and
//! the proxy injects the value itself into the box's requests. This is the
//! surface that puts the value on the host in the first place (BEP-050 to
//! BEP-053).
//!
//! `set` reads the value from the terminal, which never echoes it, or from
//! standard input when it is piped, and refuses a value given as a command-line
//! argument or named in an environment variable — both of which every process
//! on the host can read, and the first of which lands in a shell history. The
//! item is stored with an access control naming the proxy's process identity,
//! so the proxy reads it without a prompt and every other application prompts
//! (BEP-051); `min` itself never reads a stored value back.
//!
//! `list` shows what the operator's `[secret-store-rules]` register for each
//! stored identifier — the upstream authorities, the injection form, the
//! consent rule — and whether the item's access entry for the proxy is set,
//! and no value (BEP-052). `rm` takes an item out of its store (BEP-053).
//!
//! The store is the host's native one: the macOS Keychain here, since the
//! Linux default waits on the store roster. `--store gatehouse` names a
//! deposit into a Gatehouse tenant store, which is a configured Gatehouse's to
//! make and not this host's; the grammar is shared and the command is refused.

use std::io::{BufRead, IsTerminal as _, Write};
use std::path::Path;

use anyhow::bail;
use bep::github::Secret;
use bep::keychain::{ItemAcl, SecretItem, SecretItems};
use sessions::{Injection, SecretStore, StoreRule};

use crate::{
    GlobalArgs, SecretCommand, SecretListArgs, SecretRmArgs, SecretSetArgs, SecretStoreArg,
};

/// Why a value on the command line or in an environment variable is refused,
/// and what is accepted instead (BEP-050).
const ARGUMENT_REFUSAL: &str = "a value given as an argument or named in an environment variable \
                                is readable by every process on this host, and an argument lands \
                                in your shell history as well: `min secret set <id>` reads the \
                                value from the terminal, or from standard input when you pipe it";

/// Why a run with neither source fails, rather than waiting for one (BEP-050).
const NO_SOURCE: &str = "no value to read: `min secret set <id>` reads the value from the \
                         terminal, or from standard input when you pipe it, and this run has \
                         neither";

/// Why a deposit into the Gatehouse tenant store is outside this host's scope
/// (BEP-050).
const GATEHOUSE_REFUSAL: &str = "`--store gatehouse` deposits into a Gatehouse tenant store, \
                                 which is outside this host's scope: the deposit is made through \
                                 the Gatehouse that holds the tenant, and `min secret` here holds \
                                 values in this host's own stores";

/// Where `min secret set` reads the value from (BEP-050).
pub(crate) enum Source<'a> {
    /// A terminal is on standard input: ask for the value without echoing it.
    Terminal,
    /// Standard input is a pipe or a file: take the first line of it.
    Stdin(&'a mut dyn BufRead),
}

/// The host's secret store: the macOS Keychain, which is where the proxy's
/// keys and the GitHub sign-in live too.
#[cfg(target_os = "macos")]
fn host_secrets() -> Result<bep::keychain::KeychainSecrets, anyhow::Error> {
    Ok(bep::keychain::KeychainSecrets)
}

/// A host with no keychain backend holds no referenced value, as it holds no
/// sign-in to mint from either.
#[cfg(not(target_os = "macos"))]
fn host_secrets() -> Result<bep::keychain::MemorySecrets, anyhow::Error> {
    bail!(
        "min secret holds values in the host keychain, and this host has no keychain backend yet \
         (macOS only)"
    )
}

/// The proxy binary this host would run: its path is the process identity the
/// item's access control names (BEP-051). Resolved rather than required to
/// exist, because the item is set before the proxy has ever run.
fn proxy_identity() -> std::path::PathBuf {
    minvmd::net::resolve_bep_path()
}

/// The store a command names: this host's native store with no `--store`, and
/// a refusal naming the deposit for `--store gatehouse` (BEP-050).
fn resolve_store(named: Option<SecretStoreArg>) -> Result<SecretStore, anyhow::Error> {
    match named {
        None | Some(SecretStoreArg::Keychain) => Ok(SecretStore::Keychain),
        Some(SecretStoreArg::Gatehouse) => bail!(GATEHOUSE_REFUSAL),
    }
}

/// The value, from the terminal or from standard input. Neither source is
/// waited on: a terminal is asked once, a pipe is read once, and a run with
/// nothing on either fails (BEP-050).
fn read_value(source: Source<'_>) -> Result<Secret, anyhow::Error> {
    let value = match source {
        Source::Terminal => inquire::Password::new("value:")
            .without_confirmation()
            .with_display_mode(inquire::PasswordDisplayMode::Hidden)
            .with_help_message("the value is not echoed and is stored in this host's keychain")
            .prompt()?,
        Source::Stdin(reader) => {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 {
                bail!(NO_SOURCE);
            }
            line
        }
    };
    let value = value.trim_end_matches(['\n', '\r']);
    if value.is_empty() {
        bail!(NO_SOURCE);
    }
    Ok(Secret::new(value))
}

/// Stores the value under the identifier, with the access control that admits
/// the proxy alone, and prints the identifier and no value.
fn set<S: SecretItems>(
    store: &S,
    proxy: &Path,
    args: &SecretSetArgs,
    source: Source<'_>,
    out: &mut impl Write,
) -> Result<(), anyhow::Error> {
    if args.value.is_some() || args.value_flag.is_some() || args.from_env.is_some() {
        bail!(ARGUMENT_REFUSAL);
    }
    let named = resolve_store(args.store)?;
    let value = read_value(source)?;
    let acl = ItemAcl::for_proxy(proxy);
    store.set(&args.id, &value, &acl)?;
    writeln!(out, "{named} `{id}` stored", id = args.id)?;
    tracing::info!(id = %args.id, store = %named, "stored a secret");
    Ok(())
}

/// Prints one line per stored identifier: its store, what the operator's rule
/// registers for it, the consent rule, and whether the proxy's access entry is
/// set — and no value (BEP-052).
fn list<S: SecretItems>(
    store: &S,
    named: SecretStore,
    rules: &[StoreRule],
    out: &mut impl Write,
) -> Result<(), anyhow::Error> {
    let items = store.items()?;
    if items.is_empty() {
        writeln!(out, "{named}: no values stored")?;
    }
    for item in &items {
        writeln!(out, "{}", row(named, item, rules))?;
    }
    tracing::info!(store = %named, items = items.len(), "listed the stored secrets");
    Ok(())
}

/// One listing row: the item and what the matching rule registers for it.
fn row(named: SecretStore, item: &SecretItem, rules: &[StoreRule]) -> String {
    let rule = rules
        .iter()
        .find(|rule| rule.store == named && rule.id == item.id);
    let authorities = rule.map_or_else(
        || "none registered".to_owned(),
        |rule| rule.upstream.join(", "),
    );
    let inject = rule.map_or_else(
        || "none registered".to_owned(),
        |rule| injection(&rule.inject),
    );
    let consent = rule.map_or_else(|| "none".to_owned(), |rule| rule.action.to_string());
    format!(
        "{named}  {id}  authorities {authorities}  inject {inject}  consent {consent}  proxy \
         access {access}",
        id = item.id,
        access = if item.proxy_access { "set" } else { "not set" },
    )
}

/// The injection form a rule registers, as a row names it: the header and the
/// prefix that precedes the value in it, or the basic-authentication field the
/// value fills.
fn injection(inject: &Injection) -> String {
    match inject {
        Injection::Header { name, prefix } if prefix.is_empty() => format!("header `{name}`"),
        Injection::Header { name, prefix } => format!("header `{name}` prefix `{prefix}`"),
        other => other.to_string(),
    }
}

/// Removes the stored item.
fn rm<S: SecretItems>(
    store: &S,
    named: SecretStore,
    args: &SecretRmArgs,
    out: &mut impl Write,
) -> Result<(), anyhow::Error> {
    store.delete(&args.id)?;
    writeln!(out, "{named} `{id}` removed", id = args.id)?;
    tracing::info!(id = %args.id, store = %named, "removed a secret");
    Ok(())
}

/// Runs `min secret set`, `min secret list` or `min secret rm` against this
/// host's store.
///
/// # Errors
///
/// A host with no store backend, a refused command (a value as an argument, a
/// Gatehouse deposit, a run with no value to read), an unreadable client
/// configuration, or a store that refuses the write, the search or the
/// deletion.
pub fn cmd_secret(global: &GlobalArgs, command: SecretCommand) -> Result<(), anyhow::Error> {
    let store = host_secrets()?;
    let mut out = std::io::stdout().lock();
    match command {
        SecretCommand::Set(args) => {
            let proxy = proxy_identity();
            if std::io::stdin().is_terminal() {
                set(&store, &proxy, &args, Source::Terminal, &mut out)
            } else {
                let stdin = std::io::stdin();
                let mut locked = stdin.lock();
                set(&store, &proxy, &args, Source::Stdin(&mut locked), &mut out)
            }
        }
        SecretCommand::List(SecretListArgs { store: named }) => {
            let named = resolve_store(named)?;
            let client = crate::config::read_client_config(global)?;
            list(&store, named, &client.secret_store_rules, &mut out)
        }
        SecretCommand::Rm(args) => {
            let named = resolve_store(args.store)?;
            rm(&store, named, &args, &mut out)
        }
    }
}

#[cfg(test)]
mod tests {
    use bep::keychain::MemorySecrets;
    use sessions::RuleAction;

    use super::*;

    /// The proxy binary an item's access control is set for in these tests.
    const PROXY: &str = "/usr/lib/minimal/bin/bep";

    /// The value the tests store, and the string no output may carry.
    const VALUE: &str = "sk-ant-not-in-any-output";

    /// The `secret set` arguments `min <args>` parses to, so a refusal is the
    /// command's and not clap's.
    fn parse_set(args: &[&str]) -> SecretSetArgs {
        use clap::Parser as _;
        match crate::Cli::try_parse_from(args)
            .expect("the arguments parse")
            .command
        {
            Some(crate::Command::Secret(crate::SecretArgs {
                command: SecretCommand::Set(args),
            })) => args,
            _ => panic!("expected `secret set` for {args:?}"),
        }
    }

    /// A store holding `VALUE` under `anthropic-api-key`, with the proxy's
    /// access entry on the item.
    fn stored() -> MemorySecrets {
        let store = MemorySecrets::new();
        store
            .set(
                "anthropic-api-key",
                &Secret::new(VALUE),
                &ItemAcl::for_proxy(Path::new(PROXY)),
            )
            .expect("the store holds the value");
        store
    }

    /// The rule the operator registers for `anthropic-api-key`.
    fn rule() -> StoreRule {
        StoreRule {
            store: SecretStore::Keychain,
            id: "anthropic-api-key".to_owned(),
            upstream: vec!["api.anthropic.com:443".to_owned()],
            inject: Injection::Header {
                name: "x-api-key".to_owned(),
                prefix: String::new(),
            },
            action: RuleAction::Ask,
        }
    }

    /// A value piped to `min secret set` lands in the store under the
    /// identifier, and the command prints the identifier and no value
    /// (BEP-050).
    #[test]
    fn secret_set_stores_in_keychain_and_prints_id_only() {
        let store = MemorySecrets::new();
        let mut piped = std::io::Cursor::new(format!("{VALUE}\n").into_bytes());
        let mut out = Vec::new();
        set(
            &store,
            Path::new(PROXY),
            &parse_set(&["min", "secret", "set", "anthropic-api-key"]),
            Source::Stdin(&mut piped),
            &mut out,
        )
        .expect("the value is stored");

        let held = store
            .read("anthropic-api-key")
            .expect("the store can be read")
            .expect("the item is held");
        assert_eq!(held.expose(), VALUE);
        let printed = String::from_utf8(out).expect("the output is UTF-8");
        assert!(
            printed.contains("anthropic-api-key"),
            "the identifier is printed: {printed}"
        );
        assert!(
            !printed.contains(VALUE),
            "no output carries the value: {printed}"
        );
    }

    /// A value on the command line, or named in an environment variable, is
    /// refused naming the terminal and standard input as the accepted sources
    /// — and nothing is stored (BEP-050).
    #[test]
    fn secret_set_refuses_value_argument_and_env_flag() {
        for args in [
            ["min", "secret", "set", "anthropic-api-key", "sk-on-the-cli"].as_slice(),
            [
                "min",
                "secret",
                "set",
                "anthropic-api-key",
                "--value",
                "sk-on-the-cli",
            ]
            .as_slice(),
            [
                "min",
                "secret",
                "set",
                "anthropic-api-key",
                "--from-env",
                "ANTHROPIC_API_KEY",
            ]
            .as_slice(),
        ] {
            let store = MemorySecrets::new();
            let mut piped = std::io::Cursor::new(format!("{VALUE}\n").into_bytes());
            let mut out = Vec::new();
            let error = set(
                &store,
                Path::new(PROXY),
                &parse_set(args),
                Source::Stdin(&mut piped),
                &mut out,
            )
            .expect_err("the command is refused")
            .to_string();

            assert!(
                error.contains("terminal") && error.contains("standard input"),
                "the refusal names both accepted sources: {error}"
            );
            assert!(
                store.items().expect("the store can be listed").is_empty(),
                "a refused set stores nothing"
            );
            assert!(out.is_empty(), "a refused set prints nothing on stdout");
        }
    }

    /// With no terminal to ask at and nothing on standard input, the command
    /// fails instead of waiting for a value (BEP-050).
    #[test]
    fn secret_set_without_tty_or_stdin_fails_immediately() {
        let store = MemorySecrets::new();
        let mut empty = std::io::Cursor::new(Vec::new());
        let error = set(
            &store,
            Path::new(PROXY),
            &parse_set(&["min", "secret", "set", "anthropic-api-key"]),
            Source::Stdin(&mut empty),
            &mut Vec::new(),
        )
        .expect_err("the command fails")
        .to_string();

        assert!(
            error.contains("terminal") && error.contains("standard input"),
            "the failure names the sources it has neither of: {error}"
        );
        assert!(store.items().expect("the store can be listed").is_empty());
    }

    /// `--store gatehouse` is refused naming the tenant-store deposit as
    /// outside this host's scope, and stores nothing (BEP-050).
    #[test]
    fn secret_set_refuses_gatehouse_store() {
        let store = MemorySecrets::new();
        let mut piped = std::io::Cursor::new(format!("{VALUE}\n").into_bytes());
        let error = set(
            &store,
            Path::new(PROXY),
            &parse_set(&[
                "min",
                "secret",
                "set",
                "anthropic-api-key",
                "--store",
                "gatehouse",
            ]),
            Source::Stdin(&mut piped),
            &mut Vec::new(),
        )
        .expect_err("the command is refused")
        .to_string();

        assert!(
            error.contains("gatehouse") && error.contains("tenant"),
            "the refusal names the tenant-store deposit: {error}"
        );
        assert!(store.items().expect("the store can be listed").is_empty());
    }

    /// The item `min secret set` stores carries an access control admitting
    /// the proxy's process identity without a prompt, and nothing else
    /// (BEP-051).
    #[test]
    fn secret_item_acl_admits_proxy_only() {
        let store = MemorySecrets::new();
        let mut piped = std::io::Cursor::new(format!("{VALUE}\n").into_bytes());
        set(
            &store,
            Path::new(PROXY),
            &parse_set(&["min", "secret", "set", "anthropic-api-key"]),
            Source::Stdin(&mut piped),
            &mut Vec::new(),
        )
        .expect("the value is stored");

        let acl = store
            .acl("anthropic-api-key")
            .expect("the item carries an access control");
        assert_eq!(acl.trusted(), [Path::new(PROXY).to_path_buf()]);
        assert!(acl.admits(Path::new(PROXY)));
        assert!(acl.prompts(Path::new("/Applications/Editor.app")));
        assert!(
            store
                .items()
                .expect("the store can be listed")
                .iter()
                .all(|item| item.proxy_access),
            "the entry created for the proxy is set on the item"
        );
    }

    /// `min secret list` shows each item's store, the authorities and the
    /// injection form its rule registers, the consent rule and the state of
    /// the proxy's access entry — and no value (BEP-052).
    #[test]
    fn secret_list_shows_metadata_without_values() {
        let store = stored();
        store
            .set(
                "unregistered-token",
                &Secret::new(VALUE),
                &ItemAcl::for_proxy(Path::new(PROXY)),
            )
            .expect("the store holds the value");
        let mut out = Vec::new();
        list(&store, SecretStore::Keychain, &[rule()], &mut out).expect("the store is listed");
        let printed = String::from_utf8(out).expect("the output is UTF-8");

        let registered = printed
            .lines()
            .find(|line| line.contains("anthropic-api-key"))
            .expect("the registered item is listed");
        assert!(registered.contains("keychain"), "{registered}");
        assert!(registered.contains("api.anthropic.com:443"), "{registered}");
        assert!(registered.contains("header `x-api-key`"), "{registered}");
        assert!(registered.contains("consent ask"), "{registered}");
        assert!(registered.contains("proxy access set"), "{registered}");

        let unregistered = printed
            .lines()
            .find(|line| line.contains("unregistered-token"))
            .expect("an item no rule registers is listed too");
        assert!(unregistered.contains("authorities none"), "{unregistered}");
        assert!(unregistered.contains("consent none"), "{unregistered}");

        assert!(
            !printed.contains(VALUE),
            "the listing carries no value: {printed}"
        );
    }

    /// `min secret rm` takes the item out of the store (BEP-053).
    #[test]
    fn secret_rm_removes_item() {
        let store = stored();
        let mut out = Vec::new();
        rm(
            &store,
            SecretStore::Keychain,
            &SecretRmArgs {
                id: "anthropic-api-key".to_owned(),
                store: None,
            },
            &mut out,
        )
        .expect("the item is removed");

        assert!(
            store.items().expect("the store can be listed").is_empty(),
            "the store holds nothing once the item is removed"
        );
        assert!(
            store
                .read("anthropic-api-key")
                .expect("the store can be read")
                .is_none()
        );
        let printed = String::from_utf8(out).expect("the output is UTF-8");
        assert!(printed.contains("anthropic-api-key"), "{printed}");

        let error = rm(
            &store,
            SecretStore::Keychain,
            &SecretRmArgs {
                id: "anthropic-api-key".to_owned(),
                store: None,
            },
            &mut Vec::new(),
        )
        .expect_err("removing what the store does not hold is an error")
        .to_string();
        assert!(error.contains("anthropic-api-key"), "{error}");
    }
}
