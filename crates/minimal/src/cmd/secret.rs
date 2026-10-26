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
use bep::store::{HostStore, NATIVE_STORE, ProxyLookupError, SecretStore, StoreError, valid_id};
use boxes::core::bep::{StoreAction, StoreRuleConfig, StoreRuleRefusal, StoreRules};
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
    /// Standard input is a terminal, and `--no-input` forbids the prompt.
    NoInput,
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

/// The source `set` uses. Review finding 4369552000: with `--no-input`, a
/// terminal on standard input is not a source, and `run_set` refuses it
/// before any prompt. Piped standard input still answers.
fn value_source(no_input: bool, detected: ValueSource) -> ValueSource {
    if no_input && detected == ValueSource::Terminal {
        ValueSource::NoInput
    } else {
        detected
    }
}

/// The proxy binary that the item's access control names.
fn proxy_path() -> anyhow::Result<PathBuf> {
    resolve_proxy(
        std::env::var_os(bep::store::PROXY_BIN_ENV).as_deref(),
        std::env::var_os("PATH").as_deref(),
    )
}

/// The proxy that the running `minvmd` starts, by the shared rule
/// [`bep::store::proxy_binary_on_path`]: the variable's path when it is set
/// and not empty, else `bep` beside the first `minvmd` on `path`.
/// `autospawn` starts `minvmd` with `Command::new("minvmd")`, which finds
/// it on `PATH` in the same way. The `minvmd` that autospawn starts gets
/// this process's environment, so it reads the same variable.
///
/// A relative variable is refused, and `PATH` gives only absolute paths.
/// A path that exists comes back canonical. A path that does not exist
/// comes back as is, and `run_set` refuses it.
///
/// The error text names no command. `set` and `list` each add their own.
pub(crate) fn resolve_proxy(
    env: Option<&std::ffi::OsStr>,
    path: Option<&std::ffi::OsStr>,
) -> anyhow::Result<PathBuf> {
    match bep::store::proxy_binary_on_path(env, path) {
        Ok(proxy) => Ok(proxy),
        Err(ProxyLookupError::RelativeEnv(env)) => bail!(
            "{var} is the relative path {}. \
             Set {var} to the absolute path of the `bep` program, and run the command again.",
            env.display(),
            var = bep::store::PROXY_BIN_ENV
        ),
        Err(ProxyLookupError::NoMinvmd) => bail!(
            "no `minvmd` program is on PATH, \
             and `min secret` looks for the `bep` program beside it. \
             Put `minvmd` on PATH, or set {} to the path of the `bep` program, and run the command again.",
            bep::store::PROXY_BIN_ENV
        ),
    }
}

/// `min secret set`.
pub fn cmd_secret_set(global: &GlobalArgs, args: SecretSetArgs) -> anyhow::Result<()> {
    // The refusals that need no store run first, so a value typed on the
    // command line is refused before anything else happens.
    refuse_set_args(&args)?;
    let source = value_source(global.no_input, detect_source());
    let proxy = set_proxy(&HostStore, proxy_path)?;
    let path = crate::config::user_config_path(global);
    let id = args.id.clone();
    let mut confirm = |change: &str| confirm_rule_change(&id, change);
    run_set_with_rule(
        &HostStore,
        &args,
        &proxy,
        source,
        &mut || read_terminal(&args.id),
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
        Some(RuleTarget {
            path: &path,
            confirm: &mut confirm,
            notice: &mut std::io::stderr(),
        }),
    )
}

/// Show `change` on stderr and ask on the terminal whether to replace the
/// rule for `id`. The answer defaults to no.
fn confirm_rule_change(id: &str, change: &str) -> anyhow::Result<bool> {
    eprintln!("{change}");
    inquire::Confirm::new(&format!("Replace the rule for {id}?"))
        .with_default(false)
        .prompt()
        .context("min secret set did not read the answer from the terminal")
}

/// The proxy path for `set`, after the store check. Review finding
/// 4369647104: a host with no store refuses with the store message, and
/// never sends the person to put `minvmd` on PATH first.
fn set_proxy(
    store: &dyn SecretStore,
    resolve: impl FnOnce() -> anyhow::Result<PathBuf>,
) -> anyhow::Result<PathBuf> {
    store
        .check_available()
        .context("min secret set did not read the value")?;
    resolve().context("min secret set did not read the value")
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
    check_id(SET, &args.id)?;
    check_store(SET, args.store.as_deref())?;
    requested_rule(args)?;
    Ok(())
}

/// A built-in rule for a service that takes a fixed token (BEP-079).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Preset {
    /// The name `--preset` takes.
    pub name: &'static str,
    /// The one upstream authority.
    pub upstream: &'static str,
    /// The header the value goes in.
    pub header: &'static str,
    /// The text before the value, if any.
    pub prefix: Option<&'static str>,
}

/// The presets, by name. The spec fixes each one (BEP-079).
pub(crate) const PRESETS: [Preset; 5] = [
    Preset {
        name: "anthropic",
        upstream: "api.anthropic.com",
        header: "Authorization",
        prefix: Some("Bearer "),
    },
    Preset {
        name: "anthropic-api-key",
        upstream: "api.anthropic.com",
        header: "x-api-key",
        prefix: None,
    },
    Preset {
        name: "cloudflare",
        upstream: "mcp.cloudflare.com",
        header: "Authorization",
        prefix: Some("Bearer "),
    },
    Preset {
        name: "linear",
        upstream: "mcp.linear.app",
        header: "Authorization",
        prefix: Some("Bearer "),
    },
    Preset {
        name: "sentry",
        upstream: "mcp.sentry.dev",
        header: "Authorization",
        prefix: Some("Sentry-Bearer "),
    },
];

/// The rule the flags of `args` ask `set` to write, or `None` when no rule
/// flag is given. No flag sets a consent `action` or a `store`, so the
/// rule carries neither (BEP-079). `plan_rule` keeps those of a current rule.
fn requested_rule(args: &SecretSetArgs) -> anyhow::Result<Option<StoreRuleConfig>> {
    if let Some(name) = &args.preset {
        let Some(preset) = PRESETS.iter().find(|p| p.name == name) else {
            let known: Vec<&str> = PRESETS.iter().map(|p| p.name).collect();
            // The task fixes this wording.
            bail!(
                "There is no preset named {name}. Known presets: {}.",
                known.join(", ")
            );
        };
        return Ok(Some(StoreRuleConfig {
            store: None,
            upstream: vec![preset.upstream.to_owned()],
            header: Some(preset.header.to_owned()),
            prefix: preset.prefix.map(str::to_owned),
            basic_auth: None,
            action: None,
        }));
    }
    if args.upstream.is_empty()
        && args.header.is_none()
        && args.prefix.is_none()
        && args.basic_auth.is_none()
    {
        return Ok(None);
    }
    Ok(Some(StoreRuleConfig {
        store: None,
        upstream: args.upstream.clone(),
        header: args.header.clone(),
        prefix: args.prefix.clone(),
        basic_auth: args.basic_auth.clone(),
        action: None,
    }))
}

/// Refuse `rule` for `id` when the configuration reader would refuse it
/// (BEP-034), naming what it names. Nothing is read or written yet.
fn check_new_rule(id: &str, rule: &StoreRuleConfig, path: &Path) -> anyhow::Result<()> {
    let module_hosts = crate::config::store_module_hosts();
    let deny = crate::config::store_deny_set(&module_hosts);
    let file = path.display().to_string();
    let (_, refused) =
        boxes::core::bep::check_store_rules([(id.to_owned(), rule.clone())].into(), &file, deny);
    let Some(refused) = refused.first() else {
        return Ok(());
    };
    let why = match &refused.reason {
        StoreRuleRefusal::MinimalInfrastructure { host, entry }
            if !host.eq_ignore_ascii_case(entry) =>
        {
            format!(
                "{host} is under {entry}, and a secret can never be sent to {entry} or a name \
                 under it. Run the command again with another --upstream."
            )
        }
        StoreRuleRefusal::ModuleHost { host }
        | StoreRuleRefusal::MinimalInfrastructure { host, .. } => {
            format!(
                "a secret can never be sent to {host}. Run the command again with another --upstream."
            )
        }
        StoreRuleRefusal::DeniedHeader { header } => format!(
            "a secret can never be sent in the header {header}. Run the command again with another --header."
        ),
        StoreRuleRefusal::SignInItem => format!(
            "the name {id} holds your GitHub sign-in, and only GitHub grants can use it. \
             Run the command again with another name."
        ),
        StoreRuleRefusal::Malformed { field, value } => {
            let (flag, shape) = match *field {
                "upstream" => ("--upstream", "a host name or host:port"),
                "header" => ("--header", "an HTTP header name"),
                "basic_auth" => ("--basic-auth", "user or password"),
                _ => ("--prefix", "text without control characters"),
            };
            format!(
                "the {flag} value {value:?} is not {shape}. Run the command again with another {flag}."
            )
        }
        StoreRuleRefusal::Incomplete => "a rule needs at least one --upstream, and either \
             --header or --basic-auth. Run the command again with both."
            .to_owned(),
    };
    bail!("min secret set refused the rule for {id}, and stored nothing: {why}")
}

/// Where `set` writes the rule, and how it asks before it replaces one.
pub(crate) struct RuleTarget<'a> {
    /// The user-level client configuration.
    pub path: &'a Path,
    /// Show the change and ask the person at the terminal. `true` replaces
    /// the rule.
    pub confirm: &'a mut dyn FnMut(&str) -> anyhow::Result<bool>,
    /// Where `--yes` says which rule it replaces and what changes.
    pub notice: &'a mut dyn Write,
}

/// The fields of `rule`, one per line, as the change prompt shows them.
fn rule_lines(rule: &StoreRuleConfig) -> String {
    let consent = match rule.action {
        None => "none",
        Some(StoreAction::Allow) => "allow",
        Some(StoreAction::Ask) => "ask",
        Some(StoreAction::Deny) => "deny",
    };
    format!(
        "  upstream:  {}\n  injection: {}\n  consent:   {consent}",
        rule.upstream.join(", "),
        injection(rule)
    )
}

/// The text that shows the current and the new rule for `id`.
fn rule_change(id: &str, path: &Path, current: &StoreRuleConfig, new: &StoreRuleConfig) -> String {
    format!(
        "{path} has a different secret-store rule for {id}.\nCurrent rule:\n{}\nNew rule:\n{}",
        rule_lines(current),
        rule_lines(new),
        path = path.display(),
    )
}

/// The fields that differ from `current` to `new`, as the `--yes` line
/// names them.
fn rule_diff(current: &StoreRuleConfig, new: &StoreRuleConfig) -> String {
    let mut changes = Vec::new();
    if current.upstream != new.upstream {
        changes.push(format!(
            "upstream {} becomes {}",
            current.upstream.join(", "),
            new.upstream.join(", ")
        ));
    }
    let (from, to) = (injection(current), injection(new));
    if from != to {
        changes.push(format!("injection {from} becomes {to}"));
    }
    changes.join(", and ")
}

/// Decide whether `set` writes a rule for `args.id` to `target`, before
/// the value is read. `None` when the file already holds that rule.
///
/// Review findings 4371881769 and 4371881775: when a rule for the id
/// exists, the new rule keeps its `action` and its `store`, because no
/// flag sets them. A hand-set `deny` or `ask` is never dropped. With
/// `--yes`, one line on `target.notice` names the rule and the change.
fn plan_rule(
    args: &SecretSetArgs,
    mut rule: StoreRuleConfig,
    source: ValueSource,
    target: &mut RuleTarget<'_>,
) -> anyhow::Result<Option<(StoreRuleConfig, Option<String>)>> {
    let id = &args.id;
    check_new_rule(id, &rule, target.path)?;
    let (_, mut rules) = crate::config::read_config_parts(target.path).with_context(|| {
        format!(
            "min secret set stored nothing: it did not read the rules in {}",
            target.path.display()
        )
    })?;
    let Some(current) = rules.remove(id) else {
        return Ok(Some((rule, None)));
    };
    rule.action = current.action;
    rule.store.clone_from(&current.store);
    if current == rule {
        return Ok(None);
    }
    if args.yes {
        let line = format!(
            "min secret set replaces the rule for {id} in {}: {}.",
            target.path.display(),
            rule_diff(&current, &rule)
        );
        return Ok(Some((rule, Some(line))));
    }
    let change = rule_change(id, target.path, &current, &rule);
    if source != ValueSource::Terminal {
        bail!(
            "min secret set stored nothing and changed no rule: \
             it cannot ask you to confirm the new rule.\n{change}\n\
             Run the command again with --yes to replace the rule."
        );
    }
    if !(target.confirm)(&change)? {
        bail!(
            "min secret set stored nothing, and the rule for {id} is unchanged. \
             To keep the rule and store the value, run `min secret set {id}` without rule flags."
        );
    }
    Ok(Some((rule, None)))
}

/// The command names that the refusals print.
const SET: &str = "min secret set";
const LIST: &str = "min secret list";
const RM: &str = "min secret rm";

fn check_id(command: &str, id: &str) -> anyhow::Result<()> {
    if !valid_id(id) {
        return Err(anyhow::Error::new(StoreError::InvalidId(id.to_owned()))
            .context(format!("{command} refused the name")));
    }
    Ok(())
}

/// Refuse every store but the host's native one.
fn check_store(command: &str, store: Option<&str>) -> anyhow::Result<()> {
    match store {
        None | Some(NATIVE_STORE) => Ok(()),
        Some("gatehouse") => bail!(
            "{command} refused --store gatehouse. Secrets for the Gatehouse store are deposited with Gatehouse, not on this host. Run the command without --store to use the host keychain."
        ),
        Some(other) => bail!(
            "{command} does not know the store `{other}`. The one store on this host is `{NATIVE_STORE}`. Run the command without --store to use it."
        ),
    }
}

/// The largest value `set` reads from standard input, in bytes.
pub(crate) const MAX_VALUE_BYTES: usize = 64 * 1024;

/// The value on `stdin`, as bytes, without one trailing line break.
///
/// Review thread 4369746902: the value is bytes, so a value that is not
/// UTF-8 is stored as is. The buffer holds `MAX_VALUE_BYTES` and a line
/// break, and the read stops there, so a large pipe does not fill memory.
/// The buffer has its full size before the read, so it never moves and
/// leaves no copy behind.
fn read_stdin_value(stdin: &mut dyn Read) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut value = Zeroizing::new(vec![0u8; MAX_VALUE_BYTES + 2]);
    let mut len = 0;
    while len < value.len() {
        match stdin.read(&mut value[len..]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                return Err(
                    anyhow::Error::new(e).context("min secret set did not read standard input")
                );
            }
        }
    }
    // A full buffer with more input after it is too long, whatever its end.
    let mut more = len == value.len();
    if more {
        let mut probe = Zeroizing::new([0u8; 1]);
        more = loop {
            match stdin.read(&mut probe[..]) {
                Ok(n) => break n > 0,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    return Err(
                        anyhow::Error::new(e).context("min secret set did not read standard input")
                    );
                }
            }
        };
    }
    // One trailing line break is the end of the input, not part of the
    // value.
    let mut end = len;
    if value[..end].ends_with(b"\n") {
        end -= 1;
        if value[..end].ends_with(b"\r") {
            end -= 1;
        }
    }
    if more || end > MAX_VALUE_BYTES {
        bail!(
            "min secret set stored nothing: the value on standard input is longer than {MAX_VALUE_BYTES} bytes. \
             Give a value of {MAX_VALUE_BYTES} bytes or fewer."
        );
    }
    value.truncate(end);
    Ok(value)
}

/// `set` against `store`, with no rule file: [`run_set_with_rule`] for a
/// command with no rule flag.
#[cfg(test)]
pub(crate) fn run_set(
    store: &dyn SecretStore,
    args: &SecretSetArgs,
    proxy: &Path,
    source: ValueSource,
    terminal: &mut dyn FnMut() -> anyhow::Result<Zeroizing<String>>,
    stdin: &mut dyn Read,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    run_set_with_rule(store, args, proxy, source, terminal, stdin, out, None)
}

/// `set` against `store`: the refusals, then the read, then the write of
/// the rule to `target` and of the item.
///
/// Every check runs before the value is read: the arguments, the store,
/// the proxy program, the rule against the deny set, and the change to a
/// different rule. The rule is written first and the item second. When the
/// store refuses the item, the configuration file is put back, so a failed
/// command leaves both as they were (BEP-079).
///
/// The order is deliberate. `SecretStore` has no call that reads a value
/// back, so an item that is replaced first cannot be put back when the rule
/// write fails. The rule file can be put back, so it goes first.
///
/// Review finding 4374026712: this leaves one window. If the process is
/// killed after the rule write and before `store.set` returns, no restore
/// runs. The old item then stays under the new rule until the next `set`
/// or `rm`. The window is the duration of one store call. The command
/// prints no identifier in that case, and exits non-zero or not at all.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_set_with_rule(
    store: &dyn SecretStore,
    args: &SecretSetArgs,
    proxy: &Path,
    source: ValueSource,
    terminal: &mut dyn FnMut() -> anyhow::Result<Zeroizing<String>>,
    stdin: &mut dyn Read,
    out: &mut dyn Write,
    mut target: Option<RuleTarget<'_>>,
) -> anyhow::Result<()> {
    refuse_set_args(args)?;
    let rule = requested_rule(args)?;
    // Review finding 4369348711: the store and the proxy path are checked
    // before the value is read, so nobody types a secret that is refused.
    store
        .check_available()
        .context("min secret set did not read the value")?;
    if !proxy.is_absolute() || !proxy.is_file() {
        bail!(
            "min secret set did not read the value: the Box Egress Proxy program is not at {}. \
             Only that program can read the stored secret without a prompt. \
             Set {} to the path of the `bep` program, and run the command again.",
            proxy.display(),
            bep::store::PROXY_BIN_ENV
        );
    }
    // Review finding 4369438785: the access control trusts this program, so
    // nobody but the current user or root can change it.
    bep::store::check_proxy_binary(proxy).context("min secret set did not read the value")?;
    // BEP-079: the rule is checked, and any change confirmed, before the
    // value is read.
    let mut write = match (rule, target.as_mut()) {
        (None, _) => None,
        (Some(rule), Some(target)) => match plan_rule(args, rule, source, target)? {
            None => None,
            Some((rule, line)) => Some((target.path, rule, line, &mut *target.notice)),
        },
        (Some(_), None) => bail!("min secret set has no configuration file to write the rule to"),
    };
    let value = match source {
        ValueSource::Absent => bail!(
            "min secret set has no value to store: there is no terminal, and standard input is empty. \
             Pipe the value in, as in `printf %s \"$VALUE\" | min secret set {}`.",
            args.id
        ),
        ValueSource::NoInput => bail!(
            "min secret set did not prompt for the value: --no-input is set. \
             Pipe the value in on standard input, as in `printf %s \"$VALUE\" | min secret set {}`.",
            args.id
        ),
        ValueSource::Terminal => {
            let mut typed = terminal()?;
            Zeroizing::new(std::mem::take(&mut *typed).into_bytes())
        }
        ValueSource::Stdin => read_stdin_value(stdin)?,
    };
    if value.is_empty() {
        bail!(
            "min secret set stored nothing: the value is empty. Run the command again and give a value."
        );
    }
    let snapshot = match &mut write {
        None => None,
        Some((path, rule, line, notice)) => {
            if let Some(line) = line {
                writeln!(notice, "{line}")?;
            }
            let snapshot =
                crate::config::write_store_rule(path, &args.id, rule).with_context(|| {
                    format!(
                        "min secret set stored nothing: it did not write the rule for {} to {}",
                        args.id,
                        path.display()
                    )
                })?;
            tracing::info!(
                id = %args.id,
                upstream = %rule.upstream.join(", "),
                file = %path.display(),
                "secret-store rule written"
            );
            Some((*path, snapshot))
        }
    };
    if let Err(e) = store.set(&args.id, &value, proxy) {
        // The new value is stored, so "did not store" is not true, and the
        // rule stays with it.
        if matches!(e, StoreError::StagingLeft { .. }) {
            return Err(anyhow::Error::new(e));
        }
        let mut message = format!("min secret set did not store {}", args.id);
        if let Some((path, snapshot)) = &snapshot {
            match crate::config::restore_config(snapshot) {
                Ok(()) => {
                    tracing::info!(id = %args.id, file = %path.display(), "secret-store rule restored");
                    message.push_str(&format!(
                        ". The rule for {} in {} is back as it was",
                        args.id,
                        path.display()
                    ));
                }
                Err(restore) => {
                    tracing::warn!(id = %args.id, error = %restore, "secret-store rule not restored");
                    message.push_str(&format!(
                        ". The rule for {id} in {path} was not put back: {restore:#}. \
                         Check [secret-store-rules.{id}] in {path}",
                        id = args.id,
                        path = path.display()
                    ));
                }
            }
        }
        return Err(anyhow::Error::new(e).context(message));
    }
    tracing::info!(store = store.name(), id = %args.id, "secret stored");
    writeln!(out, "{}", args.id)?;
    Ok(())
}

/// `min secret list`.
pub fn cmd_secret_list(global: &GlobalArgs, args: SecretListArgs) -> anyhow::Result<()> {
    check_store(LIST, args.store.as_deref())?;
    let (_, rules) = crate::config::read_client_config_and_store_rules(global)?;
    // Review finding 4369551998: list only compares the proxy path, so a
    // proxy that cannot be resolved does not stop the listing.
    let proxy = proxy_path();
    run_list(
        &HostStore,
        &rules,
        proxy.as_deref(),
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
    proxy: Result<&Path, &anyhow::Error>,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    // With no proxy path, the access entries are not compared, and the
    // access column shows unknown.
    let items = store
        .list(proxy.unwrap_or(Path::new("")))
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
        let access = match proxy {
            Err(_) => "unknown".to_owned(),
            Ok(proxy) if item.proxy_access => format!("yes, {}", proxy.display()),
            Ok(_) => "no".to_owned(),
        };
        writeln!(out, "{}", item.id)?;
        writeln!(out, "  store:                 {}", store.name())?;
        writeln!(out, "  upstream:              {upstream}")?;
        writeln!(out, "  injection:             {injection}")?;
        writeln!(out, "  consent:               {consent}")?;
        writeln!(out, "  proxy reads it freely: {access}")?;
    }
    if let Err(e) = proxy {
        writeln!(out)?;
        writeln!(out, "min secret list shows proxy access as unknown: {e:#}")?;
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
    check_id(RM, &args.id)?;
    check_store(RM, args.store.as_deref())?;
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

    fn set_from_bytes(
        store: &MemorySecretStore,
        proxy: &Path,
        input: &[u8],
    ) -> (anyhow::Result<()>, String) {
        let mut out = Vec::new();
        let mut input = input;
        let result = run_set(
            store,
            &set_args(&["claude"]),
            proxy,
            ValueSource::Stdin,
            &mut no_terminal,
            &mut input,
            &mut out,
        );
        (result, String::from_utf8(out).unwrap())
    }

    // Review thread 4369746902: a value that is not UTF-8 is stored as is,
    // without its one trailing line break.
    #[test]
    fn secret_set_stores_binary_stdin_value() {
        let (_dir, proxy) = proxy();
        let store = MemorySecretStore::default();
        for (input, stored) in [
            (&b"\xff\x00\xfe\n"[..], &b"\xff\x00\xfe"[..]),
            (&b"\xff\xfe\r\n"[..], &b"\xff\xfe"[..]),
            (&b"\xff\n\n"[..], &b"\xff\n"[..]),
        ] {
            let (result, out) = set_from_bytes(&store, &proxy, input);
            result.unwrap();
            assert_eq!(out, "claude\n");
            assert_eq!(store.value("claude").as_deref(), Some(stored));
        }
    }

    // Review thread 4369746902: standard input is read up to a limit, and a
    // longer value is refused with a message that names the limit.
    #[test]
    fn secret_set_refuses_value_over_size_limit() {
        let (_dir, proxy) = proxy();
        let store = MemorySecretStore::default();

        // The limit itself, with or without a line break, is stored.
        for tail in [&b""[..], b"\n", b"\r\n"] {
            let mut input = vec![b'a'; MAX_VALUE_BYTES];
            input.extend_from_slice(tail);
            let (result, _) = set_from_bytes(&store, &proxy, &input);
            result.unwrap();
            assert_eq!(
                store.value("claude").map(|v| v.len()),
                Some(MAX_VALUE_BYTES)
            );
        }

        let store = MemorySecretStore::default();
        for len in [
            MAX_VALUE_BYTES + 1,
            MAX_VALUE_BYTES + 2,
            MAX_VALUE_BYTES * 4,
        ] {
            let mut input = vec![b'a'; len];
            input.push(b'\n');
            let (result, out) = set_from_bytes(&store, &proxy, &input);
            let err = format!("{:#}", result.expect_err("refused"));
            assert!(
                err.contains(&format!("longer than {MAX_VALUE_BYTES} bytes")),
                "{err}"
            );
            assert!(out.is_empty());
            assert_eq!(store.value("claude"), None);
        }
        // A value that fills the buffer with a line break and continues after
        // it is too long as well.
        let mut input = vec![b'a'; MAX_VALUE_BYTES];
        input.extend_from_slice(b"\r\nb");
        let (result, _) = set_from_bytes(&store, &proxy, &input);
        assert!(result.is_err());
        assert_eq!(store.value("claude"), None);
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

        // Review finding 4369552000: --no-input with a terminal on standard
        // input refuses at once, reads nothing, and names piped input.
        assert_eq!(
            value_source(true, ValueSource::Terminal),
            ValueSource::NoInput
        );
        assert_eq!(value_source(true, ValueSource::Stdin), ValueSource::Stdin);
        assert_eq!(value_source(true, ValueSource::Absent), ValueSource::Absent);
        assert_eq!(
            value_source(false, ValueSource::Terminal),
            ValueSource::Terminal
        );
        let mut out = Vec::new();
        let err = run_set(
            &store,
            &set_args(&["claude"]),
            &proxy,
            ValueSource::NoInput,
            &mut no_terminal,
            &mut PanicRead,
            &mut out,
        )
        .expect_err("no prompt");
        let text = format!("{err:#}");
        assert!(text.starts_with("min secret set did not prompt"), "{text}");
        assert!(text.contains("--no-input"), "{text}");
        assert!(text.contains("| min secret set claude"), "{text}");
        assert!(out.is_empty());
        assert!(store.value("claude").is_none());
    }

    /// A store that this host cannot use, as [`HostStore`] is off macOS.
    struct NoStore;
    impl SecretStore for NoStore {
        fn name(&self) -> &'static str {
            NATIVE_STORE
        }
        fn set(&self, _: &str, _: &[u8], _: &Path) -> Result<(), StoreError> {
            panic!("set was called")
        }
        fn list(&self, _: &Path) -> Result<Vec<bep::store::ItemInfo>, StoreError> {
            Err(StoreError::Unsupported)
        }
        fn remove(&self, _: &str) -> Result<bool, StoreError> {
            Err(StoreError::Unsupported)
        }
        fn check_available(&self) -> Result<(), StoreError> {
            Err(StoreError::Unsupported)
        }
    }

    // Review finding 4369348711: no value is read when the store is not
    // there, from the terminal or from standard input.
    #[test]
    fn secret_set_checks_the_store_before_it_reads() {
        let (_dir, proxy) = proxy();
        for source in [ValueSource::Terminal, ValueSource::Stdin] {
            let mut out = Vec::new();
            let err = run_set(
                &NoStore,
                &set_args(&["claude"]),
                &proxy,
                source,
                &mut no_terminal,
                &mut PanicRead,
                &mut out,
            )
            .expect_err("refused");
            let text = format!("{err:#}");
            assert!(text.contains("did not read the value"), "{text}");
            assert!(text.contains("no secret store"), "{text}");
            assert!(out.is_empty());
        }

        // Review finding 4369647104: the store check runs before the proxy
        // path is resolved, so no `minvmd` on PATH gives the store message.
        let resolved = std::cell::Cell::new(false);
        let text = format!(
            "{:#}",
            set_proxy(&NoStore, || {
                resolved.set(true);
                resolve_proxy(None, None)
            })
            .expect_err("refused")
        );
        assert!(!resolved.get(), "the proxy path was resolved first");
        assert!(text.contains("no secret store"), "{text}");
        assert!(!text.contains("minvmd"), "{text}");
        let store = MemorySecretStore::default();
        let text = format!(
            "{:#}",
            set_proxy(&store, || resolve_proxy(None, None)).expect_err("refused")
        );
        assert!(text.contains("no `minvmd` program is on PATH"), "{text}");
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
        assert!(text.starts_with("min secret set refused"), "{text}");
        assert!(store.value("claude").is_none());
        let mut out = Vec::new();
        let rm = SecretRmArgs {
            id: "claude".into(),
            store: Some("gatehouse".into()),
        };
        let text = format!("{:#}", run_rm(&store, &rm, &mut out).expect_err("refused"));
        assert!(text.starts_with("min secret rm refused"), "{text}");
        let text = format!(
            "{:#}",
            check_store(LIST, Some("gatehouse")).expect_err("refused")
        );
        assert!(text.starts_with("min secret list refused"), "{text}");
        let text = format!("{:#}", check_id(RM, "-A").expect_err("refused"));
        assert!(text.starts_with("min secret rm refused the name"), "{text}");
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
        run_list(&store, &rules, Ok(&proxy), &mut out).unwrap();
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
        run_list(&MemorySecretStore::default(), &rules, Ok(&proxy), &mut out).unwrap();
        assert_eq!(out, b"No secrets in the keychain store.\n");

        // Review finding 4369551998: with no proxy path, the listing still
        // shows every item, with access unknown and one line that says why.
        let none = tempfile::tempdir().unwrap();
        let empty = std::env::join_paths([none.path()]).unwrap();
        let missing = resolve_proxy(None, Some(&empty)).expect_err("no minvmd");
        let mut out = Vec::new();
        run_list(&store, &rules, Err(&missing), &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        for value in ["sk-ant-one", "lin-two", "sen-three"] {
            assert!(!out.contains(value), "{out}");
        }
        assert_eq!(
            out.matches("proxy reads it freely: unknown\n").count(),
            3,
            "{out}"
        );
        let last = out.lines().last().unwrap();
        assert!(
            last.starts_with(
                "min secret list shows proxy access as unknown: no `minvmd` program is on PATH"
            ),
            "{out}"
        );
        assert!(!out.contains("min secret set"), "{out}");
        assert!(!out.contains("did not read the value"), "{out}");
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
keychain: \"/Library/Keychains/System.keychain\"
class: \"genp\"
attributes:
    \"acct\"<blob>=\"claude\"
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
        // Review finding 4369647108: `claude` is in two keychains, and only
        // the first copy grants the proxy access. The copies merge, in
        // either order. Review thread 4369745218: the copy without the
        // proxy's entry prompts the proxy, so the merged item has no access.
        let items = bep::store::parse_dump(&dump, &proxy);
        let (head, tail) = dump.split_at(dump.find("keychain: \"/Library").unwrap());
        let reordered = format!("{tail}\n{head}");
        assert_eq!(bep::store::parse_dump(&reordered, &proxy), items);
        assert_eq!(
            items,
            vec![
                bep::store::ItemInfo {
                    id: "claude".into(),
                    proxy_access: false
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

        // The path is `bep` beside `minvmd`, or the variable's path.
        let minvmd = || Some(PathBuf::from("/opt/minimal/bin/minvmd"));
        assert_eq!(
            bep::store::proxy_binary_path(None, minvmd),
            Some(PathBuf::from("/opt/minimal/bin/bep"))
        );
        assert_eq!(
            bep::store::proxy_binary_path(Some(std::ffi::OsStr::new("")), minvmd),
            Some(PathBuf::from("/opt/minimal/bin/bep"))
        );
        assert_eq!(
            bep::store::proxy_binary_path(Some(std::ffi::OsStr::new("/x/bep")), minvmd),
            Some(PathBuf::from("/x/bep"))
        );

        // The anchor is the first executable `minvmd` on PATH, the one that
        // autospawn starts, and never the `min` program.
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let none = tempfile::tempdir().unwrap();
        // A `minvmd` that is not executable is not the one `execvp` runs.
        std::fs::write(first.path().join("minvmd"), b"").unwrap();
        for dir in [first.path(), second.path()] {
            let bin = dir.join("minvmd");
            std::fs::write(&bin, b"").unwrap();
            #[cfg(unix)]
            if dir == second.path() {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        let path = std::env::join_paths([none.path(), first.path(), second.path()]).unwrap();
        assert_eq!(
            resolve_proxy(None, Some(&path)).unwrap(),
            second.path().join("bep")
        );
        assert_eq!(
            resolve_proxy(Some(std::ffi::OsStr::new("")), Some(&path)).unwrap(),
            second.path().join("bep")
        );
        assert_eq!(
            resolve_proxy(Some(std::ffi::OsStr::new("/x/bep")), Some(&path)).unwrap(),
            PathBuf::from("/x/bep")
        );
        let exe = std::env::current_exe().unwrap();
        assert_ne!(
            resolve_proxy(None, Some(&path)).unwrap(),
            exe.with_file_name("bep")
        );

        // No `minvmd` on PATH: refused, with the two remedies.
        let empty = std::env::join_paths([none.path()]).unwrap();
        let text = format!(
            "{:#}",
            resolve_proxy(None, Some(&empty)).expect_err("refused")
        );
        assert!(text.contains("no `minvmd` program is on PATH"), "{text}");
        assert!(text.contains(bep::store::PROXY_BIN_ENV), "{text}");
        assert!(resolve_proxy(None, None).is_err());

        // An empty PATH entry is the current directory: skipped, so the
        // `minvmd` after it is the anchor, and alone it finds nothing.
        let after_empty = std::env::join_paths([Path::new(""), second.path()]).unwrap();
        assert_eq!(
            resolve_proxy(None, Some(&after_empty)).unwrap(),
            second.path().join("bep")
        );
        let only_empty = std::ffi::OsString::from("");
        let text = format!(
            "{:#}",
            resolve_proxy(None, Some(&only_empty)).expect_err("refused")
        );
        assert!(text.contains("no `minvmd` program is on PATH"), "{text}");

        // A relative PATH entry that reaches an executable `minvmd` from the
        // current directory is skipped too.
        let cwd = std::env::current_dir().unwrap();
        let mut relative = PathBuf::new();
        for _ in cwd.components().skip(1) {
            relative.push("..");
        }
        relative.push(second.path().strip_prefix("/").unwrap());
        assert!(relative.is_relative());
        assert!(relative.join("minvmd").is_file(), "{}", relative.display());
        let rel_path = std::env::join_paths([relative.as_path()]).unwrap();
        let text = format!(
            "{:#}",
            resolve_proxy(None, Some(&rel_path)).expect_err("refused")
        );
        assert!(text.contains("no `minvmd` program is on PATH"), "{text}");
        let rel_then_abs = std::env::join_paths([relative.as_path(), first.path()]).unwrap();
        std::fs::remove_file(first.path().join("minvmd")).unwrap();
        assert!(resolve_proxy(None, Some(&rel_then_abs)).is_err());

        // A relative MINVMD_BEP_BIN is refused, and names the variable.
        for rel in ["bep", "./bep", "bin/bep"] {
            let text = format!(
                "{:#}",
                resolve_proxy(Some(std::ffi::OsStr::new(rel)), Some(&path)).expect_err("refused")
            );
            assert!(text.contains("is the relative path"), "{text}");
            assert!(text.contains(bep::store::PROXY_BIN_ENV), "{text}");
        }

        // A proxy that exists comes back canonical, through a symbolic link.
        let real = second.path().join("bep");
        std::fs::write(&real, b"").unwrap();
        let canonical = std::fs::canonicalize(&real).unwrap();
        assert_eq!(resolve_proxy(None, Some(&path)).unwrap(), canonical);
        #[cfg(unix)]
        {
            let link = none.path().join("bep-link");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            assert_eq!(
                resolve_proxy(Some(link.as_os_str()), Some(&path)).unwrap(),
                canonical
            );

            // Review finding 4369647106: PATH holds a link to the real
            // `minvmd`, beside another `bep`. The proxy is the `bep` that
            // the daemon's `current_exe()` names: beside the real `minvmd`
            // on Linux, and beside the link on macOS.
            let links = tempfile::tempdir().unwrap();
            std::os::unix::fs::symlink(second.path().join("minvmd"), links.path().join("minvmd"))
                .unwrap();
            std::fs::write(links.path().join("bep"), b"").unwrap();
            let linked = std::env::join_paths([links.path()]).unwrap();
            let expected = if cfg!(target_os = "macos") {
                std::fs::canonicalize(links.path().join("bep")).unwrap()
            } else {
                canonical.clone()
            };
            assert_eq!(resolve_proxy(None, Some(&linked)).unwrap(), expected);
        }

        // `run_set` refuses a relative proxy path, even one that exists.
        let err = run_set(
            &store,
            &set_args(&["claude"]),
            &relative.join("minvmd"),
            ValueSource::Stdin,
            &mut no_terminal,
            &mut PanicRead,
            &mut out,
        )
        .expect_err("refused");
        assert!(format!("{err:#}").contains("did not read the value"));
        assert!(store.value("claude").is_none());
    }

    // ---- BEP-079: the store rule that `set` writes ----

    /// Run `set` with a rule file at `path`. `confirm` answers the change
    /// prompt and records the text it shows.
    fn set_with_rule(
        store: &dyn SecretStore,
        argv: &[&str],
        proxy: &Path,
        source: ValueSource,
        path: &Path,
        confirm: &mut dyn FnMut(&str) -> anyhow::Result<bool>,
    ) -> (anyhow::Result<()>, String) {
        let mut out = Vec::new();
        let result = run_set_with_rule(
            store,
            &set_args(argv),
            proxy,
            source,
            &mut || Ok(Zeroizing::new("typed".to_owned())),
            &mut &b"piped\n"[..],
            &mut out,
            Some(RuleTarget {
                path,
                confirm,
                notice: &mut std::io::sink(),
            }),
        );
        (result, String::from_utf8(out).unwrap())
    }

    fn no_confirm(_: &str) -> anyhow::Result<bool> {
        panic!("the change prompt was shown")
    }

    /// The rules of the client configuration at `path`, as written.
    fn written_rules(path: &Path) -> StoreRules {
        crate::config::read_config_parts(path).expect("parses").1
    }

    fn header_rule(upstream: &str, header: &str, prefix: Option<&str>) -> StoreRuleConfig {
        StoreRuleConfig {
            store: None,
            upstream: vec![upstream.to_owned()],
            header: Some(header.to_owned()),
            prefix: prefix.map(str::to_owned),
            basic_auth: None,
            action: None,
        }
    }

    /// A config.toml with other settings, a hand-set rule for `claude` and a
    /// rule for another item.
    const EXISTING: &str = "# my settings\n\
        [secrets]\nacknowledge_full_breadth_unenrolled = true\n\n\
        [secret-store-rules.claude]\nupstream = [\"api.anthropic.com\"]\nheader = \"x-api-key\"\naction = \"ask\"\n\n\
        [secret-store-rules.other]\nupstream = [\"api.example.com\"]\nbasic_auth = \"password\"\n";

    #[test]
    fn secret_set_writes_user_level_store_rule() {
        let (_dir, proxy) = proxy();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let store = MemorySecretStore::default();

        // A new file, from --upstream and --header with --prefix.
        let (result, out) = set_with_rule(
            &store,
            &[
                "linear-key",
                "--upstream",
                "mcp.linear.app",
                "--header",
                "Authorization",
                "--prefix",
                "Bearer ",
            ],
            &proxy,
            ValueSource::Stdin,
            &path,
            &mut no_confirm,
        );
        result.unwrap();
        assert_eq!(out, "linear-key\n");
        assert_eq!(store.value("linear-key").as_deref(), Some(&b"piped"[..]));
        let rules = written_rules(&path);
        assert_eq!(
            rules.get("linear-key"),
            Some(&header_rule(
                "mcp.linear.app",
                "Authorization",
                Some("Bearer ")
            ))
        );
        // The rule reads back through the reader and passes the deny set.
        let mut refusals = Vec::new();
        let accepted = crate::config::refuse_store_rules(rules, &path, &mut refusals);
        assert!(refusals.is_empty());
        assert!(accepted.contains_key("linear-key"));
        assert!(!std::fs::read_to_string(&path).unwrap().contains("piped"));

        // Basic auth, with two upstreams, into a file with other settings.
        // The hand-set rule for `claude` and the rest of the file stay.
        std::fs::write(&path, EXISTING).unwrap();
        let (result, _) = set_with_rule(
            &store,
            &[
                "basic",
                "--upstream",
                "a.example.com",
                "--upstream",
                "b.example.com:8443",
                "--basic-auth",
                "user",
            ],
            &proxy,
            ValueSource::Stdin,
            &path,
            &mut no_confirm,
        );
        result.unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with(EXISTING), "{text}");
        let rules = written_rules(&path);
        assert_eq!(
            rules.get("basic"),
            Some(&StoreRuleConfig {
                store: None,
                upstream: vec!["a.example.com".into(), "b.example.com:8443".into()],
                header: None,
                prefix: None,
                basic_auth: Some("user".into()),
                action: None,
            })
        );
        assert_eq!(rules.len(), 3);
        let (config, _) = crate::config::read_config_parts(&path).unwrap();
        assert!(config.secrets.acknowledge_full_breadth_unenrolled);

        // The command writes the user-level file in the config dir.
        let global = GlobalArgs {
            config_dir: Some(dir.path().to_path_buf()),
            ..GlobalArgs::default()
        };
        assert_eq!(
            crate::config::user_config_path(&global),
            dir.path().join("minimal").join("config.toml")
        );
    }

    #[test]
    fn secret_set_writes_no_project_or_org_config() {
        let (_dir, proxy) = proxy();
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("minimal.toml"), "[project]\nname = \"p\"\n").unwrap();
        let global = GlobalArgs {
            config_dir: Some(root.path().join("config")),
            ..GlobalArgs::default()
        };
        let path = crate::config::user_config_path(&global);
        assert_ne!(path, Path::new(crate::config::ORGANIZATION_CONFIG_PATH));
        assert!(!path.starts_with(&project));

        /// Every file under `dir`, with its bytes.
        fn files(dir: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
            let mut all = std::collections::BTreeMap::new();
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    all.extend(files(&path));
                } else {
                    all.insert(path.clone(), std::fs::read(&path).unwrap());
                }
            }
            all
        }
        let org = std::fs::read(crate::config::ORGANIZATION_CONFIG_PATH).ok();
        let before = files(root.path());
        let store = MemorySecretStore::default();
        let (result, _) = set_with_rule(
            &store,
            &["claude", "--preset", "anthropic"],
            &proxy,
            ValueSource::Stdin,
            &path,
            &mut no_confirm,
        );
        result.unwrap();
        let mut after = files(root.path());
        let written = after
            .remove(&path)
            .expect("the user config.toml is written");
        assert!(
            String::from_utf8(written)
                .unwrap()
                .contains("[secret-store-rules.claude]")
        );
        assert_eq!(after, before, "only the user config.toml changed");
        assert_eq!(
            std::fs::read(crate::config::ORGANIZATION_CONFIG_PATH).ok(),
            org
        );
    }

    #[test]
    fn secret_set_presets_resolve_to_their_rules() {
        let (_dir, proxy) = proxy();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let store = MemorySecretStore::default();
        let expected = [
            (
                "anthropic",
                "api.anthropic.com",
                "Authorization",
                Some("Bearer "),
            ),
            ("anthropic-api-key", "api.anthropic.com", "x-api-key", None),
            ("linear", "mcp.linear.app", "Authorization", Some("Bearer ")),
            (
                "sentry",
                "mcp.sentry.dev",
                "Authorization",
                Some("Sentry-Bearer "),
            ),
            (
                "cloudflare",
                "mcp.cloudflare.com",
                "Authorization",
                Some("Bearer "),
            ),
        ];
        assert_eq!(PRESETS.len(), expected.len());
        for (name, upstream, header, prefix) in expected {
            let id = format!("key-{name}");
            let (result, _) = set_with_rule(
                &store,
                &[&id, "--preset", name],
                &proxy,
                ValueSource::Stdin,
                &path,
                &mut no_confirm,
            );
            result.unwrap();
            assert_eq!(
                written_rules(&path).get(&id),
                Some(&header_rule(upstream, header, prefix)),
                "{name}"
            );
        }
        // `--preset` takes no other rule flag.
        for flags in [
            &["--header", "x"][..],
            &["--prefix", "x"],
            &["--basic-auth", "user"],
            &["--upstream", "a.example.com"],
        ] {
            let mut argv = vec!["min", "secret", "set", "claude", "--preset", "anthropic"];
            argv.extend_from_slice(flags);
            assert!(crate::Cli::try_parse_from(argv).is_err(), "{flags:?}");
        }
    }

    #[test]
    fn secret_set_unknown_preset_lists_known_ones() {
        let (_dir, proxy) = proxy();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let store = MemorySecretStore::default();
        for source in [ValueSource::Terminal, ValueSource::Stdin] {
            let mut out = Vec::new();
            let err = run_set_with_rule(
                &store,
                &set_args(&["claude", "--preset", "openai"]),
                &proxy,
                source,
                &mut no_terminal,
                &mut PanicRead,
                &mut out,
                Some(RuleTarget {
                    path: &path,
                    confirm: &mut no_confirm,
                    notice: &mut std::io::sink(),
                }),
            )
            .expect_err("refused");
            assert_eq!(
                format!("{err:#}"),
                "There is no preset named openai. Known presets: anthropic, anthropic-api-key, cloudflare, linear, sentry."
            );
            assert!(out.is_empty());
        }
        // The args check that `cmd_secret_set` runs first refuses it too.
        assert!(refuse_set_args(&set_args(&["claude", "--preset", "openai"])).is_err());
        assert!(store.value("claude").is_none());
        assert!(!path.exists());
    }

    #[test]
    fn secret_set_refuses_deny_set_rule_before_reading_value() {
        let (_dir, proxy) = proxy();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, EXISTING).unwrap();
        let store = MemorySecretStore::default();
        for (argv, named) in [
            (
                &[
                    "k",
                    "--upstream",
                    "api.github.com",
                    "--header",
                    "Authorization",
                ][..],
                "api.github.com",
            ),
            (
                &["k", "--upstream", "host.min.internal", "--header", "X-Key"],
                "host.min.internal",
            ),
            (
                &["k", "--upstream", "api.example.com", "--header", "Cookie"],
                "the header Cookie",
            ),
            (
                &[
                    "k",
                    "--upstream",
                    "api.example.com",
                    "--header",
                    "Proxy-Authorization",
                ],
                "the header Proxy-Authorization",
            ),
            (
                &[
                    "k",
                    "--upstream",
                    "https://api.example.com/",
                    "--header",
                    "X-Key",
                ],
                "--upstream value \"https://api.example.com/\"",
            ),
            (
                &[
                    "k",
                    "--upstream",
                    "api.example.com",
                    "--basic-auth",
                    "token",
                ],
                "--basic-auth value \"token\"",
            ),
        ] {
            for source in [ValueSource::Terminal, ValueSource::Stdin] {
                let mut out = Vec::new();
                let err = run_set_with_rule(
                    &store,
                    &set_args(argv),
                    &proxy,
                    source,
                    &mut no_terminal,
                    &mut PanicRead,
                    &mut out,
                    Some(RuleTarget {
                        path: &path,
                        confirm: &mut no_confirm,
                        notice: &mut std::io::sink(),
                    }),
                )
                .expect_err("refused");
                let text = format!("{err:#}");
                assert!(
                    text.starts_with("min secret set refused the rule for k, and stored nothing"),
                    "{text}"
                );
                assert!(text.contains(named), "{named}: {text}");
                assert!(out.is_empty());
            }
        }
        assert!(store.value("k").is_none());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), EXISTING);
    }

    #[test]
    fn secret_set_shows_rule_change_and_asks() {
        let (_dir, proxy) = proxy();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let store = MemorySecretStore::default();

        // Declined: neither the item nor the rule is written.
        std::fs::write(&path, EXISTING).unwrap();
        let mut shown = Vec::new();
        let (result, out) = set_with_rule(
            &store,
            &["claude", "--preset", "anthropic"],
            &proxy,
            ValueSource::Terminal,
            &path,
            &mut |change: &str| {
                shown.push(change.to_owned());
                Ok(false)
            },
        );
        let text = format!("{:#}", result.expect_err("declined"));
        assert!(text.contains("the rule for claude is unchanged"), "{text}");
        assert!(
            text.contains("`min secret set claude` without rule flags"),
            "{text}"
        );
        assert!(out.is_empty());
        assert!(store.value("claude").is_none());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), EXISTING);
        assert_eq!(
            shown,
            [format!(
                "{} has a different secret-store rule for claude.\n\
                 Current rule:\n  upstream:  api.anthropic.com\n  injection: header x-api-key\n  consent:   ask\n\
                 New rule:\n  upstream:  api.anthropic.com\n  injection: header Authorization, prefix \"Bearer \"\n  consent:   ask",
                path.display()
            )]
        );

        // Confirmed: the rule is replaced and the value from the terminal
        // is stored.
        let mut asked = 0;
        let (result, out) = set_with_rule(
            &store,
            &["claude", "--preset", "anthropic"],
            &proxy,
            ValueSource::Terminal,
            &path,
            &mut |_: &str| {
                asked += 1;
                Ok(true)
            },
        );
        result.unwrap();
        assert_eq!(asked, 1);
        assert_eq!(out, "claude\n");
        assert_eq!(store.value("claude").as_deref(), Some(&b"typed"[..]));
        let rules = written_rules(&path);
        // The hand-set `ask` stays (review finding 4371881769).
        assert_eq!(
            rules.get("claude"),
            Some(&StoreRuleConfig {
                action: Some(StoreAction::Ask),
                ..header_rule("api.anthropic.com", "Authorization", Some("Bearer "))
            })
        );
        assert!(rules.contains_key("other"));

        // The same rule again is not a change, so nothing is asked.
        let (result, _) = set_with_rule(
            &store,
            &["claude", "--preset", "anthropic"],
            &proxy,
            ValueSource::Terminal,
            &path,
            &mut no_confirm,
        );
        result.unwrap();
    }

    #[test]
    fn secret_set_rule_change_without_tty_needs_yes() {
        let (_dir, proxy) = proxy();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, EXISTING).unwrap();
        let store = MemorySecretStore::default();
        store
            .set("claude", b"old", &proxy)
            .expect("the old value is stored");
        for source in [
            ValueSource::Stdin,
            ValueSource::Absent,
            ValueSource::NoInput,
        ] {
            let mut out = Vec::new();
            let err = run_set_with_rule(
                &store,
                &set_args(&["claude", "--preset", "anthropic"]),
                &proxy,
                source,
                &mut no_terminal,
                &mut PanicRead,
                &mut out,
                Some(RuleTarget {
                    path: &path,
                    confirm: &mut no_confirm,
                    notice: &mut std::io::sink(),
                }),
            )
            .expect_err("refused");
            let text = format!("{err:#}");
            assert!(
                text.starts_with("min secret set stored nothing and changed no rule"),
                "{text}"
            );
            assert!(text.contains("cannot ask you to confirm"), "{text}");
            assert!(text.contains("Current rule:"), "{text}");
            assert!(text.contains("New rule:"), "{text}");
            assert!(
                text.ends_with("Run the command again with --yes to replace the rule."),
                "{text}"
            );
            assert!(out.is_empty());
        }
        assert_eq!(store.value("claude").as_deref(), Some(&b"old"[..]));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), EXISTING);
    }

    #[test]
    fn secret_set_yes_replaces_rule_without_asking() {
        let (_dir, proxy) = proxy();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let store = MemorySecretStore::default();
        for (source, flag) in [(ValueSource::Stdin, "--yes"), (ValueSource::Terminal, "-y")] {
            std::fs::write(&path, EXISTING).unwrap();
            let (result, out) = set_with_rule(
                &store,
                &["claude", "--preset", "anthropic-api-key", flag],
                &proxy,
                source,
                &path,
                &mut no_confirm,
            );
            result.unwrap();
            assert_eq!(out, "claude\n");
            let rules = written_rules(&path);
            // The hand-set `ask` stays (review finding 4371881769).
            assert_eq!(
                rules.get("claude"),
                Some(&StoreRuleConfig {
                    action: Some(StoreAction::Ask),
                    ..header_rule("api.anthropic.com", "x-api-key", None)
                })
            );
            assert!(rules.contains_key("other"));
        }
        assert_eq!(store.value("claude").as_deref(), Some(&b"typed"[..]));
    }

    /// Review findings 4371881769 and 4371881775: `--yes` with new rule
    /// flags keeps a hand-set `deny` and `store`, and one line names the
    /// rule and what changes.
    #[test]
    fn secret_set_yes_replaces_rule_without_asking_keeps_consent_and_store() {
        let (_dir, proxy) = proxy();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[secret-store-rules.claude]\nstore = \"keychain\"\n\
             upstream = [\"api.anthropic.com\"]\nheader = \"x-api-key\"\naction = \"deny\"\n",
        )
        .unwrap();
        let store = MemorySecretStore::default();
        let mut out = Vec::new();
        let mut notice = Vec::new();
        run_set_with_rule(
            &store,
            &set_args(&[
                "claude",
                "--upstream",
                "api.example.com",
                "--header",
                "Authorization",
                "--prefix",
                "Bearer ",
                "--yes",
            ]),
            &proxy,
            ValueSource::Stdin,
            &mut no_terminal,
            &mut &b"piped\n"[..],
            &mut out,
            Some(RuleTarget {
                path: &path,
                confirm: &mut no_confirm,
                notice: &mut notice,
            }),
        )
        .unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "claude\n");
        assert_eq!(store.value("claude").as_deref(), Some(&b"piped"[..]));
        assert_eq!(
            written_rules(&path).get("claude"),
            Some(&StoreRuleConfig {
                store: Some("keychain".to_owned()),
                action: Some(StoreAction::Deny),
                ..header_rule("api.example.com", "Authorization", Some("Bearer "))
            })
        );
        assert_eq!(
            String::from_utf8(notice).unwrap(),
            format!(
                "min secret set replaces the rule for claude in {}: \
                 upstream api.anthropic.com becomes api.example.com, \
                 and injection header x-api-key becomes header Authorization, prefix \"Bearer \".\n",
                path.display()
            )
        );
    }

    /// A store whose `set` always fails.
    struct RefusingStore;
    impl SecretStore for RefusingStore {
        fn name(&self) -> &'static str {
            NATIVE_STORE
        }
        fn set(&self, _: &str, _: &[u8], _: &Path) -> Result<(), StoreError> {
            Err(StoreError::Refused {
                store: NATIVE_STORE,
                action: "store the item",
                detail: "the keychain is locked".into(),
            })
        }
        fn list(&self, _: &Path) -> Result<Vec<bep::store::ItemInfo>, StoreError> {
            Ok(Vec::new())
        }
        fn remove(&self, _: &str) -> Result<bool, StoreError> {
            Ok(false)
        }
    }

    #[test]
    fn secret_set_partial_failure_restores_both() {
        let (_dir, proxy) = proxy();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        // The item fails after the rule is written: the file is put back,
        // and the error names the item step.
        std::fs::write(&path, EXISTING).unwrap();
        let (result, out) = set_with_rule(
            &RefusingStore,
            &["claude", "--preset", "anthropic", "--yes"],
            &proxy,
            ValueSource::Stdin,
            &path,
            &mut no_confirm,
        );
        let text = format!("{:#}", result.expect_err("store failed"));
        assert!(
            text.starts_with("min secret set did not store claude"),
            "{text}"
        );
        assert!(text.contains("is back as it was"), "{text}");
        assert!(text.contains("the keychain is locked"), "{text}");
        assert!(out.is_empty());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), EXISTING);

        // With no file before, no file after.
        std::fs::remove_file(&path).unwrap();
        let (result, _) = set_with_rule(
            &RefusingStore,
            &["claude", "--preset", "anthropic"],
            &proxy,
            ValueSource::Stdin,
            &path,
            &mut no_confirm,
        );
        assert!(result.is_err());
        assert!(!path.exists());

        // The rule fails: the item keeps its old value, and the error names
        // the rule step. An inline table parses but cannot take a section.
        let inline = "secret-store-rules = {}\n";
        std::fs::write(&path, inline).unwrap();
        let store = MemorySecretStore::default();
        store.set("claude", b"old", &proxy).unwrap();
        let (result, out) = set_with_rule(
            &store,
            &["claude", "--preset", "anthropic"],
            &proxy,
            ValueSource::Stdin,
            &path,
            &mut no_confirm,
        );
        let text = format!("{:#}", result.expect_err("rule failed"));
        assert!(
            text.starts_with("min secret set stored nothing: it did not write the rule for claude"),
            "{text}"
        );
        assert!(text.contains("inline table"), "{text}");
        assert!(out.is_empty());
        assert_eq!(store.value("claude").as_deref(), Some(&b"old"[..]));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), inline);
    }

    #[test]
    fn secret_set_without_rule_flags_leaves_rule_unchanged() {
        let (_dir, proxy) = proxy();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, EXISTING).unwrap();
        let store = MemorySecretStore::default();
        for source in [ValueSource::Stdin, ValueSource::Terminal] {
            let (result, out) =
                set_with_rule(&store, &["claude"], &proxy, source, &path, &mut no_confirm);
            result.unwrap();
            assert_eq!(out, "claude\n");
        }
        assert_eq!(store.value("claude").as_deref(), Some(&b"typed"[..]));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), EXISTING);
        // `--yes` alone is not a rule flag.
        let (result, _) = set_with_rule(
            &store,
            &["claude", "--yes"],
            &proxy,
            ValueSource::Stdin,
            &path,
            &mut no_confirm,
        );
        result.unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), EXISTING);
        // No file is created either.
        let missing = dir.path().join("none").join("config.toml");
        let (result, _) = set_with_rule(
            &store,
            &["claude"],
            &proxy,
            ValueSource::Stdin,
            &missing,
            &mut no_confirm,
        );
        result.unwrap();
        assert!(!missing.exists());
    }
}
