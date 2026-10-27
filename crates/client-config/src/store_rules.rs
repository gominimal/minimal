//! The client's `[secret-store-rules]`: each rule, the deny set it is checked
//! against (BEP-034), and the consent its action asks for (BEP-035).
//!
//! `min` mints under these rules and `bep serve` redeems under them, so both
//! read them through this crate.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// The injection headers no rule can name (BEP-034), lower case. A header
/// that starts with `proxy-` is refused too.
pub const DENIED_HEADERS: [&str; 6] = [
    "host",
    ":authority",
    "cookie",
    "transfer-encoding",
    "connection",
    "upgrade",
];

/// The consent a store rule asks for before a reference is redeemed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreAction {
    /// The reference is redeemed with no question.
    Allow,
    /// The client asks the person at the terminal.
    Ask,
    /// The reference is never redeemed.
    Deny,
}

/// One `[secret-store-rules.<id>]` rule. The table key is the item's
/// identifier in its store, and it is the name a message uses for the rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreRuleConfig {
    /// The store that holds the item. `None` is the host's native store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<String>,
    /// The upstream authorities the rule registers, each `host` or
    /// `host:port`.
    pub upstream: Vec<String>,
    /// The header the value goes in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    /// The text before the value in [`Self::header`], such as `Bearer `.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// The basic authentication field the value fills: `user` or
    /// `password`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basic_auth: Option<String>,
    /// The consent the rule asks for. `None` asks for none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<StoreAction>,
}

impl StoreRuleConfig {
    /// The host part of each upstream authority, normalised.
    pub fn upstream_hosts(&self) -> impl Iterator<Item = String> + '_ {
        self.upstream
            .iter()
            .map(|authority| authority_host(authority))
    }
}

/// The `[secret-store-rules]` table: rules by item identifier.
pub type StoreRules = BTreeMap<String, StoreRuleConfig>;

/// What a store rule can never name. The caller supplies the parts this
/// crate does not own.
#[derive(Debug, Clone, Copy)]
pub struct StoreDenySet<'a> {
    /// The hosts of every configured deep module, such as the GitHub set.
    pub module_hosts: &'a [&'a str],
    /// The domains of Minimal's own infrastructure: the infrastructure deny
    /// set. A rule's upstream can name neither a domain here nor a name
    /// under it. The caller passes `bep::ca::DENY_SET`, the one definition
    /// of the set, so one list feeds the root's name constraints and this
    /// check.
    pub infrastructure: &'a [&'a str],
    /// The identifiers of the GitHub sign-in item, which only the GitHub
    /// module can use.
    pub sign_in_items: &'a [&'a str],
}

impl StoreDenySet<'_> {
    /// Whether `id` names an item that holds the GitHub sign-in.
    #[must_use]
    pub fn is_sign_in_item(&self, id: &str) -> bool {
        self.sign_in_items
            .iter()
            .any(|item| item.eq_ignore_ascii_case(id))
    }
}

/// Why a store rule was refused when the configuration was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreRuleRefusal {
    /// BEP-034: an upstream is a deep module's host or a name under it.
    ModuleHost {
        /// The host, as the rule writes it.
        host: String,
    },
    /// BEP-034: an upstream is Minimal's own infrastructure.
    MinimalInfrastructure {
        /// The host, as the rule writes it.
        host: String,
        /// The deny-set entry the host is or is under, such as
        /// `minimal.dev`.
        entry: String,
    },
    /// BEP-034: the injection header is in the deny set.
    DeniedHeader {
        /// The header, as the rule writes it.
        header: String,
    },
    /// BEP-034: the rule names the GitHub sign-in item.
    SignInItem,
    /// BEP-034: a field is not in the shape the deny set can judge: an
    /// upstream that is not a plain `host` or `host:port`, a header that is
    /// not an HTTP token, a prefix with a control character, or a
    /// `basic_auth` other than `user` or `password`.
    Malformed {
        /// The field: `upstream`, `header`, `prefix` or `basic_auth`.
        field: &'static str,
        /// The value, as the rule writes it.
        value: String,
    },
    /// The rule registers no upstream, or not exactly one injection form.
    Incomplete,
}

/// A store rule refused when the configuration was read. The rule is left
/// out of the rules the caller uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreRuleRefused {
    /// The rule's name: its item identifier.
    pub rule: String,
    /// The configuration file that holds the rule.
    pub file: String,
    /// Why it was refused.
    pub reason: StoreRuleRefusal,
}

impl StoreRuleRefused {
    /// The requirement the refusal enforces, for the log line only.
    #[must_use]
    pub fn requirement(&self) -> &'static str {
        match self.reason {
            StoreRuleRefusal::Incomplete => "BEP-079",
            _ => "BEP-034",
        }
    }
}

impl fmt::Display for StoreRuleRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { rule, file, reason } = self;
        let named = match reason {
            StoreRuleRefusal::MinimalInfrastructure { host, entry }
                if authority_host(host) != normalize_host(entry) =>
            {
                return write!(
                    f,
                    "The secret-store rule {rule} in {file} names {host}, which is under \
                     {entry}. A secret can never be sent to {entry} or a name under it. Remove \
                     or change the rule."
                );
            }
            StoreRuleRefusal::ModuleHost { host }
            | StoreRuleRefusal::MinimalInfrastructure { host, .. } => host.clone(),
            StoreRuleRefusal::DeniedHeader { header } => format!("the header {header}"),
            StoreRuleRefusal::SignInItem => {
                return write!(
                    f,
                    "The secret-store rule {rule} in {file} names the item that holds your \
                     GitHub sign-in. Only GitHub grants can use that item. Remove or rename \
                     the rule."
                );
            }
            StoreRuleRefusal::Malformed { field, value } => {
                let shape = match *field {
                    "upstream" => "a host name or host:port",
                    "header" => "an HTTP header name",
                    "basic_auth" => "user or password",
                    _ => "text without control characters",
                };
                return write!(
                    f,
                    "The secret-store rule {rule} in {file} has the {field} {value:?}, which is \
                     not {shape}. Change the rule."
                );
            }
            StoreRuleRefusal::Incomplete => {
                return write!(
                    f,
                    "The secret-store rule {rule} in {file} needs at least one upstream, and \
                     either a header or basic_auth, but not both. Change the rule."
                );
            }
        };
        // The task fixes this wording.
        write!(
            f,
            "The secret-store rule {rule} in {file} names {named}, which a secret can never \
             be sent to. Remove or change the rule."
        )
    }
}

/// The first reason to refuse `rule`, or `None` when it passes.
fn store_rule_refusal(
    id: &str,
    rule: &StoreRuleConfig,
    deny: StoreDenySet<'_>,
) -> Option<StoreRuleRefusal> {
    if deny.is_sign_in_item(id) {
        return Some(StoreRuleRefusal::SignInItem);
    }
    for (written, host) in rule.upstream.iter().zip(rule.upstream_hosts()) {
        if !is_plain_authority(written) {
            return Some(StoreRuleRefusal::Malformed {
                field: "upstream",
                value: written.clone(),
            });
        }
        if deny.module_hosts.iter().any(|m| is_within(&host, m)) {
            return Some(StoreRuleRefusal::ModuleHost {
                host: written.clone(),
            });
        }
        if let Some(entry) = deny
            .infrastructure
            .iter()
            .find(|domain| is_within(&host, domain))
        {
            return Some(StoreRuleRefusal::MinimalInfrastructure {
                host: written.clone(),
                entry: (*entry).to_owned(),
            });
        }
    }
    if let Some(header) = &rule.header {
        let lower = header.trim().to_ascii_lowercase();
        if DENIED_HEADERS.contains(&lower.as_str()) || lower.starts_with("proxy-") {
            return Some(StoreRuleRefusal::DeniedHeader {
                header: header.clone(),
            });
        }
        if !is_http_token(header) {
            return Some(StoreRuleRefusal::Malformed {
                field: "header",
                value: header.clone(),
            });
        }
    }
    if let Some(prefix) = &rule.prefix {
        // A header value is visible characters, spaces and tabs only.
        if !prefix
            .chars()
            .all(|c| c == ' ' || c == '\t' || c.is_ascii_graphic())
        {
            return Some(StoreRuleRefusal::Malformed {
                field: "prefix",
                value: prefix.clone(),
            });
        }
    }
    if let Some(field) = &rule.basic_auth
        && !matches!(field.as_str(), "user" | "password")
    {
        return Some(StoreRuleRefusal::Malformed {
            field: "basic_auth",
            value: field.clone(),
        });
    }
    let forms = usize::from(rule.header.is_some()) + usize::from(rule.basic_auth.is_some());
    if rule.upstream.is_empty() || forms != 1 || (rule.prefix.is_some() && rule.header.is_none()) {
        return Some(StoreRuleRefusal::Incomplete);
    }
    None
}

/// Splits `rules`, read from `file`, into the rules that pass and the rules
/// refused (BEP-034). Logs one debug line per refused rule, naming the rule
/// and why. The caller prints each refusal for the person.
#[must_use]
pub fn check_store_rules(
    rules: StoreRules,
    file: &str,
    deny: StoreDenySet<'_>,
) -> (StoreRules, Vec<StoreRuleRefused>) {
    let mut accepted = StoreRules::new();
    let mut refused = Vec::new();
    for (id, rule) in rules {
        match store_rule_refusal(&id, &rule, deny) {
            None => {
                accepted.insert(id, rule);
            }
            Some(reason) => {
                let refusal = StoreRuleRefused {
                    rule: id,
                    file: file.to_string(),
                    reason,
                };
                tracing::debug!(
                    rule = %refusal.rule,
                    file,
                    requirement = refusal.requirement(),
                    reason = ?refusal.reason,
                    "secret-store rule refused while reading the configuration"
                );
                refused.push(refusal);
            }
        }
    }
    (accepted, refused)
}

/// What happens to a store reference under its rule's consent action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreConsent {
    /// The reference is redeemed.
    Allow,
    /// The client asks the person at the terminal first.
    Ask,
    /// The reference is denied.
    Deny,
}

/// The consent for a reference that matches `rule`. `tty` says whether the
/// client has a terminal. With no terminal, an `ask` rule denies (BEP-035).
#[must_use]
pub fn store_consent(rule: &StoreRuleConfig, tty: bool) -> StoreConsent {
    match rule.action {
        None | Some(StoreAction::Allow) => StoreConsent::Allow,
        Some(StoreAction::Deny) => StoreConsent::Deny,
        Some(StoreAction::Ask) if tty => StoreConsent::Ask,
        Some(StoreAction::Ask) => {
            tracing::debug!(
                rule = "BEP-035",
                "store reference denied: its rule asks for consent and the client has no terminal"
            );
            StoreConsent::Deny
        }
    }
}

/// The normalised host part of an authority, `host` or `host:port`.
fn authority_host(authority: &str) -> String {
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => authority,
    };
    normalize_host(host)
}

/// Whether `authority` is a plain `host` or `host:port`: a DNS name of
/// non-empty labels of letters, digits and hyphens, and a port from 1 to
/// 65535. Anything else (userinfo, a path, brackets, a wildcard, whitespace,
/// an IP address) can name a host the deny set does not see, so the rule is
/// refused. The deny set compares names, so an IP address is refused too.
fn is_plain_authority(authority: &str) -> bool {
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    let labels: Vec<&str> = host.strip_suffix('.').unwrap_or(host).split('.').collect();
    let host_ok = labels.iter().all(|label| {
        !label.is_empty() && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    }) && !labels.last().is_some_and(|last| is_numeric_label(last));
    let port_ok = port.is_none_or(|p| {
        (1..=5).contains(&p.len())
            && p.chars().all(|c| c.is_ascii_digit())
            && p.parse::<u16>().is_ok_and(|n| n != 0)
    });
    host_ok && port_ok
}

/// Whether `label`, the last label of a host, makes the host an IPv4
/// address as a URL parser reads it: decimal digits, or `0x` and hex digits.
fn is_numeric_label(label: &str) -> bool {
    let lower = label.to_ascii_lowercase();
    match lower.strip_prefix("0x") {
        Some(hex) => hex.chars().all(|c| c.is_ascii_hexdigit()),
        None => lower.chars().all(|c| c.is_ascii_digit()),
    }
}

/// Whether `name` is an HTTP header name: one or more `tchar` (RFC 9110).
fn is_http_token(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c))
}

/// Whether the normalised `host` is `domain` or a name under it.
fn is_within(host: &str, domain: &str) -> bool {
    let domain = normalize_host(domain);
    host == domain || host.ends_with(&format!(".{domain}"))
}

/// The host lower case, with no trailing dot: the form every host
/// comparison uses.
#[must_use]
pub fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}
