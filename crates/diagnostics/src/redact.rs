//! Key-based redaction of secret-shaped values in structured data.
//!
//! Shared by the CLI-side diagnostic bundler and the daemon-side
//! diagnostic RPC so both apply identical rules, over both formats the
//! producers read (JSON and TOML), plus the process-environment masking
//! both sides use for their `env.json`. Redaction is deliberately
//! conservative: false positives (masking a harmless value) are
//! acceptable, false negatives (leaking a secret) are not.

use std::borrow::Cow;
use std::collections::BTreeMap;

use serde_json_lenient::Value;

/// Key substrings that mark a value as sensitive, matched case-insensitively.
const SENSITIVE_KEY_PARTS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "credential",
    "auth",
    "bearer",
    "private",
    "api_key",
    "apikey",
    "key",
];

/// Table/object names whose *entire* contents are environment-variable style
/// user data and must be masked regardless of key names.
const ENV_TABLE_NAMES: &[&str] = &["vars", "vars_lenient", "env", "environment"];

/// Returns true when a key looks like it names secret material.
///
/// `public_key` is exempt (`public_key`, `wg_public_key` must survive
/// redaction — mesh diagnostics depend on them), but only the `public_key`
/// token itself: a key that pairs it with a sensitive marker
/// (`public_key_token`, `private_public_key`) stays sensitive. Removing the
/// exempt token before the marker scan keeps that fail-closed.
pub fn is_sensitive_key(key: &str) -> bool {
    let stripped = key.to_ascii_lowercase().replace("public_key", "");
    SENSITIVE_KEY_PARTS
        .iter()
        .any(|part| stripped.contains(part))
}

/// Names a project prefix would admit but whose values are reported by name
/// only, by every bundle producer: the telemetry exporter settings
/// (`MINIMAL_OTEL_EXPORTER_OTLP_[TRACES_|LOGS_]ENDPOINT`, `..._HEADERS`, ...).
/// An endpoint URL can carry userinfo or a token in its query, and a headers
/// value is where a collector's `Authorization` or API key goes; neither name
/// looks sensitive to the key-based rule.
pub const ENV_VALUE_DENYLIST_PREFIXES: &[&str] = &["MINIMAL_OTEL_EXPORTER_OTLP_"];

/// Name suffixes whose values are reported by name only, whatever the prefix:
/// an OTLP-style `*_HEADERS` value carries credentials as `key=value` pairs.
pub const ENV_VALUE_DENYLIST_SUFFIXES: &[&str] = &["_HEADERS"];

/// Whether `name` is on the shared deny list ([`ENV_VALUE_DENYLIST_PREFIXES`],
/// [`ENV_VALUE_DENYLIST_SUFFIXES`]): its value never travels, whatever a
/// producer's allowlist says.
#[must_use]
pub fn is_env_value_denylisted(name: &str) -> bool {
    ENV_VALUE_DENYLIST_PREFIXES
        .iter()
        .any(|p| name.starts_with(p))
        || ENV_VALUE_DENYLIST_SUFFIXES
            .iter()
            .any(|s| name.ends_with(s))
}

/// Resolves an env-var name against a caller-supplied allowlist of exact names
/// and name prefixes, fail-closed: a sensitive-shaped name always loses, even
/// when the allowlist admits it (`MINIMALD_TOKEN` matches a project prefix but
/// must never leave the machine), and so does a name on the shared deny list
/// ([`is_env_value_denylisted`]: the telemetry exporter settings).
///
/// The *mechanic* and the deny list are here so every bundle producer, the
/// CLI and the daemon, resolves them the same way; the *data* — which names a
/// given producer considers safe — stays with the caller, per this crate's
/// mechanics-vs-policy split.
#[must_use]
pub fn is_env_value_allowlisted(name: &str, exact: &[&str], prefixes: &[&str]) -> bool {
    !is_sensitive_key(name)
        && !is_env_value_denylisted(name)
        && (exact.contains(&name) || prefixes.iter().any(|p| name.starts_with(p)))
}

/// Returns true when a table/object with this name holds env-var style values
/// that must be masked wholesale.
pub fn is_env_table_name(name: &str) -> bool {
    ENV_TABLE_NAMES.iter().any(|t| name.eq_ignore_ascii_case(t))
}

/// The placeholder a redacted value is replaced with. Records the original
/// (serialized) length so size-related issues stay diagnosable.
pub fn redaction_placeholder(original: &Value) -> Value {
    let len = match original {
        Value::String(s) => s.len(),
        other => other.to_string().len(),
    };
    Value::String(format!("<redacted:len={len}>"))
}

/// Recursively masks sensitive values in `value` in place.
///
/// A leaf is masked when its own key is sensitive per [`is_sensitive_key`],
/// or when any ancestor was named like an env table ([`is_env_table_name`])
/// or like secret material — inside those, every leaf is masked, so a
/// `tokens` object can't smuggle its members out under harmless inner keys.
pub fn redact_json(value: &mut Value) {
    redact_json_inner(value, false);
}

fn redact_json_inner(value: &mut Value, mask_all: bool) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                let child_mask = mask_all || is_env_table_name(key) || is_sensitive_key(key);
                if child.is_object() || child.is_array() {
                    redact_json_inner(child, child_mask);
                } else if child_mask || is_sensitive_key(key) {
                    *child = redaction_placeholder(child);
                }
            }
        }
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| redact_json_inner(item, mask_all)),
        leaf => {
            if mask_all {
                *leaf = redaction_placeholder(leaf);
            }
        }
    }
}

/// Parses `input` as TOML and masks sensitive values: any value whose key is
/// sensitive per [`is_sensitive_key`], and *every* value inside tables named
/// like env-var containers ([`is_env_table_name`]), e.g. a loadout's `[vars]`.
///
/// Returns the re-serialized document. Comments and key ordering are not
/// preserved — callers record that in the bundle manifest. Unparseable input
/// is an error; callers must withhold the file rather than pass it through.
pub fn redact_toml(input: &str) -> Result<String, toml::de::Error> {
    let table: toml::Table = input.parse()?;
    let mut value = toml::Value::Table(table);
    redact_toml_value(&mut value, false);
    let rendered = toml::to_string_pretty(&value).expect("re-serializing a just-parsed TOML value");

    // Parsing back is not paranoia about our own masking — it is that the
    // round trip is not guaranteed to survive. A document of deeply nested
    // inline tables parses at one depth and re-serializes into a form that
    // trips the parser's recursion limit, so `to_string_pretty` succeeds and
    // the output is unreadable. Found by the `redact_roundtrip` fuzz target.
    //
    // Erroring keeps this function's contract consistent: unparseable input is
    // already an error precisely so callers withhold the file rather than pass
    // it through, and a bundle carrying TOML no consumer can read is the same
    // failure one step later. Costs a second parse of a config-sized file on a
    // path that runs when a support bundle is built.
    rendered.parse::<toml::Table>()?;
    Ok(rendered)
}

fn redact_toml_value(value: &mut toml::Value, mask_all: bool) {
    match value {
        toml::Value::Table(table) => {
            for (key, child) in table.iter_mut() {
                let child_mask = mask_all || is_env_table_name(key) || is_sensitive_key(key);
                match child {
                    toml::Value::Table(_) | toml::Value::Array(_) => {
                        redact_toml_value(child, child_mask);
                    }
                    leaf => {
                        if child_mask || is_sensitive_key(key) {
                            *leaf = toml_placeholder(leaf);
                        }
                    }
                }
            }
        }
        toml::Value::Array(items) => items
            .iter_mut()
            .for_each(|item| redact_toml_value(item, mask_all)),
        leaf => {
            if mask_all {
                *leaf = toml_placeholder(leaf);
            }
        }
    }
}

fn toml_placeholder(original: &toml::Value) -> toml::Value {
    let len = match original {
        toml::Value::String(s) => s.len(),
        other => other.to_string().len(),
    };
    toml::Value::String(format!("<redacted:len={len}>"))
}

/// The process environment with every value the caller's policy does not
/// explicitly allow masked to `<redacted:len=N>` (N = the OS value's byte
/// length, so size-related issues stay diagnosable). Names are always
/// recorded; only values are masked.
///
/// Enumerates via `vars_os`, never `vars` — the latter panics on a
/// non-UTF-8 name or value, and a panic inside a collector aborts the whole
/// run with an unfinalized archive.
pub fn masked_process_env(is_value_allowed: impl Fn(&str) -> bool) -> BTreeMap<String, String> {
    std::env::vars_os()
        .map(|(name_os, value_os)| {
            let name = name_os.to_string_lossy().into_owned();
            let shown = if is_value_allowed(&name) {
                value_os.to_string_lossy().into_owned()
            } else {
                format!("<redacted:len={}>", value_os.as_encoded_bytes().len())
            };
            (name, shown)
        })
        .collect()
}

/// Masks credential-shaped tokens in free text, fail-closed per token.
///
/// Returns `Cow::Borrowed` when nothing was changed, so callers can skip
/// re-encoding when the input was clean. The scrubber targets:
///
/// - `Authorization:` / `Proxy-Authorization:` header values (the credential
///   after `Bearer`, `Basic`, or `token`).
/// - URL userinfo (`scheme://<redacted>@host`).
/// - Well-known token prefixes: `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`,
///   `github_pat_`, `sk-`, `xoxa-`, `xoxb-`, `xoxp-`, `AKIA` + 16 hex.
/// - `key=value` pairs whose key trips [`is_sensitive_key`], including a
///   quoted value (`PASSWORD='two words'`, or `PASSWORD=\"x\"` inside a
///   JSON-encoded argv).
/// - The value after a long flag whose name trips [`is_sensitive_key`]
///   (`--password hunter2`).
///
/// The placeholder reuses [`redaction_placeholder`]'s format so every
/// redacted value in a bundle reads consistently.
pub fn scrub_secrets(input: &str) -> Cow<'_, str> {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;
    let mut changed = false;

    while let Some(pos) = find_next_credential(rest) {
        let matched = &rest[pos.start..pos.end];
        // A placeholder is already redacted; leave it and advance past it so
        // scrubbing twice equals scrubbing once.
        if matched.starts_with("<redacted:len=") {
            output.push_str(&rest[..pos.end]);
            rest = &rest[pos.end..];
            continue;
        }
        changed = true;
        // Copy the safe prefix up to the match.
        output.push_str(&rest[..pos.start]);
        // Emit the redacted placeholder.
        let original_len = pos.end - pos.start;
        output.push_str(&format!("<redacted:len={original_len}>"));
        rest = &rest[pos.end..];
    }

    if changed {
        output.push_str(rest);
        Cow::Owned(output)
    } else {
        Cow::Borrowed(input)
    }
}

/// Byte range of a credential-shaped token found in `input`.
struct CredentialMatch {
    start: usize,
    end: usize,
}

/// Scans `input` for the leftmost credential-shaped token and returns its
/// byte range, or `None` when the input is clean.
///
/// Every finder is consulted and the leftmost match wins (the longest, on a
/// tie). [`scrub_secrets`] copies everything before the match verbatim, so
/// taking the first finder that matches anywhere would let an earlier
/// credential of a different shape through unscrubbed.
fn find_next_credential(input: &str) -> Option<CredentialMatch> {
    [
        find_auth_header(input),
        find_url_userinfo(input),
        find_known_token(input),
        find_sensitive_key_value(input),
        find_sensitive_flag_value(input),
    ]
    .into_iter()
    .flatten()
    .min_by_key(|m| (m.start, std::cmp::Reverse(m.end)))
}

/// Length of the token at the start of `s`: it runs to the next whitespace,
/// quote, backslash-escaped quote (the closing `\"` of a JSON-encoded
/// string), or end of input.
fn token_len(s: &str) -> usize {
    s.char_indices()
        .find(|&(i, c)| {
            c.is_whitespace()
                || c == '\''
                || c == '"'
                || (c == '\\' && s[i + 1..].starts_with(['\'', '"']))
        })
        .map_or(s.len(), |(i, _)| i)
}

/// Offset and length of the value at the start of `s`.
///
/// A value opening with a quote, optionally backslash-escaped as in a
/// JSON-encoded argv (`\"x\"`), runs from after that quote to its match:
/// for an escaped opening quote, the next escaped quote of the same kind
/// that is not itself a shell-escaped quote (`\\\"`);
/// otherwise the next quote of the same kind that is not escaped. An
/// unclosed quote runs to the end of input, so a cut-off value is still
/// masked. Any other value is a [`token_len`] token.
fn value_span(s: &str) -> (usize, usize) {
    let escaped = s.starts_with('\\') && s[1..].starts_with(['\'', '"']);
    let open = usize::from(escaped);
    let Some(quote) = s[open..].chars().next().filter(|&c| c == '\'' || c == '"') else {
        return (0, token_len(s));
    };
    let start = open + 1;
    let body = &s[start..];
    // The quote closes on the run of backslashes before it. Unescaped, an
    // even run leaves it a real quote. Escaped, the run must be odd (the
    // escape of the quote itself), and the rest decodes to (run - 1) / 2
    // backslashes that must again be even: `\"` closes, but the `\\\"` of a
    // shell-escaped quote inside a JSON string does not.
    let closes = |run: usize| {
        if escaped {
            !run.is_multiple_of(2) && (run / 2).is_multiple_of(2)
        } else {
            run.is_multiple_of(2)
        }
    };
    let mut run = 0;
    let len = body
        .char_indices()
        .find_map(|(i, c)| {
            let close = c == quote && closes(run);
            run = if c == '\\' { run + 1 } else { 0 };
            close.then(|| if escaped { i - 1 } else { i })
        })
        .unwrap_or(body.len());
    (start, len)
}

/// Matches `Authorization: <type> <credential>` or
/// `Proxy-Authorization: <type> <credential>`, at the first header whose
/// scheme is `Bearer`, `Basic`, or `token`.
fn find_auth_header(input: &str) -> Option<CredentialMatch> {
    // ASCII lowercasing keeps byte offsets aligned with `input`.
    let lower = input.to_ascii_lowercase();
    lower
        .match_indices("authorization:")
        .find_map(|(header_start, header)| {
            let after_header = header_start + header.len();
            let rest = &input[after_header..];
            let rest_lower = &lower[after_header..];

            // Skip whitespace between `:` and the scheme.
            let scheme_start = rest.len() - rest.trim_start().len();
            let scheme_len = ["bearer", "basic", "token"]
                .into_iter()
                .find(|s| rest_lower[scheme_start..].starts_with(s))?
                .len();

            let after_scheme = scheme_start + scheme_len;
            let after_scheme_str = &rest[after_scheme..];
            let cred = after_scheme_str.trim_start();
            let (cred_offset, cred_len) = value_span(cred);
            if cred_len == 0 {
                return None;
            }
            let cred_skip = after_scheme_str.len() - cred.len() + cred_offset;
            let start = after_header + after_scheme + cred_skip;
            Some(CredentialMatch {
                start,
                end: start + cred_len,
            })
        })
}

/// Matches the userinfo of `scheme://user:password@host`.
///
/// Every `://` is tried, so a URL without userinfo does not hide a later one
/// that has it. The userinfo runs to the last `@` before the next whitespace
/// or quote, so a raw `@` or `/` inside the password cannot cut it short.
fn find_url_userinfo(input: &str) -> Option<CredentialMatch> {
    input.match_indices("://").find_map(|(idx, sep)| {
        let start = idx + sep.len();
        let word = &input[start..start + token_len(&input[start..])];
        let at = word.rfind('@')?;
        // Must contain a colon (user:password).
        word[..at].contains(':').then_some(CredentialMatch {
            start,
            end: start + at,
        })
    })
}

/// Matches well-known token shapes: GitHub tokens, OpenAI keys, Slack tokens,
/// AWS access keys.
///
/// A prefix only counts at the start of a word (not preceded by an ASCII
/// alphanumeric), so `task-runner` is not mistaken for an `sk-` key.
fn find_known_token(input: &str) -> Option<CredentialMatch> {
    const PREFIXES: &[&str] = &[
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "github_pat_",
        "sk-",
        "xoxa-",
        "xoxb-",
        "xoxp-",
    ];
    let at_word_start = |pos: usize| {
        input[..pos]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_ascii_alphanumeric())
    };

    let prefixed = PREFIXES.iter().filter_map(|prefix| {
        input.match_indices(prefix).find_map(|(pos, _)| {
            let len = token_len(&input[pos + prefix.len()..]);
            (at_word_start(pos) && len > 0).then_some(CredentialMatch {
                start: pos,
                end: pos + prefix.len() + len,
            })
        })
    });

    // AKIA + 16 uppercase alphanumerics (AWS access key).
    let aws = input.match_indices("AKIA").find_map(|(pos, _)| {
        let key = input.get(pos + 4..pos + 4 + 16)?;
        (at_word_start(pos)
            && key
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()))
        .then_some(CredentialMatch {
            start: pos,
            end: pos + 4 + 16,
        })
    });

    prefixed.chain(aws).min_by_key(|m| m.start)
}

/// Matches `key=value` where `key` trips [`is_sensitive_key`].
fn find_sensitive_key_value(input: &str) -> Option<CredentialMatch> {
    // The key is the run of non-whitespace immediately before `=`, so
    // `--token=value`, `token=value`, and `GITHUB_TOKEN=value` all match.
    input.match_indices('=').find_map(|(eq_idx, _)| {
        // The `=` inside an earlier `<redacted:len=N>` placeholder is not a
        // pair: matching it would re-redact the length and break idempotence.
        if input[..eq_idx].ends_with("<redacted:len") {
            return None;
        }
        let key_start = input[..eq_idx]
            .rfind(char::is_whitespace)
            .map_or(0, |p| p + 1);
        if !is_sensitive_key(&input[key_start..eq_idx]) {
            return None;
        }
        let (val_offset, val_len) = value_span(&input[eq_idx + 1..]);
        let val_start = eq_idx + 1 + val_offset;
        (val_len > 0).then_some(CredentialMatch {
            start: val_start,
            end: val_start + val_len,
        })
    })
}

/// Matches the value after a long flag whose name trips
/// [`is_sensitive_key`], given as a separate word: `--password hunter2`, or
/// `"--token","ghp_x"` in a JSON-encoded argv.
///
/// Short flags (`-p`) are not matched: a single letter names nothing, and
/// `-p` is as often a port or a package as a password.
fn find_sensitive_flag_value(input: &str) -> Option<CredentialMatch> {
    let is_sep = |c: char| c.is_whitespace() || matches!(c, '\'' | '"' | ',' | '[' | ']');
    let mut words = input
        .match_indices(|c: char| !is_sep(c))
        .map(|(i, _)| i)
        .filter(|&i| i == 0 || input[..i].ends_with(is_sep))
        .map(|i| {
            let len = input[i..].find(is_sep).unwrap_or(input.len() - i);
            (i, &input[i..i + len])
        })
        .peekable();
    while let Some((_, word)) = words.next() {
        if !word.starts_with("--") || word.contains('=') || !is_sensitive_key(word) {
            continue;
        }
        if let Some(&(start, value)) = words.peek()
            && !value.starts_with('-')
        {
            return Some(CredentialMatch {
                start,
                end: start + value.len(),
            });
        }
    }
    None
}

/// The OTLP exporter header variables, plain and `MINIMAL_`-prefixed, base
/// and per signal (spec 25 TEL-042). Their values are credentials: an ingest
/// key, a bearer token.
pub const EXPORTER_HEADER_VARS: &[&str] = &[
    "OTEL_EXPORTER_OTLP_HEADERS",
    "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
    "OTEL_EXPORTER_OTLP_LOGS_HEADERS",
    "MINIMAL_OTEL_EXPORTER_OTLP_HEADERS",
    "MINIMAL_OTEL_EXPORTER_OTLP_TRACES_HEADERS",
    "MINIMAL_OTEL_EXPORTER_OTLP_LOGS_HEADERS",
];

/// The shortest header value [`scrub_spool_line`] replaces wherever it
/// appears. A shorter value is no credential, and replacing every `1` or
/// `on` in a spool line would make the line unreadable. A header value
/// shorter than this is not value-matched at all: it relies on the
/// attribute-name rule ([`is_credential_attribute_key`]) and the free-text
/// scrub ([`scrub_secrets`]).
pub const HEADER_VALUE_MIN: usize = 8;

/// Every exporter header value configured in the variables `var` gives
/// ([`EXPORTER_HEADER_VARS`], each `name=value[,name=value...]`), as written
/// and percent-decoded, plus each whitespace-separated part of the decoded
/// value (the bare `<token>` of `Bearer%20<token>`, which a record can hold
/// without its scheme word), each at least [`HEADER_VALUE_MIN`] bytes long,
/// longest first so a value that contains another is replaced whole.
pub fn exporter_header_values(var: impl Fn(&str) -> Option<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for name in EXPORTER_HEADER_VARS {
        let Some(raw) = var(name) else { continue };
        for pair in raw.split(',') {
            let Some((_, value)) = pair.split_once('=') else {
                continue;
            };
            let value = value.trim();
            let decoded = percent_decode(value);
            out.extend(decoded.split_whitespace().map(str::to_owned));
            out.push(value.to_owned());
            out.push(decoded);
        }
    }
    order_header_values(out)
}

/// `values` without the ones shorter than [`HEADER_VALUE_MIN`], without
/// duplicates, longest first (ties in byte order).
fn order_header_values(mut values: Vec<String>) -> Vec<String> {
    values.retain(|v| v.len() >= HEADER_VALUE_MIN);
    values.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    values.dedup();
    values
}

/// The header values to scrub from one spool file (TEL-044): the
/// `collector`'s own `base` set, plus the exporter header values of the
/// process that wrote the file, when that is known. mlog names a spool file
/// `<service>-<pid>-<start_ms>[-<n>].jsonl`; while that pid is a live process
/// whose environment this process may read (same user: `/proc/<pid>/environ`
/// on Linux, `sysctl(KERN_PROCARGS2)` on macOS), its
/// [`EXPORTER_HEADER_VARS`] count too. So a header that minvmd or the daemon
/// was started with, and the shell running `min bug` lacks, is still found.
/// A reused pid only adds values to replace, never removes one. On another
/// OS, for a producer that has exited, or one whose environment the kernel
/// refuses to show, the set is `base`, and the key-name rule in
/// [`scrub_spool_line`] is what stands.
#[must_use]
pub fn spool_file_header_values(file_name: &str, base: &[String]) -> Vec<String> {
    let mut out = base.to_vec();
    if let Some(pid) = spool_file_pid(file_name) {
        out.extend(process_exporter_header_values(pid));
    }
    order_header_values(out)
}

/// The pid in a spool file name (`<service>-<pid>-<start_ms>[-<n>].jsonl`):
/// the digits after the first `-<digit>`, up to the next `-`.
fn spool_file_pid(name: &str) -> Option<u32> {
    let stem = name.strip_suffix(".jsonl")?;
    let bytes = stem.as_bytes();
    let at = bytes
        .windows(2)
        .position(|w| matches!(w, [b'-', d] if d.is_ascii_digit()))?;
    let rest = stem.get(at + 1..)?;
    let (pid, _) = rest.split_once('-')?;
    pid.parse().ok()
}

/// The exporter header values in the environment process `pid` started with
/// (`/proc/<pid>/environ`), empty when it cannot be read.
#[cfg(target_os = "linux")]
fn process_exporter_header_values(pid: u32) -> Vec<String> {
    let Ok(environ) = std::fs::read(format!("/proc/{pid}/environ")) else {
        return Vec::new();
    };
    environ_exporter_header_values(environ.split(|b| *b == 0))
}

/// The exporter header values in the environment process `pid` started with
/// (`sysctl(KERN_PROCARGS2)`, which the kernel answers for a process of the
/// same user), empty when it cannot be read. The kernel withholds the
/// environment of Apple's platform binaries (`/bin/sh`, `/bin/sleep`; only
/// their arguments come back), which are no telemetry producers; minimal's
/// own binaries, ad hoc or hardened-runtime signed, show theirs (measured on
/// macOS 26.6).
#[cfg(target_os = "macos")]
fn process_exporter_header_values(pid: u32) -> Vec<String> {
    let Some(args) = procargs2(pid) else {
        return Vec::new();
    };
    environ_exporter_header_values(procargs2_environ(&args))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process_exporter_header_values(_pid: u32) -> Vec<String> {
    Vec::new()
}

/// The exporter header values in a process environment given as its
/// `KEY=value` entries (NUL-separated in `/proc/<pid>/environ` and in
/// `KERN_PROCARGS2`); an entry that is not UTF-8 or has no `=` is skipped.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn environ_exporter_header_values<'a>(entries: impl Iterator<Item = &'a [u8]>) -> Vec<String> {
    let vars: Vec<(String, String)> = entries
        .filter_map(|kv| {
            let kv = std::str::from_utf8(kv).ok()?;
            let (k, v) = kv.split_once('=')?;
            Some((k.to_owned(), v.to_owned()))
        })
        .collect();
    exporter_header_values(|name| {
        vars.iter()
            .find(|(k, v)| k == name && !v.is_empty())
            .map(|(_, v)| v.clone())
    })
}

/// Process `pid`'s `KERN_PROCARGS2` block, `None` when the kernel refuses
/// it (another user's process, one that has exited, a restricted one).
#[cfg(target_os = "macos")]
fn procargs2(pid: u32) -> Option<Vec<u8>> {
    let pid = libc::c_int::try_from(pid).ok()?;
    let mut argmax: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    // SAFETY: `mib` names the two-level integer sysctl `kern.argmax`, and
    // `argmax`/`size` describe a writable `c_int` the kernel fills in.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            2,
            (&raw mut argmax).cast(),
            &raw mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    let mut buf = vec![0u8; usize::try_from(argmax).ok().filter(|n| *n > 0)?];
    let mut size = buf.len();
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    // SAFETY: `buf` is writable for `size` bytes; the kernel writes at most
    // that many and stores the length it wrote back into `size`.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &raw mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    buf.truncate(size);
    Some(buf)
}

/// The environment entries of a `KERN_PROCARGS2` block: a native-endian
/// `int` argc, the executable path, NUL padding, `argc` NUL-terminated
/// arguments, then the `KEY=value` environment strings up to the first
/// empty one (the `apple[]` strings after it are not environment). A short
/// or malformed block yields what it holds before the fault, never a panic.
/// An empty first argument is taken for padding, and the first environment
/// entry is then consumed as an argument: a value missed, never a wrong one.
#[cfg(any(target_os = "macos", test))]
fn procargs2_environ(buf: &[u8]) -> impl Iterator<Item = &[u8]> {
    let argc = buf
        .get(..4)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(i32::from_ne_bytes)
        .and_then(|n| usize::try_from(n).ok());
    let rest = argc.and(buf.get(4..)).unwrap_or_default();
    let mut strings = rest.split(|b| *b == 0);
    // The executable path, then its NUL padding.
    strings.next();
    let mut strings = strings.skip_while(|s| s.is_empty());
    for _ in 0..argc.unwrap_or(0) {
        strings.next();
    }
    strings.take_while(|s| !s.is_empty())
}

/// `s` with each `%XX` escape decoded; an escape that is not two hex digits
/// stays as written, and bytes that do not decode to UTF-8 are replaced.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        let hex = bytes
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match (b, hex) {
            (b'%', Some(decoded)) => {
                out.push(decoded);
                i += 3;
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One spool line made safe to bundle (spec 25 TEL-044), before the free-text
/// [`scrub_secrets`] runs over it as over any log line:
///
/// - each of `header_values` ([`exporter_header_values`]) is replaced
///   wherever it appears, so an exporter header value never travels even
///   when a span recorded it under a harmless name;
/// - the line is read as OTLP/JSON, and an attribute (`{"key": k, "value":
///   v}`) whose `k` trips [`is_credential_attribute_key`] (a secret-shaped
///   or header-like name) has its `v` replaced by a placeholder string
///   value. Free text cannot see these, as the value sits apart from its
///   name;
/// - a line that is not JSON (the torn first line of a tail cap, a torn
///   write) is withheld whole: it cannot be read as attributes, so it
///   cannot be scrubbed as them.
pub fn scrub_spool_line<'a>(line: &'a str, header_values: &[String]) -> Cow<'a, str> {
    if line.trim().is_empty() {
        return Cow::Borrowed(line);
    }
    let mut text = Cow::Borrowed(line);
    for value in header_values {
        let placeholder = format!("<redacted:len={}>", value.len());
        // The raw form, and the JSON-escaped form a value with `"` or `\`
        // takes inside an OTLP/JSON string.
        let escaped = serde_json_lenient::to_string(value.as_str())
            .ok()
            .and_then(|s| {
                s.strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .map(str::to_owned)
            });
        for form in std::iter::once(value.as_str()).chain(escaped.as_deref()) {
            if !form.is_empty() && text.contains(form) {
                text = Cow::Owned(text.replace(form, &placeholder));
            }
        }
    }
    let Ok(mut json) = serde_json_lenient::from_str::<Value>(&text) else {
        return Cow::Owned(format!(
            "<spool line withheld: not JSON, len={}>",
            line.len()
        ));
    };
    if !redact_otlp_attributes(&mut json) {
        return text;
    }
    match serde_json_lenient::to_string(&json) {
        Ok(s) => Cow::Owned(s),
        Err(_) => Cow::Owned(format!(
            "<spool line withheld: not re-encodable, len={}>",
            line.len()
        )),
    }
}

/// Key-name parts that mark an attribute as a request header or a header
/// list, matched case-insensitively, beyond [`is_sensitive_key`]'s: any
/// header (OTel's `http.request.header.<name>`, a recorded `headers` list),
/// a cookie, and the ingest-key header names collectors use that carry no
/// sensitive word (`x-honeycomb-team`).
const HEADER_KEY_PARTS: &[&str] = &["header", "cookie", "honeycomb-team"];

/// Whether an OTLP attribute named `key` holds a credential-shaped value:
/// [`is_sensitive_key`], or a header-like name ([`HEADER_KEY_PARTS`]). The
/// spool scrub masks these whatever the bundling process's environment says,
/// so a header a producer was started with is masked by its name even when
/// its value is unknown here.
#[must_use]
pub fn is_credential_attribute_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    is_sensitive_key(key) || HEADER_KEY_PARTS.iter().any(|p| lower.contains(p))
}

/// Replaces, anywhere in `value`, the `value` of an OTLP attribute whose
/// `key` trips [`is_credential_attribute_key`]. Returns whether anything
/// changed.
fn redact_otlp_attributes(value: &mut Value) -> bool {
    match value {
        Value::Object(map) => {
            let sensitive = map
                .get("key")
                .and_then(Value::as_str)
                .is_some_and(is_credential_attribute_key);
            let mut changed = false;
            if sensitive && let Some(v) = map.get_mut("value") {
                let placeholder = redaction_placeholder(v);
                if *v != serde_json_lenient::json!({ "stringValue": placeholder }) {
                    *v = serde_json_lenient::json!({ "stringValue": placeholder });
                    changed = true;
                }
            }
            for (k, v) in map.iter_mut() {
                if !(sensitive && k == "value") {
                    changed |= redact_otlp_attributes(v);
                }
            }
            changed
        }
        Value::Array(items) => items
            .iter_mut()
            .fold(false, |acc, v| redact_otlp_attributes(v) | acc),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json_lenient::json;

    /// A header value holding `"` or `\` is found in its JSON-escaped form
    /// too, which is how it appears inside an OTLP/JSON string.
    #[test]
    fn a_header_value_with_a_quote_or_backslash_is_replaced_in_its_json_form() {
        let value = r#"tok"en\x"#.to_owned();
        let line = format!(
            r#"{{"resourceSpans":[{{"scopeSpans":[{{"spans":[{{"name":"s","attributes":[{{"key":"note","value":{{"stringValue":{}}}}}]}}]}}]}}]}}"#,
            serde_json_lenient::to_string(&value).unwrap()
        );
        let out = scrub_spool_line(&line, std::slice::from_ref(&value));
        assert!(!out.contains(r#"tok\"en"#), "escaped value survived: {out}");
        assert!(!out.contains("tok"), "value survived: {out}");
        assert!(out.contains("<redacted:len="), "no placeholder: {out}");
    }

    /// TEL-044: a spool line keeps neither an exporter header value (even
    /// under a harmless attribute name, and the bare token of a
    /// `scheme%20token` value too) nor the value of a secret-shaped or
    /// header-like attribute, and a line that is not JSON is withheld whole.
    #[test]
    fn a_spool_line_loses_header_values_and_secret_attributes() {
        let headers = exporter_header_values(|name| {
            (name == "MINIMAL_OTEL_EXPORTER_OTLP_HEADERS")
                .then(|| "x-honeycomb-team=hcaik_s3cr3tINGEST,x-short=1".to_owned())
        });
        assert_eq!(headers, vec!["hcaik_s3cr3tINGEST".to_owned()]);
        let bearer = exporter_header_values(|name| {
            (name == "OTEL_EXPORTER_OTLP_HEADERS")
                .then(|| "authorization=Bearer%20bareTOKEN12345".to_owned())
        });
        let line = r#"{"resourceSpans":[{"scopeSpans":[{"spans":[{"name":"s","attributes":[{"key":"note","value":{"stringValue":"got bareTOKEN12345 back"}}]}]}]}]}"#;
        let out = scrub_spool_line(line, &bearer);
        assert!(
            !out.contains("bareTOKEN12345"),
            "bare token survived: {out}"
        );
        let line = r#"{"resourceSpans":[{"scopeSpans":[{"spans":[{"name":"s","attributes":[{"key":"http.request.header.x-honeycomb-team","value":{"arrayValue":{"values":[{"stringValue":"unknownKEY777"}]}}},{"key":"otel.headers","value":{"stringValue":"x-team=unknownKEY888"}},{"key":"x-honeycomb-team","value":{"stringValue":"unknownKEY999"}}]}]}]}]}"#;
        let out = scrub_spool_line(line, &[]);
        for v in ["unknownKEY777", "unknownKEY888", "unknownKEY999"] {
            assert!(!out.contains(v), "a header-like attribute kept {v}: {out}");
        }
        let line = r#"{"resourceSpans":[{"scopeSpans":[{"spans":[{"name":"cmd","attributes":[{"key":"note","value":{"stringValue":"hcaik_s3cr3tINGEST"}},{"key":"db.api_token","value":{"stringValue":"plainwords"}},{"key":"cmd.name","value":{"stringValue":"build"}}]}]}]}]}"#;
        let out = scrub_spool_line(line, &headers);
        assert!(!out.contains("hcaik_s3cr3tINGEST"), "{out}");
        assert!(!out.contains("plainwords"), "{out}");
        assert!(out.contains("\"build\""), "harmless values stay: {out}");
        assert!(out.contains("db.api_token"), "the name stays: {out}");
        let torn = r#"Value":"plainwords"}]}"#;
        assert!(!scrub_spool_line(torn, &headers).contains("plainwords"));
        assert_eq!(scrub_spool_line(r#"{"a":1}"#, &headers), r#"{"a":1}"#);
    }

    /// A producer's header set: a spool file's pid names the
    /// process that wrote it, and while that process runs (same user;
    /// `/proc` on Linux, `KERN_PROCARGS2` on macOS) its exporter headers are
    /// scrubbed too, though the collecting process's own environment has
    /// none.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_live_producers_headers_are_scrubbed_from_its_spool_file() {
        // On macOS the producer must not be an Apple platform binary (the
        // kernel withholds those environments): this test binary stands in,
        // running only `producer_stand_in`.
        #[cfg(target_os = "linux")]
        let mut producer = std::process::Command::new("sleep");
        #[cfg(target_os = "linux")]
        producer.arg("30");
        #[cfg(target_os = "macos")]
        let mut producer = std::process::Command::new(std::env::current_exe().unwrap());
        #[cfg(target_os = "macos")]
        producer
            .args(["--exact", "redact::tests::producer_stand_in", "--ignored"])
            .env(STAND_IN_ENV, "1");
        let mut child = producer
            .env_clear()
            .env(
                "MINIMAL_OTEL_EXPORTER_OTLP_HEADERS",
                "x-honeycomb-team=producerONLY4242",
            )
            .spawn()
            .unwrap();
        let name = format!("minvmd-{}-1700000000000-2.jsonl", child.id());
        let values = spool_file_header_values(&name, &[]);
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(values, vec!["producerONLY4242".to_owned()]);
        let line = r#"{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"stringValue":"sent producerONLY4242"}}]}]}]}"#;
        let out = scrub_spool_line(line, &values);
        assert!(!out.contains("producerONLY4242"), "{out}");
    }

    /// Set on the macOS stand-in producer, which then sleeps.
    #[cfg(target_os = "macos")]
    const STAND_IN_ENV: &str = "DIAGNOSTICS_PRODUCER_STAND_IN";

    /// Not a test: the process `a_live_producers_headers_are_scrubbed_from_its_spool_file`
    /// spawns on macOS (this binary, with [`STAND_IN_ENV`] set) to stand in
    /// for a producer. Run on its own it returns at once.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "a stand-in process for a_live_producers_headers_are_scrubbed_from_its_spool_file"]
    fn producer_stand_in() {
        if std::env::var_os(STAND_IN_ENV).is_some() {
            std::thread::sleep(std::time::Duration::from_secs(30));
        }
    }

    /// macOS: a `KERN_PROCARGS2` block is read for its
    /// environment only — not the executable path, its padding, the
    /// arguments (one of which looks like a header setting here) or the
    /// `apple[]` strings after the environment. Runs on every OS: the
    /// block is built by hand.
    #[test]
    fn a_procargs2_block_yields_only_its_environment() {
        let mut block = 2i32.to_ne_bytes().to_vec();
        block.extend_from_slice(b"/usr/bin/sleep\0\0\0\0");
        block.extend_from_slice(b"sleep\0MINIMAL_OTEL_EXPORTER_OTLP_HEADERS=k=argvVALUE123\0");
        block.extend_from_slice(
            b"HOME=/Users/x\0OTEL_EXPORTER_OTLP_HEADERS=x-honeycomb-team=envVALUE4567\0",
        );
        block.extend_from_slice(b"\0ptr_munge=OTEL_EXPORTER_OTLP_HEADERS=k=appleVALUE89\0\0");
        let env: Vec<&[u8]> = procargs2_environ(&block).collect();
        assert_eq!(
            env,
            [
                &b"HOME=/Users/x"[..],
                b"OTEL_EXPORTER_OTLP_HEADERS=x-honeycomb-team=envVALUE4567"
            ]
        );
        assert_eq!(
            environ_exporter_header_values(procargs2_environ(&block)),
            ["envVALUE4567"]
        );
        for short in [&b""[..], b"\x02\0", b"\xff\xff\xff\xff/x\0A=b\0"] {
            assert_eq!(procargs2_environ(short).count(), 0, "{short:?}");
        }
        let mut cut = 5i32.to_ne_bytes().to_vec();
        cut.extend_from_slice(b"/x\0a\0b");
        assert_eq!(procargs2_environ(&cut).count(), 0, "a truncated block");
    }

    /// The live-process read on the remaining OSes is empty: only `base`
    /// and the key-name rule stand there.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn elsewhere_a_producers_environment_is_not_read() {
        assert!(process_exporter_header_values(std::process::id()).is_empty());
    }

    #[test]
    fn a_spool_file_names_its_producers_pid() {
        assert_eq!(spool_file_pid("minvmd-42-1700000000000.jsonl"), Some(42));
        assert_eq!(
            spool_file_pid("minimal-cli-7-1700000000000-3.jsonl"),
            Some(7)
        );
        assert_eq!(spool_file_pid("report.jsonl"), None);
        assert_eq!(spool_file_pid("minvmd-42.jsonl"), None);
        let base = vec!["shellVALUE123".to_owned()];
        assert_eq!(
            spool_file_header_values("report.jsonl", &base),
            base,
            "an unknown producer keeps the collector's set"
        );
    }

    /// The shared deny list holds for every producer's allowlist.
    #[test]
    fn exporter_settings_are_denied_whatever_the_allowlist() {
        for name in [
            "MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT",
            "MINIMAL_OTEL_EXPORTER_OTLP_LOGS_HEADERS",
            "MINIMALD_SOMETHING_HEADERS",
        ] {
            assert!(is_env_value_denylisted(name), "{name}");
            assert!(
                !is_env_value_allowlisted(name, &[name], &["MINIMAL"]),
                "{name}"
            );
        }
        assert!(is_env_value_allowlisted(
            "MINIMAL_TELEMETRY",
            &[],
            &["MINIMAL_"]
        ));
    }

    #[test]
    fn header_values_are_read_as_written_and_percent_decoded() {
        let got = exporter_header_values(|name| {
            (name == "OTEL_EXPORTER_OTLP_TRACES_HEADERS")
                .then(|| "authorization=Bearer%20abcdefgh".to_owned())
        });
        assert_eq!(
            got,
            vec![
                "Bearer%20abcdefgh".to_owned(),
                "Bearer abcdefgh".to_owned(),
                "abcdefgh".to_owned(),
            ],
            "as written, decoded, and the token without its scheme word"
        );
        // `Bearer` alone is shorter than HEADER_VALUE_MIN and is not kept.
        assert!(!got.iter().any(|v| v == "Bearer"));
    }

    #[test]
    fn sensitive_keys_match_case_insensitively() {
        for key in [
            "token",
            "GITHUB_TOKEN",
            "api_key",
            "ApiKey",
            "ssh_private_key",
            "PASSWORD",
            "authorization",
            "my-secret-thing",
        ] {
            assert!(is_sensitive_key(key), "{key} should be sensitive");
        }
    }

    #[test]
    fn public_keys_are_exempt() {
        assert!(!is_sensitive_key("public_key"));
        assert!(!is_sensitive_key("WG_PUBLIC_KEY"));
        assert!(!is_sensitive_key("name"));
        assert!(!is_sensitive_key("packages"));
    }

    #[test]
    fn public_exemption_is_anchored_to_public_key() {
        assert!(is_sensitive_key("publication_secret"));
        assert!(is_sensitive_key("public_password"));
        assert!(is_sensitive_key("republic_token"));
        // The exempt token must not launder a sensitive marker sitting
        // beside it.
        assert!(is_sensitive_key("public_key_token"));
        assert!(is_sensitive_key("public_key_password"));
        assert!(is_sensitive_key("private_public_key"));
    }

    #[test]
    fn sensitive_keys_mask_container_values_wholesale() {
        let mut v = json!({
            "tokens": { "github": "ghp_xxx", "gitlab": "glpat_yyy" },
            "api_token": ["primary", "secondary"],
            "credentials": { "aws": { "access_key_id": "AKIA" } },
        });
        redact_json(&mut v);
        assert_eq!(v["tokens"]["github"], "<redacted:len=7>");
        assert_eq!(v["tokens"]["gitlab"], "<redacted:len=9>");
        assert_eq!(v["api_token"][0], "<redacted:len=7>");
        assert_eq!(v["api_token"][1], "<redacted:len=9>");
        assert_eq!(v["credentials"]["aws"]["access_key_id"], "<redacted:len=4>");
    }

    #[test]
    fn redacts_sensitive_values_and_env_tables() {
        let mut v = json!({
            "name": "dev",
            "api_token": "abc123",
            "vars": { "EDITOR": "vim", "HOME": "/home/u" },
            "nested": { "list": [ { "password": "hunter2", "port": 80 } ] },
        });
        redact_json(&mut v);
        assert_eq!(v["name"], "dev");
        assert_eq!(v["api_token"], "<redacted:len=6>");
        assert_eq!(v["vars"]["EDITOR"], "<redacted:len=3>");
        assert_eq!(v["vars"]["HOME"], "<redacted:len=7>");
        assert_eq!(v["nested"]["list"][0]["password"], "<redacted:len=7>");
        assert_eq!(v["nested"]["list"][0]["port"], 80);
    }

    #[test]
    fn env_table_masks_nested_structures_wholesale() {
        let mut v = json!({
            "vars": { "TERM": { "inherit": true, "default": "xterm" } },
        });
        redact_json(&mut v);
        assert_eq!(v["vars"]["TERM"]["inherit"], "<redacted:len=4>");
        assert_eq!(v["vars"]["TERM"]["default"], "<redacted:len=5>");
    }

    #[test]
    fn redaction_is_idempotent() {
        let mut v = json!({ "secret": "s3cr3t", "vars": { "A": "b" } });
        redact_json(&mut v);
        let once = v.clone();
        // Placeholders re-redact to placeholders of the placeholder's length;
        // assert full equality instead by redacting a fresh copy.
        let mut again = once.clone();
        redact_json(&mut again);
        assert_eq!(
            again["vars"]["A"], "<redacted:len=16>",
            "re-redaction only rewrites placeholders, never restores data"
        );
        assert_eq!(once["secret"], "<redacted:len=6>");
    }

    #[test]
    fn non_string_sensitive_values_are_masked() {
        let mut v = json!({ "auth_retries": 3 });
        redact_json(&mut v);
        assert_eq!(v["auth_retries"], "<redacted:len=1>");
    }

    #[test]
    fn toml_redacts_vars_tables_and_sensitive_keys() {
        let input = r#"
            description = "dev loadout"
            packages = ["ripgrep", "fd"]
            api_token = "abc123"

            [vars]
            EDITOR = "vim"
            GITHUB_TOKEN = "ghp_zzz"

            [[lifecycle_hooks]]
            type = "inline"
            value = "echo hi"
        "#;
        let out = redact_toml(input).expect("valid toml");
        assert!(out.contains(r#"description = "dev loadout""#));
        assert!(out.contains("ripgrep"));
        assert!(out.contains(r#"api_token = "<redacted:len=6>""#));
        assert!(out.contains(r#"EDITOR = "<redacted:len=3>""#));
        assert!(out.contains(r#"GITHUB_TOKEN = "<redacted:len=7>""#));
        // Hook bodies are not env values and carry no key-based signal.
        assert!(out.contains("echo hi"));
    }

    #[test]
    fn toml_sensitive_tables_are_masked_wholesale() {
        let input = r#"
            api_token = ["primary", "secondary"]

            [tokens]
            github = "ghp_zzz"

            [credentials.aws]
            access_key_id = "AKIA"
        "#;
        let out = redact_toml(input).expect("valid toml");
        assert!(!out.contains("ghp_zzz"));
        assert!(!out.contains("AKIA"));
        assert!(!out.contains("primary"));
        assert!(!out.contains("secondary"));
    }

    #[test]
    fn toml_redacts_inherit_vars_wholesale() {
        let input = r#"
            [vars]
            TERM = { inherit = true, default = "xterm-256color" }
        "#;
        let out = redact_toml(input).expect("valid toml");
        assert!(!out.contains("xterm-256color"));
        assert!(out.contains("<redacted:len=14>"));
    }

    #[test]
    fn unparseable_toml_is_an_error() {
        assert!(redact_toml("not = [ valid").is_err());
    }

    #[test]
    fn toml_public_key_survives() {
        let out = redact_toml(r#"public_key = "wg-pub-abc""#).expect("valid toml");
        assert!(out.contains("wg-pub-abc"));
    }

    #[test]
    fn masked_process_env_masks_everything_the_policy_rejects() {
        // PATH is always present in a test environment.
        let env = masked_process_env(|name| name == "PATH");
        assert!(!env["PATH"].starts_with("<redacted:"), "allowed verbatim");
        for (name, value) in &env {
            assert!(
                name == "PATH" || value.starts_with("<redacted:len="),
                "{name} must be masked, got: {value}"
            );
        }
    }

    #[test]
    fn scrub_masks_authorization_header() {
        let out = scrub_secrets("curl -H 'Authorization: Bearer abc123' https://x/");
        assert!(!out.contains("abc123"));
        assert!(out.contains("Authorization: Bearer <redacted:len=6>"));
    }

    #[test]
    fn scrub_masks_authorization_token_header() {
        let out = scrub_secrets("-H 'Authorization: token ghp_zzz'");
        assert!(!out.contains("ghp_zzz"));
        assert!(out.contains("Authorization: token <redacted:len=7>"));
    }

    #[test]
    fn scrub_masks_proxy_authorization() {
        let out = scrub_secrets("Proxy-Authorization: Basic dXNlcjpwYXNz");
        assert!(!out.contains("dXNlcjpwYXNz"));
        assert!(out.contains("Proxy-Authorization: Basic <redacted:len=12>"));
    }

    #[test]
    fn scrub_masks_url_userinfo() {
        let out = scrub_secrets("https://user:sekrit@host/path");
        assert!(!out.contains("sekrit"));
        assert!(out.contains("https://<redacted:len=11>@host/path"));
    }

    #[test]
    fn scrub_masks_bare_github_token() {
        let out = scrub_secrets("ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLE0000");
        assert!(!out.contains("EXAMPLE"));
        assert!(out.contains("<redacted:len=36>"));
    }

    #[test]
    fn scrub_masks_token_flag() {
        let out = scrub_secrets("--token=ghp_zzz");
        assert!(!out.contains("ghp_zzz"));
        assert!(out.contains("--token=<redacted:len=7>"));
    }

    #[test]
    fn scrub_masks_sk_token() {
        let out = scrub_secrets("sk-abcdef1234567890");
        assert!(!out.contains("abcdef"));
        assert!(out.contains("<redacted:len=19>"));
    }

    #[test]
    fn scrub_masks_slack_token() {
        let out = scrub_secrets("xoxb-1234567890-abcdef");
        assert!(!out.contains("1234567890"));
        assert!(out.contains("<redacted:len=22>"));
    }

    #[test]
    fn scrub_masks_aws_access_key() {
        let out = scrub_secrets("AKIAIOSFODNN7EXAMPLE");
        assert!(!out.contains("IOSFODNN7EXAMPLE"));
        assert!(out.contains("<redacted:len=20>"));
    }

    #[test]
    fn scrub_passes_ordinary_argv_through() {
        for argv in ["cargo build --release", "ls -la /tmp"] {
            let out = scrub_secrets(argv);
            assert!(matches!(out, Cow::Borrowed(_)), "{argv} should be borrowed");
            assert_eq!(out, argv);
        }
    }

    /// The leftmost credential wins whatever its shape: the scrubber copies
    /// the text before a match verbatim, so a later match of a
    /// higher-priority shape must not carry an earlier secret through.
    #[test]
    fn scrub_masks_every_credential_whatever_their_order() {
        for (input, secrets) in [
            (
                "git clone https://u:pw1@h -H 'Authorization: Bearer abc'",
                &["pw1", "abc"][..],
            ),
            ("sk-AAAA ghp_BBBB", &["AAAA", "BBBB"]),
            (
                "password=hunter2 Authorization: Bearer abc",
                &["hunter2", "abc"],
            ),
            ("TOKEN=t0k https://u:pw2@h", &["t0k", "pw2"]),
            ("https://user@h https://u:pw4@h2", &["pw4"]),
            ("https://u:p/w@d@h/x", &["p/w@d"]),
            ("AKIAnotakey AKIAIOSFODNN7EXAMPLE", &["IOSFODNN7EXAMPLE"]),
        ] {
            let out = scrub_secrets(input);
            for secret in secrets {
                assert!(!out.contains(secret), "{input:?} leaked {secret:?}: {out}");
            }
        }
    }

    #[test]
    fn scrub_masks_env_style_pair() {
        let out = scrub_secrets(r#"min://argv ["sh","-c","GITHUB_TOKEN=abc run"]"#);
        assert_eq!(
            out,
            r#"min://argv ["sh","-c","GITHUB_TOKEN=<redacted:len=3> run"]"#
        );
    }

    #[test]
    fn scrub_masks_space_separated_flag_value() {
        assert_eq!(
            scrub_secrets("login --password hunter2 --verbose"),
            "login --password <redacted:len=7> --verbose"
        );
        assert_eq!(
            scrub_secrets(r#"min://argv ["gh","--token","sekrit"]"#),
            r#"min://argv ["gh","--token","<redacted:len=6>"]"#
        );
    }

    /// A quoted value is masked to its closing quote, whether the quote is
    /// raw (a shell string) or backslash-escaped (the JSON-encoded argv
    /// minimald logs).
    #[test]
    fn scrub_masks_quoted_values() {
        for (input, secret) in [
            ("PASSWORD='hunter2' cmd", "hunter2"),
            ("PASSWORD=\"hunter2\" cmd", "hunter2"),
            ("--password='hunter2'", "hunter2"),
            ("--password=\"hunter2\"", "hunter2"),
            ("PASSWORD='two words'", "two words"),
            ("PASSWORD='two words", "two words"),
            ("PASSWORD=\"a\\\"b\" x", "b"),
            (
                r#"min://argv ["sh","-c","export GITHUB_TOKEN='abc123' && x"]"#,
                "abc123",
            ),
            (
                r#"min://argv ["sh","-c","PASSWORD=\"hunter2\" cmd"]"#,
                "hunter2",
            ),
            (
                r#"min://argv ["sh","-c","PASSWORD=\"two words\" cmd"]"#,
                "words",
            ),
            (
                r#"min://argv ["sh","-c","PASSWORD=\"foo\\\"hunter2\" cmd"]"#,
                "hunter2",
            ),
            ("Authorization: Bearer 'abc123'", "abc123"),
        ] {
            let out = scrub_secrets(input);
            assert!(!out.contains(secret), "{input:?} leaked {secret:?}: {out}");
            assert_eq!(scrub_secrets(&out), out, "{input:?} is not idempotent");
        }
        assert_eq!(
            scrub_secrets("PASSWORD='hunter2' cmd"),
            "PASSWORD='<redacted:len=7>' cmd"
        );
        assert_eq!(
            scrub_secrets(r#"["sh","-c","PASSWORD=\"two words\" cmd"]"#),
            r#"["sh","-c","PASSWORD=\"<redacted:len=9>\" cmd"]"#
        );
    }

    /// The escape before a JSON-encoded closing quote is not part of the
    /// credential: the recorded length stays true and the escaping intact.
    #[test]
    fn scrub_stops_before_an_escaped_closing_quote() {
        assert_eq!(
            scrub_secrets(r#"curl -H \"Authorization: Bearer abc123\" x"#),
            r#"curl -H \"Authorization: Bearer <redacted:len=6>\" x"#
        );
    }

    #[test]
    fn scrub_leaves_prefix_inside_a_word() {
        let out = scrub_secrets("cargo test -p task-runner");
        assert!(matches!(out, Cow::Borrowed(_)), "got {out}");
    }

    #[test]
    fn scrub_is_idempotent() {
        let input = "curl -H 'Authorization: Bearer abc123' https://user:pw@host/";
        let once = scrub_secrets(input);
        let twice = scrub_secrets(&once);
        assert_eq!(once, twice);
    }
}
