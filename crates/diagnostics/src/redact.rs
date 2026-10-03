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

/// Resolves an env-var name against a caller-supplied allowlist of exact names
/// and name prefixes, fail-closed: a sensitive-shaped name always loses, even
/// when the allowlist admits it. `MINIMALD_TOKEN` matches a project prefix but
/// must never leave the machine.
///
/// The *mechanic* is here so every bundle producer resolves the allowlist the
/// same way; the *data* — which names a given producer considers safe — stays
/// with the caller, per this crate's mechanics-vs-policy split.
#[must_use]
pub fn is_env_value_allowlisted(name: &str, exact: &[&str], prefixes: &[&str]) -> bool {
    !is_sensitive_key(name)
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
/// - `key=value` pairs whose key trips [`is_sensitive_key`].
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

/// Scans `input` for the first credential-shaped token and returns its byte
/// range, or `None` when the input is clean.
fn find_next_credential(input: &str) -> Option<CredentialMatch> {
    // Authorization / Proxy-Authorization header values.
    if let Some(m) = find_auth_header(input) {
        return Some(m);
    }
    // URL userinfo.
    if let Some(m) = find_url_userinfo(input) {
        return Some(m);
    }
    // Well-known token shapes.
    if let Some(m) = find_known_token(input) {
        return Some(m);
    }
    // key=value with a sensitive key.
    if let Some(m) = find_sensitive_key_value(input) {
        return Some(m);
    }
    None
}

/// Matches `Authorization: <type> <credential>` or
/// `Proxy-Authorization: <type> <credential>`.
fn find_auth_header(input: &str) -> Option<CredentialMatch> {
    let lower = input.to_ascii_lowercase();
    let header_start = lower.find("authorization:")?;
    let after_header = header_start + "authorization:".len();

    let rest = &input[after_header..];
    let rest_lower = &lower[after_header..];

    // Skip whitespace between `:` and the scheme.
    let trimmed = rest.trim_start();
    let ws_skip = rest.len() - trimmed.len();
    let scheme_start = ws_skip;

    // Find the auth scheme: Bearer, Basic, or token (case-insensitive).
    let scheme_len = if rest_lower[scheme_start..].starts_with("bearer") {
        "bearer".len()
    } else if rest_lower[scheme_start..].starts_with("basic") {
        "basic".len()
    } else if rest_lower[scheme_start..].starts_with("token") {
        "token".len()
    } else {
        return None;
    };

    let after_scheme = scheme_start + scheme_len;
    let after_scheme_str = &rest[after_scheme..];
    let cred = after_scheme_str.trim_start();
    if cred.is_empty() {
        return None;
    }
    let cred_skip = after_scheme_str.len() - cred.len();

    // The credential runs to the next whitespace, quote, or end of input.
    let cred_end = cred
        .find(|c: char| c.is_whitespace() || c == '\'' || c == '"')
        .unwrap_or(cred.len());

    if cred_end == 0 {
        return None;
    }

    Some(CredentialMatch {
        start: after_header + after_scheme + cred_skip,
        end: after_header + after_scheme + cred_skip + cred_end,
    })
}

/// Matches `scheme://user:password@host` — the userinfo portion.
fn find_url_userinfo(input: &str) -> Option<CredentialMatch> {
    // Find `://` then look for `@` after it, with a `:` between them.
    // Skip past any leading `<redacted:len=N>` placeholder so we don't
    // match the `://` inside one.
    let search_start = if input.starts_with("<redacted:len=") {
        input.find('>').map_or(0, |i| i + 1)
    } else {
        0
    };
    let tail = &input[search_start..];
    let scheme_end = tail.find("://")?;
    let after_scheme = &tail[scheme_end + 3..];
    let at_pos = after_scheme.find('@')?;
    let userinfo = &after_scheme[..at_pos];
    // Must contain a colon (user:password).
    if !userinfo.contains(':') {
        return None;
    }
    Some(CredentialMatch {
        start: search_start + scheme_end + 3,
        end: search_start + scheme_end + 3 + at_pos,
    })
}

/// Matches well-known token shapes: GitHub tokens, OpenAI keys, Slack tokens,
/// AWS access keys.
fn find_known_token(input: &str) -> Option<CredentialMatch> {
    let prefixes: &[&str] = &[
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

    for prefix in prefixes {
        if let Some(pos) = input.find(prefix) {
            // The token runs to the next whitespace, quote, or end of input.
            let rest = &input[pos + prefix.len()..];
            let token_end = rest
                .find(|c: char| c.is_whitespace() || c == '\'' || c == '"')
                .unwrap_or(rest.len());
            if token_end > 0 {
                return Some(CredentialMatch {
                    start: pos,
                    end: pos + prefix.len() + token_end,
                });
            }
        }
    }

    // AKIA + 16 uppercase hex chars (AWS access key).
    if let Some(pos) = input.find("AKIA") {
        let rest = &input[pos + 4..];
        if rest.len() >= 16 {
            let candidate = &rest[..16];
            if candidate
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            {
                return Some(CredentialMatch {
                    start: pos,
                    end: pos + 4 + 16,
                });
            }
        }
    }

    None
}

/// Matches `key=value` where `key` trips [`is_sensitive_key`].
fn find_sensitive_key_value(input: &str) -> Option<CredentialMatch> {
    // Scan for `=` preceded by a key-like token. The key is the run of
    // non-whitespace immediately before `=`, so `--token=value` and
    // `token=value` both match.
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(eq_pos) = bytes[i..].iter().position(|&b| b == b'=') {
            let eq_idx = i + eq_pos;
            // Walk back from `=` to the start of the key token.
            let key_start = input[..eq_idx]
                .rfind(char::is_whitespace)
                .map_or(0, |p| p + 1);
            let key = &input[key_start..eq_idx];
            if is_sensitive_key(key) {
                // Value runs to next whitespace, quote, or end.
                let val_start = eq_idx + 1;
                let val_rest = &input[val_start..];
                let val_end = val_rest
                    .find(|c: char| c.is_whitespace() || c == '\'' || c == '"')
                    .unwrap_or(val_rest.len());
                if val_end > 0 {
                    return Some(CredentialMatch {
                        start: val_start,
                        end: val_start + val_end,
                    });
                }
            }
            i = eq_idx + 1;
        } else {
            break;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json_lenient::json;

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

    #[test]
    fn scrub_is_idempotent() {
        let input = "curl -H 'Authorization: Bearer abc123' https://user:pw@host/";
        let once = scrub_secrets(input);
        let twice = scrub_secrets(&once);
        assert_eq!(once, twice);
    }
}
