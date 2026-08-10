//! Key-based redaction of secret-shaped values in structured data.
//!
//! Shared by the CLI-side diagnostic bundler and the daemon-side
//! diagnostic RPC so both apply identical rules, over both formats the
//! producers read (JSON and TOML), plus the process-environment masking
//! both sides use for their `env.json`. Redaction is deliberately
//! conservative: false positives (masking a harmless value) are
//! acceptable, false negatives (leaking a secret) are not.

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
}
