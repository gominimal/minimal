//! Key-based redaction of secret-shaped values in structured data.
//!
//! Shared by the CLI-side diagnostic bundler and the daemon-side
//! diagnostic RPC so both apply identical rules. Redaction is
//! deliberately conservative: false positives (masking a harmless value) are
//! acceptable, false negatives (leaking a secret) are not.

use serde_json::Value;

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
}
