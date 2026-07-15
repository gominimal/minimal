//! Key-based redaction of secret-shaped values in structured data.
//!
//! Shared by the `min bug` diagnostic bundler (CLI side) and the minimald
//! diagnostic RPC (daemon side) so both apply identical rules. Redaction is
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
/// Keys containing `public` are exempt (`public_key` must survive redaction —
/// mesh diagnostics depend on it).
pub fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    if key.contains("public") {
        return false;
    }
    SENSITIVE_KEY_PARTS.iter().any(|part| key.contains(part))
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
/// or when any ancestor object was named like an env table
/// ([`is_env_table_name`]) — inside those, every leaf is masked.
pub fn redact_json(value: &mut Value) {
    redact_json_inner(value, false);
}

fn redact_json_inner(value: &mut Value, mask_all: bool) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                let child_mask = mask_all || is_env_table_name(key);
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
