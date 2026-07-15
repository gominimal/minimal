//! CLI-side redaction: TOML files and the process environment.
//!
//! The key-based rules live in [`common::redact`] so the daemon applies the
//! same policy to the JSON it bundles; this module adds the TOML walk (config
//! files, loadouts) and the env-var allowlist used for `host/env.json`.

use common::redact::{is_env_table_name, is_sensitive_key};

/// Env vars whose *values* are safe and useful to include verbatim. Everything
/// else is reported by name only.
const ENV_VALUE_ALLOWLIST_EXACT: &[&str] = &["RUST_LOG", "HOME", "SHELL", "TERM", "PATH"];
const ENV_VALUE_ALLOWLIST_PREFIXES: &[&str] = &["XDG_", "MINIMAL", "MINVMD_", "MINIMALD_"];

/// Returns true when the named env var's value may be captured verbatim.
pub fn is_env_value_allowlisted(name: &str) -> bool {
    ENV_VALUE_ALLOWLIST_EXACT.contains(&name)
        || ENV_VALUE_ALLOWLIST_PREFIXES
            .iter()
            .any(|p| name.starts_with(p))
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
    Ok(toml::to_string_pretty(&value).expect("re-serializing a just-parsed TOML value"))
}

fn redact_toml_value(value: &mut toml::Value, mask_all: bool) {
    match value {
        toml::Value::Table(table) => {
            for (key, child) in table.iter_mut() {
                let child_mask = mask_all || is_env_table_name(key);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_allowlist_covers_expected_names() {
        for name in [
            "RUST_LOG",
            "XDG_STATE_HOME",
            "MINIMAL_BIN",
            "MINVMD_KERNEL_PATH",
            "MINIMALD_DETACHED",
            "HOME",
            "PATH",
        ] {
            assert!(is_env_value_allowlisted(name), "{name} should be allowed");
        }
        for name in ["AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "LANG", "USER"] {
            assert!(!is_env_value_allowlisted(name), "{name} must not be");
        }
    }

    #[test]
    fn redacts_vars_tables_and_sensitive_keys() {
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
    fn redacts_inherit_vars_wholesale() {
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
    fn public_key_survives() {
        let out = redact_toml(r#"public_key = "wg-pub-abc""#).expect("valid toml");
        assert!(out.contains("wg-pub-abc"));
    }
}
