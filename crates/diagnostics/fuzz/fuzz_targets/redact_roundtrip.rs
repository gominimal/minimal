#![no_main]

//! Fuzz `diagnostics::redact` — the masking applied to config and env data
//! before it goes into a support bundle that leaves the machine.
//!
//! The module states its own asymmetry: "false positives (masking a harmless
//! value) are acceptable, false negatives (leaking a secret) are not." That is
//! a property, so this target asserts it rather than only watching for panics:
//! after redaction, no leaf reachable under a sensitive key or an env table
//! may still hold its original value.
//!
//! Also covers the `.expect()` in `redact_toml` — re-serializing a
//! just-parsed document is assumed infallible, and the input is a user config
//! file read by the bundler.

use libfuzzer_sys::fuzz_target;

use diagnostics::redact::{
    is_env_table_name, is_env_value_allowlisted, is_sensitive_key, redact_json, redact_toml,
};

/// What a masked leaf must look like afterwards.
fn is_placeholder(v: &toml::Value) -> bool {
    matches!(v, toml::Value::String(s) if s.starts_with("<redacted:len="))
}

fn json_is_placeholder(v: &serde_json::Value) -> bool {
    matches!(v, serde_json::Value::String(s) if s.starts_with("<redacted:len="))
}

/// Walks a redacted TOML document and fails if anything that should have been
/// masked survived. `masked` tracks whether an ancestor key marked this
/// subtree as secret-bearing.
fn assert_toml_masked(value: &toml::Value, masked: bool) {
    match value {
        toml::Value::Table(t) => {
            for (key, child) in t {
                let child_masked = masked || is_env_table_name(key) || is_sensitive_key(key);
                match child {
                    toml::Value::Table(_) | toml::Value::Array(_) => {
                        assert_toml_masked(child, child_masked);
                    }
                    leaf => assert!(
                        !child_masked || is_placeholder(leaf),
                        "leaked TOML value under sensitive key {key:?}: {leaf:?}",
                    ),
                }
            }
        }
        toml::Value::Array(items) => {
            for item in items {
                match item {
                    toml::Value::Table(_) | toml::Value::Array(_) => {
                        assert_toml_masked(item, masked)
                    }
                    leaf => assert!(
                        !masked || is_placeholder(leaf),
                        "leaked TOML array element: {leaf:?}",
                    ),
                }
            }
        }
        leaf => assert!(!masked || is_placeholder(leaf), "leaked TOML leaf: {leaf:?}"),
    }
}

fn assert_json_masked(value: &serde_json::Value, masked: bool) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let child_masked = masked || is_env_table_name(key) || is_sensitive_key(key);
                if child.is_object() || child.is_array() {
                    assert_json_masked(child, child_masked);
                } else {
                    assert!(
                        !child_masked || json_is_placeholder(child),
                        "leaked JSON value under sensitive key {key:?}: {child:?}",
                    );
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                assert_json_masked(item, masked);
            }
        }
        leaf => assert!(
            !masked || json_is_placeholder(leaf),
            "leaked JSON leaf: {leaf:?}",
        ),
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    // ---- TOML ----
    // Only inputs that parse are interesting; unparseable ones are withheld by
    // the caller, per `redact_toml`'s contract.
    if s.parse::<toml::Table>().is_ok() {
        // Must not panic — including the `.expect()` on re-serialization.
        let redacted = redact_toml(s).expect("input parsed, so redact_toml must not error");

        // The output has to still be a TOML document, or the bundle carries a
        // file no consumer can read.
        let reparsed: toml::Table = redacted
            .parse()
            .expect("redacted output must still parse as TOML");

        assert_toml_masked(&toml::Value::Table(reparsed.clone()), false);

        // NOT idempotence. A second pass re-masks the placeholder itself and
        // records *its* length (`<redacted:len=1>` becomes
        // `<redacted:len=16>`), which is key-based redaction working as
        // designed: the key is sensitive, so the value is masked whatever it
        // holds. Skipping placeholder-shaped values would be the riskier
        // design, and the module's stated asymmetry — false positives
        // acceptable, false negatives not — makes over-masking fine.
        //
        // What must hold is monotonicity: a second pass may never unmask.
        let twice = redact_toml(&redacted).expect("redacting twice must not error");
        let twice_parsed: toml::Table = twice
            .parse()
            .expect("twice-redacted output must still parse as TOML");
        assert_toml_masked(&toml::Value::Table(twice_parsed), false);
    }

    // ---- JSON ----
    if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(s) {
        redact_json(&mut v);
        assert_json_masked(&v, false);

        // Monotonic, not idempotent — see the TOML arm.
        let mut again = v.clone();
        redact_json(&mut again);
        assert_json_masked(&again, false);
    }

    // ---- allowlist is fail-closed ----
    // A sensitive-shaped name must lose regardless of what the caller allows.
    // `MINIMALD_TOKEN` matches a project prefix but must never leave the box.
    let name = s.lines().next().unwrap_or("");
    if is_sensitive_key(name) {
        assert!(
            !is_env_value_allowlisted(name, &[name], &[""]),
            "allowlist admitted a sensitive name: {name:?}",
        );
    }
});
