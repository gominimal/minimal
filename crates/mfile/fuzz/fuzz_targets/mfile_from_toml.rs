#![no_main]

//! Fuzz `minimal.toml` parsing — `File::from_toml_bytes` drives serde/toml
//! through the custom visitors (`EnvVarValue`, `OutputRaw` validation, the
//! untagged `StrOrList`/`LinkConfig` enums). Malformed config must return an
//! error, never panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = mfile::File::from_toml_bytes(data);
});
