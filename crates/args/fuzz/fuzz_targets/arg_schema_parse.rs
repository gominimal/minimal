#![no_main]

//! Fuzz `ArgSchema` string parsing — the hand-written schema parser
//! (`parse_bracketed_list`, enum/primitive specs). Malformed schema strings
//! must return an error, never panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = args::ArgSchema::try_from(s);
    }
});
