#![no_main]

//! Fuzz `Target::from_str` — the hand-written `<arch>/<os>` parser fed from CLI
//! args and build expressions. Must return an error on junk, never panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = s.parse::<common::Target>();
    }
});
