#![no_main]

//! Fuzz `SpecHash::from_hex` — parses the blake3 hex a cache key / wire payload
//! carries. Must reject malformed hex with an error, never panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = common::SpecHash::from_hex(data);
});
