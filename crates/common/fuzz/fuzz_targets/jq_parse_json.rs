#![no_main]

//! Fuzz `jq::parse_file` on the JSON branch. Build reads project data files
//! (SUPPLY trust) through this; malformed JSON must return a `JqError`, never
//! panic. The `.json` extension routes to the JSON path.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = common::jq::parse_file("x.json", data.to_vec());
});
