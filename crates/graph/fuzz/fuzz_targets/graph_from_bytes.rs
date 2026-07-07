#![no_main]

//! Fuzz the streaming graph wire decoder.
//!
//! `Graph::from_bytes` decodes an attacker-influenced byte stream (the build
//! graph shipped over the remote-execution channel). It must return
//! `Err(WireError)` for any malformed input — never panic, over-allocate, or
//! slice out of bounds. Any crash here is a decoder bug: known suspects are an
//! out-of-bounds slice on an inner length field, an unbounded `vec![0u8; len]`
//! from an untrusted varint, and unsanitised entry filenames.
//!
//! Run with an RSS cap so the unbounded-allocation path surfaces as a crash
//! rather than an ambient OOM, e.g.:
//!   cargo +nightly fuzz run graph_from_bytes -- -rss_limit_mb=2048

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = graph::Graph::from_bytes(data);
});
