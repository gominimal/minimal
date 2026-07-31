#![no_main]

//! Fuzz the remote-cache index decoder.
//!
//! `IndexFile::from_reader` parses `index.shisha` — the cache index fetched over
//! the network (GCS/HTTPS) as a raw `spec_hash | flags | sha256` record stream.
//! It must return an `io::Error` for any malformed input, never panic,
//! over-allocate, or slice out of bounds. Any crash here is a decoder bug
//! reachable from a malicious or compromised cache mirror.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = rcache::IndexFile::from_reader(&mut cursor);
});
