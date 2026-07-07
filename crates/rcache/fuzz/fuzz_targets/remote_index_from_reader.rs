#![no_main]

//! Fuzz the remote-cache binary index decoder.
//!
//! `RemoteIndex::from_reader` parses the cache index fetched over the network
//! (GCS/HTTPS) — a raw length/flags/sha256 wire format. It must return an
//! `io::Error` for any malformed input, never panic, over-allocate, or slice
//! out of bounds. Any crash here is a decoder bug reachable from a malicious or
//! compromised cache mirror.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = rcache::RemoteIndex::from_reader(&mut cursor);
});
