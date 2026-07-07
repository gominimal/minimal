#![no_main]

//! Structure-aware round-trip differential for the graph wire format.
//!
//! Builds a *valid* `Graph` of a fuzzer-chosen shape and asserts
//! `from_bytes(to_bytes(g))` preserves every spec (name + spec-hash) and the
//! top-level count. It catches encoder/decoder asymmetries — arena-index
//! remapping, top-level references, checksum framing — that a byte-level
//! fuzzer can't practically construct.
//!
//! The graph is built inside the `graph` crate (`fuzz_roundtrip`, behind its
//! `fuzzing` feature) because `BuildSpec`/`insert_build` aren't public.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    graph::Graph::fuzz_roundtrip(data);
});
