# Fuzzing

This repo fuzzes the **untrusted-input decoders** — the code that turns
attacker-influenced bytes into in-memory structures. Those are the sharpest
trust boundaries: a malformed input should return an error, never panic,
over-allocate, or slice out of bounds.

The campaign so far has found and fixed five bugs this way (see
[Track record](#track-record)). The harnesses and seeds below let you keep it
going — ideally on a beefy Linux box, where AddressSanitizer coverage is best.

## Prerequisites

Fuzzing needs a **nightly** toolchain (for `-Z sanitizer` + libFuzzer) and
[`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz):

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --locked
# Linux also needs clang/llvm for the sanitizer runtime:
#   Debian/Ubuntu: apt-get install clang llvm
```

macOS works for quick triage, but run real campaigns on **Linux** — ASan is
more complete there and you avoid the Apple-container overhead.

## Targets

Each target lives in a standalone fuzz workspace (its own `[workspace]` so the
nightly/sanitizer build doesn't perturb the main workspace).

| Target | Crate | Decodes | Trust | Platform |
|---|---|---|---|---|
| `graph_from_bytes` | `crates/graph/fuzz` | `Graph::from_bytes` — the build-graph wire format shipped over the remote-execution channel | NET | any |
| `remote_index_from_reader` | `crates/rcache/fuzz` | `RemoteIndex::from_reader` — the remote-cache binary index fetched over GCS/HTTPS | NET | **Linux only** |

`remote_index_from_reader` builds only on Linux: `rcache` depends on `lcache`,
which uses `common::renameat2` (a Linux-only syscall wrapper). This is one more
reason to run the campaign on a Linux box — some targets can't build anywhere
else.

## Running

From the crate that owns the `fuzz/` dir:

```sh
cd crates/graph
cargo +nightly fuzz run graph_from_bytes -- -max_total_time=600 -rss_limit_mb=2048
```

- **`-rss_limit_mb=2048` is load-bearing.** These decoders can allocate from an
  untrusted length/count field; the RSS cap turns an unbounded-allocation bug
  into a catchable crash instead of an ambient OOM that just kills the box.
- Crashing inputs are written to `fuzz/artifacts/<target>/`; the growing corpus
  lives in `fuzz/corpus/<target>/`. Both are gitignored.

Reproduce, minimize, and inspect a crash:

```sh
cargo +nightly fuzz run graph_from_bytes fuzz/artifacts/graph_from_bytes/<crash-file>
cargo +nightly fuzz tmin graph_from_bytes fuzz/artifacts/graph_from_bytes/<crash-file>
xxd fuzz/artifacts/graph_from_bytes/<crash-file>
```

## Corpus seeding

A byte-level fuzzer struggles to build a *structurally valid* input from
scratch (valid header, correct blake3 checksums, well-formed nested records),
so it never reaches the deep decode paths. **Seeding the corpus with real,
valid inputs is what unlocks those paths** — seeding a valid graph-with-local-
file is exactly what surfaced the out-of-bounds slice panic (H1) that the
unseeded fuzzer missed.

Committed seeds live in `crates/graph/fuzz/seeds/`. Load them before a run:

```sh
mkdir -p crates/graph/fuzz/corpus/graph_from_bytes
cp crates/graph/fuzz/seeds/* crates/graph/fuzz/corpus/graph_from_bytes/
```

Generate new seeds from any code path that produces a valid encoding — build
the structure with the crate's own API and serialize it:

```rust
// e.g. in a throwaway #[test], write graph.to_bytes() to the corpus dir
let bytes = graph.to_bytes().unwrap();
std::fs::write("fuzz/corpus/graph_from_bytes/seed_myshape", &bytes).unwrap();
```

Good next seeds for `graph_from_bytes` (paths current seeds don't reach):
profiles, stacks, supply-chain records, and cross-referenced specs (the
arena-remap / dangling-ref logic).

## Track record

Each fixed with a bounds/limit check and a regression test seeded from the
fuzzer's own crashing input:

| Finding | Where | Fix |
|---|---|---|
| Record-length OOM (6-byte input → 2.8 GB `vec![0u8; len]`) | `graph::wire::read_record` | #653 |
| `build_count` preallocation OOM (35-byte input → 280 GB) | `graph::wire` `Arena::with_capacity` | #653 |
| Local-file offset out-of-bounds slice panic | `graph::wire::materialize_local_file` | #656 |
| Local-file filename `..`/absolute traversal | `graph::wire::materialize_local_file` | #656 |
| Tar `strip_prefix` path traversal (supply-chain arbitrary write) | `common::archive` | #651 |

## Continuing the campaign

Ideas, roughly in value order, for follow-up on a beefy Linux box:

1. **Structure-aware harness** — derive `Arbitrary` for `Graph` and mutate
   fields instead of raw bytes, to reach the deep structural paths a byte
   fuzzer can't. Doubles as a round-trip differential:
   `from_bytes(to_bytes(g)) == g`.
2. **Richer seeds** — see [Corpus seeding](#corpus-seeding).
3. **More targets** — `common::SpecHash`, `lcache::ReadTracker::read_records`,
   `toml::from_slice::<mfile::File>`, the `minimald-rpc` request enums,
   `common::Target::from_str`.
4. **Cheap multipliers** — a libFuzzer dictionary (the JSON keys + tag bytes
   `0x01`–`0x07`, `0xFF`), and a nightly CI fuzz job per target with a
   persisted corpus.

Related: `minimal run mutants` mutation-tests `graph`'s wire decoder in the
Linux sandbox; surviving mutants pinpoint untested encode/decode branches.
