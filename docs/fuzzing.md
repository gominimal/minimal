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
| `remote_index_from_reader` | `crates/rcache/fuzz` | `IndexFile::from_reader` — `index.shisha`, the remote-cache index fetched over GCS/HTTPS | NET | **Linux only** |
| `spec_hash_from_hex` | `crates/common/fuzz` | `SpecHash::from_hex` — blake3 hex from cache keys / wire payloads | NET | any |
| `target_from_str` | `crates/common/fuzz` | `Target::from_str` — hand-written `<arch>/<os>` parser | OWN | any |
| `mfile_from_toml` | `crates/mfile/fuzz` | `File::from_toml_bytes` — `minimal.toml` through the custom serde visitors | OWN | any |
| `arg_schema_parse` | `crates/args/fuzz` | `ArgSchema::try_from` — hand-written schema/bracketed-list parser | OWN | any |
| `jq_parse_json` | `crates/common/fuzz` | `jq::parse_file` (JSON branch) — build-time project data files | SUPPLY | any |
| `graph_roundtrip` | `crates/graph/fuzz` | structure-aware round-trip differential: `from_bytes(to_bytes(g)) == g` over arbitrary graphs | — | any |
| `archive_extract` | `crates/common/fuzz` | `archive::extract_compressed_tar` — tar behind five decompressors, the path build sources, OCI layers, and remote-cache artifacts all take | NET, SUPPLY | any |
| `path_invariants` | `crates/paths/fuzz` | the realm-tagged path constructors — a differential asserting every route to a `RelPath` enforces the same no-`..` rule | NET | any |

`remote_index_from_reader` builds only on Linux: `rcache` depends on `lcache`,
which uses `common::renameat2` (a Linux-only syscall wrapper). This is one more
reason to run the campaign on a Linux box — some targets can't build anywhere
else.

## Running

```sh
just fuzz-check                                   # type-check every target (stable, no nightly)
just fuzz graph graph_from_bytes -max_total_time=600
```

`just fuzz-check` is the **bitrot guard** — see [Keeping the targets
alive](#keeping-the-targets-alive). `just fuzz <crate> <target> [libfuzzer
args]` wraps the raw invocation below and applies the RSS cap for you.

Equivalently, from the crate that owns the `fuzz/` dir:

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

Committed seeds live in `crates/graph/fuzz/seeds/` and
`crates/common/fuzz/seeds/<target>/`. Load them before a run:

```sh
mkdir -p crates/graph/fuzz/corpus/graph_from_bytes
cp crates/graph/fuzz/seeds/* crates/graph/fuzz/corpus/graph_from_bytes/

mkdir -p crates/common/fuzz/corpus/archive_extract
cp crates/common/fuzz/seeds/archive_extract/* crates/common/fuzz/corpus/archive_extract/
```

`archive_extract` is the clearest measurement of what seeding buys. Two 15
minute runs, same target, same four cores — the only difference was 32 seed
files:

| | unseeded | seeded |
|---|---|---|
| Coverage (edges) | 1029 | 4141 |
| Corpus | 156 | 1225 |
| Bugs found | 0 | 1 |

Unseeded, the fuzzer burned ~7M executions before it first constructed a valid
ustar header, and never got past it. Seeded, it started inside the entry-path
and `strip_prefix` logic and found the symlink bug in the track record below.

Its seeds are generated, not hand-written — `crates/common/fuzz/scripts/gen-seeds.sh`
builds tarballs with the system `tar` across every compression and
`strip_prefix` selector, including adversarial payload trees (escaping
symlinks, absolute-target symlinks, setuid bits). Regenerate with:

```sh
crates/common/fuzz/scripts/gen-seeds.sh
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

## Keeping the targets alive

Every `fuzz/` dir declares its own `[workspace]`, so the nightly + sanitizer
build can't perturb the main workspace. The cost of that isolation: **no
workspace-wide build ever compiles these targets**, so they rot silently as the
crates they fuzz evolve. This is not hypothetical — the first version of this
suite went 253 commits before anyone rebuilt it, by which point one target
referenced a type that had been renamed.

`just fuzz-check` is the guard. It runs a plain `cargo check` over every fuzz
workspace: no nightly, no sanitizer, no libFuzzer runtime — just "does this
still compile against today's API." Run it after changing any fuzzed decoder,
and treat a red `fuzz-check` exactly like a red build.

Rules of thumb when a target stops compiling:

- **The fuzzed API moved** — update the harness; that is the whole point of
  the guard firing.
- **The harness needs a new hook into the crate** — prefer a `#[doc(hidden)]`
  export or a `fuzzing`-gated entry point (as `graph` does for
  `Graph::fuzz_roundtrip`) over widening real public API.
- **A target is genuinely obsolete** — delete it, don't `#[allow]` it into
  silence. A target that doesn't build is worse than no target: it looks like
  coverage that isn't there.

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
| Escaping symlink created when no `strip_prefix` was set — the link-target check only ran on the `Some(..)` branch | `common::archive::extract_tar_impl` | this branch |
| `EitherPath::new` minted a `RelPath` containing `..`, forging the guarantee the daemon composer trusts for wire-supplied paths | `paths::EitherPath` | this branch |

## Reading the prose

Fuzzing is not the only tool, and it has not been the most productive one
here. The most serious finding of the last campaign — a remote arbitrary write
chaining the workspace uploader to the SFTP subsystem — came from **grepping
doc comments**, not from any target.

Two kinds of comment are worth searching for:

```sh
# 1. Comments asserting a containment or safety property. These are claims;
#    write the test the sentence implies and try to falsify it.
rg 'guarantees|cannot escape|must never|is proof|invariant|safe because' crates/*/src

# 2. Comments explaining a threat. These mean the threat is real and someone
#    thought hard about it — so check whether EVERY sibling path is covered.
rg 'untrusted|attacker|hostile|traversal|escapes the' crates/*/src
```

The second is the higher-yield one, for an uncomfortable reason: **a good
security comment marks where an author's attention was — and where it
stopped.** Every finding so far has had the same shape, two sibling paths to
one operation with only one of them hardened:

| Hardened | Unhardened sibling |
|---|---|
| `extract_tar_impl` with a `strip_prefix` | the same function without one |
| `RelPath::try_new` | `EitherPath`'s struct literal |
| `unpack_workspace_patches` ("the client is untrusted so we re-check") | `unpack_workspace_files` |

None was a case of the threat being unknown. Each was knowledge that failed to
reach the function next door. When you find a careful defence, the next
question is *what else does this?* — and that is a grep, not a fuzz target.

Two corollaries for target design, both learned by getting them wrong:

- **Match the oracle to the bug class.** All of the above are silent: no panic,
  no sanitizer trip. A panic-only target watches them happen and reports
  success. `assert_contained` in `archive_extract` exists for that reason — and
  was itself blind to hardlink *inode* escapes, because a hardlink's path
  really is inside the tree. Ask what a successful exploit would look like on
  disk, then assert that it did not happen.
- **Assert what the code promises, not what you assume.** An idempotence check
  on `redact` fired immediately and wrongly: re-masking a placeholder is
  key-based redaction working as designed, and the module's stated asymmetry
  (false positives fine, false negatives not) permits it. The property that
  holds is monotonicity.

## Continuing the campaign

Ideas, roughly in value order, for follow-up on a beefy Linux box:

1. **Structure-aware harness** — derive `Arbitrary` for `Graph` and mutate
   fields instead of raw bytes, to reach the deep structural paths a byte
   fuzzer can't. Doubles as a round-trip differential:
   `from_bytes(to_bytes(g)) == g`.
2. **Richer seeds** — see [Corpus seeding](#corpus-seeding).
3. **More targets** — the `minimald-rpc` request enums and `decode`'s
   construction of packages/profiles/stacks from evaluated config are the
   meaningful surfaces left. Check the table above before adding one:
   `SpecHash`, `Target::from_str`, and `mfile::File` used to be listed here
   and have had targets for some time.

   Being *possible* to fuzz is not the same as being *worth* fuzzing. These
   were audited and deliberately skipped:

   | Surface | Why not |
   |---|---|
   | `lcache::ReadTracker::read_records` | Fixed-size records `read_exact`ed into a stack buffer — no length field to abuse. |
   | `lcache::EntryMeta::read_from` | Plain `serde_json_lenient::from_reader`; the serde_json parser it forks is fuzzed upstream far harder than we would. |
   | `switch` subnet/MAC math | `SwitchSubnet::new` constrains the prefix to `8..=29` so the reserved-address arithmetic cannot underflow; private fields and no `Deserialize` to bypass the constructor. |
   | `sessions::primitives` var names | Both the hand-written `Deserialize` and `FromStr` route through `try_new`; there is no second door. |
   | `minimald::net::wg` | `WgPublicKey::from_str` length-checks its `try_into`; `Ipv4Cidr` validates the prefix and special-cases `/0` in `mask()`. |
   | `minvmd::rpc_client` response decode | The defect there was a resource bound (an unbounded `read_to_end`), which a fuzzer cannot surface. Fixed with a cap instead. |

4. **Cheap multipliers** — a nightly CI fuzz job per target with a persisted
   corpus. (Dictionaries are done: see below.)

## Dictionaries

A target with a `crates/<crate>/fuzz/<target>.dict` gets it passed as
`-dict=` automatically by `just fuzz`. libFuzzer never loads one on its own,
so a dict that is not wired up is a dead file — the naming convention is what
wires it. Targets without one are unaffected; a dictionary only biases
mutation towards tokens that mean something to the parser.

Shipped so far: `arg_schema_parse`, `graph_from_bytes`, `jq_parse_json`,
`mfile_from_toml`.

Related: `minimal run mutants` mutation-tests `graph`'s wire decoder in the
Linux sandbox; surviving mutants pinpoint untested encode/decode branches.
