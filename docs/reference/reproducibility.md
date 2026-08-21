---
title: Build reproducibility
description: "How to make Minimal package builds byte-reproducible: the environment the sandbox provides, per-toolchain determinism flags for C/C++, Go, Rust and the Linux kernel, and how to verify."
---

# Build reproducibility

Two builds of the same [build spec](./build-specs.md) from the same source must produce
**byte-identical** output. Minimal's artifact cache is content-addressed: a package is
identified by the hash of its inputs, and the artifacts stored under that key are reused
everywhere the same key is resolved. A build that embeds a timestamp, a build path, or a
random ID produces a different artifact each time it runs, which makes the cached result
unverifiable — you can no longer confirm that what you fetched is what the spec describes.

Minimal makes the *environment* reproducible for you. Making the *compiler output*
reproducible is the build script's responsibility, and it is toolchain-specific.

For background and the full taxonomy of non-determinism in software builds, see
[reproducible-builds.org](https://reproducible-builds.org/).

## What the sandbox already provides

Package builds run in a hermetic, isolated [sandbox](../concepts/sandboxing.md) so the
machine running the build cannot leak into its result. The one thing the sandbox shares
with the outside world is network access, and only when a dependency calls for it — so a
build that reaches the network is reproducible only to the extent that what it fetches is
pinned. `Source` entries are pinned for you, because Minimal verifies them against the
`sha256` in the spec. Anything a build resolves for itself over the network — Go modules,
cargo crates, npm packages, all of which require an explicit
[`needs`](./build-specs.md) declaration — is an unpinned build input unless a committed
lockfile pins it.

Among the fixed environment the sandbox sets for every build are two variables that most
build systems honour:

| Variable | Value | Effect |
|---|---|---|
| `SOURCE_DATE_EPOCH` | `0` | The [standard](https://reproducible-builds.org/docs/source-date-epoch/) timestamp override. Build systems that respect it stamp this instead of the wall clock. |
| `PYTHONHASHSEED` | `0` | Pins Python's string-hash randomisation, so iteration order in build-time Python scripts is stable. |

Do **not** set either of these in your `build.sh`. They are already set, and
[`mip check`](./cli-mip.md#check) fails the package if it finds them being assigned —
the build-script audit reports `SOURCE_DATE_EPOCH=0 is already set by the build sandbox`.

## Per-toolchain recipes

Apply **only** the section matching your build system. These are alternatives, not a
checklist to run all of.

### C / C++

Strip the build directory out of debug info, stop recording the exact compiler
invocation, drop the linker's random build ID, and make `ar` write deterministic
archives:

```bash
export CFLAGS="${CFLAGS:-} -ffile-prefix-map=$(pwd)=/builddir -gno-record-gcc-switches"
export CXXFLAGS="${CXXFLAGS:-} -ffile-prefix-map=$(pwd)=/builddir -gno-record-gcc-switches"
export LDFLAGS="${LDFLAGS:-} -Wl,--build-id=none"
export ARFLAGS=Drc
```

Note the `${CFLAGS:-}` form: these determinism flags must be *added* to whatever
optimisation flags the package already sets, not substituted for them.

If you are building a package that ships its own `ar`/`ranlib` — binutils, or a
cross-binutils — also pass `--enable-deterministic-archives` to `./configure`, which makes
the tools it installs default to deterministic archives. It is a binutils configure
option, not general autotools determinism advice: other packages ignore it with an
`unrecognized options` warning, so `ARFLAGS=Drc` above is what actually does the work for
them.

With autotools, delete libtool archives after install — they embed absolute paths:

```bash
find "$OUTPUT_DIR" -name '*.la' -delete
```

### Go

Pass `-trimpath`, clear the build ID, and turn off VCS stamping on every `go build` and
`go install`:

```bash
go build -trimpath -buildvcs=false -ldflags "-buildid=" -o "$OUTPUT_DIR/usr/bin/my-tool" .
```

Set all three unconditionally. Go's default is `-buildvcs=auto`, which stamps commit
metadata whenever the main package, its module, and the working directory sit in the same
repository — and Go searches parent directories for that repository root, so it is not
enough to observe that the extracted source tree has no `.git` of its own. Passing
`-buildvcs=false` removes the question. Setting it once for the whole script works too:

```bash
export GOFLAGS="-trimpath -buildvcs=false"
```

### Rust

Remap both the build directory and the cargo registry path:

```bash
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$(pwd)=/builddir --remap-path-prefix=$HOME/.cargo=/cargo"
```

As with the C flags above, append rather than overwrite — a package that needs
`-C linker=gcc` still needs it after this line.

If two builds still differ in `.text` or `.rodata`, the remaining variation is usually
parallel codegen. Pin it:

```bash
export RUSTFLAGS="$RUSTFLAGS -C codegen-units=1"
```

If the crate graph pulls in [`const-random`](https://github.com/tkaitchuck/constrandom)
(commonly by way of `ahash`), it seeds a constant at compile time from system randomness,
which differs on every build. That crate reads its seed from the environment, so pin it
as well:

```bash
export CONST_RANDOM_SEED=0
```

This is that crate's own variable, not a `rustc` or Cargo setting — setting it does
nothing for a dependency tree that does not use `const-random`.

### Linux kernel

Kbuild stamps its own identity strings, which `SOURCE_DATE_EPOCH` does not cover:

```bash
export KBUILD_BUILD_TIMESTAMP=@0
export KBUILD_BUILD_USER=builder
export KBUILD_BUILD_HOST=minimal
```

Those three cover the timestamp, user and host only. Two further inputs bite in practice:

- **Build paths.** For an out-of-tree build, remap them in the assembler flags as well as
  the compiler flags, or the source directory ends up in the debug info:
  `export KCFLAGS="-ffile-prefix-map=$(pwd)=/builddir"` and the same value in `KAFLAGS`.
- **Module signing.** With `CONFIG_MODULE_SIG_ALL=y`, Kbuild generates a throwaway signing
  key when none is configured, so every module's signature differs between builds. Point
  `CONFIG_MODULE_SIG_KEY` at a stable key you supply, or turn the option off.

### Builds that stamp their own wall-clock time

Some build systems generate version strings or headers from the current time without
consulting `SOURCE_DATE_EPOCH`. Pin that specific stamp at its source — override the
variable the generator reads — rather than re-exporting `SOURCE_DATE_EPOCH`, which the
checker rejects.

For example, a package whose version header is generated by make variables holding a
date and a build time can override both: derive the date from `$SOURCE_DATE_EPOCH` and
set the build-time variable to empty so the time is omitted entirely.

## Verifying

Build the package twice and compare the two `$OUTPUT_DIR` trees. They must be
byte-for-byte identical.

Force both runs to actually build. By default a build is served from the binary cache
when a matching artifact exists, so a plain second `mip package build` can hand back the
first run's artifact and the comparison proves nothing:

```bash
mip --no-cache --no-fetch package build <name> --rebuild
```

[`--no-cache`](./cli-mip.md) ignores locally-available artifacts, `--no-fetch` stops
Minimal fetching them from the remote cache, and `--rebuild` builds the named packages
even when they are already available. Keep the tree each run produces, then compare them:

```bash
diff -r first-output/ second-output/
```

When they differ, the diff names the cause. Common signatures and their fixes:

| Symptom in the diff | Cause | Fix |
|---|---|---|
| An embedded date or time string | Build stamps the wall clock | Pin the generator's own date variable |
| An absolute path under the build directory | Path baked into debug info or an `.la` file | `-ffile-prefix-map` / `--remap-path-prefix`; delete `*.la` |
| A differing `.note.gnu.build-id` section | Linker-generated random build ID | `LDFLAGS="-Wl,--build-id=none"` |
| Differing member order or timestamps in a `.a` | Non-deterministic `ar` | `ARFLAGS=Drc` |
| Varying uid/gid on extracted files | Extraction restored the archive's recorded ownership | Extract with `tar -xof` |
| Varying mtime on installed files | A step stamped the wall clock onto files it wrote | Normalise explicitly, e.g. `find "$OUTPUT_DIR" -exec touch -hd @"$SOURCE_DATE_EPOCH" {} +` |

`mip check`'s build-script audit flags plain `tar -xf` and directs you to `tar -xof`. Note
what that fixes and what it does not: `-o` is `--no-same-owner`, so it only settles
ownership. Extraction still restores each member's recorded mtime — which is itself fine,
because those timestamps are fixed by the archive's content. Wall-clock mtimes come from
build steps that write files, which is why the two rows above have different fixes.

## See also

- [Build specs](./build-specs.md) — the schema a package is declared with.
- [Packages](../concepts/packages.md) — how built artifacts are cached and reused.
- [`mip check`](./cli-mip.md#check) — runs the build-script audit described here.
