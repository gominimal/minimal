#!/usr/bin/env bash
# Generate corpus seeds for the `archive_extract` fuzz target.
#
# Why this exists: an unseeded byte fuzzer spends ~10^7 executions before it
# constructs a valid ustar header, so it never reaches the entry-path and
# strip_prefix logic that carried #651. Real tarballs get it there in one
# execution. See docs/fuzzing.md "Corpus seeding".
#
# The seed format matches the target's input layout:
#   byte 0 = compression selector (mod 5), byte 1 = strip_prefix selector
#   (mod 4), rest = archive body.
#
# Usage: crates/common/fuzz/scripts/gen-seeds.sh [outdir]
#        (defaults to crates/common/fuzz/seeds/archive_extract)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/../seeds/archive_extract}"
mkdir -p "$out"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# ---------------------------------------------------------------------------
# Build the payload trees. Each becomes a tarball; the interesting ones are
# the shapes an attacker would actually send.
# ---------------------------------------------------------------------------

# plain: an ordinary nested source tree, the common case.
mkdir -p "$work/plain/pkg/src"
printf 'fn main() {}\n' > "$work/plain/pkg/src/main.rs"
printf 'name = "x"\n'   > "$work/plain/pkg/Cargo.toml"

# deep: exercises recursive dir creation and longer entry paths.
mkdir -p "$work/deep/pkg/a/b/c/d"
printf 'leaf\n' > "$work/deep/pkg/a/b/c/d/leaf.txt"

# links: symlinks, including one escaping the root. `tar` records the link
# target verbatim, so this is a genuine traversal attempt on extract.
mkdir -p "$work/links/pkg"
printf 'data\n' > "$work/links/pkg/real.txt"
ln -s real.txt        "$work/links/pkg/rel.link"
ln -s ../../../etc/passwd "$work/links/pkg/escape.link"
ln -s /etc/passwd     "$work/links/pkg/abs.link"

# modes: setuid/exec bits and an empty file, for the permission path.
mkdir -p "$work/modes/pkg"
printf '#!/bin/sh\n' > "$work/modes/pkg/run.sh"
chmod 4755 "$work/modes/pkg/run.sh"
: > "$work/modes/pkg/empty"

trees=(plain deep links modes)

# ---------------------------------------------------------------------------
# Emit one seed per (tree x compression x strip_prefix) combination.
# ---------------------------------------------------------------------------

# Compression selector values must match the target's `control[0] % 5` arm
# order: 0 none, 1 gzip, 2 zstd, 3 xz, 4 bz2.
emit() {
    local name="$1" comp_sel="$2" strip_sel="$3" tarball="$4"
    local dest="$out/${name}_c${comp_sel}_s${strip_sel}"
    printf '%b' "$(printf '\\x%02x\\x%02x' "$comp_sel" "$strip_sel")" > "$dest"
    cat "$tarball" >> "$dest"
}

# ---------------------------------------------------------------------------
# Normalized tar metadata. Without this, `tar` stamps each entry with the
# generating host's uid/gid AND the local account names (uname/gname), which
# then get committed — a public repo should not carry whoever ran the script.
# It also makes regeneration non-reproducible, since mtimes and readdir order
# vary per host.
#
# GNU tar and bsdtar (macOS) spell these differently, so pick per flavour.
# Byte-identical output ACROSS the two implementations is not guaranteed
# (padding and entry ordering differ); regenerate on one flavour consistently
# if the committed bytes need to be stable.
# ---------------------------------------------------------------------------
umask 022
export LC_ALL=C
if tar --version 2>&1 | head -1 | grep -qi 'gnu'; then
    tar_norm=(--format=ustar --sort=name --mtime='UTC 1970-01-01'
              --owner=0 --group=0 --numeric-owner)
else
    # bsdtar/libarchive: no --sort/--owner/--group; --uname/--gname blank the
    # names, --numeric-owner keeps them out of the header entirely.
    tar_norm=(--format=ustar --uid 0 --gid 0 --uname '' --gname ''
              --numeric-owner)
fi

for tree in "${trees[@]}"; do
    base="$work/$tree.tar"
    # Fixed mtime on the sources too: bsdtar has no --mtime for create.
    find "$work/$tree" -exec touch -t 197001010000 {} + 2>/dev/null || true
    tar "${tar_norm[@]}" -C "$work/$tree" -cf "$base" .

    gzip  -kfn "$base"                    # -> .tar.gz  (-n: no timestamp)
    zstd  -qf  "$base" -o "$base.zst"
    xz    -kfq "$base"                    # -> .tar.xz
    bzip2 -kfq "$base"                    # -> .tar.bz2

    # strip_prefix selectors: 0 None, 1 ".", 2 "pkg", 3 "..". Seed every
    # prefix against the uncompressed tar (cheapest to mutate), and the
    # "." prefix against each compressed form so all five decompressor
    # branches get a structurally valid entry point.
    for s in 0 1 2 3; do
        emit "$tree" 0 "$s" "$base"
    done
    emit "$tree" 1 1 "$base.gz"
    emit "$tree" 2 1 "$base.zst"
    emit "$tree" 3 1 "$base.xz"
    emit "$tree" 4 1 "$base.bz2"
done

echo "wrote $(find "$out" -type f | wc -l) seeds to $out"
