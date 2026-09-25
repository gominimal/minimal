#!/usr/bin/env bash
#
# package-version_test.sh — test harness for scripts/package-version.sh.
#
# Asserts the per-format normalization table, that a released semver is the
# identity in every format (the guarantee that keeps the stable nfpm packages
# byte-identical), and the refusals. When the real package managers are on
# PATH it additionally PROVES the ordering claims empirically — dpkg for the
# deb `~` rule and apk for the apk shape — and skips those checks where the
# tool is absent, so a dev host without them still exercises the strings. Run
# directly or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/package-version.sh"
[ -f "$script" ] || { echo "cannot find package-version.sh next to test" >&2; exit 1; }
# shellcheck disable=SC1091  # dynamic path: testlib.sh sits beside this harness
. "$here/testlib.sh"

# normalize <format> <version> — the script's stdout, or empty on failure.
normalize() { "$script" --format "$1" "$2" 2>/dev/null; }

# want <format> <input> <expected>
want() {
    local fmt="$1" in="$2" exp="$3" out
    out="$(normalize "$fmt" "$in")"
    if [ "$out" = "$exp" ]; then ok "$fmt: $in -> $exp"; else bad "$fmt: $in -> want '$exp', got '$out'"; fi
}

# --- the normalization table --------------------------------------------------

DEV=0.6.0-dev.10.g8e7e72c2
want deb  "$DEV" 0.6.0~dev.10.g8e7e72c2
want rpm  "$DEV" 0.6.0~dev.10.g8e7e72c2
# apk cannot express the `dev` word or the git hash, so the dev tail becomes
# `_pre<N>`: a below-release suffix that keeps the series ordered. See the
# script header for why the hash is dropped.
want apk  "$DEV" 0.6.0_pre10
want aur  "$DEV" 0.6.0.dev.10.g8e7e72c2
want brew "$DEV" "$DEV"

# The prerelease-tag shape (a build past v0.6.0-rc1). apk collapses it to the
# same `_pre<N>`: a documented edge (the rc marker is lost).
RC=0.6.0-rc1.dev.4.gabc12345
want deb  "$RC" 0.6.0~rc1.dev.4.gabc12345
want apk  "$RC" 0.6.0_pre4
want aur  "$RC" 0.6.0.rc1.dev.4.gabc12345

# A plain prerelease (the rc tag itself) keeps its word on apk — `rc` is one of
# the suffixes apk already knows.
want apk 0.6.0-rc1 0.6.0_rc1

# A released semver is the identity in every format.
for fmt in deb rpm apk aur brew; do
    want "$fmt" 0.6.0 0.6.0
done

# Build metadata survives deb and brew; apk has no `+build` separator at all,
# so it refuses rather than shipping a package apk will not install (asserted
# under `refusals` below).
want deb  0.6.0-dev.10.g8e7e72c2+dirty 0.6.0~dev.10.g8e7e72c2+dirty
want brew 0.6.0+dirty 0.6.0+dirty

# --- empirical ordering, where the real tools exist ---------------------------

# deb: `~` must sort below the bare release, and a higher dev count above a
# lower one. dpkg is the only authority for this; skip where absent.
if command -v dpkg >/dev/null 2>&1; then
    a="$(normalize deb 0.6.0-dev.10.g8e7e72c2)"
    b="$(normalize deb 0.6.0-dev.9.gdeadbeef)"
    if dpkg --compare-versions "$a" gt "$b"; then ok "dpkg: $a sorts above $b"; else bad "dpkg: $a should sort above $b"; fi
    if dpkg --compare-versions "$a" lt 0.6.0; then ok "dpkg: $a sorts below the stable 0.6.0"; else bad "dpkg: $a should sort below 0.6.0"; fi
else
    echo "note - dpkg not on PATH; skipping the deb ordering proof"
fi

# apk: prove the channel shape is ACCEPTED and monotonic. This is the fiddliest
# normalization in the table — apk allows only a fixed suffix vocabulary and
# uses `-r<N>` as its own revision separator — so the shape is asserted against
# the real parser rather than trusted. `apk version -c` validates ONE version
# (`-t` compares two, and with one argument it always fails, which is how this
# check used to pass over an invalid shape). Skip where apk is absent.
if command -v apk >/dev/null 2>&1; then
    a="$(normalize apk 0.6.0-dev.10.g8e7e72c2)"
    b="$(normalize apk 0.6.0-dev.9.gdeadbeef)"
    if apk version -c "$a" >/dev/null 2>&1 && apk version -c "$b" >/dev/null 2>&1; then
        ok "apk accepts the channel version shape ($a)"
        if [ "$(apk version -t "$a" "$b")" = ">" ]; then ok "apk: $a sorts above $b"; else bad "apk: $a should sort above $b"; fi
        # `pre` must sort below the bare release, or enabling a channel suite
        # would silently upgrade a stable user.
        if [ "$(apk version -t "$a" 0.6.0)" = "<" ]; then ok "apk: $a sorts below the stable 0.6.0"; else bad "apk: $a should sort below 0.6.0"; fi
        rc_shape="$(normalize apk 0.6.0-rc1)"
        if apk version -c "$rc_shape" >/dev/null 2>&1; then ok "apk accepts the rc shape ($rc_shape)"; else bad "apk rejects the rc shape ($rc_shape)"; fi
    else
        bad "apk rejects the channel version shape ($a or $b) — see the apk mapping in the script header"
    fi
else
    echo "note - apk not on PATH; skipping the apk ordering proof"
fi

# --- refusals -----------------------------------------------------------------

expect 1 "unknown --format" "an unknown format is refused" -- "$script" --format msi 0.6.0
expect 1 "--format is required" "a missing format is refused" -- "$script" 0.6.0
expect 1 "VERSION is required" "a missing version is refused" -- "$script" --format deb
expect 1 "must not carry the v prefix" "a v-prefixed version is refused" -- "$script" --format deb v0.6.0
expect 1 "not a canonical" "a bare sha is refused" -- "$script" --format deb 8e7e72c2
expect 1 "not a canonical" "a two-part version is refused" -- "$script" --format deb 0.6
# apk alone has no `+build` separator: refusing beats shipping a package apk
# will not install.
expect 1 "not a valid apk version" "apk refuses build metadata (+dirty)" -- "$script" --format apk 0.6.0+dirty
# The plain-prerelease passthrough keeps any word, but apk only knows the fixed
# suffix vocabulary: a word outside it is refused here rather than by apk days
# later (the veto enforces the vocabulary its message names).
expect 1 "not a valid apk version" "apk refuses a non-vocabulary prerelease word" -- "$script" --format apk 0.6.0-next

finish
