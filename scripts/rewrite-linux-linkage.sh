#!/usr/bin/env bash
# Rewrite a Linux minvmd binary + its libkrun pair for the SHIPPED layout, then
# verify the result. The Linux twin of scripts/rewrite-macos-linkage.sh.
#
# The installer drops bin/minvmd beside lib/libkrun.so.1 and lib/libkrunfw.so.5
# (stage-release.sh's `lib/` rows), so two RUNPATHs have to be right:
#
#   minvmd       -> $ORIGIN/../lib    finds lib/libkrun.so.1 from bin/
#   libkrun.so.1 -> $ORIGIN           finds its libkrunfw.so.5 SIBLING
#
# The second is not optional and not covered by the first: libkrun dlopen()s
# libkrunfw by soname, and glibc resolves a dlopen from a library against the
# RUNPATH of the *calling object*, never the executable's. Without it a shipped
# libkrun finds no libkrunfw and every VM boot fails on a host that has no
# system copy.
#
# build.rs already bakes `$ORIGIN` first plus the system lib dirs, and drops the
# ephemeral $LIBKRUN_PREFIX on a Linux --release build; this inserts the
# `../lib` entry after `$ORIGIN` and leaves the rest alone (so the system-libkrun
# fallback keeps working, and the list is not duplicated here).
#
# Verifies afterwards that:
#   - minvmd really links libkrun (not the stub) and its RUNPATH has $ORIGIN/../lib
#   - no ephemeral build path (a $HOME/.krun prefix) leaked into any RUNPATH
#   - the two sonames are exactly what stage-release.sh's `lib/` dests assume
#   - libkrun's RUNPATH has $ORIGIN
#
# A soname mismatch is a HARD failure: it means a libkrun major bump landed and
# the dest basenames in stage-release.sh must change with it. Failing here beats
# shipping an install whose minvmd cannot resolve its library.
#
# Usage: scripts/rewrite-linux-linkage.sh <minvmd-binary> <libkrun-dir>
#
# `$ORIGIN` is an ELF loader token, not a shell variable: every occurrence below
# is deliberately single-quoted so patchelf records it literally. Expanding it
# would bake this runner's absolute paths into the shipped binary.
# shellcheck disable=SC2016
set -euo pipefail

BIN="${1:?usage: rewrite-linux-linkage.sh <minvmd-binary> <libkrun-dir>}"
LIBDIR="${2:?usage: rewrite-linux-linkage.sh <minvmd-binary> <libkrun-dir>}"

# Kept in lockstep with the `lib/` dest basenames in scripts/stage-release.sh.
WANT_KRUN_SONAME="libkrun.so.1"
WANT_KRUNFW_SONAME="libkrunfw.so.5"

command -v patchelf >/dev/null 2>&1 || {
    echo "::error::patchelf not found (apt-get install patchelf)" >&2
    exit 1
}

die() {
    echo "::error::$1" >&2
    exit 1
}

# Resolve the real regular file behind a soname symlink chain
# (fetch-libkrun.sh copies the whole chain with `cp -a`).
resolve_real() {
    _p="$1"
    while [ -L "$_p" ]; do
        _l="$(readlink "$_p")"
        case "$_l" in
            /*) _p="$_l" ;;
            *) _p="$(dirname "$_p")/$_l" ;;
        esac
    done
    printf '%s\n' "$_p"
}

# --- minvmd ---------------------------------------------------------------

needed="$(patchelf --print-needed "$BIN")" || die "$BIN is not an ELF binary"
krun_needed="$(printf '%s\n' "$needed" | grep '^libkrun\.so' || true)"
[ -n "$krun_needed" ] \
    || die "$BIN has no libkrun DT_NEEDED; did it link the stub? (LIBKRUN_PREFIX unset at build time)"
[ "$krun_needed" = "$WANT_KRUN_SONAME" ] \
    || die "$BIN needs '$krun_needed' but stage-release.sh ships lib/$WANT_KRUN_SONAME; update both together"

current="$(patchelf --print-rpath "$BIN" || true)"
case ":$current:" in
    *":\$ORIGIN/../lib:"*)
        # Already rewritten — keep this idempotent so a re-run is safe.
        ;;
    *)
        # Insert after the leading $ORIGIN when build.rs put one there, else
        # prepend; either way the binary-relative entries stay ahead of the
        # system dirs so a shipped libkrun wins over a system one.
        case "$current" in
            '$ORIGIN'|'$ORIGIN:'*)
                new="\$ORIGIN:\$ORIGIN/../lib${current#\$ORIGIN}"
                ;;
            '') new='$ORIGIN:$ORIGIN/../lib' ;;
            *) new="\$ORIGIN/../lib:$current" ;;
        esac
        patchelf --set-rpath "$new" "$BIN"
        ;;
esac

rpath="$(patchelf --print-rpath "$BIN")"
case ":$rpath:" in
    *":\$ORIGIN/../lib:"*) ;;
    *) die "$BIN is missing the \$ORIGIN/../lib RUNPATH; lib/$WANT_KRUN_SONAME will not be found" ;;
esac
# build.rs drops the materialized prefix on a Linux release build; a leaked
# absolute path would resolve to a directory that exists only on the runner.
case "$rpath" in
    *.krun*) die "$BIN RUNPATH leaks an ephemeral build prefix: $rpath" ;;
esac

# --- libkrun + libkrunfw --------------------------------------------------

krun="$(resolve_real "$LIBDIR/$WANT_KRUN_SONAME")"
[ -f "$krun" ] || die "no $WANT_KRUN_SONAME under $LIBDIR (is the soname chain there?)"
krunfw="$(resolve_real "$LIBDIR/$WANT_KRUNFW_SONAME")"
[ -f "$krunfw" ] || die "no $WANT_KRUNFW_SONAME under $LIBDIR"

for lib in "$krun" "$krunfw"; do
    want="$WANT_KRUN_SONAME"
    case "$lib" in *krunfw*) want="$WANT_KRUNFW_SONAME" ;; esac
    got="$(patchelf --print-soname "$lib" || true)"
    [ "$got" = "$want" ] \
        || die "$lib has soname '$got', expected '$want' (a major bump: update the lib/ dests in stage-release.sh)"
done

# libkrun dlopen()s libkrunfw by soname; glibc searches the CALLING object's
# RUNPATH, so this entry is what makes the shipped sibling resolvable.
libkrun_rpath="$(patchelf --print-rpath "$krun" || true)"
case ":$libkrun_rpath:" in
    *':$ORIGIN:'*) ;;
    *)
        if [ -z "$libkrun_rpath" ]; then
            patchelf --set-rpath '$ORIGIN' "$krun"
        else
            patchelf --set-rpath "\$ORIGIN:$libkrun_rpath" "$krun"
        fi
        ;;
esac
libkrun_rpath="$(patchelf --print-rpath "$krun")"
case ":$libkrun_rpath:" in
    *':$ORIGIN:'*) ;;
    *) die "$krun is missing the \$ORIGIN RUNPATH; its dlopen of $WANT_KRUNFW_SONAME will not find the shipped sibling" ;;
esac

echo "minvmd  RUNPATH: $rpath"
echo "libkrun RUNPATH: $libkrun_rpath"
echo "sonames: $WANT_KRUN_SONAME, $WANT_KRUNFW_SONAME"
echo "linkage rewrite OK: $BIN"
