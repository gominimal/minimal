#!/usr/bin/env bash
# Rewrite a Linux minvmd binary's libkrun linkage for the SHIPPED layout, then
# verify the result. The Linux twin of scripts/rewrite-macos-linkage.sh.
#
# The installer drops bin/minvmd beside lib/libkrun.so.1 (stage-release.sh's
# `lib/` row), so one RUNPATH has to be right:
#
#   minvmd -> $ORIGIN/../lib    finds lib/libkrun.so.1 from bin/
#
# build.rs already bakes `$ORIGIN` first plus the system lib dirs, and drops the
# ephemeral $LIBKRUN_PREFIX on a Linux --release build; this inserts the
# `../lib` entry after `$ORIGIN` and leaves the rest alone (so the system-libkrun
# fallback keeps working, and the list is not duplicated here).
#
# NOT libkrunfw: its purpose is to carry a bundled GPL-2 guest kernel, and
# minvmd supplies its own (`ctx.set_kernel`, from the shipped data/vmlinuz), so
# it is neither linked nor needed at runtime. macOS has shipped libkrun without
# it all along. Nothing here touches it.
#
# Verifies afterwards that:
#   - minvmd really links libkrun (not the stub) and its RUNPATH has $ORIGIN/../lib
#   - no ephemeral build path (a $HOME/.krun prefix) leaked into the RUNPATH
#   - libkrun's soname is exactly what stage-release.sh's `lib/` dest assumes
#
# A soname mismatch is a HARD failure: it means a libkrun major bump landed and
# the dest basename in stage-release.sh must change with it. Failing here beats
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

# Kept in lockstep with the `lib/` dest basename in scripts/stage-release.sh.
WANT_KRUN_SONAME="libkrun.so.1"

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

# --- libkrun ---------------------------------------------------------------

krun="$(resolve_real "$LIBDIR/$WANT_KRUN_SONAME")"
[ -f "$krun" ] || die "no $WANT_KRUN_SONAME under $LIBDIR (is the soname chain there?)"

got="$(patchelf --print-soname "$krun" || true)"
[ "$got" = "$WANT_KRUN_SONAME" ] \
    || die "$krun has soname '$got', expected '$WANT_KRUN_SONAME' (a major bump: update the lib/ dest in stage-release.sh)"

# The upstream .so carries whatever RUNPATH its own build host baked in, and it
# ships verbatim, so an absolute build path would reach users in a file nothing
# else in the pipeline inspects. Same check minvmd gets above.
libkrun_rpath="$(patchelf --print-rpath "$krun" || true)"
case "$libkrun_rpath" in
    *.krun*) die "$krun RUNPATH leaks an ephemeral build prefix: $libkrun_rpath" ;;
esac

echo "minvmd  RUNPATH: $rpath"
echo "libkrun RUNPATH: ${libkrun_rpath:-(none)}"
echo "soname: $WANT_KRUN_SONAME"
echo "linkage rewrite OK: $BIN"
