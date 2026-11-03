#!/usr/bin/env bash
#
# build-pkg.sh — build the macOS system install: a component package that
# installs minimal machine-wide under /usr/local and does the privileged
# setup in its postinstall (gominimal/inbox#1179).
#
# The payload is a released artifact set, the same files the curl installer
# downloads, placed where a system install keeps them:
#
#   manifest prefix   package path                  what
#   bin/              /usr/local/bin/               min, minvmd, gvproxy-min,
#                                                   git-remote-min -> min, Minimal.app,
#                                                   bep.app and bep -> into it
#   lib/              /usr/local/lib/               libkrun.1.dylib (minvmd's rpath
#                                                   finds it beside bin/)
#   data/             /usr/local/share/minimal/     vmlinuz, rootfs.img, initramfs.cpio
#                                                   (minvmd looks here after the
#                                                   user's own data dir)
#                     /usr/local/share/minimal/     uninstall.sh (macOS has no
#                                                   package uninstall), pkg-info
#                     /usr/local/share/zsh/site-functions/_min, and the bash and
#                     fish completions, printed by the payload's own min
#
# Scripts (packaging/macos/pkg/scripts/): preinstall stops the privileged
# services of an earlier install, postinstall does what `min finalize-install`
# does for a user, with nobody logged in, and the box-name service under the
# role account `_minimal`; uninstall.sh undoes all of it and removes the
# receipt.
#
# Usage:
#   packaging/macos/pkg/build-pkg.sh (--version V | --channel stable|unstable)
#                                    [--with <manifest dest>=<path>]...
#                                    [--sign "<Developer ID Installer identity>"]
#                                    [--out DIR]
#
#   --version V      The staged release to package (versions/V/ in the bucket).
#   --channel C      Resolve V from a channel pointer (stable, unstable).
#   --with D=P       Replace the artifact at manifest dest D (bin/min,
#                    bin/minvmd, bin/bep, bin/Minimal.app for the whole bundle)
#                    with the local file or directory P: a build of this
#                    tree, for testing before it is released. bin/bep is a
#                    link into the release's bep.app; a replacement is a
#                    plain program there, and the bundle stays. A package with
#                    replacements is a test build: pkg-info says so, and the
#                    postinstall accepts any valid signature on the bundle
#                    instead of requiring minimal's Developer ID.
#   --sign IDENTITY  productsign the package with a Developer ID Installer
#                    identity. Without it the package is unsigned: Gatekeeper
#                    refuses it on a double-click, `installer -pkg` as root
#                    takes it. Notarization (notarytool, stapler) is the
#                    release workflow's step, after signing.
#   --out DIR        Where the package is written (default: target/pkg).
#
# Requires: curl, shasum, pkgbuild, productbuild, codesign (Xcode CLT).
# Env: MINIMAL_OVERRIDE_INSTALLER_BUCKET overrides the bucket, as for the
# installer.
#
set -euo pipefail

die() {
    printf 'build-pkg: %s\n' "$1" >&2
    exit 1
}
usage() {
    sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SCRIPTS_SRC="$ROOT/packaging/macos/pkg/scripts"
BUCKET="${MINIMAL_OVERRIDE_INSTALLER_BUCKET:-https://storage.googleapis.com/minimal-one}"
ID=dev.minimal.min
VERSION=""
CHANNEL=""
OUT="$ROOT/target/pkg"
SIGN=""
declare -a WITH=()

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
        --channel) CHANNEL="${2:?--channel needs a value}"; shift 2 ;;
        --with) WITH+=("${2:?--with needs dest=path}"); shift 2 ;;
        --sign) SIGN="${2:?--sign needs an identity}"; shift 2 ;;
        --out) OUT="${2:?--out needs a directory}"; shift 2 ;;
        -h|--help) usage 0 ;;
        *) die "unknown argument $1 (see --help)" ;;
    esac
done
[ "$(uname -s)" = Darwin ] || die "this builds a macOS package; run it on macOS"
[ "$(uname -m)" = arm64 ] || die "the package carries the darwin/arm64 artifact set; build it on Apple Silicon"
for tool in curl shasum pkgbuild productbuild codesign xattr; do
    command -v "$tool" >/dev/null || die "$tool is not on PATH"
done
if [ -n "$CHANNEL" ]; then
    [ -z "$VERSION" ] || die "give --version or --channel, not both"
    case "$CHANNEL" in stable|unstable) ;; *) die "--channel takes stable or unstable" ;; esac
    VERSION="$(curl --proto '=https' --tlsv1.2 -fsSL "$BUCKET/$CHANNEL")" \
        || die "could not read the $CHANNEL pointer from $BUCKET"
    VERSION="${VERSION//[[:space:]]/}"
fi
[ -n "$VERSION" ] || die "give --version V or --channel stable|unstable (see --help)"
case "$VERSION" in
    *[!A-Za-z0-9._-]*|'') die "version '$VERSION' has characters a bucket path cannot carry" ;;
esac

# The bill of materials records the staging tree's modes, and the installer
# applies them, to /usr/local/bin and the other directories that exist
# already: the builder's umask must not reach a Mac.
umask 022
work="$(mktemp -d "${TMPDIR:-/tmp}/minimal-pkg.XXXXXX")"
trap 'rm -rf "$work"' EXIT
root="$work/root"
scripts="$work/scripts"
mkdir -p "$root/usr/local/bin" "$root/usr/local/lib" "$root/usr/local/share/minimal" "$scripts"

# --- 1. The artifact set, from the components manifest ---------------------
# Rows: component os arch version sha256 kind dest src. The prefix token in
# dest is the installer's (bin, lib, data); a system install maps it to
# /usr/local. Every file is checksum-checked against the manifest, as the
# installer does.
manifest="$work/components"
curl --proto '=https' --tlsv1.2 -fsSL "$BUCKET/versions/$VERSION/components" -o "$manifest" \
    || die "no components manifest at $BUCKET/versions/$VERSION/components (is $VERSION staged?)"
prefix_dir() {
    case "$1" in
        bin) printf '%s\n' "$root/usr/local/bin" ;;
        lib) printf '%s\n' "$root/usr/local/lib" ;;
        data) printf '%s\n' "$root/usr/local/share/minimal" ;;
        *) die "component with an unknown dest prefix '$1'" ;;
    esac
}
rows=0
while read -r comp os arch _ want kind dest src; do
    [ -n "$comp" ] || continue
    [ "$os" = darwin ] && [ "$arch" = arm64 ] || continue
    prefix="${dest%%/*}"
    subpath="${dest#*/}"
    case "$subpath" in ''|/*|..|../*|*/..|*/../*) die "component $comp has an unsafe dest '$dest'" ;; esac
    target="$(prefix_dir "$prefix")/$subpath"
    mkdir -p "$(dirname "$target")"
    case "$kind" in
        file)
            echo "==> $comp -> /usr/local/${target#"$root"/usr/local/}"
            curl --proto '=https' --tlsv1.2 -fsSL "$BUCKET/$src" -o "$target" || die "download of $src failed"
            got="$(shasum -a 256 "$target" | cut -d' ' -f1)"
            [ "$got" = "$want" ] || die "$comp: sha256 $got, the manifest says $want"
            case "$dest" in bin/*) chmod 0755 "$target" ;; *) chmod 0644 "$target" ;; esac
            ;;
        symlink)
            echo "==> $comp -> /usr/local/${target#"$root"/usr/local/} (symlink to $src)"
            ln -sfn "$src" "$target"
            ;;
        *) die "component $comp has an unknown kind '$kind'" ;;
    esac
    rows=$((rows + 1))
done <"$manifest"
[ "$rows" -gt 0 ] || die "the manifest for $VERSION has no darwin/arm64 rows"
# The bundle's program is the only executable inside it; the rest are data.
chmod 0755 "$root/usr/local/bin/Minimal.app/Contents/MacOS/minzoned" 2>/dev/null || true

# --- 2. Local replacements: a test build of this tree ----------------------
test_build=0
for pair in ${WITH[@]+"${WITH[@]}"}; do
    dest="${pair%%=*}"
    path="${pair#*=}"
    [ "$dest" != "$pair" ] && [ -n "$path" ] || die "--with takes dest=path, got '$pair'"
    [ -e "$path" ] || die "--with $dest: $path does not exist"
    case "$dest" in
        bin/min|bin/minvmd|bin/bep|bin/Minimal.app) ;;
        *) die "--with takes bin/min, bin/minvmd, bin/bep or bin/Minimal.app (the whole bundle), not $dest" ;;
    esac
    prefix="${dest%%/*}"
    subpath="${dest#*/}"
    target="$(prefix_dir "$prefix")/$subpath"
    echo "==> replacing $dest with $path"
    rm -rf "$target"
    if [ -d "$path" ]; then
        cp -R "$path" "$target"
        chmod -R u=rwX,go=rX "$target"
    else
        cp "$path" "$target"
        case "$dest" in bin/*) chmod 0755 "$target" ;; esac
    fi
    # A minvmd built here links libkrun by the build prefix; the shipped
    # layout is bin/minvmd beside lib/libkrun.1.dylib, which the release
    # rewrites to (release.yml) and signs after, as the rewrite drops the
    # signature. The same two steps here, with the hypervisor entitlement
    # and an ad-hoc identity.
    if [ "$dest" = bin/minvmd ]; then
        "$ROOT/scripts/rewrite-macos-linkage.sh" "$target"
        codesign --entitlements "$ROOT/crates/minvmd/minvmd.entitlements" --force -s - "$target"
    fi
    test_build=1
done

# A replaced bundle comes from build-app-bundle.sh, which never signs; the
# postinstall copies only a signed bundle, so a test build's is ad-hoc signed
# here, with the identifier the release signs it under. So is a released
# bundle whose signature a replacement broke.
bundle="$root/usr/local/bin/Minimal.app"
if [ "$test_build" -eq 1 ] && ! codesign --verify --strict "$bundle" 2>/dev/null; then
    echo "==> ad-hoc signing the replaced bundle"
    codesign --force -s - --identifier dev.minimal.minzoned "$bundle"
fi

# --- 3. What the package adds: completions, the uninstaller, pkg-info ------
min="$root/usr/local/bin/min"
[ -x "$min" ] || die "the payload has no executable at bin/min"
version="$("$min" --version 2>/dev/null | sed -n 's/^min //p')"
[ -n "$version" ] || die "the payload's min --version said nothing (a build for another machine?)"
mkdir -p "$root/usr/local/share/zsh/site-functions" \
    "$root/usr/local/share/bash-completion/completions" \
    "$root/usr/local/share/fish/vendor_completions.d"
"$min" completions print zsh >"$root/usr/local/share/zsh/site-functions/_min"
"$min" completions print bash >"$root/usr/local/share/bash-completion/completions/min"
"$min" completions print fish >"$root/usr/local/share/fish/vendor_completions.d/min.fish"
install -m 0755 "$SCRIPTS_SRC/uninstall.sh" "$root/usr/local/share/minimal/uninstall.sh"
install -m 0755 "$SCRIPTS_SRC/preinstall" "$scripts/preinstall"
install -m 0755 "$SCRIPTS_SRC/postinstall" "$scripts/postinstall"

# The bundle's signature decides what the postinstall requires of it: a
# released bundle carries minimal's Developer ID and the postinstall checks
# for exactly that before anything names it under /Library; a test build's
# bundle is ad-hoc signed, and the postinstall checks for a valid signature.
requirement='=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "3G47C5HY64" and identifier "dev.minimal.minzoned"'
if codesign --verify --strict -R "$requirement" "$bundle" 2>/dev/null; then
    bundle_signing=developer-id
else
    codesign --verify --strict "$bundle" 2>/dev/null || die "the bundle at bin/Minimal.app has no valid signature"
    bundle_signing=ad-hoc
    [ "$test_build" -eq 1 ] || die "the released bundle does not carry minimal's Developer ID; refusing to package it"
    echo "==> test build: the bundle is ad-hoc signed; the postinstall will accept any valid signature"
fi
{
    echo "version=$version"
    echo "release=$VERSION"
    echo "channel=$CHANNEL"
    echo "bundle_signing=$bundle_signing"
    echo "test_build=$test_build"
    echo "built=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$root/usr/local/share/minimal/pkg-info"
chmod 0644 "$root/usr/local/share/minimal/pkg-info"

# macOS 27 stamps com.apple.provenance on every file written; cleared so the
# bill of materials carries no AppleDouble entries.
xattr -rc "$root" 2>/dev/null || true

# --- 4. The package ---------------------------------------------------------
mkdir -p "$OUT"
component="$work/minimal-component.pkg"
pkg="$OUT/minimal-$version.pkg"
if [ "$test_build" -eq 1 ]; then
    # Never the name a release has: a test build signed and passed on
    # would otherwise be told apart from a release by nothing.
    pkg="$OUT/minimal-$version-test.pkg"
    [ -z "$SIGN" ] || echo "==> note: signing a TEST BUILD; its service program is ad-hoc signed" >&2
fi
echo "==> pkgbuild $ID $version"
# pkgbuild prints "write: Permission denied" lines on macOS 27 and still exits
# 0 with a good package (a one-file root reproduces it); dropped.
pkgbuild --quiet --root "$root" --identifier "$ID" --version "$version" --install-location / \
    --scripts "$scripts" "$component" 2> >(grep -v '^write: Permission denied$' >&2)
if [ -n "$SIGN" ]; then
    echo "==> productbuild, signed by $SIGN"
    productbuild --quiet --package "$component" --sign "$SIGN" "$pkg"
else
    echo "==> productbuild, unsigned"
    productbuild --quiet --package "$component" "$pkg"
fi
du -h "$pkg"
echo "receipt $ID $version, release $VERSION, bundle $bundle_signing$( [ "$test_build" -eq 1 ] && echo ', TEST BUILD')"
echo "install: sudo installer -pkg $pkg -target /"
echo "remove:  sudo /usr/local/share/minimal/uninstall.sh"
