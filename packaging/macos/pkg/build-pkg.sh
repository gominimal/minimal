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
#                                    [--dmg [--sign-dmg "<Developer ID Application identity>"]]
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
#   --sign IDENTITY  Sign the product archive with a Developer ID Installer
#                    identity (productbuild --sign, timestamped). Without it
#                    the package is unsigned: Gatekeeper refuses it on a
#                    double-click, `installer -pkg` as root takes it. Refused
#                    on a test build: a signed package carries released code
#                    or nothing.
#   --notarize PROF  After signing, submit the package to Apple's notary
#                    service with the notarytool keychain profile PROF
#                    (`xcrun notarytool store-credentials PROF`), wait for the
#                    verdict, staple the ticket, and assess the result as
#                    Gatekeeper would (`spctl --assess --type install`). Needs
#                    --sign.
#   --dmg            Also write a disk image beside the package, for a
#                    download page: a read-only compressed volume named
#                    "Minimal" with the package alone at its top. A person
#                    opens the image and double-clicks the package; an MDM
#                    takes the package itself. With --notarize the image is
#                    notarized and stapled too, so a Mac offline at first
#                    open still sees the ticket.
#   --sign-dmg ID    Sign the disk image with a Developer ID Application
#                    identity (the one the binaries carry; a disk image is
#                    not an installer package, so the Installer identity
#                    does not apply). Optional: Gatekeeper judges the
#                    package inside on a double-click. Needs --dmg and
#                    --sign; refused on a test build as --sign is.
#   --min-os VER     The oldest macOS the package installs on (default 15.0,
#                    the first with the hypervisor minvmd needs on Apple
#                    Silicon). Installer refuses an older Mac before any
#                    script runs.
#   --out DIR        Where the package is written (default: target/pkg).
#
# The product archive carries its own Distribution: Apple Silicon only (the
# payload is darwin/arm64), the minimum macOS, the local-system domain only
# (never a home-directory install), and the two app bundles pinned in place
# (a component plist with BundleIsRelocatable false), so Installer never
# moves them to an older copy elsewhere on the disk.
#
# Requires: curl, shasum, pkgbuild, productbuild, codesign (Xcode CLT);
# hdiutil for --dmg; xcrun notarytool and stapler for --notarize.
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
NOTARIZE=""
MIN_OS="15.0"
DMG=0
SIGN_DMG=""
declare -a WITH=()

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
        --channel) CHANNEL="${2:?--channel needs a value}"; shift 2 ;;
        --with) WITH+=("${2:?--with needs dest=path}"); shift 2 ;;
        --sign) SIGN="${2:?--sign needs an identity}"; shift 2 ;;
        --notarize) NOTARIZE="${2:?--notarize needs a notarytool keychain profile}"; shift 2 ;;
        --dmg) DMG=1; shift ;;
        --sign-dmg) SIGN_DMG="${2:?--sign-dmg needs an identity}"; shift 2 ;;
        --min-os) MIN_OS="${2:?--min-os needs a version}"; shift 2 ;;
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
case "$MIN_OS" in
    [0-9]*.[0-9]*) ;;
    *) die "--min-os takes a version such as 15.0" ;;
esac
[ -z "$NOTARIZE" ] || [ -n "$SIGN" ] || die "--notarize needs --sign: Apple notarizes signed packages only"
[ -z "$SIGN_DMG" ] || [ "$DMG" -eq 1 ] || die "--sign-dmg needs --dmg"
[ -z "$SIGN_DMG" ] || [ -n "$SIGN" ] || die "--sign-dmg needs --sign: a signed image around an unsigned package would say more than is true"
[ "$DMG" -eq 0 ] || command -v hdiutil >/dev/null || die "hdiutil is not on PATH"
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
    # would otherwise be told apart from a release by nothing. And never
    # signed: a Developer ID on a package whose service program is ad-hoc
    # signed would say more than is true.
    pkg="$OUT/minimal-$version-test.pkg"
    [ -z "$SIGN" ] || die "refusing to sign a TEST BUILD (its service program is ad-hoc signed); sign a release build"
fi
# The bundles stay where the payload puts them. pkgbuild's own analysis
# marks every bundle relocatable, and Installer would then follow an older
# copy of the same bundle identifier elsewhere on the disk (a user's
# ~/.local/bin/Minimal.app from the curl installer, the service's copy
# under /Library/PrivilegedHelperTools) instead of writing /usr/local/bin.
# The analysis is kept and the one key turned off, for each bundle found.
components="$work/components.plist"
pkgbuild --quiet --analyze --root "$root" "$components" 2> >(grep -v '^write: Permission denied$' >&2)
i=0
while /usr/libexec/PlistBuddy -c "Print :$i:RootRelativeBundlePath" "$components" >/dev/null 2>&1; do
    # The analysis writes the key only when it is false already; absent
    # means pkgbuild's default, true.
    /usr/libexec/PlistBuddy -c "Set :$i:BundleIsRelocatable false" "$components" 2>/dev/null \
        || /usr/libexec/PlistBuddy -c "Add :$i:BundleIsRelocatable bool false" "$components"
    i=$((i + 1))
done
[ "$i" -ge 1 ] || die "pkgbuild --analyze found no bundle in the payload (expected usr/local/bin/Minimal.app)"
echo "==> pkgbuild $ID $version ($i bundle(s) pinned in place)"
# pkgbuild prints "write: Permission denied" lines on macOS 27 and still exits
# 0 with a good package (a one-file root reproduces it); dropped.
pkgbuild --quiet --root "$root" --identifier "$ID" --version "$version" --install-location / \
    --component-plist "$components" \
    --scripts "$scripts" "$component" 2> >(grep -v '^write: Permission denied$' >&2)
# The Distribution: synthesized from the component, then given what the
# synthesis leaves out. Apple Silicon only (the synthesis says
# x86_64,arm64 for any payload), the oldest macOS, the local system as the
# only install domain (no per-home install, which the scripts could not
# serve), a title for Installer's window.
distribution="$work/Distribution"
productbuild --quiet --synthesize --package "$component" "$distribution"
grep -q 'hostArchitectures="x86_64,arm64"' "$distribution" \
    || die "the synthesized Distribution has no hostArchitectures to narrow (productbuild changed?)"
sed -i '' \
    -e 's/hostArchitectures="x86_64,arm64"/hostArchitectures="arm64" rootVolumeOnly="true"/' \
    -e "s|<installer-gui-script minSpecVersion=\"1\">|&\\
    <title>Minimal</title>\\
    <domains enable_localSystem=\"true\"/>\\
    <volume-check><allowed-os-versions><os-version min=\"$MIN_OS\"/></allowed-os-versions></volume-check>|" \
    "$distribution"
if [ -n "$SIGN" ]; then
    echo "==> productbuild, signed by $SIGN"
    productbuild --quiet --distribution "$distribution" --package-path "$work" --timestamp --sign "$SIGN" "$pkg"
    echo "==> pkgutil --check-signature"
    pkgutil --check-signature "$pkg" || die "the signed package does not check out"
else
    echo "==> productbuild, unsigned"
    productbuild --quiet --distribution "$distribution" --package-path "$work" "$pkg"
fi
if [ -n "$NOTARIZE" ]; then
    echo "==> notarytool submit (profile $NOTARIZE), waiting for Apple"
    xcrun notarytool submit "$pkg" --keychain-profile "$NOTARIZE" --wait \
        || die "notarization did not succeed; xcrun notarytool log <id> --keychain-profile $NOTARIZE says why"
    echo "==> stapler staple"
    xcrun stapler staple "$pkg" || die "stapling failed"
    echo "==> spctl --assess --type install"
    spctl --assess --type install -vv "$pkg" || die "Gatekeeper does not accept the notarized package"
fi
du -h "$pkg"
# --- 5. The disk image, for a download page ---------------------------------
# One volume, one package at its top: nothing else for a person to
# double-click. Read-only and compressed (UDZO), checksummed on attach.
# The image is a wrapper: the package inside carries the signature and
# the ticket Gatekeeper judges on a double-click. It is signed and
# notarized itself when asked, so Finder shows no warning on the image
# either and a Mac offline at first open finds the ticket stapled.
dmg=""
if [ "$DMG" -eq 1 ]; then
    dmg="${pkg%.pkg}.dmg"
    stage="$work/dmg-root"
    mkdir -p "$stage"
    cp "$pkg" "$stage/"
    rm -f "$dmg"
    echo "==> hdiutil create $(basename "$dmg")"
    hdiutil create -quiet -volname "Minimal" -srcfolder "$stage" -fs HFS+ -format UDZO -ov "$dmg" \
        || die "hdiutil could not create the disk image"
    if [ -n "$SIGN_DMG" ]; then
        echo "==> codesign the disk image, $SIGN_DMG"
        codesign --force --timestamp --sign "$SIGN_DMG" "$dmg" || die "the disk image did not sign"
    fi
    if [ -n "$NOTARIZE" ]; then
        echo "==> notarytool submit (profile $NOTARIZE) for the disk image, waiting for Apple"
        xcrun notarytool submit "$dmg" --keychain-profile "$NOTARIZE" --wait \
            || die "the disk image's notarization did not succeed; xcrun notarytool log <id> --keychain-profile $NOTARIZE says why"
        echo "==> stapler staple (disk image)"
        xcrun stapler staple "$dmg" || die "stapling the disk image failed"
    fi
    echo "==> hdiutil verify"
    hdiutil verify -quiet "$dmg" || die "the disk image does not verify"
    du -h "$dmg"
fi
echo "distribution: arm64 only, macOS $MIN_OS or later, local system, $i bundle(s) pinned"
echo "receipt $ID $version, release $VERSION, bundle $bundle_signing$( [ "$test_build" -eq 1 ] && echo ', TEST BUILD')$( [ -n "$NOTARIZE" ] && echo ', notarized and stapled')"
echo "install: sudo installer -pkg $pkg -target /"
[ -z "$dmg" ] || echo "download page: $dmg (open it, double-click $(basename "$pkg"))"
echo "remove:  sudo /usr/local/share/minimal/uninstall.sh"
