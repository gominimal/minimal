#!/usr/bin/env bash
# Install (or remove) the AppArmor profile that lets minimald create the
# unprivileged user namespace its session sandbox needs.
#
# Ubuntu 24.04+ defaults kernel.apparmor_restrict_unprivileged_userns=1, under
# which an unconfined minimald cannot write /proc/self/uid_map and every session
# dies with EPERM before it starts. packaging/apparmor/minimald is the sanctioned
# fix: an unconfined-mode profile whose only job is to carry the `userns`
# permission. See docs/reference/linux-host-setup.md.
#
# Usage:
#   sudo scripts/install-apparmor-profile.sh [--path BINARY]...
#   sudo scripts/install-apparmor-profile.sh --uninstall
#        scripts/install-apparmor-profile.sh --check      # syntax only, no root
#
# --path attaches the profile to a binary outside the standard install locations
# (/usr/bin, /usr/local/bin, ~/.local/bin) — a dev build in target/debug, say.
# Repeatable. Passing --path replaces the set recorded by a previous run.
set -euo pipefail

readonly PROFILE_NAME=minimald
readonly APPARMOR_D=/etc/apparmor.d
readonly SRC_DIR="$(cd "$(dirname "$0")/../packaging/apparmor" && pwd)"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
note() { printf '%s\n' "$*"; }

mode=install
extra_paths=()

while [ $# -gt 0 ]; do
    case "$1" in
        --path)
            [ $# -ge 2 ] || die "--path needs a binary path"
            # AppArmor matches on the path the kernel sees, which is absolute
            # and symlink-resolved; store it that way or the profile silently
            # fails to attach.
            [ -e "$2" ] || die "no such file: $2"
            extra_paths+=("$(readlink -f "$2")")
            shift 2
            ;;
        --uninstall) mode=uninstall; shift ;;
        --check)     mode=check; shift ;;
        -h|--help)   sed -n '2,18p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *)           die "unknown argument: $1 (see --help)" ;;
    esac
done

command -v apparmor_parser >/dev/null 2>&1 ||
    die "apparmor_parser not found; this host does not have AppArmor (nothing to install)"

# --check: parse the profile out of the source tree without touching the kernel
# or the policy cache, so CI and pre-commit can run it unprivileged.
if [ "$mode" = check ]; then
    apparmor_parser --skip-kernel-load --skip-cache \
        -I "$SRC_DIR" -I "$APPARMOR_D" "$SRC_DIR/$PROFILE_NAME"
    note "profile parses: $SRC_DIR/$PROFILE_NAME"
    exit 0
fi

[ "$(id -u)" -eq 0 ] || die "must run as root (try: sudo $0 $*)"

if [ "$mode" = uninstall ]; then
    # Unload first: removing the file alone leaves the profile live in the
    # kernel until the next boot or `systemctl reload apparmor`.
    if [ -f "$APPARMOR_D/$PROFILE_NAME" ]; then
        apparmor_parser --remove "$APPARMOR_D/$PROFILE_NAME" || true
    fi
    rm -f "$APPARMOR_D/$PROFILE_NAME" \
          "$APPARMOR_D/tunables/$PROFILE_NAME" \
          "$APPARMOR_D/tunables/$PROFILE_NAME.d/local"
    rmdir "$APPARMOR_D/tunables/$PROFILE_NAME.d" 2>/dev/null || true
    note "removed the $PROFILE_NAME AppArmor profile"
    exit 0
fi

install -m 0644 "$SRC_DIR/tunables/$PROFILE_NAME" "$APPARMOR_D/tunables/$PROFILE_NAME"
install -m 0644 "$SRC_DIR/$PROFILE_NAME" "$APPARMOR_D/$PROFILE_NAME"

if [ ${#extra_paths[@]} -gt 0 ]; then
    install -d -m 0755 "$APPARMOR_D/tunables/$PROFILE_NAME.d"
    {
        printf '# Written by scripts/install-apparmor-profile.sh --path. Edits are overwritten.\n'
        for p in "${extra_paths[@]}"; do printf '@{minimald_bin} += %s\n' "$p"; done
    } > "$APPARMOR_D/tunables/$PROFILE_NAME.d/local"
fi

apparmor_parser --replace "$APPARMOR_D/$PROFILE_NAME"

note "loaded the $PROFILE_NAME AppArmor profile ($APPARMOR_D/$PROFILE_NAME)"
for p in "${extra_paths[@]:-}"; do [ -n "$p" ] && note "  also attached to: $p"; done
note "minimald may now create unprivileged user namespaces; no need to set"
note "kernel.apparmor_restrict_unprivileged_userns=0."
