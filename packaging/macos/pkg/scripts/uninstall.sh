#!/bin/sh
# uninstall.sh: remove the macOS system install. macOS keeps a receipt for a
# package but has no command to remove one, so the package ships this.
# Undoes the postinstall (the DNS service, its role account, the resolver,
# the boot-time range job), then removes every file the receipt lists, then
# the receipt. Never /usr or /usr/local themselves. A user's own state under
# their home (~/.local/state/minimal, ~/.cache/minimal) is theirs and stays.
#
# The postinstall puts this script where only root writes, with the list of
# files the payload placed beside it. A first install that failed has no
# receipt; the list then stands in for it, so that install can be removed
# too.
#
#   sudo "/Library/Application Support/minimal/uninstall.sh"
set -u
id=dev.minimal.min
role=_minimal
support="/Library/Application Support/minimal"
if [ "$(id -u)" -ne 0 ]; then
    echo "run it as root: sudo $0" >&2
    exit 1
fi
receipt=0
if pkgutil --pkg-info "$id" >/dev/null 2>&1; then
    receipt=1
elif [ ! -f "$support/payload-files" ]; then
    echo "no receipt for $id and no file list at $support/payload-files: minimal is not installed as a package on this Mac" >&2
    exit 1
fi
# The payload's paths, relative to the install location: the receipt's when
# there is one, else the list the package brought.
payload() {
    if [ "$receipt" -eq 1 ]; then pkgutil --files "$id"; else cat "$support/payload-files"; fi
}

# The privileged setup the postinstall did.
launchctl bootout system/dev.gominimal.zone 2>/dev/null || true
launchctl bootout system/dev.minimal.local-range 2>/dev/null || true
rm -f /Library/LaunchDaemons/dev.gominimal.zone.plist /Library/LaunchDaemons/dev.minimal.local-range.plist
rm -f /etc/resolver/min.internal
rmdir /etc/resolver 2>/dev/null || true
rm -rf /Library/PrivilegedHelperTools/Minimal.app /Library/PrivilegedHelperTools/Minimal.app.old
rmdir /Library/PrivilegedHelperTools 2>/dev/null || true
rm -rf "$support/run"
# The boot-time job's loopback range, alias by alias.
ifconfig lo0 | awk '/inet 127\.0\.64\./ {print $2}' | while IFS= read -r a; do
    ifconfig lo0 -alias "$a" 2>/dev/null || true
done
# The role account. Deleting a user record needs the Full Disk Access
# privacy permission even as root: a Terminal with it, or an MDM agent, can;
# root over ssh can only where sshd holds it, which turning Remote Login on
# in System Settings grants and enabling sshd any other way does not
# (eDSPermissionError otherwise), while the group deletes either way. Both
# of Apple's tools are tried; what is left is reported, with the command for
# a session that has the permission.
account_left=0
if dscl . -read "/Users/$role" >/dev/null 2>&1; then
    # -keepHome: the account's home is /var/empty, which sshd needs; the
    # default removes the home with the account.
    dscl . -delete "/Users/$role" 2>/dev/null \
        || sysadminctl -deleteUser "$role" -keepHome >/dev/null 2>&1 \
        || true
    if dscl . -read "/Users/$role" >/dev/null 2>&1; then account_left=1; fi
fi
# The group goes only once the user is gone: a group deleted beside a user
# macOS kept would leave the next install with an account and no group.
if [ "$account_left" = 0 ] && dscl . -read "/Groups/$role" >/dev/null 2>&1; then
    dscl . -delete "/Groups/$role" 2>/dev/null || account_left=1
fi

# The payload, by the receipt. `pkgutil --files` lists files, directories and
# symlinks alike (`--only-files` skips symlinks: git-remote-min would stay);
# files and links first, then directories deepest first.
loc=""
if [ "$receipt" -eq 1 ]; then loc="$(pkgutil --pkg-info "$id" | sed -n 's/^location: //p')"; fi
base="/${loc#/}"
base="${base%/}"
payload | while IFS= read -r f; do
    p="$base/$f"
    if [ -d "$p" ] && [ ! -L "$p" ]; then continue; fi
    rm -f "$p"
done
payload | sort -r | while IFS= read -r d; do
    # The standard directories stay, empty or not: every shell's PATH names
    # /usr/local/bin, and other software keeps its own files beside ours.
    case "$d" in usr|usr/local|usr/local/bin|usr/local/lib|usr/local/share|Library) continue ;; esac
    p="$base/$d"
    if [ -d "$p" ] && [ ! -L "$p" ]; then rmdir "$p" 2>/dev/null || true; fi
done
rmdir /Library/PrivilegedHelperTools 2>/dev/null || true
# Last, this script and its list.
rm -f "$support/payload-files" "$support/uninstall.sh"
rmdir "$support" 2>/dev/null || true
if [ "$receipt" -eq 1 ]; then
    pkgutil --forget "$id" >/dev/null
    echo "minimal: removed from this Mac (the receipt $id is forgotten); each user's own state under their home stays"
else
    echo "minimal: removed from this Mac (an install that did not finish: there was no receipt); each user's own state under their home stays"
fi
if [ "$account_left" -eq 1 ]; then
    echo "minimal: the service account $role and its group are still on this Mac: macOS refused to delete the account from this session (it needs Full Disk Access). From a Terminal that has it, run: sudo sysadminctl -deleteUser $role -keepHome && sudo dscl . -delete /Groups/$role" >&2
    exit 1
fi
