#!/usr/bin/env bash
# Install (or remove) the host-address classifier ruleset for one minimald.
#
# A native minimald cannot load packet-filter rules itself (no CAP_NET_ADMIN),
# so the ruleset it renders for its cgroup tree (crates/minimald/src/net/
# host_cohort.rs, NET-078..NET-080) is installed once, with root, by this
# script. minimald writes this script beside the ruleset under
# <state>/net/host-classifier/ and names the exact command in the session
# banner when the step has not run.
#
# What it installs:
#   /etc/minimal/host-classifier/<uid>.nft   a root-owned copy of the ruleset
#   /etc/minimal/host-classifier/reload.sh   loads that copy and stamps it
#   minimal-host-classifier-<uid>.{path,service}
#       a root path unit that runs the reloader whenever the daemon rewrites
#       <state>/net/host-classifier/request, which it does at every start:
#       a re-created cgroup tree has new ids, so the rules must be reloaded
#       after the tree exists. Root only ever loads its own copy; the
#       daemon's files are watched, never read.
#
# Usage:
#   sudo bash <state>/net/host-classifier/install-host-classifier.sh
#   sudo bash <state>/net/host-classifier/install-host-classifier.sh --uninstall
#   sudo bash scripts/install-host-classifier.sh --dir <state>/net/host-classifier
#
# --dir names the daemon's directory when the script is run from a checkout
# rather than from that directory.
set -euo pipefail

readonly INSTALL_DIR=/etc/minimal/host-classifier
readonly STAMP_DIR=/run/minimal/host-classifier
readonly UNIT_PREFIX=minimal-host-classifier

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
note() { printf '%s\n' "$*"; }

mode=install
dir="$(cd "$(dirname "$0")" && pwd)"
original_args=("$@")

while [ $# -gt 0 ]; do
    case "$1" in
        --dir)
            [ $# -ge 2 ] || die "--dir needs a directory"
            dir="$(cd "$2" && pwd)" || die "no such directory: $2"
            shift 2
            ;;
        --uninstall) mode=uninstall; shift ;;
        -h|--help)   sed -n '2,29p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *)           die "unknown argument: $1 (see --help)" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "must run as root (try: sudo $0${original_args[0]+ }${original_args[*]-})"
command -v nft >/dev/null 2>&1 || die "nft not found; install nftables"
command -v systemctl >/dev/null 2>&1 || die "systemctl not found; the reloader is a systemd path unit"

rules="$dir/rules.nft"
[ -f "$rules" ] || die "no ruleset at $rules (start minimald once so it renders one)"
uid="$(stat -c %u "$dir")"
[ "$uid" -ne 0 ] || die "$dir is owned by root; it must be the daemon user's state directory"
unit="$UNIT_PREFIX-$uid"
# The chain the daemon renders: one per uid, so uninstall removes only it.
chain="$(sed -n 's/^flush chain inet minimal \([A-Za-z0-9_]*\)$/\1/p' "$rules" | head -n1)"
[ -n "$chain" ] || die "$rules does not name its chain (not a ruleset minimald rendered)"

if [ "$mode" = uninstall ]; then
    systemctl disable --now "$unit.path" >/dev/null 2>&1 || true
    systemctl stop "$unit.service" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/$unit.path" "/etc/systemd/system/$unit.service"
    systemctl daemon-reload
    nft flush chain inet minimal "$chain" 2>/dev/null || true
    nft delete chain inet minimal "$chain" 2>/dev/null || true
    rm -f "$INSTALL_DIR/$uid.nft" "$STAMP_DIR/$uid.loaded"
    note "removed the host-address classifier for uid $uid"
    exit 0
fi

install -d -m 0755 "$INSTALL_DIR"
install -m 0644 "$rules" "$INSTALL_DIR/$uid.nft"

# The reloader: loads root's copy for one uid and stamps what it loaded where
# the daemon can read it. Never touches the daemon's own directory.
cat > "$INSTALL_DIR/reload.sh" <<'EOF'
#!/bin/sh
# Written by install-host-classifier.sh. Loads /etc/minimal/host-classifier/<uid>.nft
# and stamps it into /run/minimal/host-classifier/<uid>.loaded.
set -eu
uid=$1
rules="/etc/minimal/host-classifier/$uid.nft"
stamp_dir=/run/minimal/host-classifier
nft -f "$rules"
mkdir -p "$stamp_dir"
chmod 0755 "$stamp_dir"
cp "$rules" "$stamp_dir/$uid.loaded.tmp"
chmod 0644 "$stamp_dir/$uid.loaded.tmp"
mv "$stamp_dir/$uid.loaded.tmp" "$stamp_dir/$uid.loaded"
EOF
chmod 0755 "$INSTALL_DIR/reload.sh"

cat > "/etc/systemd/system/$unit.service" <<EOF
# Written by install-host-classifier.sh. Edits are overwritten.
[Unit]
Description=Load the Minimal host-address classifier ruleset for uid $uid

[Service]
Type=oneshot
ExecStart=$INSTALL_DIR/reload.sh $uid
EOF

cat > "/etc/systemd/system/$unit.path" <<EOF
# Written by install-host-classifier.sh. Edits are overwritten.
[Unit]
Description=Reload the Minimal host-address classifier when uid $uid's minimald asks

[Path]
PathChanged=$dir/request
Unit=$unit.service

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$unit.path" >/dev/null
note "installed the host-address classifier for uid $uid ($INSTALL_DIR/$uid.nft)"

# Load it now: the daemon that rendered the ruleset is normally running, so
# the tree the rules name exists. If it is not, the path unit loads the rules
# at the daemon's next start.
if systemctl start "$unit.service"; then
    note "loaded chain inet minimal $chain; host-address boxes launched from now on are decided per box"
else
    note "the ruleset could not be loaded yet (is minimald running?); it loads when minimald next starts"
fi
