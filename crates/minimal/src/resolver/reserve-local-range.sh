#!/bin/sh
# dev.minimal.local-range: apply the reserved local range 127.0.64.0/24 on lo0.
#
# Installed by the advisory command min prints at session start (spec 18,
# NET-123). Rendered by min at command time with the host addresses of the
# reserved range filled in: the script reads no argument, no environment
# variable and no file, and applies exactly the reserved range and nothing
# else. Its one read is the state of the interface itself, reported by the
# same absolute-path system tool the aliases are added with, so nothing
# user-writable can change what it applies. Idempotent over what lo0 already
# carries: an address already present is skipped, never re-added, so a re-run
# (a repeated install, or a kickstart as a boot loads the unit) adds only the
# missing aliases and removes nothing. The skip, not a re-add, is the shape
# the spike ships: its recorded runs never re-added a present alias, so this
# program does not assume one exits zero
# (docs/spikes/2026-09-22-macos-loopback-alias.md). It runs as root, once
# per load (RunAtLoad, no KeepAlive): at install and at every boot. Exits
# non-zero on the first failure.
set -e
present=$(/sbin/ifconfig lo0 inet)
for addr in @RANGE_ADDRESSES@; do
  case " $present " in *" $addr "*) ;; *) /sbin/ifconfig lo0 alias "$addr" 255.255.255.255 ;; esac
done
