#!/bin/sh
# dev.minimal.local-range: apply the reserved local range 127.0.64.0/24 on lo0.
#
# Installed by the advisory command `min` prints at session start (spec 18,
# NET-123). Rendered by `min` at command time with the range's host addresses
# filled in: the script reads no argument, no environment variable and no
# file, and applies exactly the reserved range and nothing else. It runs as
# root, once per load (RunAtLoad, no KeepAlive): at install and at every
# boot. Idempotent: an alias that is already present re-applies cleanly, so a
# boot-time re-run adds nothing and removes nothing (the macOS loopback-alias
# spike, docs/spikes/2026-09-22-macos-loopback-alias.md). Exits non-zero on
# the first failure.
set -e
@RANGE_ALIASES@
