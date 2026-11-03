#!/bin/sh
# dev.minimal.local-range: add the loopback IPs boxes use (127.0.64.0/24) to lo0.
#
# Installed by min finalize-install. It reads no argument, no environment
# variable and no file: the addresses below are fixed when it is installed.
# An address lo0 already carries with the /32 mask is skipped, so running it
# again adds only the missing ones and removes nothing. An address carried
# with any other mask is applied again, which sets its mask to /32. It runs
# as root at install and at every boot, and exits non-zero on the first
# failure.
#
# The mask needs the netmask keyword. Without it ifconfig reads the second
# address as a destination and gives the alias the /8 of its class, and 254
# addresses on one /8 slow the host's name lookups down.
set -e
present=$(/sbin/ifconfig lo0 inet)
for addr in @RANGE_ADDRESSES@; do
  case "$present" in *"inet $addr netmask 0xffffffff"*) ;; *) /sbin/ifconfig lo0 alias "$addr" netmask 255.255.255.255 ;; esac
done
