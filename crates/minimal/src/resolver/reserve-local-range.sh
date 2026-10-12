#!/bin/sh
# dev.minimal.local-range: add the loopback IPs boxes use (127.0.64.0/24) to lo0.
#
# Installed by min finalize-install. It reads no argument, no environment
# variable and no file: the addresses below are fixed when it is installed.
# An address lo0 already carries is skipped, so running it again adds only
# the missing ones and removes nothing. It runs as root at install and at
# every boot, and exits non-zero on the first failure.
set -e
present=$(/sbin/ifconfig lo0 inet)
for addr in @RANGE_ADDRESSES@; do
  case " $present " in *" $addr "*) ;; *) /sbin/ifconfig lo0 alias "$addr" 255.255.255.255 ;; esac
done
