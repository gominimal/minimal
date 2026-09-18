#!/bin/sh
# Run after `sudo reboot` and a fresh login. No root needed.
SP=docs/spikes/2026-09-22-macos-loopback-alias
echo "## boot time";        sysctl -n kern.boottime
echo "## launchd state";    launchctl print system/dev.minimal.loopback | grep -E "state|last exit|runs|program"
echo "## alias count";      ifconfig lo0 | grep -c 127.0.64
echo "## daemon log";       cat /var/log/dev.minimal.loopback.log
echo "## bind probe, every address in the range (expect 254 OK, plus 127.0.0.1 and ::1)"
python3 "$SP/bind-probe.py" 127.0.0.1 ::1 $(seq -f "127.0.64.%g" 1 254) | tail -8
python3 "$SP/bind-probe.py" $(seq -f "127.0.64.%g" 1 254) | grep -c " OK "
echo "## alias timing relative to boot (unified log, first 3 minutes after boot)"
BOOT=$(date -r "$(sysctl -n kern.boottime | sed -E 's/.*sec = ([0-9]+), usec.*/\1/')" "+%Y-%m-%d %H:%M:%S")
END=$(date -r "$(( $(sysctl -n kern.boottime | sed -E 's/.*sec = ([0-9]+), usec.*/\1/') + 180 ))" "+%Y-%m-%d %H:%M:%S")
/usr/bin/log show --start "$BOOT" --end "$END" --style compact \
  --predicate '(process == "launchd" && eventMessage CONTAINS "dev.minimal.loopback") || process == "ifconfig"' | head -20
echo "## resolver"
scutil --dns | grep -A6 "min.internal"
