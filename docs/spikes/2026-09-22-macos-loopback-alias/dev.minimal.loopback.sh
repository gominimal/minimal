#!/bin/sh
# dev.minimal.loopback: re-apply the reserved local range 127.0.64.0/24 on lo0.
# Run by launchd at boot (RunAtLoad) and once at install. Idempotent: an alias
# that is already present is skipped, so a re-run adds nothing and removes
# nothing. The range and the interface are literal on purpose: the daemon reads
# no configuration (arch design 7.1, post-install custody).
set -u
PATH=/sbin:/usr/sbin:/bin:/usr/bin
IFACE=lo0
PREFIX=127.0.64
present=$(ifconfig "$IFACE" inet 2>/dev/null | awk '$1 == "inet" { print $2 }')
added=0
n=1
while [ "$n" -le 254 ]; do
    addr="$PREFIX.$n"
    case " $present " in
        *" $addr "*) ;;
        *)
            if ifconfig "$IFACE" alias "$addr" 255.255.255.255; then
                added=$((added + 1))
            else
                echo "dev.minimal.loopback: alias $addr failed" >&2
            fi
            ;;
    esac
    n=$((n + 1))
done
count=$(ifconfig "$IFACE" inet 2>/dev/null | awk -v p="$PREFIX." 'index($2, p) == 1 { c++ } END { print c + 0 }')
boot=$(sysctl -n kern.boottime | sed -E 's/.*sec = ([0-9]+), usec.*/\1/')
now=$(date +%s)
echo "dev.minimal.loopback: $(date -u +%Y-%m-%dT%H:%M:%SZ) since_boot=$((now - boot))s added=$added present=$count/254 on $IFACE"
[ "$count" -eq 254 ]
