#!/usr/bin/env bash
# Time one ECDSA signature and one ECDH through tpm2-tools against a TCTI.
#
#   tools-bench.sh <tcti> [runs]          e.g. device:/dev/tpmrm0
#   FLUSH=1 tools-bench.sh swtpm:host=localhost,port=2331
#
# FLUSH=1 flushes transient objects and sessions after every command. A TPM
# reached with no resource manager (swtpm over TCP, /dev/tpm0) needs it: each
# command leaves its objects loaded, and the TPM runs out of slots.
#
# Each key is P-256 under an ECC storage key, fixedtpm|fixedparent|noda, with
# a 128-bit authorization value. The bench passes it as `hex:` on the command
# line; the record says why the key store must use `file:` instead.
set -euo pipefail

tcti="$1"
runs="${2:-20}"
flush="${FLUSH:-0}"
export TPM2TOOLS_TCTI="$tcti"

work="$(mktemp -d)"
cd "$work"
trap 'rm -rf "$work"' EXIT

# Run a tpm2 command, then flush when FLUSH=1.
f() {
    local r=0
    "$@" || r=$?
    if [[ $flush == 1 ]]; then
        { tpm2_flushcontext -t; tpm2_flushcontext -l; tpm2_flushcontext -s; } >/dev/null 2>&1 || true
    fi
    return "$r"
}
# Print the wall time of a command in microseconds.
us() {
    local s e
    s=$(date +%s%N)
    "$@" >/dev/null 2>"$work/err" || { cat "$work/err" >&2; return 1; }
    e=$(date +%s%N)
    echo $(((e - s) / 1000))
}
summary() {
    sort -n | awk '{a[NR]=$1} END {printf "median %.1f ms  p90 %.1f ms  (n=%d)\n",
        a[int((NR+1)/2)]/1000, a[int(NR*0.9+0.5)]/1000, NR}'
}
times() {
    local _
    for _ in $(seq "$runs"); do us "$@"; done | summary
}
# Load a key from its blob as a restarted process would: storage key, load, use.
# shellcheck disable=SC2329 # called through `times`
# Returns the first failure, after the flush, so `us` drops the sample.
from_blob() {
    local key="$1" r=0
    shift
    f tpm2_createprimary -C o -G ecc256 -c p.ctx >/dev/null || return
    f tpm2_load -C p.ctx -u "$key.pub" -r "$key.priv" -c k.ctx >/dev/null || r=$?
    tpm2_flushcontext -t || true
    ((r == 0)) || return "$r"
    f "$@" >/dev/null || r=$?
    tpm2_flushcontext -t || true
    return "$r"
}

auth="hex:$(head -c16 /dev/urandom | xxd -p)"
attrs='fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'
f tpm2_createprimary -C o -G ecc256 -c srk.ctx >/dev/null
f tpm2_create -C srk.ctx -G ecc256:ecdsa-sha256 -a "$attrs|sign" -p "$auth" -u s.pub -r s.priv >/dev/null
f tpm2_create -C srk.ctx -G ecc256:ecdh -a "$attrs|decrypt" -p "$auth" -u e.pub -r e.priv >/dev/null
tpm2_flushcontext -t
f tpm2_load -C srk.ctx -u s.pub -r s.priv -c s.ctx >/dev/null
tpm2_flushcontext -t
f tpm2_load -C srk.ctx -u e.pub -r e.priv -c e.ctx >/dev/null
tpm2_flushcontext -t

openssl ecparam -name prime256v1 -genkey -noout -out peer.pem
openssl ec -in peer.pem -pubout -outform DER -out peer.der 2>/dev/null
# tpm2_ecdhzgen reads the peer point as a TPM2B_ECC_POINT: a size, then x and
# y, each with its own size.
python3 - <<'PY'
d = open("peer.der", "rb").read()[-65:]
x, y = d[1:33], d[33:]
b = len(x).to_bytes(2, "big") + x + len(y).to_bytes(2, "big") + y
open("peer.pt", "wb").write(len(b).to_bytes(2, "big") + b)
PY
head -c32 /dev/urandom >msg
openssl dgst -sha256 -binary msg >dig

echo "== $tcti"
printf 'process start (tpm2_getrandom 8):        '; times f tpm2_getrandom 8
printf 'ECDSA, cached context, 1 process:        '; times f tpm2_sign -c s.ctx -p "$auth" -g sha256 -d dig -o sig
printf 'ECDH,  cached context, 1 process:        '; times f tpm2_ecdhzgen -c e.ctx -p "$auth" -u peer.pt -o z
printf 'ECDSA, from blob (primary+load+sign):    '; times from_blob s tpm2_sign -c k.ctx -p "$auth" -g sha256 -d dig -o sig
printf 'ECDH,  from blob (primary+load+zgen):    '; times from_blob e tpm2_ecdhzgen -c k.ctx -p "$auth" -u peer.pt -o z

# Checks: the signature verifies, Z matches OpenSSL's, the TPM refuses to
# duplicate the key, and it refuses a wrong authorization. A failed check
# fails the run, so its timings do not count.
failed=0
fail() { echo "check: $1 (bad)"; failed=1; }
f tpm2_sign -c s.ctx -p "$auth" -g sha256 -d dig -f plain -o sig.der >/dev/null
f tpm2_readpublic -c s.ctx -f pem -o s.pem >/dev/null
if openssl dgst -sha256 -verify s.pem -signature sig.der msg >/dev/null; then
    echo "check: signature verifies with OpenSSL"
else
    fail "SIGNATURE DOES NOT VERIFY"
fi
f tpm2_ecdhzgen -c e.ctx -p "$auth" -u peer.pt -o z >/dev/null
f tpm2_readpublic -c e.ctx -f pem -o e.pem >/dev/null
openssl pkeyutl -derive -inkey peer.pem -peerkey e.pem -out zo 2>/dev/null
if [[ "$(dd if=z bs=1 skip=4 count=32 2>/dev/null | xxd -p -c64)" == "$(xxd -p -c64 zo)" ]]; then
    echo "check: ECDH Z matches OpenSSL"
else
    fail "ECDH Z DIFFERS"
fi
if f tpm2_duplicate -C srk.ctx -c s.ctx -G null -p "session:" -u d.pub -r d.priv -s d.seed >/dev/null 2>&1; then
    fail "DUPLICATION ALLOWED"
else
    echo "check: duplication refused"
fi
if f tpm2_sign -c s.ctx -p "hex:00" -g sha256 -d dig -o sig >/dev/null 2>&1; then
    fail "WRONG AUTH ACCEPTED"
else
    echo "check: wrong auth refused"
fi
exit "$failed"
