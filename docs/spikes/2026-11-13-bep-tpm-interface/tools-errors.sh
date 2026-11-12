#!/usr/bin/env bash
# What tpm2-tools reports for each failure the key store must sort into a kept
# or a lost key: the exit status, the response code, the first error line.
# Runs against device:/dev/tpmrm0 as a member of the tss group.
set -u
export TPM2TOOLS_TCTI=device:/dev/tpmrm0
w=$(mktemp -d); cd "$w" || exit 1
head -c16 /dev/urandom > auth; chmod 600 auth
a='fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|sign'
# The fixture must exist, or a row reports a fixture error under its label.
fixture() { "$@" || { echo "error: fixture step failed: $*" >&2; exit 1; }; }
fixture tpm2_createprimary -Q -C o -G ecc256 -c srk.ctx
fixture tpm2_create -Q -C srk.ctx -G ecc256:ecdsa-sha256 -a "$a" -p file:auth -u k.pub -r k.priv
fixture tpm2_load -Q -C srk.ctx -u k.pub -r k.priv -c k.ctx
fixture tpm2_flushcontext -t
fixture openssl rand -out dig 32
run() { local label=$1; shift; "$@" >/dev/null 2>err; echo "$label: exit $? | $(grep -o '0x[0-9A-Fa-f]*)' err | head -1) $(grep -m1 '^ERROR' err | cut -c1-90)"; }
run "auth from file:, right"         tpm2_sign -c k.ctx -p file:auth -g sha256 -d dig -o s
run "auth from stdin (file:-)"       sh -c 'tpm2_sign -c k.ctx -p file:- -g sha256 -d dig -o s < auth'
head -c16 /dev/urandom > bad
run "wrong auth"                     tpm2_sign -c k.ctx -p file:bad -g sha256 -d dig -o s
run "TPM unreachable (swtpm port)"   env TPM2TOOLS_TCTI=swtpm:host=localhost,port=2399 tpm2_sign -c k.ctx -p file:auth -g sha256 -d dig -o s
run "no TPM device"                  env TPM2TOOLS_TCTI=device:/dev/tpmrm9 tpm2_sign -c k.ctx -p file:auth -g sha256 -d dig -o s
run "auth file unreadable"           tpm2_sign -c k.ctx -p file:/root/x -g sha256 -d dig -o s
cp k.priv x.priv; printf '\x00\x00' | dd of=x.priv bs=1 seek=20 conv=notrunc 2>/dev/null
run "key blob corrupt (integrity)"   tpm2_load -C srk.ctx -u k.pub -r x.priv -c x.ctx
tpm2_flushcontext -t
fixture tpm2_createprimary -Q -C o -G ecc256 -c other.ctx -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt|noda' -q 01
run "blob under another parent"      tpm2_load -C other.ctx -u k.pub -r k.priv -c y.ctx
tpm2_flushcontext -t
run "key file missing"               tpm2_load -C srk.ctx -u k.pub -r nope.priv -c z.ctx
rm -rf "$w"
