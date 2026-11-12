#!/usr/bin/env bash
# Run the Box Egress Proxy's TPM key-store proofs (BEP-088): every
# crates/bep/tests/*_tpm_integration.rs binary, auto-discovered by name.
#
# The proofs are #[ignore] and need a TPM named in BEP_TPM_TCTI.
#   - BEP_TPM_TCTI set: use that TPM, such as `device:/dev/tpmrm0` in a VM
#     with a TPM. Nothing is started.
#   - BEP_TPM_TCTI unset: start a userspace swtpm on a free state dir, reach
#     it over its TCP TCTI, and stop it on exit. Needs `swtpm` and
#     `tpm2_getcap` on PATH (Debian and Ubuntu: `apt-get install swtpm
#     swtpm-tools tpm2-tools libtss2-dev`).
#
# The CI lane ci-linux-native runs this script; `just test-tpm` runs it here.
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v tpm2_getcap >/dev/null; then
    echo "error: tpm2_getcap is not on PATH. On Debian and Ubuntu: sudo apt-get install tpm2-tools" >&2
    exit 1
fi

if [[ -z "${BEP_TPM_TCTI:-}" ]]; then
    if ! command -v swtpm >/dev/null; then
        echo "error: swtpm is not on PATH. On Debian and Ubuntu: sudo apt-get install swtpm swtpm-tools libtss2-dev" >&2
        exit 1
    fi
    port="${BEP_TPM_PORT:-2321}"
    state="$(mktemp -d)"
    pidfile="$state/swtpm.pid"
    cleanup() {
        if [[ -f "$pidfile" ]]; then
            kill "$(cat "$pidfile")" 2>/dev/null || true
        fi
        rm -rf "$state"
    }
    trap cleanup EXIT
    # not-need-init,startup-clear: the TPM starts up itself, so a proof sees
    # a TPM in the state a booted host's is in.
    swtpm socket --tpm2 --tpmstate dir="$state" \
        --server type=tcp,port="$port" --ctrl type=tcp,port="$((port + 1))" \
        --flags not-need-init,startup-clear --pid file="$pidfile" --daemon
    export BEP_TPM_TCTI="swtpm:host=localhost,port=$port"
fi

echo "TPM: $BEP_TPM_TCTI"
# Check the TPM answers, whether this script started it or BEP_TPM_TCTI named
# it, and before any proof exists, so the lane keeps proving its TPM comes up.
# Capture before printing: a pipe into head can SIGPIPE tpm2_getcap.
if ! caps="$(TPM2TOOLS_TCTI="$BEP_TPM_TCTI" tpm2_getcap properties-fixed)"; then
    echo "error: the TPM at $BEP_TPM_TCTI does not answer." >&2
    exit 1
fi
printf '%s\n' "$caps" | sed -n '1,4p'

shopt -s nullglob
proofs=(crates/bep/tests/*_tpm_integration.rs)
if ((${#proofs[@]} == 0)); then
    # nextest refuses a binary() filter that names no binary.
    echo "No crates/bep/tests/*_tpm_integration.rs yet: nothing to run."
    exit 0
fi
# --no-tests=fail reds the run if the convention ever matches nothing.
cargo nextest run -p bep --locked --profile ci \
    --run-ignored all --no-tests=fail -E 'binary(/_tpm_integration$/)'
