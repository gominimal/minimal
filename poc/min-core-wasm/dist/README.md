# Built bundle (for consumers without a wasm toolchain)

Built from the `poc/min-core-wasm` sources in the same commit that added these
files (2026-09-04): rust 1.97.1 (std bootstrapped with `-Zbuild-std`), wasm-bindgen
0.2.127 (`--target web`), binaryen 124 (`wasm-opt -Os -g`). `min_core_bg.wasm`
is the optimized module **with its `name` section kept** (1,595,601 B raw /
553,010 B gzip; stripped it is 1,222,716 B / 501,083 B) so a trap names the function; strip it for a size
measurement, not for debugging. `SHA256SUMS` covers every file. Regenerate
with the steps in `../README.md`; do not edit by hand.

ES module usage:

    import init, { attach_mesh, attach_wg, attach, MinAttach,
                   ssh_public_key_from_ed25519_raw, dpop_jkt_ed25519, dpop_proof,
                   pkce_verifier, pkce_challenge } from "./min_core.js";
    await init();            // fetches ./min_core_bg.wasm next to the JS
    // or: await init({ module_or_path: new URL("./min_core_bg.wasm", import.meta.url) });
