# Built bundle (for consumers without a wasm toolchain)

Built from the `poc/min-core-wasm` sources in the same commit that added these
files (2026-09-04): rust 1.97.1 (std bootstrapped with `-Zbuild-std`), wasm-bindgen
0.2.127 (`--target web`), binaryen 124 (`wasm-opt -Os -g`). `min_core_bg.wasm`
is the optimized module **with its `name` section kept** (+340 KB raw / +46 KB
gzip over a stripped build) so a trap names the function; strip it for a size
measurement, not for debugging. `SHA256SUMS` covers every file. Regenerate
with the steps in `../README.md`; do not edit by hand.

ES module usage:

    import init, { attach, attach_wg, MinAttach } from "./min_core.js";
    await init();            // fetches ./min_core_bg.wasm next to the JS
    // or: await init({ module_or_path: new URL("./min_core_bg.wasm", import.meta.url) });
