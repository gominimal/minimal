/* tslint:disable */
/* eslint-disable */

/**
 * An attached session, as seen from JS.
 */
export class MinAttach {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Detach: closes the channel, which leaves the session running.
     */
    close(): Promise<any>;
    resize(cols: number, rows: number): Promise<any>;
    /**
     * Keystrokes / pasted bytes into the session PTY.
     */
    write(data: Uint8Array): Promise<any>;
}

/**
 * Dial `relay_url` (a WebSocket that forwards bytes to the daemon UDS), run
 * the attach handshake for `session_id`, then stream PTY output to `on_data`
 * (Uint8Array) until the channel closes, when `on_close` receives the exit
 * status (number) or `undefined`.
 */
export function attach(relay_url: string, session_id: string, term: string, cols: number, rows: number, on_data: Function, on_close: Function): Promise<MinAttach>;

/**
 * Attach over the mesh with a JSON config:
 *
 * ```json
 * { "wsUrl", "privateKey", "peerPublicKey", "localIp", "peerIp", "prefixLen"?, "sshPort"?,
 *   "sessionId", "term"?, "cols", "rows",
 *   "auth"?: { "username", "certificate", "hostCa": [..], "expectedHostPrincipal" } }
 * ```
 *
 * Without `auth`: `auth_none` and any host key (Stage 1). With `auth`: the
 * certificate is presented, `sign` is called with the bytes to sign and must
 * resolve to the raw signature, and the host must present a certificate
 * chaining to `hostCa` and naming `expectedHostPrincipal`, or the attach is
 * rejected before authentication. Rejections reject the returned promise
 * with a message that names the stage: `host rejected: … (code)`,
 * `authentication rejected by daemon`, `signing: …`.
 */
export function attach_mesh(config_json: string, sign: Function | null | undefined, on_data: Function, on_close: Function): Promise<MinAttach>;

/**
 * Attach over the mesh: dial `ws_url` (a WireGuard-over-WebSocket ingress),
 * bring up a WireGuard tunnel to the peer with the given keys and tunnel
 * addresses, open TCP to `peer_ip:ssh_port` inside it, then run the same
 * attach handshake as [`attach`]. Keys are base64 as WireGuard prints them.
 */
export function attach_wg(ws_url: string, private_key_b64: string, peer_public_key_b64: string, local_ip: string, peer_ip: string, prefix_len: number, ssh_port: number, session_id: string, term: string, cols: number, rows: number, on_data: Function, on_close: Function): Promise<MinAttach>;

/**
 * RFC 7638 thumbprint of the OKP/Ed25519 JWK, the `dpop_jkt` value.
 */
export function dpop_jkt_ed25519(raw_public: Uint8Array): string;

/**
 * A DPoP proof JWS (`EdDSA`) for one request, signed through `sign`.
 * `nonce` and `access_token` may be null.
 */
export function dpop_proof(raw_public: Uint8Array, htm: string, htu: string, nonce: string | null | undefined, access_token: string | null | undefined, sign: Function): Promise<string>;

/**
 * PKCE S256 challenge for a verifier.
 */
export function pkce_challenge(verifier: string): string;

/**
 * A fresh PKCE verifier.
 */
export function pkce_verifier(): string;

/**
 * `ssh-ed25519 AAAA...` for the raw 32-byte public key WebCrypto exports.
 */
export function ssh_public_key_from_ed25519_raw(raw: Uint8Array): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_minattach_free: (a: number, b: number) => void;
    readonly attach: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: any, j: any) => any;
    readonly attach_mesh: (a: number, b: number, c: number, d: any, e: any) => any;
    readonly attach_wg: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number, r: number, s: any, t: any) => any;
    readonly dpop_jkt_ed25519: (a: number, b: number) => [number, number];
    readonly dpop_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: any) => any;
    readonly minattach_close: (a: number) => any;
    readonly minattach_resize: (a: number, b: number, c: number) => any;
    readonly minattach_write: (a: number, b: number, c: number) => any;
    readonly pkce_challenge: (a: number, b: number) => [number, number];
    readonly pkce_verifier: () => [number, number, number, number];
    readonly ssh_public_key_from_ed25519_raw: (a: number, b: number) => [number, number, number, number];
    readonly ring_core_0_17_14__bn_mul_mont: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly wasm_bindgen_c7ad7b152c17969b___convert__closures_____invoke___wasm_bindgen_c7ad7b152c17969b___JsValue__core_352c1e50950a8150___result__Result_____wasm_bindgen_c7ad7b152c17969b___JsError___true_: (a: number, b: number, c: any) => [number, number];
    readonly wasm_bindgen_c7ad7b152c17969b___convert__closures_____invoke___js_sys_63b5cee501afdfd___Function_fn_wasm_bindgen_c7ad7b152c17969b___JsValue_____wasm_bindgen_c7ad7b152c17969b___sys__Undefined___js_sys_63b5cee501afdfd___Function_fn_wasm_bindgen_c7ad7b152c17969b___JsValue_____wasm_bindgen_c7ad7b152c17969b___sys__Undefined_______true_: (a: number, b: number, c: any, d: any) => void;
    readonly wasm_bindgen_c7ad7b152c17969b___convert__closures_____invoke___web_sys_1d6c54c190c41b18___features__gen_CloseEvent__CloseEvent______true_: (a: number, b: number, c: any) => void;
    readonly wasm_bindgen_c7ad7b152c17969b___convert__closures_____invoke___web_sys_1d6c54c190c41b18___features__gen_CloseEvent__CloseEvent______true__2: (a: number, b: number, c: any) => void;
    readonly wasm_bindgen_c7ad7b152c17969b___convert__closures_____invoke___web_sys_1d6c54c190c41b18___features__gen_CloseEvent__CloseEvent______true__3: (a: number, b: number, c: any) => void;
    readonly wasm_bindgen_c7ad7b152c17969b___convert__closures_____invoke_______true_: (a: number, b: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_destroy_closure: (a: number, b: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
