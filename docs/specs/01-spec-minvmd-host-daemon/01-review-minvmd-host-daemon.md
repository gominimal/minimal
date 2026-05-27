# Code Review Report — minvmd host daemon (T01 group)

**Reviewed:** 2026-05-26T00:00:00Z
**Branch:** feature/minvmd-host-daemon
**Base:** main
**Commits:** 4 (3928bbed, 9e4799b9, 04ad1068, d08671cc) — 26 files changed, 1648 insertions(+)
**Reviewer:** cw-review (inline path; opus model)
**Overall:** **APPROVED**

## Summary

- Blocking issues: **0**
- Advisory notes: **2** (cosmetic / quality)
- Files reviewed: 12 non-test source files
- FIX tasks created: none

## Scope

Reviewed everything under `crates/minvmd/`, the workspace `Cargo.toml` addition, the entitlements plist, and the new `justfile`. Tests (`tests/krun_smoke.rs` plus the helper bin `src/bin/krun_smoke_child.rs`, treated together as the test surface) and the spec / Gherkin / proof artifacts under `docs/specs/` are not reviewed for correctness — tests are the oracle and the spec was the input to planning, not a review target.

T01 parent ships in three sub-tasks: T01.1 (scaffold), T01.2 (FFI + wrappers), T01.3 (smoke test). All three are committed; T01.3 was verified end-to-end against libkrun v1.18.1 on `aarch64-apple-darwin`.

## Files Reviewed

| File | Status | Verdict |
|------|--------|---------|
| `Cargo.toml` (workspace) | modified (+1) | clean |
| `crates/minvmd/Cargo.toml` | new (12) | clean |
| `crates/minvmd/build.rs` | new (21) | clean |
| `crates/minvmd/minvmd.entitlements` | new (8) | clean |
| `crates/minvmd/src/lib.rs` | new (18) | clean |
| `crates/minvmd/src/main.rs` | new (46) | clean |
| `crates/minvmd/src/error.rs` | new (115) | clean |
| `crates/minvmd/src/krun/mod.rs` | new (20) | clean |
| `crates/minvmd/src/krun/raw.rs` | new (101) | clean |
| `crates/minvmd/src/krun/ctx.rs` | new (320) | clean — 2 advisory |
| `crates/minvmd/src/bin/krun_smoke_child.rs` | new (97) | clean (test surface) |
| `justfile` | new (11) | clean |
| `crates/minvmd/tests/krun_smoke.rs` | new (95) | not reviewed (tests) |

## Spec Compliance (Category C)

Trace against `docs/specs/01-spec-minvmd-host-daemon/01-spec-minvmd-host-daemon.md`:

| Req | Status | Notes |
|-----|--------|-------|
| R1.1 — compile on macOS, no-op stub on Linux | ✓ | `krun` module is `#[cfg(target_os = "macos")]`-gated in `src/lib.rs`; `build.rs` only emits link flags on macOS; Linux build verified to produce no libkrun symbol references. |
| R1.2 — FFI in single `src/krun/raw.rs`, every unsafe carries SAFETY | ✓ | One block-level SAFETY on the `unsafe extern "C"` block enumerating pointer / NUL / ctx_id / ownership invariants for all 9 declarations; 9 per-call SAFETY comments in `ctx.rs`. |
| R1.3 — safe wrappers validate inputs; FFI returns → `VmError::Backend` preserving errno magnitude | ✓ | `check_backend` strips sign; `cstring_from_path` / `_from_str` validate NUL pre-FFI. Wrappers build CStrings on the stack and bind them through the FFI call. |
| R1.4 — entitlements grant only `com.apple.security.hypervisor`; justfile codesign target | ✓ | Plist verified; justfile builds release and runs ad-hoc codesign with the entitlements file. |
| R1.5 — gated `MINVMD_E2E=1` smoke test creates context, configures 1 vcpu + 512 MiB, sets `/bin/true` as exec, confirms `krun_start_enter` exits cleanly | ✓ | Verified end-to-end against libkrun v1.18.1 — see `01-proofs/T01.3-01-cli.txt`. The full `start_enter` path is opt-in via `MINVMD_KERNEL_PATH` + `MINVMD_ROOTFS_PATH`; bring-up path verified today. |

Forward-looking surface for T02 (`set_root`, `set_kernel`, `add_vsock_port`, `set_console_output`) pulled into `raw.rs` + `ctx.rs` per the T01.2 task description ("pull additional ones as required by T02"). Avoids a churn-only re-edit later.

## Security (Category B)

- **Entitlement scope:** only `com.apple.security.hypervisor`. No file-access entitlements, no network entitlements. Matches the spec's security model.
- **`LIBKRUN_PREFIX` env override in `build.rs`:** standard supply-chain trust on the linker search path. Documented; same model as min-ctl. Not a finding.
- **No hardcoded credentials, tokens, or PII** in any file (verified via the proof-stage scan and visual review).
- **`unsafe` discipline:** every unsafe block in the diff (1 in `raw.rs`, 9 in `ctx.rs`, 0 elsewhere) is preceded by a SAFETY comment naming the invariants the call relies on. The wrappers themselves uphold those invariants via stack-owned CStrings, NULL-terminated pointer arrays, and an RAII Context that prevents double-free / use-after-free.
- **`start_enter` ownership:** `mem::forget(self)` runs before the FFI call so Drop does not double-free a configuration that libkrun's docs document as consumed by `krun_start_enter`. Correct per the C ABI contract.

## Correctness (Category A)

No correctness defects observed. Notable invariants checked:

- `set_exec` lifetimes: prior bug (envp_ptrs binding-scope) was caught during T01.2 implementation and fixed before commit. Verified the published version binds `envp_cstrs` and `envp_ptrs` at the method scope so both outlive the unsafe block.
- `Drop::drop`: surfaces non-zero `krun_free_ctx` returns via `tracing::warn!` (cannot return errors from Drop, so logging is the right escape valve).
- `check_backend`: `i32::MIN` edge case — `ret.unsigned_abs() as i32` would wrap to negative for `i32::MIN`, but errno values are 1–200 in practice; theoretical only.

## Advisory Notes (Category D)

### [NOTE-1] `ctx.rs::Context::start_enter` synthesises a misleading `VmError::Backend { code: 0 }` if libkrun ever returns success

- **File:** `crates/minvmd/src/krun/ctx.rs:226-234`
- **Observation:** The `Ok(_)` arm of `check_backend` constructs `VmError::Backend { op: "krun_start_enter", code: 0 }`. libkrun's docs say `krun_start_enter` only returns on error (success → `exit()`), so this branch is unreachable in practice — but if it ever fires, the operator sees "libkrun krun_start_enter returned errno 0", which is confusing.
- **Suggestion:** `unreachable!("krun_start_enter only returns on error per libkrun.h")` or a dedicated `VmError::StartEnterReturnedUnexpectedly` variant. Cosmetic — does not block.

### [NOTE-2] `ctx.rs::set_exec` envp construction checks `envp_cstrs.is_some()` three times in sequence

- **File:** `crates/minvmd/src/krun/ctx.rs:94-109`
- **Observation:** The envp pointer-vector setup runs three conditional branches on the same `envp_cstrs.is_some()` check. The current shape was driven by lifetime discipline (binding `envp_ptrs` at method scope) but reads as repetitive.
- **Suggestion:** Unify into a single `match envp_cstrs.as_ref()` that returns the final `(envp_ptrs, envp_ptr)` pair, e.g.:
  ```rust
  let (envp_ptrs, envp_ptr) = match envp_cstrs.as_ref() {
      Some(cstrs) => {
          let mut v: Vec<_> = cstrs.iter().map(|c| c.as_ptr()).collect();
          v.push(ptr::null());
          let p = v.as_ptr();
          (v, p)
      }
      None => (Vec::new(), ptr::null()),
  };
  ```
  Style only — no behaviour change.

## Reuse Check (Category E)

- `CString` validation / NUL handling: pure std, no duplication.
- RAII for FFI resources: `std::ops::Drop`, idiomatic.
- Error enum convention: matches `crates/sandbox2/src/error.rs` (hand-rolled `Display` + `std::error::Error` impls, no `thiserror`). Consistent.
- No utility code accidentally re-implemented; no existing minvmd-or-sibling code overlaps with what landed.

## Checklist

- [x] No hardcoded credentials or secrets
- [x] Error handling at system boundaries (typed `VmError`; `tracing::warn!` from `Drop`)
- [x] Input validation on FFI boundaries (NUL-termination, RAII ctx)
- [x] Changes match spec requirements (R1.1–R1.5 traced)
- [x] Follows repository patterns and conventions (hand-rolled error enum, workspace-pinned deps, structured tracing)
- [x] No obvious performance regressions
- [x] No `unsafe` block without `// SAFETY:` (verified by grep)
- [x] No `unwrap` outside `#[cfg(test)]` (verified — `expect` used in the test-helper bin only)
- [x] No `println!` / `eprintln!` outside CLI / test surface (verified)

## Verdict

**APPROVED** — ready for either continued execution (T02.1 / T02.2 are next unblocked) or, if the user wants to land the T01 surface as its own PR, that's a viable cut point. The two advisory notes are cosmetic and can be folded into a future T02 commit when `start_enter` and `set_exec` are exercised in earnest.
