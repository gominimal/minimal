# Source: docs/specs/spec-minvmd-host-daemon/spec-minvmd-host-daemon.md
# Pattern: CLI/Process (build + smoke test)
# Recommended test type: Integration

Feature: Crate scaffold, FFI wrappers, libkrun smoke test

  Scenario: Crate compiles on macOS aarch64 target
    Given a checkout of the minimal workspace on an aarch64-apple-darwin host
    When the user runs "cargo build -p minvmd --target aarch64-apple-darwin"
    Then the command exits with code 0
    And the binary "target/aarch64-apple-darwin/debug/minvmd" is produced

  Scenario: Crate compiles on macOS x86_64 target
    Given a checkout of the minimal workspace on a host with the x86_64-apple-darwin toolchain installed
    When the user runs "cargo build -p minvmd --target x86_64-apple-darwin"
    Then the command exits with code 0
    And the binary "target/x86_64-apple-darwin/debug/minvmd" is produced

  Scenario: Linux build produces a no-op shim that keeps CI green
    Given a checkout of the minimal workspace on an x86_64-unknown-linux-gnu host
    When the user runs "cargo build -p minvmd"
    Then the command exits with code 0
    And running the resulting "minvmd" binary with any subcommand exits non-zero with a stderr message naming macOS as the only supported platform

  Scenario: FFI return codes surface as typed VmError::Backend with preserved errno
    Given a safe wrapper around a libkrun FFI call configured to receive a known failure return code from the backend
    When the wrapper is invoked with inputs that pass safe-Rust validation but trigger the backend failure
    Then the wrapper returns Err(VmError::Backend { op, code }) where op names the FFI function and code equals the original errno magnitude returned by libkrun
    And no panic, abort, or process exit occurs

  Scenario: Safe wrappers reject invalid inputs before crossing the FFI boundary
    Given a safe wrapper that requires a NUL-terminated path argument
    When the wrapper is called with a Rust string containing an interior NUL byte
    Then the wrapper returns a typed validation error
    And no libkrun FFI function is invoked

  Scenario: Release binary is code-signed with the hypervisor entitlement via justfile
    Given a release build of minvmd has been produced on macOS
    When the user runs the justfile signing target
    Then the command exits with code 0
    And "codesign -d --entitlements - target/release/minvmd" prints an entitlements plist containing "com.apple.security.hypervisor"
    And the printed entitlements plist contains no other entitlement keys

  Scenario: Smoke test boots libkrun with /bin/true and exits cleanly
    Given a macOS host with libkrun installed
    And the environment variable "MINVMD_E2E" is set to "1"
    When the user runs "cargo test -p minvmd --test krun_smoke -- --include-ignored"
    Then the command exits with code 0
    And the test output reports the smoke test as passing

  Scenario: Smoke test is skipped by default to keep unit-test runs hermetic
    Given a checkout of the minimal workspace
    And the environment variable "MINVMD_E2E" is unset
    When the user runs "cargo test -p minvmd"
    Then the command exits with code 0
    And the krun_smoke test is reported as ignored rather than executed
