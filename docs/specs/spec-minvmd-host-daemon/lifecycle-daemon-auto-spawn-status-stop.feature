# Source: docs/specs/spec-minvmd-host-daemon/spec-minvmd-host-daemon.md
# Pattern: State + CLI/Process (lifecycle, atomic persistence, auto-spawn)
# Recommended test type: Integration

Feature: Lifecycle daemon — auto-spawn, status, stop

  Scenario: state.toml, vmm.pid, and lifecycle.lock live under XDG_STATE_HOME
    Given XDG_STATE_HOME is set to a temporary directory
    When minvmd is started with "minvmd run --detach"
    Then the file "$XDG_STATE_HOME/minimal/minvmd/state.toml" exists and parses as TOML containing fields "state", "vmm_pid", and "started_at"
    And the file "$XDG_STATE_HOME/minimal/minvmd/vmm.pid" exists and contains the PID of the VMM child process
    And the file "$XDG_STATE_HOME/minimal/minvmd/lifecycle.lock" exists

  Scenario: state.toml writes are atomic across a crash mid-write
    Given a running minvmd with a populated state.toml whose "state" field is "running"
    When the parent supervisor is SIGKILLed at any point during a state transition write
    Then state.toml on disk parses cleanly as TOML on every read
    And the "state" field is either the prior committed value or the new committed value, never partial

  Scenario: minvmd run --detach returns only once the host UDS accepts connections
    Given no minvmd is currently running and the state directory is empty
    When the user runs "minvmd run --detach"
    Then the command exits with code 0 within the default 8 second timeout
    And immediately after the command returns, a client can connect to the host UDS at "$XDG_RUNTIME_DIR/minimal/minimald.sock" successfully

  Scenario: minvmd run --detach times out and exits non-zero if the UDS never opens
    Given no minvmd is currently running
    And the kernel/rootfs configuration is invalid so the VM cannot reach READY
    When the user runs "minvmd run --detach" with the default 8 second timeout
    Then the command exits non-zero within 8 seconds plus a small grace period
    And stderr names the boot or UDS-readiness failure

  Scenario: minvmd status --json prints structured fields when running
    Given a running minvmd attached to a booted VM configured with 2 vcpus and 1024 MiB of RAM
    When the user runs "minvmd status --json"
    Then the command exits with code 0
    And stdout is a single JSON object containing the keys "state", "vmm_pid", "uptime_seconds", "vcpus", and "ram_mib"
    And "state" equals "running", "vcpus" equals 2, and "ram_mib" equals 1024

  Scenario: minvmd status exits 1 when stopped
    Given no minvmd is running and state.toml reports "stopped"
    When the user runs "minvmd status --json"
    Then the command exits with code 1
    And stdout is a JSON object whose "state" field equals "stopped"

  Scenario: minvmd status exits 2 on lock contention
    Given the lifecycle.lock file is held exclusively by another process performing a state transition
    When the user runs "minvmd status --json"
    Then the command exits with code 2
    And stderr names the lock contention

  Scenario: minvmd stop terminates the child, cleans up files, and resets state
    Given a running minvmd with a live VMM child and a populated vmm.pid file
    When the user runs "minvmd stop"
    Then the command exits with code 0 within 5 seconds
    And the VMM child process is no longer present in the process table
    And the file "vmm.pid" no longer exists in the state directory
    And state.toml's "state" field is "stopped"

  Scenario: minvmd stop escalates to SIGKILL if the child does not exit within 5 seconds
    Given a running minvmd whose VMM child ignores SIGTERM
    When the user runs "minvmd stop"
    Then the VMM child process is no longer present in the process table within 6 seconds of the command starting
    And the command exits with code 0
    And state.toml's "state" field is "stopped"

  Scenario: minvmd stop is idempotent on an already-stopped VM
    Given no minvmd is running and state.toml reports "stopped"
    When the user runs "minvmd stop"
    Then the command exits with code 0
    And state.toml's "state" field remains "stopped"

  Scenario: First minimal call on macOS auto-spawns minvmd and warm second call is fast
    Given a macOS host with no minvmd process running and an empty minvmd state directory
    When the user runs "minimal ls"
    Then the command exits with code 0 within 8 seconds
    And after the command returns, "minvmd status --json" reports "state" equal to "running"
    When the user immediately runs "minimal ls" a second time
    Then the second command exits with code 0 in under 500 milliseconds

  Scenario: Auto-spawn is a no-op on Linux
    Given a Linux host with no minvmd installed and a running native minimald
    When the user runs "minimal ls"
    Then the command exits with code 0
    And no "minvmd" process is spawned during the call
    And the CLI connects directly to the native minimald UDS

  Scenario: Concurrent CLI invocations cannot race the lifecycle
    Given no minvmd is currently running
    When 5 "minimal ls" processes are launched concurrently on a macOS host
    Then exactly one minvmd parent supervisor process is started
    And all 5 client commands exit with code 0
    And state.toml's "state" field ends as "running" with a single consistent vmm_pid

  Scenario: A panicking Starting transition is recovered to Stopped by the RAII guard
    Given a minvmd run process that is forced to panic during the Starting transition before commit
    When the process exits due to the panic
    Then state.toml's "state" field is "stopped" once the panicking process has fully exited
    And no orphaned VMM child remains in the process table

  Scenario: Pure next_state function accepts legal transitions and rejects illegal ones
    Given the lifecycle states "NotProvisioned", "Stopped", "Starting", "Running", "Stopping"
    When the unit tests in "crates/minvmd/src/lifecycle.rs" are executed via "cargo test -p minvmd lifecycle::"
    Then every test case exercising a legal transition returns Ok with the expected next state
    And every test case exercising an illegal transition returns Err(InvalidTransition)
    And the test suite exits with code 0
