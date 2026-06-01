# Source: docs/specs/spec-minvmd-host-daemon/spec-minvmd-host-daemon.md
# Pattern: CLI/Process + Async (boot to READY marker)
# Recommended test type: Integration

Feature: VM bring-up with virtio-linux kernel and Alpine rootfs

  Scenario: minvmd boot brings up the VM and prints vm-up within 5 seconds
    Given a macOS host with libkrun installed
    And MINVMD_KERNEL_PATH points to a valid virtio-linux vmlinuz artifact for the host architecture
    And MINVMD_ROOTFS_PATH points to a staged Alpine minirootfs directory
    When the user runs "minvmd boot --foreground"
    Then stdout contains the line "vm-up" within 5 seconds
    And the process remains running until interrupted

  Scenario: Guest writes READY marker on the designated vsock port
    Given minvmd boot --foreground has been started with valid kernel and rootfs paths
    And a host-side reader is connected to the marker vsock port
    When the guest userspace init runs
    Then the host-side reader reads the bytes "READY\n" from the marker socket within 5 seconds

  Scenario: Parent does not block on krun_start_enter and supervises a hidden child
    Given minvmd boot --foreground has been started
    When the VM has reached the READY marker
    Then a file "vmm.pid" exists in the minvmd state directory containing the PID of the child VMM process
    And that PID belongs to a running "minvmd __krun-vmm" process distinct from the parent supervisor PID

  Scenario: Child VMM exit is surfaced by the parent supervisor
    Given minvmd boot --foreground is running with a booted VM
    When the child VMM process exits with a non-zero status
    Then the parent supervisor exits with a non-zero status
    And the parent's stderr or tracing output names the child exit code

  Scenario: No network device is added to the libkrun configuration in v0.1
    Given a macOS host with libkrun installed
    And valid MINVMD_KERNEL_PATH and MINVMD_ROOTFS_PATH are exported
    When the user runs "MINVMD_E2E=1 cargo test -p minvmd --test boot_e2e -- --include-ignored"
    Then the command exits with code 0
    And the guest, while booted, has no network interfaces beyond loopback when probed via the guest init

  Scenario: Boot fails fast and cleanly when the kernel path is missing
    Given the environment variable MINVMD_KERNEL_PATH points to a non-existent file
    And MINVMD_ROOTFS_PATH points to a valid Alpine minirootfs directory
    When the user runs "minvmd boot --foreground"
    Then the command exits non-zero within 1 second
    And stderr names the missing kernel path
    And no "vmm.pid" file is created in the minvmd state directory
