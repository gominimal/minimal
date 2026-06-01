# Source: docs/specs/spec-minvmd-host-daemon/spec-minvmd-host-daemon.md
# Pattern: CLI/Process + Async (libkrun-owned UDS<->vsock bridge, host-initiated)
# Recommended test type: Integration

Feature: UDS to vsock bridge for minimald

  # minvmd registers the host UDS via krun_add_vsock_port2(.., listen=true) before
  # boot; libkrun owns the bind and the forwarding. minvmd runs no byte relay.

  Scenario: Host UDS is created with 0600 mode owned by the invoking user
    Given minvmd has registered the host UDS via krun_add_vsock_port2 with listen=true
    And the VM has started
    Then a Unix domain socket exists at "$XDG_RUNTIME_DIR/minimal/minimald.sock"
    And the socket file mode is 0600
    And the socket file is owned by the invoking user's UID

  Scenario: Host UDS falls back to ~/.minimal/local/minimald.sock when XDG_RUNTIME_DIR is unset
    Given the environment variable XDG_RUNTIME_DIR is unset
    And minvmd has registered the host UDS via krun_add_vsock_port2 with listen=true
    And the VM has started
    Then a Unix domain socket exists at "~/.minimal/local/minimald.sock"
    And the socket file mode is 0600

  Scenario: Five concurrent host UDS connections each round-trip distinct payloads
    Given a booted minvmd VM with a guest listener on vsock port VSOCK_PORT running "socat VSOCK-LISTEN:VSOCK_PORT,fork EXEC:cat"
    When 5 host processes connect concurrently to the host UDS, each writes a distinct payload, and each reads a response
    Then each of the 5 connections reads back exactly the payload it wrote
    And all 5 connections complete without error
    And minvmd holds no per-connection state because libkrun multiplexes the connections

  Scenario: Bridge is transport-agnostic and forwards arbitrary bytes unchanged
    Given a booted minvmd VM with an echo service on vsock port VSOCK_PORT
    When a host client writes a 4 KiB random binary payload to the host UDS and reads until EOF
    Then the bytes read back equal the bytes written byte-for-byte
    And no minvmd-side code parses, reframes, or rewrites the payload

  Scenario: Guest unavailability surfaces as a connect failure the client can recover from
    Given the host UDS is registered and the VM is running
    And no guest process is listening on vsock port VSOCK_PORT
    When a host client connects to the host UDS and attempts to exchange bytes
    Then the connection fails at the libkrun bridge
    And minimal's provider discovery treats the failed connect as a stale provider, pruning it and continuing
    And the host UDS registration is not torn down, so a later connection can succeed once a guest listener returns

  Scenario: End-to-end CLI call reaches a stub minimald in the VM
    Given a booted minvmd VM with a stub minimald reachable on vsock port VSOCK_PORT that responds to "list-sessions" with an empty list
    When the host runs a client that sends "list-sessions" over the host UDS at "$XDG_RUNTIME_DIR/minimal/minimald.sock"
    Then the client receives the empty-list response
    And the exchange completes without the host needing to know a VM exists
