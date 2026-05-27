# Source: docs/specs/01-spec-minvmd-host-daemon/01-spec-minvmd-host-daemon.md
# Pattern: CLI/Process + Async (bidirectional bridge with concurrency)
# Recommended test type: Integration

Feature: UDS to vsock bridge for minimald

  Scenario: Host UDS is created with 0600 mode owned by the invoking user
    Given a booted minvmd VM
    When the bridge has started accepting connections
    Then a Unix domain socket exists at "$XDG_RUNTIME_DIR/minimal/minimald.sock"
    And the socket file mode is 0600
    And the socket file is owned by the invoking user's UID

  Scenario: Host UDS falls back to ~/.minimal/local/minimald.sock when XDG_RUNTIME_DIR is unset
    Given a booted minvmd VM
    And the environment variable XDG_RUNTIME_DIR is unset
    When the bridge has started accepting connections
    Then a Unix domain socket exists at "~/.minimal/local/minimald.sock"
    And the socket file mode is 0600

  Scenario: Five concurrent host UDS connections each round-trip distinct payloads
    Given a booted minvmd VM running "socat VSOCK-LISTEN:2222,fork EXEC:cat" on the guest
    And the host UDS bridge is accepting connections
    When 5 host processes connect concurrently to the UDS, each writes a distinct payload, and each reads a response
    Then each of the 5 connections reads back exactly the payload it wrote
    And all 5 connections complete without error

  Scenario: Bridge is transport-agnostic and forwards arbitrary bytes unchanged
    Given a booted minvmd VM with an echo service on vsock port 2222
    And the host UDS bridge is accepting connections
    When a host client writes a 4 KiB random binary payload to the UDS and reads until EOF
    Then the bytes read back equal the bytes written byte-for-byte
    And the bridge does not parse, reframe, or rewrite the payload

  Scenario: Guest unavailability does not take down the listener
    Given the host UDS bridge is accepting connections
    And the guest-side vsock listener on port 2222 has been stopped so connection attempts are refused
    When a host client connects to the UDS and attempts to send a request
    Then the client connection is closed with a BridgeError::GuestUnavailable surfaced in the bridge tracing log at warn level
    And a subsequent connection from a second client to the UDS is accepted by the listener without restart

  Scenario: End-to-end CLI call reaches a stub minimald in the VM
    Given a booted minvmd VM with a stub minimald listening on vsock port 2222 that responds to "list-sessions" with an empty list
    And the host UDS bridge is accepting connections
    When the host runs a client that sends "list-sessions" over the UDS at "~/.local/state/minimal/minvmd/minimald.sock"
    Then the client receives the empty-list response
    And the exchange completes without the host needing to know a VM exists
