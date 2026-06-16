//! Pure lifecycle state machine for `minimald` (R4.7).
//!
//! All state transitions pass through [`next_state`], which has no I/O and is
//! exhaustively tested. Illegal transitions return [`TransitionError`].
//!
//! This module is a direct adaptation of the equivalent in `crates/minvmd/src/lifecycle.rs`.
//! Both daemons share the same lifecycle model; this copy avoids a
//! cross-crate dependency for what is fundamentally an 80-line pure-function
//! module.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The lifecycle states of the `minimald` daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Lifecycle {
    /// No state file exists; daemon has never been provisioned.
    NotProvisioned,
    /// Daemon is stopped and ready to start.
    Stopped,
    /// Daemon is in the process of starting (listening on UDS).
    Starting,
    /// Daemon is running and accepting connections.
    Running,
    /// Daemon is shutting down.
    Stopping,
}

/// An action that drives a lifecycle transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Initialise state storage; `NotProvisioned → Stopped`.
    Provision,
    /// Begin startup sequence; `Stopped → Starting`.
    Start,
    /// Daemon UDS is accepting connections; `Starting → Running`.
    MarkRunning,
    /// Begin graceful shutdown; `Running → Stopping`.
    Stop,
    /// Shutdown complete; `Stopping → Stopped`.
    MarkStopped,
    /// An unexpected failure; `Starting | Running | Stopping → Stopped`.
    Fail,
}

/// Error produced by an illegal (`current`, `action`) combination.
#[derive(Debug)]
pub struct TransitionError {
    pub current: Lifecycle,
    pub action: Action,
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "illegal lifecycle transition: {:?} + {:?}",
            self.current, self.action
        )
    }
}

impl std::error::Error for TransitionError {}

/// Compute the next lifecycle state given `current` and `action` (R4.7).
///
/// This function is pure — no I/O, no side effects. Every caller that wants
/// to persist the new state must write it to disk themselves.
#[must_use = "the resulting state must be persisted"]
pub fn next_state(current: Lifecycle, action: Action) -> Result<Lifecycle, TransitionError> {
    use Action::*;
    use Lifecycle::*;

    match (current, action) {
        (NotProvisioned, Provision) => Ok(Stopped),
        (Stopped, Start) => Ok(Starting),
        (Starting, MarkRunning) => Ok(Running),
        (Starting, Fail) => Ok(Stopped),
        (Running, Stop) => Ok(Stopping),
        (Running, Fail) => Ok(Stopped),
        (Stopping, MarkStopped) => Ok(Stopped),
        (Stopping, Fail) => Ok(Stopped),
        _ => Err(TransitionError { current, action }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Case {
        current: Lifecycle,
        action: Action,
        expected: Result<Lifecycle, ()>,
    }

    fn ok(s: Lifecycle) -> Result<Lifecycle, ()> {
        Ok(s)
    }
    fn err() -> Result<Lifecycle, ()> {
        Err(())
    }

    fn run(cases: &[Case]) {
        for c in cases {
            let got = next_state(c.current, c.action).map_err(|_| ());
            assert_eq!(
                got, c.expected,
                "next_state({:?}, {:?})",
                c.current, c.action
            );
        }
    }

    #[test]
    fn legal_transitions() {
        use Action::*;
        use Lifecycle::*;

        run(&[
            Case {
                current: NotProvisioned,
                action: Provision,
                expected: ok(Stopped),
            },
            Case {
                current: Stopped,
                action: Start,
                expected: ok(Starting),
            },
            Case {
                current: Starting,
                action: MarkRunning,
                expected: ok(Running),
            },
            Case {
                current: Starting,
                action: Fail,
                expected: ok(Stopped),
            },
            Case {
                current: Running,
                action: Stop,
                expected: ok(Stopping),
            },
            Case {
                current: Running,
                action: Fail,
                expected: ok(Stopped),
            },
            Case {
                current: Stopping,
                action: MarkStopped,
                expected: ok(Stopped),
            },
            Case {
                current: Stopping,
                action: Fail,
                expected: ok(Stopped),
            },
        ]);
    }

    #[test]
    fn illegal_transitions() {
        use Action::*;
        use Lifecycle::*;

        run(&[
            // Can't re-provision once initialised
            Case {
                current: Stopped,
                action: Provision,
                expected: err(),
            },
            Case {
                current: Starting,
                action: Provision,
                expected: err(),
            },
            Case {
                current: Running,
                action: Provision,
                expected: err(),
            },
            Case {
                current: Stopping,
                action: Provision,
                expected: err(),
            },
            // Can't start from non-Stopped states
            Case {
                current: NotProvisioned,
                action: Start,
                expected: err(),
            },
            Case {
                current: Starting,
                action: Start,
                expected: err(),
            },
            Case {
                current: Running,
                action: Start,
                expected: err(),
            },
            Case {
                current: Stopping,
                action: Start,
                expected: err(),
            },
            // MarkRunning only valid from Starting
            Case {
                current: NotProvisioned,
                action: MarkRunning,
                expected: err(),
            },
            Case {
                current: Stopped,
                action: MarkRunning,
                expected: err(),
            },
            Case {
                current: Running,
                action: MarkRunning,
                expected: err(),
            },
            Case {
                current: Stopping,
                action: MarkRunning,
                expected: err(),
            },
            // Stop only valid from Running
            Case {
                current: NotProvisioned,
                action: Stop,
                expected: err(),
            },
            Case {
                current: Stopped,
                action: Stop,
                expected: err(),
            },
            Case {
                current: Starting,
                action: Stop,
                expected: err(),
            },
            Case {
                current: Stopping,
                action: Stop,
                expected: err(),
            },
            // MarkStopped only valid from Stopping
            Case {
                current: NotProvisioned,
                action: MarkStopped,
                expected: err(),
            },
            Case {
                current: Stopped,
                action: MarkStopped,
                expected: err(),
            },
            Case {
                current: Starting,
                action: MarkStopped,
                expected: err(),
            },
            Case {
                current: Running,
                action: MarkStopped,
                expected: err(),
            },
            // Fail not valid from NotProvisioned or Stopped
            Case {
                current: NotProvisioned,
                action: Fail,
                expected: err(),
            },
            Case {
                current: Stopped,
                action: Fail,
                expected: err(),
            },
        ]);
    }

    #[test]
    fn transition_error_display() {
        let err = TransitionError {
            current: Lifecycle::Stopped,
            action: Action::MarkRunning,
        };
        let s = format!("{err}");
        assert!(s.contains("illegal"), "display: {s}");
        assert!(s.contains("Stopped"), "display: {s}");
        assert!(s.contains("MarkRunning"), "display: {s}");
    }
}