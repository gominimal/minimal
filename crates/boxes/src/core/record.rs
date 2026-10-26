//! The five states a box record is held in (BOX-011) and the decision
//! which records a daemon restart reaps (BOX-012).
//!
//! A record is in exactly one [`RecordState`]. The ending of a `stopped`
//! or `exited` record is a typed value, so the `reason`, `exit_code` and
//! `signal` the BOX-011 table gives for each way a box ends are the only
//! combinations the type can hold.
//!
//! The stored [`BoxState`] does not yet hold `stopped` or `exited`: every
//! stored record projects onto `pending`, `materializing` or `running`
//! through [`RecordState::from`]. Until the store holds an ending, the
//! `state_is_exactly_one` harness runs over [`RecordState`], not over
//! the stored [`crate::Record`] that the BOX-011 harness line names.
//! Issue #2634 owns the stored ending and the move of the harness to
//! [`crate::Record`].

use serde::{Deserialize, Serialize};

use crate::BoxState;

/// The exit code an OOM kill gives a box (BOX-011): 128 + SIGKILL.
pub const OOM_EXIT_CODE: i32 = 137;

/// The `reason` a `stopped` or `exited` record carries (BOX-011).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    /// The entrypoint exited on its own.
    Exit,
    /// The box ran past its `timeout` (BOX-037).
    Timeout,
    /// An OOM kill ended the box.
    Oom,
    /// A stop ended the box, or the daemon found it with no process left.
    Stopped,
}

/// How a `stopped` box ended (BOX-011, BOX-013, BOX-154).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum StopEnding {
    /// A stop, the entrypoint having exited before a signal ended it.
    ExitedFirst {
        /// The entrypoint's exit status.
        exit_code: i32,
    },
    /// A stop whose signal ended the entrypoint (BOX-013).
    Signalled {
        /// That signal's number.
        signal: i32,
    },
    /// Set at daemon start for a running record with no process left
    /// (BOX-154): no signal from this daemon ended it.
    AtDaemonStart,
}

/// How an `exited` box ended (BOX-011).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum ExitEnding {
    /// The entrypoint exited on its own.
    Exit {
        /// The entrypoint's exit status.
        exit_code: i32,
    },
    /// The box ran past its `timeout` (BOX-037).
    Timeout,
    /// An OOM kill ended the box.
    Oom,
}

/// The one state a box record is in (BOX-011).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum RecordState {
    /// Composition is in flight.
    Pending,
    /// Composition is final and the client is still uploading.
    Materializing,
    /// The box is ready and its processes can run.
    Running,
    /// A stop ended the box, or the daemon found it with no process left.
    Stopped(StopEnding),
    /// The box ended on its own, by timeout, or by an OOM kill.
    Exited(ExitEnding),
}

impl RecordState {
    /// The state's name as BOX-011 spells it.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Materializing => "materializing",
            Self::Running => "running",
            Self::Stopped(_) => "stopped",
            Self::Exited(_) => "exited",
        }
    }

    /// The `reason` of a `stopped` or `exited` record, else `None`.
    #[must_use]
    pub const fn reason(&self) -> Option<EndReason> {
        match self {
            Self::Pending | Self::Materializing | Self::Running => None,
            Self::Stopped(_) => Some(EndReason::Stopped),
            Self::Exited(ExitEnding::Exit { .. }) => Some(EndReason::Exit),
            Self::Exited(ExitEnding::Timeout) => Some(EndReason::Timeout),
            Self::Exited(ExitEnding::Oom) => Some(EndReason::Oom),
        }
    }

    /// The `exit_code` the BOX-011 table gives the record, else `None`.
    #[must_use]
    pub const fn exit_code(&self) -> Option<i32> {
        match self {
            Self::Stopped(StopEnding::ExitedFirst { exit_code })
            | Self::Exited(ExitEnding::Exit { exit_code }) => Some(*exit_code),
            Self::Exited(ExitEnding::Oom) => Some(OOM_EXIT_CODE),
            Self::Pending
            | Self::Materializing
            | Self::Running
            | Self::Stopped(StopEnding::Signalled { .. } | StopEnding::AtDaemonStart)
            | Self::Exited(ExitEnding::Timeout) => None,
        }
    }

    /// The number of the signal that ended a stopped box, else `None`.
    #[must_use]
    pub const fn signal(&self) -> Option<i32> {
        match self {
            Self::Stopped(StopEnding::Signalled { signal }) => Some(*signal),
            _ => None,
        }
    }

    /// Whether a daemon restart reaps a record in this state (BOX-012):
    /// only `pending` and `materializing` records, whose in-flight
    /// composition the restart lost.
    #[must_use]
    pub const fn reaped_at_restart(&self) -> bool {
        matches!(self, Self::Pending | Self::Materializing)
    }
}

impl From<BoxState> for RecordState {
    /// The stored status's state. A stored `Active` record is `running`.
    fn from(status: BoxState) -> Self {
        match status {
            BoxState::Pending => Self::Pending,
            BoxState::Materializing => Self::Materializing,
            BoxState::Active => Self::Running,
        }
    }
}

/// What a daemon restart does to a store (BOX-012).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartReap<T> {
    /// The records the restart keeps, in store order.
    pub kept: Vec<T>,
    /// The records the restart reaps, in store order.
    pub reaped: Vec<T>,
}

/// Split `records` into the ones a restart keeps and the ones it reaps,
/// by the state `state_of` reads from each.
pub fn restart_reap<T>(
    records: impl IntoIterator<Item = T>,
    state_of: impl Fn(&T) -> RecordState,
) -> RestartReap<T> {
    let (reaped, kept) = records
        .into_iter()
        .partition(|record| state_of(record).reaped_at_restart());
    RestartReap { kept, reaped }
}

/// The BOX-011 property for one state: the record is in exactly one of
/// the five states, and its `reason`, `exit_code` and `signal` are a row
/// of the table.
#[cfg(any(test, kani))]
fn holds_one_state_with_its_ending(state: &RecordState) -> bool {
    // Summed without a loop, so the Kani harness needs no unwinding.
    let held = u8::from(matches!(state, RecordState::Pending))
        + u8::from(matches!(state, RecordState::Materializing))
        + u8::from(matches!(state, RecordState::Running))
        + u8::from(matches!(state, RecordState::Stopped(_)))
        + u8::from(matches!(state, RecordState::Exited(_)));
    let exactly_one = held == 1;
    // Matched on the variant, not on `name()`: a string compare is a byte
    // loop, and Kani then needs a longer unwind bound.
    let ending = match state {
        RecordState::Pending | RecordState::Materializing | RecordState::Running => {
            state.reason().is_none() && state.exit_code().is_none() && state.signal().is_none()
        }
        RecordState::Stopped(_) => {
            state.reason() == Some(EndReason::Stopped)
                && !(state.exit_code().is_some() && state.signal().is_some())
        }
        RecordState::Exited(_) => {
            state.signal().is_none()
                && match state.reason() {
                    Some(EndReason::Exit) => state.exit_code().is_some(),
                    Some(EndReason::Timeout) => state.exit_code().is_none(),
                    Some(EndReason::Oom) => state.exit_code() == Some(OOM_EXIT_CODE),
                    _ => false,
                }
        }
    };
    exactly_one && ending
}

/// The BOX-012 property for one store: the restart reaps exactly the
/// `pending` and `materializing` records, keeps every other, and loses
/// none.
#[cfg(test)]
fn reaps_exactly_the_unfinished(store: &[RecordState]) -> bool {
    let unfinished =
        |s: &RecordState| matches!(s, RecordState::Pending | RecordState::Materializing);
    let outcome = restart_reap(store.iter().copied(), |s| *s);
    outcome.kept.len() + outcome.reaped.len() == store.len()
        && outcome.reaped.len() == store.iter().filter(|s| unfinished(s)).count()
        && outcome.reaped.iter().all(unfinished)
        && outcome.kept.iter().all(|s| !unfinished(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One value of every shape the type can hold, with edge numbers.
    fn every_shape() -> Vec<RecordState> {
        let mut states = vec![
            RecordState::Pending,
            RecordState::Materializing,
            RecordState::Running,
            RecordState::Stopped(StopEnding::AtDaemonStart),
            RecordState::Exited(ExitEnding::Timeout),
            RecordState::Exited(ExitEnding::Oom),
        ];
        for n in [0, 1, 2, 9, 15, 137, 255, -1, i32::MAX, i32::MIN] {
            states.push(RecordState::Stopped(StopEnding::ExitedFirst {
                exit_code: n,
            }));
            states.push(RecordState::Stopped(StopEnding::Signalled { signal: n }));
            states.push(RecordState::Exited(ExitEnding::Exit { exit_code: n }));
        }
        states
    }

    // BOX-011: each row of the table, and each pre-ending state.
    #[test]
    fn record_state_is_one_of_five_with_exit_reason() {
        let rows = [
            (RecordState::Pending, "pending", None, None, None),
            (
                RecordState::Materializing,
                "materializing",
                None,
                None,
                None,
            ),
            (RecordState::Running, "running", None, None, None),
            (
                RecordState::Exited(ExitEnding::Exit { exit_code: 3 }),
                "exited",
                Some(EndReason::Exit),
                Some(3),
                None,
            ),
            (
                RecordState::Exited(ExitEnding::Timeout),
                "exited",
                Some(EndReason::Timeout),
                None,
                None,
            ),
            (
                RecordState::Exited(ExitEnding::Oom),
                "exited",
                Some(EndReason::Oom),
                Some(137),
                None,
            ),
            (
                RecordState::Stopped(StopEnding::ExitedFirst { exit_code: 0 }),
                "stopped",
                Some(EndReason::Stopped),
                Some(0),
                None,
            ),
            (
                RecordState::Stopped(StopEnding::Signalled { signal: 15 }),
                "stopped",
                Some(EndReason::Stopped),
                None,
                Some(15),
            ),
            (
                RecordState::Stopped(StopEnding::AtDaemonStart),
                "stopped",
                Some(EndReason::Stopped),
                None,
                None,
            ),
        ];
        for (state, name, reason, exit_code, signal) in rows {
            assert_eq!(state.name(), name, "{state:?}");
            assert_eq!(state.reason(), reason, "{state:?}");
            assert_eq!(state.exit_code(), exit_code, "{state:?}");
            assert_eq!(state.signal(), signal, "{state:?}");
        }

        for (reason, spelled) in [
            (EndReason::Exit, "exit"),
            (EndReason::Timeout, "timeout"),
            (EndReason::Oom, "oom"),
            (EndReason::Stopped, "stopped"),
        ] {
            assert_eq!(
                serde_json_lenient::to_value(reason).unwrap(),
                serde_json_lenient::json!(spelled)
            );
        }

        assert_eq!(RecordState::from(BoxState::Pending), RecordState::Pending);
        assert_eq!(
            RecordState::from(BoxState::Materializing),
            RecordState::Materializing
        );
        assert_eq!(
            RecordState::from(BoxState::Active),
            RecordState::Running,
            "a stored active record, an old session included, is running"
        );
    }

    // BOX-011: the property the `state_is_exactly_one` Kani harness proves
    // for every value, checked here over every shape.
    #[test]
    fn state_is_exactly_one() {
        for state in every_shape() {
            assert!(holds_one_state_with_its_ending(&state), "{state:?}");
        }
    }

    fn names(records: &[(&'static str, RecordState)]) -> Vec<&'static str> {
        records.iter().map(|(name, _)| *name).collect()
    }

    // BOX-012: restart reaps the unfinished records and keeps the rest.
    #[test]
    fn restart_reaps_only_pending_and_materializing() {
        let store = [
            ("a", RecordState::Pending),
            ("b", RecordState::Running),
            ("c", RecordState::Materializing),
            ("d", RecordState::Stopped(StopEnding::AtDaemonStart)),
            ("e", RecordState::Exited(ExitEnding::Oom)),
        ];
        let outcome = restart_reap(store, |(_, state)| *state);
        assert_eq!(names(&outcome.reaped), ["a", "c"]);
        assert_eq!(names(&outcome.kept), ["b", "d", "e"]);

        for state in every_shape() {
            assert_eq!(
                state.reaped_at_restart(),
                matches!(state, RecordState::Pending | RecordState::Materializing),
                "{state:?}"
            );
        }
    }

    // BOX-012: the property the Kani harness of the same name proves,
    // checked here over every store of at most 4 records drawn from one
    // value of each state.
    #[test]
    fn restart_reaps_only_pending_or_materializing() {
        let shapes = [
            RecordState::Pending,
            RecordState::Materializing,
            RecordState::Running,
            RecordState::Stopped(StopEnding::Signalled { signal: 9 }),
            RecordState::Exited(ExitEnding::Exit { exit_code: 1 }),
        ];
        let mut stores: Vec<Vec<RecordState>> = vec![Vec::new()];
        let mut shorter: Vec<Vec<RecordState>> = vec![Vec::new()];
        for _ in 0..4 {
            shorter = shorter
                .iter()
                .flat_map(|store| {
                    shapes.iter().map(move |state| {
                        let mut next = store.clone();
                        next.push(*state);
                        next
                    })
                })
                .collect();
            stores.extend(shorter.iter().cloned());
        }
        assert_eq!(stores.len(), 1 + 5 + 25 + 125 + 625);
        for store in &stores {
            assert!(reaps_exactly_the_unfinished(store), "{store:?}");
        }
    }
}

/// Kani harnesses for BOX-011 and BOX-012. Run: `./scripts/kani.sh`.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// BOX-011: every record value is in exactly one state, and its
    /// ending is a row of the table.
    #[kani::proof]
    #[kani::unwind(1)]
    fn state_is_exactly_one() {
        let state = kani::any::<RecordState>();
        assert!(holds_one_state_with_its_ending(&state));
    }

    /// BOX-012: a restart reaps a record exactly when it is `pending` or
    /// `materializing`. The harness proves this per-record decision with
    /// no collection, so CBMC sees no heap. `restart_reap` is a
    /// `partition` on this predicate. The unit test of the same name
    /// checks `restart_reap` over every store of at most 4 records.
    #[kani::proof]
    fn restart_reaps_only_pending_or_materializing() {
        let state = kani::any::<RecordState>();
        assert!(
            state.reaped_at_restart()
                == matches!(state, RecordState::Pending | RecordState::Materializing)
        );
    }
}
