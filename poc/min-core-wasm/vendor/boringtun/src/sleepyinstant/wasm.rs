//! Fallback clock for targets with neither `clock_gettime` nor the Windows
//! APIs — in practice `wasm32-unknown-unknown`, where `std::time::Instant`
//! panics. `web-time` reads `performance.now()` in a browser and is a plain
//! `std::time::Instant` everywhere else. A page cannot observe host sleep the
//! way the unix backend does, so this clock is monotonic but not sleep-aware.
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Instant {
    t: web_time::Instant,
}

impl Instant {
    pub(crate) fn now() -> Self {
        Self {
            t: web_time::Instant::now(),
        }
    }

    pub(crate) fn duration_since(&self, earlier: Instant) -> Duration {
        self.t.saturating_duration_since(earlier.t)
    }
}
