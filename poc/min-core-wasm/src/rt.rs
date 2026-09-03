//! The two runtime services the network layer needs and the core must not
//! take from tokio directly: a monotonic clock and a sleep. Native: tokio.
//! Browser: `Date.now()` and `setTimeout` (gloo-timers).

use std::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
pub fn now_ms() -> i64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as i64
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn sleep(d: Duration) {
    tokio::time::sleep(d).await
}

#[cfg(target_arch = "wasm32")]
pub fn now_ms() -> i64 {
    js_sys::Date::now() as i64
}

#[cfg(target_arch = "wasm32")]
pub async fn sleep(d: Duration) {
    gloo_timers::future::TimeoutFuture::new(d.as_millis().min(u32::MAX as u128) as u32).await
}
