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

/// Seconds since the Unix epoch, for certificate validity windows.
#[cfg(not(target_arch = "wasm32"))]
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(target_arch = "wasm32")]
pub fn unix_now() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}
