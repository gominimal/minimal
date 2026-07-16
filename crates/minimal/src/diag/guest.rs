//! Fetching the daemon's own diagnostic bundle for `min bug`.
//!
//! The daemon (native minimald or the in-VM one behind the minvmd bridge)
//! streams a nested tar+zstd archive which is stored raw at
//! `providers/<name>/guest/daemon-diag.tar.zst` — never re-packed, so "what
//! the daemon said" stays exactly distinguishable from "what the host saw".

use std::time::Duration;

use super::bundle::BundleWriter;
use super::manifest::Redaction;
use crate::client::Client;

/// Hard cap on the accepted guest bundle. A wedged vsock or runaway log
/// cannot make `min bug` itself balloon.
pub const GUEST_BUNDLE_MAX_BYTES: usize = 256 * 1024 * 1024;

/// Downloads the daemon bundle over `client` and stores it under
/// `providers/<provider>/guest/`. On failure writes `error.txt` there
/// instead and records a collector error — `min bug` always produces a
/// bundle.
pub async fn collect(
    w: &mut BundleWriter,
    provider: &str,
    client: &mut Client,
    timeout: Duration,
) -> Result<(), anyhow::Error> {
    let started = std::time::Instant::now();
    let req = minimald_rpc::DiagBundleRequest::default();

    let result = tokio::time::timeout(
        timeout,
        client.download_diag_bundle(&req, GUEST_BUNDLE_MAX_BYTES),
    )
    .await;

    let dest = format!("providers/{provider}/guest/daemon-diag.tar.zst");
    match result {
        Ok(Ok((bytes, truncated))) => {
            // A truncated stream is still collected — the manifest entry's
            // redaction records that only the leading bytes survived.
            let redaction = if truncated {
                Redaction::Truncated
            } else {
                Redaction::None
            };
            w.add_bytes(&dest, &bytes, redaction).await
        }
        Ok(Err(e)) => {
            let msg = format!("guest bundle download failed: {e:#}");
            w.error(format!("guest.{provider}"), &msg, started.elapsed());
            w.add_bytes(
                &format!("providers/{provider}/guest/error.txt"),
                msg.as_bytes(),
                Redaction::None,
            )
            .await
        }
        Err(_) => {
            let msg = format!("guest bundle download timed out after {timeout:?}");
            w.error(format!("guest.{provider}"), &msg, started.elapsed());
            w.add_bytes(
                &format!("providers/{provider}/guest/error.txt"),
                msg.as_bytes(),
                Redaction::None,
            )
            .await
        }
    }
}

/// Records why guest collection didn't run (no daemon, `--no-guest`).
pub async fn record_skipped(
    w: &mut BundleWriter,
    provider: &str,
    reason: &str,
) -> Result<(), anyhow::Error> {
    w.add_bytes(
        &format!("providers/{provider}/guest/error.txt"),
        reason.as_bytes(),
        Redaction::None,
    )
    .await
}
