//! The microVM guest's `/init` initialises telemetry from an initramfs that
//! holds the daemon binary and nothing else, so there are no CA roots on
//! disk. An `http://` collector must still get an exporter (spec 25,
//! TEL-007). This is its own test binary, so the environment it sets is
//! this process's alone.

use std::time::Duration;

/// Linux only, like the guest. On macOS rustls-native-certs reads the
/// keychain and ignores `SSL_CERT_FILE` and `SSL_CERT_DIR`, so the
/// environment cannot take the roots away and the test would prove
/// nothing; it is reported as ignored there rather than passing.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "needs Linux: elsewhere the platform finds CA roots without SSL_CERT_FILE/SSL_CERT_DIR, so the guest's no-roots case cannot be simulated"
)]
fn an_http_exporter_builds_with_no_ca_roots_on_disk() {
    let empty = tempfile::tempdir().unwrap();
    // SAFETY: the only test in this binary, so no other thread reads the
    // environment while it is set, and `init` starts its threads afterwards.
    // When set, rustls-native-certs reads only these: a missing file and
    // an empty directory are the initramfs's "no roots at all".
    unsafe { std::env::set_var("SSL_CERT_FILE", empty.path().join("none.pem")) };
    // SAFETY: as above.
    unsafe { std::env::set_var("SSL_CERT_DIR", empty.path()) };
    // Premise: the client `opentelemetry-otlp` would build fails here, as it
    // does in the guest. If it builds, this host finds roots some other way
    // and the test would prove nothing, so that fails rather than passes.
    assert!(
        reqwest::blocking::Client::builder().build().is_err(),
        "premise: the default reqwest client still finds CA roots with SSL_CERT_FILE and \
         SSL_CERT_DIR pointing at nothing, so this host cannot simulate the guest"
    );
    for k in [
        "OTEL_SDK_DISABLED",
        "DO_NOT_TRACK",
        "OTEL_TRACES_EXPORTER",
        "MINIMAL_OTEL_TRACES_EXPORTER",
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
        "MINIMAL_OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
        "OTEL_EXPORTER_OTLP_ENDPOINT",
    ] {
        // SAFETY: as above.
        unsafe { std::env::remove_var(k) };
    }
    for (k, v) in [
        ("MINIMAL_TELEMETRY", "1"),
        ("MINIMAL_OTEL_SPOOL", "0"),
        ("MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:9"),
    ] {
        // SAFETY: as above.
        unsafe { std::env::set_var(k, v) };
    }
    mlog::otel::init("minimald");
    // With the spool off, a tracer is installed only if the exporter built.
    assert!(
        mlog::otel::exporting(),
        "no trace exporter for an http endpoint without CA roots"
    );
    mlog::otel::shutdown(Duration::from_millis(100));
}
