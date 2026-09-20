//! The process-level rustls crypto provider.

/// Names `ring` as this process's rustls crypto provider, once.
///
/// A workspace build compiles two providers in: `ring`, which the workspace
/// rustls pin selects and which the egress proxy's configurations name
/// explicitly, and `aws-lc-rs`, which `google-cloud-auth` and
/// `google-cloud-storage` turn on through their default
/// `default-rustls-provider` feature. rustls refuses to choose between two and
/// panics the first time a configuration is built without a named provider —
/// `hyper-rustls`'s connector builder, under every google-cloud client, does
/// exactly that:
///
/// ```text
/// Could not automatically determine the process-level CryptoProvider from
/// Rustls crate features.
/// ```
///
/// So the choice is made here, in library code, and every constructor that
/// builds a TLS client calls it first. A `main` cannot do this on behalf of the
/// tests: no test binary runs one, which is why naming the provider in
/// `minimald`'s `main` alone left the workspace's test binaries panicking.
///
/// Idempotent and infallible: a second call is a no-op, and so is a call made
/// after some other code installed a provider — `install_default` refuses to
/// replace one, and that refusal is the outcome we want.
pub fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(test)]
mod tests {
    use super::install_crypto_provider;
    use rustls::crypto::CryptoProvider;

    /// The panic this guards against is "no provider chosen", so prove one is
    /// installed afterwards — and that the second call stays a no-op instead of
    /// letting `install_default`'s refusal escape.
    #[test]
    fn installs_a_process_default_and_is_idempotent() {
        install_crypto_provider();
        assert!(CryptoProvider::get_default().is_some());

        install_crypto_provider();
        assert!(CryptoProvider::get_default().is_some());
    }
}
