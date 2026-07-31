//! Bake the shipped GitHub App client id into the crate at build time.
//!
//! `config.rs` reads the value with `option_env!(CLIENT_ID_BUILD_ENV)`, which is
//! resolved when *this crate* is compiled. Cargo does not otherwise know that
//! the compilation depends on that variable, so a changed id would be served
//! from a stale build cache; the `rerun-if-env-changed` below is what makes the
//! injection reliable.
//!
//! Nothing here fails an unset build: a tree built without the variable ships an
//! unconfigured client id and every GitHub op fails closed with
//! `Error::NotConfigured`, exactly as it did before this seam existed.

/// Build-time environment variable carrying the GitHub App client id. Kept in
/// step with `config::CLIENT_ID_BUILD_ENV`.
const CLIENT_ID_BUILD_ENV: &str = "MINIMAL_GITHUB_CLIENT_ID";

fn main() {
    println!("cargo::rerun-if-env-changed={CLIENT_ID_BUILD_ENV}");
    println!("cargo::rerun-if-changed=build.rs");
}
