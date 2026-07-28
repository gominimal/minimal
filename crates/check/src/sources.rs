use std::path::Path;

use super::Error;
use crate::{CheckCtx, CheckResult, CheckVerdict};
use graph::{BuildDep, Graph, SourceFetch};
use ot::OpTracker;
use tokio::sync::RwLockReadGuard;
use url::Url;

/// The URL schemes the source fetcher knows how to download; anything else
/// panics (`todo!()`) at fetch time. Keep in sync with `op::sources`.
const SUPPORTED_SCHEMES: &[&str] = &["http", "https", "gs"];

/// Validates the URLs of `type = source` (web) build inputs: each must parse as
/// a URL with a fetcher-supported scheme, and must not carry a double-slash in
/// its path (the classic result of concatenating a base and a relative path).
pub(crate) struct SourceUrlsValid;

impl crate::GraphBasedChecker for SourceUrlsValid {
    async fn check(
        self,
        ctx: &CheckCtx,
        pkg: String,
        _package_dir: &Path,
        graph: RwLockReadGuard<'_, Graph>,
        _ot: Option<OpTracker>,
    ) -> Result<CheckResult, Error> {
        let mut result = CheckResult {
            verdict: CheckVerdict::Skip,
            check: "source urls valid".into(),
            err: vec![],
        };
        if ctx.skip_checkers.contains(&"source urls valid".to_string()) {
            return Ok(result);
        }

        let bsr = match graph.by_name(&pkg) {
            Some(b) => *b,
            None => {
                return Ok(result); // skip, we need the build
            }
        };
        let build = graph.get(&bsr).unwrap();

        result.verdict = CheckVerdict::Pass;
        for dep in &build.build_deps {
            // Only web sources carry a URL; local sources are file paths.
            let BuildDep::Source(source) = dep else {
                continue;
            };
            let SourceFetch::Web { url, .. } = &source.from else {
                continue;
            };

            let parsed = match Url::parse(url) {
                Ok(u) => u,
                Err(e) => {
                    result.verdict = CheckVerdict::Fail;
                    result
                        .err
                        .push(format!("source url '{}' is not a valid URL: {}", url, e));
                    continue;
                }
            };

            if !SUPPORTED_SCHEMES.contains(&parsed.scheme()) {
                result.verdict = CheckVerdict::Fail;
                result.err.push(format!(
                    "source url '{}' has unsupported scheme '{}': expected one of {}",
                    url,
                    parsed.scheme(),
                    SUPPORTED_SCHEMES.join(", "),
                ));
            }

            // The scheme's own `//` and the authority live outside the path, so
            // a `//` in the path is always an accidental double-slash.
            if parsed.path().contains("//") {
                result.verdict = CheckVerdict::Fail;
                result.err.push(format!(
                    "source url '{}' contains a double-slash in its path",
                    url,
                ));
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CheckCtx, CheckVerdict, GraphBasedChecker};
    use decode::Layer;
    use graph::Graph;
    use lcache::Cache;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    /// Builds a minimal `CheckCtx`. The source-url checker touches neither the
    /// cache nor the filesystem, so a cache rooted at a throwaway dir suffices.
    fn make_ctx(cache_dir: &std::path::Path, skip_checkers: Vec<String>) -> CheckCtx {
        let cache = Cache::at_dir(cache_dir).expect("Cache::at_dir");
        CheckCtx::new(
            vec![],
            skip_checkers,
            false,
            None,
            cache_dir.to_path_buf(),
            cache,
            None,
        )
    }

    fn make_tmp_dir(suffix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "check_sources_test_{}_{suffix}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create test tmp dir");
        dir
    }

    /// Serializes the `CARGO_MANIFEST_DIR` redirect below so concurrent
    /// ingesting tests never race on the process environment.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Ingests a single inline-Nickel package into a fresh graph. Mirrors the
    /// helper in `outputs.rs`: `Layer::new_for_test` resolves
    /// `import "minimal.ncl"` relative to `CARGO_MANIFEST_DIR/minimal-ncl`, so
    /// we point that variable at the `stdlib` crate for the duration of the
    /// parse.
    fn graph_with_pkg(nickel: &str) -> Arc<RwLock<Graph>> {
        let stdlib = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../stdlib")
            .canonicalize()
            .expect("stdlib crate dir must exist");
        let layer = {
            let _guard = ENV_LOCK.lock().expect("env lock");
            let prev_manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR");
            // SAFETY: every test that mutates CARGO_MANIFEST_DIR does so while
            // holding ENV_LOCK, and no other code in this test binary reads the
            // variable, so this set never races with another thread's access.
            unsafe {
                std::env::set_var("CARGO_MANIFEST_DIR", &stdlib);
            }
            let parsed = Layer::new_for_test(nickel.to_string());
            // SAFETY: same invariant as the set above — still under ENV_LOCK.
            unsafe {
                match prev_manifest_dir {
                    Some(v) => std::env::set_var("CARGO_MANIFEST_DIR", v),
                    None => std::env::remove_var("CARGO_MANIFEST_DIR"),
                }
            }
            parsed.expect("parse test layer")
        };
        let graph = Graph::new().ingest(layer).expect("ingest test layer");
        Arc::new(RwLock::new(graph))
    }

    async fn run(graph: &Arc<RwLock<Graph>>, pkg: &str, ctx: &CheckCtx) -> CheckResult {
        let guard = graph.read().await;
        SourceUrlsValid
            .check(ctx, pkg.to_string(), std::path::Path::new("."), guard, None)
            .await
            .expect("check should not error")
    }

    /// A well-formed `http://` source with a clean path passes.
    #[tokio::test]
    async fn passes_for_valid_url() {
        let tmpdir = make_tmp_dir("valid");
        let ctx = make_ctx(&tmpdir, vec![]);
        let graph = graph_with_pkg(
            r#"
            let {BuildSpec, Source, ..} = import "minimal.ncl" in
            {
                name = "pkg",
                build_deps = [
                    {url = "https://example.com/src.tar.gz", sha256 = "abc123"} | Source,
                ],
                cmd = "",
            } | BuildSpec
            "#,
        );

        let result = run(&graph, "pkg", &ctx).await;
        assert!(
            matches!(result.verdict, CheckVerdict::Pass),
            "expected Pass, got {:?} (errors: {:?})",
            result.verdict,
            result.err
        );
        assert!(result.err.is_empty());

        std::fs::remove_dir_all(&tmpdir).ok();
    }

    /// A package with no source inputs at all still passes (nothing to check).
    #[tokio::test]
    async fn passes_when_no_source_inputs() {
        let tmpdir = make_tmp_dir("no_sources");
        let ctx = make_ctx(&tmpdir, vec![]);
        let graph = graph_with_pkg(
            r#"
            let {BuildSpec, ..} = import "minimal.ncl" in
            { name = "pkg", build_deps = [], cmd = "" } | BuildSpec
            "#,
        );

        let result = run(&graph, "pkg", &ctx).await;
        assert!(matches!(result.verdict, CheckVerdict::Pass));

        std::fs::remove_dir_all(&tmpdir).ok();
    }

    /// A syntactically invalid URL (no scheme) fails.
    #[tokio::test]
    async fn fails_for_unparseable_url() {
        let tmpdir = make_tmp_dir("unparseable");
        let ctx = make_ctx(&tmpdir, vec![]);
        let graph = graph_with_pkg(
            r#"
            let {BuildSpec, Source, ..} = import "minimal.ncl" in
            {
                name = "pkg",
                build_deps = [
                    {url = "example.com/src.tar.gz", sha256 = "abc123"} | Source,
                ],
                cmd = "",
            } | BuildSpec
            "#,
        );

        let result = run(&graph, "pkg", &ctx).await;
        assert!(
            matches!(result.verdict, CheckVerdict::Fail),
            "expected Fail, got {:?}",
            result.verdict
        );
        assert!(
            result.err.iter().any(|e| e.contains("not a valid URL")),
            "expected an invalid-URL error, got {:?}",
            result.err
        );

        std::fs::remove_dir_all(&tmpdir).ok();
    }

    /// A URL whose scheme the fetcher can't handle fails.
    #[tokio::test]
    async fn fails_for_unsupported_scheme() {
        let tmpdir = make_tmp_dir("scheme");
        let ctx = make_ctx(&tmpdir, vec![]);
        let graph = graph_with_pkg(
            r#"
            let {BuildSpec, Source, ..} = import "minimal.ncl" in
            {
                name = "pkg",
                build_deps = [
                    {url = "ftp://example.com/src.tar.gz", sha256 = "abc123"} | Source,
                ],
                cmd = "",
            } | BuildSpec
            "#,
        );

        let result = run(&graph, "pkg", &ctx).await;
        assert!(matches!(result.verdict, CheckVerdict::Fail));
        assert!(
            result.err.iter().any(|e| e.contains("unsupported scheme")),
            "expected an unsupported-scheme error, got {:?}",
            result.err
        );

        std::fs::remove_dir_all(&tmpdir).ok();
    }

    /// A double-slash in the path (but not the scheme) fails.
    #[tokio::test]
    async fn fails_for_double_slash_in_path() {
        let tmpdir = make_tmp_dir("double_slash");
        let ctx = make_ctx(&tmpdir, vec![]);
        let graph = graph_with_pkg(
            r#"
            let {BuildSpec, Source, ..} = import "minimal.ncl" in
            {
                name = "pkg",
                build_deps = [
                    {url = "https://example.com/foo//src.tar.gz", sha256 = "abc123"} | Source,
                ],
                cmd = "",
            } | BuildSpec
            "#,
        );

        let result = run(&graph, "pkg", &ctx).await;
        assert!(matches!(result.verdict, CheckVerdict::Fail));
        assert!(
            result.err.iter().any(|e| e.contains("double-slash")),
            "expected a double-slash error, got {:?}",
            result.err
        );

        std::fs::remove_dir_all(&tmpdir).ok();
    }

    /// `skip_checkers` short-circuits to Skip before any graph inspection.
    #[tokio::test]
    async fn skips_when_in_skip_checkers() {
        let tmpdir = make_tmp_dir("skip");
        let ctx = make_ctx(&tmpdir, vec!["source urls valid".to_string()]);
        let graph = graph_with_pkg(
            r#"
            let {BuildSpec, Source, ..} = import "minimal.ncl" in
            {
                name = "pkg",
                build_deps = [
                    {url = "example.com/broken", sha256 = "abc123"} | Source,
                ],
                cmd = "",
            } | BuildSpec
            "#,
        );

        let result = run(&graph, "pkg", &ctx).await;
        assert!(matches!(result.verdict, CheckVerdict::Skip));

        std::fs::remove_dir_all(&tmpdir).ok();
    }
}
