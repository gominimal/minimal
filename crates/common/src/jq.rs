use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;

use jaq_all::jaq_core::Filter;
use jaq_all::jaq_core::ValT;
use jaq_all::jaq_core::{Ctx, Vars, data::JustLut};
use jaq_all::json::Val;

/// An error when working with a jq predicate or filter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JqError {
    pub err: String,

    pub relevant_file: Option<String>,
    pub relevant_jq: Option<String>,
}

/// Parses the given bytes based on heuristics regarding the given path (i.e. file extension).
///
/// The parse call into the third-party jaq stack is wrapped in [`guard`]: this
/// module's contract is to return `Err` on bad input, never to abort the
/// process, but `jaq`/`hifijson` can panic on adversarial data (a fuzzer found
/// an `Ord` total-order violation in std's sort on numbers that overflow to
/// ±inf). Since `parse_file`'s input is supply-chain-influenced (upstream
/// project data files, via `decode::stacks`), a hostile file must not take the
/// tool down.
pub fn parse_file<P: AsRef<Path>>(path: P, data: Vec<u8>) -> Result<Val, JqError> {
    let path = path.as_ref();
    let err = |e: String| JqError {
        err: e,
        relevant_file: Some(path.to_string_lossy().into_owned()),
        relevant_jq: None,
    };
    match path.extension().map(|oss| oss.to_str()) {
        Some(Some("toml")) => guard(path, || {
            let text = String::from_utf8(data).map_err(|e| err(e.to_string()))?;
            jaq_all::fmts::read::toml::parse(&text).map_err(|e| err(e.to_string()))
        }),
        Some(Some("json")) => guard(path, || {
            jaq_all::fmts::read::json::parse_single(&data).map_err(|e| err(e.to_string()))
        }),
        _ => Err(err("cannot handle file extension".to_string())),
    }
}

/// Runs a call into the third-party jaq parser with panic containment,
/// converting a caught unwind into the [`JqError`] the signature promises.
///
/// This relies on the default `panic = "unwind"` strategy. The `jq_parse_json`
/// fuzz target builds `panic = "abort"` (libfuzzer-sys installs an abort hook),
/// so it cannot observe this containment — the regression is proven by
/// `parse_file_contains_jaq_panic` below, an ordinary `#[test]`, per
/// docs/fuzzing.md §7.
fn guard<T>(path: &Path, f: impl FnOnce() -> Result<T, JqError>) -> Result<T, JqError> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(result) => result,
        Err(panic) => {
            let detail = panic
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".to_string());
            Err(JqError {
                err: format!("jq parser panicked on this input: {detail}"),
                relevant_file: Some(path.to_string_lossy().into_owned()),
                relevant_jq: None,
            })
        }
    }
}

/// A compiled jq expression.
pub struct Expression {
    raw: String,
    filter: Filter<JustLut<Val>>,
}

impl Expression {
    pub fn parse(filter_str: &str) -> Result<Self, JqError> {
        match jaq_all::compile_with(
            filter_str,
            jaq_all::jaq_core::defs()
                .chain(jaq_all::jaq_std::defs())
                .chain(jaq_all::json::defs()),
            jaq_all::jaq_core::funs()
                .chain(jaq_all::jaq_std::funs())
                .chain(jaq_all::json::funs()),
            &[],
        ) {
            Ok(filter) => Ok(Expression {
                filter,
                raw: filter_str.to_string(),
            }),
            Err(error) => Err(JqError {
                err: format!("{:?}", error),
                relevant_file: None,
                relevant_jq: Some(filter_str.to_string()),
            }),
        }
    }

    pub fn predicate_eval(&self, input: Val) -> Result<bool, JqError> {
        let ctx = Ctx::<JustLut<Val>>::new(&self.filter.lut, Vars::new([]));

        match self.filter.id.run((ctx, input)).next() {
            Some(Ok(v)) => Ok(v.as_bool()),
            Some(Err(e)) => Err(JqError {
                err: format!("{:?}", e),
                relevant_file: None,
                relevant_jq: Some(self.raw.clone()),
            }),
            None => Err(JqError {
                err: "predicate yielded no result".to_string(),
                relevant_file: None,
                relevant_jq: Some(self.raw.clone()),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_file_rejects_malformed_json_without_panicking() {
        // Regression for a fuzzer-found panic: `parse_single(..).unwrap()` on
        // malformed (or empty) JSON. Both must now return a `JqError`.
        assert!(parse_file("x.json", Vec::new()).is_err());
        assert!(parse_file("x.json", b"{not json".to_vec()).is_err());
    }

    #[test]
    fn parse_file_accepts_valid_json() {
        assert!(parse_file("x.json", b"{\"a\": 1}".to_vec()).is_ok());
    }

    #[test]
    fn parse_file_contains_jaq_panic() {
        // Regression for a fuzzer-found abort: the jaq/hifijson JSON parser
        // panics via an `Ord` total-order violation in std's sort on inputs
        // with numbers that overflow f64 to ±inf. `parse_file` must contain
        // that unwind and return a `JqError`, not abort the process. The fuzz
        // target can't prove this (it builds panic=abort), so this test does.
        // Input is the minimized crash artifact.
        let repro = include_bytes!("testdata/jq_ord_violation_repro");
        let err = parse_file("x.json", repro.to_vec())
            .expect_err("jaq panic must be contained as an error, not abort");
        // Assert the panic path specifically — not just any error — so this
        // can't pass vacuously if the reproducer ever stops panicking.
        assert!(
            err.err.contains("jq parser panicked"),
            "expected a contained panic, got: {}",
            err.err
        );
    }
}
