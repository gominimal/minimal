//! `BuildSpec` declares `attrs | Attrs` and `needs | Needs` in
//! `minimal.ncl`. These tests pin that both contracts hold however a
//! package writes the field (inbox#1268): through `Layer::new_for_test` and
//! from a layer directory through `Layer::new`, with and without the
//! package applying the contract itself. Each case loads a good value
//! first, so a load error for another reason cannot pass for a refusal.

use crate::load::Loader;
use crate::{Error, Layer, LoadOptions};

/// The attribute every `attrs` case loads.
const GOOD_ATTR: &str = "upstream_version = \"1.25.0\"";
/// REV-001: `upstream_version` never carries our revision suffix.
const BAD_ATTR: &str = "upstream_version = \"1.25.0-r1\"";

/// The loader's report for an error, as a user reads it.
fn report(err: &Error) -> String {
    let mut buf = codespan_reporting::term::termcolor::Buffer::no_color();
    err.report_to(&mut buf);
    String::from_utf8_lossy(buf.as_slice()).into_owned()
}

/// A package spec under `| BuildSpec` alone, with `extra` among its fields.
fn spec(extra: &str) -> String {
    format!(
        "let {{ Attrs, BuildSpec, .. }} = import \"minimal.ncl\" in\n\
         {{ name = \"p\", build_deps = [], cmd = \"\", {extra} }} | BuildSpec\n"
    )
}

/// Lays out a one-package layer, as a real layer is on disk, and loads it
/// with `Layer::new`, the call `graph::loader` makes for a layer. Returns
/// the load and the package's build.ncl path.
fn load_layer_dir(build_ncl: &str) -> (Result<Layer, Error>, String) {
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("packages").join("p");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(pkg.join("build.ncl"), build_ncl).unwrap();
    let path = pkg.join("build.ncl").to_string_lossy().into_owned();
    (Layer::new(dir.path(), &LoadOptions::for_test()), path)
}

/// `good` loads and `bad` is refused by a contract with an error, not a
/// panic. Returns the refusal's report.
fn good_loads_bad_refused(
    good: &str,
    bad: &str,
    load: impl Fn(&str) -> Result<Layer, Error>,
) -> String {
    if let Err(e) = load(good) {
        panic!(
            "the good value did not load, so the test proves nothing:\n{}\n{good}",
            report(&e)
        );
    }
    match load(bad) {
        Ok(_) => panic!("the bad value loaded:\n{bad}"),
        Err(e @ Error::Nickel(_)) => report(&e),
        Err(e) => panic!(
            "the bad value was refused by the reader, not the contract:\n{}",
            report(&e)
        ),
    }
}

/// From a layer directory: `bad` is refused, and the report names the
/// package's file and `names`.
fn layer_dir_refuses_naming(good: &str, bad: &str, names: &str) {
    let path = std::sync::Mutex::new(String::new());
    let r = good_loads_bad_refused(good, bad, |src| {
        let (res, p) = load_layer_dir(src);
        *path.lock().unwrap() = p;
        res
    });
    let path = path.into_inner().unwrap();
    assert!(
        r.contains(&path) && r.contains(names),
        "the refusal does not name both {path} and `{names}`:\n{r}"
    );
}

/// The Attrs contract applied to an attrs record itself refuses the
/// revision suffix: the rule the load-path tests below expect.
#[test]
fn attrs_contract_refuses_a_revision_suffix() {
    let accepted = |attrs: &str| {
        let src = format!("let {{Attrs, ..}} = import \"minimal.ncl\" in {{{attrs}}} | Attrs");
        Loader::new(&src, None, &LoadOptions::for_test())
            .unwrap()
            .finish()
            .is_ok()
    };
    assert!(accepted(GOOD_ATTR));
    assert!(!accepted(BAD_ATTR));
}

/// A spec with no `| Attrs` of its own gets the attribute rules from
/// BuildSpec's `attrs | Attrs` field contract.
#[test]
fn buildspec_applies_the_attrs_contract() {
    let r = good_loads_bad_refused(
        &spec(&format!("attrs.{GOOD_ATTR}")),
        &spec(&format!("attrs.{BAD_ATTR}")),
        |src| Layer::new_for_test(src.to_string()),
    );
    assert!(r.contains("upstream_version"), "{r}");
}

/// A package in a layer directory that writes `attrs = { .. } | Attrs`, as
/// most packages do: the contract then applies twice, and the good value
/// still loads.
#[test]
fn a_package_with_its_own_attrs_contract_is_checked() {
    layer_dir_refuses_naming(
        &spec(&format!("attrs = {{ {GOOD_ATTR} }} | Attrs")),
        &spec(&format!("attrs = {{ {BAD_ATTR} }} | Attrs")),
        "upstream_version",
    );
}

/// A package in a layer directory that writes a plain attrs record,
/// relying on BuildSpec's field contract.
#[test]
fn a_package_without_its_own_attrs_contract_is_checked() {
    layer_dir_refuses_naming(
        &spec(&format!("attrs = {{ {GOOD_ATTR} }}")),
        &spec(&format!("attrs = {{ {BAD_ATTR} }}")),
        "upstream_version",
    );
}

/// BuildSpec's `needs | Needs`: an unknown need, and a known need of the
/// wrong shape, are refused on both load paths. The wrong shape's refusal
/// says what a need looks like.
#[test]
fn an_unknown_or_misshapen_need_is_refused() {
    let good = spec("needs = { internet = {} }");
    for (bad, names) in [
        (spec("needs = { bogus = {} }"), "bogus"),
        (
            spec("needs = { internet = true }"),
            "a need is written as a record, as in `needs.internet = {}`",
        ),
    ] {
        good_loads_bad_refused(&good, &bad, |src| Layer::new_for_test(src.to_string()));
        layer_dir_refuses_naming(&good, &bad, names);
    }
}

/// `attrs` and `needs` are not loosely annotated: their contracts refuse a
/// value that is not a record before the decoder sees it.
#[test]
fn attrs_or_needs_that_are_not_a_record_are_refused() {
    for field in ["attrs", "needs"] {
        let r = good_loads_bad_refused(
            &spec(&format!("{field} = {{}}")),
            &spec(&format!("{field} = 1")),
            |src| Layer::new_for_test(src.to_string()),
        );
        assert!(r.contains("not a record"), "`{field} = 1`:\n{r}");
    }
}
