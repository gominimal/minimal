//! Golden vectors for the Box Spec expansion (BOX-145).
//!
//! The session and task entries of the example `minimal.toml`, and the
//! implicit `default` entry of a file that declares only
//! `[defaults.session]`, expand to the spec bytes and projection digests
//! pinned in `tests/golden/vectors.json`. The six built-in types render
//! their definitions equal to theirs.
//!
//! The vectors file holds one vector on each line, as JCS. When a vector
//! fails, the test names it and the first byte that differs. After an
//! intended change, run the test with `MFILE_BLESS_GOLDEN=1` to write the
//! file again, and review its diff.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use mfile::box_types::{BUILTIN_BOX_TYPES, BoxTypes, builtin_constraints, builtin_defaults};
use mfile::entry::{BoxEntry, implicit_default_entry, read_entries};
use mfile::expand::{Layers, expand, expandable_type};
use mfile::projection::Json;

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

/// The vector of one entry, expanded as `min box start` expands it: the
/// file's legacy tables read, the type chain and `[defaults]` layers
/// applied, and the flat egress keys moved to their nested keys.
fn entry_vector(doc: &toml::Table, types: &BoxTypes, entry: &BoxEntry) -> Json {
    let resolved = expandable_type(entry, types).expect("the entry's type resolves");
    let defaults = doc
        .get("defaults")
        .and_then(toml::Value::as_table)
        .cloned()
        .unwrap_or_default();
    let project_types: BTreeSet<String> = types.project().keys().cloned().collect();
    let layers = Layers {
        upstream: doc
            .get("upstream")
            .and_then(toml::Value::as_table)
            .cloned()
            .unwrap_or_default(),
        type_defaults: resolved.defaults.clone(),
        type_constraints: resolved.constraints.clone(),
        ..Layers::default()
    }
    .with_file_defaults(&defaults, entry.box_type.as_deref(), &project_types);
    let mut expansion = expand(entry, &layers).expect("the entry expands");
    mfile::network::canonicalize(&mut expansion.spec).expect("the network canonicalises");
    let spec = expansion.spec_bytes().expect("the spec serialises");
    let projection = expansion.projection(&resolved);
    Json::Object(BTreeMap::from([
        ("spec".to_owned(), Json::Str(spec)),
        ("projection".to_owned(), Json::Str(projection.record.jcs())),
        ("digest".to_owned(), Json::Str(projection.digest())),
    ]))
}

/// The vectors of every session and task entry of the file `name`, and of
/// its implicit `default` entry when it has one, each under
/// `<file stem>/<entry name>`.
fn file_vectors(name: &str, out: &mut Vec<(String, Json)>) {
    let bytes = std::fs::read(golden_dir().join(name)).expect("the golden file reads");
    let mut doc: toml::Table = toml::from_slice(&bytes).expect("the golden file is TOML");
    mfile::legacy::canonicalize(&mut doc, mfile::legacy::this_release())
        .expect("the legacy tables read");
    let types = BoxTypes::from_file(&doc).expect("the box types resolve");
    let mut entries = read_entries(&bytes).expect("the entries read");
    if let Some(implicit) = implicit_default_entry(&entries, |t| types.root(t)) {
        entries.push(implicit);
    }
    let stem = name.trim_end_matches(".toml");
    for entry in &entries {
        let root = entry.box_type.as_deref().and_then(|t| types.root(t));
        // Only session and task entries expand (BOX-063). The others are
        // declared for gominimal/inbox#678.
        if !matches!(root, Some("session" | "task")) {
            continue;
        }
        out.push((
            format!("{stem}/{}", entry.name),
            entry_vector(&doc, &types, entry),
        ));
    }
}

/// The definition of each built-in type: its root, its defaults and its
/// constraints, as canonical TOML.
fn builtin_vectors(out: &mut Vec<(String, Json)>) {
    for name in BUILTIN_BOX_TYPES {
        let toml_of = |t: toml::Table| toml::to_string(&t).expect("the table serialises");
        out.push((
            format!("builtin/{name}"),
            Json::Object(BTreeMap::from([
                (
                    "root".to_owned(),
                    Json::Str(mfile::box_types::builtin(name).unwrap_or("").to_owned()),
                ),
                (
                    "defaults".to_owned(),
                    Json::Str(toml_of(builtin_defaults(name))),
                ),
                (
                    "constraints".to_owned(),
                    Json::Str(toml_of(builtin_constraints(name))),
                ),
            ])),
        ));
    }
}

/// The vectors file's bytes: a JSON object with one member on each line.
fn render(vectors: &[(String, Json)]) -> String {
    let mut out = String::from("{\n");
    for (i, (name, value)) in vectors.iter().enumerate() {
        let sep = if i + 1 < vectors.len() { "," } else { "" };
        out.push_str(&format!(
            "{}:{}{sep}\n",
            Json::Str(name.clone()).jcs(),
            value.jcs()
        ));
    }
    out.push_str("}\n");
    out
}

/// The vector whose line holds byte `offset` of `text`, by its name.
fn vector_at(text: &str, offset: usize) -> String {
    let bytes = text.as_bytes();
    let start = bytes[..offset]
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(0, |i| i + 1);
    let line = String::from_utf8_lossy(&bytes[start..]);
    line.strip_prefix('"')
        .and_then(|rest| rest.split('"').next())
        .unwrap_or("(the file's frame)")
        .to_owned()
}

// BOX-145
#[test]
fn example_expansion_matches_golden_vectors() {
    let mut vectors = Vec::new();
    file_vectors("example.toml", &mut vectors);
    file_vectors("defaults_session_only.toml", &mut vectors);
    builtin_vectors(&mut vectors);

    let names: Vec<&str> = vectors.iter().map(|(n, _)| n.as_str()).collect();
    for expected in [
        "example/dev",
        "example/lint",
        "example/test",
        "defaults_session_only/default",
    ] {
        assert!(names.contains(&expected), "no vector {expected}: {names:?}");
    }
    assert!(
        !names.iter().any(|n| n.ends_with("/reviewer")),
        "the agent entry is not expanded: {names:?}"
    );

    let actual = render(&vectors);
    let path = golden_dir().join("vectors.json");
    if std::env::var_os("MFILE_BLESS_GOLDEN").is_some() {
        std::fs::write(&path, &actual).expect("the vectors file writes");
        return;
    }
    let pinned = std::fs::read_to_string(&path).expect("the vectors file reads");
    if actual == pinned {
        return;
    }
    let (a, p) = (actual.as_bytes(), pinned.as_bytes());
    let at = a
        .iter()
        .zip(p)
        .position(|(x, y)| x != y)
        .unwrap_or_else(|| a.len().min(p.len()));
    let context = |b: &[u8]| {
        let end = (at + 40).min(b.len());
        String::from_utf8_lossy(&b[at.saturating_sub(20)..end]).into_owned()
    };
    panic!(
        "vector {} differs from tests/golden/vectors.json at byte {at}: \
         pinned {:?} (near {:?}), got {:?} (near {:?})",
        vector_at(&pinned, at.min(pinned.len())),
        p.get(at).map(|b| *b as char),
        context(p),
        a.get(at).map(|b| *b as char),
        context(a),
    );
}
