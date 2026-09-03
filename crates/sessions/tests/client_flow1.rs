//! Integration tests for the client side of session creation, flow 1:
//! TOML loadout → [`UserComposer`] → `WireContribution`.
//!
//! Each test exercises the crate's public surface only (this lives in
//! `tests/`, not `src/`, so visibility leaks here mean we broke the
//! contract).

use std::collections::HashMap;

use camino::Utf8Path;
use sessions::client::composer::UserComposer;
use sessions::core::compose::{ComposeError, ComposeOptions, StoredEnv};
use sessions::core::loadout::Loadout;
use sessions::core::policy::{PatchesPolicy, UserPolicy, VarsPolicy};
use sessions::core::source::Source;
use sessions::wire::primitives::WireSource;

// =====================================================================
// Support
// =====================================================================

/// Build an env closure pinned to a fixed `(name, value)` table. Tests
/// using this never touch the process environment.
fn pinned_env(pairs: &[(&str, &str)]) -> StoredEnv {
    let owned: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    Box::new(move |name: &str| {
        owned
            .get(name)
            .cloned()
            .ok_or(std::env::VarError::NotPresent)
    })
}

/// Write each `(rel, contents)` pair under `root`. Creates parent dirs
/// as needed.
fn fixture_tree<'a>(root: &Utf8Path, files: impl IntoIterator<Item = (&'a str, &'a str)>) {
    for (rel, body) in files {
        let p = root.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent.as_std_path()).unwrap();
        }
        std::fs::write(p.as_std_path(), body).unwrap();
    }
}

/// Assert that two paths resolve to the same on-disk file. Tolerates
/// canonicalization differences (e.g. macOS's `/tmp` → `/private/tmp`).
/// Use this when comparing a path the gate produced against one the
/// test constructed from the same tempdir root.
fn assert_paths_equivalent(actual: &str, expected: impl AsRef<std::path::Path>) {
    let actual_canon = std::fs::canonicalize(actual).expect("canonicalize actual");
    let expected_canon = std::fs::canonicalize(expected).expect("canonicalize expected");
    assert_eq!(
        actual_canon, expected_canon,
        "paths don't resolve to the same file",
    );
}

// =====================================================================
// Tests
// =====================================================================

/// Minimal happy path. A loadout with one var, one patch, one package,
/// and one lifecycle hook produces a wire contribution with one of each,
/// every item tagged `UserLoadout { name: "dev" }`.
#[test]
fn happy_path_one_of_each() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(tmp.path()).unwrap();
    fixture_tree(root, [("dotfiles/helix/config.toml", "theme = 'nord'\n")]);

    let src = format!(
        r#"name = "dev"
packages = ["helix"]

[vars]
EDITOR = "hx"

[[patches]]
dest = ".config/helix/config.toml"
source = "{root}/dotfiles/helix/config.toml"

[[lifecycle_hooks]]
on_activate = {{ type = "inline", value = "echo activated" }}
"#,
    );

    let loadout: Loadout = toml::from_str(&src).expect("loadout deserialize");
    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer.add(loadout).unwrap();
    let (wire, _) = composer
        .compose(UserPolicy::empty(), ComposeOptions::default())
        .unwrap();

    assert_eq!(wire.vars.len(), 1);
    assert_eq!(wire.vars[0].var.name, "EDITOR");
    assert_eq!(wire.vars[0].var.value, "hx");

    assert_eq!(wire.patches.len(), 1);
    assert_eq!(wire.requested_packages.len(), 1);
    assert_eq!(wire.requested_packages[0].name, "helix");
    assert_eq!(wire.lifecycle_hooks.len(), 1);

    // Every item carries the loadout name as its source.
    let sources = [
        &wire.vars[0].source,
        &wire.patches[0].source,
        &wire.requested_packages[0].source,
        &wire.lifecycle_hooks[0].source,
    ];
    assert!(
        sources
            .iter()
            .all(|s| matches!(s, WireSource::UserLoadout { name } if name == "dev")),
        "expected every item to carry UserLoadout `dev`; got: {sources:?}",
    );
}

/// Two loadouts added in order via `add_all` both reach the wire output;
/// every item retains its originating loadout's name in its `source`.
#[test]
fn multiple_loadouts_preserve_per_item_provenance() {
    let l1: Loadout = toml::from_str(
        r#"name = "first"
[vars]
EDITOR = "hx"
"#,
    )
    .unwrap();
    let l2: Loadout = toml::from_str(
        r#"name = "second"
[vars]
LANG = "sjn_IV"
"#,
    )
    .unwrap();

    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer.add_all([l1, l2]).unwrap();
    let (wire, _) = composer
        .compose(UserPolicy::empty(), ComposeOptions::default())
        .unwrap();

    assert_eq!(wire.vars.len(), 2);

    let editor = wire
        .vars
        .iter()
        .find(|sv| sv.var.name == "EDITOR")
        .expect("EDITOR missing from wire output");
    assert!(
        matches!(&editor.source, WireSource::UserLoadout { name } if name == "first"),
        "expected EDITOR source UserLoadout `first`, got: {:?}",
        editor.source,
    );

    let lang = wire
        .vars
        .iter()
        .find(|sv| sv.var.name == "LANG")
        .expect("LANG missing from wire output");
    assert!(
        matches!(&lang.source, WireSource::UserLoadout { name } if name == "second"),
        "expected LANG source UserLoadout `second`, got: {:?}",
        lang.source,
    );
}

/// `Inherit` resolves against the composer's env. `InheritWithDefault`
/// also resolves against env when the variable is present.
#[test]
fn inherit_uses_env_value() {
    let loadout: Loadout = toml::from_str(
        r#"name = "dev"
[vars]
LANG = { inherit = true }
TERM = { inherit = true, default = "xterm-256color" }
"#,
    )
    .unwrap();

    let env = pinned_env(&[("LANG", "sjn_IV"), ("TERM", "wezterm")]);
    let mut composer = UserComposer::new().with_env(env);
    composer.add(loadout).unwrap();
    let (wire, _) = composer
        .compose(UserPolicy::empty(), ComposeOptions::default())
        .unwrap();

    assert_eq!(wire.vars.len(), 2);
    let by_name: HashMap<&str, &str> = wire
        .vars
        .iter()
        .map(|sv| (sv.var.name.as_str(), sv.var.value.as_str()))
        .collect();
    assert_eq!(by_name.get("LANG"), Some(&"sjn_IV"));
    assert_eq!(by_name.get("TERM"), Some(&"wezterm"));
}

/// `InheritWithDefault` falls back to its `default` when the variable
/// is missing from env.
#[test]
fn inherit_with_default_falls_back_when_env_missing() {
    let loadout: Loadout = toml::from_str(
        r#"name = "dev"
[vars]
LANG = { inherit = true, default = "sjn_IV" }
"#,
    )
    .unwrap();

    let env = pinned_env(&[]); // LANG deliberately absent
    let mut composer = UserComposer::new().with_env(env);
    composer.add(loadout).unwrap();
    let (wire, _) = composer
        .compose(UserPolicy::empty(), ComposeOptions::default())
        .unwrap();
    assert_eq!(wire.vars.len(), 1);
    assert_eq!(wire.vars[0].var.value, "sjn_IV");
}

/// A `~/`-prefixed patch source expands against the env's `HOME` value
/// when the loadout doesn't declare one. The wire form carries the
/// absolute host path.
#[test]
fn tilde_patch_source_expands_against_env_home() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(tmp.path()).unwrap();
    fixture_tree(root, [("dotfiles/helix/config.toml", "theme = 'nord'\n")]);

    let loadout: Loadout = toml::from_str(
        r#"name = "dev"

[[patches]]
dest = ".config/helix/config.toml"
source = "~/dotfiles/helix/config.toml"
"#,
    )
    .unwrap();

    let env = pinned_env(&[("HOME", root.as_str())]);
    let mut composer = UserComposer::new().with_env(env);
    composer.add(loadout).unwrap();
    let (wire, _) = composer
        .compose(UserPolicy::empty(), ComposeOptions::default())
        .unwrap();
    assert_eq!(wire.patches.len(), 1);
    let host_path = wire.patches[0].patch.host_path.as_str();

    // The gate produces the path with the tilde expanded against HOME.
    // Verify shape directly first — otherwise a canonicalize-driven
    // prefix swap (e.g. macOS /tmp → /private/tmp) would mask a bug
    // in expansion itself. Anchor both ends to catch a missing prefix
    // OR a missing suffix.
    assert!(
        host_path.starts_with(root.as_str()) && host_path.ends_with("dotfiles/helix/config.toml"),
        "expected <{root}>/dotfiles/helix/config.toml, got: {host_path}",
    );
    assert_paths_equivalent(
        host_path,
        root.join("dotfiles/helix/config.toml").as_std_path(),
    );
}

/// A patch with a glob source fans out into one wire patch per matched
/// file. Destinations are computed from the path relative to the walk
/// root.
#[test]
fn multi_file_patch_fans_out() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(tmp.path()).unwrap();
    fixture_tree(
        root,
        [
            ("dotfiles/helix/themes/nord.toml", "# nord\n"),
            ("dotfiles/helix/themes/nord-light.toml", "# nord-light\n"),
            ("dotfiles/helix/themes/notes.md", "noise"),
        ],
    );

    let src = format!(
        r#"name = "dev"

[[patches]]
dest = ".config/helix/themes"
source = "{root}/dotfiles/helix/themes/**/*.toml"
"#,
    );
    let loadout: Loadout = toml::from_str(&src).unwrap();
    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer.add(loadout).unwrap();
    let (mut wire, _) = composer
        .compose(UserPolicy::empty(), ComposeOptions::default())
        .unwrap();

    // The filesystem walk that drives patch fan-out doesn't guarantee
    // order across platforms (readdir is unordered on Linux). Sort by
    // destination before asserting so the test is deterministic; this
    // is a test concern, not a gate guarantee.
    wire.patches.sort_by(|a, b| {
        a.patch
            .destination
            .as_str()
            .cmp(b.patch.destination.as_str())
    });
    let dests: Vec<&str> = wire
        .patches
        .iter()
        .map(|sp| sp.patch.destination.as_str())
        .collect();
    assert_eq!(
        dests,
        [
            ".config/helix/themes/nord-light.toml",
            ".config/helix/themes/nord.toml",
        ]
    );
}

/// User policy's `ignore` rule drops a matching var even though the
/// item is user-origin. Regression on the gate-precedence change.
///
/// Both vars use `inherit = true` so `ResolvedVar::carries_user_data`
/// is true — the policy gate skips vars that don't pull env data
/// (nothing to leak), and this test needs both vars to reach the
/// gate for the ignore rule to have anything to fire on.
#[test]
fn ignore_filters_user_var() {
    let loadout: Loadout = toml::from_str(
        r#"name = "dev"
[vars]
EDITOR = { inherit = true }
_TMP = { inherit = true }
"#,
    )
    .unwrap();

    let vars_policy = VarsPolicy::empty().try_with_ignore(["_*"]).unwrap();
    let policy = UserPolicy::empty().with_vars(vars_policy);
    let mut composer =
        UserComposer::new().with_env(pinned_env(&[("EDITOR", "hx"), ("_TMP", "skip")]));
    composer.add(loadout).unwrap();
    let (wire, _) = composer.compose(policy, ComposeOptions::default()).unwrap();

    let names: Vec<&str> = wire.vars.iter().map(|sv| sv.var.name.as_str()).collect();
    assert_eq!(names, ["EDITOR"]);
}

/// `PatchesPolicy::ignore` drops a matching user-origin patch file. The
/// patch-side analogue of [`ignore_filters_user_var`].
///
/// Both the source pattern and the deny pattern use `**` — the source
/// to drive a recursive walk under `themes/` (so the fixture's nested
/// `.bak` file gets considered at all), the deny to match anywhere in
/// the absolute path (globset's `*` doesn't cross `/`, so non-anchored
/// matches need `**`).
#[test]
fn ignore_filters_user_patch() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(tmp.path()).unwrap();
    fixture_tree(
        root,
        [
            ("dotfiles/helix/themes/nord.toml", "# nord\n"),
            // Stray backup in a nested directory; the deny pattern
            // must reach it via `**`.
            ("dotfiles/helix/themes/backups/nord.toml.bak", "stale\n"),
        ],
    );

    let src = format!(
        r#"name = "dev"

[[patches]]
dest = ".config/helix/themes"
source = "{root}/dotfiles/helix/themes/**/*"
"#,
    );
    let loadout: Loadout = toml::from_str(&src).unwrap();

    let patch_policy = PatchesPolicy::empty().with_ignore(["/**/*.bak"]);
    let policy = UserPolicy::empty().with_patches(patch_policy);
    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer.add(loadout).unwrap();
    let (wire, _) = composer.compose(policy, ComposeOptions::default()).unwrap();

    assert_eq!(wire.patches.len(), 1);
    let host_path = wire.patches[0].patch.host_path.as_str();
    // Shape match (starts_with + ends_with) — both sides come from
    // the same tempdir root, so canonicalization gymnastics aren't
    // needed. If we shipped a `.bak` or grabbed the wrong file, one
    // of these would fail.
    assert!(
        host_path.starts_with(root.as_str())
            && host_path.ends_with("dotfiles/helix/themes/nord.toml"),
        "expected <{root}>/dotfiles/helix/themes/nord.toml, got: {host_path}",
    );
}

/// User policy's `deny` rule rejects a matching user-origin patch
/// file. The patch-side analogue of [`deny_rejects_user_var`].
#[test]
fn deny_rejects_user_patch() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(tmp.path()).unwrap();
    fixture_tree(root, [("dotfiles/secrets/id_rsa", "PRIVATE\n")]);

    let src = format!(
        r#"name = "dev"

[[patches]]
dest = ".ssh/id_rsa"
source = "{root}/dotfiles/secrets/id_rsa"
"#,
    );
    let loadout: Loadout = toml::from_str(&src).unwrap();

    let patch_policy = PatchesPolicy::empty().with_deny(["/**/id_rsa"]);
    let policy = UserPolicy::empty().with_patches(patch_policy);

    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer.add(loadout).unwrap();
    let err = composer
        .compose(policy, ComposeOptions::default())
        .unwrap_err();
    match err {
        ComposeError::Denied { what, from } => {
            assert!(
                what.ends_with("dotfiles/secrets/id_rsa"),
                "expected denied path to end with secrets/id_rsa, got: {what}",
            );
            assert!(
                matches!(from, Source::UserLoadout { ref name } if name == "dev"),
                "expected UserLoadout source, got: {from:?}",
            );
        }
        other => panic!("expected ComposeError::Denied, got: {other:?}"),
    }
}

/// User policy's `deny` rule rejects a matching user-origin var.
/// Locks the "deny applies to user loadouts" behavior. Uses
/// `inherit = true` so `carries_user_data` is true — the policy
/// only fires on env-derived vars, which is the whole point of a
/// deny rule (block leakage of user env into the sandbox).
#[test]
fn deny_rejects_user_var() {
    let loadout: Loadout = toml::from_str(
        r#"name = "dev"
[vars]
AWS_KEY = { inherit = true }
"#,
    )
    .unwrap();

    let vars_policy = VarsPolicy::empty().try_with_deny(["AWS_*"]).unwrap();
    let policy = UserPolicy::empty().with_vars(vars_policy);

    let mut composer = UserComposer::new().with_env(pinned_env(&[("AWS_KEY", "leaked")]));
    composer.add(loadout).unwrap();
    let err = composer
        .compose(policy, ComposeOptions::default())
        .unwrap_err();
    match err {
        ComposeError::Denied { what, from } => {
            assert_eq!(what, "AWS_KEY");
            assert!(
                matches!(from, Source::UserLoadout { ref name } if name == "dev"),
                "expected UserLoadout source, got: {from:?}",
            );
        }
        other => panic!("expected ComposeError::Denied, got: {other:?}"),
    }
}

/// The full `WireContribution` — the payload the client ships to
/// the daemon inside `CreateSessionRequest` — round-trips through
/// JSON. Catches drift in any wire-form type without snapshotting
/// against a fragile byte-for-byte fixture.
#[test]
fn wire_contribution_round_trips_through_json() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(tmp.path()).unwrap();
    fixture_tree(root, [("dotfiles/helix/config.toml", "theme = 'nord'\n")]);

    let src = format!(
        r#"name = "dev"
packages = ["helix"]

[vars]
LANG = "sjn_IV"

[[patches]]
dest = ".config/helix/config.toml"
source = "{root}/dotfiles/helix/config.toml"

[[lifecycle_hooks]]
on_activate = {{ type = "inline", value = "echo activated" }}
"#,
    );
    let loadout: Loadout = toml::from_str(&src).unwrap();
    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer.add(loadout).unwrap();
    let (contribution, _) = composer
        .compose(UserPolicy::empty(), ComposeOptions::default())
        .unwrap();

    let json = serde_json_lenient::to_string(&contribution).unwrap();
    let decoded: sessions::wire::request::WireContribution =
        serde_json_lenient::from_str(&json).unwrap();

    assert_eq!(decoded.vars.len(), 1);
    assert_eq!(decoded.vars[0].var.value, "sjn_IV");
    assert_eq!(decoded.patches.len(), 1);
    assert_eq!(decoded.lifecycle_hooks.len(), 1);
    assert_eq!(decoded.requested_packages.len(), 1);
}

// =====================================================================
// `$LOADOUT_ROOT`
// =====================================================================

/// Lay out a loadouts directory holding two loadouts that ship files:
/// `dev.toml` + `dev/`, and an `ops/` tree whose files must never be
/// reached by `dev`'s patterns.
fn loadouts_dir_fixture(root: &Utf8Path) {
    fixture_tree(
        root,
        [
            ("dev/config.toml", "theme = 'nord'\n"),
            ("dev/themes/nord.toml", "# nord\n"),
            ("dev/themes/notes.md", "noise"),
            ("ops/config.toml", "theme = 'not-yours'\n"),
        ],
    );
}

/// The end the feature exists for: a loadout patches in files shipped
/// beside it, naming neither the user's config directory nor its own
/// name. Both a literal file and a glob resolve under `<dir>/dev/`,
/// and nothing reaches the neighbouring `ops/` tree.
#[test]
fn loadout_root_resolves_to_the_directory_beside_the_loadout() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(tmp.path()).unwrap();
    loadouts_dir_fixture(root);
    std::fs::write(
        root.join("dev.toml").as_std_path(),
        r#"
[[patches]]
dest = ".config/helix/config.toml"
source = "$LOADOUT_ROOT/config.toml"

[[patches]]
dest = ".config/helix/themes"
source = "${LOADOUT_ROOT}/themes/**/*.toml"
"#,
    )
    .unwrap();

    // Read from disk, so the loadout is named after its file the way an
    // activation names it — that name is what picks the directory.
    let loadout = sessions::client::disk::read_loadout_file(root.join("dev.toml").as_std_path())
        .expect("fixture loadout loads");
    let mut composer = UserComposer::new()
        .with_env(pinned_env(&[]))
        .with_loadouts_dir(paths::HostAbsPath::try_new(root.to_owned()).unwrap());
    composer.add(loadout).unwrap();
    let (wire, _) = composer
        .compose(UserPolicy::empty(), ComposeOptions::default())
        .unwrap();

    let mut resolved: Vec<(&str, &str)> = wire
        .patches
        .iter()
        .map(|p| {
            (
                p.patch.host_path.as_str(),
                p.patch.destination.as_utf8_path().as_str(),
            )
        })
        .collect();
    resolved.sort_unstable();
    assert_eq!(resolved.len(), 2, "got: {resolved:?}");
    assert_paths_equivalent(resolved[0].0, root.join("dev/config.toml").as_std_path());
    assert_paths_equivalent(
        resolved[1].0,
        root.join("dev/themes/nord.toml").as_std_path(),
    );
    assert!(
        resolved.iter().all(|(host, _)| !host.contains("/ops/")),
        "a loadout's root must not reach a sibling loadout's files: {resolved:?}",
    );
    // Destinations are what the session actually sees: the literal
    // source lands verbatim, and the glob match lands under its `dest`
    // directory at its path relative to the walk root — which is the
    // loadout's own directory, not the loadouts directory above it.
    assert_eq!(
        resolved.iter().map(|(_, dest)| *dest).collect::<Vec<_>>(),
        vec![
            ".config/helix/config.toml",
            ".config/helix/themes/nord.toml"
        ],
    );
}

/// The two on-disk layouts are anchor-equivalent: a loadout filed as
/// `<dir>/vc/loadout.toml` resolves `$LOADOUT_ROOT` to `<dir>/vc/` —
/// the very directory holding its definition — exactly as the flat
/// `<dir>/dev.toml` resolves it to the sibling `<dir>/dev/`.
///
/// This is the property that makes the directory layout a pure
/// relocation of the definition file: `Source::loadout_dir` derives
/// the anchor from the loadout's *name*, so nothing downstream of
/// discovery has to know which layout was used. A loadout migrates
/// with `mkdir dev && mv dev.toml dev/loadout.toml` and keeps patching
/// the same files.
#[test]
fn loadout_root_is_the_same_directory_under_both_layouts() {
    // The same patch declarations, filed both ways below: `dev.toml`
    // beside a `dev/` of assets, and `vc/loadout.toml` inside its own
    // `vc/`.
    const PATCHES: &str = r#"
[[patches]]
dest = ".config/helix/config.toml"
source = "$LOADOUT_ROOT/config.toml"

[[patches]]
dest = ".config/helix/themes"
source = "${LOADOUT_ROOT}/themes/**/*.toml"
"#;

    let tmp = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(tmp.path()).unwrap();
    loadouts_dir_fixture(root);

    std::fs::write(root.join("dev.toml").as_std_path(), PATCHES).unwrap();
    fixture_tree(
        root,
        [
            ("vc/config.toml", "theme = 'nord'\n"),
            ("vc/themes/nord.toml", "# nord\n"),
        ],
    );
    std::fs::write(root.join("vc/loadout.toml").as_std_path(), PATCHES).unwrap();

    // Resolve each through the shared name→loadout entry point, the
    // way an activation does, and collect the host paths each ends up
    // patching from.
    let sources_for = |name: &str| -> Vec<String> {
        let loadout_name = sessions::core::loadout::LoadoutName::try_new(name).unwrap();
        let (loadout, _layout) =
            sessions::client::disk::load_loadout(root.as_std_path(), &loadout_name)
                .expect("fixture loadout loads");
        let mut composer = UserComposer::new()
            .with_env(pinned_env(&[]))
            .with_loadouts_dir(paths::HostAbsPath::try_new(root.to_owned()).unwrap());
        composer.add(loadout).unwrap();
        let (wire, _) = composer
            .compose(UserPolicy::empty(), ComposeOptions::default())
            .unwrap();
        let mut hosts: Vec<String> = wire
            .patches
            .iter()
            .map(|p| p.patch.host_path.as_str().to_owned())
            .collect();
        hosts.sort_unstable();
        hosts
    };

    let flat = sources_for("dev");
    let directory = sources_for("vc");

    assert_eq!(flat.len(), 2, "got: {flat:?}");
    assert_eq!(directory.len(), 2, "got: {directory:?}");
    assert_paths_equivalent(&directory[0], root.join("vc/config.toml").as_std_path());
    assert_paths_equivalent(
        &directory[1],
        root.join("vc/themes/nord.toml").as_std_path(),
    );

    // The same declarations reach the same files under each layout,
    // differing only in the loadout's own name.
    let rebased: Vec<String> = directory
        .iter()
        .map(|p| p.replace("/vc/", "/dev/"))
        .collect();
    assert_eq!(
        rebased, flat,
        "the layouts must anchor identically: {directory:?} vs {flat:?}",
    );
}

/// The reference is reserved in patch sources: a loadout that also
/// exports a `LOADOUT_ROOT` variable still patches from its own
/// directory, and the variable itself reaches the session untouched.
#[test]
fn a_loadout_root_var_does_not_redirect_patch_sources() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Utf8Path::from_path(tmp.path()).unwrap();
    loadouts_dir_fixture(root);
    let src = format!(
        r#"
[vars]
LOADOUT_ROOT = "{root}/ops"

[[patches]]
dest = ".config/helix/config.toml"
source = "$LOADOUT_ROOT/config.toml"
"#,
    );
    std::fs::write(root.join("dev.toml").as_std_path(), src).unwrap();

    let loadout = sessions::client::disk::read_loadout_file(root.join("dev.toml").as_std_path())
        .expect("fixture loadout loads");
    let mut composer = UserComposer::new()
        .with_env(pinned_env(&[]))
        .with_loadouts_dir(paths::HostAbsPath::try_new(root.to_owned()).unwrap());
    composer.add(loadout).unwrap();
    let (wire, _) = composer
        .compose(UserPolicy::empty(), ComposeOptions::default())
        .unwrap();

    assert_eq!(wire.patches.len(), 1);
    assert_paths_equivalent(
        wire.patches[0].patch.host_path.as_str(),
        root.join("dev/config.toml").as_std_path(),
    );
    // Reserved in patch sources, ordinary everywhere else: the var is
    // still contributed to the session's environment.
    assert_eq!(wire.vars.len(), 1);
    assert_eq!(wire.vars[0].var.name, "LOADOUT_ROOT");
    assert_eq!(wire.vars[0].var.value, format!("{root}/ops"));
}

/// A composer that was never told where its loadouts came from can't
/// resolve the reference, and says so instead of walking some default
/// directory.
#[test]
fn loadout_root_without_a_loadouts_dir_fails_the_composition() {
    let loadout: Loadout = toml::from_str(
        r#"name = "dev"

[[patches]]
dest = ".config/helix/config.toml"
source = "$LOADOUT_ROOT/config.toml"
"#,
    )
    .unwrap();
    let mut composer = UserComposer::new().with_env(pinned_env(&[]));
    composer.add(loadout).unwrap();
    let err = composer
        .compose(UserPolicy::empty(), ComposeOptions::default())
        .expect_err("no loadouts dir means no anchor");
    assert!(
        matches!(
            err,
            ComposeError::Expansion(
                sessions::core::expansion::ExpandError::LoadoutRootUnavailable { .. }
            )
        ),
        "got: {err:?}",
    );
}
