use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use crate::{BuildSpecRef, Graph};
use decode::AttrValue;
use mfile::EnvPatches;

/// The nickel enum tag `'Credential` as rendered by `decode::AttrValue`'s
/// enum-tag conversion (a bare `AttrValue::String`, not `EnumVariant` —
/// see [`decode::AttrValue::from_term`]). Compared as a plain string at
/// runtime by [`is_credential_class`], so if that rendering ever changes
/// (angle-brackets, hash prefix, etc.) the check silently stops matching —
/// Credential mappings would then flow through unfiltered.
///
/// The regression guards are the `credential_class_*` tests in this
/// module's `tests` submodule and
/// `credential_class_fs_mappings_are_filtered_out` in
/// `minimald::sessions::composables`, which assert a `'Credential`-tagged
/// mapping is dropped on both the task and session composition paths.
pub const CREDENTIAL_CLASS_TAG: &str = "Credential";

/// True when an `env_dir_mappings` / `env_file_mappings` entry's `class`
/// field names the Credential class. The one shared parse both the task
/// path ([`SetupForPackages::build`]) and the session composition path
/// (`minimald::sessions::composables::extract_fs_mappings`) call, so the
/// two filters can't drift on how the tag is compared.
///
/// Fails open (`false`) when `class` is `None` or not a string — a
/// missing/malformed `class` is a nickel-schema violation on the package
/// side (the schema requires it), not grounds for this accessor to treat
/// the entry as if it had opted into being dropped.
pub fn is_credential_class(class: Option<&AttrValue>) -> bool {
    class.and_then(AttrValue::as_string).map(String::as_str) == Some(CREDENTIAL_CLASS_TAG)
}

/// A `class = 'Credential` mapping [`SetupForPackages::build`] declined to
/// bind into the task sandbox. Recorded rather than silently discarded so
/// the fact is visible downstream — a caller can log it, and the future
/// extractor that routes package-declared credentials through a secrets
/// lane instead of a bind mount has somewhere to start from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DroppedCredential {
    /// The declaring package's name.
    pub package: String,
    /// The mapping's `path`, as declared (not normalized).
    pub path: String,
}

/// Describes sandbox configuration that needs to be set to power present packages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupForPackages {
    /// Environment variables that need to be set, typically for an env_state_wiring entry.
    pub env_vars: HashMap<String, String>,
    /// Directories that should be created in `/state`, typically from an env_state_wiring entry.
    pub state_dirs: HashSet<String>,

    /// Whether any package sets `needs.dns`.
    pub needs_dns: bool,
    /// Whether any package sets `needs.internet`.
    pub needs_internet: bool,
    /// The filesystem mappings accumulated from `env_file_mappings` and `env_dir_mappings` attrs.
    pub fs_mappings: EnvPatches,
    /// `class = 'Credential` entries dropped from `fs_mappings` rather than
    /// bound into the task sandbox. See [`DroppedCredential`].
    pub dropped_credentials: Vec<DroppedCredential>,
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
        let (mut needs_dns, mut needs_internet) = (false, false);
        let mut env_vars: HashMap<String, String> = Default::default();
        let mut state_dirs = HashSet::default();
        let mut dropped_credentials = Vec::new();

        use mfile::PatchSetting;
        for dep in i.into_iter() {
            let b = g.get(dep).unwrap();
            if let Some(dirs) = b.attrs.get("env_dir_mappings") {
                for mapping in dirs.as_list().unwrap() {
                    let mapping = mapping.as_map().unwrap();
                    let path = mapping.get("path").unwrap().as_string().unwrap().clone();
                    if is_credential_class(mapping.get("class")) {
                        tracing::warn!(
                            package = %b.name,
                            path = %path,
                            "dropping Credential-class dir mapping from task sandbox; \
                             the secrets strategy is deferred, so credentials do not \
                             reach the task sandbox via this path",
                        );
                        dropped_credentials.push(DroppedCredential {
                            package: b.name.clone(),
                            path,
                        });
                        continue;
                    }
                    patch.dir.insert(
                        path,
                        if *mapping.get("read_only").unwrap().as_bool().unwrap() {
                            PatchSetting::ReadOnly
                        } else {
                            PatchSetting::ReadWrite
                        },
                    );
                }
            }
            if let Some(dirs) = b.attrs.get("env_file_mappings") {
                for mapping in dirs.as_list().unwrap() {
                    let mapping = mapping.as_map().unwrap();
                    let path = mapping.get("path").unwrap().as_string().unwrap().clone();
                    if is_credential_class(mapping.get("class")) {
                        tracing::warn!(
                            package = %b.name,
                            path = %path,
                            "dropping Credential-class file mapping from task sandbox; \
                             the secrets strategy is deferred, so credentials do not \
                             reach the task sandbox via this path",
                        );
                        dropped_credentials.push(DroppedCredential {
                            package: b.name.clone(),
                            path,
                        });
                        continue;
                    }
                    patch.file.insert(
                        path,
                        if *mapping.get("read_only").unwrap().as_bool().unwrap() {
                            PatchSetting::ReadOnly
                        } else {
                            PatchSetting::ReadWrite
                        },
                    );
                }
            }
            if let Some(wiring) = b.attrs.get("env_state_wiring") {
                let mut apply_wiring = |entry: &AttrValue| -> Result<(), std::io::Error> {
                    let entry = entry.as_map().unwrap();
                    let env_var = entry.get("env_var").unwrap().as_string().unwrap().clone();
                    let prefix = entry.get("prefix").unwrap().as_string().unwrap().clone();

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
            state_dirs,
            needs_dns,
            needs_internet,
            dropped_credentials,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use decode::Layer;
    use indoc::indoc;
    use mfile::PatchSetting;

    /// `class = 'Credential` entries are dropped from the fs mappings a
    /// task sandbox receives — never bound in, read-write or otherwise —
    /// and recorded in `dropped_credentials`. `class = 'State` entries on
    /// the same package survive unaffected.
    #[test]
    fn credential_class_file_mapping_is_dropped() {
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
                    dir: HashMap::from_iter([("~/.claude".to_string(), PatchSetting::ReadWrite)]),
                    file: HashMap::default(),
                },
                dropped_credentials: vec![DroppedCredential {
                    package: "b1".to_string(),
                    path: "~/.claude.json".to_string(),
                }],
            }
        )
    }

    /// The dir-mapping twin of the above: `class = 'Credential` on an
    /// `env_dir_mappings` entry is dropped the same way as on
    /// `env_file_mappings`.
    #[test]
    fn credential_class_dir_mapping_is_dropped() {
        let layer = Layer::new_for_test(
            indoc! {
                "
            let {BuildSpec, ..} = import \"minimal.ncl\" in
            {
                name = \"b1\",
                build_deps = [],
                cmd = \"\",
                attrs.env_dir_mappings = [{ read_only = false, path = \"~/.secret\", class = 'Credential }],
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
                env_vars: Default::default(),
                needs_dns: false,
                needs_internet: false,
                state_dirs: Default::default(),
                fs_mappings: Default::default(),
                dropped_credentials: vec![DroppedCredential {
                    package: "b1".to_string(),
                    path: "~/.secret".to_string(),
                }],
            }
        )
    }

    /// A mapping with no `class` field at all fails open: it is not
    /// treated as Credential and survives into `fs_mappings` untouched.
    /// The nickel schema requires `class` on every `env_file_mappings` /
    /// `env_dir_mappings` entry declared inline under `| BuildSpec`, so
    /// this constructs a valid spec first (for the `__magic_buildspec_id`
    /// the decoder requires) and merges the class-less `attrs` in
    /// afterwards, outside the contract's reach — real packages can't
    /// produce this shape, but `is_credential_class` must not panic if
    /// one somehow does.
    #[test]
    fn missing_class_fails_open() {
        let layer = Layer::new_for_test(
            indoc! {
                "
            let {BuildSpec, ..} = import \"minimal.ncl\" in
            ({
                name = \"b1\",
                build_deps = [],
                cmd = \"\",
            } | BuildSpec)
            & {
                attrs.env_file_mappings = [{ read_only = false, path = \"~/.noclass\" }],
            }
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
                    dir: HashMap::default(),
                    file: HashMap::from_iter([("~/.noclass".to_string(), PatchSetting::ReadWrite)]),
                },
                dropped_credentials: Vec::new(),
            }
        )
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
                dropped_credentials: Vec::new(),
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
                env_vars: HashMap::from_iter([
                    ("GOCACHE".to_string(), "/state/gocache".to_string(),),
                    ("GOMODCACHE".to_string(), "/state/gomodcache".to_string(),)
                ]),
                needs_dns: false,
                needs_internet: false,
                state_dirs: HashSet::from_iter(["gocache".to_string(), "gomodcache".to_string()]),
                fs_mappings: Default::default(),
                dropped_credentials: Vec::new(),
            }
        )
    }
}
