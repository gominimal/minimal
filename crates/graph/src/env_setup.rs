use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use crate::env_mapping::{EnvFsMapping, EnvMappingClass, EnvMappingKind};
use crate::{BuildSpecRef, Graph};
use decode::AttrValue;
use mfile::EnvPatches;

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
    /// Which package contributed each entry of `fs_mappings`, keyed by the
    /// path exactly as the package declared it (`~/`-rooted paths are not
    /// expanded here). Last writer wins, matching `fs_mappings` itself.
    ///
    /// Consumed when a mapping can't be honoured, so the error can name the
    /// package to go and look at rather than only the path it landed on.
    pub fs_mapping_packages: HashMap<String, String>,
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
        let mut fs_mapping_packages: HashMap<String, String> = Default::default();
        let (mut needs_dns, mut needs_internet) = (false, false);
        let mut env_vars: HashMap<String, String> = Default::default();
        let mut state_dirs = HashSet::default();

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
    use decode::Layer;
    use indoc::indoc;
    use mfile::PatchSetting;

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
                    dir: HashMap::from_iter([("~/.claude".to_string(), PatchSetting::ReadWrite)]),
                    file: HashMap::new(),
                },
                fs_mapping_packages: HashMap::from_iter([(
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
                env_vars: HashMap::from_iter([
                    ("GOCACHE".to_string(), "/state/gocache".to_string(),),
                    ("GOMODCACHE".to_string(), "/state/gomodcache".to_string(),)
                ]),
                needs_dns: false,
                needs_internet: false,
                state_dirs: HashSet::from_iter(["gocache".to_string(), "gomodcache".to_string()]),
                fs_mappings: Default::default(),
                fs_mapping_packages: Default::default(),
            }
        )
    }
}
