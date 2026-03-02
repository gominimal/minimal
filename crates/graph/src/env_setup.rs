use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

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

        use mfile::PatchSetting;
        for dep in i.into_iter() {
            let b = g.get(dep).unwrap();
            if let Some(dirs) = b.attrs.get("env_dir_mappings") {
                for mapping in dirs.as_list().unwrap() {
                    let mapping = mapping.as_map().unwrap();
                    patch.dir.insert(
                        mapping.get("path").unwrap().as_string().unwrap().clone(),
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
                    patch.file.insert(
                        mapping.get("path").unwrap().as_string().unwrap().clone(),
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
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use decode::Layer;
    use indoc::indoc;
    use mfile::PatchSetting;

    #[test]
    fn fs_mappings() {
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
                    file: HashMap::from_iter([(
                        "~/.claude.json".to_string(),
                        PatchSetting::ReadWrite
                    )])
                },
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
            }
        )
    }
}
