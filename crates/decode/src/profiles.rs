use mfile::{EnvPatches, EnvVarValue};
use nickel_lang_core::{
    eval::{cache::CacheImpl, value::NickelValue},
    program::Program,
    term::IndexMap,
};
use serde::{Deserialize, Serialize};

use crate::{
    Error, ObjTy, env_vars_from_term, eval_if_closure, packages_array_from_term,
    record_data_from_val,
};

/// A profile, the initial configuration for an environment.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Profile {
    /// The human-readable name declared on the profile. Unique within a repo/layer.
    pub name: String,
    /// The profile which this profile extends.
    pub from_profile: Option<String>,

    /// The names of build-specs/packages that should be present in any environment using this profile.
    pub packages: Vec<String>,

    /// The environment variables that should be applied to any environment using this profile.
    pub env_vars: IndexMap<String, EnvVarValue>,

    /// Files/directories to be patched into the sandbox this task executes in.
    pub patch: EnvPatches,
}

impl Profile {
    /// Combines two profiles into one. On conflict, the values from other takes precedent.
    pub fn union(&mut self, other: &Profile) {
        self.from_profile = other.from_profile.clone();

        self.packages.extend_from_slice(&other.packages);
        self.packages.sort();
        self.packages.dedup();

        self.env_vars
            .extend(other.env_vars.iter().map(|(k, v)| (k.clone(), v.clone())));
        self.patch.union(&other.patch);
    }

    /// Deserializes a profile structure from the given nickel term tree.
    pub fn from_term(rt: &NickelValue, program: &mut Program<CacheImpl>) -> Result<Self, Error> {
        let rt = eval_if_closure(rt, program)?;

        let mut ty: Option<ObjTy> = None;
        let mut name: Option<String> = None;
        let mut from_profile: Option<String> = None;
        let mut packages: Option<Vec<String>> = None;
        let mut env_vars: Option<IndexMap<String, EnvVarValue>> = None;
        let mut patches: Option<EnvPatches> = None;

        if let Some(r) = record_data_from_val(&rt) {
            r.fields
                .iter()
                .try_for_each(|(ident_and_loc, field)| -> Result<(), Error> {
                    match ident_and_loc.label() {
                        "ty" => {
                            ty = Some(
                                ObjTy::deserialize(eval_if_closure(
                                    field.value.as_ref().unwrap(),
                                    program,
                                )?)
                                .unwrap(),
                            );
                            Ok(())
                        }
                        "name" => {
                            name = Some(
                                String::deserialize(eval_if_closure(
                                    field.value.as_ref().unwrap(),
                                    program,
                                )?)
                                .unwrap(),
                            );
                            Ok(())
                        }
                        "from_profile" => {
                            if let Some(rt) = field.value.as_ref() {
                                from_profile = Some(
                                    String::deserialize(eval_if_closure(rt, program)?).unwrap(),
                                );
                            }
                            Ok(())
                        }

                        "env_vars" => {
                            if let Some(ev_rt) = field.value.as_ref() {
                                let ev_rt = eval_if_closure(ev_rt, program)?;

                                if let Some(r) = record_data_from_val(&ev_rt) {
                                    env_vars = Some(env_vars_from_term(r, program)?);
                                } else {
                                    todo!("unexpected term for env_vars: {:?}", ev_rt);
                                }
                            }

                            Ok(())
                        }
                        "packages" => {
                            if let Some(packages_rt) = field.value.as_ref() {
                                packages = Some(packages_array_from_term(packages_rt, program)?);
                            }
                            Ok(())
                        }
                        "patch" | "patches" => {
                            if let Some(patch_rt) = field.value.as_ref() {
                                if patches.is_some() {
                                    todo!("error for both 'patch' and 'patches' set");
                                }
                                patches = Some(crate::patches_from_term(patch_rt, program)?);
                            }
                            Ok(())
                        }
                        _ => Ok(()),
                    }
                })?;
        }

        match ty {
            Some(ObjTy::Profile) => {} // happy path
            None => {
                return Err(Error::MissingTy(
                    program.files(),
                    rt.pos(program.pos_table()),
                ));
            }
            Some(ty) => {
                return Err(Error::UnexpectedObject {
                    files: program.files(),
                    got: ty,
                    want: ObjTy::Profile,
                    pos: rt.pos(program.pos_table()),
                });
            }
        };
        let name = match name {
            Some(name) => name,
            None => {
                return Err(Error::MissingField {
                    files: program.files(),
                    obj: ObjTy::Builder,
                    pos: rt.pos(program.pos_table()),
                    field: "name",
                });
            }
        };
        let packages = packages.unwrap_or_default();
        let env_vars = env_vars.unwrap_or_default();

        Ok(Self {
            name,
            from_profile,
            packages,
            env_vars,
            patch: patches.unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load::*;
    use indoc::indoc;
    use mfile::PatchSetting;

    #[test]
    fn parse() {
        let (term, mut program, _origin, _target) = Loader::new(
            indoc! {
                "
                let {profile, ..} = import \"minimal.ncl\" in
                profile {
                    name = \"uwu\",
                    packages = [\"gcc\", \"rust\"],
                    env_vars.something = \"some value\",

                    patch.file.\"~/uwu.json\" = \"ro\",
                }
                "
            }
            .to_string(),
            None,
            &LoadOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("load failed");
        })
        .finish()
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("finish failed");
        });

        let p = Profile::from_term(&term, &mut program).unwrap();

        assert_eq!(
            p,
            Profile {
                name: "uwu".to_string(),
                from_profile: None,
                packages: vec!["gcc".to_string(), "rust".to_string()],
                env_vars: IndexMap::from_iter([(
                    "something".to_string(),
                    EnvVarValue::Value("some value".to_string())
                )]),
                patch: EnvPatches {
                    file: [("~/uwu.json".to_string(), PatchSetting::ReadOnly)].into(),
                    ..Default::default()
                },
            }
        )
    }
}
