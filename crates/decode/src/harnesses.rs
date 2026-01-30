use std::collections::HashMap;

use nickel_lang_core::{
    eval::cache::CacheImpl,
    program::Program,
    term::{IndexMap, RichTerm, Term},
};
use serde::Deserialize;

use crate::{Error, ObjTy, eval_if_closure};

/// A harness, a specific set of norms for building a codebase.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[allow(dead_code)]
pub struct Harness {
    /// The human-readable name declared on the harness. Unique within a repo/layer.
    pub name: String,

    /// The names of build-specs/packages that are needed to execute a build.
    pub build_packages: Vec<String>,
    /// The names of build-specs/packages that are needed by anything built with this harness.
    pub runtime_packages: Vec<String>,
    /// The environment variables that should be applied to any execution within this harness.
    pub build_env_vars: IndexMap<String, String>,

    /// Static commands to build software using this harness.
    ///
    /// Only one of `build_cmds` and `build_cmds_cmd` may be set.
    pub build_cmds: Option<Vec<Vec<String>>>,
    /// The command to generate the build commands to build software using this harness.
    ///
    /// Only one of `build_cmds` and `build_cmds_cmd` may be set.
    pub build_cmds_cmd: Option<Vec<String>>,
}

impl Harness {
    /// Deserializes a harness structure from the given nickel term tree.
    pub(crate) fn from_term(
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
    ) -> Result<Self, Error> {
        let rt = eval_if_closure(rt, program)?;

        let mut ty: Option<ObjTy> = None;
        let mut name: Option<String> = None;
        let mut build_packages: Option<Vec<String>> = None;
        let mut runtime_packages: Option<Vec<String>> = None;
        let mut build_env_vars: Option<IndexMap<String, String>> = None;
        let mut build_cmds: Option<Vec<Vec<String>>> = None;
        let mut build_cmds_cmd: Option<Vec<String>> = None;

        match rt.term.as_ref() {
            Term::Record(r) | Term::RecRecord(r, _, _, _) => {
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

                            "build_env_vars" => {
                                if let Some(ev_rt) = field.value.as_ref() {
                                    let ev_rt =
                                        eval_if_closure(ev_rt, program)?;

                                    match ev_rt.term.as_ref() {
                                        Term::Record(r) | Term::RecRecord(r, _, _, _) => {
                                            build_env_vars = Some(r.fields.iter().map(
                                                |(ident_and_loc, field)| -> Result<(String, String), Error> {
                                                    Ok((
                                                        ident_and_loc.label().to_string(),
                                                        String::deserialize(eval_if_closure(
                                                            field.value.as_ref().unwrap(),
                                                            program,
                                                        )?).unwrap(),
                                                    ))
                                                },
                                            ).collect::<Result<IndexMap<_, _>, Error>>()?);
                                        }
                                        _ => todo!("unexpected term for build_env_vars: {:?}", ev_rt.term.as_ref()),
                                    };
                                }

                                Ok(())
                            }
                            "build_packages" => {
                                if let Some(packages_rt) = field.value.as_ref() {
                                    let packages_rt =
                                        eval_if_closure(packages_rt, program)?;

                                    match packages_rt.term.as_ref() {
                                        Term::Array(a, _attrs) => {
                                            build_packages = Some(
                                                a.iter()
                                                    .map(|input| {
                                                        Ok(String::deserialize(eval_if_closure(
                                                            input,
                                                            program,
                                                        )?).unwrap())
                                                    })
                                                    .collect::<Result<Vec<_>, Error>>()?,
                                            );
                                        }
                                        _ => todo!(
                                            "handle build_packages value being non-array {:?}",
                                            field.value
                                        ),
                                    }
                                }

                                Ok(())
                            }
                            "runtime_packages" => {
                                if let Some(packages_rt) = field.value.as_ref() {
                                    let packages_rt =
                                        eval_if_closure(packages_rt, program)?;

                                    match packages_rt.term.as_ref() {
                                        Term::Array(a, _attrs) => {
                                            runtime_packages = Some(
                                                a.iter()
                                                    .map(|input| {
                                                        Ok(String::deserialize(eval_if_closure(
                                                            input,
                                                            program,
                                                        )?).unwrap())
                                                    })
                                                    .collect::<Result<Vec<_>, Error>>()?,
                                            );
                                        }
                                        _ => todo!(
                                            "handle runtime_packages value being non-array {:?}",
                                            field.value
                                        ),
                                    }
                                }

                                Ok(())
                            }
                            "build_cmd" => {
                                if let Some(rt) = field.value.as_ref() {
                                    let rt = eval_if_closure(rt, program)?;
                                    match rt.term.as_ref() {
                                        Term::Str(s) => {
                                            build_cmds = Some(vec![
                                                shlex::split(s).unwrap(),
                                            ]);
                                        }
                                        Term::Array(a, _attrs) => {
                                            build_cmds = Some(vec![
                                                a.iter()
                                                    .map(|rt| eval_if_closure(rt, program))
                                                    .collect::<Result<Vec<_>, _>>()?
                                                    .into_iter()
                                                    .map(|rt| String::deserialize(rt).unwrap())
                                                    .collect(),
                                            ]);
                                        }
                                        _ => todo!("error for 'build_cmds' field being non-string & non-array, got {:?}", rt.term.as_ref()),
                                    };
                                    Ok(())
                                } else {
                                    Ok(())
                                }
                            }
                            "build_cmds_cmd" => {
                                if let Some(rt) = field.value.as_ref() {
                                    let rt = eval_if_closure(rt, program)?;
                                    match rt.term.as_ref() {
                                        Term::Str(s) => {
                                            build_cmds_cmd = Some(
                                                shlex::split(s).unwrap(),
                                            );
                                        }
                                        Term::Array(a, _attrs) => {
                                            build_cmds_cmd = Some(
                                                a.iter()
                                                    .map(|rt| eval_if_closure(rt, program))
                                                    .collect::<Result<Vec<_>, _>>()?
                                                    .into_iter()
                                                    .map(|rt| String::deserialize(rt).unwrap())
                                                    .collect(),
                                            );
                                        }
                                        _ => todo!("error for 'build_cmds_cmd' field being non-string & non-array, got {:?}", rt.term.as_ref()),
                                    };
                                    Ok(())
                                } else {
                                    Ok(())
                                }
                            }

                            // TODO: `build_cmds` like `cmds` in build-specs.
                            _ => Ok(()),
                        }
                    })?;
            }
            _ => {}
        };

        match ty {
            Some(ObjTy::Harness) => {} // happy path
            None => return Err(Error::MissingTy(program.files(), rt.pos)),
            Some(ty) => {
                return Err(Error::UnexpectedObject {
                    files: program.files(),
                    got: ty,
                    want: ObjTy::Harness,
                    pos: rt.pos,
                });
            }
        };
        let name = match name {
            Some(name) => name,
            None => {
                return Err(Error::MissingField {
                    files: program.files(),
                    obj: ObjTy::Builder,
                    pos: rt.pos,
                    field: "name",
                });
            }
        };
        let build_packages = build_packages.unwrap_or_default();
        let runtime_packages = runtime_packages.unwrap_or_default();
        let build_env_vars = build_env_vars.unwrap_or_default();

        match (&build_cmds, &build_cmds_cmd) {
            (Some(_), Some(_)) => {
                return Err(Error::Other(format!(
                    "harness {}: only one of build_cmd or build_cmds_cmd may be set",
                    name
                )));
            }
            (None, None) => {
                return Err(Error::MissingField {
                    files: program.files(),
                    obj: ObjTy::Harness,
                    pos: rt.pos,
                    field: "build_cmd or build_cmds_cmd",
                });
            }
            _ => {}
        }

        Ok(Self {
            name,
            build_packages,
            runtime_packages,
            build_env_vars,
            build_cmds,
            build_cmds_cmd,
        })
    }

    /// Synthesizes a task representing the build using this harness.
    pub fn build_task(&self) -> mfile::Task {
        mfile::Task {
            state_key: None,
            profile: None,
            cmd: match (&self.build_cmds, &self.build_cmds_cmd) {
                (Some(cmds), _) => cmds[0].join(" "), // TODO: this is trash
                _ => todo!(),
            },
            packages: self
                .build_packages
                .iter()
                .chain(self.runtime_packages.iter())
                .cloned()
                .collect(),
            vars: HashMap::from_iter(
                self.build_env_vars
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone())),
            ),
            patch: Default::default(),
            inherit_cwd: false,
        }
    }

    /// Returns the default task with the specified name this harness provides, if any.
    pub fn task_by_name(&self, name: &str) -> Option<mfile::Task> {
        match name {
            "build" => Some(self.build_task()),
            _ => None,
        }
    }

    /// Enumerates the default tasks this harness provides.
    pub fn task_names(&self) -> Vec<String> {
        vec!["build".to_string()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load::*;
    use indoc::indoc;

    #[test]
    fn parse() {
        let (term, mut program, _origin) = Loader::new(
            indoc! {
                "
                let {harness, ..} = import \"minimal.ncl\" in
                harness {
                    name = \"rust\",

                    build_packages = [\"gcc\", \"rust\", \"binutils\"],
                    build_cmd = \"cargo build --release\",
                }
                "
            }
            .to_string(),
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

        let p = Harness::from_term(&term, &mut program).unwrap();

        assert_eq!(
            p,
            Harness {
                name: "rust".to_string(),
                build_packages: vec![
                    "gcc".to_string(),
                    "rust".to_string(),
                    "binutils".to_string()
                ],
                build_cmds: Some(vec![vec![
                    "cargo".to_string(),
                    "build".to_string(),
                    "--release".to_string()
                ]]),
                build_env_vars: Default::default(),
                ..Default::default()
            }
        )
    }
}
