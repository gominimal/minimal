use std::{collections::HashMap, path::Path};

use common::jq::JqError;
use either::Either;
use mfile::{EnvVarValue, TaskAction};
use nickel_lang_core::{
    eval::cache::CacheImpl,
    program::Program,
    term::{IndexMap, RichTerm, RuntimeContract, Term},
};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};

use crate::{Error, ObjTy, eval_if_closure};

/// A predicate that when matched, indicates a package should be added when using a harness.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageMatcherPredicate {
    /// A list of file paths in the project and corresponding regexes, all of which must match
    /// for this harness to be applicable.
    ///
    /// In lieu of a regex, the value may be the string `*` to signal the file need only exist.
    pub file_regexes: IndexMap<String, String>,

    /// A list of file paths in the project and corresponding predicates in jq syntax. All predicates
    /// must match for this harness to be applicable.
    pub file_predicates: IndexMap<String, String>,
}

impl PackageMatcherPredicate {
    /// Returns true if all the predicates in this matcher apply to the given source tree.
    pub fn match_dir<P: AsRef<Path>>(&self, p: P) -> Result<bool, Either<regex::Error, JqError>> {
        matches(p, &self.file_regexes, &self.file_predicates)
    }

    /// Deserializes a matcher structure from the given nickel term tree.
    pub(crate) fn from_term(
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
    ) -> Result<Self, Error> {
        let rt = eval_if_closure(rt, program)?;

        let mut file_regexes: Option<IndexMap<String, String>> = None;
        let mut file_predicates: Option<IndexMap<String, String>> = None;
        match rt.term.as_ref() {
            Term::Record(r) | Term::RecRecord(r, _, _, _) => {
                r.fields
                    .iter()
                    .try_for_each(|(ident_and_loc, field)| -> Result<(), Error> {
                        if let Some(rt) = field.value.as_ref() {
                        let rt = RuntimeContract::apply_all(
                            rt.clone(),
                            field.pending_contracts.iter().cloned(),
                            rt.pos,
                        );

                        match ident_and_loc.label() {
                            "file_regexes" => {
                                    let rt = eval_if_closure(&rt, program)?;
                                    match rt.term.as_ref() {
                                        Term::Record(r) | Term::RecRecord(r, _, _, _) => {
                                            file_regexes = Some(r.fields.iter().map(
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
                                        _ => todo!("unexpected term for file_regexes: {:?}", rt.term.as_ref()),
                                    };

                                Ok(())
                            }
                            "file_predicates" => {
                                    let rt = eval_if_closure(&rt, program)?;
                                    match rt.term.as_ref() {
                                        Term::Record(r) | Term::RecRecord(r, _, _, _) => {
                                            file_predicates = Some(r.fields.iter().map(
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
                                        _ => todo!("unexpected term for file_predicates: {:?}", rt.term.as_ref()),
                                    };

                                Ok(())
                            }
                            _ => Ok(()),
                        }
                        } else {
                            Ok(())
                        }
                    })?;
            }
            _ => {}
        };

        Ok(PackageMatcherPredicate {
            file_regexes: file_regexes.unwrap_or_default(),
            file_predicates: file_predicates.unwrap_or_default(),
        })
    }
}

/// Parses a nickel tree representing a map of `String` to `Vec<PackageMatcherPredicate>`.
fn package_map_from_term(
    rt: &RichTerm,
    program: &mut Program<CacheImpl>,
) -> Result<IndexMap<String, Vec<PackageMatcherPredicate>>, Error> {
    let rt = eval_if_closure(rt, program)?;
    match rt.term.as_ref() {
        Term::Record(r) | Term::RecRecord(r, _, _, _) => r
            .fields
            .iter()
            .map(
                |(ident_and_loc, field)| -> Result<(String, Vec<PackageMatcherPredicate>), Error> {
                    let a_rt = eval_if_closure(field.value.as_ref().unwrap(), program)?;
                    let pred = match a_rt.term.as_ref() {
                        Term::Array(a, _attrs) => a
                            .iter()
                            .map(|input| PackageMatcherPredicate::from_term(input, program))
                            .collect::<Result<Vec<_>, Error>>()?,
                        _ => todo!(
                            "handle build_package_if_any value being non-array {:?}",
                            field.value
                        ),
                    };

                    Ok((ident_and_loc.label().to_string(), pred))
                },
            )
            .collect::<Result<IndexMap<_, _>, Error>>(),
        _ => todo!(
            "unexpected term for build_package_if_any: {:?}",
            rt.term.as_ref()
        ),
    }
}

/// Returns true if all the predicates in this matcher apply to the given source tree.
fn matches<P: AsRef<Path>>(
    p: P,
    file_regexes: &IndexMap<String, String>,
    file_predicates: &IndexMap<String, String>,
) -> Result<bool, Either<regex::Error, JqError>> {
    for (path, regex_str) in file_regexes {
        let f = p.as_ref().join(path);

        if let Ok(data) = std::fs::read(&f) {
            if regex_str == "*" {
                continue; // special case: match anything
            }

            let r = Regex::new(regex_str).map_err(Either::Left)?;
            if !r.is_match(&data) {
                return Ok(false);
            }
        } else {
            return Ok(false);
        }
    }

    for (path, predicate_str) in file_predicates {
        let f = p.as_ref().join(path);
        use common::jq;
        if let Ok(data) = std::fs::read(&f) {
            let data = jq::parse_file(&f, data).map_err(Either::Right)?;

            let exp = jq::Expression::parse(predicate_str).map_err(Either::Right)?;
            if !exp.predicate_eval(data).map_err(Either::Right)? {
                return Ok(false);
            }
        } else {
            return Ok(false);
        }
    }

    Ok(true)
}

/// A set of rules that when matched, indicate that this harness is applicable to a source tree.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessMatcher {
    /// A list of file paths in the project and corresponding regexes, all of which must match
    /// for this harness to be applicable.
    ///
    /// In lieu of a regex, the value may be the string `*` to signal the file need only exist.
    pub file_regexes: IndexMap<String, String>,

    /// A list of file paths in the project and corresponding predicates in jq syntax. All predicates
    /// must match for this harness to be applicable.
    pub file_predicates: IndexMap<String, String>,

    /// Predicates for when a package should be an additional build package. The package should be added
    /// if any predicate matches.
    pub build_package_matchers: IndexMap<String, Vec<PackageMatcherPredicate>>,
    /// Predicates for when a package should be an additional runtime package. The package should be added
    /// if any predicate matches.
    pub runtime_package_matchers: IndexMap<String, Vec<PackageMatcherPredicate>>,
}

impl HarnessMatcher {
    /// Returns true if all the predicates in this matcher apply to the given source tree.
    pub fn match_dir<P: AsRef<Path>>(&self, p: P) -> Result<bool, Either<regex::Error, JqError>> {
        matches(p, &self.file_regexes, &self.file_predicates)
    }

    /// Deserializes a harness matcher structure from the given nickel term tree.
    pub(crate) fn from_term(
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
    ) -> Result<Self, Error> {
        let rt = eval_if_closure(rt, program)?;

        let PackageMatcherPredicate {
            file_regexes,
            file_predicates,
        } = PackageMatcherPredicate::from_term(&rt, program)?;

        let mut build_package_matchers: IndexMap<String, Vec<PackageMatcherPredicate>> =
            Default::default();
        let mut runtime_package_matchers: IndexMap<String, Vec<PackageMatcherPredicate>> =
            Default::default();
        match rt.term.as_ref() {
            Term::Record(r) | Term::RecRecord(r, _, _, _) => {
                r.fields
                    .iter()
                    .try_for_each(|(ident_and_loc, field)| -> Result<(), Error> {
                        if let Some(rt) = field.value.as_ref() {
                            let rt = RuntimeContract::apply_all(
                                rt.clone(),
                                field.pending_contracts.iter().cloned(),
                                rt.pos,
                            );

                            match ident_and_loc.label() {
                                "build_package_if_any" => {
                                    build_package_matchers = package_map_from_term(&rt, program)?;
                                    Ok(())
                                }
                                "runtime_package_if_any" => {
                                    runtime_package_matchers = package_map_from_term(&rt, program)?;
                                    Ok(())
                                }
                                _ => Ok(()),
                            }
                        } else {
                            Ok(())
                        }
                    })?;
            }
            _ => {}
        };

        Ok(HarnessMatcher {
            file_regexes,
            file_predicates,
            build_package_matchers,
            runtime_package_matchers,
        })
    }
}

/// A harness, a specific set of norms for building a codebase.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Harness {
    /// The human-readable name declared on the harness. Unique within a repo/layer.
    pub name: String,

    /// The names of build-specs/packages that are needed to execute a build.
    pub build_packages: Vec<String>,
    /// The names of build-specs/packages that are needed by anything built with this harness.
    pub runtime_packages: Vec<String>,
    /// The environment variables that should be applied to any execution within this harness.
    pub build_env_vars: IndexMap<String, EnvVarValue>,

    /// Static commands to build software using this harness.
    ///
    /// Only one of `build_cmds` and `build_cmds_cmd` may be set.
    pub build_cmds: Option<Vec<Vec<String>>>,
    /// The command to generate the build commands to build software using this harness.
    ///
    /// Only one of `build_cmds` and `build_cmds_cmd` may be set.
    pub build_cmds_cmd: Option<Vec<String>>,

    /// Predicates that indicate this harness is applicable to a source tree.
    ///
    /// For a harness to be applicable, one of the matchers in this list must have all its predicates met.
    pub matches_project_if_any: Option<Vec<HarnessMatcher>>,

    /// Priority of this harness for matching, defaults to zero.
    pub matches_project_priority: i32,
}

impl Harness {
    /// Deserializes a harness structure from the given nickel term tree.
    pub fn from_term(rt: &RichTerm, program: &mut Program<CacheImpl>) -> Result<Self, Error> {
        let rt = eval_if_closure(rt, program)?;

        let mut ty: Option<ObjTy> = None;
        let mut name: Option<String> = None;
        let mut build_packages: Option<Vec<String>> = None;
        let mut runtime_packages: Option<Vec<String>> = None;
        let mut build_env_vars: Option<IndexMap<String, EnvVarValue>> = None;
        let mut build_cmds: Option<Vec<Vec<String>>> = None;
        let mut build_cmds_cmd: Option<Vec<String>> = None;
        let mut matches_project_if_any: Option<Vec<HarnessMatcher>> = None;
        let mut matches_project_priority: Option<i32> = None;

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
                                                |(ident_and_loc, field)| -> Result<(String, EnvVarValue), Error> {
                                                    Ok((
                                                        ident_and_loc.label().to_string(),
                                                        EnvVarValue::Value(String::deserialize(eval_if_closure(
                                                            field.value.as_ref().unwrap(),
                                                            program,
                                                        )?).unwrap()),
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
                            "matches_project_if_any" => {
                                if let Some(matchers_rt) = field.value.as_ref() {
                                    let matchers_rt =
                                        eval_if_closure(matchers_rt, program)?;

                                    match matchers_rt.term.as_ref() {
                                        Term::Array(a, attrs) => {
                                            matches_project_if_any = Some(
                                                a.iter()
                                                    .map(|m| {
                                                        let rt = RuntimeContract::apply_all(
                                                            m.clone(),
                                                            attrs.pending_contracts.iter().cloned(),
                                                            m.pos,
                                                        );

                                                        HarnessMatcher::from_term(&eval_if_closure(
                                                            &rt,
                                                            program,
                                                        )?, program)
                                                    })
                                                    .collect::<Result<Vec<_>, Error>>()?,
                                            );
                                        }
                                        _ => todo!(
                                            "handle matches_project_if_any value being non-array {:?}",
                                            field.value
                                        ),
                                    }
                                }

                                Ok(())
                            }
                            "matches_project_priority" => {
                                if let Some(matchers_rt) = field.value.as_ref() {
                                    let matchers_rt =
                                        eval_if_closure(matchers_rt, program)?;
                                    matches_project_priority = Some(i32::deserialize(matchers_rt).unwrap());
                                }

                                Ok(())
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
        let matches_project_priority = matches_project_priority.unwrap_or(0);

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
            matches_project_if_any,
            matches_project_priority,
        })
    }

    /// Synthesizes a task representing the build using this harness.
    pub fn build_task(&self) -> mfile::Task {
        mfile::Task {
            state_key: None,
            profile: None,
            action: match (&self.build_cmds, &self.build_cmds_cmd) {
                (Some(cmds), _) => TaskAction::exec_from_str(&cmds[0].join(" ")), // TODO: this is trash
                (_, Some(bcc)) => TaskAction::CmdCmd(bcc.clone()),
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
            interactive: false,
            args: Default::default(),
            extra: HashMap::new(),
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
        let (term, mut program, _origin, _target) = Loader::new(
            indoc! {
                "
                let {harness, ..} = import \"minimal.ncl\" in
                harness {
                    name = \"rust\",

                    build_packages = [\"gcc\", \"rust\", \"binutils\"],
                    build_cmd = \"cargo build --release\",

                    matches_project_if_any = [{
                        file_regexes = {
                            \"Cargo.toml\" = \"*\",
                        },

                        file_predicates = {
                            \"Cargo.toml\" = \".workspace.dependencies.dirs == '6'\",
                        },

                        build_package_if_any.\"openssl\" = [
                          {
                            file_predicates.\"Cargo.toml\" = \".workspace.dependencies.reqwest.features | contains(\\\"native-tls\\\")\",
                          }
                        ],
                    }],
                    matches_project_priority = 1,
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
                matches_project_if_any: Some(vec![HarnessMatcher {
                    file_regexes: [("Cargo.toml".to_string(), "*".to_string())].into(),
                    file_predicates: [(
                        "Cargo.toml".to_string(),
                        ".workspace.dependencies.dirs == '6'".to_string()
                    )]
                    .into(),
                    build_package_matchers: [(
                        "openssl".to_string(),
                        vec![PackageMatcherPredicate {
                            file_predicates: [(
                                "Cargo.toml".to_string(),
                                ".workspace.dependencies.reqwest.features | contains(\"native-tls\")".to_string()
                            )]
                            .into(),
                            ..Default::default()
                        }]
                    )]
                    .into(),
                    runtime_package_matchers: Default::default(),
                }]),
                matches_project_priority: 1,
                ..Default::default()
            }
        )
    }

    #[test]
    fn harness_matcher_match_dir_file_wildcard() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"test\"\n",
        )
        .unwrap();

        let matcher = HarnessMatcher {
            file_regexes: [("Cargo.toml".to_string(), "*".to_string())].into(),
            ..Default::default()
        };
        assert!(matcher.match_dir(dir.path()).unwrap());
    }
    #[test]
    fn harness_matcher_match_dir_regex() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"test\"\n",
        )
        .unwrap();

        let matcher = HarnessMatcher {
            file_regexes: [(
                "Cargo.toml".to_string(),
                "(?m).*\\[package\\].*".to_string(),
            )]
            .into(),
            ..Default::default()
        };
        assert!(matcher.match_dir(dir.path()).unwrap());
    }

    #[test]
    fn harness_matcher_match_dir_toml_missing() {
        let dir = tempfile::tempdir().unwrap();

        let matcher = HarnessMatcher {
            file_regexes: [("Cargo.toml".to_string(), "*".to_string())].into(),
            ..Default::default()
        };
        // File doesn't exist, so the predicate is skipped and match_dir returns true.
        assert!(!matcher.match_dir(dir.path()).unwrap());
    }

    #[test]
    fn harness_matcher_match_toml_predicate() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"test\"\n",
        )
        .unwrap();

        let matcher = HarnessMatcher {
            file_predicates: [(
                "Cargo.toml".to_string(),
                ".package.name == \"test\"".to_string(),
            )]
            .into(),
            ..Default::default()
        };
        assert!(matcher.match_dir(dir.path()).unwrap());
        let matcher = HarnessMatcher {
            file_predicates: [(
                "Cargo.toml".to_string(),
                ".package.name == \"wrong thing\"".to_string(),
            )]
            .into(),
            ..Default::default()
        };
        assert!(!matcher.match_dir(dir.path()).unwrap());
    }
}
