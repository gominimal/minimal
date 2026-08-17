use std::{collections::HashMap, path::Path};

use common::jq::JqError;
use either::Either;
use mfile::{EnvVarValue, TaskAction};
use nickel_lang_core::{
    eval::{cache::CacheImpl, value::NickelValue},
    program::Program,
    term::{IndexMap, RuntimeContract},
};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};

use crate::{
    Error, ObjTy, cmds_from_cmd_term, env_vars_from_term, eval_if_closure,
    packages_array_from_term, record_data_from_val,
};

/// A predicate that when matched, indicates a package should be added when using a stack.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageMatcherPredicate {
    /// A list of file paths in the project and corresponding regexes, all of which must match
    /// for this stack to be applicable.
    ///
    /// In lieu of a regex, the value may be the string `*` to signal the file need only exist.
    pub file_regexes: IndexMap<String, String>,

    /// A list of file paths in the project and corresponding predicates in jq syntax. All predicates
    /// must match for this stack to be applicable.
    pub file_predicates: IndexMap<String, String>,
}

impl PackageMatcherPredicate {
    /// Returns true if all the predicates in this matcher apply to the given source tree.
    pub fn match_dir<P: AsRef<Path>>(&self, p: P) -> Result<bool, Either<regex::Error, JqError>> {
        matches(p, &self.file_regexes, &self.file_predicates)
    }

    /// Deserializes a matcher structure from the given nickel term tree.
    pub(crate) fn from_term(
        rt: &NickelValue,
        program: &mut Program<CacheImpl>,
    ) -> Result<Self, Error> {
        let rt = eval_if_closure(rt, program)?;

        let mut file_regexes: Option<IndexMap<String, String>> = None;
        let mut file_predicates: Option<IndexMap<String, String>> = None;
        if let Some(r) = record_data_from_val(&rt) {
            r.fields
                .iter()
                .try_for_each(|(ident_and_loc, field)| -> Result<(), Error> {
                    if let Some(rt) = field.value.as_ref() {
                    let rt = RuntimeContract::apply_all(
                        rt.clone(),
                        field.pending_contracts.iter().cloned(),
                        rt.pos_idx(),
                    );

                    match ident_and_loc.label() {
                        "file_regexes" => {
                                let rt = eval_if_closure(&rt, program)?;
                                if let Some(r) = record_data_from_val(&rt) {
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
                                } else {
                                    todo!("unexpected term for file_regexes: {:?}", rt);
                                }

                            Ok(())
                        }
                        "file_predicates" => {
                                let rt = eval_if_closure(&rt, program)?;
                                if let Some(r) = record_data_from_val(&rt) {
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
                                } else {
                                    todo!("unexpected term for file_predicates: {:?}", rt);
                                }

                            Ok(())
                        }
                        _ => Ok(()),
                    }
                    } else {
                        Ok(())
                    }
                })?;
        }

        Ok(PackageMatcherPredicate {
            file_regexes: file_regexes.unwrap_or_default(),
            file_predicates: file_predicates.unwrap_or_default(),
        })
    }
}

/// Parses a nickel tree representing a map of `String` to `Vec<PackageMatcherPredicate>`.
fn package_map_from_term(
    rt: &NickelValue,
    program: &mut Program<CacheImpl>,
) -> Result<IndexMap<String, Vec<PackageMatcherPredicate>>, Error> {
    let rt = eval_if_closure(rt, program)?;
    if let Some(r) = record_data_from_val(&rt) {
        r.fields
            .iter()
            .map(
                |(ident_and_loc, field)| -> Result<(String, Vec<PackageMatcherPredicate>), Error> {
                    let a_rt = eval_if_closure(field.value.as_ref().unwrap(), program)?;
                    let pred = if let Some(a) = a_rt.as_array() {
                        a.iter()
                            .map(|input| PackageMatcherPredicate::from_term(input, program))
                            .collect::<Result<Vec<_>, Error>>()?
                    } else {
                        todo!(
                            "handle build_package_if_any value being non-array {:?}",
                            field.value
                        )
                    };

                    Ok((ident_and_loc.label().to_string(), pred))
                },
            )
            .collect::<Result<IndexMap<_, _>, Error>>()
    } else {
        todo!("unexpected term for build_package_if_any: {:?}", rt)
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

/// A set of rules that when matched, indicate that this stack is applicable to a source tree.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackMatcher {
    /// A list of file paths in the project and corresponding regexes, all of which must match
    /// for this stack to be applicable.
    ///
    /// In lieu of a regex, the value may be the string `*` to signal the file need only exist.
    pub file_regexes: IndexMap<String, String>,

    /// A list of file paths in the project and corresponding predicates in jq syntax. All predicates
    /// must match for this stack to be applicable.
    pub file_predicates: IndexMap<String, String>,

    /// Predicates for when a package should be an additional build package. The package should be added
    /// if any predicate matches.
    pub build_package_matchers: IndexMap<String, Vec<PackageMatcherPredicate>>,
    /// Predicates for when a package should be an additional runtime package. The package should be added
    /// if any predicate matches.
    pub runtime_package_matchers: IndexMap<String, Vec<PackageMatcherPredicate>>,
}

impl StackMatcher {
    /// Returns true if all the predicates in this matcher apply to the given source tree.
    pub fn match_dir<P: AsRef<Path>>(&self, p: P) -> Result<bool, Either<regex::Error, JqError>> {
        matches(p, &self.file_regexes, &self.file_predicates)
    }

    /// Deserializes a stack matcher structure from the given nickel term tree.
    pub(crate) fn from_term(
        rt: &NickelValue,
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
        if let Some(r) = record_data_from_val(&rt) {
            r.fields
                .iter()
                .try_for_each(|(ident_and_loc, field)| -> Result<(), Error> {
                    if let Some(rt) = field.value.as_ref() {
                        let rt = RuntimeContract::apply_all(
                            rt.clone(),
                            field.pending_contracts.iter().cloned(),
                            rt.pos_idx(),
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

        Ok(StackMatcher {
            file_regexes,
            file_predicates,
            build_package_matchers,
            runtime_package_matchers,
        })
    }
}

/// A stack, a specific set of norms for building a codebase.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Stack {
    /// The human-readable name declared on the stack. Unique within a repo/layer.
    pub name: String,

    /// The names of build-specs/packages that are needed to execute a build.
    pub build_packages: Vec<String>,
    /// The names of build-specs/packages that are needed by anything built with this stack.
    pub runtime_packages: Vec<String>,
    /// The environment variables that should be applied to any execution within this stack.
    pub build_env_vars: IndexMap<String, EnvVarValue>,

    /// Static commands to build software using this stack.
    ///
    /// Only one of `build_cmds` and `build_cmds_cmd` may be set.
    pub build_cmds: Option<Vec<Vec<String>>>,
    /// The command to generate the build commands to build software using this stack.
    ///
    /// Only one of `build_cmds` and `build_cmds_cmd` may be set.
    pub build_cmds_cmd: Option<Vec<String>>,

    /// Predicates that indicate this stack is applicable to a source tree.
    ///
    /// For a stack to be applicable, one of the matchers in this list must have all its predicates met.
    pub matches_project_if_any: Option<Vec<StackMatcher>>,

    /// Priority of this stack for matching, defaults to zero.
    pub matches_project_priority: i32,
}

impl Stack {
    /// Deserializes a stack structure from the given nickel term tree.
    pub fn from_term(rt: &NickelValue, program: &mut Program<CacheImpl>) -> Result<Self, Error> {
        let rt = eval_if_closure(rt, program)?;

        let mut ty: Option<ObjTy> = None;
        let mut name: Option<String> = None;
        let mut build_packages: Option<Vec<String>> = None;
        let mut runtime_packages: Option<Vec<String>> = None;
        let mut build_env_vars: Option<IndexMap<String, EnvVarValue>> = None;
        let mut build_cmds: Option<Vec<Vec<String>>> = None;
        let mut build_cmds_cmd: Option<Vec<String>> = None;
        let mut matches_project_if_any: Option<Vec<StackMatcher>> = None;
        let mut matches_project_priority: Option<i32> = None;

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

                        "build_env_vars" => {
                            if let Some(ev_rt) = field.value.as_ref() {
                                let ev_rt = eval_if_closure(ev_rt, program)?;

                                if let Some(r) = record_data_from_val(&ev_rt) {
                                    build_env_vars = Some(env_vars_from_term(r, program)?);
                                } else {
                                    todo!("unexpected term for build_env_vars: {:?}", ev_rt);
                                }
                            }

                            Ok(())
                        }
                        "build_packages" => {
                            if let Some(packages_rt) = field.value.as_ref() {
                                build_packages =
                                    Some(packages_array_from_term("build_packages", packages_rt, program)?);
                            }
                            Ok(())
                        }
                        "runtime_packages" => {
                            if let Some(packages_rt) = field.value.as_ref() {
                                runtime_packages = Some(packages_array_from_term(
                                    "runtime_packages",
                                    packages_rt,
                                    program,
                                )?);
                            }
                            Ok(())
                        }
                        "build_cmd" => {
                            if let Some(rt) = field.value.as_ref() {
                                build_cmds = Some(cmds_from_cmd_term(rt, program)?);
                            };
                            Ok(())
                        }
                        "build_cmds_cmd" => {
                            if let Some(rt) = field.value.as_ref() {
                                let rt = eval_if_closure(rt, program)?;
                                if let Some(s) = rt.as_string() {
                                    build_cmds_cmd = Some(
                                        shlex::split(s.as_ref()).unwrap(),
                                    );
                                } else if let Some(a) = rt.as_array() {
                                    build_cmds_cmd = Some(
                                        a.iter()
                                            .map(|rt| eval_if_closure(rt, program))
                                            .collect::<Result<Vec<_>, _>>()?
                                            .into_iter()
                                            .map(|rt| String::deserialize(rt).unwrap())
                                            .collect(),
                                    );
                                } else {
                                    todo!("error for 'build_cmds_cmd' field being non-string & non-array, got {:?}", rt);
                                }
                                Ok(())
                            } else {
                                Ok(())
                            }
                        }
                        "matches_project_if_any" => {
                            if let Some(matchers_rt) = field.value.as_ref() {
                                let matchers_rt = eval_if_closure(matchers_rt, program)?;

                                if let Some(a) = matchers_rt.as_array() {
                                    matches_project_if_any = Some(
                                        a.iter()
                                            .map(|m| {
                                                let pending = a.iter_pending_contracts()
                                                    .cloned()
                                                    .collect::<Vec<_>>();
                                                let rt = RuntimeContract::apply_all(
                                                    m.clone(),
                                                    pending,
                                                    m.pos_idx(),
                                                );

                                                StackMatcher::from_term(&eval_if_closure(
                                                    &rt,
                                                    program,
                                                )?, program)
                                            })
                                            .collect::<Result<Vec<_>, Error>>()?,
                                    );
                                } else {
                                    todo!(
                                        "handle matches_project_if_any value being non-array {:?}",
                                        field.value
                                    );
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

        match ty {
            Some(ObjTy::Stack) => {} // happy path
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
                    want: ObjTy::Stack,
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
        let build_packages = build_packages.unwrap_or_default();
        let runtime_packages = runtime_packages.unwrap_or_default();
        let build_env_vars = build_env_vars.unwrap_or_default();
        let matches_project_priority = matches_project_priority.unwrap_or(0);

        match (&build_cmds, &build_cmds_cmd) {
            (Some(_), Some(_)) => {
                return Err(Error::Other(format!(
                    "stack {}: only one of build_cmd or build_cmds_cmd may be set",
                    name
                )));
            }
            (None, None) => {
                return Err(Error::MissingField {
                    files: program.files(),
                    obj: ObjTy::Stack,
                    pos: rt.pos(program.pos_table()),
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

    /// Synthesizes a task representing the build using this stack.
    pub fn build_task(&self) -> mfile::Task {
        mfile::Task {
            state_key: None,
            profile: None,
            description: None,
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

    /// Returns the default task with the specified name this stack provides, if any.
    pub fn task_by_name(&self, name: &str) -> Option<mfile::Task> {
        match name {
            "build" => Some(self.build_task()),
            _ => None,
        }
    }

    /// Enumerates the default tasks this stack provides.
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
                let {stack, ..} = import \"minimal.ncl\" in
                stack {
                    name = \"rust\",

                    build_packages = [\"gcc\", \"rust\", \"binutils\"],
                    build_cmd = \"cargo build --release\",
                    build_env_vars.CC = \"gcc\",

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
            .to_string(),None,
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

        let p = Stack::from_term(&term, &mut program).unwrap();

        assert_eq!(
            p,
            Stack {
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
                build_env_vars: IndexMap::from_iter([(
                    "CC".to_string(),
                    EnvVarValue::Value("gcc".to_string())
                )]),
                matches_project_if_any: Some(vec![StackMatcher {
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
    fn non_string_package_entry_errors() {
        // Must be an error, not a panic: the array's element contract is
        // pending until applied.
        for field in ["build_packages", "runtime_packages"] {
            let src = format!(
                "let {{stack, ..}} = import \"minimal.ncl\" in\n\
                 stack {{ name = \"s\", build_cmd = \"x\", {field} = [1] }}"
            );
            let (term, mut program, _origin, _target) =
                Loader::new(src, None, &LoadOptions::for_test())
                    .unwrap()
                    .finish()
                    .unwrap();

            let err = Stack::from_term(&term, &mut program)
                .err()
                .unwrap_or_else(|| panic!("expected `{field} = [1]` to be rejected"));
            assert!(
                format!("{err:?}").contains("Nickel") || matches!(err, Error::Other(_)),
                "unexpected error for `{field}`: {err:?}"
            );
        }
    }

    #[test]
    fn stack_matcher_match_dir_file_wildcard() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"test\"\n",
        )
        .unwrap();

        let matcher = StackMatcher {
            file_regexes: [("Cargo.toml".to_string(), "*".to_string())].into(),
            ..Default::default()
        };
        assert!(matcher.match_dir(dir.path()).unwrap());
    }
    #[test]
    fn stack_matcher_match_dir_regex() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"test\"\n",
        )
        .unwrap();

        let matcher = StackMatcher {
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
    fn stack_matcher_match_dir_toml_missing() {
        let dir = tempfile::tempdir().unwrap();

        let matcher = StackMatcher {
            file_regexes: [("Cargo.toml".to_string(), "*".to_string())].into(),
            ..Default::default()
        };
        // File doesn't exist, so the predicate is skipped and match_dir returns true.
        assert!(!matcher.match_dir(dir.path()).unwrap());
    }

    #[test]
    fn stack_matcher_match_toml_predicate() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"test\"\n",
        )
        .unwrap();

        let matcher = StackMatcher {
            file_predicates: [(
                "Cargo.toml".to_string(),
                ".package.name == \"test\"".to_string(),
            )]
            .into(),
            ..Default::default()
        };
        assert!(matcher.match_dir(dir.path()).unwrap());
        let matcher = StackMatcher {
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
