use nickel_lang_core::{
    eval::{cache::CacheImpl, value::NickelValue},
    program::Program,
};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use crate::{
    Error, ObjTy, builds::BuildRef, cmds_from_cmd_term, cmds_from_cmds_term, eval_if_closure,
    read_ty, record_data_from_val,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Test {
    /// The test needs to run in the build sandbox, rather than standalone.
    pub build_test: bool,
    /// Additional dependencies needed for the test.
    pub deps: Option<SmallVec<[BuildRef; 6]>>,

    /// The tests commands.
    pub cmds: Vec<Vec<String>>,
}

impl Test {
    pub(crate) fn from_term<A: super::DeclAccumulator>(
        rt: &NickelValue,
        program: &mut Program<CacheImpl>,
        acc: &mut A,
    ) -> Result<Self, Error> {
        let rt = eval_if_closure(rt, program)?;

        // The type hint ty identifies which input variant this term represents
        let ty = read_ty(&rt, program)?;
        match ty {
            ObjTy::Test => {
                let mut cmds: Option<Vec<Vec<String>>> = None;
                let mut deps: Option<SmallVec<[BuildRef; 6]>> = None;
                let mut is_build_test: bool = false;
                if let Some(r) = record_data_from_val(&rt) {
                    r.fields.iter().try_for_each(
                        |(ident_and_loc, field)| -> Result<(), Error> {
                            match ident_and_loc.label() {
                                "class" => {
                                    let rt =
                                        eval_if_closure(field.value.as_ref().unwrap(), program)?;
                                    if let Some(tag) = rt.as_enum_tag() {
                                        is_build_test = tag.label() == "Build";
                                    } else {
                                        return Err(Error::unexpected_type(
                                            "test `class`",
                                            "an enum tag",
                                            &rt,
                                            program,
                                        ));
                                    }
                                    Ok(())
                                }
                                "cmd" => {
                                    if let Some(rt) = field.value.as_ref() {
                                        cmds = Some(cmds_from_cmd_term("test `cmd`", rt, program)?);
                                    };
                                    Ok(())
                                }
                                "cmds" => {
                                    if let Some(rt) = field.value.as_ref() {
                                        cmds =
                                            Some(cmds_from_cmds_term("test `cmds`", rt, program)?);
                                    };
                                    Ok(())
                                }
                                "test_deps" => {
                                    let test_deps_rt =
                                        field.value.as_ref().map(|rt| eval_if_closure(rt, program));
                                    match test_deps_rt {
                                        None => {}
                                        Some(test_deps_rt) => {
                                            let test_deps_val = test_deps_rt?;
                                            if let Some(a) = test_deps_val.as_array() {
                                                deps = Some(
                                                    a.iter()
                                                        .map(|input| {
                                                            BuildRef::from_term(input, program, acc)
                                                        })
                                                        .collect::<Result<SmallVec<_>, Error>>()?,
                                                );
                                            } else {
                                                return Err(Error::unexpected_type(
                                                    "test `test_deps`",
                                                    "an array of build references",
                                                    &test_deps_val,
                                                    program,
                                                ));
                                            }
                                        }
                                    }
                                    Ok(())
                                }
                                _ => Ok(()), // TODO: Should we error if we see an unknown field?
                            }
                        },
                    )?;
                }

                let cmds = cmds.unwrap_or_default();
                Ok(Test {
                    build_test: is_build_test,
                    deps,
                    cmds,
                })
            }
            _ => Err(Error::UnexpectedObject {
                files: program.files(),
                got: ty,
                want: ObjTy::Test,
                pos: rt.pos(program.pos_table()),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load::*;
    use indoc::indoc;

    #[test]
    fn basic() {
        let (term, mut program, _origin, _target) = Loader::new(
            indoc! {
                "
                let {buildTest, ..} = import \"minimal.ncl\" in
                buildTest \"/usr/bin/yes\"
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

        let source = Test::from_term(&term, &mut program, &mut ()).unwrap();

        assert!(matches!(
            source,
            Test {
                build_test: true,
                cmds,
                deps: None,
            } if cmds == vec![vec!["/usr/bin/yes".to_string()]],
        ));
    }

    #[test]
    fn with_deps() {
        let (term, mut program, _origin, _target) = Loader::new(
            indoc! {
                "
                let {BuildSpec, Test, ..} = import \"minimal.ncl\" in
                {
                    class = 'Build,
                    cmd = \"/usr/bin/yes\",
                    test_deps = [
                        {
                 			name = \"single buildspec\",
                 			build_deps = [],
                            outputs = {},
                 			cmd = \"./build.sh\",
                  		} | BuildSpec
                    ],
                } | Test
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

        let source = Test::from_term(&term, &mut program, &mut ()).unwrap();

        assert!(matches!(
            source,
            Test {
                build_test: _,
                cmds: _,
                deps,
            } if deps.as_ref().unwrap().len() == 1,
        ));
    }
}
