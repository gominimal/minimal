use nickel_lang_core::{
    eval::{cache::CacheImpl, value::NickelValue},
    program::Program,
};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use crate::{Error, ObjTy, builds::BuildRef, eval_if_closure, read_ty, record_data_from_val};

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
                                    let rt = eval_if_closure(field.value.as_ref().unwrap(), program)?;
                                    if let Some(tag) = rt.as_enum_tag() {
                                        is_build_test = tag.label() == "Build";
                                    } else {
                                        todo!("class enum err: {:?}", rt)
                                    }
                                    Ok(())
                                }
                                "cmd" => {
                                    if let Some(rt) = field.value.as_ref() {
                                        let rt = eval_if_closure(rt, program)?;
                                        if let Some(s) = rt.as_string() {
                                            cmds = Some(vec![
                                                shlex::split(s.as_ref()).unwrap(),
                                            ]);
                                        } else if let Some(a) = rt.as_array() {
                                            cmds = Some(vec![
                                                a.iter()
                                                    .map(|rt| eval_if_closure(rt, program))
                                                    .collect::<Result<Vec<_>, _>>()?
                                                    .into_iter()
                                                    .map(|rt| String::deserialize(rt).unwrap())
                                                    .collect(),
                                            ]);
                                        } else {
                                            todo!("error for 'cmd' field being non-string & non-array, got {:?}", rt);
                                        }
                                        Ok(())
                                    } else {
                                        Ok(())
                                    }
                                }
                                "cmds" => {
                                    if let Some(rt) = field.value.as_ref() {
                                        let rt = eval_if_closure(rt,program)?;
                                        if let Some(cmds_a) = rt.as_array() {
                                            cmds = Some(
                                                cmds_a.iter()
                                                    .map(|rt| {
                                                        let rt = eval_if_closure(rt, program)?;
                                                        if let Some(a) = rt.as_array() {
                                                            Ok::<_, Error>(a.iter()
                                                                .map(|rt| eval_if_closure(rt, program))
                                                                .collect::<Result<Vec<_>, _>>()?
                                                                .into_iter()
                                                                .map(|rt| String::deserialize(rt).unwrap())
                                                                .collect())
                                                        } else if let Some(s) = rt.as_string() {
                                                            Ok::<_, Error>(shlex::split(s.as_ref()).unwrap())
                                                        } else {
                                                            todo!("error for 'cmds' field being non-array & non-string, got {:?}", rt);
                                                        }
                                                    })
                                                    .collect::<Result<Vec<_>, _>>()?,
                                            );

                                            Ok(())
                                        } else {
                                            todo!("error for 'cmds' field being non-array, got {:?}", rt);
                                        }
                                    } else {
                                        Ok(())
                                    }
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
                                                todo!(
                                                    "handle test_deps value being non-array {:?}",
                                                    field.value
                                                );
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
                let {BuildSpec, HostPath, Test, ..} = import \"minimal.ncl\" in
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
