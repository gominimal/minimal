//! Decodes a layer in the software supply chain.
//!
//! Concretely, this means walking the codebase which declares the layer to enumerate
//! packages/profiles/stacks, then evaluating the resulting Nickel to decode them
//! into in-memory structures.

use common::{SpecOrigin, Target};
use generational_arena::Arena;
use mfile::{EnvPatches, EnvVarValue, PatchSetting, Upstream};
use nickel_lang_core::eval::value::{NickelValue, RecordData};
use nickel_lang_core::identifier::LocIdent;
use nickel_lang_core::position::TermPos;
use nickel_lang_core::term::{IndexMap, RuntimeContract};
use nickel_lang_core::{
    eval::{Closure, cache::CacheImpl},
    program::Program,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

mod load;
pub use load::{LoadOptions, build_decls_in_dir};

mod error;
pub use error::Error;

pub mod attrs;
pub use attrs::AttrValue;
pub mod builds;
use builds::BuildDecl;
mod decl_tests;
pub use decl_tests::Test;
mod stacks;
pub use stacks::{PackageMatcherPredicate, Stack, StackMatcher};
mod container;
pub use container::{Container, ExposedPort, Proto};

// Increment for any big change to the format of build specs / stacks, so that hash
// keys get invalidated.
//
// Version 1: Switch from harnesses/ to stacks/.
const FORMAT_VERSION: u8 = 1;

/// The start and end bytes where a string was defined.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct StrPos {
    pub start_offset: usize,
    pub end_offset: usize,
}

impl TryFrom<TermPos> for StrPos {
    type Error = ();
    fn try_from(value: TermPos) -> Result<Self, Self::Error> {
        match value {
            TermPos::None => Err(()),
            TermPos::Original(p) | TermPos::Inherited(p) => Ok(Self {
                start_offset: p.start.to_usize(),
                end_offset: p.end.to_usize(),
            }),
        }
    }
}

/// A collection of nickel objects, defined together in a single codebase.
#[derive(Debug, Serialize, Deserialize)]
pub struct Layer {
    upstream: Option<Upstream>,
    pub origin: SpecOrigin,
    pub for_target: Target,

    pub builds: Arena<BuildDecl>,
    pub top_levels: Vec<generational_arena::Index>,

    pub stacks: HashMap<String, Stack>,
    pub containers: HashMap<String, Container>,

    read_ids: HashMap<u64, generational_arena::Index>,
}

impl Layer {
    /// Fetches a build-decl by reference.
    pub fn get(&self, idx: generational_arena::Index) -> Option<&BuildDecl> {
        self.builds.get(idx)
    }
    /// Resolves a [builds::BuildRef].
    pub fn resolve(&self, br: &builds::BuildRef) -> Option<&generational_arena::Index> {
        match br {
            builds::BuildRef::Local {
                annotated_id,
                name: _,
            } => self.read_ids.get(annotated_id),
            builds::BuildRef::Upstream { .. } => None,
        }
    }

    /// Returns an iterator over all build-spec references with the given name.
    pub fn by_name<S: AsRef<str>>(
        &self,
        name: S,
    ) -> impl Iterator<Item = generational_arena::Index> + use<'_, S> {
        self.builds.iter().filter_map(move |(br, b)| {
            if b.name == name.as_ref() {
                Some(br)
            } else {
                None
            }
        })
    }

    /// Returns the upstream layer this layer depends on, if any.
    pub fn upstream(&self) -> Option<&Upstream> {
        self.upstream.as_ref()
    }

    /// Simple builder of literal nickel for a test.
    pub fn new_for_test(s: String) -> Result<Self, Error> {
        let l = load::Loader::new(s, None, &load::LoadOptions::for_test())?;
        Self::from_loader(l, None)
    }

    /// Loads all objects in the given directory following the standard directory layout.
    pub fn new<P: AsRef<Path>>(layer_dir: P, opts: &LoadOptions) -> Result<Self, Error> {
        let (upstream, params, config_dir) = match mfile::File::from_dir(layer_dir.as_ref()) {
            Ok(mfile) => {
                if let Some(min_vers) = &mfile.stdlib.minimum_version
                    && stdlib::outdated(min_vers)
                {
                    return Err(Error::StdlibOutdated {
                        need_version: min_vers.to_string(),
                        needed_by: layer_dir.as_ref().to_str().unwrap().to_string(),
                        current_version: stdlib::VERSION.to_string(),
                    });
                }

                (
                    mfile.upstream.clone(),
                    mfile.params.clone(),
                    mfile.dir_path().map(|p| p.to_path_buf()),
                )
            }
            Err(mfile::Error::IO(_, _, e)) if e.kind() == std::io::ErrorKind::NotFound => {
                (None, None, None)
            }
            Err(mfile::Error::NotFound) => (None, None, None),
            Err(mfile::Error::IO(_, _, e)) => return Err(Error::IO(e)),
            Err(e) => return Err(Error::Other(e.to_string())),
        };

        let args = match params {
            Some(schema) => Some(
                // TODO: Make own error for bad parameters
                schema
                    .from_deserialized(&opts.params.clone().unwrap_or_default())
                    .map_err(|e| Error::Other(format!("bad parameters: {e}")))?,
            ),
            None => None,
        };
        let loader = load::Loader::new_with_all_pkgs(
            config_dir.unwrap_or_else(|| layer_dir.as_ref().to_path_buf()),
            args.as_ref(),
            opts,
        )?;
        Self::from_loader(loader, upstream)
    }

    fn from_loader(loader: load::Loader, upstream: Option<Upstream>) -> Result<Self, Error> {
        let (ncl_tree, mut program, origin, for_target) = loader.finish()?;
        let mut layer = Self {
            origin,
            upstream,
            for_target,
            top_levels: Vec::new(),
            builds: Arena::with_capacity(512),
            read_ids: HashMap::with_capacity(512),

            stacks: HashMap::with_capacity(32),
            containers: HashMap::with_capacity(32),
        };

        // The top-level of the nickel tree can either evaluate to:
        //  - A build-spec to ingest
        //  - An array of build-specs to ingest
        //  - A Layer object, containing arrays of all the objects to ingest

        let ncl_tree = eval_if_closure(&ncl_tree, &mut program)?;
        layer.top_levels = if let Some(a) = ncl_tree.as_array() {
            a.iter()
                .map(|bs| layer.ingest_buildspec(bs, &mut program))
                .collect::<Result<Vec<_>, Error>>()?
        } else {
            let ty = read_ty(&ncl_tree, &mut program)?;
            match ty {
                ObjTy::Builder => vec![layer.ingest_buildspec(&ncl_tree, &mut program)?],
                ObjTy::Layer => {
                    let record = ncl_tree
                        .as_record()
                        .expect("Layer must be a record")
                        .into_opt()
                        .expect("Layer record must not be empty");

                    if let Ok(Some(rt)) = record.get_value_with_ctrs(&LocIdent::new("stacks")) {
                        let rt = eval_if_closure(&rt, &mut program)?;
                        if let Some(a) = rt.as_array() {
                            layer.stacks = HashMap::from_iter(
                                a.iter()
                                    .map(|p| layer.ingest_stack(p, &mut program))
                                    .collect::<Result<Vec<_>, Error>>()?
                                    .into_iter()
                                    .map(|p| (p.name.clone(), p)),
                            );
                        }
                    };
                    if let Ok(Some(rt)) = record.get_value_with_ctrs(&LocIdent::new("containers")) {
                        let rt = eval_if_closure(&rt, &mut program)?;
                        if let Some(a) = rt.as_array() {
                            layer.containers = HashMap::from_iter(
                                a.iter()
                                    .map(|c| layer.ingest_container(c, &mut program))
                                    .collect::<Result<Vec<_>, Error>>()?
                                    .into_iter()
                                    .map(|c| (c.name.clone(), c)),
                            );
                        }
                    };
                    if let Ok(Some(rt)) = record.get_value_with_ctrs(&LocIdent::new("builds")) {
                        let rt = eval_if_closure(&rt, &mut program)?;
                        if let Some(a) = rt.as_array() {
                            a.iter()
                                .map(|bs| layer.ingest_buildspec(bs, &mut program))
                                .collect::<Result<Vec<_>, Error>>()?
                        } else {
                            unreachable!(); // validation for Layer should ensure its an array
                        }
                    } else {
                        vec![]
                    }
                }
                _ => {
                    return Err(Error::UnexpectedObject {
                        files: program.files(),
                        got: ty,
                        want: ObjTy::Builder,
                        pos: ncl_tree.pos(program.pos_table()),
                    });
                }
            }
        };

        Ok(layer)
    }

    fn ingest_buildspec(
        &mut self,
        rt: &NickelValue,
        program: &mut Program<CacheImpl>,
    ) -> Result<generational_arena::Index, Error> {
        let id = match builds::BuildRef::from_term(rt, program, self)? {
            builds::BuildRef::Local {
                annotated_id,
                name: _,
            } => annotated_id,
            builds::BuildRef::Upstream { name } => {
                return Err(Error::Other(format!(
                    "expected build, found upstream '{}'",
                    name
                )));
            }
        };

        // Thanks to [DeclAccumulator], all transitive builds would have been ingested
        Ok(self.read_ids[&id])
    }

    fn ingest_stack(
        &mut self,
        rt: &NickelValue,
        program: &mut Program<CacheImpl>,
    ) -> Result<Stack, Error> {
        Stack::from_term(rt, program)
    }

    fn ingest_container(
        &mut self,
        rt: &NickelValue,
        program: &mut Program<CacheImpl>,
    ) -> Result<Container, Error> {
        Container::from_term(rt, program)
    }
}

impl DeclAccumulator for Layer {
    fn maybe_decode(
        &mut self,
        spec_id: &u64,
        rt: &NickelValue,
        program: &mut Program<CacheImpl>,
    ) -> Result<(), Error> {
        if self.read_ids.contains_key(spec_id) {
            return Ok(());
        }

        // Allocate a ref
        let build_ref = self.builds.insert(BuildDecl::default());
        self.read_ids.insert(*spec_id, build_ref);

        let decl = BuildDecl::from_term(rt, program, self)?;
        *self.builds.get_mut(build_ref).unwrap() = decl;

        Ok(())
    }
}

// Types which can learn about and store build declarations through recursion.
trait DeclAccumulator {
    fn maybe_decode(
        &mut self,
        spec_id: &u64,
        rt: &NickelValue,
        program: &mut Program<CacheImpl>,
    ) -> Result<(), Error>;
}

#[cfg(test)]
impl DeclAccumulator for () {
    fn maybe_decode(
        &mut self,
        _spec_id: &u64,
        _rt: &NickelValue,
        _program: &mut Program<CacheImpl>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

/// Markers for the various objects that are being generated in Nickel.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[allow(dead_code)]
pub enum ObjTy {
    Builder,
    OutputLib,
    OutputBin,
    OutputData,
    Source,
    Local,
    Subset,
    Profile,
    Layer,
    Upstream,
    Test,
    Stack,
    Container,
}

pub(crate) fn read_ty(val: &NickelValue, program: &mut Program<CacheImpl>) -> Result<ObjTy, Error> {
    let record = val
        .as_record()
        .expect("read_ty: expected record")
        .into_opt()
        .expect("read_ty: expected non-empty record");
    if let Ok(Some(rt)) = record.get_value_with_ctrs(&LocIdent::new("ty")) {
        let rt = eval_if_closure(&rt, program)?;
        Ok(ObjTy::deserialize(rt).unwrap())
    } else {
        Err(Error::MissingTy(
            program.files(),
            val.pos(program.pos_table()),
        ))
    }
}

pub(crate) fn eval_if_closure(
    val: &NickelValue,
    program: &'_ mut Program<CacheImpl>,
) -> Result<NickelValue, Error> {
    if !val.is_whnf() {
        program
            .eval_closure(Closure::from(val.clone()))
            .map_err(|e| {
                Error::Nickel(Box::new((
                    program.files(),
                    nickel_lang_core::error::Error::EvalError(e),
                )))
            })
    } else {
        Ok(val.clone())
    }
}

pub(crate) fn record_data_from_val(
    val: &NickelValue,
) -> Option<&nickel_lang_core::term::record::RecordData> {
    val.as_record().and_then(|c| c.into_opt())
}

/// Returns true if the value is a record (including an empty one).
pub(crate) fn is_record(val: &NickelValue) -> bool {
    val.as_record().is_some()
}

#[allow(dead_code)]
pub(crate) fn patches_from_term(
    rt: &NickelValue,
    program: &mut Program<CacheImpl>,
) -> Result<EnvPatches, Error> {
    let patch_rt = eval_if_closure(rt, program)?;

    let mut dirs: Option<HashMap<String, PatchSetting>> = None;
    let mut files: Option<HashMap<String, PatchSetting>> = None;

    let r = record_data_from_val(&patch_rt)
        .unwrap_or_else(|| panic!("unexpected term for patches: {:?}", patch_rt));

    r.fields
        .iter()
        .try_for_each(|(ident_and_loc, field)| -> Result<(), Error> {
            match ident_and_loc.label() {
                "dir" | "dirs" => {
                    let dir_rt = eval_if_closure(field.value.as_ref().unwrap(), program)?;

                    let r = record_data_from_val(&dir_rt)
                        .unwrap_or_else(|| panic!("unexpected term for dir: {:?}", dir_rt));
                    if dirs.is_some() {
                        todo!("error for both 'dirs' and 'dir' set");
                    }
                    dirs = Some(
                        r.fields
                            .iter()
                            .map(
                                |(ident_and_loc, field)| -> Result<(String, PatchSetting), Error> {
                                    let val = String::deserialize(eval_if_closure(
                                        field.value.as_ref().unwrap(),
                                        program,
                                    )?)
                                    .unwrap();
                                    Ok((
                                        ident_and_loc.label().to_string(),
                                        match val.as_str() {
                                            "ReadOnly" | "read-only" | "ro" => {
                                                PatchSetting::ReadOnly
                                            }
                                            "ReadWrite" | "read-write" | "rw" => {
                                                PatchSetting::ReadWrite
                                            }
                                            _ => todo!("unexpected patch setting: {}", val),
                                        },
                                    ))
                                },
                            )
                            .collect::<Result<HashMap<_, _>, Error>>()?,
                    );
                    Ok(())
                }
                "file" | "files" => {
                    let file_rt = eval_if_closure(field.value.as_ref().unwrap(), program)?;

                    let r = record_data_from_val(&file_rt)
                        .unwrap_or_else(|| panic!("unexpected term for file: {:?}", file_rt));
                    if files.is_some() {
                        todo!("error for both 'file' and 'files' set");
                    }
                    files = Some(
                        r.fields
                            .iter()
                            .map(
                                |(ident_and_loc, field)| -> Result<(String, PatchSetting), Error> {
                                    let val = String::deserialize(eval_if_closure(
                                        field.value.as_ref().unwrap(),
                                        program,
                                    )?)
                                    .unwrap();
                                    Ok((
                                        ident_and_loc.label().to_string(),
                                        match val.as_str() {
                                            "ReadOnly" | "read-only" | "ro" => {
                                                PatchSetting::ReadOnly
                                            }
                                            "ReadWrite" | "read-write" | "rw" => {
                                                PatchSetting::ReadWrite
                                            }
                                            _ => todo!("unexpected patch setting: {}", val),
                                        },
                                    ))
                                },
                            )
                            .collect::<Result<HashMap<_, _>, Error>>()?,
                    );
                    Ok(())
                }
                _ => Ok(()),
            }
        })?;

    Ok(EnvPatches {
        file: files.unwrap_or_default(),
        dir: dirs.unwrap_or_default(),
    })
}

pub(crate) fn env_vars_from_term(
    r: &RecordData,
    program: &mut Program<CacheImpl>,
) -> Result<IndexMap<String, EnvVarValue>, Error> {
    r.fields
        .iter()
        .map(
            |(ident_and_loc, field)| -> Result<(String, EnvVarValue), Error> {
                Ok((
                    ident_and_loc.label().to_string(),
                    EnvVarValue::Value(
                        String::deserialize(eval_if_closure(
                            field.value.as_ref().unwrap(),
                            program,
                        )?)
                        .unwrap(),
                    ),
                ))
            },
        )
        .collect::<Result<IndexMap<_, _>, Error>>()
}

pub(crate) fn packages_array_from_term(
    field: &'static str,
    rt: &NickelValue,
    program: &mut Program<CacheImpl>,
) -> Result<Vec<String>, Error> {
    let packages_rt = eval_if_closure(rt, program)?;

    if let Some(a) = packages_rt.as_array() {
        // Element contracts are pending on the array; without applying them a
        // non-string entry reaches `String::deserialize` and panics.
        let pending = a.iter_pending_contracts().cloned().collect::<Vec<_>>();
        a.iter()
            .map(|input| {
                let input = RuntimeContract::apply_all(
                    input.clone(),
                    pending.iter().cloned(),
                    input.pos_idx(),
                );
                let input = eval_if_closure(&input, program)?;
                String::deserialize(input)
                    .map_err(|_| Error::Other(format!("`{field}` must be a list of package names")))
            })
            .collect::<Result<Vec<_>, Error>>()
    } else {
        todo!("handle packages value being non-array {:?}", packages_rt);
    }
}

pub(crate) fn cmds_from_cmd_term(
    rt: &NickelValue,
    program: &mut Program<CacheImpl>,
) -> Result<Vec<Vec<String>>, Error> {
    let rt = eval_if_closure(rt, program)?;
    if let Some(s) = rt.as_string() {
        Ok(vec![shlex::split(s.as_ref()).unwrap()])
    } else if let Some(a) = rt.as_array() {
        Ok(vec![
            a.iter()
                .map(|rt| eval_if_closure(rt, program))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .map(|rt| String::deserialize(rt).unwrap())
                .collect(),
        ])
    } else {
        todo!(
            "error for 'cmd' field being non-string & non-array, got {:?}",
            rt
        );
    }
}

pub(crate) fn cmds_from_cmds_term(
    rt: &NickelValue,
    program: &mut Program<CacheImpl>,
) -> Result<Vec<Vec<String>>, Error> {
    let rt = eval_if_closure(rt, program)?;
    if let Some(cmds_rt) = rt.as_array() {
        Ok(cmds_rt
            .iter()
            .map(|rt| {
                let rt = eval_if_closure(rt, program)?;
                if let Some(a) = rt.as_array() {
                    Ok::<_, Error>(
                        a.iter()
                            .map(|rt| eval_if_closure(rt, program))
                            .collect::<Result<Vec<_>, _>>()?
                            .into_iter()
                            .map(|rt| String::deserialize(rt).unwrap())
                            .collect(),
                    )
                } else if let Some(s) = rt.as_string() {
                    Ok::<_, Error>(shlex::split(s.as_ref()).unwrap())
                } else {
                    todo!(
                        "error for 'cmds' field being non-array & non-string, got {:?}",
                        rt
                    );
                }
            })
            .collect::<Result<Vec<_>, _>>()?)
    } else {
        todo!("error for 'cmds' field being non-array, got {:?}", rt);
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        builds::BuildRef,
        load::{LoadOptions, Loader},
    };

    use super::*;
    use indoc::indoc;
    use mfile::EnvVarValue;
    use nickel_lang_core::term::IndexMap;

    #[test]
    fn simple_buildspec() {
        let l = Loader::new(
            indoc! {
                "
                let {BuildSpec, Source, OutputLib, ..} = import \"minimal.ncl\" in
                {
        			name = \"single buildspec\",
        			build_deps = [
                        {url = \"http://uwu.com\", sha256 = \"abcdef\"} | Source,
                    ],
                    outputs = {
                        something = { glob = \"/usr/lib/something.*.so\" } | OutputLib,
                    },
        			cmd = \"./build.sh\",
                    build_args = {
                        fish = \"swiggity swooty\",
                    },
        		} | BuildSpec"
            }
            .to_string(),
            None,
            &LoadOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let l = Layer::from_loader(l, Default::default()).unwrap();
        // We expect a single buildspec with a known name
        assert_eq!(
            vec!["single buildspec".to_string()],
            l.builds
                .iter()
                .map(|b| b.1.name.clone())
                .collect::<Vec<String>>()
        );
        // We expect that buildspec to have one Source input
        assert!(matches!(
            l.builds.iter().next().unwrap().1.build_deps[0],
            builds::BuildDep::Source(_)
        ));

        assert_eq!(
            l.builds.iter().next().unwrap().1.cmds,
            vec![vec!["./build.sh"]]
        );
        assert_eq!(
            l.builds
                .iter()
                .next()
                .unwrap()
                .1
                .build_args
                .clone()
                .unwrap()
                .get("fish")
                .to_owned(),
            Some("swiggity swooty".to_string()).as_ref(),
        );
    }

    #[test]
    fn shared_spec_not_duplicated() {
        let l = Loader::new(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in

                let shared = {
        			name = \"sharing is caringgggg\",
        			build_deps = [],
        			cmd = \"\",
        		} | BuildSpec
        		in

                {
        			name = \"top build\",
        			build_deps = [
						{
		        			name = \"nested build\",
		        			build_deps = [shared],
		        			cmd = \"\",
		        		} | BuildSpec,
		        		shared,
        			],
        			cmd = \"\",
        		} | BuildSpec"
            }
            .to_string(),
            None,
            &LoadOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let l = Layer::from_loader(l, Default::default()).unwrap();
        // We expect three buildspecs - four buildspecs would mean that `shared` (referenced twice) was duplicated
        assert_eq!(
            vec![
                "top build".to_string(),
                "nested build".to_string(),
                "sharing is caringgggg".to_string(),
            ],
            l.builds
                .into_iter()
                .map(|b| b.name)
                .collect::<Vec<String>>()
        );
    }

    #[test]
    fn one_nested() {
        let l = Loader::new(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in
                {
        			name = \"top build\",
        			build_deps = [
						{
		        			name = \"nested build\",
		        			build_deps = [],
		        			cmd = \"\",
		        		} | BuildSpec
        			],
        			cmd = \"\",
        		} | BuildSpec"
            }
            .to_string(),
            None,
            &LoadOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let l = Layer::from_loader(l, Default::default()).unwrap();
        // We expect two buildspecs - shallow first
        assert_eq!(
            vec!["top build".to_string(), "nested build".to_string(),],
            l.builds
                .into_iter()
                .map(|b| b.name)
                .collect::<Vec<String>>()
        );
    }

    #[test]
    fn runtime_deps() {
        let l = Loader::new(
            indoc! {
                "
                let {BuildSpec, OutputData, Subset, build, subsetOf, ..} = import \"minimal.ncl\" in
                let our_runtime_dep = build {
                    name = \"runtime dep\",
                    build_deps = [],
                    cmd = \"\",
                    outputs = {
                        some_data = { glob = \"usr/*\"} | OutputData,
                    }
                } in
                {
                    name = \"top build\",
                    build_deps = [our_runtime_dep],
                    runtime_deps = [
                        our_runtime_dep,
                        subsetOf our_runtime_dep [\"some_data\"],
                    ],
                    cmd = \"\",
                } | BuildSpec"
            }
            .to_string(),
            None,
            &LoadOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });
        let l = Layer::from_loader(l, Default::default())
            .map_err(|e| {
                e.report_to_stderr();
                Err::<Layer, ()>(())
            })
            .unwrap();

        // We expect two buildspecs - shallow first
        assert_eq!(
            vec!["top build".to_string(), "runtime dep".to_string()],
            l.builds
                .iter()
                .map(|b| b.1.name.clone())
                .collect::<Vec<String>>()
        );

        // We expect the runtime_dep to be the same as the input
        assert_eq!(
            l.builds
                .iter()
                .map(|b| b.1.clone())
                .collect::<Vec<BuildDecl>>()[0]
                .build_deps[0]
                .as_build()
                .unwrap(),
            l.builds
                .iter()
                .map(|b| b.1.clone())
                .collect::<Vec<BuildDecl>>()[0]
                .runtime_deps[0]
                .bsr()
        );
        // Lets check the subset
        assert!(matches!(
            &l.get(l.by_name("top build").next().unwrap()).unwrap().runtime_deps[1].clone(),
            builds::RuntimeDep::Subset(builds::SubsetInput {
                from: BuildRef::Local {  name, .. },
                outputs,
            }) if name == "runtime dep" && outputs.to_vec() == vec!["some_data"],
        ));
    }

    #[test]
    fn circular_ref_doesnt_crash() {
        Layer::new_for_test(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in

                let rec b1 = {
                    name = \"build 1\",
                    build_deps = [b2],
                    cmd = \"\",
                } | BuildSpec,
                b2 = {
                    name = \"build 2\",
                    build_deps = [b1],
                    cmd = \"\",
                } | BuildSpec,
                in
                b1
                "
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });
    }

    #[test]
    fn load_layer() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {layer, stack, container, BuildSpec, ..} = import \"minimal.ncl\" in

                layer {
                  builds = [
                    {
                        name = \"build\",
                        build_deps = [],
                        cmd = \"\",
                    } | BuildSpec,
                  ],

                  stacks = [
                    stack {
                        name = \"uwu\",
                        runtime_packages = [\"glibc\"],
                        build_packages = [\"gcc\", \"rust\"],
                        build_env_vars = {
                            CC = \"gcc\",
                        },

                        build_cmd = [\"uwu\", \"build\"],
                    }
                  ],

                  containers = [
                    container {
                        name = \"owo\",
                        packages = [\"glibc\", \"nginx\"],

                        entrypoint = \"/usr/bin/nginx\",
                        exposed_ports = [{ port = 80 }],
                    }
                  ],
                }
                "
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        assert_eq!(
            layer
                .get(layer.by_name("build").next().unwrap())
                .unwrap()
                .name,
            "build",
        );
        assert_eq!(
            layer.stacks.get("uwu"),
            Some(&Stack {
                name: "uwu".to_string(),
                runtime_packages: vec!["glibc".to_string()],
                build_packages: vec!["gcc".to_string(), "rust".to_string()],
                build_env_vars: IndexMap::from_iter([(
                    "CC".to_string(),
                    EnvVarValue::Value("gcc".to_string())
                )]),
                build_cmds_cmd: None,
                build_cmds: Some(vec![vec!["uwu".to_string(), "build".to_string()]]),
                matches_project_if_any: None,
                matches_project_priority: 0,
            }),
        );
        assert_eq!(
            layer.containers.get("owo"),
            Some(&Container {
                name: "owo".to_string(),
                packages: vec!["glibc".to_string(), "nginx".to_string()],
                entrypoint: Some(vec!["/usr/bin/nginx".to_string()]),
                exposed_ports: vec![ExposedPort {
                    proto: Proto::Tcp,
                    port: 80
                }],
                ..Default::default()
            }),
        );
    }
}
