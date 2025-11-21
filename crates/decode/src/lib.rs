//! Decodes a layer of build specs into objects.

use common::SpecOrigin;
use generational_arena::Arena;
use nickel_lang_core::identifier::LocIdent;
use nickel_lang_core::term::{RichTerm, Term};
use nickel_lang_core::{
    eval::{Closure, cache::CacheImpl},
    program::Program,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

mod load;
pub use load::LoadOptions;

mod error;
pub use error::Error;

pub mod attrs;
pub use attrs::AttrValue;
pub mod builds;
use builds::BuildDecl;
mod profiles;
pub use profiles::Profile;

/// A collection of nickel objects, defined together in a single codebase.
#[derive(Debug)]
pub struct Layer {
    pub builds: Arena<BuildDecl>,
    pub origin: SpecOrigin,
    pub top_levels: Vec<generational_arena::Index>,

    pub profiles: HashMap<String, Profile>,

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

    /// Simple builder of literal nickel for a test.
    pub fn new_for_test(s: String) -> Result<Self, Error> {
        let l = load::Loader::new(s, &load::LoadOptions::for_test())?;
        Self::from_loader(l)
    }

    /// Loads all objects in the given directory following the standard directory layout.
    pub fn new<P: AsRef<Path>>(layer_dir: P, opts: &LoadOptions) -> Result<Self, Error> {
        Self::from_loader(load::Loader::new_with_all_pkgs(layer_dir, opts)?)
    }

    fn from_loader(loader: load::Loader) -> Result<Self, Error> {
        let (ncl_tree, mut program, origin) = loader.finish()?;
        let mut layer = Self {
            origin,
            top_levels: Vec::new(),
            builds: Arena::with_capacity(1024),
            read_ids: HashMap::with_capacity(1024),

            profiles: HashMap::with_capacity(32),
        };

        // The top-level of the nickel tree can either evaluate to:
        //  - A build-spec to ingest
        //  - An array of build-specs to ingest
        //  - A Layer object, containing arrays of all the objects to ingest

        let ncl_tree = eval_if_closure(&ncl_tree, &mut program)?;
        layer.top_levels = match ncl_tree.term.as_ref() {
            Term::Array(a, _attrs) => a
                .iter()
                .map(|bs| layer.ingest_buildspec(bs, &mut program))
                .collect::<Result<Vec<_>, Error>>()?,
            _ => {
                let ty = read_ty(&ncl_tree, &mut program)?;
                match ty {
                    ObjTy::Builder => vec![layer.ingest_buildspec(&ncl_tree, &mut program)?],
                    ObjTy::Layer => {
                        let record = match ncl_tree.as_ref() {
                            Term::RecRecord(record_data, _, _, _) => record_data,
                            Term::Record(record_data) => record_data,
                            _ => unreachable!(), // read_ty implicitly does the same check
                        };

                        if let Ok(Some(rt)) = record.get_value_with_ctrs(&LocIdent::new("profiles"))
                        {
                            if let Term::Array(a, _attrs) =
                                eval_if_closure(&rt, &mut program)?.term.as_ref()
                            {
                                layer.profiles = HashMap::from_iter(
                                    a.iter()
                                        .map(|p| layer.ingest_profile(p, &mut program))
                                        .collect::<Result<Vec<_>, Error>>()?
                                        .into_iter()
                                        .map(|p| (p.name.clone(), p)),
                                );
                            }
                        };
                        if let Ok(Some(rt)) = record.get_value_with_ctrs(&LocIdent::new("builds")) {
                            if let Term::Array(a, _attrs) =
                                eval_if_closure(&rt, &mut program)?.term.as_ref()
                            {
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
                            pos: ncl_tree.pos,
                        });
                    }
                }
            }
        };

        Ok(layer)
    }

    fn ingest_buildspec(
        &mut self,
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
    ) -> Result<generational_arena::Index, Error> {
        let id = match builds::BuildRef::from_term(rt, program, self)? {
            builds::BuildRef::Local {
                annotated_id,
                name: _,
            } => annotated_id,
        };

        // Thanks to [DeclAccumulator], all transitive builds would have been ingested
        Ok(self.read_ids[&id])
    }

    fn ingest_profile(
        &mut self,
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
    ) -> Result<Profile, Error> {
        Profile::from_term(rt, program)
    }
}

impl DeclAccumulator for Layer {
    fn maybe_decode(
        &mut self,
        spec_id: &u64,
        rt: &RichTerm,
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
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
    ) -> Result<(), Error>;
}

#[cfg(test)]
impl DeclAccumulator for () {
    fn maybe_decode(
        &mut self,
        _spec_id: &u64,
        _rt: &RichTerm,
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
    Path,
    OutputLib,
    OutputBin,
    OutputData,
    Source,
    Local,
    Prebuilt,
    Subset,
    Profile,
    Layer,
}

pub(crate) fn read_ty(rt: &RichTerm, program: &mut Program<CacheImpl>) -> Result<ObjTy, Error> {
    let record = match rt.as_ref() {
        Term::RecRecord(record_data, _, _, _) => record_data,
        Term::Record(record_data) => record_data,
        _ => todo!("err"),
    };
    if let Ok(Some(rt)) = record.get_value_with_ctrs(&LocIdent::new("ty")) {
        let rt = eval_if_closure(&rt, program)?;
        Ok(ObjTy::deserialize(rt).unwrap())
    } else {
        Err(Error::MissingTy(program.files(), rt.pos))
    }
}

pub(crate) fn eval_if_closure(
    rt: &RichTerm,
    program: &'_ mut Program<CacheImpl>,
) -> Result<RichTerm, Error> {
    if let Term::Closure(c) = rt.term.as_ref() {
        program.eval_closure(c.clone().into_closure()).map_err(|e| {
            Error::Nickel(Box::new((
                program.files(),
                nickel_lang_core::error::Error::EvalError(e),
            )))
        })
    } else if !rt.term.is_eff_whnf() {
        program
            .eval_closure(Closure::atomic_closure(rt.clone()))
            .map_err(|e| {
                Error::Nickel(Box::new((
                    program.files(),
                    nickel_lang_core::error::Error::EvalError(e),
                )))
            })
    } else {
        Ok(rt.clone())
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
    use nickel_lang_core::term::IndexMap;

    #[test]
    fn simple_buildspec() {
        let l = Loader::new(
            indoc! {
                "
                let {BuildSpec, HostPath, OutputLib, ..} = import \"minimal.ncl\" in
                {
        			name = \"single buildspec\",
        			inputs = [
                        {path = \"/\"} | HostPath,
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
            &LoadOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let l = Layer::from_loader(l).unwrap();
        // We expect a single buildspec with a known name
        assert_eq!(
            vec!["single buildspec".to_string()],
            l.builds
                .iter()
                .map(|b| b.1.name.clone())
                .collect::<Vec<String>>()
        );
        // We expect that buildspec to have one HostPath input
        assert!(matches!(
            l.builds.iter().next().unwrap().1.inputs[0],
            builds::BuildDeclInput::HostPath(_)
        ));

        assert_eq!(l.builds.iter().next().unwrap().1.cmd, "./build.sh",);
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
        			inputs = [],
        			cmd = \"\",
        		} | BuildSpec
        		in

                {
        			name = \"top build\",
        			inputs = [
						{
		        			name = \"nested build\",
		        			inputs = [shared],
		        			cmd = \"\",
		        		} | BuildSpec,
		        		shared,
        			],
        			cmd = \"\",
        		} | BuildSpec"
            }
            .to_string(),
            &LoadOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let l = Layer::from_loader(l).unwrap();
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
        			inputs = [
						{
		        			name = \"nested build\",
		        			inputs = [],
		        			cmd = \"\",
		        		} | BuildSpec
        			],
        			cmd = \"\",
        		} | BuildSpec"
            }
            .to_string(),
            &LoadOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let l = Layer::from_loader(l).unwrap();
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
                    inputs = [],
                    cmd = \"\",
                    outputs = {
                        some_data = { glob = \"usr/*\"} | OutputData,
                    }
                } in
                {
                    name = \"top build\",
                    inputs = [our_runtime_dep],
                    runtime_deps = [
                        our_runtime_dep,
                        subsetOf our_runtime_dep [\"some_data\"],
                    ],
                    cmd = \"\",
                } | BuildSpec"
            }
            .to_string(),
            &LoadOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });
        let l = Layer::from_loader(l)
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
                .inputs[0]
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
                    inputs = [b2],
                    cmd = \"\",
                } | BuildSpec,
                b2 = {
                    name = \"build 2\",
                    inputs = [b1],
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
                let {layer, profile, BuildSpec, ..} = import \"minimal.ncl\" in

                layer {
                  builds = [
                    {
                        name = \"build\",
                        inputs = [],
                        cmd = \"\",
                    } | BuildSpec,
                  ],

                  profiles = [
                    profile {
                        name = \"uwu\",
                        from_profile = \"rust\",
                        packages = [\"gcc\", \"rust\"],
                        env_vars = {
                            CC = \"gcc\",
                        },
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
            layer.profiles.get("uwu"),
            Some(&Profile {
                name: "uwu".to_string(),
                from_profile: Some("rust".to_string()),
                packages: vec!["gcc".to_string(), "rust".to_string()],
                env_vars: IndexMap::from_iter([("CC".to_string(), "gcc".to_string())])
            }),
        );
    }
}
