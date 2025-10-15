//! The machinery for processing build specs into a dependency graph.

#![allow(clippy::result_large_err)]
#![allow(clippy::single_match)]

use common::{
    SubsetSpec, Target,
    target::{Arch, OS},
};
use nickel_lang_core::eval::Closure;
use nickel_lang_core::files::FileId;
use nickel_lang_core::identifier::LocIdent;
use nickel_lang_core::position::{RawSpan, TermPos};
use nickel_lang_core::term::{IndexMap, RichTerm, Term};
use nickel_lang_core::{eval::cache::CacheImpl, program::Program};

use generational_arena::Arena;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use crate::{Error, SpecError, SpecHash, SpecHasher, SpecReader};
use crate::{spec_hasher::SubsetHasher, spec_schema::*};
use serde::Deserialize;

/// A map with ordered iteration semantics - we need this for stable spec hashes.
type OutputMap = IndexMap<String, BuildOutput>;

/// A reference to some other [BuildSpec] in a [DepGraph].
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct BuildSpecRef(pub(crate) generational_arena::Index);

/// A description of pulling source code regardless of form.
#[derive(Debug, Clone, PartialEq)]
pub enum SourceFetch {
    URL(String),
}

/// A description of source code thats used as an input.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceInput {
    pub from: SourceFetch,
    pub sha256: String,
    pub extract: bool,
    pub strip_prefix: Option<String>,
}

/// A dependency on some of the outputs of a build-spec.
#[derive(Debug, Clone, PartialEq)]
pub struct SubsetInput {
    pub from: BuildSpecRef,
    pub outputs: Vec<String>,
}

impl SubsetInput {
    /// Constructs a new [SubsetInput], except using the given build instead.
    pub fn override_build(&self, bsr: BuildSpecRef) -> Self {
        Self {
            from: bsr,
            ..self.clone()
        }
    }

    pub fn as_spec(&self, graph: &DepGraph) -> SubsetSpec {
        SubsetSpec::new_single(&graph.spec_hash(&self.from), self.outputs.clone())
    }
}

/// A description of where a build was declared.
#[derive(Debug, Clone, PartialEq)]
pub struct DeclPos {
    file: String,
    span: RawSpan,
}

/// An input to a build spec.
///
/// Each entry in a build-spec's `inputs` array corresponds to one [BuildSpecInput].
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum BuildSpecInput {
    Build(BuildSpecRef),
    Source(SourceInput),
    HostPath(PathBuf),
    Local((PathBuf, blake3::Hash)),
    Prebuilt(String, Option<String>), // Package name, sha256
    Subset(SubsetInput),
}

#[allow(dead_code)]
impl BuildSpecInput {
    /// Returns the underlying build-spec reference if this value was the Build variant.
    pub(crate) fn as_build(&self) -> Option<&BuildSpecRef> {
        match self {
            BuildSpecInput::Build(bsr) => Some(bsr),
            _ => None,
        }
    }
}

/// An output from a build.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum BuildOutput {
    /// This output describes shared libraries matched with the given glob.
    Library { glob: String },
    /// This output describes data files matched with the given glob.
    Data { glob: String },
    /// This output describes binaries matched with the given glob.
    Binary { glob: String },
}

impl BuildOutput {
    pub fn glob(&self) -> &String {
        match self {
            BuildOutput::Binary { glob } => glob,
            BuildOutput::Data { glob } => glob,
            BuildOutput::Library { glob } => glob,
        }
    }
}

/// A runtime dependency declared on a build-spec.
///
/// Each entry in a build-spec's `runtime_deps` array corresponds to one [RuntimeDep].
#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeDep {
    /// A direct runtime dependency on the build-spec described by the contained reference.
    Build(BuildSpecRef),
    /// A direct runtime dependency on a subset of the outputs of some other build-spec.
    Subset(SubsetInput),
}

impl RuntimeDep {
    /// Returns the build spec that the runtime dependency ultimately depends on.
    pub fn bsr(&self) -> &BuildSpecRef {
        match self {
            RuntimeDep::Build(bsr) => bsr,
            RuntimeDep::Subset(SubsetInput { from, .. }) => from,
        }
    }
}

/// Some task or build in the dependency graph.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BuildSpec {
    /// The human-readable name declared on the build spec.
    pub name: String,
    /// The system this build-spec is meant to run on. Defaults to amd64 Linux.
    pub target: Target,

    /// The build command declared on the build spec.
    pub cmd: String,
    /// Any arguments to the build command, ultimately passed as environment variables.
    pub build_args: Option<IndexMap<String, String>>,

    /// The dependencies needed to execute the build spec.
    pub inputs: Vec<BuildSpecInput>,
    /// The dependencies needed to run outputs of this build spec, as well as possibly needed
    /// during the build.
    pub runtime_deps: Vec<RuntimeDep>,
    /// The named outputs (and match patterns) produced by executing this build spec.
    pub outputs: OutputMap,

    /// An alternative build spec to use to break cycles in resolving dependencies on this build spec.
    pub replace_on_cycle: Option<BuildSpecRef>,

    /// Where in the source the build was declared.
    /// TODO: Work out why this is seldom set.
    pub pos: Option<DeclPos>,
}

impl BuildSpec {
    /// Returns true if the build-spec represents a fetch of files but no actual computation.
    pub fn is_pure_prebuilt(&self) -> bool {
        let has_prebuilt = self
            .inputs
            .iter()
            .any(|input| matches!(input, BuildSpecInput::Prebuilt(_, _)));
        let has_local_or_source = self
            .inputs
            .iter()
            .any(|input| matches!(input, BuildSpecInput::Local(_) | BuildSpecInput::Source(_)));

        has_prebuilt && !has_local_or_source
    }

    /// Returns true if the build-spec represents a rollup of runtime_deps but no substance or computation of its own.
    pub fn is_pure_collection(&self) -> bool {
        self.inputs.is_empty() && self.cmd.is_empty()
    }
}

/// The dependency graph.
#[derive(Debug)]
#[allow(dead_code)]
pub struct DepGraph {
    /// All the build-specs known to this dependency graph.
    builds: Arena<BuildSpec>,
    /// The top level build-specs (i.e. non-transitive) that were read when
    /// constructing this dependency graph.
    pub top_levels: Vec<BuildSpecRef>,

    /// The cache of build specs to their [SpecHash]. There is also a
    /// reverse cache of [SpecHash]'s to the build spec they correspond to.
    #[allow(clippy::type_complexity)]
    hash_cache: Arc<
        RwLock<(
            HashMap<BuildSpecRef, SpecHash>,
            HashMap<SpecHash, BuildSpecRef>,
        )>,
    >,
}

impl DepGraph {
    /// Constructs a new dependency graph from the given parsed/annotated nickel universe.
    pub fn new(sr: SpecReader) -> Result<Self, Error> {
        let mut graph = GraphBuilder {
            builds: Arena::with_capacity(4096),
            spec_id_lookup: HashMap::with_capacity(4096),
        };

        let (ncl_tree, mut program) = sr.finish()?;
        let ncl_tree = eval_if_closure(&ncl_tree, &mut program)?;
        let top_levels = if let Term::Array(a, _attrs) = ncl_tree.term.as_ref() {
            a.iter()
                .map(|bs| graph.read_buildspec(bs, &mut program))
                .collect::<Result<Vec<_>, Error>>()?
        } else {
            vec![graph.read_buildspec(&ncl_tree, &mut program)?]
        };

        Ok(graph.finish(top_levels))
    }

    /// Fetches a build-spec by reference.
    pub fn get(&self, bsr: &BuildSpecRef) -> Option<&BuildSpec> {
        self.builds.get(bsr.0)
    }

    /// Returns an iterator over all build-spec references with the given name.
    pub fn by_name<S: AsRef<str>>(
        &self,
        name: S,
    ) -> impl Iterator<Item = BuildSpecRef> + use<'_, S> {
        self.builds.iter().filter_map(move |(bsr, b)| {
            if b.name == name.as_ref() {
                Some(BuildSpecRef(bsr))
            } else {
                None
            }
        })
    }

    /// Returns the specification hash of the given build spec.
    pub fn spec_hash(&self, bsr: &BuildSpecRef) -> SpecHash {
        {
            if let Some(hash) = self.hash_cache.read().unwrap().0.get(bsr) {
                return hash.clone();
            }
        }

        let hash = SpecHasher::hash(self, bsr);

        {
            let mut hashes = self.hash_cache.write().unwrap();
            hashes.0.insert(*bsr, hash.clone());
            hashes.1.insert(hash.clone(), *bsr);
        }
        hash
    }

    /// Returns the specification hash of a subset.
    pub fn subset_hash(&self, subset: &SubsetInput) -> SpecHash {
        SubsetHasher::hash_single(self, &subset.from, subset.outputs.clone())
    }

    /// Returns an iterator over all build-spec references.
    pub fn all(&self) -> impl Iterator<Item = BuildSpecRef> + use<'_> {
        self.builds.iter().map(|e| BuildSpecRef(e.0))
    }

    /// Returns the number of build-specs in the graph.
    pub fn len(&self) -> usize {
        self.builds.len()
    }
    /// Returns true if the graph contains no build-specs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterates over all build specs and their keys.
    pub fn iter(&self) -> impl Iterator<Item = (BuildSpecRef, &BuildSpec)> + use<'_> {
        self.builds
            .iter()
            .map(|(index, spec)| (BuildSpecRef(index), spec))
    }

    /// Returns the unique set of transitive build-spec dependencies of the given toplevel.
    ///
    /// Dependencies of a build-spec are its inputs and its runtime dependencies.
    pub fn transitive_specs_of(&self, toplevel: &BuildSpecRef) -> Vec<BuildSpecRef> {
        let mut seen: HashMap<BuildSpecRef, ()> = HashMap::with_capacity(self.builds.len());
        let mut reachable = Vec::with_capacity(self.builds.len());
        self.collect_transitive_buildspecs(toplevel, &mut seen, &mut reachable);

        reachable
    }

    fn collect_transitive_buildspecs(
        &self,
        bsr: &BuildSpecRef,
        seen: &mut HashMap<BuildSpecRef, ()>,
        reachable: &mut Vec<BuildSpecRef>,
    ) {
        let build_spec = self.get(bsr).unwrap();

        use BuildSpecInput::*;
        build_spec
            .inputs
            .iter()
            .filter_map(|input| match input {
                Build(bsr) => Some(bsr),
                Subset(si) => Some(&si.from),
                Source(_) | HostPath(_) | Local(_) | Prebuilt(_, _) => None,
            })
            .chain(build_spec.runtime_deps.iter().map(|dep| match dep {
                RuntimeDep::Build(bsr) => bsr,
                RuntimeDep::Subset(si) => &si.from,
            }))
            .for_each(|bsr| {
                if !seen.contains_key(bsr) {
                    seen.insert(*bsr, ());
                    reachable.push(*bsr);
                    self.collect_transitive_buildspecs(bsr, seen, reachable);
                }
            })
    }
}

/// A graph thats under construction.
#[allow(dead_code)]
struct GraphBuilder {
    builds: Arena<BuildSpec>,

    spec_id_lookup: HashMap<u64, BuildSpecRef>,
}

fn read_buildspec_id(rt: &RichTerm) -> Option<u64> {
    let record = match rt.as_ref() {
        Term::RecRecord(record_data, _, _, _) => record_data,
        Term::Record(record_data) => record_data,
        _ => {
            return None;
        }
    };
    if let Ok(Some(id_rt)) = record.get_value_with_ctrs(&LocIdent::new("__magic_buildspec_id")) {
        if let Term::ForeignId(id) = id_rt.as_ref() {
            Some(*id)
        } else {
            None
        }
    } else {
        None
    }
}

fn read_ty(rt: &RichTerm, program: &mut Program<CacheImpl>) -> Result<ObjTy, Error> {
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

fn eval_if_closure(rt: &RichTerm, program: &'_ mut Program<CacheImpl>) -> Result<RichTerm, Error> {
    if let Term::Closure(c) = rt.term.as_ref() {
        program.eval_closure(c.clone().into_closure()).map_err(|e| {
            Error::SpecError(SpecError::Nickel(
                program.files(),
                nickel_lang_core::error::Error::EvalError(e),
            ))
        })
    } else if !rt.term.is_eff_whnf() {
        program
            .eval_closure(Closure::atomic_closure(rt.clone()))
            .map_err(|e| {
                Error::SpecError(SpecError::Nickel(
                    program.files(),
                    nickel_lang_core::error::Error::EvalError(e),
                ))
            })
    } else {
        Ok(rt.clone())
    }
}

impl GraphBuilder {
    fn finish(self, top_levels: Vec<BuildSpecRef>) -> DepGraph {
        let Self { builds, .. } = self;
        let hash_cache = Arc::new(RwLock::new((
            HashMap::with_capacity(builds.len()),
            HashMap::with_capacity(builds.len()),
        )));
        DepGraph {
            builds,
            top_levels,
            hash_cache,
        }
    }

    /// Recursively processes and inserts a buildspec into the graph, returning
    /// a handle to it in the build graph.
    fn read_buildspec(
        &mut self,
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
    ) -> Result<BuildSpecRef, Error> {
        let mut pos = rt.pos;
        let rt = eval_if_closure(rt, program)?;
        if pos == TermPos::None && rt.pos != TermPos::None {
            pos = rt.pos;
        }
        let magic_id =
            read_buildspec_id(&rt).ok_or_else(|| Error::MissingID(program.files(), rt.pos))?;

        // If we have seen this build-spec object before, bail-out with a reference to the existing
        // object, that way we can handle circular references of build specs.
        //
        // TODO: Probably sanity check that at least this object and the one indexed by magic_id
        // have the same name
        if let Some(bsr) = self.spec_id_lookup.get(&magic_id) {
            return Ok(*bsr);
        }

        // Read out the simple attributes
        let mut name: Option<String> = None;
        let mut cmd: Option<String> = None;
        let mut ty: Option<ObjTy> = None;
        let mut target: Option<Target> = None;
        let mut build_args: Option<IndexMap<String, String>> = None;
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
                            "cmd" => {
                                cmd = Some(
                                    String::deserialize(eval_if_closure(
                                        field.value.as_ref().unwrap(),
                                        program,
                                    )?)
                                    .unwrap(),
                                );
                                Ok(())
                            }
                            "target" => {
                                if let Some(target_rt) = field.value.as_ref() {
                                    let target_str =
                                        String::deserialize(eval_if_closure(
                                            target_rt,
                                            program,
                                        )?)
                                        .unwrap();
                                    match Target::all().iter().find(|t| t.as_ref() == target_str) {
                                        None => Err(Error::InvalidTarget { files: program.files(), got: target_str, pos: rt.pos }),
                                        Some(t) => {
                                            target = Some(t.clone());
                                            Ok(())
                                        }
                                    }
                                } else {
                                    Ok(())
                                }
                            }
                            "build_args" => {
                                if let Some(build_args_rt) = field.value.as_ref() {
                                    let build_args_rt =
                                        eval_if_closure(build_args_rt, program)?;

                                    match build_args_rt.term.as_ref() {
                                        Term::Record(r) | Term::RecRecord(r, _, _, _) => {
                                            build_args = Some(r.fields.iter().map(
                                                |(ident_and_loc, field)| -> Result<(String, String), Error> {
                                                    Ok((
                                                        ident_and_loc.label().to_string(),
                                                        String::deserialize(eval_if_closure(
                                                            field.value.as_ref().unwrap(),
                                                            program,
                                                        )?)
                                                        .unwrap(),
                                                    ))
                                                },
                                            ).collect::<Result<IndexMap<_, _>, Error>>()?
                                            );
                                        }
                                        _ => todo!("unexpected term for build_args"),
                                    };
                                }

                                Ok(())
                            }
                            _ => Ok(()), // TODO: Should we error if we see an unknown field?
                        }
                    })?;
            }
            _ => {}
        }
        match ty {
            Some(ObjTy::Builder) => {} // happy path
            None => return Err(Error::MissingTy(program.files(), rt.pos)),
            Some(ty) => {
                return Err(Error::UnexpectedObject {
                    files: program.files(),
                    got: ty,
                    want: ObjTy::Builder,
                    pos: rt.pos,
                });
            }
        }
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
        let cmd = cmd.unwrap_or_default();

        // Start constructing the BuildSpec object. Insert it into the graph
        // and cache before we recurse.
        let bsr = BuildSpecRef(self.builds.insert(BuildSpec {
            name,
            cmd,
            build_args,
            target: target.unwrap_or(Target::new(Arch::Amd64, OS::Linux)),
            inputs: Vec::new(),
            runtime_deps: Vec::new(),
            outputs: OutputMap::new(),
            replace_on_cycle: None,
            pos: pos.into_opt().map(|rs| {
                DeclPos {
                    file: program
                        .files()
                        .name(rs.src_id)
                        .to_str()
                        .unwrap()
                        .to_string(),
                    span: rs,
                }
            }),
        }));
        self.spec_id_lookup.insert(magic_id, bsr);

        // Handle more complicated attributes.
        let mut inputs: Option<Vec<BuildSpecInput>> = None;
        let mut runtime_deps: Option<Vec<RuntimeDep>> = None;
        let mut outputs: Option<OutputMap> = None;
        let mut replace_on_cycle: Option<BuildSpecRef> = None;
        match rt.term.as_ref() {
            Term::Record(r) => {
                r.fields
                    .iter()
                    .try_for_each(|(ident_and_loc, field)| -> Result<(), Error> {
                        match ident_and_loc.label() {
                            "inputs" => {
                                let inputs_rt = field
                                    .value
                                    .as_ref()
                                    .map(|rt| eval_if_closure(rt, program))
                                    .ok_or_else(|| Error::MissingField {
                                        files: program.files(),
                                        obj: ObjTy::Builder,
                                        pos: rt.pos,
                                        field: "inputs",
                                    })??;
                                if let Term::Array(a, _attrs) = inputs_rt.as_ref() {
                                    inputs = Some(
                                        a.iter()
                                            .map(|input| self.read_input(input, program))
                                            .collect::<Result<Vec<_>, Error>>()?,
                                    );
                                } else {
                                    todo!("handle inputs value being non-array {:?}", field.value);
                                };
                                Ok(())
                            }
                            "runtime_deps" => {
                                let runtime_deps_rt =
                                    field.value.as_ref().map(|rt| eval_if_closure(rt, program));
                                match runtime_deps_rt {
                                    None => {}
                                    Some(runtime_deps_rt) => match runtime_deps_rt?.term.as_ref() {
                                        Term::Array(a, _attrs) => {
                                            runtime_deps = Some(
                                                a.iter()
                                                    .map(|input| {
                                                        self.read_runtime_dep(input, program)
                                                    })
                                                    .collect::<Result<Vec<_>, Error>>()?,
                                            );
                                        }
                                        _ => todo!(
                                            "handle runtime_deps value being non-array {:?}",
                                            field.value
                                        ),
                                    },
                                }
                                Ok(())
                            }
                            "outputs" => {
                                let outputs_rt = field
                                    .value
                                    .as_ref()
                                    .map(|rt| eval_if_closure(rt, program))
                                    .ok_or_else(|| Error::MissingField {
                                        files: program.files(),
                                        obj: ObjTy::Builder,
                                        pos: rt.pos,
                                        field: "outputs",
                                    })??;

                                if let Term::Record(r) = outputs_rt.as_ref() {
                                    outputs = Some(
                                        r.iter_serializable()
                                            .map(|entry| entry.unwrap())
                                            .map(|(ident, val)| {
                                                Ok((
                                                    ident.label().to_string(),
                                                    self.read_output_value(val, program)?,
                                                ))
                                            })
                                            .collect::<Result<_, Error>>()?,
                                    );
                                } else {
                                    todo!("handle value being non-dict {:?}", field.value);
                                };
                                Ok(())
                            }
                            "replace_on_cycle" => {
                                if let Some(value) = &field.value {
                                    replace_on_cycle = Some(self.read_buildspec(value, program)?);
                                }
                                Ok(())
                            }
                            _ => Ok(()),
                        }
                    })?;
            }
            _ => panic!("unexpected type: want Record, got {:?}", rt.term),
        }
        let inputs = match inputs {
            Some(inputs) => inputs,
            None => {
                return Err(Error::MissingField {
                    files: program.files(),
                    obj: ObjTy::Builder,
                    pos: rt.pos,
                    field: "inputs",
                });
            }
        };
        let outputs = match outputs {
            Some(mut outputs) => {
                // [OutputMap] has a defined iteration order. For stable hashes, sort this by key.
                outputs.sort_by(|k1, _v1, k2, _v2| String::cmp(k1, k2));
                outputs
            }
            None => {
                return Err(Error::MissingField {
                    files: program.files(),
                    obj: ObjTy::Builder,
                    pos: rt.pos,
                    field: "outputs",
                });
            }
        };
        let runtime_deps = runtime_deps.unwrap_or_default();

        let bs = self.builds.get_mut(bsr.0).unwrap();
        bs.inputs = inputs;
        bs.runtime_deps = runtime_deps;
        bs.outputs = outputs;
        bs.replace_on_cycle = replace_on_cycle;

        Ok(bsr)
    }

    fn read_subset(
        &mut self,
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
    ) -> Result<SubsetInput, Error> {
        let mut from: Option<BuildSpecRef> = None;
        let mut outputs: Option<Vec<String>> = None;
        match rt.term.as_ref() {
            Term::Record(r) | Term::RecRecord(r, _, _, _) => {
                r.fields
                    .iter()
                    .try_for_each(|(ident_and_loc, field)| -> Result<(), Error> {
                        match ident_and_loc.label() {
                            "from" => {
                                from = Some(
                                    self.read_buildspec(field.value.as_ref().unwrap(), program)?,
                                );
                                Ok(())
                            }
                            "outputs" => {
                                let outputs_rt =
                                    field.value.as_ref().map(|rt| eval_if_closure(rt, program));
                                match outputs_rt {
                                    None => {}
                                    Some(outputs_rt) => match outputs_rt?.term.as_ref() {
                                        Term::Array(a, _attrs) => {
                                            outputs = Some(
                                                a.iter()
                                                    .map(|input| {
                                                        Ok(String::deserialize(eval_if_closure(
                                                            input, program,
                                                        )?)
                                                        .unwrap())
                                                    })
                                                    .collect::<Result<Vec<_>, Error>>()?,
                                            );
                                        }
                                        _ => todo!(
                                            "handle outputs value being non-array {:?}",
                                            field.value
                                        ),
                                    },
                                }
                                Ok(())
                            }
                            _ => Ok(()), // TODO: Should we error if we see an unknown field?
                        }
                    })?;
            }
            _ => {}
        }
        let from = match from {
            Some(from) => from,
            None => {
                return Err(Error::MissingField {
                    files: program.files(),
                    obj: ObjTy::Subset,
                    pos: rt.pos,
                    field: "from",
                });
            }
        };
        let mut outputs = match outputs {
            Some(outputs) => outputs,
            None => {
                return Err(Error::MissingField {
                    files: program.files(),
                    obj: ObjTy::Subset,
                    pos: rt.pos,
                    field: "outputs",
                });
            }
        };
        outputs.sort();
        outputs.dedup();

        for output in &outputs {
            let build = self.builds.get(from.0).unwrap();
            if !build.outputs.contains_key(output) {
                return Err(Error::NoSuchOutput {
                    files: program.files(),
                    pos: rt.pos,
                    output: output.clone(),
                });
            }
        }

        Ok(SubsetInput { from, outputs })
    }

    fn read_input_source(
        &mut self,
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
    ) -> Result<SourceInput, Error> {
        let mut url: Option<String> = None;
        let mut sha256: Option<String> = None;
        let mut extract: Option<bool> = None;
        let mut strip_prefix: Option<String> = None;
        match rt.term.as_ref() {
            Term::Record(r) | Term::RecRecord(r, _, _, _) => {
                r.fields
                    .iter()
                    .try_for_each(|(ident_and_loc, field)| -> Result<(), Error> {
                        match ident_and_loc.label() {
                            "url" => {
                                url = Some(
                                    String::deserialize(eval_if_closure(
                                        field.value.as_ref().unwrap(),
                                        program,
                                    )?)
                                    .unwrap(),
                                );
                                Ok(())
                            }
                            "sha256" => {
                                sha256 = Some(
                                    String::deserialize(eval_if_closure(
                                        field.value.as_ref().unwrap(),
                                        program,
                                    )?)
                                    .unwrap(),
                                );
                                Ok(())
                            }
                            "extract" => {
                                if let Some(ext_rt) = field.value.as_ref() {
                                    extract = Some(
                                        bool::deserialize(eval_if_closure(ext_rt, program)?)
                                            .unwrap(),
                                    );
                                }
                                Ok(())
                            }
                            "strip_prefix" => {
                                if let Some(st_rt) = field.value.as_ref() {
                                    strip_prefix = Some(
                                        String::deserialize(eval_if_closure(st_rt, program)?)
                                            .unwrap(),
                                    );
                                }
                                Ok(())
                            }
                            _ => Ok(()), // TODO: Should we error if we see an unknown field?
                        }
                    })?;
            }
            _ => {}
        }
        let url = match url {
            Some(url) => url,
            None => {
                return Err(Error::MissingField {
                    files: program.files(),
                    obj: ObjTy::Source,
                    pos: rt.pos,
                    field: "url",
                });
            }
        };
        let sha256 = match sha256 {
            Some(sha256) => sha256,
            None => {
                return Err(Error::MissingField {
                    files: program.files(),
                    obj: ObjTy::Source,
                    pos: rt.pos,
                    field: "sha256",
                });
            }
        };

        Ok(SourceInput {
            from: SourceFetch::URL(url),
            sha256,
            extract: extract.unwrap_or(false),
            strip_prefix,
        })
    }

    fn read_input_hostpath(
        &mut self,
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
    ) -> Result<String, Error> {
        let mut path: Option<String> = None;
        match rt.term.as_ref() {
            Term::Record(r) | Term::RecRecord(r, _, _, _) => {
                r.fields
                    .iter()
                    .try_for_each(|(ident_and_loc, field)| -> Result<(), Error> {
                        match ident_and_loc.label() {
                            "path" => {
                                path = Some(
                                    String::deserialize(eval_if_closure(
                                        field.value.as_ref().unwrap(),
                                        program,
                                    )?)
                                    .unwrap(),
                                );
                                Ok(())
                            }
                            _ => Ok(()), // TODO: Should we error if we see an unknown field?
                        }
                    })?;
            }
            _ => {}
        }
        let path = match path {
            Some(path) => path,
            None => {
                return Err(Error::MissingField {
                    files: program.files(),
                    obj: ObjTy::Path,
                    pos: rt.pos,
                    field: "path",
                });
            }
        };

        Ok(path)
    }

    fn read_input_local(
        &mut self,
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
    ) -> Result<(PathBuf, blake3::Hash), Error> {
        let mut file: Option<(String, FileId)> = None;
        match rt.term.as_ref() {
            Term::Record(r) | Term::RecRecord(r, _, _, _) => {
                r.fields
                    .iter()
                    .try_for_each(|(ident_and_loc, field)| -> Result<(), Error> {
                        match ident_and_loc.label() {
                            "file" => {
                                file = Some((
                                    String::deserialize(eval_if_closure(
                                        field.value.as_ref().unwrap(),
                                        program,
                                    )?)
                                    .unwrap(),
                                    field.value.as_ref().unwrap().pos.src_id().unwrap(),
                                ));
                                Ok(())
                            }
                            _ => Ok(()), // TODO: Should we error if we see an unknown field?
                        }
                    })?;
            }
            _ => {}
        }
        let (file, src_id) = match file {
            Some(file) => file,
            None => {
                return Err(Error::MissingField {
                    files: program.files(),
                    obj: ObjTy::Local,
                    pos: rt.pos,
                    field: "file",
                });
            }
        };

        let full_path = Path::new(program.files().name(src_id))
            .parent()
            .unwrap()
            .join(file);

        let file_hash = blake3::hash(&std::fs::read(&full_path).unwrap_or_else(|err| {
            panic!(
                "Local input could not be read: {} (file: {})",
                err,
                full_path.display()
            )
        }));

        Ok((full_path, file_hash))
    }

    fn read_input_prebuilt(
        &mut self,
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
    ) -> Result<(String, Option<String>), Error> {
        let mut package: Option<String> = None;
        let mut sha256: Option<String> = None;
        match rt.term.as_ref() {
            Term::Record(r) | Term::RecRecord(r, _, _, _) => {
                r.fields
                    .iter()
                    .try_for_each(|(ident_and_loc, field)| -> Result<(), Error> {
                        match ident_and_loc.label() {
                            "package" => {
                                package = Some(
                                    String::deserialize(eval_if_closure(
                                        field.value.as_ref().unwrap(),
                                        program,
                                    )?)
                                    .unwrap(),
                                );
                                Ok(())
                            }
                            "sha256" => {
                                if let Some(field) = field.value.as_ref() {
                                    sha256 = Some(
                                        String::deserialize(eval_if_closure(field, program)?)
                                            .unwrap(),
                                    );
                                }
                                Ok(())
                            }
                            _ => Ok(()), // TODO: Should we error if we see an unknown field?
                        }
                    })?;
            }
            _ => {}
        }
        let package = match package {
            Some(package) => package,
            None => {
                return Err(Error::MissingField {
                    files: program.files(),
                    obj: ObjTy::Prebuilt,
                    pos: rt.pos,
                    field: "package",
                });
            }
        };

        Ok((package, sha256))
    }

    /// Reads an entry in runtime_deps, which can either be a build spec or a subset.
    fn read_runtime_dep(
        &mut self,
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
    ) -> Result<RuntimeDep, Error> {
        let rt = eval_if_closure(rt, program)?;

        // The type hint ty identifies which input variant this term represents
        let ty = read_ty(&rt, program)?;
        match ty {
            ObjTy::Builder => Ok(RuntimeDep::Build(self.read_buildspec(&rt, program)?)),
            ObjTy::Subset => Ok(RuntimeDep::Subset(self.read_subset(&rt, program)?)),
            ObjTy::OutputLib
            | ObjTy::OutputBin
            | ObjTy::OutputData
            | ObjTy::Source
            | ObjTy::Path
            | ObjTy::Local
            | ObjTy::Prebuilt => Err(Error::UnexpectedObject {
                files: program.files(),
                got: ty,
                want: ObjTy::Builder,
                pos: rt.pos,
            }),
        }
    }

    /// Recursively reads a buildspec input, inserting it into the graph.
    fn read_input(
        &mut self,
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
    ) -> Result<BuildSpecInput, Error> {
        let rt = eval_if_closure(rt, program)?;

        // The type hint ty identifies which input variant this term represents
        let ty = read_ty(&rt, program)?;
        match ty {
            ObjTy::Builder => Ok(BuildSpecInput::Build(self.read_buildspec(&rt, program)?)),
            ObjTy::Subset => Ok(BuildSpecInput::Subset(self.read_subset(&rt, program)?)),
            ObjTy::Source => Ok(BuildSpecInput::Source(
                self.read_input_source(&rt, program)?,
            )),
            ObjTy::Path => Ok(BuildSpecInput::HostPath(
                self.read_input_hostpath(&rt, program)?.into(),
            )),
            ObjTy::Local => {
                let (full_path, file_hash) = self.read_input_local(&rt, program)?;
                Ok(BuildSpecInput::Local((full_path, file_hash)))
            }
            ObjTy::Prebuilt => {
                let pb = self.read_input_prebuilt(&rt, program)?;
                Ok(BuildSpecInput::Prebuilt(pb.0, pb.1))
            }
            ObjTy::OutputLib | ObjTy::OutputBin | ObjTy::OutputData => {
                Err(Error::UnexpectedObject {
                    files: program.files(),
                    got: ty,
                    want: ObjTy::Builder,
                    pos: rt.pos,
                })
            }
        }
    }

    fn read_output_lib(
        &mut self,
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
    ) -> Result<BuildOutput, Error> {
        let mut glob: Option<String> = None;
        match rt.term.as_ref() {
            Term::Record(r) | Term::RecRecord(r, _, _, _) => {
                r.fields
                    .iter()
                    .try_for_each(|(ident_and_loc, field)| -> Result<(), Error> {
                        match ident_and_loc.label() {
                            "glob" => {
                                glob = Some(
                                    String::deserialize(eval_if_closure(
                                        field.value.as_ref().unwrap(),
                                        program,
                                    )?)
                                    .unwrap(),
                                );
                                Ok(())
                            }
                            _ => Ok(()), // TODO: Should we error if we see an unknown field?
                        }
                    })?;
            }
            _ => {}
        }
        let glob = match glob {
            Some(glob) => glob,
            None => {
                return Err(Error::MissingField {
                    files: program.files(),
                    obj: ObjTy::OutputLib,
                    pos: rt.pos,
                    field: "glob",
                });
            }
        };

        Ok(BuildOutput::Library { glob })
    }

    fn read_output_data(
        &mut self,
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
    ) -> Result<BuildOutput, Error> {
        let mut glob: Option<String> = None;
        match rt.term.as_ref() {
            Term::Record(r) | Term::RecRecord(r, _, _, _) => {
                r.fields
                    .iter()
                    .try_for_each(|(ident_and_loc, field)| -> Result<(), Error> {
                        match ident_and_loc.label() {
                            "glob" => {
                                glob = Some(
                                    String::deserialize(eval_if_closure(
                                        field.value.as_ref().unwrap(),
                                        program,
                                    )?)
                                    .unwrap(),
                                );
                                Ok(())
                            }
                            _ => Ok(()), // TODO: Should we error if we see an unknown field?
                        }
                    })?;
            }
            _ => {}
        }
        let glob = match glob {
            Some(glob) => glob,
            None => {
                return Err(Error::MissingField {
                    files: program.files(),
                    obj: ObjTy::OutputData,
                    pos: rt.pos,
                    field: "glob",
                });
            }
        };

        Ok(BuildOutput::Data { glob })
    }

    fn read_output_bin(
        &mut self,
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
    ) -> Result<BuildOutput, Error> {
        let mut glob: Option<String> = None;
        match rt.term.as_ref() {
            Term::Record(r) | Term::RecRecord(r, _, _, _) => {
                r.fields
                    .iter()
                    .try_for_each(|(ident_and_loc, field)| -> Result<(), Error> {
                        match ident_and_loc.label() {
                            "glob" => {
                                glob = Some(
                                    String::deserialize(eval_if_closure(
                                        field.value.as_ref().unwrap(),
                                        program,
                                    )?)
                                    .unwrap(),
                                );
                                Ok(())
                            }
                            _ => Ok(()), // TODO: Should we error if we see an unknown field?
                        }
                    })?;
            }
            _ => {}
        }
        let glob = match glob {
            Some(glob) => glob,
            None => {
                return Err(Error::MissingField {
                    files: program.files(),
                    obj: ObjTy::OutputBin,
                    pos: rt.pos,
                    field: "glob",
                });
            }
        };

        Ok(BuildOutput::Binary { glob })
    }

    /// Recursively reads a buildspec output value, inserting it into the graph.
    fn read_output_value(
        &mut self,
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
    ) -> Result<BuildOutput, Error> {
        let rt = eval_if_closure(rt, program)?;

        // The type hint ty identifies which input variant this term represents
        let ty = read_ty(&rt, program)?;
        match ty {
            ObjTy::OutputLib => self.read_output_lib(&rt, program),
            ObjTy::OutputData => self.read_output_data(&rt, program),
            ObjTy::OutputBin => self.read_output_bin(&rt, program),
            _ => Err(Error::UnexpectedObject {
                files: program.files(),
                got: ty,
                want: ObjTy::OutputLib,
                pos: rt.pos,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SpecReaderOptions;
    use indoc::indoc;

    #[test]
    fn single() {
        let sr = SpecReader::new(
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
            &SpecReaderOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = DepGraph::new(sr).unwrap();
        // We expect a single buildspec with a known name
        assert_eq!(
            vec!["single buildspec".to_string()],
            dp.builds
                .iter()
                .map(|b| b.1.name.clone())
                .collect::<Vec<String>>()
        );
        // We expect that buildspec to have one HostPath input
        assert!(matches!(
            dp.builds.iter().next().unwrap().1.inputs[0],
            BuildSpecInput::HostPath(_)
        ));

        assert_eq!(dp.builds.iter().next().unwrap().1.cmd, "./build.sh",);
        assert_eq!(
            dp.builds
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
    fn source_input() {
        let sr = SpecReader::new(
            indoc! {
                "
                let {BuildSpec, HostPath, OutputLib, Source, ..} = import \"minimal.ncl\" in
                {
                    name = \"single buildspec\",
                    inputs = [
                        {url = \"http://uwu.com\", sha256 = \"abcdef\", extract = true} | Source,
                    ],
                    cmd = \"\",
                } | BuildSpec"
            }
            .to_string(),
            &SpecReaderOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = DepGraph::new(sr).unwrap();
        // We expect that buildspec to have one Source input
        assert!(matches!(
            dp.builds.iter().next().unwrap().1.inputs[0].clone(),
            BuildSpecInput::Source(SourceInput {
                from: SourceFetch::URL(url),
                sha256: sha,
                extract: true,
                strip_prefix: None,
            }) if url == "http://uwu.com" && sha == "abcdef",
        ));
    }
    #[test]
    fn local_input() {
        let sr = SpecReader::new_with_path(
            std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                .join("testdata/local_input.ncl"),
            &SpecReaderOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = DepGraph::new(sr).unwrap();
        // We expect that buildspec to have one Local input
        assert!(matches!(
            dp.builds.iter().next().unwrap().1.inputs[0].clone(),
            BuildSpecInput::Local((p, _)) if p.ends_with("testdata/local_input.txt"),
        ));
    }
    #[test]
    fn subset_input() {
        let sr = SpecReader::new(
            indoc! {
                "
                let {BuildSpec, OutputData, Subset, ..} = import \"minimal.ncl\" in
                let other_spec = {
                    name = \"other\",
                    inputs = [],
                    cmd = \"\",
                    outputs = {
                        abc = {glob=\"\"} | OutputData,
                        uwu = {glob=\"\"} | OutputData,
                    },
                } | BuildSpec in
                {
                    name = \"top\",
                    inputs = [
                        {from = other_spec, outputs = [\"uwu\", \"abc\"]} | Subset,
                    ],
                    cmd = \"\",
                } | BuildSpec"
            }
            .to_string(),
            &SpecReaderOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = DepGraph::new(sr)
            .map_err(|e| {
                e.report_to_stderr();
                Err::<DepGraph, ()>(())
            })
            .unwrap();
        // We expect that buildspec to have one Subset input
        assert!(matches!(
            dp.get(&dp.by_name("top").next().unwrap()).unwrap().inputs[0].clone(),
            BuildSpecInput::Subset(SubsetInput {
                from,
                outputs,
            }) if from == dp.by_name("other").next().unwrap() && outputs == vec!["abc", "uwu"],
        ));
    }

    #[test]
    fn outputs() {
        let sr = SpecReader::new(
            indoc! {
                "
                let {BuildSpec, HostPath, OutputLib, OutputData, OutputBin, Source, ..} = import \"minimal.ncl\" in
                {
                    name = \"single buildspec\",
                    inputs = [
                        {url = \"http://uwu.com\", sha256 = \"abcdef\"} | Source,
                    ],
                    outputs = {
                        something = { glob = \"/usr/lib/something.*.so\" } | OutputLib,
                        uwu_tool = { glob = \"/bin/uwu\" } | OutputBin,
                        some_data = { glob = \"/data/locale/*\"  } | OutputData,
                    },
                    cmd = \"\",
                } | BuildSpec"
            }
            .to_string(),
            &SpecReaderOptions::for_test(),
        ).unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = DepGraph::new(sr).unwrap();
        // We expect that buildspec to have one Library output
        assert_eq!(
            dp.builds.iter().next().unwrap().1.outputs["something"],
            BuildOutput::Library {
                glob: "/usr/lib/something.*.so".to_string()
            },
        );
        // We expect that buildspec to have one Binary output
        assert_eq!(
            dp.builds.iter().next().unwrap().1.outputs["uwu_tool"],
            BuildOutput::Binary {
                glob: "/bin/uwu".to_string()
            },
        );
        // We expect that buildspec to have one Data output
        assert_eq!(
            dp.builds.iter().next().unwrap().1.outputs["some_data"],
            BuildOutput::Data {
                glob: "/data/locale/*".to_string()
            },
        );
    }

    #[test]
    fn one_nested() {
        let sr = SpecReader::new(
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
            &SpecReaderOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = DepGraph::new(sr).unwrap();
        // We expect two buildspecs - deeper first
        assert_eq!(
            vec!["top build".to_string(), "nested build".to_string()],
            dp.builds
                .into_iter()
                .map(|b| b.name)
                .collect::<Vec<String>>()
        );
    }

    #[test]
    fn shared_spec_not_duplicated() {
        let sr = SpecReader::new(
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
            &SpecReaderOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = DepGraph::new(sr).unwrap();
        // We expect three buildspecs - four buildspecs would mean that `shared` (referenced twice) was duplicated
        assert_eq!(
            vec![
                "top build".to_string(),
                "nested build".to_string(),
                "sharing is caringgggg".to_string(),
            ],
            dp.builds
                .into_iter()
                .map(|b| b.name)
                .collect::<Vec<String>>()
        );
    }

    #[test]
    fn spec_hash_doesnt_explode_on_cycles() {
        let sr = SpecReader::new(
            indoc! {
                "
                let {BuildSpec, Source, ..} = import \"minimal.ncl\" in

                let rec b1 = {
                    name = \"b1\",
                    inputs = [
                        b2,
                    ],
                    cmd = \"\",
                } | BuildSpec,
                b2 = {
                    name = \"b2\",
                    inputs = [
                        b1,
                    ],
                    cmd = \"\",
                } | BuildSpec,
                in
                b1"
            }
            .to_string(),
            &SpecReaderOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = DepGraph::new(sr).unwrap();
        assert!(
            dp.spec_hash(&dp.by_name("b1").next().unwrap())
                != dp.spec_hash(&dp.by_name("b2").next().unwrap()),
        );
    }

    #[test]
    fn runtime_deps() {
        let sr = SpecReader::new(
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
            &SpecReaderOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });
        let dp = DepGraph::new(sr)
            .map_err(|e| {
                e.report_to_stderr();
                Err::<DepGraph, ()>(())
            })
            .unwrap();

        // We expect two buildspecs - deeper first
        assert_eq!(
            vec!["top build".to_string(), "runtime dep".to_string()],
            dp.builds
                .iter()
                .map(|b| b.1.name.clone())
                .collect::<Vec<String>>()
        );

        // We expect the runtime_dep to be the same as the input
        assert_eq!(
            dp.builds
                .iter()
                .map(|b| b.1.clone())
                .collect::<Vec<BuildSpec>>()[0]
                .inputs[0]
                .as_build()
                .unwrap(),
            dp.builds
                .iter()
                .map(|b| b.1.clone())
                .collect::<Vec<BuildSpec>>()[0]
                .runtime_deps[0]
                .bsr()
        );
        // Lets check the subset
        assert!(matches!(
            dp.get(&dp.by_name("top build").next().unwrap()).unwrap().runtime_deps[1].clone(),
            RuntimeDep::Subset(SubsetInput {
                from,
                outputs,
            }) if from == dp.by_name("runtime dep").next().unwrap() && outputs == vec!["some_data"],
        ));
    }

    #[test]
    fn transitive_specs_of() {
        let sr = SpecReader::new(
            indoc! {
                "
                let {BuildSpec, Source, ..} = import \"minimal.ncl\" in

                let shared = {
                    name = \"shared\",
                    inputs = [
                        {url = \"http://uwu.com\", sha256 = \"abcdef\"} | Source,
                    ],
                    cmd = \"\",
                } | BuildSpec
                in

                {
                    name = \"top build\",
                    inputs = [
                        shared,
                        {
                            name = \"second build\",
                            inputs = [],
                            cmd = \"\",
                        } | BuildSpec,
                    ],
                    cmd = \"\",
                } | BuildSpec"
            }
            .to_string(),
            &SpecReaderOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = DepGraph::new(sr).unwrap();
        assert_eq!(
            dp.transitive_specs_of(&dp.top_levels[0]),
            vec![
                BuildSpecRef(dp.builds.iter().find(|b| b.1.name == "shared").unwrap().0),
                BuildSpecRef(
                    dp.builds
                        .iter()
                        .find(|b| b.1.name == "second build")
                        .unwrap()
                        .0
                )
            ]
        );
    }

    #[test]
    fn circular_ref_doesnt_crash() {
        let sr = SpecReader::new(
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
            &SpecReaderOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = DepGraph::new(sr).unwrap();
        // We expect two buildspecs
        assert_eq!(
            vec!["build 1".to_string(), "build 2".to_string(),],
            dp.builds
                .into_iter()
                .map(|b| b.name)
                .collect::<Vec<String>>()
        );
    }

    #[test]
    fn packages_ensure_no_dupes() {
        let sr = SpecReader::new_with_all_pkgs(
            std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                .join("../../packages"),
            &SpecReaderOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = DepGraph::new(sr).unwrap();

        let mut names: Vec<_> = dp.iter().map(|(_bsr, bs)| bs.name.clone()).collect();
        names.sort();

        let mut dupes = names.clone();
        dupes.dedup();
        if dupes.len() < names.len() {
            panic!("duplicate build-specs in packages/:\n{:?}", names);
        }
    }

    #[test]
    fn parse_target() {
        let sr = SpecReader::new(
            indoc! {
                "
                let {BuildSpec, HostPath, OutputLib, ..} = import \"minimal.ncl\" in
                {
        			name = \"buildspec\",
                    inputs = [],
        			cmd = \"./build.sh\",
                    target = \"arm64/macos\",
        		} | BuildSpec"
            }
            .to_string(),
            &SpecReaderOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = DepGraph::new(sr)
            .map_err(|e| {
                e.report_to_stderr();
                Err::<DepGraph, ()>(())
            })
            .unwrap();
        // We expect a single buildspec with a known name
        assert_eq!(
            dp.get(&dp.by_name("buildspec").next().unwrap())
                .unwrap()
                .target,
            Target::new(Arch::Arm64, OS::MacOS),
        );
    }
}
