//! The machinery for processing build specs into a dependency graph.

#![allow(clippy::result_large_err)]
#![allow(clippy::single_match)]

use nickel_lang_core::eval::Closure;
use nickel_lang_core::files::FileId;
use nickel_lang_core::identifier::LocIdent;
use nickel_lang_core::term::{RichTerm, Term};
use nickel_lang_core::{eval::cache::CacheImpl, program::Program};

use generational_arena::Arena;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use crate::spec_schema::*;
use crate::{Error, SpecError, SpecHash, SpecHashable, SpecReader};
use serde::Deserialize;

/// A map with ordered iteration semantics - we need this for stable spec hashes.
type OutputMap = nickel_lang_core::term::IndexMap<String, BuildOutput>;

/// A reference to some other [BuildSpec] in a [DepGraph].
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
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
}

/// An input to a build spec.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum BuildSpecInput {
    Build(BuildSpecRef),
    Source(SourceInput),
    HostPath(PathBuf),
    Local((PathBuf, blake3::Hash)),
    Prebuilt(String), // Package name
}

impl SpecHashable for BuildSpecInput {
    fn spec_hash(&self, g: &DepGraph, seen: &mut HashMap<BuildSpecRef, ()>) -> SpecHash {
        let mut h = blake3::Hasher::new();

        use BuildSpecInput::*;
        match self {
            Build(bsr) => {
                h.write_all(b"input").unwrap();
                h.write_all(g.spec_hash_impl(bsr, seen).as_bytes()).unwrap();
            }
            Source(s) => {
                h.write_all(b"source").unwrap();
                match &s.from {
                    SourceFetch::URL(url) => {
                        h.write_all(b"url").unwrap();
                        h.write_all(url.as_bytes()).unwrap()
                    }
                };
                h.write_all(s.sha256.as_bytes()).unwrap()
            }
            HostPath(p) => {
                h.write_all(b"host path").unwrap();
                h.write_all(p.as_path().to_string_lossy().as_bytes())
                    .unwrap();
            }
            Local(p) => {
                h.write_all(b"local").unwrap();
                h.write_all(p.0.as_path().to_string_lossy().as_bytes())
                    .unwrap();
                h.write_all(p.1.as_bytes()).unwrap();
            }
            Prebuilt(package) => {
                h.write_all(b"prebuilt").unwrap();
                h.write_all(package.as_bytes()).unwrap();
            }
        }

        SpecHash(h.finalize())
    }
}

#[allow(dead_code)]
impl BuildSpecInput {
    fn as_build(&self) -> Option<&BuildSpecRef> {
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
    Library { glob: String },
    Data { glob: String },
    Binary { path: String },
}

impl BuildOutput {
    #[allow(dead_code)]
    fn partial_spec_hash(&self, h: &mut blake3::Hasher) {
        use BuildOutput::*;
        match self {
            Library { glob } => {
                h.write_all(b"library").unwrap();
                h.write_all(glob.as_bytes()).unwrap();
            }
            Data { glob } => {
                h.write_all(b"data").unwrap();
                h.write_all(glob.as_bytes()).unwrap();
            }
            Binary { path } => {
                h.write_all(b"binary").unwrap();
                h.write_all(path.as_bytes()).unwrap();
            }
        }
    }
}

/// Some task or build in the dependency graph.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BuildSpec {
    pub name: String,
    pub cmd: String,

    pub inputs: Vec<BuildSpecInput>,
    pub runtime_deps: Vec<BuildSpecRef>,
    pub outputs: OutputMap,

    pub replace_on_cycle: Option<BuildSpecRef>,
}

impl SpecHashable for BuildSpec {
    fn spec_hash(&self, g: &DepGraph, seen: &mut HashMap<BuildSpecRef, ()>) -> SpecHash {
        let mut h = blake3::Hasher::new();

        h.write_all(b"build spec").unwrap();
        h.write_all(self.name.as_bytes()).unwrap();
        h.write_all(self.cmd.as_bytes()).unwrap();

        // We don't want the spec hash to change if the order of the inputs or runtime_deps change,
        // so lets sort the hashes before they are updated to our spec hash.
        // TODO: Consider performance implications of linear sort
        h.write_all(b"-inputs").unwrap();
        let mut input_hashes: Vec<SpecHash> =
            self.inputs.iter().map(|i| i.spec_hash(g, seen)).collect();
        input_hashes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        for hash in input_hashes.drain(..) {
            h.write_all(hash.as_bytes()).unwrap();
        }
        h.write_all(b"-runtime_deps").unwrap();
        let mut runtime_dep_hashes: Vec<SpecHash> = self
            .runtime_deps
            .iter()
            .map(|bsr| g.spec_hash_impl(bsr, seen))
            .collect();
        runtime_dep_hashes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        for hash in runtime_dep_hashes.drain(..) {
            h.write_all(hash.as_bytes()).unwrap();
        }

        h.write_all(b"-outputs").unwrap();
        for (name, output) in self.outputs.iter() {
            h.write_all(name.as_bytes()).unwrap();
            output.partial_spec_hash(&mut h);
        }

        if let Some(replace_on_cycle) = self.replace_on_cycle {
            h.write_all(b"replace on cycle").unwrap();
            h.write_all(g.spec_hash_impl(&replace_on_cycle, seen).as_bytes())
                .unwrap();
        }

        SpecHash(h.finalize())
    }
}

/// The dependency graph.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DepGraph {
    builds: Arena<BuildSpec>,
    pub top_level: BuildSpecRef,

    hash_cache: Arc<RwLock<HashMap<BuildSpecRef, SpecHash>>>,
}

impl DepGraph {
    pub fn new(sr: SpecReader) -> Result<Self, Error> {
        let mut graph = GraphBuilder {
            builds: Arena::with_capacity(4096),
            spec_id_lookup: HashMap::with_capacity(4096),
        };

        let (ncl_tree, mut program) = sr.finish()?;
        let top_level = graph.read_buildspec(&ncl_tree, &mut program)?;
        Ok(graph.finish(top_level))
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
            if let Some(hash) = self.hash_cache.read().unwrap().get(bsr) {
                return hash.clone();
            }
        }

        // TODO: use smol/starts-on-stack type for hashmap?
        let mut seen = HashMap::with_capacity(32);
        let hash = self.spec_hash_impl(bsr, &mut seen);

        self.hash_cache.write().unwrap().insert(*bsr, hash.clone());
        hash
    }

    fn spec_hash_impl(&self, bsr: &BuildSpecRef, seen: &mut HashMap<BuildSpecRef, ()>) -> SpecHash {
        if seen.contains_key(bsr) {
            return SpecHash::cycle();
        }

        let build = self.get(bsr).unwrap();

        seen.insert(*bsr, ());
        let hash = build.spec_hash(self, seen);
        seen.remove(bsr);
        hash
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
                Source(_) | HostPath(_) | Local(_) | Prebuilt(_) => None,
            })
            .chain(build_spec.runtime_deps.iter())
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
    fn finish(self, top_level: BuildSpecRef) -> DepGraph {
        let Self { builds, .. } = self;
        let hash_cache = Arc::new(RwLock::new(HashMap::with_capacity(builds.len())));
        DepGraph {
            builds,
            top_level,
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
        let rt = eval_if_closure(rt, program)?;
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
                })
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
                })
            }
        };
        let cmd = cmd.unwrap_or_default();

        // Start constructing the BuildSpec object. Insert it into the graph
        // and cache before we recurse.
        let bsr = BuildSpecRef(self.builds.insert(BuildSpec {
            name,
            cmd,
            inputs: Vec::new(),
            runtime_deps: Vec::new(),
            outputs: OutputMap::new(),
            replace_on_cycle: None,
        }));
        self.spec_id_lookup.insert(magic_id, bsr);

        // Handle more complicated attributes.
        let mut inputs: Option<Vec<BuildSpecInput>> = None;
        let mut runtime_deps: Option<Vec<BuildSpecRef>> = None;
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
                                    .unwrap()?;
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
                                                        self.read_buildspec(input, program)
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
                                    .unwrap()?;

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
                })
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
                })
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

    fn read_input_source(
        &mut self,
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
    ) -> Result<SourceInput, Error> {
        let mut url: Option<String> = None;
        let mut sha256: Option<String> = None;
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
                })
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
                })
            }
        };

        Ok(SourceInput {
            from: SourceFetch::URL(url),
            sha256,
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
                })
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
                })
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
    ) -> Result<String, Error> {
        let mut package: Option<String> = None;
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
                })
            }
        };

        Ok(package)
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
            ObjTy::Prebuilt => Ok(BuildSpecInput::Prebuilt(
                self.read_input_prebuilt(&rt, program)?,
            )),
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
                })
            }
        };

        Ok(BuildOutput::Library { glob })
    }

    fn read_output_data(
        &mut self,
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
    ) -> Result<BuildOutput, Error> {
        let mut data: Option<String> = None;
        match rt.term.as_ref() {
            Term::Record(r) | Term::RecRecord(r, _, _, _) => {
                r.fields
                    .iter()
                    .try_for_each(|(ident_and_loc, field)| -> Result<(), Error> {
                        match ident_and_loc.label() {
                            "data" => {
                                data = Some(
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
        let data = match data {
            Some(data) => data,
            None => {
                return Err(Error::MissingField {
                    files: program.files(),
                    obj: ObjTy::OutputData,
                    pos: rt.pos,
                    field: "data",
                })
            }
        };

        Ok(BuildOutput::Data { glob: data })
    }

    fn read_output_bin(
        &mut self,
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
    ) -> Result<BuildOutput, Error> {
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
                    obj: ObjTy::OutputBin,
                    pos: rt.pos,
                    field: "path",
                })
            }
        };

        Ok(BuildOutput::Binary { path })
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
                        {url = \"http://uwu.com\", sha256 = \"abcdef\"} | Source,
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
                        uwu_tool = { path = \"/bin/uwu\" } | OutputBin,
                        some_data = { data = \"/data/locale/*\"  } | OutputData,
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
                path: "/bin/uwu".to_string()
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
    fn spec_hash_smoketest() {
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

        let mut dp = DepGraph::new(sr).unwrap();

        let top_hash = dp
            .builds
            .iter()
            .find(|b| b.1.name == "top build")
            .unwrap()
            .1
            .spec_hash(&dp, &mut HashMap::new());

        {
            let (mut input1, mut input2) = dp
                .builds
                .iter_mut()
                .find(|b| b.1.name == "top build")
                .unwrap()
                .1
                .inputs
                .split_at_mut(1);
            std::mem::swap(&mut input1, &mut input2);
        }

        // check the spec hash is the same even if the input order changes
        assert_eq!(
            top_hash,
            dp.builds
                .iter()
                .find(|b| b.1.name == "top build")
                .unwrap()
                .1
                .spec_hash(&dp, &mut HashMap::new()),
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
                let {BuildSpec, ..} = import \"minimal.ncl\" in
                let our_runtime_dep = {
                    name = \"runtime dep\",
                    inputs = [],
                    cmd = \"\",
                } | BuildSpec in
                {
                    name = \"top build\",
                    inputs = [our_runtime_dep],
                    runtime_deps = [our_runtime_dep],
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
                .unwrap()
                .clone(),
            dp.builds
                .iter()
                .map(|b| b.1.clone())
                .collect::<Vec<BuildSpec>>()[0]
                .runtime_deps[0]
        );
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
            dp.transitive_specs_of(&dp.top_level),
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
}
