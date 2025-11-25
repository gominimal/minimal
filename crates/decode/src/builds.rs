//! Build specification objects.

use crate::{Error, ObjTy, attrs::AttrValue, eval_if_closure, read_ty};
use common::{
    Target,
    target::{Arch, OS},
};
use nickel_lang_core::files::FileId;
use nickel_lang_core::identifier::LocIdent;
use nickel_lang_core::term::{IndexMap, RichTerm, Term};
use nickel_lang_core::{eval::cache::CacheImpl, program::Program};
use serde::Deserialize;
use smallvec::SmallVec;

use std::path::{Path, PathBuf};

/// A map with ordered iteration semantics - we need this for stable spec hashes.
type OutputMap = IndexMap<String, BuildOutput>;

/// A reference to some other build.
#[derive(Debug, Clone, Eq, PartialOrd, Ord)]
pub enum BuildRef {
    /// A build within the same layer.
    Local { annotated_id: u64, name: String },
    /// A build/package with a given name from an upstream layer.
    Upstream { name: String },
}

impl PartialEq for BuildRef {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                BuildRef::Local {
                    annotated_id: id1, ..
                },
                BuildRef::Local {
                    annotated_id: id2, ..
                },
            ) => id1 == id2,
            (BuildRef::Upstream { name: n1 }, BuildRef::Upstream { name: n2 }) => n1 == n2,
            (BuildRef::Local { .. }, BuildRef::Upstream { .. })
            | (BuildRef::Upstream { .. }, BuildRef::Local { .. }) => false,
        }
    }
}

impl core::hash::Hash for BuildRef {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            BuildRef::Local {
                annotated_id: id, ..
            } => state.write_u64(*id),
            BuildRef::Upstream { name } => {
                state.write(b"upstream");
                state.write(name.as_bytes());
            }
        }
    }
}

impl BuildRef {
    pub(crate) fn from_term<A: super::DeclAccumulator>(
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
        acc: &mut A,
    ) -> Result<Self, Error> {
        let rt = eval_if_closure(rt, program)?;

        // The type hint ty identifies which variant this term represents
        let ty = read_ty(&rt, program)?;
        match ty {
            ObjTy::Upstream => {
                let record = match rt.as_ref() {
                    Term::RecRecord(record_data, _, _, _) => record_data,
                    Term::Record(record_data) => record_data,
                    _ => unreachable!(),
                };

                let name =
                    if let Ok(Some(n_rt)) = record.get_value_with_ctrs(&LocIdent::new("name")) {
                        String::deserialize(eval_if_closure(&n_rt, program)?).unwrap()
                    } else {
                        return Err(Error::MissingField {
                            files: program.files(),
                            obj: ObjTy::Upstream,
                            pos: rt.pos,
                            field: "name",
                        });
                    };

                Ok(BuildRef::Upstream { name })
            }

            ObjTy::Builder => {
                let record = match rt.as_ref() {
                    Term::RecRecord(record_data, _, _, _) => record_data,
                    Term::Record(record_data) => record_data,
                    _ => unreachable!(),
                };
                let id = if let Ok(Some(id_rt)) =
                    record.get_value_with_ctrs(&LocIdent::new("__magic_buildspec_id"))
                {
                    if let Term::ForeignId(id) = id_rt.as_ref() {
                        *id
                    } else {
                        return Err(Error::MissingID(program.files(), rt.pos));
                    }
                } else {
                    return Err(Error::MissingID(program.files(), rt.pos));
                };

                let name =
                    if let Ok(Some(n_rt)) = record.get_value_with_ctrs(&LocIdent::new("name")) {
                        String::deserialize(eval_if_closure(&n_rt, program)?).unwrap()
                    } else {
                        return Err(Error::MissingField {
                            files: program.files(),
                            obj: ObjTy::Builder,
                            pos: rt.pos,
                            field: "name",
                        });
                    };

                // We need to do this conditionally to avoid an infinite recursion when there are cycles.
                acc.maybe_decode(&id, &rt, program)?;

                Ok(Self::Local {
                    annotated_id: id,
                    name,
                })
            }
            _ => Err(Error::UnexpectedObject {
                files: program.files(),
                got: ty,
                want: ObjTy::Builder,
                pos: rt.pos,
            }),
        }
    }
}

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

impl SourceInput {
    fn from_term(rt: &RichTerm, program: &mut Program<CacheImpl>) -> Result<Self, Error> {
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
}

/// A dependency on some of the outputs of a build-spec.
#[derive(Debug, Clone, PartialEq)]
pub struct SubsetInput {
    pub from: BuildRef,
    pub outputs: SmallVec<[String; 4]>,
}

impl SubsetInput {
    /// Constructs a new [SubsetInput], except using the given build instead.
    pub fn override_build(&self, br: BuildRef) -> Self {
        Self {
            from: br,
            ..self.clone()
        }
    }
}

impl SubsetInput {
    fn from_term<A: super::DeclAccumulator>(
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
        acc: &mut A,
    ) -> Result<Self, Error> {
        let mut from: Option<BuildRef> = None;
        let mut outputs: Option<SmallVec<[String; 4]>> = None;
        match rt.term.as_ref() {
            Term::Record(r) | Term::RecRecord(r, _, _, _) => {
                r.fields
                    .iter()
                    .try_for_each(|(ident_and_loc, field)| -> Result<(), Error> {
                        match ident_and_loc.label() {
                            "from" => {
                                from = Some(BuildRef::from_term(
                                    field.value.as_ref().unwrap(),
                                    program,
                                    acc,
                                )?);
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
                                                    .collect::<Result<SmallVec<_>, Error>>()?,
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

        Ok(SubsetInput { from, outputs })
    }
}

/// An input to a build spec.
///
/// Each entry in a build-spec's `inputs` array corresponds to one [BuildSpecInput].
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum BuildDeclInput {
    Build(BuildRef),
    Source(SourceInput),
    HostPath(PathBuf),
    Local {
        full_path: PathBuf,
        filename: String,
        file_hash: blake3::Hash,
    },
    Prebuilt(String, Option<String>), // Package name, sha256
    Subset(SubsetInput),
}

#[allow(dead_code)]
impl BuildDeclInput {
    /// Returns the underlying build-spec reference if this value was the Build variant.
    pub(crate) fn as_build(&self) -> Option<&BuildRef> {
        match self {
            BuildDeclInput::Build(bsr) => Some(bsr),
            _ => None,
        }
    }
}

impl BuildDeclInput {
    fn from_term<A: super::DeclAccumulator>(
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
        acc: &mut A,
    ) -> Result<Self, Error> {
        let rt = eval_if_closure(rt, program)?;

        // The type hint ty identifies which input variant this term represents
        let ty = read_ty(&rt, program)?;
        match ty {
            ObjTy::Builder | ObjTy::Upstream => {
                Ok(Self::Build(BuildRef::from_term(&rt, program, acc)?))
            }
            ObjTy::Subset => Ok(Self::Subset(SubsetInput::from_term(&rt, program, acc)?)),
            ObjTy::Source => Ok(Self::Source(SourceInput::from_term(&rt, program)?)),
            ObjTy::Path => Ok(BuildDeclInput::HostPath(
                Self::from_term_hostpath(&rt, program)?.into(),
            )),
            ObjTy::Local => {
                let (full_path, filename, file_hash) = Self::from_term_local(&rt, program)?;
                Ok(BuildDeclInput::Local {
                    full_path,
                    filename,
                    file_hash,
                })
            }
            ObjTy::Prebuilt => {
                let pb = Self::from_term_prebuilt(&rt, program)?;
                Ok(BuildDeclInput::Prebuilt(pb.0, pb.1))
            }
            ObjTy::OutputLib
            | ObjTy::OutputBin
            | ObjTy::OutputData
            | ObjTy::Profile
            | ObjTy::Layer => Err(Error::UnexpectedObject {
                files: program.files(),
                got: ty,
                want: ObjTy::Builder,
                pos: rt.pos,
            }),
        }
    }

    fn from_term_hostpath(
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

    fn from_term_local(
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
    ) -> Result<(PathBuf, String, blake3::Hash), Error> {
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
            .join(&file);

        let file_hash = blake3::hash(&std::fs::read(&full_path).unwrap_or_else(|err| {
            panic!(
                "Local input could not be read: {} (file: {})",
                err,
                full_path.display()
            )
        }));

        Ok((full_path, file, file_hash))
    }

    fn from_term_prebuilt(
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

impl BuildOutput {
    fn from_term(rt: &RichTerm, program: &mut Program<CacheImpl>) -> Result<Self, Error> {
        let rt = eval_if_closure(rt, program)?;

        // The type hint ty identifies which output variant this term represents
        let ty = read_ty(&rt, program)?;
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
                    obj: ty,
                    pos: rt.pos,
                    field: "glob",
                });
            }
        };

        match ty {
            ObjTy::OutputLib => Ok(BuildOutput::Library { glob }),
            ObjTy::OutputData => Ok(BuildOutput::Data { glob }),
            ObjTy::OutputBin => Ok(BuildOutput::Binary { glob }),
            _ => Err(Error::UnexpectedObject {
                files: program.files(),
                got: ty,
                want: ObjTy::OutputLib,
                pos: rt.pos,
            }),
        }
    }
}

/// A runtime dependency declared on a build-spec.
///
/// Each entry in a build-spec's `runtime_deps` array corresponds to one [RuntimeDep].
#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeDep {
    /// A direct runtime dependency on the build-spec described by the contained reference.
    Build(BuildRef),
    /// A direct runtime dependency on a subset of the outputs of some other build-spec.
    Subset(SubsetInput),
}

impl RuntimeDep {
    /// Returns the build spec that the runtime dependency ultimately depends on.
    pub fn bsr(&self) -> &BuildRef {
        match self {
            RuntimeDep::Build(bsr) => bsr,
            RuntimeDep::Subset(SubsetInput { from, .. }) => from,
        }
    }
}

impl RuntimeDep {
    fn from_term<A: super::DeclAccumulator>(
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
        acc: &mut A,
    ) -> Result<RuntimeDep, Error> {
        let rt = eval_if_closure(rt, program)?;

        // The type hint ty identifies which input variant this term represents
        let ty = read_ty(&rt, program)?;
        match ty {
            ObjTy::Builder | ObjTy::Upstream => {
                Ok(RuntimeDep::Build(BuildRef::from_term(&rt, program, acc)?))
            }
            ObjTy::Subset => Ok(RuntimeDep::Subset(SubsetInput::from_term(
                &rt, program, acc,
            )?)),
            _ => Err(Error::UnexpectedObject {
                files: program.files(),
                got: ty,
                want: ObjTy::Builder,
                pos: rt.pos,
            }),
        }
    }
}

/// Some task or build in the dependency graph.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct BuildDecl {
    /// The human-readable name declared on the build decl.
    pub name: String,
    /// The system this build-decl is meant to run on. Defaults to amd64 Linux.
    pub target: Target,
    /// Any attributes explicitly set on this build-decl.
    pub attrs: Option<IndexMap<String, AttrValue>>,

    /// The build command declared on the build spec.
    pub cmd: String,
    /// Any arguments to the build command, ultimately passed as environment variables.
    pub build_args: Option<IndexMap<String, String>>,

    /// The dependencies needed to execute the build spec.
    pub inputs: SmallVec<[BuildDeclInput; 10]>,
    /// The dependencies needed to run outputs of this build spec, as well as possibly needed
    /// during the build.
    pub runtime_deps: SmallVec<[RuntimeDep; 8]>,
    /// Any needs explicitly set on this build-decl.
    pub abstract_deps: Option<IndexMap<String, AttrValue>>,
    /// The named outputs (and match patterns) produced by executing this build spec.
    pub outputs: OutputMap,

    /// An alternative build spec to use to break cycles in resolving dependencies on this build spec.
    pub replace_on_cycle: Option<BuildRef>,
}

impl BuildDecl {
    /// Returns true if the build-spec represents a fetch of files but no actual computation.
    pub fn is_pure_prebuilt(&self) -> bool {
        let has_prebuilt = self
            .inputs
            .iter()
            .any(|input| matches!(input, BuildDeclInput::Prebuilt(_, _)));
        let has_local_or_source = self.inputs.iter().any(|input| {
            matches!(
                input,
                BuildDeclInput::Local { .. } | BuildDeclInput::Source(_)
            )
        });

        has_prebuilt && !has_local_or_source
    }

    /// Returns true if the build-spec represents a rollup of runtime_deps but no substance or computation of its own.
    pub fn is_pure_collection(&self) -> bool {
        self.inputs.is_empty() && self.cmd.is_empty()
    }
}

impl BuildDecl {
    pub(crate) fn from_term<A: super::DeclAccumulator>(
        rt: &RichTerm,
        program: &mut Program<CacheImpl>,
        acc: &mut A,
    ) -> Result<Self, Error> {
        let rt = eval_if_closure(rt, program)?;

        // Read out the attributes
        let mut name: Option<String> = None;
        let mut cmd: Option<String> = None;
        let mut ty: Option<ObjTy> = None;
        let mut target: Option<Target> = None;
        let mut build_args: Option<IndexMap<String, String>> = None;
        let mut inputs: Option<SmallVec<[BuildDeclInput; 10]>> = None;
        let mut runtime_deps: Option<SmallVec<[RuntimeDep; 8]>> = None;
        let mut needs: Option<IndexMap<String, AttrValue>> = None;
        let mut outputs: Option<OutputMap> = None;
        let mut replace_on_cycle: Option<BuildRef> = None;
        let mut attrs: Option<IndexMap<String, AttrValue>> = None;
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
                                            .map(|input| BuildDeclInput::from_term(input, program, acc))
                                            .collect::<Result<SmallVec<_>, Error>>()?,
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
                                                        RuntimeDep::from_term(input, program, acc)
                                                    })
                                                    .collect::<Result<SmallVec<_>, Error>>()?,
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
                                                    BuildOutput::from_term(val, program)?,
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
                                    replace_on_cycle = Some(BuildRef::from_term(value, program, acc)?);
                                }
                                Ok(())
                            }
                            "attrs" => {
                                if let Some(attrs_rt) = field.value.as_ref() {
                                    let attrs_rt =
                                        eval_if_closure(attrs_rt, program)?;

                                    match attrs_rt.term.as_ref() {
                                        Term::Record(r) | Term::RecRecord(r, _, _, _) => {
                                            attrs = Some(r.fields.iter().map(
                                                |(ident_and_loc, field)| -> Result<(String, AttrValue), Error> {
                                                    Ok((
                                                        ident_and_loc.label().to_string(),
                                                        AttrValue::from_term(
                                                            field.value.as_ref().unwrap(),
                                                            program,
                                                        )?,
                                                    ))
                                                },
                                            ).collect::<Result<IndexMap<_, _>, Error>>()?);
                                        }
                                        _ => todo!("unexpected term for attrs: {:?}", attrs_rt.term.as_ref()),
                                    };
                                }

                                Ok(())
                            }
                            "needs" => {
                                if let Some(needs_rt) = field.value.as_ref() {
                                    let needs_rt =
                                        eval_if_closure(needs_rt, program)?;

                                    match needs_rt.term.as_ref() {
                                        Term::Record(r) | Term::RecRecord(r, _, _, _) => {
                                            needs = Some(r.fields.iter().map(
                                                |(ident_and_loc, field)| -> Result<(String, AttrValue), Error> {
                                                    Ok((
                                                        ident_and_loc.label().to_string(),
                                                        AttrValue::from_term(
                                                            field.value.as_ref().unwrap(),
                                                            program,
                                                        )?,
                                                    ))
                                                },
                                            ).collect::<Result<IndexMap<_, _>, Error>>()?);
                                        }
                                        _ => todo!("unexpected term for needs: {:?}", needs_rt.term.as_ref()),
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

        Ok(Self {
            name,
            cmd,
            attrs,
            build_args,
            target: target.unwrap_or(Target::new(Arch::Amd64, OS::Linux)),
            inputs,
            runtime_deps,
            abstract_deps: needs,
            outputs,
            replace_on_cycle,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load::*;
    use indoc::indoc;

    #[test]
    fn source_input() {
        let (term, mut program, _origin) = Loader::new(
            indoc! {
                "
                let {Source, ..} = import \"minimal.ncl\" in
                {url = \"http://uwu.com\", sha256 = \"abcdef\", extract = true} | Source
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

        let source = BuildDeclInput::from_term(&term, &mut program, &mut ()).unwrap();

        assert!(matches!(
            source,
            BuildDeclInput::Source( SourceInput {
                from: SourceFetch::URL(url),
                sha256: sha,
                extract: true,
                strip_prefix: None,
            }) if url == "http://uwu.com" && sha == "abcdef",
        ));
    }

    #[test]
    fn local_input() {
        let path = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("testdata/local_input.ncl");

        let (term, mut program, _origin) = Loader::new(
            format!("import \"{}\"", path.to_str().unwrap()),
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

        let source = BuildDeclInput::from_term(&term, &mut program, &mut ()).unwrap();

        assert!(matches!(
            source,
            BuildDeclInput::Local{ full_path, .. } if full_path.ends_with("testdata/local_input.txt"),
        ));
    }

    #[test]
    fn hostpath_input() {
        let (term, mut program, _origin) = Loader::new(
            indoc! {
                "
                let {HostPath, ..} = import \"minimal.ncl\" in
                {path = \"/bin/bash\"} | HostPath
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

        let source = BuildDeclInput::from_term(&term, &mut program, &mut ()).unwrap();

        assert!(matches!(
            source,
            BuildDeclInput::HostPath(p) if p.to_str().unwrap() == "/bin/bash",
        ));
    }

    #[test]
    fn subset_input() {
        let (term, mut program, _origin) = Loader::new(
            indoc! {
                "
                let {Subset, BuildSpec, OutputData, ..} = import \"minimal.ncl\" in
                {from = {
                    name = \"speccy\",
                    inputs = [],
                    cmd = \"\",
                    outputs = {
                        abc = {glob=\"\"} | OutputData,
                        uwu = {glob=\"\"} | OutputData,
                    },
                } | BuildSpec, outputs = [\"uwu\", \"abc\"]} | Subset
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

        let source = BuildDeclInput::from_term(&term, &mut program, &mut ()).unwrap();

        assert!(matches!(
            source,
            BuildDeclInput::Subset(SubsetInput { from: BuildRef::Local { name, .. }, outputs }) if name == "speccy" && outputs.to_vec() == vec!["abc", "uwu"],
        ));
    }

    #[test]
    fn build_simple() {
        let (term, mut program, _origin) = Loader::new(
            indoc! {
                "
                let {BuildSpec, HostPath, OutputLib, ..} = import \"minimal.ncl\" in
                {
        			name = \"single buildspec\",
        			inputs = [],
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
            panic!("load failed");
        })
        .finish()
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("finish failed");
        });

        let build = BuildDecl::from_term(&term, &mut program, &mut ()).unwrap();

        assert!(matches!(
            build,
            BuildDecl {
                name,
                target,
                cmd,
                attrs: _,
                build_args,
                inputs: _,
                runtime_deps: _,
                abstract_deps: _,
                outputs,
                replace_on_cycle
            } if name == "single buildspec" &&
                target == Target::default() &&
                cmd == "./build.sh" &&
                replace_on_cycle.is_none() &&
                build_args == Some([("fish".to_string(), "swiggity swooty".to_string())].into()) &&
                outputs == [("something".to_string(), BuildOutput::Library{ glob: "/usr/lib/something.*.so".to_string()})].into(),
        ));
    }

    #[test]
    fn parse_target() {
        let (term, mut program, _origin) = Loader::new(
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

        let build = BuildDecl::from_term(&term, &mut program, &mut ()).unwrap();

        assert_eq!(build.target, Target::new(Arch::Arm64, OS::MacOS),);
    }

    #[test]
    fn outputs() {
        let (term, mut program, _origin) = Loader::new(
            indoc! {
                "
                let {OutputLib, OutputData, OutputBin, ..} = import \"minimal.ncl\" in
                [
                    { glob = \"/usr/lib/something.*.so\" } | OutputLib,
                    { glob = \"/bin/uwu\" } | OutputBin,
                    { glob = \"/data/locale/*\"  } | OutputData,
                ]
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

        let (o_lib, o_bin, o_data) = if let Term::Array(a, _) = term.as_ref() {
            (
                BuildOutput::from_term(&a[0], &mut program).unwrap(),
                BuildOutput::from_term(&a[1], &mut program).unwrap(),
                BuildOutput::from_term(&a[2], &mut program).unwrap(),
            )
        } else {
            unreachable!()
        };

        // We expect that buildspec to have one Library output
        assert_eq!(
            o_lib,
            BuildOutput::Library {
                glob: "/usr/lib/something.*.so".to_string()
            },
        );
        // We expect that buildspec to have one Binary output
        assert_eq!(
            o_bin,
            BuildOutput::Binary {
                glob: "/bin/uwu".to_string()
            },
        );
        // We expect that buildspec to have one Data output
        assert_eq!(
            o_data,
            BuildOutput::Data {
                glob: "/data/locale/*".to_string()
            },
        );
    }

    #[test]
    fn parse_attrs() {
        let (term, mut program, _origin) = Loader::new(
            indoc! {
                "
                let {Attrs, BuildSpec, ..} = import \"minimal.ncl\" in
                {
        			name = \"buildspec\",
                    inputs = [],
        			cmd = \"./build.sh\",
                    attrs = {
                      upstream_version = \"1.2.3\",
                    } | Attrs,
        		} | BuildSpec"
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

        assert_eq!(
            BuildDecl::from_term(&term, &mut program, &mut ())
                .unwrap()
                .attrs,
            Some(IndexMap::from_iter([(
                "upstream_version".to_string(),
                AttrValue::String("1.2.3".to_string())
            )])),
        );
    }

    #[test]
    fn parse_needs() {
        let (term, mut program, _origin) = Loader::new(
            indoc! {
                "
                let {Needs, BuildSpec, ..} = import \"minimal.ncl\" in
                {
        			name = \"buildspec\",
                    inputs = [],
        			cmd = \"./build.sh\",
                    needs = {
                      dns = {},
                    } | Needs,
        		} | BuildSpec"
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

        assert_eq!(
            BuildDecl::from_term(&term, &mut program, &mut ())
                .unwrap()
                .abstract_deps,
            Some(IndexMap::from_iter([(
                "dns".to_string(),
                AttrValue::Map(Default::default())
            )])),
        );
    }

    #[test]
    fn parse_upstream() {
        let (term, mut program, _origin) = Loader::new(
            indoc! {
                "
                let {upstream, BuildSpec, HostPath, OutputLib, ..} = import \"minimal.ncl\" in
                {
        			name = \"single buildspec\",
        			inputs = [upstream \"upstream-pkg\"],
        			cmd = \"./build.sh\",
        		} | BuildSpec"
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

        let build = BuildDecl::from_term(&term, &mut program, &mut ()).unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("from_term failed");
        });

        assert_eq!(
            build.inputs[0],
            BuildDeclInput::Build(BuildRef::Upstream {
                name: "upstream-pkg".to_string()
            })
        );
    }
}
