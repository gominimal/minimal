//! Build specification objects.

use crate::{Error, ObjTy, attrs::AttrValue, eval_if_closure, read_ty};
use crate::{StrPos, cmds_from_cmd_term, cmds_from_cmds_term};
use common::Target;
use nickel_lang_core::eval::value::NickelValue;
use nickel_lang_core::files::FileId;
use nickel_lang_core::identifier::LocIdent;
use nickel_lang_core::position::TermPos;
use nickel_lang_core::term::{IndexMap, RuntimeContract};
use nickel_lang_core::{eval::cache::CacheImpl, program::Program};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use std::path::{Path, PathBuf};

/// A map with ordered iteration semantics - we need this for stable spec hashes.
type OutputMap = IndexMap<String, BuildOutput>;

/// A reference to some other build.
#[derive(Debug, Clone, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
        rt: &NickelValue,
        program: &mut Program<CacheImpl>,
        acc: &mut A,
    ) -> Result<Self, Error> {
        let rt = eval_if_closure(rt, program)?;

        // The type hint ty identifies which variant this term represents
        let ty = read_ty(&rt, program)?;
        match ty {
            ObjTy::Upstream => {
                let record = crate::record_data_from_val(&rt).unwrap();

                let name =
                    if let Ok(Some(n_rt)) = record.get_value_with_ctrs(&LocIdent::new("name")) {
                        String::deserialize(eval_if_closure(&n_rt, program)?).unwrap()
                    } else {
                        return Err(Error::MissingField {
                            files: program.files(),
                            obj: ObjTy::Upstream,
                            pos: rt.pos(program.pos_table()),
                            field: "name",
                        });
                    };

                Ok(BuildRef::Upstream { name })
            }

            ObjTy::Builder => {
                let record = crate::record_data_from_val(&rt).unwrap();
                let id = if let Ok(Some(id_rt)) =
                    record.get_value_with_ctrs(&LocIdent::new("__magic_buildspec_id"))
                {
                    if let Some(id) = id_rt.as_foreign_id() {
                        *id
                    } else {
                        return Err(Error::MissingID(
                            program.files(),
                            rt.pos(program.pos_table()),
                        ));
                    }
                } else {
                    return Err(Error::MissingID(
                        program.files(),
                        rt.pos(program.pos_table()),
                    ));
                };

                let name =
                    if let Ok(Some(n_rt)) = record.get_value_with_ctrs(&LocIdent::new("name")) {
                        String::deserialize(eval_if_closure(&n_rt, program)?).unwrap()
                    } else {
                        return Err(Error::MissingField {
                            files: program.files(),
                            obj: ObjTy::Builder,
                            pos: rt.pos(program.pos_table()),
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
                pos: rt.pos(program.pos_table()),
            }),
        }
    }
}

/// A description of pulling source code regardless of form.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SourceFetch {
    Web {
        url: String,
        sha256: String,
        url_pos: Option<StrPos>,
        sha256_pos: Option<StrPos>,
    },
    Local {
        full_path: PathBuf,
        filename: String,
        file_hash: blake3::Hash,
    },
}

/// A description of source code thats used as an input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceInput {
    pub from: SourceFetch,
    pub extract: bool,
    pub strip_prefix: Option<String>,
}

impl SourceInput {
    fn from_term(rt: &NickelValue, program: &mut Program<CacheImpl>) -> Result<Self, Error> {
        let mut filename: Option<(String, FileId)> = None;

        let mut url: Option<(String, Option<TermPos>)> = None;
        let mut sha256: Option<(String, Option<TermPos>)> = None;

        let mut extract: Option<bool> = None;
        let mut strip_prefix: Option<String> = None;
        if let Some(r) = crate::record_data_from_val(rt) {
            r.fields
                .iter()
                .try_for_each(|(ident_and_loc, field)| -> Result<(), Error> {
                    match ident_and_loc.label() {
                        "file" => {
                            if let Some(rt) = field.value.as_ref() {
                                filename = Some((
                                    String::deserialize(eval_if_closure(rt, program)?).unwrap(),
                                    field
                                        .value
                                        .as_ref()
                                        .unwrap()
                                        .pos(program.pos_table())
                                        .src_id()
                                        .unwrap(),
                                ));
                            }
                            Ok(())
                        }
                        "url" => {
                            if let Some(rt) = field.value.as_ref() {
                                url = Some((
                                    String::deserialize(eval_if_closure(rt, program)?).unwrap(),
                                    Some(rt.pos(program.pos_table())),
                                ));
                            }
                            Ok(())
                        }
                        "sha256" => {
                            if let Some(rt) = field.value.as_ref() {
                                sha256 = Some((
                                    String::deserialize(eval_if_closure(rt, program)?).unwrap(),
                                    Some(rt.pos(program.pos_table())),
                                ));
                            }
                            Ok(())
                        }
                        "extract" => {
                            if let Some(ext_rt) = field.value.as_ref() {
                                extract = Some(
                                    bool::deserialize(eval_if_closure(ext_rt, program)?).unwrap(),
                                );
                            }
                            Ok(())
                        }
                        "strip_prefix" => {
                            if let Some(st_rt) = field.value.as_ref() {
                                strip_prefix = Some(
                                    String::deserialize(eval_if_closure(st_rt, program)?).unwrap(),
                                );
                            }
                            Ok(())
                        }
                        _ => Ok(()), // TODO: Should we error if we see an unknown field?
                    }
                })?;
        }

        let from = if let Some((file, file_id)) = filename {
            if file.contains("..") {
                return Err(Error::Other(format!(
                    "{}: file sources cannot contain '..'",
                    file
                )));
            }

            let full_path = Path::new(program.files().name(file_id))
                .parent()
                .unwrap()
                .join(&file);

            let file_hash = blake3::hash(&std::fs::read(&full_path).unwrap_or_else(|err| {
                panic!(
                    "Source input could not be read: {} (file: {})",
                    err,
                    full_path.display()
                )
            }));

            SourceFetch::Local {
                full_path,
                file_hash,
                filename: file,
            }
        } else {
            let (url, url_pos) = match url {
                Some(url) => url,
                None => {
                    return Err(Error::MissingField {
                        files: program.files(),
                        obj: ObjTy::Source,
                        pos: rt.pos(program.pos_table()),
                        field: "url",
                    });
                }
            };
            let (sha256, sha256_pos) = match sha256 {
                Some(sha256) => sha256,
                None => {
                    return Err(Error::MissingField {
                        files: program.files(),
                        obj: ObjTy::Source,
                        pos: rt.pos(program.pos_table()),
                        field: "sha256",
                    });
                }
            };

            SourceFetch::Web {
                url,
                url_pos: url_pos.and_then(|p| p.try_into().ok()),
                sha256,
                sha256_pos: sha256_pos.and_then(|p| p.try_into().ok()),
            }
        };

        Ok(SourceInput {
            from,
            extract: extract.unwrap_or(false),
            strip_prefix,
        })
    }
}

/// A dependency on some of the outputs of a build-spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
        rt: &NickelValue,
        program: &mut Program<CacheImpl>,
        acc: &mut A,
    ) -> Result<Self, Error> {
        let mut from: Option<BuildRef> = None;
        let mut outputs: Option<SmallVec<[String; 4]>> = None;
        if let Some(r) = crate::record_data_from_val(rt) {
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
                                Some(outputs_rt) => {
                                    let outputs_val = outputs_rt?;
                                    if let Some(a) = outputs_val.as_array() {
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
                                    } else {
                                        todo!(
                                            "handle outputs value being non-array {:?}",
                                            field.value
                                        );
                                    }
                                }
                            }
                            Ok(())
                        }
                        _ => Ok(()), // TODO: Should we error if we see an unknown field?
                    }
                })?;
        }
        let from = match from {
            Some(from) => from,
            None => {
                return Err(Error::MissingField {
                    files: program.files(),
                    obj: ObjTy::Subset,
                    pos: rt.pos(program.pos_table()),
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
                    pos: rt.pos(program.pos_table()),
                    field: "outputs",
                });
            }
        };
        outputs.sort();
        outputs.dedup();

        Ok(SubsetInput { from, outputs })
    }
}

/// An entry in a build spec's `build_deps` array.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum BuildDep {
    Build(BuildRef),
    Source(SourceInput),
    Local {
        full_path: PathBuf,
        filename: String,
        file_hash: blake3::Hash,
    },
    Subset(SubsetInput),
}

#[allow(dead_code)]
impl BuildDep {
    /// Returns the underlying build-spec reference if this value was the Build variant.
    pub(crate) fn as_build(&self) -> Option<&BuildRef> {
        match self {
            BuildDep::Build(bsr) => Some(bsr),
            _ => None,
        }
    }
}

impl BuildDep {
    fn from_term<A: super::DeclAccumulator>(
        rt: &NickelValue,
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
            ObjTy::Local => {
                let (full_path, filename, file_hash) = Self::from_term_local(&rt, program)?;
                Ok(BuildDep::Local {
                    full_path,
                    filename,
                    file_hash,
                })
            }
            ObjTy::OutputLib
            | ObjTy::OutputBin
            | ObjTy::OutputData
            | ObjTy::Profile
            | ObjTy::Stack
            | ObjTy::Container
            | ObjTy::Layer
            | ObjTy::Test => Err(Error::UnexpectedObject {
                files: program.files(),
                got: ty,
                want: ObjTy::Builder,
                pos: rt.pos(program.pos_table()),
            }),
        }
    }

    fn from_term_local(
        rt: &NickelValue,
        program: &mut Program<CacheImpl>,
    ) -> Result<(PathBuf, String, blake3::Hash), Error> {
        let mut file: Option<(String, FileId)> = None;
        if let Some(r) = crate::record_data_from_val(rt) {
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
                                field
                                    .value
                                    .as_ref()
                                    .unwrap()
                                    .pos(program.pos_table())
                                    .src_id()
                                    .unwrap(),
                            ));
                            Ok(())
                        }
                        _ => Ok(()), // TODO: Should we error if we see an unknown field?
                    }
                })?;
        }
        let (file, src_id) = match file {
            Some(file) => file,
            None => {
                return Err(Error::MissingField {
                    files: program.files(),
                    obj: ObjTy::Local,
                    pos: rt.pos(program.pos_table()),
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
}

/// An output from a build.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum BuildOutput {
    /// This output describes shared libraries matched with the given glob.
    Library { glob: String, allow_data: bool },
    /// This output describes data files matched with the given glob.
    Data {
        glob: String,
        allow_executable: bool,
    },
    /// This output describes binaries matched with the given glob.
    Binary {
        glob: String,
        #[serde(default)]
        allow_missing_interpreter: bool,
    },
}

impl BuildOutput {
    pub fn glob(&self) -> &String {
        match self {
            BuildOutput::Binary {
                glob,
                allow_missing_interpreter: _,
            } => glob,
            BuildOutput::Data {
                glob,
                allow_executable: _,
            } => glob,
            BuildOutput::Library {
                glob,
                allow_data: _,
            } => glob,
        }
    }
}

impl BuildOutput {
    fn from_term(rt: &NickelValue, program: &mut Program<CacheImpl>) -> Result<Self, Error> {
        let rt = eval_if_closure(rt, program)?;

        // The type hint ty identifies which output variant this term represents
        let ty = read_ty(&rt, program)?;
        let mut glob: Option<String> = None;
        let mut allow_executable: Option<bool> = None;
        let mut allow_data: Option<bool> = None;
        let mut allow_missing_interpreter: Option<bool> = None;

        if let Some(r) = crate::record_data_from_val(&rt) {
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
                        "allow_executable" => {
                            if let Some(rt) = field.value.as_ref() {
                                allow_executable =
                                    Some(bool::deserialize(eval_if_closure(rt, program)?).unwrap());
                            }
                            Ok(())
                        }
                        "allow_data" => {
                            if let Some(rt) = field.value.as_ref() {
                                allow_data =
                                    Some(bool::deserialize(eval_if_closure(rt, program)?).unwrap());
                            }
                            Ok(())
                        }
                        "allow_missing_interpreter" => {
                            if let Some(rt) = field.value.as_ref() {
                                allow_missing_interpreter =
                                    Some(bool::deserialize(eval_if_closure(rt, program)?).unwrap());
                            }
                            Ok(())
                        }
                        _ => Ok(()), // TODO: Should we error if we see an unknown field?
                    }
                })?;
        }
        let glob = match glob {
            Some(glob) => glob,
            None => {
                return Err(Error::MissingField {
                    files: program.files(),
                    obj: ty,
                    pos: rt.pos(program.pos_table()),
                    field: "glob",
                });
            }
        };
        let allow_executable = allow_executable.unwrap_or(false);
        let allow_data = allow_data.unwrap_or(false);
        let allow_missing_interpreter = allow_missing_interpreter.unwrap_or(false);

        match ty {
            ObjTy::OutputLib => Ok(BuildOutput::Library { glob, allow_data }),
            ObjTy::OutputData => Ok(BuildOutput::Data {
                glob,
                allow_executable,
            }),
            ObjTy::OutputBin => Ok(BuildOutput::Binary {
                glob,
                allow_missing_interpreter,
            }),
            _ => Err(Error::UnexpectedObject {
                files: program.files(),
                got: ty,
                want: ObjTy::OutputLib,
                pos: rt.pos(program.pos_table()),
            }),
        }
    }
}

/// A runtime dependency declared on a build-spec.
///
/// Each entry in a build-spec's `runtime_deps` array corresponds to one [RuntimeDep].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
        rt: &NickelValue,
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
                pos: rt.pos(program.pos_table()),
            }),
        }
    }
}

/// Some task or build in the dependency graph.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct BuildDecl {
    /// The human-readable name declared on the build decl.
    pub name: String,
    /// The system this build-decl is meant to run on.
    ///
    /// `None` means the build-decl did not explicitly declare a target and should
    /// be hydrated with the target of whatever graph is being constructed from it.
    /// This happens at the decode→graph seam in `graph::BuildSpec::from_decoded`,
    /// which consults `Loader::for_target`. Moved from eager to deferred to fix
    /// an arm64 dispatch bug where the target was resolved before it was known.
    pub target: Option<Target>,
    /// Any attributes explicitly set on this build-decl.
    pub attrs: Option<IndexMap<String, AttrValue>>,
    /// Marker that this build-spec is a prebuilt, meaning:
    ///  - No cmds may be defined.
    ///  - build_deps must consist of a single source input.
    pub prebuilt: bool,

    /// The build commands declared on the build spec.
    pub cmds: Vec<Vec<String>>,
    /// Any arguments to the build command, ultimately passed as environment variables.
    pub build_args: Option<IndexMap<String, String>>,

    /// The dependencies needed to execute the build spec.
    pub build_deps: SmallVec<[BuildDep; 10]>,
    /// The dependencies needed to run outputs of this build spec, as well as possibly needed
    /// during the build.
    pub runtime_deps: SmallVec<[RuntimeDep; 8]>,
    /// Any needs explicitly set on this build-decl.
    pub abstract_deps: Option<IndexMap<String, AttrValue>>,
    /// The named outputs (and match patterns) produced by executing this build spec.
    pub outputs: OutputMap,

    /// An alternative build spec to use to break cycles in resolving dependencies on this build spec.
    pub replace_on_cycle: Option<BuildRef>,

    /// Unit tests declared on this build spec.
    pub tests: Option<IndexMap<String, crate::Test>>,
}

impl BuildDecl {
    /// Returns true if the build-spec represents a rollup of runtime_deps but no substance or computation of its own.
    pub fn is_pure_collection(&self) -> bool {
        self.build_deps.is_empty()
            && (self.cmds.is_empty() || (self.cmds.len() == 1 && self.cmds[0][0].is_empty()))
    }
}

impl BuildDecl {
    pub(crate) fn from_term<A: super::DeclAccumulator>(
        rt: &NickelValue,
        program: &mut Program<CacheImpl>,
        acc: &mut A,
    ) -> Result<Self, Error> {
        let rt = eval_if_closure(rt, program)?;

        // Read out the attributes
        let mut name: Option<String> = None;
        let mut cmds: Option<Vec<Vec<String>>> = None;
        let mut ty: Option<ObjTy> = None;
        let mut target: Option<Target> = None;
        let mut build_args: Option<IndexMap<String, String>> = None;
        let mut build_deps: Option<SmallVec<[BuildDep; 10]>> = None;
        let mut runtime_deps: Option<SmallVec<[RuntimeDep; 8]>> = None;
        let mut needs: Option<IndexMap<String, AttrValue>> = None;
        let mut outputs: Option<OutputMap> = None;
        let mut replace_on_cycle: Option<BuildRef> = None;
        let mut attrs: Option<IndexMap<String, AttrValue>> = None;
        let mut prebuilt: Option<bool> = None;
        let mut tests: Option<IndexMap<String, crate::Test>> = None;
        if let Some(r) = crate::record_data_from_val(&rt) {
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
                        "prebuilt" => {
                            if let Some(rt) = field.value.as_ref() {
                            prebuilt = Some(
                                bool::deserialize(eval_if_closure(
                                    rt,
                                    program,
                                )?)
                                .unwrap(),
                            );
                            }
                            Ok(())
                        }
                        "cmd" => {
                            if let Some(rt) = field.value.as_ref() {
                                cmds = Some(cmds_from_cmd_term(rt, program)?);
                            };
                            Ok(())
                        }
                        "cmds" => {
                            if let Some(rt) = field.value.as_ref() {
                                cmds = Some(cmds_from_cmds_term(rt, program)?);
                            };
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
                                match target_str.parse::<Target>() {
                                    Ok(t) => {
                                        target = Some(t);
                                        Ok(())
                                    }
                                    Err(_) => Err(Error::InvalidTarget { files: program.files(), got: target_str, pos: rt.pos(program.pos_table()) }),
                                }
                            } else {
                                Ok(())
                            }
                        }
                        "build_args" => {
                            if let Some(build_args_rt) = field.value.as_ref() {
                                let build_args_rt =
                                    eval_if_closure(build_args_rt, program)?;

                                if let Some(r) = crate::record_data_from_val(&build_args_rt) {
                                    build_args = Some(r.fields.iter().map(
                                        |(ident_and_loc, field)| -> Result<(String, String), Error> {
                                            if field.value.is_none() {
                                                // TODO: This should be a more customized error, missing
                                                // field with the pretty print will probably get the message
                                                // across, but its not super precise.
                                                return Err(Error::MissingField{
                                                    field: "build_args",
                                                    files: program.files(),
                                                    obj: ObjTy::Builder,
                                                    pos: ident_and_loc.pos,
                                                });
                                            }

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
                                } else if crate::is_record(&build_args_rt) {
                                    build_args = Some(Default::default());
                                } else {
                                    todo!("unexpected term for build_args");
                                }
                            }

                            Ok(())
                        }
                        "build_deps" => {
                            let build_deps_rt = field
                                .value
                                .as_ref()
                                .map(|rt| eval_if_closure(rt, program))
                                .ok_or_else(|| Error::MissingField {
                                    files: program.files(),
                                    obj: ObjTy::Builder,
                                    pos: rt.pos(program.pos_table()),
                                    field: "build_deps",
                                })??;
                            if let Some(a) = build_deps_rt.as_array() {
                                build_deps = Some(
                                    a.iter()
                                        .map(|input| BuildDep::from_term(input, program, acc))
                                        .collect::<Result<SmallVec<_>, Error>>()?,
                                );
                            } else {
                                todo!("handle build_deps value being non-array {:?}", field.value);
                            };
                            Ok(())
                        }
                        "runtime_deps" => {
                            let runtime_deps_rt =
                                field.value.as_ref().map(|rt| eval_if_closure(rt, program));
                            match runtime_deps_rt {
                                None => {}
                                Some(runtime_deps_rt) => {
                                    let runtime_deps_val = runtime_deps_rt?;
                                    if let Some(a) = runtime_deps_val.as_array() {
                                        runtime_deps = Some(
                                            a.iter()
                                                .map(|input| {
                                                    RuntimeDep::from_term(input, program, acc)
                                                })
                                                .collect::<Result<SmallVec<_>, Error>>()?,
                                        );
                                    } else {
                                        todo!(
                                            "handle runtime_deps value being non-array {:?}",
                                            field.value
                                        );
                                    }
                                }
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
                                    pos: rt.pos(program.pos_table()),
                                    field: "outputs",
                                })??;

                            if let Some(r) = crate::record_data_from_val(&outputs_rt) {
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
                            } else if crate::is_record(&outputs_rt) {
                                // Empty record - no outputs
                                outputs = Some(Default::default());
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

                                if let Some(r) = crate::record_data_from_val(&attrs_rt) {
                                    attrs = Some(r.fields.iter().map(
                                        |(ident_and_loc, field)| -> Result<Option<(String, AttrValue)>, Error> {
                                            if let Some(rt) = field.value.as_ref() {
                                                let rt = RuntimeContract::apply_all(
                                                    rt.clone(),
                                                    field.pending_contracts.iter().cloned(),
                                                    rt.pos_idx(),
                                                );

                                                let value = AttrValue::from_term(
                                                    &rt,
                                                    program,
                                                )?;
                                                match value {
                                                    Some(v) => Ok(Some((
                                                        ident_and_loc.label().to_string(),
                                                        v,
                                                    ))),
                                                    None => Ok(None),
                                                }
                                            } else {
                                                Ok(None)
                                            }
                                        },
                                    ).collect::<Result<Vec<_>, Error>>()?
                                    .into_iter()
                                    .flatten()
                                    .collect());
                                } else if crate::is_record(&attrs_rt) {
                                    attrs = Some(Default::default());
                                } else {
                                    todo!("unexpected term for attrs: {:?}", attrs_rt);
                                }
                            }

                            Ok(())
                        }
                        "needs" => {
                            if let Some(needs_rt) = field.value.as_ref() {
                                let needs_rt =
                                    eval_if_closure(needs_rt, program)?;

                                if let Some(r) = crate::record_data_from_val(&needs_rt) {
                                    needs = Some(r.fields.iter().map(
                                        |(ident_and_loc, field)| -> Result<Option<(String, AttrValue)>, Error> {
                                            let value = AttrValue::from_term(
                                                field.value.as_ref().unwrap(),
                                                program,
                                            )?;
                                            match value {
                                                Some(v) => Ok(Some((
                                                    ident_and_loc.label().to_string(),
                                                    v,
                                                ))),
                                                None => Ok(None),
                                            }
                                        },
                                    ).collect::<Result<Vec<_>, Error>>()?
                                    .into_iter()
                                    .flatten()
                                    .collect());
                                } else if crate::is_record(&needs_rt) {
                                    needs = Some(Default::default());
                                } else {
                                    todo!("unexpected term for needs: {:?}", needs_rt);
                                }
                            }

                            Ok(())
                        }
                        "tests" => {
                            if let Some(tests_res) = field
                                .value
                                .as_ref()
                                .map(|rt| eval_if_closure(rt, program)) {
                                    let tests_rt = tests_res?;

                                    if let Some(r) = crate::record_data_from_val(&tests_rt) {
                                        tests = Some(
                                            r.iter_serializable()
                                                .map(|entry| entry.unwrap())
                                                .map(|(ident, val)| {
                                                    Ok((
                                                        ident.label().to_string(),
                                                        crate::Test::from_term(val, program, acc)?,
                                                    ))
                                                })
                                                .collect::<Result<_, Error>>()?,
                                        );
                                    } else if crate::is_record(&tests_rt) {
                                        // Empty record - no tests
                                        tests = Some(Default::default());
                                    } else {
                                        todo!("handle value being non-dict {:?}", field.value);
                                    };
                                }
                            Ok(())
                        }
                        _ => Ok(()), // TODO: Should we error if we see an unknown field?
                    }
                })?;
        }
        match ty {
            Some(ObjTy::Builder) => {} // happy path
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
                    want: ObjTy::Builder,
                    pos: rt.pos(program.pos_table()),
                });
            }
        }
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
        let prebuilt = prebuilt.unwrap_or_default();
        let cmds = cmds.unwrap_or_default();
        let build_deps = match build_deps {
            Some(build_deps) => build_deps,
            None => {
                return Err(Error::MissingField {
                    files: program.files(),
                    obj: ObjTy::Builder,
                    pos: rt.pos(program.pos_table()),
                    field: "build_deps",
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
                    pos: rt.pos(program.pos_table()),
                    field: "outputs",
                });
            }
        };
        let runtime_deps = runtime_deps.unwrap_or_default();

        // Validate our magic prebuilt-marked decls
        if prebuilt {
            if let [BuildDep::Source(_)] = build_deps.as_slice() {
                if !cmds.is_empty() {
                    return Err(Error::Other(
                        "prebuilt decls must not declare commands to execute".to_string(),
                    ));
                }
                if replace_on_cycle.is_some() {
                    return Err(Error::Other(
                        "prebuilt decls must not set replace_on_cycle".to_string(),
                    ));
                }
            } else {
                return Err(Error::Other(
                    "prebuilt decls must have a single source input".to_string(),
                ));
            }
        }

        Ok(Self {
            name,
            cmds,
            attrs,
            prebuilt,
            build_args,
            target,
            build_deps,
            runtime_deps,
            abstract_deps: needs,
            outputs,
            replace_on_cycle,
            tests,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Test, load::*};
    use common::target::{Arch, OS};
    use indoc::indoc;

    #[test]
    fn source_input() {
        let (term, mut program, _origin, _target) = Loader::new(
            indoc! {
                "
                let {Source, ..} = import \"minimal.ncl\" in
                {url = \"http://uwu.com\", sha256 = \"abcdef\", extract = true} | Source
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

        let source = BuildDep::from_term(&term, &mut program, &mut ()).unwrap();

        assert!(matches!(
            source,
            BuildDep::Source( SourceInput {
                from: SourceFetch::Web{url, sha256: sha, sha256_pos: _, url_pos: _},
                extract: true,
                strip_prefix: None,
            }) if url == "http://uwu.com" && sha == "abcdef",
        ));
    }

    #[test]
    fn local_input() {
        let path = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("testdata/local_input.ncl");

        let (term, mut program, _origin, _target) = Loader::new(
            format!("import \"{}\"", path.to_str().unwrap()),
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

        let source = BuildDep::from_term(&term, &mut program, &mut ()).unwrap();

        assert!(matches!(
            source,
            BuildDep::Local{ full_path, .. } if full_path.ends_with("testdata/local_input.txt"),
        ));
    }

    #[test]
    fn subset_input() {
        let (term, mut program, _origin, _target) = Loader::new(
            indoc! {
                "
                let {Subset, BuildSpec, OutputData, ..} = import \"minimal.ncl\" in
                {from = {
                    name = \"speccy\",
                    build_deps = [],
                    cmd = \"\",
                    outputs = {
                        abc = {glob=\"\"} | OutputData,
                        uwu = {glob=\"\"} | OutputData,
                    },
                } | BuildSpec, outputs = [\"uwu\", \"abc\"]} | Subset
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

        let source = BuildDep::from_term(&term, &mut program, &mut ()).unwrap();

        assert!(matches!(
            source,
            BuildDep::Subset(SubsetInput { from: BuildRef::Local { name, .. }, outputs }) if name == "speccy" && outputs.to_vec() == vec!["abc", "uwu"],
        ));
    }

    #[test]
    fn build_simple() {
        let (term, mut program, _origin, _target) = Loader::new(
            indoc! {
                "
                let {BuildSpec, OutputLib, ..} = import \"minimal.ncl\" in
                {
        			name = \"single buildspec\",
        			build_deps = [],
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
                cmds,
                prebuilt: false,
                attrs: _,
                build_args,
                build_deps: _,
                runtime_deps: _,
                abstract_deps: _,
                outputs,
                replace_on_cycle,
                tests: None,
            } if name == "single buildspec" &&
                target.is_none() &&
                cmds == vec![vec!["./build.sh"]] &&
                replace_on_cycle.is_none() &&
                build_args == Some([("fish".to_string(), "swiggity swooty".to_string())].into()) &&
                outputs == [("something".to_string(), BuildOutput::Library{ glob: "/usr/lib/something.*.so".to_string(), allow_data: false})].into(),
        ));
    }

    #[test]
    fn build_cmd_as_array() {
        let (term, mut program, _origin, _target) = Loader::new(
            indoc! {
                "
                let {BuildSpec, OutputLib, ..} = import \"minimal.ncl\" in
                {
        			name = \"simple\",
        			build_deps = [],
        			cmd = [\"bash\", \"-c\", \"echo uwu\"],
        		} | BuildSpec"
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

        let build = BuildDecl::from_term(&term, &mut program, &mut ()).unwrap();

        assert!(matches!(
            build,
            BuildDecl {cmds, .. } if
                cmds == vec![vec!["bash", "-c", "echo uwu"]]
        ));
    }
    #[test]
    fn build_cmds() {
        let (term, mut program, _origin, _target) = Loader::new(
            indoc! {
                "
                let {BuildSpec, OutputLib, ..} = import \"minimal.ncl\" in
                {
        			name = \"simple\",
        			build_deps = [],
        			cmds = [
                        [\"bash\", \"-c\", \"echo uwu\"],
                        \"/bin/pip3 wheel -w dist --no-build-isolation --no-deps --no-cache-dir ./\",
                    ],
        		} | BuildSpec"
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

        let build = BuildDecl::from_term(&term, &mut program, &mut ()).unwrap();

        assert!(matches!(
            build,
            BuildDecl {cmds, .. } if
                cmds == vec![
                    vec!["bash", "-c", "echo uwu"],
                    vec!["/bin/pip3", "wheel", "-w", "dist", "--no-build-isolation", "--no-deps", "--no-cache-dir", "./"],
                ]
        ));
    }
    #[test]
    fn build_tests() {
        let (term, mut program, _origin, _target) = Loader::new(
            indoc! {
                "
                let {standaloneTest, BuildSpec, ..} = import \"minimal.ncl\" in
                {
        			name = \"simple\",
        			build_deps = [],
                    tests.uwu = standaloneTest \"/usr/bin/yes\",
        		} | BuildSpec"
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

        let build = BuildDecl::from_term(&term, &mut program, &mut ()).unwrap();

        assert!(
            matches!(build, BuildDecl { tests, .. } if tests == Some([("uwu".to_string(),
            Test{
                build_test: false,
                deps: None,
                cmds: vec![vec!["/usr/bin/yes".to_string()]],
            })].into()),)
        );
    }

    #[test]
    fn parse_target() {
        let (term, mut program, _origin, _target) = Loader::new(
            indoc! {
                "
                let {BuildSpec, OutputLib, ..} = import \"minimal.ncl\" in
                {
        			name = \"buildspec\",
                    build_deps = [],
        			cmd = \"./build.sh\",
                    target = \"arm64/macos\",
        		} | BuildSpec"
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

        let build = BuildDecl::from_term(&term, &mut program, &mut ()).unwrap();

        assert_eq!(build.target, Some(Target::new(Arch::Arm64, OS::MacOS)),);
    }

    #[test]
    fn outputs() {
        let (term, mut program, _origin, _target) = Loader::new(
            indoc! {
                "
                let {OutputLib, OutputData, OutputBin, ..} = import \"minimal.ncl\" in
                [
                    { glob = \"/usr/lib/something.*.so\", allow_data = true } | OutputLib,
                    { glob = \"/bin/uwu\" } | OutputBin,
                    { glob = \"/data/locale/*\"  } | OutputData,
                ]
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

        let (o_lib, o_bin, o_data) = if let Some(a) = term.as_array() {
            (
                BuildOutput::from_term(a.get(0).unwrap(), &mut program).unwrap(),
                BuildOutput::from_term(a.get(1).unwrap(), &mut program).unwrap(),
                BuildOutput::from_term(a.get(2).unwrap(), &mut program).unwrap(),
            )
        } else {
            unreachable!()
        };

        // We expect that buildspec to have one Library output
        assert_eq!(
            o_lib,
            BuildOutput::Library {
                glob: "/usr/lib/something.*.so".to_string(),
                allow_data: true,
            },
        );
        // We expect that buildspec to have one Binary output
        assert_eq!(
            o_bin,
            BuildOutput::Binary {
                glob: "/bin/uwu".to_string(),
                allow_missing_interpreter: false,
            },
        );
        // We expect that buildspec to have one Data output
        assert_eq!(
            o_data,
            BuildOutput::Data {
                glob: "/data/locale/*".to_string(),
                allow_executable: false,
            },
        );
    }

    #[test]
    fn parse_attrs() {
        let (term, mut program, _origin, _target) = Loader::new(
            indoc! {
                "
                let {Attrs, BuildSpec, ..} = import \"minimal.ncl\" in
                {
        			name = \"buildspec\",
                    build_deps = [],
        			cmd = \"./build.sh\",
                    attrs = {
                      upstream_version = \"1.2.3\",
                    } | Attrs,
        		} | BuildSpec"
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

        let attrs = BuildDecl::from_term(&term, &mut program, &mut ())
            .unwrap()
            .attrs
            .unwrap();
        assert_eq!(attrs.len(), 1);
        assert!(matches!(
            attrs.get("upstream_version").unwrap(),
            AttrValue::String(v, _) if v == "1.2.3"
        ));
    }

    #[test]
    fn parse_needs() {
        let (term, mut program, _origin, _target) = Loader::new(
            indoc! {
                "
                let {Needs, BuildSpec, ..} = import \"minimal.ncl\" in
                {
        			name = \"buildspec\",
                    build_deps = [],
        			cmd = \"./build.sh\",
                    needs = {
                      dns = {},
                    } | Needs,
        		} | BuildSpec"
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
        let (term, mut program, _origin, _target) = Loader::new(
            indoc! {
                "
                let {upstream, BuildSpec, OutputLib, ..} = import \"minimal.ncl\" in
                {
        			name = \"single buildspec\",
        			build_deps = [upstream \"upstream-pkg\"],
        			cmd = \"./build.sh\",
        		} | BuildSpec"
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

        let build = BuildDecl::from_term(&term, &mut program, &mut ()).unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("from_term failed");
        });

        assert_eq!(
            build.build_deps[0],
            BuildDep::Build(BuildRef::Upstream {
                name: "upstream-pkg".to_string()
            })
        );
    }

    #[test]
    fn parse_subset_of_upstream() {
        let (term, mut program, _origin, _target) = Loader::new(
            indoc! {
                "
                let {subsetOf, upstream, BuildSpec, OutputLib, ..} = import \"minimal.ncl\" in
                {
        			name = \"single buildspec\",
        			build_deps = [subsetOf (upstream \"upstream-pkg\") [\"libgcc\"]],
        			runtime_deps = [subsetOf (upstream \"upstream-pkg\") [\"libgcc\"]],
        			cmd = \"./build.sh\",
        		} | BuildSpec"
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

        let build = BuildDecl::from_term(&term, &mut program, &mut ()).unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("from_term failed");
        });

        assert_eq!(
            build.build_deps[0],
            BuildDep::Subset(SubsetInput {
                from: BuildRef::Upstream {
                    name: "upstream-pkg".to_string()
                },
                outputs: vec!["libgcc".to_string()].into()
            })
        );
        assert_eq!(
            build.runtime_deps[0],
            RuntimeDep::Subset(SubsetInput {
                from: BuildRef::Upstream {
                    name: "upstream-pkg".to_string()
                },
                outputs: vec!["libgcc".to_string()].into()
            })
        );
    }
}
