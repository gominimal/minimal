//! Partial wire datatypes which result from evaluating nickel files.
#[allow(dead_code)]
use serde::Deserialize;

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
}

/// A structure with just the type hint field.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct OnlyObj {
    pub ty: ObjTy,
}

/// The basic attributes of the BuildSpec object, except fields which are recursively processed (i.e. inputs).
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ObjBaseBuildSpec {
    pub name: String,
    pub ty: ObjTy,

    pub cmd: String,
}

/// The HostPath object.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ObjHostPath {
    #[serde(default)]
    pub path: String,
    pub ty: ObjTy,
}

/// The Source object.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ObjSource {
    #[serde(default)]
    pub url: String,
    pub sha256: String,
    pub ty: ObjTy,
}

/// The Local object.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ObjLocal {
    pub ty: ObjTy,
    pub file: String,
}

/// The Prebuilt object.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ObjPrebuilt {
    pub ty: ObjTy,
    pub package: String,
}

/// A library output.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ObjLibraryOutput {
    pub glob: String,
    pub ty: ObjTy,
}

/// A binary output.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ObjBinaryOutput {
    pub path: String,
    pub ty: ObjTy,
}

/// A data output.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ObjDataOutput {
    pub data: String,
    pub ty: ObjTy,
}
