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
    Subset,
}
