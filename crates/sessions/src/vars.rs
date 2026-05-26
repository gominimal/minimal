#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum Var {
    Inherit,
    InheritWithDefault { default: String },
    Specified { value: String },
}
