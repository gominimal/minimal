use std::collections::BTreeMap;

use crate::lifecyclehook::LifecycleHook;
use crate::vars::Var;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Loadout {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    vars: BTreeMap<String, Var>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    lifecycle_hooks: Vec<LifecycleHook>,
    // #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
}
