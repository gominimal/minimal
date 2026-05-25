use std::collections::HashMap;

use crate::lifecyclehook::LifecycleHook;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Loadout {
    env_vars: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    lifecycle_hooks: Vec<LifecycleHook>,
}
