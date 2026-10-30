//! The name a front-end puts on a create (BOX-163). A front-end invents no
//! name: the daemon names the box with its spec's `[box] name`, else its
//! entry's name. The request carries a name only when the person typed one
//! (`min session activate --name`, or the `min dash` form). Shared by the
//! `min` CLI and `min dash`, so either side names a box the same way.

use minimald_rpc::HeldNameRefusal;

/// The name a create request carries: the one the person typed, or none.
/// With none, the daemon names the box from its spec. A front-end never
/// mints a `<dir>-<hex>` name in its place.
pub fn request_name(typed: Option<&str>) -> Option<String> {
    typed.map(str::to_string)
}

/// The holder named by a create's refusal, when a running box holds the
/// name the create asked for (BOX-163).
pub fn held_name_refusal(error: &str) -> Option<HeldNameRefusal> {
    HeldNameRefusal::from_error(error)
}

/// Whether a refused create runs again as a fresh instance (BOX-163): only
/// a create whose name the person did not type, and only when a running box
/// holds the name the daemon gave it. The daemon then names it
/// `<name>-<n>`. A typed name is never changed: its refusal ends the
/// command, naming the holder.
pub fn retry_as_fresh_instance(typed: bool, fresh_instance: bool, error: &str) -> bool {
    !typed && !fresh_instance && held_name_refusal(error).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal() -> String {
        HeldNameRefusal {
            name: "default".to_string(),
            holder: boxes::SessionId::parse_str("0192f3c4-5d6e-7f80-9a1b-2c3d4e5f6a7b").unwrap(),
            holder_name: "default".to_string(),
        }
        .to_string()
    }

    /// BOX-163: a create with no typed name carries no name, so the daemon
    /// names the box from its entry. Nothing mints `<dir>-<hex>`.
    #[test]
    fn no_invented_directory_hex_name() {
        assert_eq!(request_name(None), None, "no typed name, no name sent");
        assert_eq!(request_name(Some("dev")).as_deref(), Some("dev"));

        // A held name retries as a fresh instance only when nobody typed it.
        let held = refusal();
        assert!(retry_as_fresh_instance(false, false, &held));
        assert!(
            !retry_as_fresh_instance(true, false, &held),
            "a typed name is refused, never renamed"
        );
        assert!(
            !retry_as_fresh_instance(false, true, &held),
            "a fresh instance is not refused for a held name, so it never retries"
        );
        assert!(!retry_as_fresh_instance(
            false,
            false,
            "CreateSession failed: boom"
        ));
        assert!(!retry_as_fresh_instance(
            false,
            false,
            "A session with that name already exists"
        ));
    }
}
