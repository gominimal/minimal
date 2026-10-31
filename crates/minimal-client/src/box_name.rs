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

        // A create under a held name with no typed name is refused, and is
        // never turned into a fresh instance. Only `min task run` asks for
        // one.
        let mut request = minimald_rpc::CreateSessionRequest::new(
            String::new(),
            paths::HostAbsPath::try_new("/home/u/code/foo").unwrap(),
            boxes::NetworkMode::HostNet,
            boxes::BoxPolicy::default(),
        );
        request.config.name = request_name(None);
        assert!(
            !request.fresh_instance,
            "an untyped create does not ask for a fresh instance"
        );
        let held = held_name_refusal(&refusal()).expect("the refusal names the holder");
        assert_eq!(held.holder_name, "default");
        assert!(held_name_refusal("CreateSession failed: boom").is_none());
    }
}
