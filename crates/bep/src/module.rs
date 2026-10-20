//! Credential modules: the upstream authorities a module's credential is good
//! for.
//!
//! The GitHub module's v1 host set is Gatehouse §6.10's (Module host sets).
//! A sealed member binds the module's identifier and the version of its host
//! set (BEP-006), so a change to the set is a new version. A member sealed
//! under an old version still opens. The proxy admits it for an authority
//! only when the authority is in both the bound set and the current set.
//!
//! This file carries no deny set. The fixed deny set that the root's name
//! constraints subtract lands with the leaf-certificate work (BEP-013).

use std::fmt;

/// The default HTTPS port. Every v1 module authority carries it, so no
/// plaintext authority exists in any module's host set.
pub const HTTPS_PORT: u16 = 443;

/// One upstream authority: a DNS host name and a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Authority {
    /// The lowercase DNS name, with no trailing dot.
    pub host: &'static str,
    /// The TCP port.
    pub port: u16,
}

impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// A credential module: its identifier, the version of its host set, and
/// the host set itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Module {
    /// The identifier a sealed member binds.
    pub id: &'static str,
    /// The version of `hosts`. A sealed member binds it.
    pub host_set_version: u32,
    /// The authorities a member of this module is good for.
    pub hosts: &'static [Authority],
}

impl Module {
    /// Whether `authority` is in this module's host set.
    #[must_use]
    pub fn admits(&self, authority: &Authority) -> bool {
        self.hosts.contains(authority)
    }
}

/// The GitHub module, host set v1.
pub const GITHUB: Module = Module {
    id: "github",
    host_set_version: 1,
    hosts: &[
        Authority {
            host: "github.com",
            port: HTTPS_PORT,
        },
        Authority {
            host: "api.github.com",
            port: HTTPS_PORT,
        },
        Authority {
            host: "uploads.github.com",
            port: HTTPS_PORT,
        },
        Authority {
            host: "codeload.github.com",
            port: HTTPS_PORT,
        },
    ],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_v1_host_set_is_the_four_github_authorities_at_443() {
        let hosts: Vec<String> = GITHUB.hosts.iter().map(ToString::to_string).collect();
        assert_eq!(
            hosts,
            [
                "github.com:443",
                "api.github.com:443",
                "uploads.github.com:443",
                "codeload.github.com:443",
            ]
        );
        assert_eq!(GITHUB.id, "github");
        assert_eq!(GITHUB.host_set_version, 1);
        assert!(!GITHUB.admits(&Authority {
            host: "api.github.com",
            port: 80
        }));
    }
}
