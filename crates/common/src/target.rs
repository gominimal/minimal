use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::Write;
use std::str::FromStr;

/// A supported CPU architecture.
#[derive(Debug, Clone, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum Arch {
    #[default]
    Amd64,
    Arm64,
}

impl Arch {
    pub fn as_nickel_literal(&self) -> &[u8] {
        match self {
            Arch::Amd64 => b"'Amd64",
            Arch::Arm64 => b"'Arm64",
        }
    }
}

/// Error from parsing an [`Arch`] out of a string the user typed on the
/// command line or in a config file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchParseError {
    input: String,
}

impl fmt::Display for ArchParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unsupported architecture: {}. Use 'amd64' or 'arm64'.",
            self.input
        )
    }
}

impl std::error::Error for ArchParseError {}

impl FromStr for Arch {
    type Err = ArchParseError;

    /// Parse an arch from the strings a user is likely to type on the
    /// command line. Accepts both the Minimal-native names (`amd64`,
    /// `arm64`) and the Rust target-triple forms (`x86_64`, `aarch64`)
    /// so that `uname -m` output works verbatim on both platforms.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "amd64" | "x86_64" => Ok(Arch::Amd64),
            "arm64" | "aarch64" => Ok(Arch::Arm64),
            _ => Err(ArchParseError {
                input: s.to_string(),
            }),
        }
    }
}

/// A supported OS.
#[derive(Debug, Clone, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum OS {
    #[default]
    Linux,
    MacOS,
}

impl OS {
    pub fn as_nickel_literal(&self) -> &[u8] {
        match self {
            OS::Linux => b"'Linux",
            OS::MacOS => b"'MacOS",
        }
    }
}

/// The description of a system where software runs.
#[derive(Debug, Clone, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    arch: Arch,
    os: OS,
}

impl Target {
    /// Creates a new target with the given [Arch] and [OS].
    pub const fn new(arch: Arch, os: OS) -> Self {
        Self { arch, os }
    }
    /// Creates a target matching the host system.
    pub const fn host() -> Self {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            Self {
                arch: Arch::Amd64,
                os: OS::Linux,
            }
        }

        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        {
            Self {
                arch: Arch::Arm64,
                os: OS::Linux,
            }
        }

        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            Self {
                arch: Arch::Arm64,
                os: OS::MacOS,
            }
        }
    }

    /// Writes a description of the target to the given hasher.
    pub fn hash_to(&self, h: &mut Hasher) {
        h.write_all(b"-arch").unwrap();
        match self.arch {
            Arch::Amd64 => h.write_all(b"amd64").unwrap(),
            Arch::Arm64 => h.write_all(b"arm64").unwrap(),
        }

        h.write_all(b"-os").unwrap();
        match self.os {
            OS::Linux => h.write_all(b"linux").unwrap(),
            OS::MacOS => h.write_all(b"macOS").unwrap(),
        }
    }

    /// Enumerates the possible [Target] values.
    pub fn all<'a>() -> &'a [Target] {
        &[
            Target {
                arch: Arch::Amd64,
                os: OS::Linux,
            },
            Target {
                arch: Arch::Amd64,
                os: OS::MacOS,
            },
            Target {
                arch: Arch::Arm64,
                os: OS::Linux,
            },
            Target {
                arch: Arch::Arm64,
                os: OS::MacOS,
            },
        ]
    }

    pub fn arch(&self) -> &Arch {
        &self.arch
    }
    pub fn os(&self) -> &OS {
        &self.os
    }
}

impl AsRef<str> for Target {
    fn as_ref(&self) -> &'static str {
        use {Arch::*, OS::*};
        match (&self.arch, &self.os) {
            (Amd64, Linux) => "amd64/linux",
            (Amd64, MacOS) => "amd64/macos",
            (Arm64, Linux) => "arm64/linux",
            (Arm64, MacOS) => "arm64/macos",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arch_parses_amd64_and_alias() {
        assert_eq!("amd64".parse::<Arch>().unwrap(), Arch::Amd64);
        assert_eq!("x86_64".parse::<Arch>().unwrap(), Arch::Amd64);
    }

    #[test]
    fn arch_parses_arm64_and_alias() {
        assert_eq!("arm64".parse::<Arch>().unwrap(), Arch::Arm64);
        assert_eq!("aarch64".parse::<Arch>().unwrap(), Arch::Arm64);
    }

    #[test]
    fn arch_rejects_unknown_and_names_input() {
        let err = "riscv64".parse::<Arch>().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("riscv64") && msg.contains("'amd64'") && msg.contains("'arm64'"),
            "error should name the bad input and list valid options, got: {msg}",
        );
    }

    #[test]
    fn arch_rejects_case_mismatch() {
        // Case-sensitive — "AMD64" isn't an accepted spelling, users
        // should stick to the lowercase form that matches uname -m /
        // rust target triples.
        assert!("AMD64".parse::<Arch>().is_err());
        assert!("ARM64".parse::<Arch>().is_err());
    }

    #[test]
    fn arch_rejects_empty_string() {
        assert!("".parse::<Arch>().is_err());
    }
}
