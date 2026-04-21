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

/// Error from parsing an [`OS`] out of a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsParseError {
    input: String,
}

impl fmt::Display for OsParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unsupported OS: {}. Use 'linux' or 'macos'.", self.input)
    }
}

impl std::error::Error for OsParseError {}

impl FromStr for OS {
    type Err = OsParseError;

    /// Parse an OS from the short lowercase strings that appear in
    /// `Target::as_ref()` output and that consumers (build.ncl target
    /// expressions, CLI args) type by hand.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "linux" => Ok(OS::Linux),
            "macos" => Ok(OS::MacOS),
            _ => Err(OsParseError {
                input: s.to_string(),
            }),
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

/// Error from parsing a [`Target`] out of an `<arch>/<os>` string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetParseError {
    /// The string didn't match the required `<arch>/<os>` shape.
    Shape(String),
    /// The arch segment didn't parse.
    Arch(ArchParseError),
    /// The OS segment didn't parse.
    Os(OsParseError),
}

impl fmt::Display for TargetParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetParseError::Shape(s) => write!(
                f,
                "target {s:?} is not in the expected <arch>/<os> form (e.g. 'amd64/linux')"
            ),
            TargetParseError::Arch(e) => write!(f, "target: {e}"),
            TargetParseError::Os(e) => write!(f, "target: {e}"),
        }
    }
}

impl std::error::Error for TargetParseError {}

impl FromStr for Target {
    type Err = TargetParseError;

    /// Parse a [`Target`] from the `<arch>/<os>` string produced by
    /// [`Target::as_ref`] — round-trips with that impl. Arch and OS
    /// parsing delegate to [`Arch::from_str`] / [`OS::from_str`] so the
    /// accepted alias set stays consistent across every consumer.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (arch_str, os_str) = s
            .split_once('/')
            .ok_or_else(|| TargetParseError::Shape(s.to_string()))?;
        let arch = arch_str.parse::<Arch>().map_err(TargetParseError::Arch)?;
        let os = os_str.parse::<OS>().map_err(TargetParseError::Os)?;
        Ok(Target::new(arch, os))
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

    #[test]
    fn os_parses_both_variants() {
        assert_eq!("linux".parse::<OS>().unwrap(), OS::Linux);
        assert_eq!("macos".parse::<OS>().unwrap(), OS::MacOS);
    }

    #[test]
    fn os_rejects_unknown() {
        let err = "freebsd".parse::<OS>().unwrap_err();
        assert!(format!("{err}").contains("freebsd"));
    }

    #[test]
    fn target_roundtrips_with_as_ref() {
        // Every representation in Target::all() must parse back to the
        // same value — keeps as_ref and from_str in lockstep.
        for expected in Target::all() {
            let s: &str = expected.as_ref();
            let parsed: Target = s.parse().expect("every Target::all() must parse");
            assert_eq!(&parsed, expected, "roundtrip failed for {s}");
        }
    }

    #[test]
    fn target_rejects_missing_separator() {
        let err = "amd64linux".parse::<Target>().unwrap_err();
        assert!(matches!(err, TargetParseError::Shape(_)));
    }

    #[test]
    fn target_propagates_arch_error() {
        let err = "riscv64/linux".parse::<Target>().unwrap_err();
        assert!(matches!(err, TargetParseError::Arch(_)));
        assert!(format!("{err}").contains("riscv64"));
    }

    #[test]
    fn target_propagates_os_error() {
        let err = "amd64/freebsd".parse::<Target>().unwrap_err();
        assert!(matches!(err, TargetParseError::Os(_)));
        assert!(format!("{err}").contains("freebsd"));
    }
}
