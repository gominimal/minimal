use blake3::Hasher;
use std::io::Write;

/// A supported CPU architecture.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Arch {
    #[default]
    Amd64,
    Arm64,
}

/// A supported OS.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum OS {
    #[default]
    Linux,
    MacOS,
}

/// The description of a system where software runs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
