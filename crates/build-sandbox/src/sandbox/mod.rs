use std::process::Command;

use crate::config::BuildConfig;
use crate::error::Result;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
mod linux;

pub trait Sandbox {
    fn create_instance(config: &BuildConfig) -> Result<Box<dyn Sandbox>>
    where
        Self: Sized;

    fn execute(&self, command: &mut Command) -> Result<()>;

    fn cleanup(&mut self) -> Result<()>;
}

#[cfg(target_os = "macos")]
pub fn create_sandbox(config: &BuildConfig) -> Result<Box<dyn Sandbox>> {
    macos::MacOSSandbox::create_instance(config)
}

#[cfg(target_os = "linux")]
pub fn create_sandbox(config: &BuildConfig) -> Result<Box<dyn Sandbox>> {
    linux::LinuxSandbox::create_instance(config)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn create_sandbox(_config: &BuildConfig) -> Result<Box<dyn Sandbox>> {
    use crate::error::SandboxError;
    Err(SandboxError::UnsupportedPlatform.into())
}
