#![allow(dead_code)]

use std::path::{Path, PathBuf};

use crate::{BuildConfig, error::Result};

#[derive(Debug)]
pub struct BuildExecutor {
    build_workspace_dir: PathBuf,
}
impl BuildExecutor {
    pub fn new(_: PathBuf, _: String) -> Result<Self> {
        todo!()
    }

    pub async fn execute(
        &self,
        _: &BuildConfig,
        _: &str,
    ) -> Result<i32> {
        todo!()
    }

    pub fn build_workspace_dir(&self) -> &Path {
        todo!()
    }

    pub fn output_staging_dir(&self) -> PathBuf {
        todo!()
    }

    fn hardlink_to_tmpdir(&self, _: &Path) -> Result<()> {
        todo!()
    }

    async fn execute_in_container(
        &self,
        _: &BuildConfig,
        _: &str,
    ) -> Result<()> {
        todo!()
    }

    fn prepare_rootfs(&self, _: &BuildConfig) -> Result<PathBuf> {
        todo!()
    }
}

fn hardlink_dir_contents(_: &Path, _: &Path) -> Result<()> {
    todo!()
}
