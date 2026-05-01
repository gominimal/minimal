use crate::error::Error;
use std::path::PathBuf;

/// Describes how to find an MFile
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MFileSearchStrategy {
    // Only look at a specific path, if there is no mfile there,
    // we do not find one
    Override(PathBuf),
    /// Try the current directory first, if there is no mfile there,
    /// we do not find one
    CurrentDirOnly,
    /// Start in the current directory and recurse the ancestor directories until we find an mfile
    CurrentDirRecursive,
}

impl MFileSearchStrategy {
    /// Find the mfile according to the strategy
    pub fn find_mfile(&self) -> Result<mfile::File, Error> {
        match self {
            Self::Override(path) => mfile::File::from_dir(path).map_err(|e| e.into()),
            Self::CurrentDirOnly => {
                let current_dir = std::env::current_dir()
                    .map_err(|e| Error::IO("Getting current directory", PathBuf::new(), e))?;
                mfile::File::from_dir(current_dir).map_err(Error::MFile)
            }
            Self::CurrentDirRecursive => {
                let current_dir = std::env::current_dir()
                    .map_err(|e| Error::IO("Getting current directory", PathBuf::new(), e))?;
                mfile::File::from_dir_recursive(current_dir).map_err(Error::MFile)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::path::Path;

    /// Restore the current working directory automatically when dropped
    struct DirGuard(std::path::PathBuf);

    impl DirGuard {
        fn new() -> Self {
            Self(std::env::current_dir().unwrap())
        }
    }

    impl Drop for DirGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.0);
        }
    }

    fn cargo_manifest_dir() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
    }

    fn testdata() -> PathBuf {
        cargo_manifest_dir().join("testdata")
    }

    fn fakerepo() -> PathBuf {
        testdata().join("fakerepo")
    }

    fn uninitialized_repo() -> PathBuf {
        testdata().join("fake-ancestor").join("uninitialized-repo")
    }

    #[test]
    fn mfile_search_strategy_override() {
        // Case: Override path has an mfile
        let strategy = MFileSearchStrategy::Override(fakerepo());
        let mfile = strategy.find_mfile().unwrap();
        assert_eq!(*mfile.file_path().unwrap(), fakerepo().join("minimal.toml"));

        // Case: Override path doesn't exist
        let strategy = MFileSearchStrategy::Override(
            testdata().join("pleasedontcreateadirectorywiththisname"),
        );
        assert!(strategy.find_mfile().is_err());

        // Case: Override path exists but has no mfile
        let strategy = MFileSearchStrategy::Override(uninitialized_repo());
        assert!(strategy.find_mfile().is_err());
    }

    #[test]
    #[serial] // Any test that sets CWD must be serial to avoid race conditions
    fn mfile_search_strategy_current_dir_only() {
        let _guard = DirGuard::new();
        let strategy = MFileSearchStrategy::CurrentDirOnly;

        // Case: Current directory has an mfile
        std::env::set_current_dir(fakerepo()).unwrap();
        let mfile = strategy.find_mfile().unwrap();
        assert_eq!(*mfile.file_path().unwrap(), fakerepo().join("minimal.toml"));

        // Case: Current directory does not have an mfile (and ancestor does)
        std::env::set_current_dir(uninitialized_repo()).unwrap();
        assert!(strategy.find_mfile().is_err());
    }

    #[test]
    #[serial] // Any test that sets CWD must be serial to avoid race conditions
    fn mfile_search_strategy_current_dir_recursive() {
        let _guard = DirGuard::new();
        let strategy = MFileSearchStrategy::CurrentDirRecursive;

        // Case: Current directory has an mfile
        std::env::set_current_dir(fakerepo()).unwrap();
        let mfile = strategy.find_mfile().unwrap();
        assert_eq!(*mfile.file_path().unwrap(), fakerepo().join("minimal.toml"));

        // Case: Current directory doesn't have an mfile but an ancestor does
        std::env::set_current_dir(uninitialized_repo()).unwrap();
        let mfile = strategy.find_mfile().unwrap();
        assert_eq!(
            *mfile.file_path().unwrap(),
            testdata().join("fake-ancestor").join("minimal.toml")
        );
    }
}
