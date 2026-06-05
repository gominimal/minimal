//! Direct wrapper around the Linux `renameat2(2)` syscall.
//!
//! Unlike `rename(2)`, `renameat2` accepts flags such as `RENAME_EXCHANGE`
//! that atomically swap two paths — useful for cache finalization where the
//! existing entry must be replaced without ever leaving the destination empty.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

#[cfg(target_arch = "x86_64")]
const SYS_RENAMEAT2: i64 = 316;

#[cfg(target_arch = "aarch64")]
const SYS_RENAMEAT2: i64 = 276;

/// Special value used as a directory fd to indicate the current working directory.
pub const AT_FDCWD: i32 = -100;

/// Flag for `renameat2`: don't overwrite the target.
pub const RENAME_NOREPLACE: u32 = 1 << 0;
/// Flag for `renameat2`: atomically exchange the two paths.
pub const RENAME_EXCHANGE: u32 = 1 << 1;
/// Flag for `renameat2`: create a whiteout object at the source.
pub const RENAME_WHITEOUT: u32 = 1 << 2;

/// Invokes the `renameat2(2)` syscall directly.
pub fn renameat2<P: AsRef<Path>>(
    olddirfd: i32,
    oldpath: P,
    newdirfd: i32,
    newpath: P,
    flags: u32,
) -> io::Result<()> {
    let oldpath_c = path_to_cstring(oldpath.as_ref())?;
    let newpath_c = path_to_cstring(newpath.as_ref())?;

    // SAFETY: `oldpath_c` and `newpath_c` are owned `CString`s that remain live
    // for the duration of the call, so their `.as_ptr()` values are valid,
    // NUL-terminated C strings. `olddirfd` and `newdirfd` are either real file
    // descriptors supplied by the caller or `AT_FDCWD`, both of which the
    // kernel accepts. `flags` is a `u32` bitmask of the `RENAME_*` constants
    // documented in `renameat2(2)`; unknown bits are rejected by the kernel
    // with `EINVAL` rather than causing UB. The syscall returns `-1` on error
    // (with errno set) or a non-negative value on success, which we inspect
    // immediately below.
    let ret = unsafe {
        libc::syscall(
            SYS_RENAMEAT2,
            olddirfd,
            oldpath_c.as_ptr(),
            newdirfd,
            newpath_c.as_ptr(),
            flags,
        )
    };

    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Convenience wrapper around [`renameat2`] for the common case where both
/// paths are resolved relative to the current working directory.
pub fn renameat2_cwd<P: AsRef<Path>>(oldpath: P, newpath: P, flags: u32) -> io::Result<()> {
    renameat2(AT_FDCWD, oldpath, AT_FDCWD, newpath, flags)
}

fn path_to_cstring(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contained null byte"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_rename_noreplace() {
        let tmp = TempDir::new().unwrap();
        let old = tmp.path().join("old");
        let new = tmp.path().join("new");

        fs::write(&old, "source").unwrap();
        fs::write(&new, "destination").unwrap();

        let err = renameat2_cwd(&old, &new, RENAME_NOREPLACE).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EEXIST));

        assert_eq!(fs::read_to_string(&new).unwrap(), "destination");
        assert_eq!(fs::read_to_string(&old).unwrap(), "source");
    }

    #[test]
    fn test_rename_exchange() {
        let tmp = TempDir::new().unwrap();
        let path1 = tmp.path().join("a");
        let path2 = tmp.path().join("b");

        fs::write(&path1, "content1").unwrap();
        fs::write(&path2, "content2").unwrap();

        renameat2_cwd(&path1, &path2, RENAME_EXCHANGE).unwrap();

        assert_eq!(fs::read_to_string(&path1).unwrap(), "content2");
        assert_eq!(fs::read_to_string(&path2).unwrap(), "content1");
    }
}
