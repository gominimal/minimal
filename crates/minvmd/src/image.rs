//! Kernel and rootfs image resolution.
//!
//! Paths are supplied at runtime via environment variables. When an override is
//! unset, each resolver falls back to the image directory: the first of the
//! minimal data directory (`$XDG_DATA_HOME/minimal`, else
//! `$HOME/.local/share/minimal`) and then each system data directory
//! (`$XDG_DATA_DIRS`, else `/usr/local/share:/usr/share`, each with `minimal/`
//! appended: where a machine-wide package puts the images) that holds every
//! image whose override is unset, so all the defaulted images of one boot come
//! from one directory, one install: a user directory missing a file (an
//! interrupted or older install) is passed over whole, never mixed with the
//! machine's copy. [`resolve_boot_images`] selects that directory once for
//! the three images of a boot. A default install works with no env setup, a
//! system install serves every user with no per-user copy, and a genuinely
//! missing image still errors rather than silently returning a non-existent
//! path.

use std::path::{Path, PathBuf};

use crate::error::{SearchedDir, VmError};

/// Filenames the installer stamps into the `data/` prefix. Kept in sync with
/// `scripts/stage-release.sh` (`data/vmlinuz`, `data/rootfs.img`,
/// `data/initramfs.cpio`).
const DEFAULT_KERNEL_FILE: &str = "vmlinuz";
const DEFAULT_ROOTFS_FILE: &str = "rootfs.img";
const DEFAULT_INITRAMFS_FILE: &str = "initramfs.cpio";

/// Each guest image's override variable and default file name.
const IMAGES: [(&str, &str); 3] = [
    ("MINVMD_KERNEL_PATH", DEFAULT_KERNEL_FILE),
    ("MINVMD_ROOTFS_PATH", DEFAULT_ROOTFS_FILE),
    ("MINVMD_INITRAMFS", DEFAULT_INITRAMFS_FILE),
];

/// The minimal data directory: `$XDG_DATA_HOME/minimal`, else
/// `$HOME/.local/share/minimal`. Mirrors the installer's `data` prefix
/// resolution in `scripts/install.sh`. `None` when neither `XDG_DATA_HOME` nor
/// `HOME` is set, so no default location can be computed.
fn data_dir() -> Option<PathBuf> {
    data_dir_from(
        std::env::var("XDG_DATA_HOME").ok(),
        std::env::var("HOME").ok(),
    )
}

/// [`data_dir`] from the values of `XDG_DATA_HOME` and `HOME`.
fn data_dir_from(xdg_data_home: Option<String>, home: Option<String>) -> Option<PathBuf> {
    if let Some(xdg) = xdg_data_home.filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(xdg).join("minimal"));
    }
    home.filter(|v| !v.is_empty())
        .map(|home| PathBuf::from(home).join(".local/share/minimal"))
}

/// System data directories, each with `minimal/` appended: `$XDG_DATA_DIRS`
/// (colon-separated), else `/usr/local/share:/usr/share` (the XDG base
/// directory default). A machine-wide install puts the images here:
/// `/usr/local/share/minimal` on macOS, `/usr/share/minimal` for a Linux
/// package. Looked at after the user's own data directory, so a user's copy
/// wins over the machine's.
fn system_data_dirs() -> Vec<PathBuf> {
    let dirs = std::env::var("XDG_DATA_DIRS")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "/usr/local/share:/usr/share".to_owned());
    // A relative entry is ignored, as the XDG specification says: it would
    // name a directory under whatever the daemon's working directory is.
    dirs.split(':')
        .filter(|d| d.starts_with('/'))
        .map(|d| PathBuf::from(d).join("minimal"))
        .collect()
}

/// The override in `var` when set and non-empty, used verbatim.
fn override_path(var: &str) -> Option<PathBuf> {
    std::env::var(var)
        .ok()
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// The override of each image, in [`IMAGES`] order: kernel, rootfs, initramfs.
fn overrides() -> [Option<PathBuf>; 3] {
    IMAGES.map(|(var, _)| override_path(var))
}

/// The images whose override is `None` in `overrides`, each with its file:
/// the ones the image directory must hold.
fn unset_images(overrides: &[Option<PathBuf>; 3]) -> Vec<(&'static str, &'static str)> {
    IMAGES
        .iter()
        .zip(overrides)
        .filter(|(_, o)| o.is_none())
        .map(|(image, _)| *image)
        .collect()
}

/// Return the override in `var` when set and non-empty (used verbatim, without
/// an existence check — the caller owns an explicit path). Otherwise return
/// `default_file` in the image directory (see [`select_image_dir`]).
///
/// This selects the directory for one image. A caller that needs more than
/// one image of a boot uses [`resolve_boot_images`], which selects it once.
fn resolve_or_default(var: &'static str, default_file: &str) -> Result<PathBuf, VmError> {
    if let Some(path) = override_path(var) {
        return Ok(path);
    }
    let unset = unset_images(&overrides());
    select_image_dir(var, &unset, data_dir(), system_data_dirs(), Path::is_file)
        .map(|dir| dir.join(default_file))
}

/// The image directory: the first of `user` (the user's data directory, `None`
/// when none resolves) and `system` (the system data directories) that holds,
/// as files by `has_file`, every image in `unset` (each unset override with
/// its file; see the module doc). `has_file` is [`Path::is_file`] outside
/// tests.
///
/// Errors with `VmError::MissingImage`, `var` naming the image being resolved,
/// when no directory holds them all, including when there is no directory to
/// look in (no `XDG_DATA_HOME`, no `HOME` and no absolute `XDG_DATA_DIRS`
/// entry).
fn select_image_dir(
    var: &'static str,
    unset: &[(&'static str, &'static str)],
    user: Option<PathBuf>,
    system: Vec<PathBuf>,
    has_file: impl Fn(&Path) -> bool,
) -> Result<PathBuf, VmError> {
    let mut searched = Vec::new();
    for dir in user.into_iter().chain(system) {
        // `is_file`, not `exists`: a directory that happens to carry an
        // image's name is not the image, and the lookup moves on.
        let missing: Vec<_> = unset
            .iter()
            .map(|(_, file)| *file)
            .filter(|file| !has_file(&dir.join(file)))
            .collect();
        if missing.is_empty() {
            return Ok(dir);
        }
        searched.push(SearchedDir { dir, missing });
    }
    Err(VmError::MissingImage {
        var,
        unset: unset.iter().map(|(v, _)| *v).collect(),
        searched,
    })
}

/// The lookup behind [`resolve_boot_images`], with its inputs passed in: each
/// image's override, then the inputs of [`select_image_dir`]. The directory is
/// selected once, so every defaulted image comes from it even when an install
/// changes the data directories while the boot resolves.
fn resolve_images_in(
    overrides: [Option<PathBuf>; 3],
    user: Option<PathBuf>,
    system: Vec<PathBuf>,
    has_file: impl Fn(&Path) -> bool,
) -> Result<(PathBuf, PathBuf, PathBuf), VmError> {
    let unset = unset_images(&overrides);
    let dir = match unset.first() {
        Some(&(var, _)) => select_image_dir(var, &unset, user, system, has_file)?,
        // Every image has its override, so nothing is joined to the directory
        // and none is needed: a boot with all three overrides set needs no
        // data directory at all.
        None => PathBuf::new(),
    };
    let [kernel, rootfs, initramfs] = overrides;
    let pick = |path: Option<PathBuf>, file: &str| path.unwrap_or_else(|| dir.join(file));
    Ok((
        pick(kernel, DEFAULT_KERNEL_FILE),
        pick(rootfs, DEFAULT_ROOTFS_FILE),
        pick(initramfs, DEFAULT_INITRAMFS_FILE),
    ))
}

/// Arch-appropriate libkrun kernel format.
///
/// - `aarch64`: the kernel is shipped **uncompressed** (`fetch-virtio-kernel.sh`
///   gunzips the upstream `Image.gz`) and loaded with `KernelFormat::Raw`.
///   Loading raw skips libkrun's gzip decompress, which measured ~77 ms (over
///   half of boot-to-READY) versus a `PeGz` `Image.gz`. The aarch64 loader
///   implements only RAW and PE_GZ.
/// - `x86_64`:  `virtio-linux` ships a `bzImage` → `KernelFormat::ImageGz`.
///   A bzImage is a PE/`MZ` container that embeds the `vmlinux` ELF as a
///   gzip member; libkrun's `ImageGz` loader scans for the gzip magic
///   (`1f 8b 08`), inflates that single member, and ELF-loads the result.
///   Loading it as `Elf` directly fails (`krun_start_enter` → EINVAL) because
///   the ELF loader is handed the PE container, not the inner vmlinux.
#[cfg(minvmd_libkrun)]
pub fn kernel_format() -> crate::krun::KernelFormat {
    #[cfg(target_arch = "aarch64")]
    {
        crate::krun::KernelFormat::Raw
    }
    #[cfg(target_arch = "x86_64")]
    {
        crate::krun::KernelFormat::ImageGz
    }
}

/// Resolve the kernel path from `MINVMD_KERNEL_PATH`, falling back to
/// `vmlinuz` in the image directory (the first data directory, the user's then
/// the system ones, that holds every image whose override is unset) when the
/// override is unset or empty.
///
/// Errors with `VmError::MissingImage` when the override is unset and no data
/// directory holds those images, or there is no data directory to look in.
pub fn resolve_kernel_path() -> Result<PathBuf, VmError> {
    resolve_or_default("MINVMD_KERNEL_PATH", DEFAULT_KERNEL_FILE)
}

/// Resolve the rootfs path from `MINVMD_ROOTFS_PATH`, falling back to
/// `rootfs.img` in the image directory (see [`resolve_kernel_path`]) when the
/// override is unset or empty.
///
/// This is the path to a read-only ext4 root disk image (loaded via
/// `krun_add_disk2`), not a directory. Errors with `VmError::MissingImage` as
/// [`resolve_kernel_path`] does.
pub fn resolve_rootfs_path() -> Result<PathBuf, VmError> {
    resolve_or_default("MINVMD_ROOTFS_PATH", DEFAULT_ROOTFS_FILE)
}

/// Resolve the initramfs path from `MINVMD_INITRAMFS`, falling back to
/// `initramfs.cpio` in the image directory (see [`resolve_kernel_path`]) when
/// the override is unset or empty.
///
/// This is the cpio initramfs whose `/init` is minimald (booted as pid-1).
/// Errors with `VmError::MissingImage` as [`resolve_kernel_path`] does.
pub fn resolve_initramfs_path() -> Result<PathBuf, VmError> {
    resolve_or_default("MINVMD_INITRAMFS", DEFAULT_INITRAMFS_FILE)
}

/// Resolve all three boot image paths at once: (kernel, rootfs, initramfs).
///
/// Each override is honoured as its resolver honours it, and the image
/// directory is selected once for the three, so one boot never takes its
/// images from two directories, even when an install finishes the user's copy
/// between two lookups. Errors with `VmError::MissingImage`, `var` naming the
/// first image whose override is unset, when no data directory holds them.
/// Used by the VMM child for the images it boots, by `minvmd run` and `boot`
/// to fail fast and log them, and by tests that prove a fresh install resolves
/// its payload with no overrides.
pub fn resolve_boot_images() -> Result<(PathBuf, PathBuf, PathBuf), VmError> {
    resolve_images_in(overrides(), data_dir(), system_data_dirs(), Path::is_file)
}

/// Resolve the host gvproxy binary path: the `MINVMD_GVPROXY_BIN` override,
/// then the installed location — the user-local `bin/gvproxy-min` the curl|sh
/// installer stamps, else a system-wide path ([`switch::installed_gvproxy_bin`],
/// the definition shared with minimald, which also honours the pre-rename
/// `/usr/lib/minimal/bin/gvproxy` when only that exists).
///
/// Unlike the kernel/rootfs/initramfs resolvers this never errors: gvproxy is
/// only spawned for an own-IP VM, so an absent override is the common case, and
/// the system path is returned as a last resort even if nothing exists there
/// (the caller surfaces a spawn failure with that concrete path).
#[must_use]
pub fn resolve_gvproxy_path() -> PathBuf {
    // Explicit override, honoured verbatim.
    std::env::var("MINVMD_GVPROXY_BIN")
        .ok()
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(switch::installed_gvproxy_bin)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    // Resolver tests mutate process-global env (the MINVMD_* overrides and
    // XDG_DATA_HOME, which feeds `data_dir`), so serialise them to avoid races
    // when `cargo test` runs them in parallel.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    // Point the data dir at an isolated temp dir by setting XDG_DATA_HOME (so
    // `data_dir` never consults the real HOME), point XDG_DATA_DIRS at
    // `system` (so the machine's real /usr/local/share and /usr/share never
    // count), and clear every image override.
    fn scoped_data_dirs(xdg: &std::path::Path, system: &std::path::Path) {
        for (var, _) in IMAGES {
            unset_env(var);
        }
        set_env("XDG_DATA_HOME", xdg);
        set_env("XDG_DATA_DIRS", system);
    }

    fn clear_env() {
        for (var, _) in IMAGES {
            unset_env(var);
        }
        unset_env("XDG_DATA_HOME");
        unset_env("XDG_DATA_DIRS");
    }

    // Callers hold ENV_LOCK.
    fn set_env(var: &str, value: impl AsRef<std::ffi::OsStr>) {
        // SAFETY: the calling test holds ENV_LOCK, so nothing else in this
        // module reads or writes the process environment meanwhile.
        unsafe { std::env::set_var(var, value) };
    }

    // Callers hold ENV_LOCK.
    fn unset_env(var: &str) {
        // SAFETY: as in `set_env`.
        unsafe { std::env::remove_var(var) };
    }

    // Write `files` into `<root>/minimal`, as an install would.
    fn install(root: &std::path::Path, files: &[&str]) {
        let dir = root.join("minimal");
        std::fs::create_dir_all(&dir).unwrap();
        for file in files {
            std::fs::write(dir.join(file), file.as_bytes()).unwrap();
        }
    }

    const ALL_FILES: [&str; 3] = [
        DEFAULT_KERNEL_FILE,
        DEFAULT_ROOTFS_FILE,
        DEFAULT_INITRAMFS_FILE,
    ];

    #[test]
    fn falls_back_to_a_system_data_dir_when_the_user_has_no_copy() {
        let _g = ENV_LOCK.lock().unwrap();
        let home = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        install(system.path(), &ALL_FILES);

        scoped_data_dirs(home.path(), system.path());
        let path = resolve_kernel_path().unwrap();
        assert_eq!(
            path,
            system.path().join("minimal").join(DEFAULT_KERNEL_FILE)
        );
        clear_env();
    }

    #[test]
    fn the_users_copy_wins_over_the_systems() {
        let _g = ENV_LOCK.lock().unwrap();
        let home = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        install(home.path(), &ALL_FILES);
        install(system.path(), &ALL_FILES);

        scoped_data_dirs(home.path(), system.path());
        let path = resolve_rootfs_path().unwrap();
        assert_eq!(path, home.path().join("minimal").join(DEFAULT_ROOTFS_FILE));
        clear_env();
    }

    #[test]
    fn a_partial_user_copy_is_passed_over_whole_never_mixed() {
        let _g = ENV_LOCK.lock().unwrap();
        let home = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        // An interrupted or older install: no initramfs in the user's copy.
        install(home.path(), &[DEFAULT_KERNEL_FILE, DEFAULT_ROOTFS_FILE]);
        install(system.path(), &ALL_FILES);

        scoped_data_dirs(home.path(), system.path());
        let (kernel, rootfs, initramfs) = resolve_boot_images().unwrap();
        let want = system.path().join("minimal");
        assert_eq!(kernel, want.join(DEFAULT_KERNEL_FILE));
        assert_eq!(rootfs, want.join(DEFAULT_ROOTFS_FILE));
        assert_eq!(initramfs, want.join(DEFAULT_INITRAMFS_FILE));
        clear_env();
    }

    #[test]
    fn an_overridden_image_is_not_needed_in_the_directory() {
        let _g = ENV_LOCK.lock().unwrap();
        let home = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        install(home.path(), &[DEFAULT_ROOTFS_FILE, DEFAULT_INITRAMFS_FILE]);
        install(system.path(), &ALL_FILES);

        scoped_data_dirs(home.path(), system.path());
        set_env("MINVMD_KERNEL_PATH", "/boot/vmlinuz");
        let (kernel, rootfs, _) = resolve_boot_images().unwrap();
        assert_eq!(kernel, PathBuf::from("/boot/vmlinuz"));
        assert_eq!(
            rootfs,
            home.path().join("minimal").join(DEFAULT_ROOTFS_FILE)
        );
        clear_env();
    }

    #[test]
    fn a_directory_named_like_an_image_is_skipped() {
        let _g = ENV_LOCK.lock().unwrap();
        let home = tempfile::tempdir().unwrap();
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        install(first.path(), &[DEFAULT_ROOTFS_FILE, DEFAULT_INITRAMFS_FILE]);
        std::fs::create_dir_all(first.path().join("minimal").join(DEFAULT_KERNEL_FILE)).unwrap();
        install(second.path(), &ALL_FILES);

        scoped_data_dirs(home.path(), first.path());
        let dirs = format!("{}:{}", first.path().display(), second.path().display());
        set_env("XDG_DATA_DIRS", dirs);
        let path = resolve_kernel_path().unwrap();
        assert_eq!(
            path,
            second.path().join("minimal").join(DEFAULT_KERNEL_FILE)
        );
        clear_env();
    }

    #[test]
    fn missing_everywhere_names_each_directory_and_what_it_lacked() {
        let _g = ENV_LOCK.lock().unwrap();
        let home = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        install(home.path(), &[DEFAULT_KERNEL_FILE, DEFAULT_ROOTFS_FILE]);
        scoped_data_dirs(home.path(), system.path());
        let err = resolve_initramfs_path().unwrap_err();
        let VmError::MissingImage {
            var,
            unset,
            searched,
        } = &err
        else {
            panic!("expected MissingImage, got {err:?}");
        };
        assert_eq!(*var, "MINVMD_INITRAMFS");
        assert_eq!(
            *unset,
            vec![
                "MINVMD_KERNEL_PATH",
                "MINVMD_ROOTFS_PATH",
                "MINVMD_INITRAMFS"
            ]
        );
        assert_eq!(
            *searched,
            vec![
                SearchedDir {
                    dir: home.path().join("minimal"),
                    missing: vec![DEFAULT_INITRAMFS_FILE],
                },
                SearchedDir {
                    dir: system.path().join("minimal"),
                    missing: ALL_FILES.to_vec(),
                },
            ]
        );
        let text = err.to_string();
        let user_dir = home.path().join("minimal");
        assert!(
            text.contains(&format!("{} (no initramfs.cpio)", user_dir.display())),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "{} (no vmlinuz, rootfs.img, initramfs.cpio)",
                system.path().join("minimal").display()
            )),
            "{text}"
        );
        assert!(
            text.contains(
                "Reinstall minimal, or set MINVMD_KERNEL_PATH, MINVMD_ROOTFS_PATH, \
                 MINVMD_INITRAMFS to the image files."
            ),
            "{text}"
        );
        clear_env();
    }

    #[test]
    fn no_data_directory_without_xdg_data_home_or_home() {
        assert_eq!(data_dir_from(None, None), None);
        assert_eq!(
            data_dir_from(Some(String::new()), Some(String::new())),
            None
        );
        assert_eq!(
            data_dir_from(None, Some("/home/me".to_owned())),
            Some(PathBuf::from("/home/me/.local/share/minimal"))
        );
    }

    #[test]
    fn with_no_data_directory_the_systems_copy_serves() {
        // The no-HOME daemon (a service account, a scrubbed environment):
        // `data_dir` gives `None` (see the test above). Driven through
        // `select_image_dir` rather than by clearing HOME, which other
        // modules' tests read outside ENV_LOCK.
        let system = tempfile::tempdir().unwrap();
        install(system.path(), &ALL_FILES);
        let dir = system.path().join("minimal");
        let got = select_image_dir(
            "MINVMD_ROOTFS_PATH",
            &IMAGES,
            None,
            vec![dir.clone()],
            Path::is_file,
        )
        .unwrap();
        assert_eq!(got, dir);
    }

    #[test]
    fn with_no_data_directory_and_no_system_copy_the_error_names_the_system_dirs() {
        let system = tempfile::tempdir().unwrap();
        let dir = system.path().join("minimal");
        let err = select_image_dir(
            "MINVMD_KERNEL_PATH",
            &IMAGES[..1],
            None,
            vec![dir.clone()],
            Path::is_file,
        )
        .unwrap_err();
        let VmError::MissingImage { searched, .. } = &err else {
            panic!("expected MissingImage, got {err:?}");
        };
        assert_eq!(searched.len(), 1, "only the system directory: {err}");
        let text = err.to_string();
        assert!(
            text.contains(&format!("{} (no vmlinuz)", dir.display())),
            "{text}"
        );
        assert!(
            text.contains("set MINVMD_KERNEL_PATH to the image file."),
            "{text}"
        );
        assert!(!text.contains("required environment variable"), "{text}");
    }

    #[test]
    fn with_no_directory_at_all_the_error_says_so() {
        let err = select_image_dir(
            "MINVMD_KERNEL_PATH",
            &IMAGES,
            None,
            Vec::new(),
            Path::is_file,
        )
        .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("There was no directory to look in"), "{text}");
        assert!(!text.contains("()"), "{text}");
    }

    #[test]
    fn a_boot_selects_its_image_directory_once() {
        // An install finishes the user's copy while the boot resolves: the
        // user's initramfs is absent at the first look and present at every
        // later one. One selection sees one state, so all three images come
        // from the system copy. A selection per image would take the kernel
        // and rootfs from the system copy and the initramfs from the user's.
        let user = PathBuf::from("/home/me/.local/share/minimal");
        let system = PathBuf::from("/usr/share/minimal");
        let late = user.join(DEFAULT_INITRAMFS_FILE);
        let looks = std::cell::Cell::new(0);
        let has_file = |path: &Path| {
            if path != late.as_path() {
                return true;
            }
            looks.set(looks.get() + 1);
            looks.get() > 1
        };
        let (kernel, rootfs, initramfs) = resolve_images_in(
            [None, None, None],
            Some(user),
            vec![system.clone()],
            has_file,
        )
        .unwrap();
        assert_eq!(kernel, system.join(DEFAULT_KERNEL_FILE));
        assert_eq!(rootfs, system.join(DEFAULT_ROOTFS_FILE));
        assert_eq!(initramfs, system.join(DEFAULT_INITRAMFS_FILE));
        assert_eq!(looks.get(), 1, "the user's directory is looked at once");
    }

    #[test]
    fn a_boot_with_every_override_needs_no_data_directory() {
        let overrides = [
            Some(PathBuf::from("/boot/vmlinuz")),
            Some(PathBuf::from("/boot/rootfs.img")),
            Some(PathBuf::from("/boot/initramfs.cpio")),
        ];
        let got = resolve_images_in(overrides, None, Vec::new(), |_: &Path| false).unwrap();
        assert_eq!(
            got,
            (
                PathBuf::from("/boot/vmlinuz"),
                PathBuf::from("/boot/rootfs.img"),
                PathBuf::from("/boot/initramfs.cpio"),
            )
        );
    }

    #[test]
    fn a_boot_joins_only_its_unset_images_to_the_directory() {
        let system = tempfile::tempdir().unwrap();
        install(
            system.path(),
            &[DEFAULT_KERNEL_FILE, DEFAULT_INITRAMFS_FILE],
        );
        let dir = system.path().join("minimal");
        let overrides = [None, Some(PathBuf::from("/srv/rootfs.img")), None];
        let (kernel, rootfs, initramfs) =
            resolve_images_in(overrides, None, vec![dir.clone()], Path::is_file).unwrap();
        assert_eq!(kernel, dir.join(DEFAULT_KERNEL_FILE));
        assert_eq!(rootfs, PathBuf::from("/srv/rootfs.img"));
        assert_eq!(initramfs, dir.join(DEFAULT_INITRAMFS_FILE));
    }

    #[test]
    fn system_data_dirs_default_to_the_xdg_base_dirs() {
        let _g = ENV_LOCK.lock().unwrap();
        unset_env("XDG_DATA_DIRS");
        assert_eq!(
            system_data_dirs(),
            vec![
                PathBuf::from("/usr/local/share/minimal"),
                PathBuf::from("/usr/share/minimal")
            ]
        );
        set_env("XDG_DATA_DIRS", "/opt/data::share:/srv/share");
        assert_eq!(
            system_data_dirs(),
            vec![
                PathBuf::from("/opt/data/minimal"),
                PathBuf::from("/srv/share/minimal")
            ],
            "an empty entry and a relative entry are skipped"
        );
        unset_env("XDG_DATA_DIRS");
    }

    #[test]
    fn returns_override_verbatim_without_existence_check() {
        let _g = ENV_LOCK.lock().unwrap();
        // A non-existent explicit path is still honoured: the caller owns it.
        unsafe { std::env::set_var("MINVMD_KERNEL_PATH", "/boot/Image.gz") };
        let path = resolve_kernel_path().unwrap();
        assert_eq!(path, PathBuf::from("/boot/Image.gz"));
        clear_env();
    }

    #[test]
    fn falls_back_to_default_when_file_exists() {
        let _g = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        install(tmp.path(), &ALL_FILES);

        scoped_data_dirs(tmp.path(), system.path());
        let path = resolve_kernel_path().unwrap();
        assert_eq!(path, tmp.path().join("minimal").join(DEFAULT_KERNEL_FILE));
        clear_env();
    }

    #[test]
    fn errors_with_missing_image_when_default_absent() {
        let _g = ENV_LOCK.lock().unwrap();
        // XDG_DATA_HOME and XDG_DATA_DIRS each point at an empty temp dir: the
        // directories resolve but hold no image, whatever this host has
        // installed under /usr/local/share or /usr/share.
        let tmp = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        scoped_data_dirs(tmp.path(), system.path());
        let err = resolve_rootfs_path().unwrap_err();
        let VmError::MissingImage { var, searched, .. } = &err else {
            panic!("expected MissingImage, got {err:?}");
        };
        assert_eq!(*var, "MINVMD_ROOTFS_PATH");
        assert_eq!(searched[0].dir, tmp.path().join("minimal"));
        clear_env();
    }

    #[test]
    fn empty_override_is_treated_as_unset() {
        let _g = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        install(tmp.path(), &ALL_FILES);

        scoped_data_dirs(tmp.path(), system.path());
        // Empty string must not be used as a path; it falls through to default.
        set_env("MINVMD_INITRAMFS", "");
        let path = resolve_initramfs_path().unwrap();
        assert_eq!(
            path,
            tmp.path().join("minimal").join(DEFAULT_INITRAMFS_FILE)
        );
        clear_env();
    }

    // Remove every env var the gvproxy resolver consults, so a tier is only
    // exercised by what the test sets explicitly.
    fn clear_gvproxy_env() {
        unsafe {
            std::env::remove_var("MINVMD_GVPROXY_BIN");
            std::env::remove_var("MINIMAL_BIN");
        }
    }

    #[test]
    fn gvproxy_tier1_override_wins() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_gvproxy_env();
        unsafe { std::env::set_var("MINVMD_GVPROXY_BIN", "/custom/gvproxy") };
        assert_eq!(resolve_gvproxy_path(), PathBuf::from("/custom/gvproxy"));
        clear_gvproxy_env();
    }

    #[test]
    fn gvproxy_tier2_installer_bin_when_present() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_gvproxy_env();
        let tmp = tempfile::tempdir().unwrap();
        let want = tmp.path().join(switch::GVPROXY_FILE);
        std::fs::write(&want, b"gvproxy").unwrap();
        // MINIMAL_BIN steers installer_bin_dir without touching HOME.
        unsafe { std::env::set_var("MINIMAL_BIN", tmp.path()) };
        assert_eq!(resolve_gvproxy_path(), want);
        clear_gvproxy_env();
    }

    #[test]
    fn gvproxy_tier3_system_path_when_no_local() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_gvproxy_env();
        // MINIMAL_BIN points at an empty dir: no user-local gvproxy present.
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("MINIMAL_BIN", tmp.path()) };
        // One of the two system paths — the shared resolver prefers the legacy
        // one on a host that still has it, so asserting a single path here
        // would fail on exactly the pre-rename hosts that branch serves.
        // `switch`'s own tests pin which branch wins; this one only proves the
        // tier-2 miss falls through to a system path.
        let got = resolve_gvproxy_path();
        assert!(
            got.starts_with("/usr/lib/minimal/bin"),
            "expected a system-wide switch path, got {got:?}"
        );
        clear_gvproxy_env();
    }

    #[test]
    fn default_image_paths_resolve_from_install() {
        let _g = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("minimal");
        std::fs::create_dir_all(&data).unwrap();

        let want_kernel = data.join(DEFAULT_KERNEL_FILE);
        let want_rootfs = data.join(DEFAULT_ROOTFS_FILE);
        let want_initramfs = data.join(DEFAULT_INITRAMFS_FILE);
        std::fs::write(&want_kernel, b"kernel").unwrap();
        std::fs::write(&want_rootfs, b"rootfs").unwrap();
        std::fs::write(&want_initramfs, b"initramfs").unwrap();

        // No overrides and no HOME — only XDG_DATA_HOME points at the installed
        // layout. This is exactly the fresh-install case: the installer stamps
        // the three guest images into the data prefix and the daemon resolves
        // them with no env setup.
        unsafe {
            std::env::remove_var("MINVMD_KERNEL_PATH");
            std::env::remove_var("MINVMD_ROOTFS_PATH");
            std::env::remove_var("MINVMD_INITRAMFS");
            std::env::set_var("XDG_DATA_HOME", tmp.path());
        }

        let (kernel, rootfs, initramfs) = resolve_boot_images().unwrap();
        assert_eq!(kernel, want_kernel);
        assert_eq!(rootfs, want_rootfs);
        assert_eq!(initramfs, want_initramfs);

        // Per-resolver checks match the combined helper.
        assert_eq!(resolve_kernel_path().unwrap(), want_kernel);
        assert_eq!(resolve_rootfs_path().unwrap(), want_rootfs);
        assert_eq!(resolve_initramfs_path().unwrap(), want_initramfs);

        clear_env();
    }

    #[cfg(minvmd_libkrun)]
    #[test]
    fn kernel_format_matches_arch() {
        let fmt = kernel_format();
        // aarch64 ships the uncompressed Image → RAW (skips the libkrun gzip
        // decompress). x86_64 ships a bzImage → IMAGE_GZ (libkrun inflates the
        // embedded gzip vmlinux and ELF-loads it).
        #[cfg(target_arch = "aarch64")]
        assert_eq!(fmt, crate::krun::KernelFormat::Raw);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(fmt, crate::krun::KernelFormat::ImageGz);
    }
}
