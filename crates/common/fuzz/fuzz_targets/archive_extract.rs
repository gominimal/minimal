#![no_main]

//! Fuzz `archive::extract_compressed_tar` — the tar/decompressor entry point
//! that build sources, OCI image layers, and remote-cache artifacts all flow
//! through (NET + SUPPLY trust). A malformed archive must return an
//! `ArchiveError`, never panic, and must never write outside `dest_dir`.
//!
//! This is the surface that carried the #651 `strip_prefix` path-traversal
//! bug; `normalize_within_root` is the fix under test here. The harness
//! asserts containment after every extraction rather than trusting the
//! return value: a successful extract that escaped the root is the exact
//! shape of bug this target exists to catch, and on its own it trips neither
//! a panic nor a sanitizer.
//!
//! # Input layout
//!
//! Deliberately hand-rolled rather than `#[derive(Arbitrary)]`. Seeding is
//! what makes this target work at all — an unseeded byte fuzzer burns ~10^7
//! executions before it stumbles onto a valid ustar header — and seeds are
//! only cheap to produce if the corpus encoding is something `cat` can
//! build. Here a seed is two control bytes prepended to a real tarball
//! (`scripts/gen-seeds.sh`). An `Arbitrary`-derived struct would bury the
//! body behind an opaque, arbitrary-version-dependent prefix encoding.
//!
//! ```text
//! byte 0   compression selector (mod 5)
//! byte 1   strip_prefix selector (mod 4)
//! byte 2.. the archive body, fed to the selected decompressor
//! ```

use std::path::Path;

use libfuzzer_sys::fuzz_target;

use common::archive::{extract_compressed_tar, Compression};

/// Cap the archive body. Decompressors legitimately amplify their input, and
/// an unbounded body turns a disk-fill into an ambient failure that tells us
/// nothing about the decoder. The RSS cap covers memory; this covers bytes.
const MAX_BODY: usize = 64 * 1024;

/// Prefixes worth stripping. `".."` is the adversarial one: the #651 class of
/// bug lived in how a stripped prefix interacts with entry paths.
const PREFIXES: [Option<&str>; 4] = [None, Some("."), Some("pkg"), Some("..")];

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let (control, body) = data.split_at(2);

    if body.len() > MAX_BODY {
        return;
    }

    let compression = match control[0] % 5 {
        0 => Compression::None,
        1 => Compression::Gzip,
        2 => Compression::Zstd,
        3 => Compression::Xz,
        _ => Compression::Bz2,
    };
    // xz is skipped here, and only here. `lzma_rs` panics on some malformed
    // streams (`backward_size + 1` overflows in its footer check) instead of
    // erroring. `extract_compressed_tar` contains that with `catch_unwind`, so
    // production returns an `ArchiveError` as the contract requires — but
    // `libfuzzer-sys` installs a panic hook that aborts before unwinding, so
    // the guard cannot take effect inside this harness and every mutation of
    // an xz seed halts the run on a dependency bug.
    //
    // The guard itself is covered by `extract_xz_panic_is_contained` in the
    // crate's own tests, against the exact stream the fuzzer produced.
    if matches!(compression, Compression::Xz) {
        return;
    }

    let strip = PREFIXES[usize::from(control[1] % 4)].map(str::to_owned);

    // Sandbox under the fuzz target dir (gitignored) rather than `/tmp`, and
    // deliberately so: hard links cannot cross devices. A tar hardlink target
    // is resolved against the *process CWD* by `tar::Entry::unpack`, and the
    // CWD here is the crate root — so a `/tmp` destination on another mount
    // turns every inode escape into a silent EXDEV instead of a finding.
    let sandbox = match tempfile::tempdir_in("fuzz/target") {
        Ok(d) => d,
        // Before the first build there is no fuzz/target; the run is still
        // useful for path escapes even if inode escapes go unseen.
        Err(_) => match tempfile::tempdir() {
            Ok(d) => d,
            Err(_) => return,
        },
    };
    let dest = sandbox.path().join("dest");
    if std::fs::create_dir(&dest).is_err() {
        return;
    }

    // A file OUTSIDE the destination but on the same device: nothing that
    // lands inside may share its inode.
    let sentinel = sandbox.path().join("sentinel");
    if std::fs::write(&sentinel, b"sentinel").is_err() {
        return;
    }
    let Ok(sentinel_meta) = std::fs::metadata(&sentinel) else {
        return;
    };

    let _ = extract_compressed_tar(body, compression, &dest, strip.as_ref());

    // Whatever the call returned, nothing may have landed outside the
    // destination root. A partial extraction on the error path still has to
    // obey containment.
    assert_contained(&dest);
    assert_no_inode_escape(&dest, &sentinel_meta);
});

/// Fails if anything extracted shares an inode with a file outside the
/// destination.
///
/// [`assert_contained`] is a *path* oracle and structurally cannot see this. A
/// hardlink's path really is inside the tree and `canonicalize` agrees, because
/// a hardlink has no target to resolve — it is a second name for one inode.
/// The escape is by identity, not by location.
///
/// Not hypothetical: `tar::Entry::unpack` validates a hardlink target only when
/// handed a `target_base`, which the whole-archive `unpack_in` supplies and a
/// per-entry call does not, so a relative target resolves against the process
/// CWD. A path-only oracle watched that happen and reported success.
fn assert_no_inode_escape(root: &Path, sentinel: &std::fs::Metadata) {
    use std::os::unix::fs::MetadataExt;

    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_symlink() {
                continue; // assert_contained's job
            }
            if kind.is_dir() {
                stack.push(path);
                continue;
            }
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            assert!(
                !(meta.ino() == sentinel.ino() && meta.dev() == sentinel.dev()),
                "inode escape: {} is a hardlink to a file outside the destination",
                path.display(),
            );
        }
    }
}

/// Walks the extracted tree and fails if any entry — including a symlink
/// target — resolves outside `root`. Symlinks are checked without following
/// them: a link *pointing* outside the root is itself the escape primitive,
/// even before anything writes through it.
fn assert_contained(root: &Path) {
    let Ok(canonical_root) = root.canonicalize() else {
        return;
    };

    // Seed from the CANONICAL root, not `root`: on macOS the tempdir is
    // `/var/folders/...` while its canonical form is `/private/var/folders/...`
    // (`/var` is a symlink). Descending from the non-canonical form would make
    // `dir.join(target)` carry a prefix `canonical_root` never matches, so
    // `escapes()` would fire on in-tree symlinks. Linux `/tmp` is not
    // symlinked, so this only ever reproduced on macOS.
    let mut stack = vec![canonical_root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };

            if kind.is_symlink() {
                if let Ok(target) = std::fs::read_link(&path) {
                    let resolved = if target.is_absolute() {
                        target
                    } else {
                        dir.join(target)
                    };
                    // Lexical, not canonical: the target may not exist, and
                    // canonicalize() would follow the very link being judged.
                    assert!(
                        !escapes(&resolved, &canonical_root),
                        "symlink {} points outside root: {}",
                        path.display(),
                        resolved.display(),
                    );
                }
                continue;
            }

            if let Ok(real) = path.canonicalize() {
                assert!(
                    real.starts_with(&canonical_root),
                    "extracted entry escaped root: {}",
                    real.display(),
                );
            }

            if kind.is_dir() {
                stack.push(path);
            }
        }
    }
}

/// Lexically normalizes `path` (resolving `..` without touching the
/// filesystem) and reports whether it leaves `root`.
fn escapes(path: &Path, root: &Path) -> bool {
    use std::path::{Component, PathBuf};

    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    !out.starts_with(root)
}
