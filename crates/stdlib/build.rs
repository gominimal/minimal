use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let stdlib_dir = PathBuf::from("minimal-ncl");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    // Collect all files, sorted for determinism
    let mut files: BTreeMap<String, PathBuf> = BTreeMap::new();

    collect_files(&stdlib_dir, &stdlib_dir, &mut files);

    // Tell cargo to rerun if any of these files change
    println!("cargo:rerun-if-changed={}", stdlib_dir.display());
    for path in files.values() {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    // Hash all file contents (sorted by relative path for determinism)
    let mut hasher = Hasher::new();
    for (rel, path) in &files {
        hasher.update(rel.as_bytes());
        hasher.update(&fs::read(path).unwrap_or_default());
    }
    let hash = hasher.finalize();
    println!("cargo:rustc-env=STDLIB_HASH={:016x}", hash);

    // Generate the source file
    let generated = out_dir.join("stdlib_files.rs");
    let mut out = fs::File::create(&generated).unwrap();

    writeln!(out, "pub struct StdlibFile {{").unwrap();
    writeln!(out, "    pub path: &'static str,").unwrap();
    writeln!(out, "    pub contents: &'static [u8],").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "pub static STDLIB_FILES: &[StdlibFile] = &[").unwrap();

    for (rel, abs) in &files {
        writeln!(out, "    StdlibFile {{").unwrap();
        writeln!(out, "        path: {:?},", rel).unwrap();
        writeln!(
            out,
            "        contents: include_bytes!({:?}),",
            abs.canonicalize().unwrap()
        )
        .unwrap();
        writeln!(out, "    }},").unwrap();
    }

    writeln!(out, "];").unwrap();
}

fn collect_files(base: &PathBuf, dir: &PathBuf, files: &mut BTreeMap<String, PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(base, &path, files);
        } else {
            let rel = path
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/"); // normalise on Windows
            files.insert(rel, path);
        }
    }
}

// A minimal FNV-1a 64-bit hasher — no external deps needed in build.rs
struct Hasher(u64);

impl Hasher {
    fn new() -> Self {
        Self(0xcbf29ce484222325)
    }

    fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.0 ^= b as u64;
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }

    fn finalize(self) -> u64 {
        self.0
    }
}
