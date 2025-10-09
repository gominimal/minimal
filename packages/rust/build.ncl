let { BuildSpec, Local, OutputLib, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let cmake = import "../cmake/build.ncl" in
let curl = import "../curl/build.ncl" in
let llvm = import "../llvm/build.ncl" in
let openssl = import "../openssl/build.ncl" in
let pkgconf = import "../pkgconf/build.ncl" in
let python = import "../python/build.ncl" in
let sqlite = import "../sqlite/build.ncl" in
let libffi = import "../libffi/build.ncl" in
let toolchain-gnullvm = import "../toolchain-gnullvm/build.ncl" in
let gcc = import "../gcc/build.ncl" in
{
  name = "rust",
  inputs = [
    { file = "bootstrap.toml" } | Local,
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/rustc-1.89.0-src.tar.xz",
      sha256 = "0b9d55610d8270e06c44f459d1e2b7918a5e673809c592abed9b9c600e33d95a"
    } | Source,
    base,
    cmake,
    curl,
    pkgconf,
    python,
    toolchain-gnullvm,
  ],
  runtime_deps = [
    libffi,
    llvm,
    openssl,
    sqlite,
    gcc, # TODO: Use subsets for just libstdc++.so.6 and libgcc_s.so.1.
  ],

  cmd = "./build.sh",
  outputs = {
    usr = { glob = "usr/**/*" } | OutputLib,
  },
} | BuildSpec
