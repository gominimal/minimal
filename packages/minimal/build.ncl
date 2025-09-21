let { BuildSpec, Local, OutputLib, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let ca-certificates = import "../ca-certificates/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let rust = import "../rust/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "minimal",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/minpkgs-ca7133e671320bc33ccb07d2a682a5f2ec10586d.tar.gz",
      sha256 = "6f49f8a5ab8ad6eb96afbb62f1e4189d7b34e9307431172788303223dc3ac7cc"
    } | Source,
    base,
    rust,
    toolchain,
  ],
  runtime_deps = [
    ca-certificates, # TODO move to rust
    glibc,
    gcc, # TODO, weird
  ],
  cmd = "./build.sh",
  outputs = {
    minimal = { glob = "usr/bin/minimal" } | OutputLib,
  },
} | BuildSpec
