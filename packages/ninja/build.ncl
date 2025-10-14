let { BuildSpec, Local, OutputLib, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let python = import "../python/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let gcc = import "../gcc/build.ncl" in
{
  name = "ninja",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/ninja-1.13.1.tar.gz",
      sha256 = "f0055ad0369bf2e372955ba55128d000cfcc21777057806015b45e4accbebf23"
    } | Source,
    base,
    python,
    toolchain,
  ],
  runtime_deps = [
    glibc,
    gcc, # TODO: just need libstdc++.so.6
  ],

  cmd = "./build.sh",
  outputs = {
    ninja = { glob = "usr/bin/ninja" } | OutputLib,
  },
} | BuildSpec
