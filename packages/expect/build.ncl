let { BuildSpec, Local, OutputBin, OutputData, OutputLib, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let patch = import "../patch/build.ncl" in
let python = import "../python/build.ncl" in
let tcl = import "../tcl/build.ncl" in
let make = import "../make/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "expect",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/expect5.45.4.tar.gz",
      sha256 = "49a7da83b0bdd9f46d04a04deec19c7767bb9a323e40c4781f89caf760b92c34"
    } | Source,
    {
      url = "gs://minimal-staging-archives/expect-5.45.4-gcc15-1.patch",
      sha256 = "ab5fc0af9e2e0f80d7623c1a3a3dbeb1da3d8c9134276792199df401f9eb2cec"
    } | Source,
    base,
    make,
    patch,
    python,
    toolchain,
  ],
  runtime_deps = [
    tcl
  ],
  cmd = "./build.sh",
  outputs = {
    bins = { glob = "usr/bin/*" } | OutputBin,
    libs = { glob = "usr/lib/**/*.{a,so*}" } | OutputLib,

    includes = { glob = "usr/include/**" } | OutputData,
  },
} | BuildSpec
