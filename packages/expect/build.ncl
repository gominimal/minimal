let { BuildSpec, Local, OutputLib, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let patch = import "../patch/build.ncl" in
let python = import "../python/build.ncl" in
let tcl = import "../tcl/build.ncl" in
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
    patch,
    python,
    toolchain,
  ],
  runtime_deps = [
    tcl
  ],
  cmd = "./build.sh",
  outputs = {
    libexpect5 = { glob = "usr/lib/libexpect5.45.4.so" } | OutputLib,
    usr_bin = { glob = "usr/bin/*" } | OutputLib,
    usr_lib_expect = { glob = "usr/lib/expect5.45.4/*" } | OutputLib,
    usr_include = { glob = "usr/include/*" } | OutputLib,
  },
} | BuildSpec
