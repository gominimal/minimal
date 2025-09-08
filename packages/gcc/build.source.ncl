let { BuildSpec, HostPath, OutputLib, Local, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let gmp = import "../gmp/build.ncl" in
let mpc = import "../mpc/build.ncl" in
let mpfr = import "../mpfr/build.ncl" in
let zlib = import "../zlib/build.ncl" in
let zstd = import "../zstd/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "gcc",
  inputs = [
    { file = "build.source.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/gcc-15.2.0.tar.xz",
      sha256 = "438fd996826b0c82485a29da03a72d71d6e3541a83ec702df4271f6fe025d24e"
    } | Source,
    base,
    gmp,
    mpc,
    mpfr,
    zlib,
    zstd,
    toolchain,
  ],
  cmd = "./build.source.sh",
  outputs = {
    usr = { glob = "usr/**/*" } | OutputLib,
  },
} | BuildSpec
