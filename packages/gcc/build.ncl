let { BuildSpec, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
let gmp = import "../gmp/build.ncl" in
let mpc = import "../mpc/build.ncl" in
let mpfr = import "../mpfr/build.ncl" in
let zlib = import "../zlib/build.ncl" in
let zstd = import "../zstd/build.ncl" in
{
  name = "gcc",
  inputs = [
    { package = "gcc", sha256 = "f06ee65f2f8bd9cfc53f779807b78174b7822d773a5a8c198d182aa6f9f06d9c" } | Prebuilt,
  ],
  runtime_deps = [
    gmp,
    mpc,
    mpfr,
    zlib,
    zstd,
  ],
  cmd = "",
  outputs = {
    usr = { glob = "usr/**/*" } | OutputLib,
  },
} | BuildSpec
