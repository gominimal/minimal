let { BuildSpec, Local, OutputLib, Source, .. } = import "minimal.ncl" in
let autoconf = import "../autoconf/build.ncl" in
let base = import "../base/build.ncl" in
let make = import "../make/build.ncl" in
let perl = import "../perl/build.ncl" in
let m4 = import "../m4/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let zstd = import "../zstd/build.ncl" in
{
  name = "automake",
  inputs = [
    {
      url = "gs://minimal-staging-archives/automake-1.17.tar.xz",
      sha256 = "8920c1fc411e13b90bf704ef9db6f29d540e76d232cb3b2c9f4dc4cc599bd990"
    } | Source,
    { file = "build.sh" } | Local,
    autoconf,
    base,
    make,
    perl,
    m4,
    toolchain,
    zstd,
  ],
  cmd = "./build.sh",
  outputs = {
    usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
    usr_share = { glob = "usr/share/**/*" } | OutputLib,
  },
} | BuildSpec
