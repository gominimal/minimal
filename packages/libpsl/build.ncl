let { BuildSpec, HostPath, OutputLib, Local, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let libidn2 = import "../libidn2/build.ncl" in
let libunistring = import "../libunistring/build.ncl" in
let meson = import "../meson/build.ncl" in
let ninja = import "../ninja/build.ncl" in
let pkgconf = import "../pkgconf/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "libpsl",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/libpsl-0.21.5.tar.gz",
      sha256 = "1dcc9ceae8b128f3c0b3f654decd0e1e891afc6ff81098f227ef260449dae208"
    } | Source,
    base,
    meson,
    ninja,
    pkgconf,
    toolchain,
  ],
  runtime_deps = [
    libidn2,
    libunistring
  ],
  cmd = "./build.sh",
  outputs = {
    bin = { glob = "usr/bin/*" } | OutputLib,
    pkg_config = { glob = "usr/lib/pkgconfig/libpsl.pc" } | OutputLib,
    lib = { glob = "usr/lib/*" } | OutputLib,
    header = { glob = "usr/include/*" } | OutputLib,
  },
} | BuildSpec
