let { BuildSpec, Local, OutputBin, OutputData, Source, .. } = import "minimal.ncl" in
let cmake = import "../cmake/build.ncl" in
let meson = import "../meson/build.ncl" in
let ninja = import "../ninja/build.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let glibc = import "../glibc/build.ncl" in
{
  name = "patchelf",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "https://github.com/NixOS/patchelf/archive/b49de1b3384e7928bf0df9a889fe5a4e7b3fbddf.tar.gz",
      sha256 = "8ed5382f1ac423328b1d50b2c89d96dbab156de0285d003ff51940975db66572"
    } | Source,
    base,
    cmake,
    meson,
    ninja,
    toolchain,
  ],
  runtime_deps = [
    glibc,
  ],

  cmd = "./build.sh",
  outputs = {
    patchelf = { glob = "usr/bin/patchelf" } | OutputBin,
    man = { glob = "usr/share/man/**/*" } | OutputData,
  },
} | BuildSpec
