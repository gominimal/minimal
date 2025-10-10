let { BuildSpec, Local, OutputBin, OutputData, OutputLib, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let make = import "../make/build.ncl" in
let glibc = import "../glibc/build.ncl" in
{
  name = "gdbm",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/gdbm-1.26.tar.gz",
      sha256 = "6a24504a14de4a744103dcb936be976df6fbe88ccff26065e54c1c47946f4a5e"
    } | Source,
    base,
    make,
    toolchain,
  ],
  runtime_deps = [
    glibc,
  ],

  cmd = "./build.sh",
  outputs = {
    bin = { glob = "usr/bin/*" } | OutputBin,
    lib = { glob = "usr/lib/*" } | OutputLib,
    usr_include = { glob = "usr/include/**/*" } | OutputData,
    man = { glob = "usr/share/man/**/*" } | OutputData,
    info = { glob = "usr/share/info/*" } | OutputData,
  },
} | BuildSpec
