let { BuildSpec, Local, OutputLib, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let m4 = import "../m4/build.ncl" in
let make = import "../make/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let glibc = import "../glibc/build.ncl" in
{
  name = "libtool",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/libtool-2.5.4.tar.xz",
      sha256 = "f81f5860666b0bc7d84baddefa60d1cb9fa6fceb2398cc3baca6afaa60266675"
    } | Source,
    base,
    m4,
    make,
    toolchain,
  ],
  runtime_deps = [
    glibc,
  ],

  cmd = "./build.sh",
  outputs = {
    bin = { glob = "usr/bin/*" } | OutputLib,
    lib = { glob = "usr/lib/*" } | OutputLib,
    usr_include = { glob = "usr/include/**/*" } | OutputLib,
    share = { glob = "usr/share/libtool/**/*" } | OutputLib,
    aclocal = { glob = "usr/share/aclocal/*.m4" } | OutputLib,
    man = { glob = "usr/share/man/**/*" } | OutputLib,
  },
} | BuildSpec
