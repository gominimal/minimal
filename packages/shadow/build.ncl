let { BuildSpec, Local, OutputLib, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let make = import "../make/build.ncl" in
let acl = import "../acl/build.ncl" in
let attr = import "../attr/build.ncl" in
let libxcrypt = import "../libxcrypt/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "shadow",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/shadow-4.18.0.tar.xz",
      sha256 = "add4604d3bc410344433122a819ee4154b79dd8316a56298c60417e637c07608"
    } | Source,
    base,
    make,
    toolchain,
  ],
  runtime_deps = [
    acl,
    attr,
    libxcrypt,
  ],
  cmd = "./build.sh",
  outputs = {
    bin = { glob = "usr/bin/*" } | OutputLib,
    sbin = { glob = "usr/sbin/*" } | OutputLib,
    lib = { glob = "usr/lib/*" } | OutputLib,
    usr_include = { glob = "usr/include/**/*" } | OutputLib,
    etc = { glob = "etc/**/*" } | OutputLib,
    locale = { glob = "usr/share/locale/**/*" } | OutputLib,
  },
} | BuildSpec
