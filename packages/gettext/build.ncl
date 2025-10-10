let { BuildSpec, Local, OutputLib, Source, .. } = import "minimal.ncl" in
let acl = import "../acl/build.ncl" in
let base = import "../base/build.ncl" in
let ncurses = import "../ncurses/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let make = import "../make/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let gcc = import "../gcc/build.ncl" in
{
  name = "gettext",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/gettext-0.26.tar.xz",
      sha256 = "d1fb86e260cfe7da6031f94d2e44c0da55903dbae0a2fa0fae78c91ae1b56f00"
    } | Source,
    base,
    make,
    toolchain,
  ],
  runtime_deps = [
    acl,
    ncurses,
    glibc,
    gcc, # TODO: Use a subset for this
  ],

  cmd = "./build.sh",
  outputs = {
    bin = { glob = "usr/bin/*" } | OutputLib,
    lib = { glob = "usr/lib/*" } | OutputLib,
    libexec = { glob = "usr/libexec/gettext/*" } | OutputLib,
    usr_include = { glob = "usr/include/**/*" } | OutputLib,
    man = { glob = "usr/share/man/**/*" } | OutputLib,
    info = { glob = "usr/share/info/*" } | OutputLib,
    locale = { glob = "usr/share/locale/**/*" } | OutputLib,
    gettext = { glob = "usr/share/gettext/**/*" } | OutputLib,
    aclocal = { glob = "usr/share/aclocal/*" } | OutputLib,
  },
} | BuildSpec
