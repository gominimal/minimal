let { BuildSpec, HostPath, OutputLib, Local, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "pkgconf",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/pkgconf-2.5.1.tar.xz",
      sha256 = "cd05c9589b9f86ecf044c10a2269822bc9eb001eced2582cfffd658b0a50c243"
    } | Source,
    base,
    toolchain,
  ],
  cmd = "./build.sh",
  outputs = {
    usr_bin = { glob = "usr/bin/*" } | OutputLib,
    usr_include_pkgconf_libpkgconf = { glob = "usr/include/pkgconf/libpkgconf/*" } | OutputLib,
    usr_lib = { glob = "usr/lib/*" } | OutputLib,
    usr_lib_pkgconfig = { glob = "usr/lib/pkgconfig/*" } | OutputLib,
    usr_share_aclocal = { glob = "usr/share/aclocal/*" } | OutputLib,
  },
} | BuildSpec
