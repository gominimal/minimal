let { BuildSpec, HostPath, OutputLib, Local, Source, .. } = import "minimal.ncl" in
let acl = import "../acl/build.ncl" in
let attr = import "../attr/build.ncl" in
let base = import "../base/build.ncl" in
let libcap = import "../libcap/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "coreutils",
  inputs = [
    { file = "build.source.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/coreutils-9.7.tar.xz",
      sha256 = "e8bb26ad0293f9b5a1fc43fb42ba970e312c66ce92c1b0b16713d7500db251bf"
    } | Source,
    acl,
    attr,
    base,
    libcap,
    toolchain,
  ],
  cmd = "./build.source.sh",
  outputs = {
    usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
    usr_libexec = { glob = "usr/libexec/**/*" } | OutputLib,
    usr_share = { glob = "usr/share/**/*" } | OutputLib,
  },
} | BuildSpec
