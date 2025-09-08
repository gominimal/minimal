let { BuildSpec, HostPath, OutputLib, Local, Source, .. } = import "minimal.ncl" in
let acl = import "../make/build.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "tar",
  inputs = [
    { file = "build.source.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/tar-1.35.tar.xz",
      sha256 = "4d62ff37342ec7aed748535323930c7cf94acf71c3591882b26a7ea50f3edc16"
    } | Source,
    acl,
    base,
    toolchain,
  ],
  cmd = "./build.source.sh",
  outputs = {
    tar = { glob = "usr/bin/tar" } | OutputLib,
    rmt = { glob = "usr/libexec/rmt" } | OutputLib,
    info = { glob = "usr/share/info/tar.info*" } | OutputLib,
    locale_files = { glob = "usr/share/locale/**/*" } | OutputLib,
  },
} | BuildSpec
