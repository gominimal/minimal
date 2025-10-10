let { BuildSpec, Local, OutputBin, OutputLib, Prebuilt, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let acl = import "../acl/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let xz = import "../xz/build.ncl" in
{
  name = "tar",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/tar-1.35.tar.xz",
      sha256 = "4d62ff37342ec7aed748535323930c7cf94acf71c3591882b26a7ea50f3edc16"
    } | Source,
    base,
    toolchain,
  ],
  runtime_deps = [
    acl,
    gzip,
    xz,
  ],
  cmd = "./build.sh",
  outputs = {
    tar = { glob = "usr/bin/tar" } | OutputBin,
    rmt = { glob = "usr/libexec/rmt" } | OutputLib,
    info = { glob = "usr/share/info/tar.info*" } | OutputLib,
    locale_files = { glob = "usr/share/locale/**/*" } | OutputLib,
  },

  replace_on_cycle =
    {
      name = "tar (prebuilt)",
      inputs = [
        { package = "tar" } | Prebuilt,
      ],
      cmd = "",
      outputs = {
        tar = { glob = "usr/bin/tar" } | OutputBin,
      },
    } | BuildSpec,
} | BuildSpec
