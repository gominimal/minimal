let { BuildSpec, Local, OutputBin, OutputData, Prebuilt, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let make = import "../make/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let glibc = import "../glibc/build.ncl" in
{
  name = "gzip",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/gzip-1.14.tar.xz",
      sha256 = "01a7b881bd220bfdf615f97b8718f80bdfd3f6add385b993dcf6efd14e8c0ac6"
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
    bins = { glob = "usr/bin/*" } | OutputBin,

    infos = { glob = "usr/share/info/*.info" } | OutputData,
    mans = { glob = "usr/share/man/**" } | OutputData,
  },

  replace_on_cycle =
    {
      name = "gzip (prebuilt)",
      inputs = [
        { package = "gzip" } | Prebuilt,
      ],
      cmd = "",
      outputs = {
        binaries = { glob = "usr/bin/*" } | OutputBin,
      },
    } | BuildSpec,
} | BuildSpec
