let { BuildSpec, HostPath, OutputLib, OutputBin, OutputData, Local, Prebuilt, Source, .. } = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let grep = import "../grep/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let linux_headers = import "../linux_headers/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "libcap",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/libcap-2.76.tar.xz",
      sha256 = "629da4ab29900d0f7fcc36227073743119925fd711c99a1689bbf5c9b40c8e6f"
    } | Source,
    bash,
    diffutils,
    grep,
    make,
    sed,
    tar,
    linux_headers,
    coreutils,
    toolchain,
  ],
  cmd = "./build.sh",
  outputs = {
    sbin = { path = "usr/sbin/*" } | OutputBin,
    lib = { glob = "usr/lib/*" } | OutputLib,
    usr_include = { data = "usr/include/**/*" } | OutputData,
    man = { data = "usr/share/man/**/*" } | OutputData,
    pkgconfig = { data = "usr/lib/pkgconfig/*" } | OutputData,
  },

  replace_on_cycle = {
    name = "libcap (prebuilt)",
    inputs = [
      { package = "libcap" } | Prebuilt,
    ],
    cmd = "",
    outputs = {
      usr = { glob = "usr/**/*" } | OutputLib,
    },
  } | BuildSpec,
} | BuildSpec
