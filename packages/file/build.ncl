let { BuildSpec, Local, OutputBin, OutputData, OutputLib, Prebuilt, Source, .. } = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let tar = import "../tar/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in

let glibc = import "../glibc/build.ncl" in
let lz4 = import "../lz4/build.ncl" in
let xz = import "../xz/build.ncl" in
{
  name = "file",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/file-5.46.tar.gz",
      sha256 = "c9cc77c7c560c543135edc555af609d5619dbef011997e988ce40a3d75d86088"
    } | Source,
    bash,
    tar,
    make,
    sed,
    gawk,
    grep,
    coreutils,
    toolchain,
  ],
  runtime_deps = [
    glibc,
    lz4,
    xz,
  ],

  cmd = "./build.sh",
  outputs = {
    file = { glob = "usr/bin/file" } | OutputBin,

    libmagic = { glob = "usr/lib/libmagic.so*" } | OutputLib,
    data = { glob = "usr/share/misc/magic*" } | OutputData,

    includes = { glob = "usr/include/**" } | OutputData,
  },

  replace_on_cycle =
    {
      name = "file (prebuilt)",
      inputs = [
        { package = "file" } | Prebuilt,
      ],
      cmd = "",
      outputs = {
        usr_bin = { glob = "usr/bin/**/*" } | OutputBin,
        usr_lib = { glob = "usr/lib/**/*" } | OutputLib,
        usr_include = { glob = "usr/include/**/*" } | OutputLib,
        usr_share = { glob = "usr/share/**/*" } | OutputLib,
      }
    } | BuildSpec,
} | BuildSpec
