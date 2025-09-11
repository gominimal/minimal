let { BuildSpec, OutputLib, Local, Source, .. } = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "bash",
  inputs = [
    { file = "build.source.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/bash-5.3.tar.gz",
      sha256 = "0d5cd86965f869a26cf64f4b71be7b96f90a3ba8b3d74e27e8e9d9d5550f31ba"
    } | Source,
    bash,
    coreutils,
    gawk,
    grep,
    gzip,
    make,
    sed,
    tar,
    toolchain,
  ],
  cmd = "./build.source.sh",
  outputs = {
    bash = { glob = "usr/bin/bash" } | OutputLib,
    usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
    usr_lib = { glob = "usr/lib/**/*" } | OutputLib,
    usr_share = { glob = "usr/share/**/*" } | OutputLib,
    usr_include = { glob = "usr/include/**/*" } | OutputLib,
  },
} | BuildSpec