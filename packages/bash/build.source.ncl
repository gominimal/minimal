let { BuildSpec, HostPath, OutputLib, Local, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let readline = import "../readline/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "bash",
  inputs = [
    { file = "build.source.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/bash-5.3.tar.gz",
      sha256 = "0d5cd86965f869a26cf64f4b71be7b96f90a3ba8b3d74e27e8e9d9d5550f31ba"
    } | Source,
    base,
    readline,
    toolchain,
  ],
  cmd = "./build.source.sh",
  outputs = {
    bin = { glob = "bin/sh" } | OutputLib,
    usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
    usr_lib = { glob = "usr/lib/**/*" } | OutputLib,
    usr_share = { glob = "usr/share/**/*" } | OutputLib,
    usr_include = { glob = "usr/include/**/*" } | OutputLib,
  },
} | BuildSpec
