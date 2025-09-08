let { BuildSpec, HostPath, OutputLib, Local, Source, .. } = import "minimal.ncl" in
let acl = import "../acl/build.ncl" in
let base = import "../bash/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "sed",
  inputs = [
    { file = "build.source.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/sed-4.9.tar.xz",
      sha256 = "6e226b732e1cd739464ad6862bd1a1aba42d7982922da7a53519631d24975181"
    } | Source,
    acl,
    base,
    toolchain,
  ],
  cmd = "./build.source.sh",
  outputs = {
    usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
    usr_share = { glob = "usr/share/**/*" } | OutputLib,
  },
} | BuildSpec
