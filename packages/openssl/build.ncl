let { BuildSpec, HostPath, OutputLib, Local, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "openssl",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/openssl-3.5.2.tar.gz",
      sha256 = "c53a47e5e441c930c3928cf7bf6fb00e5d129b630e0aa873b08258656e7345ec"
    } | Source,
    base,
    toolchain,
  ],
  cmd = "./build.sh",
  outputs = {
    etc = { glob = "etc/ssl/**/*" } | OutputLib,
    usr = { glob = "usr/**/*" } | OutputLib,
  },
} | BuildSpec
