let { BuildSpec, HostPath, OutputLib, Local, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let openssl = import "../openssl/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "cmake",
  inputs = [
    {
      url = "gs://minimal-staging-archives/cmake-4.1.1.tar.gz",
      sha256 = "b29f6f19733aa224b7763507a108a427ed48c688e1faf22b29c44e1c30549282"
    } | Source,
    { file = "build.sh" } | Local,
    base,
    toolchain,
  ],
  runtime_deps = [
    openssl,
  ],
  cmd = "./build.sh",
  outputs = {
    usr = { glob = "usr/**/*" } | OutputLib,
  },
} | BuildSpec
