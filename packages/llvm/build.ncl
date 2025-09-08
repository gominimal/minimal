let { BuildSpec, HostPath, OutputLib, Local, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let cmake = import "../cmake/build.ncl" in
let ninja = import "../ninja/build.ncl" in
let python = import "../python/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
  name = "llvm",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/llvm-20.1.8.src.tar.xz",
      sha256 = "e1363888216b455184dbb8a74a347bf5612f56a3f982369e1cba6c7e0726cde1"
    } | Source,
    {
      url = "gs://minimal-staging-archives/cmake-20.1.8.src.tar.xz",
      sha256 = "3319203cfd1172bbac50f06fa68e318af84dcb5d65353310c0586354069d6634"
    } | Source,
    {
      url = "gs://minimal-staging-archives/third-party-20.1.8.src.tar.xz",
      sha256 = "9a4e452a8163732d417db067a89190fcda823cb3aa33199e834ac7c028923f4b"
    } | Source,
    base,
    cmake,
    ninja,
    python,
    toolchain,
  ],
  cmd = "./build.sh",
  outputs = {
    usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
    usr_share = { glob = "usr/share/**/*" } | OutputLib,
  },
} | BuildSpec
