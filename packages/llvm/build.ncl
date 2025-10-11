let { BuildSpec, Local, OutputLib, Prebuilt, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let cmake = import "../cmake/build.ncl" in
let libffi = import "../libffi/build.ncl" in
let ninja = import "../ninja/build.ncl" in
let python = import "../python/build.ncl" in
let toolchain-gnullvm = import "../toolchain-gnullvm/build.ncl" in
let glibc = import "../glibc/build.ncl" in
let gcc = import "../gcc/build.ncl" in
let zlib = import "../zlib/build.ncl" in

{
  name = "llvm",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/clang-20.1.8.src.tar.xz",
      sha256 = "b7a1b7b0af7b9c7596af6bd46e36d11321926eaa66a7a7dc957ab0a1375ee4b0"
    } | Source,
    {
      url = "gs://minimal-staging-archives/cmake-20.1.8.src.tar.xz",
      sha256 = "3319203cfd1172bbac50f06fa68e318af84dcb5d65353310c0586354069d6634"
    } | Source,
    {
      url = "gs://minimal-staging-archives/compiler-rt-20.1.8.src.tar.xz",
      sha256 = "15277402f6fd63397c0917a5c7171cda82d16d226094b828c1ed0f58f73b9c69"
    } | Source,
    {
      url = "gs://minimal-staging-archives/llvm-20.1.8.src.tar.xz",
      sha256 = "e1363888216b455184dbb8a74a347bf5612f56a3f982369e1cba6c7e0726cde1"
    } | Source,
    {
      url = "gs://minimal-staging-archives/third-party-20.1.8.src.tar.xz",
      sha256 = "9a4e452a8163732d417db067a89190fcda823cb3aa33199e834ac7c028923f4b"
    } | Source,
    base,
    cmake,
    ninja,
    python,
    toolchain-gnullvm,
  ],
  runtime_deps = [
    glibc,
    libffi,
    gcc, # TODO: Only need libgcc_s.so.1, libstdc++.so.6
    zlib,
  ],

  cmd = "./build.sh",
  outputs = {
    usr = { glob = "usr/**/*" } | OutputLib,
  },

  replace_on_cycle =
    {
      name = "llvm (prebuilt)",
      inputs = [
        { package = "llvm" } | Prebuilt,
      ],
      cmd = "",
      outputs = {},
    } | BuildSpec,
} | BuildSpec
