let { BuildSpec, Local, OutputBin, OutputData, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
let variants = {
  "1.25.1" = {
    binaries_url = "https://go.dev/dl/go1.25.1.linux-amd64.tar.gz",
    binaries_sha256 = "7716a0d940a0f6ae8e1f3b3f4f36299dc53e31b16840dbd171254312c41ca12e",

    source_url = "https://go.dev/dl/go1.25.1.src.tar.gz",
    source_sha256 = "d010c109cee94d80efe681eab46bdea491ac906bf46583c32e9f0dbb0bd1a594",
  },
}
in
let version = "1.25.1" in
{
  name = "go",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = variants."%{version}".binaries_url,
      sha256 = variants."%{version}".binaries_sha256,
    } | Source,
    {
      url = variants."%{version}".source_url,
      sha256 = variants."%{version}".source_sha256,
    } | Source,
    base,
    toolchain,
  ],

  cmd = "./build.sh",
  build_args = {
    include version,
  },

  outputs = {
    go_bin = { glob = "usr/bin/go" } | OutputBin,
    gofmt_bin = { glob = "usr/bin/gofmt" } | OutputBin,

    goroot = { glob = "usr/go/**/*" } | OutputData,
  },
} | BuildSpec
