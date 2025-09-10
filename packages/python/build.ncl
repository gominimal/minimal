let { BuildSpec, HostPath, OutputLib, Local, Prebuilt, .. } = import "minimal.ncl" in
let expat = import "../expat/build.ncl" in
let openssl = import "../openssl/build.ncl" in
{
  name = "python",
  inputs = [
    { package = "python" } | Prebuilt,
  ],
  runtime_deps = [
    expat,
    openssl,
  ],
  cmd = "",
  outputs = {},
} | BuildSpec
