let { BuildSpec, Local, OutputData, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
let openssl = import "../openssl/build.ncl" in
{
  name = "ca-certificates",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/ssl-certs-complete.tar.gz",
      sha256 = "4b080b63089e05eede8f2f653c6b8329d2a8332285b393bb7844dc8c8d9d062d"
    } | Source,
    base,
    openssl,
  ],
  cmd = "./build.sh",
  outputs = {
    certs = { glob = "etc/ssl/certs/*" } | OutputData,
  },
} | BuildSpec
