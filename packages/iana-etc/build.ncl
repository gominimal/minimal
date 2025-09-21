let { BuildSpec, Local, OutputLib, Source, .. } = import "minimal.ncl" in
let base = import "../base/build.ncl" in
{
  name = "iana-etc",
  inputs = [
    { file = "build.sh" } | Local,
    {
      url = "gs://minimal-staging-archives/iana-etc-20250618.tar.gz",
      sha256 = "432d475ea36aa3f18fe709878e6f1e4e894efc5e92a8ee0bee0756b792ac2160"
    } | Source,
    base,
  ],
  cmd = "./build.sh",
  outputs = {
    protocols = { glob = "etc/protocols" } | OutputLib,
    services = { glob = "etc/services" } | OutputLib,
  },
} | BuildSpec
