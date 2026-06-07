let { BuildSpec, Local, OutputData, upstream, .. } = import "minimal.ncl" in
{
  name = "minvmd-rootfs",

  # No source tarball: this package composes the guest userland from the
  # closure of its build_deps and packs it into an ext4 image. e2fsprogs
  # provides mke2fs at build time (it is not meant for the guest, but is
  # harmless if it ends up in the image). socat is the bring-up workload's
  # only hard requirement; bash + coreutils provide /bin/sh and the
  # printf/sleep/test the stub init uses.
  build_deps = [
    { file = "build.sh" } | Local,
    upstream "socat",
    upstream "bash",
    upstream "coreutils",
    upstream "e2fsprogs",
  ],

  cmd = "./build.sh",

  outputs = {
    # A raw ext4 image, loaded by minvmd via krun_add_disk2 (root=/dev/vda).
    rootfs = { glob = "usr/share/minvmd-rootfs/rootfs.img" } | OutputData,
  },
} | BuildSpec
