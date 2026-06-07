let { BuildSpec, Local, OutputData, upstream, .. } = import "minimal.ncl" in
{
  name = "virtio-kernel-raw",

  # Decompress the upstream virtio-linux kernel (Image.gz) to a raw Image.
  # libkrun loads a raw aarch64 Image via KRUN_KERNEL_FORMAT_RAW, skipping the
  # in-VMM gzip decompress that dominated boot-to-READY (~77 ms of ~146 ms).
  build_deps = [
    { file = "build.sh" } | Local,
    upstream "virtio-linux",
    upstream "gzip",
    upstream "bash",
    upstream "coreutils",
  ],

  cmd = "./build.sh",

  outputs = {
    image = { glob = "usr/share/virtio-linux/Image" } | OutputData,
  },
} | BuildSpec
