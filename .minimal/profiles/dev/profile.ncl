let { profile, .. } = import "minimal.ncl" in
profile {
  name = "dev",
  from_profile = "rust", # inherit from upstream 'rust' profile

  packages = [
    # Additional build needs
    "pkgconf",
    "openssl",
    "linux_headers",
    "zlib",
    "protobuf",
    # Shell and claude-code needs
    "base",
    "bash",
    "claude-code",
    "git",
    "skopeo",
    "coreutils",
  ],
}
