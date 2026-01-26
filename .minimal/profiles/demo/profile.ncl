let {profile, ..} = import "minimal.ncl" in
profile {
    name = "demo",

    env_vars.CC = "gcc",

    packages = [
        # Build needs
        "gcc", "binutils", "python",
        "pkgconf", "openssl", "linux_headers", "zlib",
        # Shell
        "base", "bash",
        "git", "coreutils",
        # Vim
        "vim", "btop",
    ],
}
