let {BuildSpec, HostPath, OutputLib, Local, Prebuilt, ..} = import "minimal.ncl" in
let acl = import "../acl/build.ncl" in
let libcap = import "../libcap/build.ncl" in
{
    name = "coreutils",
    inputs = [
        {package = "coreutils"} | Prebuilt,
    ],
    runtime_deps = [
        acl,
        libcap,
    ],
    cmd = "",
    outputs = {
        # Core file operations
        ls = { glob = "usr/bin/ls" } | OutputLib,
        cp = { glob = "usr/bin/cp" } | OutputLib,
        mv = { glob = "usr/bin/mv" } | OutputLib,
        rm = { glob = "usr/bin/rm" } | OutputLib,
        mkdir = { glob = "usr/bin/mkdir" } | OutputLib,
        rmdir = { glob = "usr/bin/rmdir" } | OutputLib,
        ln = { glob = "usr/bin/ln" } | OutputLib,
        chmod = { glob = "usr/bin/chmod" } | OutputLib,
        chown = { glob = "usr/bin/chown" } | OutputLib,
        chgrp = { glob = "usr/bin/chgrp" } | OutputLib,
        
        # Text utilities
        cat = { glob = "usr/bin/cat" } | OutputLib,
        head = { glob = "usr/bin/head" } | OutputLib,
        tail = { glob = "usr/bin/tail" } | OutputLib,
        sort = { glob = "usr/bin/sort" } | OutputLib,
        uniq = { glob = "usr/bin/uniq" } | OutputLib,
        cut = { glob = "usr/bin/cut" } | OutputLib,
        tr = { glob = "usr/bin/tr" } | OutputLib,
        wc = { glob = "usr/bin/wc" } | OutputLib,
        
        # System utilities
        date = { glob = "usr/bin/date" } | OutputLib,
        whoami = { glob = "usr/bin/whoami" } | OutputLib,
        id = { glob = "usr/bin/id" } | OutputLib,
        pwd = { glob = "usr/bin/pwd" } | OutputLib,
        uname = { glob = "usr/bin/uname" } | OutputLib,
        
        # All binaries (catch remaining utilities)
        all_binaries = { glob = "usr/bin/*" } | OutputLib,
        
        # Library and documentation
        libstdbuf = { glob = "usr/libexec/coreutils/libstdbuf.so" } | OutputLib,
        man_pages = { glob = "usr/share/man/man1/*.1" } | OutputLib,
        info_pages = { glob = "usr/share/info/*.info*" } | OutputLib,
        locale_files = { glob = "usr/share/locale/**/*" } | OutputLib,
    },
} | BuildSpec
