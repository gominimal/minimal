let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
let make = import "../make/build.ncl" in
{
    name = "coreutils",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "coreutils-9.7.tar.xz"} | Local,
        {file = "coreutils-9.7-upstream_fix-1.patch"} | Local,
        {file = "coreutils-9.7-i18n-1.patch"} | Local,
        busybox_static,
        make,
    ],
    cmd = "./build.sh",
    outputs = {
        # Core file operations
        ls = { glob = "bin/ls" } | OutputLib,
        cp = { glob = "bin/cp" } | OutputLib,
        mv = { glob = "bin/mv" } | OutputLib,
        rm = { glob = "bin/rm" } | OutputLib,
        mkdir = { glob = "bin/mkdir" } | OutputLib,
        rmdir = { glob = "bin/rmdir" } | OutputLib,
        ln = { glob = "bin/ln" } | OutputLib,
        chmod = { glob = "bin/chmod" } | OutputLib,
        chown = { glob = "bin/chown" } | OutputLib,
        chgrp = { glob = "bin/chgrp" } | OutputLib,
        
        # Text utilities
        cat = { glob = "bin/cat" } | OutputLib,
        head = { glob = "bin/head" } | OutputLib,
        tail = { glob = "bin/tail" } | OutputLib,
        sort = { glob = "bin/sort" } | OutputLib,
        uniq = { glob = "bin/uniq" } | OutputLib,
        cut = { glob = "bin/cut" } | OutputLib,
        tr = { glob = "bin/tr" } | OutputLib,
        wc = { glob = "bin/wc" } | OutputLib,
        
        # System utilities
        date = { glob = "bin/date" } | OutputLib,
        whoami = { glob = "bin/whoami" } | OutputLib,
        id = { glob = "bin/id" } | OutputLib,
        pwd = { glob = "bin/pwd" } | OutputLib,
        uname = { glob = "bin/uname" } | OutputLib,
        
        # All binaries (catch remaining utilities)
        all_binaries = { glob = "bin/*" } | OutputLib,
        
        # Library and documentation
        libstdbuf = { glob = "lib/coreutils/libstdbuf.so" } | OutputLib,
        man_pages = { glob = "share/man/man1/*.1" } | OutputLib,
        info_pages = { glob = "share/info/*.info*" } | OutputLib,
        locale_files = { glob = "share/locale/*/LC_MESSAGES/*.mo" } | OutputLib,
    },
} | BuildSpec