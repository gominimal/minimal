let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let make = import "../make/build.ncl" in
let grep = import "../grep/build.ncl" in
let bash = import "../bash/build.ncl" in
let tar = import "../tar/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let sed = import "../sed/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
{
    name = "ncurses",
    inputs = [
        {file = "build.sh"} | Local,
        {file = "ncurses-6.5.tar.gz"} | Local,
        make,
        grep,
        bash,
        tar,
        gzip,
        sed,
        coreutils,
        gawk,
    ],
    cmd = "./build.sh",
    outputs = {
        binaries = { glob = "usr/bin/*" } | OutputLib,

        libraries = { glob = "usr/lib/libncurses*.so*" } | OutputLib,
        form_lib = { glob = "usr/lib/libform*.so*" } | OutputLib,
        panel_lib = { glob = "usr/lib/libpanel*.so*" } | OutputLib,
        menu_lib = { glob = "usr/lib/libmenu*.so*" } | OutputLib,
        pkgconfig = { glob = "usr/lib/pkgconfig/*.pc" } | OutputLib,
        terminfo_lib = { glob = "usr/lib/terminfo/**/*" } | OutputLib,

        headers = { glob = "usr/include/*.h" } | OutputLib,

        manpages = { glob = "usr/share/man/man*/*" } | OutputLib,
        tabset_share = { glob = "usr/share/tabset/*" } | OutputLib,
        terminfo_share = { glob = "usr/share/terminfo/**/*" } | OutputLib,
    },
} | BuildSpec
