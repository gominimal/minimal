let {BuildSpec, HostPath, OutputLib, Local, Source, ..} = import "minimal.ncl" in
let bash = import "../bash/build.ncl" in
let coreutils = import "../coreutils/build.ncl" in
let diffutils = import "../diffutils/build.ncl" in
let gawk = import "../gawk/build.ncl" in
let grep = import "../grep/build.ncl" in
let gzip = import "../gzip/build.ncl" in
let make = import "../make/build.ncl" in
let sed = import "../sed/build.ncl" in
let tar = import "../tar/build.ncl" in
let toolchain = import "../toolchain/build.ncl" in
{
    name = "ncurses",
    inputs = [
        {file = "build.source.sh"} | Local,
        {
            url = "gs://minimal-staging-archives/ncurses-6.5-20250830.tgz",
            sha256 = "519ec9f748d7f2873cf763394fc766a701967439610125ad0fbf76ab2c7510a5"
        } | Source,
        bash,
        coreutils,
        diffutils,
        gawk,
        grep,
        gzip,
        make,
        sed,
        tar,
        toolchain,
    ],
    cmd = "./build.source.sh",
    outputs = {
        bin = { glob = "usr/bin/*" } | OutputLib,
        form_lib = { glob = "usr/lib/libform*.so*" } | OutputLib,
        include = { glob = "usr/include/*" } | OutputLib,
        libraries = { glob = "usr/lib/libncurses*.so*" } | OutputLib,
        menu_lib = { glob = "usr/lib/libmenu*.so*" } | OutputLib,
        panel_lib = { glob = "usr/lib/libpanel*.so*" } | OutputLib,
        pkgconfig = { glob = "usr/lib/pkgconfig/*.pc" } | OutputLib,
        tabset = { glob = "usr/share/tabset/*" } | OutputLib,
        terminfo_lib = { glob = "usr/lib/terminfo/**/*" } | OutputLib,
        terminfo_share = { glob = "usr/share/terminfo/**/*" } | OutputLib,
    },
} | BuildSpec
