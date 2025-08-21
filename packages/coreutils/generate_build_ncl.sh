#!/bin/bash

cat > build.ncl << 'EOF'
let {BuildSpec, HostPath, OutputLib, Local, ..} = import "minimal.ncl" in
let busybox_static = import "../busybox_static/build.ncl" in
{
    name = "coreutils",
    inputs = [
        {file = "build.sh"} | Local,
EOF

find prebuilt -type f | sort | while read -r file; do
    echo "        {file = \"$file\"} | Local," >> build.ncl
done

cat >> build.ncl << 'EOF'
        busybox_static,
    ],
    cmd = "./build.sh",
    outputs = {
        usr_bin = { glob = "usr/bin/**/*" } | OutputLib,
        usr_libexec = { glob = "usr/libexec/**/*" } | OutputLib,
        usr_share = { glob = "usr/share/**/*" } | OutputLib,
    },
} | BuildSpec
EOF

echo "Generated build.ncl for coreutils package with $(find prebuilt -type f | wc -l) files"
