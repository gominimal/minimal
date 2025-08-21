#!/bin/bash

echo "let {BuildSpec, HostPath, OutputLib, Local, ..} = import \"minimal.ncl\" in"
echo "let busybox_static = import \"../busybox_static/build.ncl\" in"
echo "{"
echo "    name = \"gcc\","
echo "    inputs = ["
echo "        {file = \"build.sh\"} | Local,"

# All files and symlinks in all directories except usr/share
find prebuilt/usr/bin prebuilt/usr/lib prebuilt/usr/libexec prebuilt/usr/lib/gcc prebuilt/usr/include \( -type f -o -type l \) | sort | while read f; do
    echo "        {file = \"$f\"} | Local,"
done

echo "        busybox_static,"
echo "    ],"
echo "    cmd = \"./build.sh\","
echo "    outputs = {"
echo "        usr = { glob = \"usr/**/*\" } | OutputLib,"
echo "    },"
echo "} | BuildSpec"
