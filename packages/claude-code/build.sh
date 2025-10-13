#!/bin/sh
set -e

chmod -v +x claude

mkdir -pv $OUTPUT_DIR/usr/{bin,share/claude/versions}
mv -v claude $OUTPUT_DIR/usr/share/claude/versions/$MINIMAL_ARG_VERSION

cat > "${OUTPUT_DIR}/usr/bin/claude" << EOF
#!/bin/bash
DISABLE_AUTOUPDATER=1 exec /usr/share/claude/versions/$MINIMAL_ARG_VERSION "\$@"
EOF

chmod -v +x "${OUTPUT_DIR}/usr/bin/claude"
