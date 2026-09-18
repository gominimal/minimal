# Run these by hand, one at a time, from the repository root.
# Step 1 needs one administrator password; nothing below prompts again.
cd docs/spikes/2026-09-22-macos-loopback-alias
sudo install -o root -g wheel -m 755 -d /Library/PrivilegedHelperTools /etc/resolver
sudo install -o root -g wheel -m 755 dev.minimal.loopback.sh /Library/PrivilegedHelperTools/dev.minimal.loopback.sh
sudo install -o root -g wheel -m 644 dev.minimal.loopback.plist /Library/LaunchDaemons/dev.minimal.loopback.plist
sudo install -o root -g wheel -m 644 min.internal /etc/resolver/min.internal
sudo launchctl bootstrap system /Library/LaunchDaemons/dev.minimal.loopback.plist
# Immediate check, before any reboot. The job is LaunchOnlyOnce, so launchd drops
# it once it exits and `launchctl print` says "Could not find service"; the log
# line is the evidence. Wait for the 254 ifconfig calls first.
sleep 2
launchctl print system/dev.minimal.loopback 2>&1 | grep -E "state|last exit|Could not find"
ifconfig lo0 | grep -c 127.0.64
cat /var/log/dev.minimal.loopback.log
