#! /bin/bash

set -e

if [[ $(vmrun list) == "Total running VMs: 0" ]]; then
  echo "start the VM first" && exit 1
fi

vmpath=$(vmrun list | sed -n '2p')
echo "get vmpath ${vmpath}"
ip=$(vmrun getGuestIPAddress "${vmpath}" -wait)
echo "get vm ip address ${ip}"

cat << EOF > config
{
  "syzkaller": "${GOPATH}/src/github.com/google/syzkaller",
  "vmpath": "${vmpath}",
  "kernel": "to/be/filled"
  "user": "wchen130",
  "ip": "${ip}",
  "dead": {},
  "waypoint": {},
  "funcWithZero": {},
  "funcWithOne": {},
  "entitlements": [
    "com.apple.private.iowatchdog.user-access",
    "com.apple.private.applehda.user-access",
    "com.apple.private.audio.driver-host",
    "com.apple.hid.system.user-access-service",
    "com.apple.hid.system.server-access",
    "com.apple.iokit.CoreAnalytics.user",
    "com.apple.private.applegraphicsdevicecontrol",
    "com.apple.private.gpuwrangler",
    "com.apple.private.KextAudit.user-access",
    "com.apple.private.security.AppleImage4.user-client",
    "com.apple.private.applecredentialmanager.allow",
    "com.apple.private.diskimages.kext.user-client-access",
    "com.apple.private.applesse.allow",
    "com.apple.private.timesync.clock-testing",
    "com.apple.hid.system.user-access-fast-path",
    "com.apple.private.applesmc.user-access",
    "com.apple.private.timesync.edge-generate",
    "com.apple.private.timesync.edge-capture",
    "com.apple.hid.manager.user-access-protected",
    "com.apple.private.applefdekeystore.readpassphrase",
    "com.apple.private.securityd.stash",
    "com.apple.private.securityd.keychain",
    "com.apple.private.applefdekeystore.deletepassphrase",
    "com.apple.private.storage.revoke-access",
    "com.apple.keystore.filevault",
    "com.apple.bluetooth.iokit-user-access",
    "com.apple.vm.device-access"
  ]
}
EOF

echo "Note you need to replace the ssh user!"
echo "Note you need to replace the kernel"