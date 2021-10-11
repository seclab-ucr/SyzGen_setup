
## Setup VM
Please follow this [artical](https://ddeville.me/2015/08/kernel-debugging-with-lldb-and-vmware-fusion/) to setup the vm. In summary:
```
1. Run sw_vers | grep BuildVersion to determine your build version.
2. Download the appropriate Kernel Debug Kit from [Apple](https://developer.apple.com/download/more).
3. Install the KDK package.
4. Reboot to the Recovery System by restarting your target machine and hold down the Command and R keys at startup.
5. From the Utilities menu, select Terminal.
6. Type, csrutil disable to disable System Integrity Protection.
7. reboot
8. sudo mount -uw /
8. sudo cp /Library/Developer/KDKs/<KDK Version>/System/Library/Kernels/kernel.development /System/Library/Kernels/
9. sudo kextcache -invalidate /Volumes/<Target Volume>
10. sudo nvram boot-args="debug=0x144 kcsuffix=development -v pmuflags=1 amfi_get_out_of_my_way=0x1 kext-dev-mode=1"
11. sudo reboot
12. Virtual Machine -> install VMware Tools
```

Please note that for unknown reason, the kernel often fails to suspend all cpus before communicating with debugger and thus results in panic. One simple solution is to use one cpu core.
 
Setup root user following this [doc](https://support.apple.com/en-us/HT204012) (It is optional if you don't need to test module with root privilege).

Afterwards, we need to setup ssh as follows.
```
Go to System Preference --> Sharing --> Enable Remote Login
```
Remember to add all your users to the list. Also, we need to edit `/private/etc/ssh/sshd_config` to enable the following:
```
PermitRootLogin yes
```

Allow ssh without password
```
mkdir -p $HOME/.ssh
chmod 0700 $HOME/.ssh
vim ~/.ssh/authorized_keys  // Add your public key to this file
```

Allow sudo without password if you didn't enable root user.
```
sudo visudo
```

And then edit the line `%admin ALL=(ALL) ALL` to `%admin ALL=(ALL) NOPASSWD: ALL`

### Config
Make sure your VM is running and run the following command to generate a config file:
`./scripts/genConfig.sh`

To model some trivial functions without coding, we can simply add them to the config. For now, we only support substitute a function with dummy model returning zero or one (True/False).

For example, we know there is a check in the driver AppleFDEKeyStore. To bypass it, we can simply add the function address (offset) and its bundle id to the config as follows:
```
"funcWithOne": {
  "com.apple.driver.AppleFDEKeyStore": [15516]
},
```

To avoid path explosion or functions that cannot be handled (e.g., interaction with hardware), we can add exit points to the field `dead` with the same format as `funcWithOne`. 

### Bypass Signature Check
Try `nvram boot-args` to get original boot args and then add one more `amfi_get_out_of_my_way=0x1` if you didn't do it eariler.

### GDB
[macOS with GDB](https://ddeville.me/2015/08/using-the-vmware-fusion-gdb-stub-for-kernel-debugging-with-lldb/)

[GDB to lldb](http://lldb.llvm.org/use/map.html)

[KDP](https://blog.quarkslab.com/an-overview-of-macos-kernel-debugging.html)

[kernel programming](http://3.droppdf.com/files/mJdlB/os-x-and-ios-kernel-programming.pdf)