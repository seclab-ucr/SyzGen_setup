# SyzGen
SyzGen: Automated Generation of Syscall Specification of Closed-Source macOS Drivers

Most drivers expose their interfaces through the uniform syscall `IOConnectCallMethod` (ioctl is its counterpart in Linux). SyzGen could learn from traces collected from existing applications that invoke the target driver and then perform symbolic execution to anlyze the driver to produce the syscall specification used by Syzkaller for fuzzing.

## How to install
Please refer to [SyzGen_setup](../../README.md).

## How to run it
Please follow the [instructions](run.md)