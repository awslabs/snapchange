# Design of this snapshot mechanism

A snapshot fuzzer relies on a few key components to aid in fuzzing:

* A physical memory dump
* A register state during execution of the target
* (Optional) Debug symbols and memory layout information

To aid in the first two components, a small patch is applied to QEMU. This patch modifies
the `vmcall` instruction to write the physical memory and register state to disk upon
execution as well as a few system registers which help hypervisor-based snapshot fuzzers.

For the third bullet point, a gdb script is provided to write symbol information, memory
map, and the found modules loaded at the time of the snapshot. This information can help
a fuzzer provide more verbose feedback for the developer/researcher when running a given
fuzz case.

## Execution

An image is built using a modified [Syzkaller](https://github.com/google/syzkaller/blob/master/tools/create-image.sh)
`create-image.sh` script to bootstrap a Debian image.

To execute the target, the `/etc/rc.local` startup script is utilized. This script will
run at the end of the boot process before login. Leveraging this script allows the
process to not require further input once the image is booting.

To prepare the image, the target is added to the `/root` directory along with the `gdb`
script and commands to execute in the image. The `IMAGE/build.sh` script provides a base
for how this process can work, but could be modified for more elaborate targets. The base
script copies a given target into the image and writes a simple `/etc/rc.local` script 
executing the target under `gdb` with the included gdbscript. Further modification could
be include more files in the `chroot` directory before building the image or modifying
the `/etc/rc.local` script to execute the specific commands needed to execute the target.

The `gdb` setup assumes the following "snapshot point" has been added to the target:

```
__asm("int3 ; vmcall");
```

In this way, the gdbscript waits for an `int3` and calls the `gdbsnapshot.py` script when
triggered. Once the script is finished, the `vmcall` instruction is executed, allowing
the modified QEMU to write the physical memory and register state to disk. Once this is
completed, the binary exits and the boot process finishes.

Once the login prompt is displayed, the `utils/extract.sh` can be used to mount the
current image and extract the files written by the `gdbsnapshot.py` script. With the
debug symbols extracted, the `utils/kill.sh` can be used to kill the running VM.
