# A snapshot mechanism using QEMU

This repository provides a method to gather a target snapshot for the use in a snapshot
fuzzer leveraging a slightly modified QEMU. In depth explanation can be found [here](./DESIGN.md).

This mechanism assumes an `int3 ; vmcall` instruction sequence is in the target
application at the location where the snapshot is wanting to be taken.

# Setup

Quick setup of the kernel, QEMU, and basic debian image.

```console
$ ./init.sh
```

With the basics built, the target needs to be inserted into the image in preparation for
the snapshot.

### Build the image with the target

Use the `IMAGE/build.sh` script to add the target to the image and write the setup script
to execute on boot.

```console
$ cd IMAGE
$ ./build.sh ../example/example1
```

Another example, the target is `target` and the snapshot test case is called `input`:

```console
$ cd IMAGE
$ ./build /path/to/target /path/to/input
```

This will copy the binary and input test case into the image to be used by the boot
startup script.

### Snapshot using the built image

Executing the following script will execute the image, writing the snapshot into `output`.

```console
./snapshot.sh
```

After exectution, the following files should be available for use in a snapshot fuzzer.

```text
[*] Found the following files
total 2167516
drwxrwxr-x  2 ubuntu ubuntu       4096 Jun 15 18:03 .
drwxrwxr-x  9 ubuntu ubuntu       4096 Jun 15 18:03 ..
-rw-rw-r--  1 ubuntu ubuntu 2147483647 Jun 15 18:03 fuzzvm.physmem
-rw-rw-r--  1 ubuntu ubuntu       2359 Jun 15 18:03 fuzzvm.qemuregs
-rw-r--r--. 1 ubuntu ubuntu        111 Jun 15 18:03 gdb.modules
-rw-r--r--. 1 ubuntu ubuntu    8887461 Jun 15 18:03 gdb.symbols
-rw-r--r--. 1 ubuntu ubuntu       1703 Jun 15 18:03 gdb.vmmap
-rwxrwxr-x  1 ubuntu ubuntu   70355488 Jun 15 18:03 vmlinux

[*] Found this SNAPSHOT output from the vm log
[   17.827279] rc.local[221]: SNAPSHOT Data buffer: 0x7fffffffec70 Pid: 0x7fffffffec6c
```

# Explanation

Further explanation of the `init.sh` script.

## Linux for snapshotting

Download the kernel repo and create the config

```text
$ git clone https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
$ cd linux
$ make defconfig
```

Add options needed for the debian bootstrap image. Also add options for adding debug information
to the kernel and non-relocatable base address.

```text
$ echo CONFIG_CONFIGFS_FS=y       >> .config
$ echo CONFIG_SECURITYFS=y        >> .config
$ echo CONFIG_DEBUG_INFO=y        >> .config
$ echo CONFIG_DEBUG_INFO_DWARF4=y >> .config
$ echo CONFIG_RELOCATABLE=n       >> .config
$ echo CONFIG_RANDOMIZE_BASE=n    >> .config
```

Build the kernel

```console
$ make -j`nproc`
```

## Patch QEMU for snapshotting on vmcall

Ensure `Ninja` is installed

```console
$ sudo apt install ninja-build
```

Download and apply the QEMU patch enabling writing physical memory and register state on
`vmcall` instruction.

``` console
$ git clone https://github.com/qemu/QEMU
$ cd QEMU
$ git am ../0001-Snapchange-patches.patch
```

Buid the patched qemu for `x86_64`

```console
$ mkdir build
$ cd build
$ ../configure --target-list=x86_64-softmmu --enable-system
$ make -j`nproc`
```

## Bootstrap Debian

A modified
[Syzkaller](https://github.com/google/syzkaller/blob/master/tools/create-image.sh)
`create-image.sh` script to bootstrap a Debian image. This image is used as the base to 
execute the target when creating the snapshot.
