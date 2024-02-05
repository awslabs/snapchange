# Bundling QEMU-based snapshotting in docker

### Step 1: Prepare your root FS

You can utilize docker to prepare your root filesystem for snapchange's snapshoting mechanism. If you already have a Dockerfile for your application then you should be able to re-use that.
We recommend to keep that you keep the root filesystem as small as possible.

For example, to create a snapshot for a simple hello world program in C you can utilize a `Dockerfile` akin to this:

```Dockerfile
FROM alpine:edge as base

# install dependencies (gdb and python3 are required for snapshoting)
RUN apk add --no-cache --initramfs-diskless-boot python3 gdb build-base

# copy source code and invoke make
COPY ./src/ /opt/
RUN cd /opt/ && make clean && make

[...]
```

#### Harness Root Filesystem Requirements

* **You must install gdb with python inside of your root filesystem.**
    * We use gdb with a custom gdb script to obtain symbols of the snapshot'ed binary.
* For best results, make sure that symbols are available for your target binary and all loaded library.
    * Ubuntu works out-of-the-box as they ship a libc with symbols.
    * For alpine we found that `apk --no-cache upgrade && apk add --no-cache --initramfs-diskless-boot python3 gdb build-base musl-dbg` works best.


### Step 2: Prepare the snapshoting container

Now that we have prepared a root filesystem, we can now build the snapshoting container. In the same `Dockerfile`, you can now specify the snapshot parameters.
First, you switch to the snapchange docker image and then copy the root filesystem from the previous step to the snapchange container.

```Dockerfile
[...]

FROM snapchange

COPY --from=base / "$SNAPSHOT_INPUT"
```

And you are almost done. Now you just need to specify the "entry point" to your
fuzzing image, i.e., the program that you want to fuzz. You do this by
specifying the environment variable `SNAPSHOT_ENTRYPOINT`.

You can do this by adding the following to your `Dockerfile`:

```Dockerfile
env SNAPSHOT_ENTRYPOINT="/full/path/to/your/binary"
```

You can also specify this on the docker commandline with `-e SNAPSHOT_ENTRYPOINT=...`.


#### Snapchange Snapshoting Options

There are several environment options that control how snapchange creates a snapshot.

* `SNAPSHOT_IMGTYPE` - can be either `initramfs` or `disk`.
    * `initramfs` enables reading/writing from the rootfs. The whole rootfs will be kept in RAM and will be reset by snapchange. Caveat: all files will be owned by `root:root`.
    * `disk` creates a disk image to boot from. Currently, snapchange does not handle devices and will stop execution on disk read/writes. You will need to add your own hooks to handle disk i/o in snapchange.
* `SNAPSHOT_ENTRYPOINT` - **REQUIRED** full path to the binary that is being fuzzed/snapshotted.
* `SNAPSHOT_ENTRYPOINT_ARGUMENTS=""` - cli arguments passed to the snapshot entry point.
* `SNAPSHOT_ENTRYPOINT_CWD` - working directory of the snapshot entrypoint.
* `SNAPSHOT_USER="root"` - the user that runs the binary within the image. Make sure the user exists in the harness docker image.
* `SNAPSHOT_EXTRACT=""` - a space separated list of paths to extract from the image to the snapshot directory (e.g., use libraries, additional binaries, etc.).
  * for example: `SNAPSHOT_EXTRACT="/etc/fstab /usr/lib/libc.so"`
* `SNAPSHOT_INPUT="/image/"` - the path where the snapshot input is stored. Ususally you don't need to change that.
* `SNAPSHOT_CHOWN_TO="1000"` - the snapshot is `chown -R`'ed for convenience. Set to `""` to disable.
* to specify a custom kernel:
  * `SNAPSHOT_KERNEL_IMG` - path to bootable kernel image ("bzimage") passed to qemu's direct kernel boot.
  * `SNAPSHOT_KERNEL_ELF` - path to unstripped kernel ELF file - used to lookup kernel symbols.
* `SNAPSHOT_ENV` - a space separate list of `VAR=val` pairs that are exported as environment variables before launching the harness.
* `SNAPSHOT_RUN_BEFORE` - line of shell commands executed before the target is started.
* `SNAPSHOT_RUN_AFTER` - line of shell commands executed after the target was started.
* `SNAPSHOT_CUSTOM_LAUNCH_SCRIPT` - provide a shell script or binary to launch your target. Runs as root.
    * Using this will disregard most other environment variables related to launching the target: `SNAPSHOT_ENTRYPOINT`, `SNAPSHOT_ENTRYPOINT_ARGUMENTS`, `SNAPSHOT_USER`.
    * You can still use the standard gdb commands like this: `gdb --batch --command=/snapchange/snapshot.gdbcmds --args your_binary --first-arg`
* `SNAPSHOT_CUSTOM_GDBCMDS` - use this if you need to customize the commands executed by gdb for your target.
    * Use the gdb command `source /snapchange/gdbsnapshot.py` once you hit the snapshot breakpoint.
* `SNAPSHOT_GDB_MODE` - can be set to
    * `"quit"` (default) - forcefully stop the target with gdb after the snapshot has been taken.
        * Use this when your target is looping forever waiting for input that is not present (e.g., stdin input).
        * Disadvantage: gdb is present in the snapshot, which can lead to issues when a gdb-set breakpoint is hit during fuzzing.
        * Advantage: compatible with most targets.
    * `"detach"` - gdb detaches from the target before the snapshot is triggered.
        * Use this when your target naturally exits, e.g., you provide a sensible default input in the snapshot.
        * Advantage: gdb will detach before the snapshot is taken and is not present in the snapshot.
        * Disadvantage: not applicable to all targets.

The following environment variables can be used to control coverage breakpoint
analysis in the docker container.
        
* `GENERATE_COVERAGE_BREAKPOINTS` - (defaults to 1) set to 0 to disable automatic coverage breakpoint generation with one of the coverage scripts.
* `COVERAGE_BREAKPOINT_COMMAND` - configure the coverage script used.
    * Set to `ghidra`, `angr`, `binaryninja`, or `rizin` to use one of the scripts we ship. We recommend `ghidra` (the default), but other script might offer 
      better (or worse) analysis results. For example, `angr` supports automatically generating a basic fuzzing dictionary from the binary.
    * Can be set to a custom command to obtain coverage breakpoints.
    * `binaryninja` generally offers the best results and also enables the use of redqueen. However, this requires putting binary ninja and a valid commercial license into the container.
* `COVERAGE_BREAKPOINTS_EXTRA_BINS` - a space separated list of extra binaries (or rather libraries) to analyze for coverage breakpoints.
    * This is especially useful if your target dynamically links to a library that is interesting to you.
    * If you also use `SNAPSHOT_EXTRACT`, make sure that the files listed here are also contained in the `SNAPSHOT_EXTRACT` paths.
 
There are some more exotic options that you can pass to the snapshot script.

* `LIBFUZZER=0` - set to 1 to enable special handling of creating snapshots from libfuzzer fuzzing harnesses.
* `KASAN=0` - set to 1 to use a KASAN-enabled kernel.
* `TEMPLATE_OUT="/out/"` - if you run the container with `template` as first argument, it will copy a rust fuzzer template into this directory.
