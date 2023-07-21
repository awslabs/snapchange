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

* `SNAPSHOT_ENTRYPOINT` - **REQUIRED** full path to the binary that is being fuzzed/snapshotted.
* `SNAPSHOT_ENTRYPOINT_ARGUMENTS=""` - cli arguments passed to the snapshot entry point
* `SNAPSHOT_USER="root"` - the user that runs the binary.
* `SNAPSHOT_EXTRACT=""` - a space separated list of paths to extract along with the snapshotting (e.g., additional binaries etc.)
  * for example: `SNAPSHOT_EXTRACT="/etc/fstab /usr/lib/libc.so"`
* `SNAPSHOT_INPUT="/image/"` - the path where the snapshot input is stored. Ususally you don't need to change that.
* `SNAPSHOT_CHOWN_TO="1000"` - the snapshot is `chown -R`'ed for convenience. Set to `""` to disable.
* to specify a custom kernel:
  * `SNAPSHOT_KERNEL_IMG` - path to bootable kernel image ("bzimage") passed to qemu's direct kernel boot.
  * `SNAPSHOT_KERNEL_ELF` - path to unstripped kernel ELF file - used to lookup kernel symbols.

There are some more specialized options that you can pass to the snapshoting.

* `LIBFUZZER=0` - set to 1 to enable special handling of creating snapshots from libfuzzer fuzzing harnesses.
* `KASAN=0` - set to 1 to use a KASAN-enabled kernel.
* `TEMPLATE_OUT="/out/"` - if you run the container with `template` as first argument, it will copy a rust fuzzer template into this directory.
