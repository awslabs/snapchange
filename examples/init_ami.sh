#!/bin/bash

DIRS="01_getpid 02_libtiff 03_ffmpeg_custom_mutator 04_syscall_fuzzer 05_redqueen"

# Init qemu_snapshot for all examples using Linux v5.4 with KASAN
cp -r -L ../fuzzer_template/qemu_snapshot .
pushd qemu_snapshot
./init.sh --kernel-version v5.4 --with-kasan
popd

# Make and snapshot all included examples
for dir in $DIRS; do 
  echo $dir
  pushd $dir
    # Make the example using 
    ./make_example.sh ami > ../stdout.$dir 2>../stderr.$dir

    # Remove the qemu_snapshot used to take the snapshot to preserve space
    sudo rm -rf qemu_snapshot
  popd
done

# Remove the qemu_snapshot from this directory since it is no longer needed
sudo rm -rf qemu_snapshot
