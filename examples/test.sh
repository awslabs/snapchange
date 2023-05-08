#!/bin/bash

DIRS="01_getpid 02_libtiff 03_ffmpeg_custom_mutator 04_syscall_fuzzer"

# Make and test all included examples
for dir in $DIRS; do 
  echo $dir
  pushd $dir
    ./reset.sh
    ./make_example.sh
  popd
done

for dir in $DIRS; do
  pushd $dir
    ./test.sh
  popd
done
