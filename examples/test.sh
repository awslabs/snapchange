#!/bin/bash

DIRS="01_getpid 02_libtiff 03_ffmpeg_custom_mutator 04_syscall_fuzzer 05_redqueen 06_custom_feedback"

# Make and test all included examples
for dir in $DIRS; do 
  echo Testing $dir
  pushd $dir >/dev/null
    if ! [ -d ./snapshot ]; then 
      ./make_example.sh
    else 
      pushd ./snapshot >/dev/null
      ./reset.sh
      popd >/dev/null
    fi

    ./test.sh
  popd >/dev/null
done
