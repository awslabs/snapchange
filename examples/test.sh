#!/bin/bash

# DIRS="01_getpid 02_libtiff 03_ffmpeg_custom_mutator 04_syscall_fuzzer 05_redqueen 06_custom_feedback"
DIRS="01_getpid 02_libtiff 04_syscall_fuzzer 05_redqueen 06_custom_feedback 07_libfuzzer"

# Make and test all included examples
for dir in $DIRS; do 
  echo Testing $dir
  pushd $dir >/dev/null
    # Create the snapshot for this example or reset the snapshot for testing
    if ! [ -d ./snapshot ]; then 
      ./make_snapshot.sh
    else 
      pushd ./snapshot >/dev/null
      ./reset.sh
      popd >/dev/null
    fi

    # Test this example
    ./test.sh

    # Check the result of this test
    STATUS=$?
  popd >/dev/null

  if [ "$STATUS" -gt 0 ]; then
    echo "Test $dir failed!"
    exit 1
  fi
done
