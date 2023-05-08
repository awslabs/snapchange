#!/bin/bash

example3() {
  echo "Testing Example 03"

  # Reset the snapshot
  pushd snapshot > /dev/null
  ./reset.sh
  popd > /dev/null

  # Rebuild the fuzzer
  echo "Building Example 03"
  cargo build -r 2>/dev/null >/dev/null

  # Start the fuzzers
  echo "Begin fuzzing!"
  timeout 300s cargo run -r -- fuzz -c 92 --ascii-stats 2>/dev/null >/dev/null &

  # If we find a crash early, kill the fuzzer
  for i in $(seq 0 300); do
    ls snapshot/crashes/ASAN_WRITE* >/dev/null 2>/dev/null
    STATUS=$?
    if [ "$STATUS" -eq 0 ]; then
      break
    fi
    sleep 1
  done

  # Kill the example 03 fuzzers
  ps -ef | rg Example03 | tr -s ' ' | cut -d' ' -f2 | xargs kill -9 2>/dev/null >/dev/null

  # Check if the fuzzer found a crash
  ls snapshot/crashes/ASAN_WRITE* >/dev/null
  STATUS=$?
  if [ "$STATUS" -gt 0 ]; then
    echo "Example 3 did not find crash"
    ls snapchange-example-03/snapshot/crashes >/dev/null
    popd > /dev/null
    exit 1
  else 
    echo -e "\e[32mExample 03 SUCCESS!\e[0m"
  fi
}

example3
