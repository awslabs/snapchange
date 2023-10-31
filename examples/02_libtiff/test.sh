#!/bin/bash

example2() {
  echo "Testing Example 02"

  # Reset the snapshot
  pushd snapshot > /dev/null
  ./reset.sh
  popd > /dev/null

  # Rebuild the fuzzer
  echo "Building Example 02"
  cargo build -r 2>/dev/null >/dev/null

  # Start the fuzzers
  echo "Begin fuzzing!"
  cargo run -r -- fuzz -c 64 --ascii-stats --stop-after-first-crash --stop-after-time 2m 2>/dev/null >/dev/null &

  # If we find a crash early, kill the fuzzer
  PID=$!
  for i in $(seq 0 60); do
    ls snapshot/crashes/ASAN_READ* >/dev/null 2>/dev/null
    STATUS=$?
    if [ "$STATUS" -eq 0 ]; then
      ps -ef | rg Example02 | tr -s ' ' | cut -d' ' -f2 | xargs kill -9 2>/dev/null >/dev/null
      break
    fi
    sleep 1
  done

  # Kill the example 02 fuzzers
  ps -ef | rg Example02 | tr -s ' ' | cut -d' ' -f2 | xargs kill -9 2>/dev/null >/dev/null

  # Check if the fuzzer found a crash
  ls snapshot/crashes/ASAN_READ* >/dev/null
  STATUS=$?
  if [ "$STATUS" -gt 0 ]; then
    echo "Example 2 did not find crash"
    ls snapchange-example-02/snapshot/crashes >/dev/null
    popd > /dev/null
    exit 1
  else 
    echo -e "\e[32mExample 02 SUCCESS!\e[0m"
  fi
}

example2
