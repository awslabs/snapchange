#!/bin/bash

example4() {
  echo "Testing Example 04"

  # Reset the snapshot
  pushd snapshot > /dev/null
  ./reset.sh
  popd > /dev/null

  # Rebuild the fuzzer
  echo "Building Example 04"
  cargo build -r 2>/dev/null >/dev/null

  # Start the fuzzers
  echo "Begin fuzzing!"
  timeout 60s cargo run -r -- fuzz -c 8 --ascii-stats 2>/dev/null >/dev/null &

  # If we find a crash early, kill the fuzzer
  PID=$!
  for i in $(seq 0 60); do
    ls snapshot/crashes/KASAN_WRITE* >/dev/null 2>/dev/null
    STATUS=$?
    if [ "$STATUS" -eq 0 ]; then
      kill -9 $PID 2>/dev/null >/dev/null
      break
    fi
    sleep 1
  done

  # Kill the example 04 fuzzers
  ps -ef | rg Example04 | tr -s ' ' | cut -d' ' -f2 | xargs kill -9 2>/dev/null >/dev/null

  # Check if the fuzzer found a crash
  ls snapshot/crashes/KASAN_WRITE* >/dev/null
  STATUS=$?
  if [ "$STATUS" -gt 0 ]; then
    echo "Example 4 did not find crash"
    ls snapchange-example-04/snapshot/crashes >/dev/null
    popd > /dev/null
    exit 1
  else 
    echo -e "\e[32mExample 04 SUCCESS!\e[0m"
  fi

}

example4
