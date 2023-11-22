#!/bin/bash

example5() {
  echo "Testing Example 05"

  # Reset the snapshot
  pushd snapshot > /dev/null
  ./reset.sh
  popd > /dev/null

  # Rebuild the fuzzer
  echo "Building Example 05"
  cargo build -r 2>/dev/null >/dev/null

  # Start the fuzzers
  echo "Begin fuzzing! we have $(nproc) cores; using half for fuzzing; using at most $(grep -Eo 'cores = ([0-9]*)' ./harness/config.toml) for redqueen"
  cargo run -r -- fuzz -c /2 --ascii-stats --stop-after-first-crash --stop-after-time 6m

  # Kill the example 05 fuzzers
  ps -ef | rg Example05 | tr -s ' ' | cut -d' ' -f2 | xargs kill -9 2>/dev/null >/dev/null

  # Check if the fuzzer found a crash
  ls snapshot/crashes/SIGSEGV* >/dev/null
  STATUS=$?
  if [ "$STATUS" -gt 0 ]; then
    echo "Example 5 did not find crash"
    exit 1
  else 
    echo -e "\e[32mExample 05 SUCCESS!\e[0m"
    exit 0
  fi
}

example5
