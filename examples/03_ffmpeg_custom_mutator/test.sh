#!/bin/bash

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
cargo run -r -- fuzz -c 16 --ascii-stats --stop-after-time 10m --stop-after-first-crash --timeout 1m 2>/dev/null >/dev/null

# Kill the example 03 fuzzers
ps -ef | rg Example03 | tr -s ' ' | cut -d' ' -f2 | xargs kill -9 2>/dev/null >/dev/null

# Check if the fuzzer found a crash
ls snapshot/crashes/ASAN_WRITE* >/dev/null
STATUS=$?
if [ "$STATUS" -gt 0 ]; then
  echo "Example 3 did not find crash"
  exit 1
else 
  echo -e "\e[32mExample 03 SUCCESS!\e[0m"
fi
