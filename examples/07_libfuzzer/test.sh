#!/bin/bash

# Reset the snapshot from a previous run
pushd snapshot > /dev/null
./reset.sh
popd > /dev/null

# Rebuild the fuzzer
echo "Building Example 07"
cargo build -r >/dev/null 2>/dev/null

# Seed the input with an easier input
echo "Begin fuzzing!"
cargo run -r -- fuzz -c 8 --ascii-stats --stop-after-first-crash --stop-after-time 5m

ls snapshot/crashes/SIGSEGV* >/dev/null 2>/dev/null
STATUS=$?
if [ "$STATUS" -eq 0 ]; then
  kill -9 $PID 2>/dev/null >/dev/null
  ps -ef | rg Example07 | tr -s ' ' | cut -d' ' -f2 | xargs kill -9 2>/dev/null >/dev/null
fi

# Check if the fuzzer found a crash
ls snapshot/crashes/SIGSEGV* >/dev/null
STATUS=$?
if [ "$STATUS" -gt 0 ]; then
  echo "Example 7 did not find crash"
  exit 1
fi

echo -e "\e[32mExample 07 fuzz SUCCESS!\e[0m"
