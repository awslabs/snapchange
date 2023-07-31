#!/bin/bash

# Reset the snapshot from a previous run
pushd snapshot > /dev/null
./reset.sh
popd > /dev/null

# Rebuild the fuzzer
echo "Building Example 01"
cargo build -r >/dev/null 2>/dev/null

# Seed the input with an easier input
echo "Begin fuzzing!"
mkdir -p snapshot/input
echo -n fuzzmetosolvem11 > snapshot/input/test
timeout 60s cargo run -r -- fuzz -c 92 --ascii-stats >/dev/null 2>/dev/null &

# If we find a crash early, kill the fuzzer
for i in $(seq 0 60); do
  ls snapshot/crashes/SIGSEGV* >/dev/null 2>/dev/null
  STATUS=$?
  if [ "$STATUS" -eq 0 ]; then
    kill -9 $PID 2>/dev/null >/dev/null
    ps -ef | rg Example01 | tr -s ' ' | cut -d' ' -f2 | xargs kill -9 2>/dev/null >/dev/null
    break
  fi
  sleep 1
done

# Kill the example 01 fuzzers
ps -ef | rg Example01 | tr -s ' ' | cut -d' ' -f2 | xargs kill -9 2>/dev/null >/dev/null

# Check if the fuzzer found a crash
ls snapshot/crashes/SIGSEGV* >/dev/null
STATUS=$?
if [ "$STATUS" -gt 0 ]; then
  echo "Example 1 did not find crash"
  ls snapchange-example-01/snapshot/crashes >/dev/null
  exit 1
else 
  echo -e "\e[32mExample 01 SUCCESS!\e[0m"

fi
