#!/bin/bash

# Reset the snapshot from a previous run
pushd snapshot > /dev/null
# ./reset.sh
popd > /dev/null

# Rebuild the fuzzer
echo "Building Example 01"
cargo build -r >/dev/null 2>/dev/null

# Seed the input with an easier input
echo "Begin fuzzing!"
mkdir -p snapshot/input
echo -n fuzzmetosolvem11 > snapshot/input/test
cargo run -r -- fuzz -c 4 --ascii-stats --stop-after-first-crash --stop-after-time 1m >/dev/null 2>/dev/null &

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
  exit 1
fi

echo -e "\e[32mExample 01 fuzz SUCCESS!\e[0m"

CRASH_FILE=$(find ./snapshot/crashes/SIGSEGV* -type f | head -n 1) 

### Test trace ###

## trace -- basic
cargo run -r -- trace $CRASH_FILE 2>/dev/null >/dev/null

grep unhandled_signal snapshot/traces/* >/dev/null
STATUS=$?
if [ "$STATUS" -gt 0 ]; then
  echo "Example 1 failed trace test -- basic"
  exit 1
fi

## trace -- no-single-step
cargo run -r -- trace $CRASH_FILE --no-single-step 2>/dev/null >/dev/null
grep INSTR snapshot/traces/*no_single_step >/dev/null
STATUS=$?
if [ "$STATUS" -gt 0 ]; then
  echo "Example 1 failed trace test -- --no-single-step"
  exit 1
fi

echo -e "\e[32mExample 01 trace SUCCESS!\e[0m"

### Test coverage ###

## coverage
cargo run -r -- coverage $CRASH_FILE 2>/dev/null >/dev/null
ls coverages >/dev/null
if [ "$STATUS" -gt 0 ]; then
  echo "Example 1 failed coverage test"
  exit 1
fi
echo -e "\e[32mExample 01 coverage SUCCESS!\e[0m"
