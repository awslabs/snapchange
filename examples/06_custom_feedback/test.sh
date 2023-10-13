#!/bin/bash

export MAZE_TARGET="maze.small"

# Reset the snapshot from a previous run
pushd "snapshot/$MAZE_TARGET" > /dev/null
./reset.sh
popd > /dev/null

# Rebuild the fuzzer
echo "Building Example 06"
cargo build -r >/dev/null 2>/dev/null || { echo "Example 6 build failure"; exit 1; }

echo "Begin fuzzing!"
timeout 65s cargo run -r -- \
    -p "snapshot/$MAZE_TARGET/" \
    fuzz -c /2 --ascii-stats \
    --stop-after-first-crash --stop-after-time 60s >/dev/null 2>/dev/null

# Check if the fuzzer found a crash
ls snapshot/$MAZE_TARGET/crashes/*assert_fail* >/dev/null
STATUS=$?
if [ "$STATUS" -gt 0 ]; then
  echo "Example 6 did not find crash"
  exit 1
else 
  echo -e "\e[32mExample 06 SUCCESS!\e[0m"
fi
