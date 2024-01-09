#!/bin/bash

source ../test.include.sh

setup_build

start_fuzzing

# Kill the example 02 fuzzers
ps -ef | rg Example02 | tr -s ' ' | cut -d' ' -f2 | xargs kill -9 2>/dev/null >/dev/null

# Check if the fuzzer found a crash
ls snapshot/crashes/ASAN_READ* >/dev/null
STATUS=$?
if [ "$STATUS" -gt 0 ]; then
    err "fuzzer did not find crash"
else
    log_success "fuzzing"
fi
