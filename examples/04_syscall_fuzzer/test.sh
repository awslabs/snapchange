#!/usr/bin/env bash

source ../test.include.sh

setup_build

start_fuzzing

# Kill the example 04 fuzzers
ps -ef | rg Example04 | tr -s ' ' | cut -d' ' -f2 | xargs kill -9 2>/dev/null >/dev/null

# Check if the fuzzer found a crash
ls snapshot/crashes/KASAN_WRITE* >/dev/null
STATUS=$?
if [ "$STATUS" -gt 0 ]; then
    err "did not find crash"
fi

log_success "fuzzing"
