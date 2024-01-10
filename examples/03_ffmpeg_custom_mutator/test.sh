#!/bin/bash

source ../test.include.sh

setup_build

log_info "start fuzzing"
cargo run -r -- \
    fuzz \
        --ascii-stats \
        --stop-after-first-crash \
        -c "$FUZZ_CORES" \
        --stop-after-time "$FUZZ_TIMEOUT" \
        --timeout 1m \
    >/dev/null 2>&1

# Kill the example 03 fuzzers
ps -ef | rg Example03 | tr -s ' ' | cut -d' ' -f2 | xargs kill -9 2>/dev/null >/dev/null

# Check if the fuzzer found a crash
ls snapshot/crashes/ASAN_WRITE* >/dev/null
STATUS=$?
if [ "$STATUS" -gt 0 ]; then
    err "did not find crash"
fi

log_success "fuzzing"
