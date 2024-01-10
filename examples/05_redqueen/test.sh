#!/usr/bin/env bash

source ../test.include.sh

setup_build

# Start the fuzzers
log_info "Begin fuzzing! we have $(nproc) cores; using half for fuzzing; using at most $(grep -Eo 'cores = ([0-9]*)' ./harness/config.toml) for redqueen"
cargo run -r -- fuzz -c "$FUZZ_CORES" \
    --ascii-stats \
    --stop-after-first-crash \
    --stop-after-time "$FUZZ_TIMEOUT" \
    >/dev/null 2>&1 || err "fuzzing abnormal exit"

# Kill the example 05 fuzzers
ps -ef | rg Example05 | tr -s ' ' | cut -d' ' -f2 | xargs kill -9 2>/dev/null >/dev/null

  # Check if the fuzzer found a crash
ls snapshot/crashes/SIGSEGV* >/dev/null
STATUS=$?
if [ "$STATUS" -gt 0 ]; then
    err "did not find crash"
else 
    log_success "fuzz"
fi
