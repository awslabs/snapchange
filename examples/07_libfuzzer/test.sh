#!/usr/bin/env bash

source ../test.include.sh

# Seed the input with an easier input
log_info "start fuzzing"
cargo run -r -- \
    fuzz \
    -c "$FUZZ_CORES" \
    --ascii-stats \
    --stop-after-first-crash \
    --stop-after-time "$FUZZ_TIMEOUT" >/dev/null 2>&1 || err "fuzzing failed"

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
  err "did not find crash"
fi

log_success "fuzzing"
