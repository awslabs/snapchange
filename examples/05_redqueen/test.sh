#!/usr/bin/env bash

if [[ -z "$FUZZ_CORES" ]]; then
   FUZZ_CORES="/2"
fi

if [[ -z "$FUZZ_TIMEOUT" ]]; then
   FUZZ_TIMEOUT="6m"
fi

EX="$(basename $PWD)"

COLOR_CLEAR='\e[0m'
COLOR_RED='\e[0;31m'
COLOR_GREEN='\e[0;32m'

function err {
    echo -e "${COLOR_RED}ERROR: $EX - $* $COLOR_CLEAR"
    exit 1
}

function log_success {
    echo -e "${COLOR_GREEN}SUCCESS: $EX - $* $COLOR_CLEAR"
}

if ! test -d snapshot; then
    err "require snapshot"
fi

# Reset the snapshot from a previous run
pushd snapshot > /dev/null
./reset.sh
popd > /dev/null

# Rebuild the fuzzer
cargo build -r >/dev/null 2>&1 || err "build failure"

# Start the fuzzers
echo "Begin fuzzing! we have $(nproc) cores; using half for fuzzing; using at most $(grep -Eo 'cores = ([0-9]*)' ./harness/config.toml) for redqueen"
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
