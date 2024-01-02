#!/usr/bin/env bash

if [[ -z "$FUZZ_CORES" ]]; then
   FUZZ_CORES="/2"
fi

if [[ -z "$FUZZ_TIMEOUT" ]]; then
   FUZZ_TIMEOUT="1m"
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
echo "Building Example 06"
cargo build -r >/dev/null 2>/dev/null || err "build failure"

export USE_MAZE=0
export CHECK_CODE=1
export MAZE_NO_BT=0

echo "Begin fuzzing!"
timeout 160s cargo run -r -- \
    fuzz -c /2 --ascii-stats \
    --stop-after-first-crash --stop-after-time 120s >/dev/null 2>/dev/null

# Check if the fuzzer found a crash
ls snapshot/crashes/*assert_fail* >/dev/null
STATUS=$?
if [ "$STATUS" -gt 0 ]; then
    err "did not find a crash"
fi

log_success "fuzz"

CRASH_FILE="$(find ./snapshot/crashes/*assert_fail* -type f | head -n 1)"
CORPUS_FILE="$(find ./snapshot/current_corpus/ -type f | tail -n 1)"

if [[ -z "$CRASH_FILE" ]]; then
    err "failed to identify a crash"
fi
if [[ -z "$CORPUS_FILE" ]]; then
    err "failed to identify a corpus file"
fi

### Test minimize ###
# minimize only according to rip + custom feedback
MIN_FLAGS="--rip-only --consider-coverage=none"
cargo run -r -- minimize $MIN_FLAGS "$CRASH_FILE" 2>/dev/null >/dev/null || err "running minimize subcommand on $CRASH_FILE failed"
cargo run -r -- minimize $MIN_FLAGS "$CORPUS_FILE" 2>/dev/null >/dev/null || err "running minimize subcommand on $CORPUS_FILE failed"

log_success "minimize"


### Test corpus-min ###
PRIOR="$(ls -l ./snapshot/current_corpus | wc -l)"
cargo run -r -- corpus-min 2>/dev/null >/dev/null || err "running corpus-min subcommand failed"
NEW="$(ls -l ./snapshot/current_corpus | wc -l)"
if [ "$NEW" -ge "$PRIOR" ]; then
    err "corpus-min did not reduce corpus size"
fi
log_success "corpus-min"
