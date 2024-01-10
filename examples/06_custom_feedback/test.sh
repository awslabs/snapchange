#!/usr/bin/env bash

source ../test.include.sh

export USE_MAZE=0
export CHECK_CODE=1
export MAZE_NO_BT=0

setup_build

start_fuzzing

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

pushd harness >/dev/null
make >/dev/null 2>&1 || err "failed to build harness/maze on host"
popd >/dev/null

### Test minimize ###
# minimize only according to rip + custom feedback
MIN_FLAGS="--rip-only --consider-coverage=none"
# cargo run -r -- minimize $MIN_FLAGS "$CRASH_FILE" 2>/dev/null >/dev/null || err "running minimize subcommand on $CRASH_FILE failed"
cargo run -r -- minimize $MIN_FLAGS "$CORPUS_FILE" 2>/dev/null >/dev/null || err "running minimize subcommand on $CORPUS_FILE failed"

for CRASH_FILE in ./snapshot/crashes/*assert_fail*/*; do
    cargo run -r -- minimize $MIN_FLAGS "$CRASH_FILE" 2>/dev/null >/dev/null || err "running minimize subcommand on $CRASH_FILE failed"
    if [[ -e "$CRASH_FILE.min" ]]; then
        if [[ "$(sha1sum "$CRASH_FILE" | awk '{print $1}')" == "$(sha1sum "$CRASH_FILE.min")" ]]; then
            err "minimized file $CRASH_FILE.min equal to original"
        fi
        # out_orig="$(./harness/maze "$CRASH_FILE")"
        out_min="$(./harness/maze "$CRASH_FILE.min" 2>&1)"
        if echo "$out_min" | grep "Assertion" >/dev/null 2>&1; then
            true
        else
            err "minimized file $CRASH_FILE.min does not trigger crash"
        fi
    else
        err "no minimized file found for $CRASH_FILE"
    fi
done

log_success "minimize"


### Test corpus-min ###
PRIOR="$(ls -l ./snapshot/current_corpus | wc -l)"
cargo run -r -- corpus-min 2>/dev/null >/dev/null || err "running corpus-min subcommand failed"
NEW="$(ls -l ./snapshot/current_corpus | wc -l)"
if [ "$NEW" -ge "$PRIOR" ]; then
    err "corpus-min did not reduce corpus size"
fi
log_success "corpus-min"
