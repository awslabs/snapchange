#!/usr/bin/env bash

source ../test.include.sh

setup_build

# Seed the input with an easier input
log_info "start fuzzing"
mkdir -p snapshot/input
echo -n fuzzmetosolvem11 > snapshot/input/test
cargo run -r -- fuzz -c "$FUZZ_CORES" --ascii-stats --stop-after-first-crash --stop-after-time "$FUZZ_TIMEOUT" >/dev/null 2>/dev/null

# # If we find a crash early, kill the fuzzer
# for i in $(seq 0 60); do
#   ls snapshot/crashes/SIGSEGV* >/dev/null 2>/dev/null
#   STATUS=$?
#   if [ "$STATUS" -eq 0 ]; then
#     kill -9 $PID 2>/dev/null >/dev/null
#     ps -ef | rg Example01 | tr -s ' ' | cut -d' ' -f2 | xargs kill -9 2>/dev/null >/dev/null
#     break
#   fi
#   sleep 1
# done
#
# # Kill the example 01 fuzzers
# ps -ef | rg Example01 | tr -s ' ' | cut -d' ' -f2 | xargs kill -9 2>/dev/null >/dev/null

# Check if the fuzzer found a crash
ls snapshot/crashes/SIGSEGV* >/dev/null
STATUS=$?
if [ "$STATUS" -gt 0 ]; then
    err "did not find crash"
fi


log_success "fuzz"

CRASH_FILE="$(find ./snapshot/crashes/SIGSEGV* -type f | head -n 1)"
CORPUS_FILE="$(find ./snapshot/current_corpus/ -type f | tail -n 1)"

### Test trace ###

## trace -- basic
cargo run -r -- trace "$CRASH_FILE" 2>/dev/null >/dev/null || err "running trace failed"

grep unhandled_signal snapshot/traces/* >/dev/null || err "trace test basic - no unhandled_signal"

## trace -- no-single-step
cargo run -r -- trace $CRASH_FILE --no-single-step 2>/dev/null >/dev/null
grep INSTR snapshot/traces/*no_single_step >/dev/null || err "trace test no-single-step - no unhandled_signal"

log_success "trace"

### Test coverage ###

if ! [[ -e ./snapshot/coverage.lcov ]]; then
    ls -al ./snapshot/coverage*
    err "no lcov output after fuzzing"
fi
lcov_counts="$(grep -c ",1" ./snapshot/coverage.lcov)"
if [[ "$lcov_counts" -lt 5 ]]; then
    err "lcov coverage output seems wrong with $lcov_counts hit lines"
fi

## coverage
cargo run -r -- coverage $CRASH_FILE 2>/dev/null >/dev/null || err "running coverage subcommand failed"
ls snapshot/coverage_per_input/ >/dev/null
STATUS=$?
if [ "$STATUS" -gt 0 ]; then
    err "coverage command did not yield per-input coverage"
fi
log_success "coverage"

### Test minimize ###
cargo run -r -- minimize "$CRASH_FILE" 2>/dev/null >/dev/null || err "running minimize subcommand failed"
# if [ "$STATUS" -gt 0 ]; then
#   echo "Example 1 failed minimize test"
#   exit 1
# fi
cargo run -r -- minimize "$CORPUS_FILE" 2>/dev/null >/dev/null || err "running minimize subcommand failed"

log_success "minimize"

### Test corpus-min ###
PRIOR="$(ls -l ./snapshot/current_corpus | wc -l)"
cargo run -r -- corpus-min 2>/dev/null >/dev/null || err "running corpus-min subcommand failed"
NEW="$(ls -l ./snapshot/current_corpus | wc -l)"
if [ "$NEW" -ge "$PRIOR" ]; then
    err "corpus-min did not reduce corpus size"
fi
log_success "corpus-min"
