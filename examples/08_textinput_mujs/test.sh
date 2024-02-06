#!/usr/bin/env bash

source ../test.include.sh

setup_build

start_fuzzing

# Check if the fuzzer found a crash
SEGV_FILE="$(find ./snapshot/crashes/*SIGSEGV* -type f | head -n 1)"
RAISE_FILE="$(find ./snapshot/crashes/*SIGABRT* -type f | head -n 1)"
if [[ -z "$SEGV_FILE" ]]; then
    err "failed to identify the crash that leads to SIGSEGV"
fi
if [[ -z "$RAISE_FILE" ]]; then
    err "failed to identify the crash that leads to SIGABRT"
fi

CORPUS_FILE="$(find ./snapshot/current_corpus/ -type f | tail -n 1)"

if [[ -z "$CORPUS_FILE" ]]; then
    err "failed to identify a corpus file"
fi

log_success "fuzz"

