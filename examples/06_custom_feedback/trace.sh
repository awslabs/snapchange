#!/usr/bin/env bash

export MAZE_TARGET="$1"
shift
set -x
exec cargo run -r -- -p "./snapshot/$MAZE_TARGET" trace $@
