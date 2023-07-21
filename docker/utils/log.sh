#!/usr/bin/env bash

C_BLUE='\033[94m'
C_GREEN='\033[92m'
C_YELLOW='\033[93m'
C_RED='\033[91m'
C_CLEAR='\033[0m'
C_BOLD='\033[1m'
SCRIPT_NAME="$(basename "$0")"

function log_error {
  printf "$C_RED[ERROR][$SCRIPT_NAME] $* $C_CLEAR\n"
}
function log_warning {
  printf "$C_YELLOW[WARNING][$SCRIPT_NAME] $* $C_CLEAR\n"
}
function log_success {
  printf "$C_GREEN[+][$SCRIPT_NAME] $* $C_CLEAR\n"
}
function log_msg {
  printf "[+][$SCRIPT_NAME] $*\n"
}
