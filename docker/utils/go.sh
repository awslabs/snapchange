#!/usr/bin/env bash

if [[ -z "$SNAPCHANGE_ROOT" ]]; then
  export SNAPCHANGE_ROOT="$(realpath "$(dirname "$0")/../")"
fi
if [[ -z "$SNAPSHOT_CHOWN_TO" ]]; then
  export SNAPSHOT_CHOWN_TO="$(id -u)"
fi
if [[ -z "$TEMPLATE_OUT" ]]; then
  TEMPLATE_OUT=""
fi

source "$SNAPCHANGE_ROOT/utils/log.sh" || { echo "Failed to source $SNAPCHANGE_ROOT/utils/log.sh"; exit 1; }

set -e

if [[ "$1" == "template" ]]; then
  if [[ -z "$TEMPLATE_OUT" ]]; then
    log_error "please specify TEMPLATE_OUT"
    exit 1
  fi
  log_msg "extracting template files to $TEMPLATE_OUT"
  for in_file in $SNAPCHANGE_ROOT/fuzzer_template/{.[!.]*,*}; do
      out_file="$TEMPLATE_OUT/${in_file#*$SNAPCHANGE_ROOT/fuzzer_template/}"
      if [[ -e "$out_file" ]]; then
          log_warning "I will not overwrite file $out_file."
      else
          mkdir -p "$(dirname "$out_file")"
          cp -r -n "$in_file" "$out_file"
      fi
  
      chown -R "$SNAPSHOT_CHOWN_TO" "$out_file"
  done
  exit 0
fi

if [[ -n "$SNAPSHOT_INPUT" ]]; then
  if [[ -z "$(ls "$SNAPSHOT_INPUT")" ]]; then
    log_warning "No files provided for snapshot root filesystem in (copy to $SNAPSHOT_INPUT)" 
  fi
fi

cd "$SNAPCHANGE_ROOT/"
echo "[+] building target image"
./utils/build.sh
echo "[+] creating snapshot"
./utils/snapshot.sh
echo "[+] done"
