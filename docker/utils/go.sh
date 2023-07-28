#!/usr/bin/env bash

source /snapchange/log.sh || { echo "Failed to source /snapchange/log.sh"; exit 1; }

set -e

if [[ "$1" == "template" ]]; then
  log_msg "extracting template files to $TEMPLATE_OUT"
  for in_file in /snapchange/fuzzer_template/{.[!.]*,*}; do
      out_file="$TEMPLATE_OUT/${in_file#*/snapchange/fuzzer_template/}"
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

cd /snapchange/
echo "[+] building target image"
./build.sh
echo "[+] creating snapshot"
./snapshot.sh
echo "[+] done"
