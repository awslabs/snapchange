#!/bin/bash

if [[ -z "$SNAPCHANGE_ROOT" ]]; then
  export SNAPCHANGE_ROOT="$(realpath "$(dirname "$0")../")"
fi
if [[ -z "$SNAPSHOT_OUTPUT" ]]; then
  # Directory to output snapshot files
  OUTPUT=/snapshot/
else
  OUTPUT="$SNAPSHOT_OUTPUT"
fi
if [[ -z "$SNAPSHOT_IMGTYPE" ]]; then
    # IMGTYPE="disk"
    IMGTYPE="initramfs"
else
    IMGTYPE="$SNAPSHOT_IMGTYPE"
fi
if [[ -z "$SNAPSHOT_USER" ]]; then
    USER=root
else
    USER="$SNAPSHOT_USER"
fi
if [[ -z "$SNAPSHOT_KERNEL_IMG" ]]; then
  SNAPSHOT_KERNEL_IMG=""
fi
if [[ -z "$SNAPSHOT_KERNEL_ELF" ]]; then
  SNAPSHOT_KERNEL_ELF=""
fi
if [[ -z "$LIBFUZZER" ]]; then 
    LIBFUZZER=0
else
    SNAPSHOT_FUNCTION="LLVMFuzzerTestOneInput"
fi
if [[ -z "$SNAPSHOT_FUNCTION" ]]; then
    SNAPSHOT_FUNCTION=""
fi
if [[ -z "$QEMU_MEM" ]]; then
    QEMU_MEM="4G"
fi
if [[ -z "$KASAN" ]]; then
    KASAN=0
fi
if [[ -z "$GENERATE_COVERAGE_BREAKPOINTS" ]]; then
    GENERATE_COVERAGE_BREAKPOINTS=1
fi
if [[ -z "$COVERAGE_BREAKPOINT_COMMAND" ]]; then
    COVERAGE_BREAKPOINT_COMMAND=ghidra
fi
if [[ -z "$COVERAGE_BREAKPOINTS_EXTRA_BINS" ]]; then
    COVERAGE_BREAKPOINTS_EXTRA_BINS=""
fi


source $SNAPCHANGE_ROOT/utils/log.sh || { echo "Failed to source $SNAPCHANGE_ROOT/utils/log.sh"; exit 1; }

if [[ -z "$SNAPSHOT_ENTRYPOINT" ]]; then
    log_error "require setting a SNAPSHOT_ENTRYPOINT"
    exit 1
fi
  
RELEASE="harness"
D9P="$(mktemp -d "/tmp/mnt.9p.XXXXXXX")"  # directory for 9pfs

set -eu -o pipefail

function start_vm {
  QEMU="$SNAPCHANGE_ROOT/QEMU/build/qemu-system-x86_64"
  KERNEL="$SNAPCHANGE_ROOT/linux.bzImage"
  if [[ -n "$SNAPSHOT_KERNEL_IMG" ]]; then
    KERNEL="$SNAPSHOT_KERNEL_IMG"
  elif [[ "$KASAN" -eq 1 ]]; then
    KERNEL="$SNAPCHANGE_ROOT/linux.kasan.bzImage"
  fi

  if ! command -v "$QEMU" >/dev/null; then
    log_error "No qemu found! ('$QEMU')"
    exit 1
  fi
  if [[ ! -e "$KERNEL" ]]; then
    log_error "kernel not found! ('$KERNEL')"
    exit 1
  fi

  rm -rf "$D9P" || true
  mkdir -p "$D9P"
  D9P="$(realpath "$D9P")"

  rm "$SNAPCHANGE_ROOT/vm.pid" >/dev/null 2>&1 || true

  log_msg "launching qemu"

  if [[ "$IMGTYPE" = "disk" ]]; then
     set -x
     "$QEMU" \
        -m "$QEMU_MEM" \
        -smp 1 \
        -kernel "$KERNEL" \
        -append "console=ttyS0 root=/dev/sda earlyprintk=serial init=/init nokaslr mitigations=off" \
        -drive "file=$SNAPCHANGE_ROOT/$RELEASE.img" \
        -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
        -net nic,model=e1000 \
        -virtfs "local,path=$D9P,mount_tag=snapchange_mnt,security_model=mapped" \
        -nographic \
        -pidfile "$SNAPCHANGE_ROOT/vm.pid" \
        2>&1 | tee vm.log
     set +x
  elif [[ "$IMGTYPE" = "initramfs" ]]; then
     set -x
      "$QEMU" \
          -m "$QEMU_MEM" \
          -smp 1 \
          -kernel "$KERNEL" \
          -initrd "$SNAPCHANGE_ROOT/$RELEASE.initramfs.lz4" \
          -append "console=ttyS0 earlyprintk=serial nokaslr mitigations=off" \
          -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
          -net nic,model=e1000 \
          -virtfs "local,path=$D9P,mount_tag=snapchange_mnt,security_model=mapped" \
          -nographic \
          -pidfile "$SNAPCHANGE_ROOT/vm.pid" \
          2>&1 | tee vm.log
     set +x
  else
    log_error "invalid IMGTYPE=$IMGTYPE - must be (disk|initramfs)"
    exit 1 
  fi
}

function kill_vm {
    if [[ -e "$SNAPCHANGE_ROOT/vm.pid" ]]; then
        kill -9 "$(cat vm.pid)" || true
    fi
}

function check_vm_halted {
    if [[ -e "$SNAPCHANGE_ROOT/vm.pid" ]]; then
        if ps -p "$(cat vm.pid)" >/dev/null; then
            return 1
        else
            return 0
        fi
    else
        return 0
    fi
}

function extract_output { 

  DIR="$D9P"

  log_msg "VM returned data:"
  ls -al "$DIR"

  # Copy over the files written by `gdbsnapshot.py`
  mv "$DIR/gdb.vmmap" . || true
  mv "$DIR/gdb.modules" . || true
  mv "$DIR/gdb.symbols" . || true

  # Copy over the root symbols and, if found, move the user symbols to .symbols in order to
  # combine the symbols into one gdb.symbols
  if [ -f "$DIR/gdb.symbols.root" ]; then
      log_msg "Combining root and user symbols"
      # cat "$DIR/gdb.symbols.root" | grep -v main > gdb.symbols.root
      cp "$DIR/gdb.symbols.root" .
      mv gdb.symbols gdb.symbols.user 
      python3 $SNAPCHANGE_ROOT/utils/combine_symbols.py
      # cat gdb.symbols.user gdb.symbols.root | sort -u > gdb.symbols
  fi

  # Ensure the files are the current user and not root anymore
  if [ -f gdb.symbols.root ]; then 
      chown `id -u`:`id -g` gdb.symbols.root
  fi
  chown `id -u`:`id -g` gdb.symbols || true
  chown `id -u`:`id -g` gdb.modules || true
  chown `id -u`:`id -g` gdb.vmmap || true

  cp  "$DIR"/guestkernel* "$OUTPUT" || true
}


# Create the output directory
mkdir -p $OUTPUT || true

if [[ -n "$SNAPSHOT_KERNEL_IMG" ]]; then
  cp "$SNAPSHOT_KERNEL_IMG" "$OUTPUT/vmlinux.bzimg"
  if [[ -n "$SNAPSHOT_KERNEL_ELF" ]]; then
    cp "$SNAPSHOT_KERNEL_ELF" "$OUTPUT/vmlinux"
  else
    log_warning "couldn't find vmlinux corresponding to bootable kernel image '$SNAPSHOT_KERNEL_IMG'."
    log_warning "please set the variable SNAPSHOT_KERNEL_ELF for kernel symbols!"
  fi
else
  # Copy over the `vmlinux` into the output directory
  if [[ "$KASAN" -eq 1 ]]; then
      cp $SNAPCHANGE_ROOT/vmlinux.kasan "$OUTPUT/vmlinux"
  else
      cp $SNAPCHANGE_ROOT/vmlinux "$OUTPUT/vmlinux"
  fi
fi

# Start the VM
start_vm &

sleep 1

# While the VM is booting, wait for the login prompt. Once the login prompt is shown,
# extarct the gdb output and kill the VM
while true; do
    if grep -i -e "end Kernel panic" vm.log 2>&1 >/dev/null; then
        log_warning "kernel panic while snapshotting! please check the vm.log file"
    fi

    # Login prompt signals that the /etc/rc.local script executed and can extract output
    # Status code of 0 means the login prompt was found in the vm.log
    if grep -i -e "\(linux login:\|snapshot done\|Attempted to kill init|end Kernel panic\)" vm.log 2>&1 >/dev/null || check_vm_halted; then
        log_msg "Finished booting.. extracting gdb output";
        extract_output

        if ! [[ -e fuzzvm.physmem ]]; then
          log_error "qemu did not produce a dump of the VM's memory/register state. Have you added a snapshot hypercall to your harness?"
          log_msg "Make sure to set the environment variable LIBFUZZER=1 if you are using a libfuzzer binary."
          log_msg "Otherwise, make sure that your program contains \`__asm(\"int3 ; vmcall\");\` to trigger the snapshot."
          log_msg "Or set the envirionment variable SNAPSHOT_FUNCTION=THISFUNCTION to snapshot at THISFUNCTION"
          exit 1
        fi

        REQUIRED_FILES="fuzzvm.physmem fuzzvm.qemuregs"
        if [[ "$SNAPSHOT_CHECK_FOR_GDB" -eq 1 ]]; then
          REQUIRED_FILES="$REQUIRED_FILES gdb.symbols gdb.vmmap"
        fi

        for file in $REQUIRED_FILES; do
          if ! [[ -e "$file" ]]; then
            log_error "missing required file: $file"
            exit 1
          fi
        done

        log_msg "Moving the snapshot data into $OUTPUT"
        mv fuzzvm.* $OUTPUT
        mv gdb.* $OUTPUT

        log_msg "Found the following files"
        ls -la $OUTPUT

        log_msg "Found this SNAPSHOT output from the vm log"
        grep SNAPSHOT vm.log || true

        log_msg "Killing the VM"
        kill_vm

        log_success "(almost) done!"
        break
    fi

    if grep -i -e "Initramfs unpacking failed" vm.log 2>&1 >/dev/null; then
        log_error "VM failed to boot properly! kernel could not unpack initramfs..."
        exit -1
    fi

    log_msg "Waiting for VM..."
    sleep 2
done

cp vm.log "$OUTPUT/"

log_success "extracted snapshot - postprocessing now."

if [[ $SNAPSHOT_FUNCTION ]]; then 
    log_msg "patching physmem"
    BYTES="$(cat /tmp/libfuzzer.bytes.bak)"
    R2Z=""
    if command -v rizin >/dev/null 2>&1; then
        R2Z=rizin
    elif command -v r2 >/dev/null 2>&1; then
        R2Z=r2
    else
        log_error "please install radare2/rizin for patching"
        exit 1
    fi
    # Restore the original bytes at the LLVMFuzzerTestOneInput bytes
    "$R2Z" -w -q -c "/x cc0f01c1cdcdcdcdcdcdcdcdcdcdcdcd ; wx $BYTES @ hit0_0" "$OUTPUT/fuzzvm.physmem"
fi

# Create the reset script for the snapshot
cp $SNAPCHANGE_ROOT/utils/reset_snapshot.sh $OUTPUT/reset.sh

function create_covbps() {
  BIN_NAME="$1"
  # Get the base address of the example from the module list
  BASE="$(grep "$BIN_NAME" "$OUTPUT/gdb.modules" | cut -d' ' -f1)"
  log_msg "analyzing $BIN_NAME @ ($BASE) for breakpoints with '$COVERAGE_BREAKPOINT_COMMAND'"
  if [[ "$COVERAGE_BREAKPOINT_COMMAND" == "ghidra" ]]; then
    # Use ghidra to find the coverage basic blocks
    time python3 $SNAPCHANGE_ROOT/coverage_scripts/ghidra_basic_blocks.py --base-addr "$BASE" "$OUTPUT/$BIN_NAME.bin" > "$OUTPUT/ghidra.log" 2>&1
  elif [[ "$COVERAGE_BREAKPOINT_COMMAND" == "angr" ]]; then
    time python3 $SNAPCHANGE_ROOT/coverage_scripts/angr_snapchange.py --dict-path "$OUTPUT/dict" --auto-dict --base-addr "$BASE" "$OUTPUT/$BIN_NAME.bin" > "$OUTPUT/angr.log" 2>&1
  elif [[ "$COVERAGE_BREAKPOINT_COMMAND" == "rizin" ]]; then
    time python3 $SNAPCHANGE_ROOT/coverage_scripts/rz_snapchange.py --base-addr "$BASE" "$OUTPUT/$BIN_NAME.bin" > "$OUTPUT/rizin.log" 2>&1
  elif [[ "$COVERAGE_BREAKPOINT_COMMAND" == "binaryninja" ]]; then
    log_warning "binary ninja coverage script requires a headless license! make sure everything is set up inside of the container."
    time python3 $SNAPCHANGE_ROOT/coverage_scripts/bn_snapchange.py --bps --analysis --base-addr "$BASE" "$OUTPUT/$BIN_NAME.bin" 
  else
    time $COVERAGE_BREAKPOINT_COMMAND "$BASE" "$OUTPUT/$BIN_NAME.bin" 2>&1 | tee "$OUTPUT/custom_coverage_command.log"
  fi
  mv *.covbps "$OUTPUT/" || true
}

# finally just chown to something more sensible
chown -R "$SNAPSHOT_CHOWN_TO" "$OUTPUT" || true

if [[ "$GENERATE_COVERAGE_BREAKPOINTS" -eq 1 ]]; then
  log_msg "creating coverage breakpoints with $COVERAGE_BREAKPOINT_COMMAND"
  # Create the coverage breakpoints and analysis
  bin_name="$(basename "$SNAPSHOT_ENTRYPOINT")"
  create_covbps "$bin_name"
  if [[ -n "$COVERAGE_BREAKPOINTS_EXTRA_BINS" ]]; then
      for bin_path in $COVERAGE_BREAKPOINTS_EXTRA_BINS; do
          bin_name="$(basename "$bin_path")"
          if [[ -e "$OUTPUT/image/$bin_path" ]]; then
              cp "$OUTPUT/image/$bin_path" "$OUTPUT/${bin_name}.bin"
              create_covbps "$bin_name"
          elif [[ -e "$OUTPUT/$bin_name.bin" ]]; then
              create_covbps "$bin_name"
          else
              log_warning "failed to locate $bin_path in snapshot directory"
          fi
      done
  fi
  log_msg "[+] generated $(cat "$OUTPUT"/*.covbps | wc -l) coverage breakpoints in total"
else
  log_msg "Skipping generating coverage breakpoints"
fi


# finally just chown to something more sensible
chown -R "$SNAPSHOT_CHOWN_TO" "$OUTPUT" || true

log_success "snapshot is ready now"
