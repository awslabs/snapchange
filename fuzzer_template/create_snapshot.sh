#!/bin/bash

set -e

# Initialize a linux kernel for this snapshot
init_qemu_snapshot() {
  pushd qemu_snapshot

  # Use kernel v5.19 by default
  ./init.sh --kernel-version v5.19

  # Use the latest kernel commit with KASAN
  # ./init.sh --with-kasan

  # Use the latest kernel commit, but download the full source tree
  # to potentially change to a specific version later
  # ./init.sh --full

  popd
}

# Build the harness for this target
build_harness() {
  echo "ERROR: No harness being built.." 
}

# Take the snapshot
take_snapshot() {
  # Build the image to execute the harness on start
  pushd ./qemu_snapshot/IMAGE
  ./build.sh /path/to/harness/to/execute arg1 /path/to/path2
  popd

  # Take the snapshot
  pushd ./qemu_snapshot
  ./snapshot.sh
  popd
}

# Move the snapshot directory out of qemu_snapshot
copy_snapshot_directory() {
  mv qemu_snapshot/output snapshot
}

# Initialize the fuzzer based on the output of the snapshot
init_fuzzer() {
  # Check if fuzzer still has REPLACEME markers that need replacing
  grep REPLACEME src/fuzzer.rs >/dev/null

  # Continue replacing REPLACEME markers if they still exist
  if [ $? -eq 0 ]; then
    # Begin the fuzzer with the SNAPSHOT output from the vm.log
    COMMENTS=`grep SNAPSHOT qemu_snapshot/vm.log | sed 's_^_// _g' | tr '\n' '\r'`
    echo "Found snapshot comments in vm.log:"
    echo $COMMENTS

    # Slight hack to sed a multiline string
    sed -z "s_REPLACEMECOMMENTS_${COMMENTS}_" src/fuzzer.rs | tr '\r' '\n' > /tmp/.fuzzer.rs
    mv /tmp/.fuzzer.rs src/fuzzer.rs

    # Replace the RIP for the snapshot
    # RIP=0000000000401362 RFL=00000306 [-----P-] CPL=3 II=0 A20=1 SMM=0 HLT=0
    NEWRIP=`grep RIP snapshot/*qemuregs | cut -d' ' -f1 | cut -d'=' -f2`
    echo "Found RIP in snapshot: $NEWRIP"
    sed  -i "s/REPLACEMERIP/0x${NEWRIP}/" src/fuzzer.rs

    # Replace the CR3 for the snapshot
    # 16:CR0=80050033 CR2=00007f8814613610 CR3=00000000084be000 CR4=000006f0
    NEWCR3=`grep CR3 snapshot/*qemuregs | cut -d' ' -f3 | cut -d'=' -f2`
    echo "Found CR3 in snapshot: $NEWCR3"
    sed -i "s/REPLACEMECR3/0x${NEWCR3}/" src/fuzzer.rs
  else
    echo "Fuzzer doesn't have REPLACEME markers.. skipping"
  fi
}

# Create the coverage breakpoints and analysis 
create_coverage_breakpoints() {

  # Get the base address of the example from the module list
  BASE=`grep example1 ./snapshot/gdb.modules | cut -d' ' -f1`

  # If binaryninja is available, attempt to create the coverage breakpoints and analysis
  if python3 -c "import binaryninja" 2>/dev/null; then 
    # Execute the binja plugin
    python3 ./coverage_scripts/bn_snapchange.py --bps --analysis --base-addr $BASE ./snapshot/example1.bin
  else
    pushd coverage_scripts

    # Install ghidra
    ../../install_ghidra.sh

    # Use ghidra to find the coverage basic blocks
    python3 ./ghidra_basic_blocks.py --base-addr $BASE ../snapshot/example1.bin

    popd

    # Install radare2
    # if [ ! -f $HOME/radare2 ]; then
    #   git clone https://github.com/radareorg/radare2 $HOME/radare2
    #   pushd $HOME/radare2
    #   ./sys/install.sh
    #   popd
    # fi

    # Use radare2 to gather the basic blocks
    # /usr/local/bin/r2 -q -B $BASE -c 'aa ; afb @@ *' ./example1.bin | cut -d' ' -f1 | sort | uniq > ./example1.bin.r2.covbps
  fi
}

build_harness
init_qemu_snapshot
take_snapshot
copy_snapshot_directory
init_fuzzer
create_coverage_breakpoints
