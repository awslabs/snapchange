#!/bin/bash

set -e

AMI=$1

# Install prereqs
install_prereqs() {
  ../install_prereqs.sh
}

# Initialize the fuzz template for this example
init_fuzz_template() {
  # Initialize this example based on the fuzzer template
  cp -r -L ../../fuzzer_template/* .

  # Remove the create_snapshot.sh template since this example uses this file (make_example.sh)
  rm create_snapshot.sh

  # Copy this example's fuzzer into the src/ directory (created by copying from fuzzer_template)
  if [ "$AMI" == "ami" ]; then
    # Use the demo challenge fuzzer for the AMI
    cp fuzzer.rs.ami src/fuzzer.rs
  else
    # Use the solution fuzzer
    cp fuzzer.rs src/fuzzer.rs
  fi

  # Copy the src files for this example
  cp main.rs src/main.rs

  # Add snapchange as dependency and build-dependency for this example
  $HOME/.cargo/bin/cargo add snapchange --path ../..
}

# Initialize a qemu_snapshot for this target
init_qemu_snapshot() {
  if [ "$AMI" == "ami" ]; then
    # Use the pre-built qemu_snapshot from the init_ami.sh script
    echo "Copying from AMI qemu_snapshot"
    sudo cp -r ../qemu_snapshot .
    sudo chown -R $USER:$USER qemu_snapshot
  else 
    pushd qemu_snapshot
    ./init.sh
    popd
  fi
}

build_harness() {
  pushd harness

  # Build the example binary
  gcc -ggdb example1.c -o example1

  popd
}

take_snapshot() {
  # Sanity check the target has been build
  if [ ! -f "./harness/example1" ]; then 
    echo "ERROR: example1 target not found"
    exit 0
  fi

  # Build the image to execute the harness on start
  pushd ./qemu_snapshot/IMAGE
  ./build.sh ../../harness/example1
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

    # Replace the data buffer from the snapshot
    # [   19.760751] rc.local[189]: SNAPSHOT Data buffer: 0x555555556004
    NEWBUFF=`grep "Data buffer" qemu_snapshot/vm.log | rev | cut -d' ' -f1 | rev`
    echo "Found data buffer in snapshot: $NEWBUFF"
    sed -i "s/REPLACEMEDATABUFFER/${NEWBUFF}/" src/fuzzer.rs

  else
    echo "Fuzzer doesn't have REPLACEME markers.. skipping"
  fi

}

# Modify config to expedite the fuzzing for this simple example
modify_config() {
  # Initialize the config for the project
  $HOME/.cargo/bin/cargo run -- project init-config

  # Change the merge coverage timeout from 60 sec -> 2 sec
  sed -i 's/secs = 60/secs = 2/' ./snapshot/config.toml
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

install_prereqs
init_fuzz_template
init_qemu_snapshot
build_harness
take_snapshot
copy_snapshot_directory
init_fuzzer
modify_config
create_coverage_breakpoints
