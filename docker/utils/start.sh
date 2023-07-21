#!/bin/bash

echo "LIBFUZZER: $LIBFUZZER"

# Exit early if no command was given
if [ $# -eq 0 ]; then
  echo "[!] No command given to the script!"
  exit 1
fi

# Variables affected by options
OUTPUT=output
USER=root

# Choose the correct homedir
if [ $USER = 'root' ]; then
    HOMEDIR=/root
else
    HOMEDIR=/home/$USER
fi

# Uncompress the base image
echo "[+] Uncompressing the linux image"
gunzip /qemu_snapshot/IMAGE/bookworm.img.gz

# If given any new arguments, rewrite the rc.local boot script
echo "[+] Adding the binaries to the image"

# Create the output directory
mkdir $OUTPUT


if [ $# -gt 0 ];
then
    # Make the copied binary executable
    sudo chmod +x $1

    # Save the path of the binary to copy into the output directory
    BINARY=$1

    # If LIBFUZZER, dump the first 16 bytes of LLVMFuzzerTestOneInput to restore
    # after taking the snapshot. These bytes are corrupted 
    if [[ "$LIBFUZZER" ]]; then 
        nm $1 | grep LLVMFuzzerTestOneInput

        if [ $? -eq 1 ]; then
            echo "LLVMFuzzerTestOneInput not found in $1."
            exit 1
        fi
        
        BYTES=`r2 -q -c 'p8 16 @ sym.LLVMFuzzerTestOneInput' $1`
    fi

    # Copy the binary into the root directory of the image
    e2cp -p $1 /qemu_snapshot/IMAGE/bookworm.img:$HOMEDIR/`basename $1`

    # Copy the binary into the output directory
    sudo cp $1 $OUTPUT/`basename $1`.bin

    # Init the rc.local script
    echo "#!/bin/sh -e"  >> rc.local

    # Enable the snapshot
    echo "export SNAPSHOT=1" >> rc.local

    # If user is not root, run gdb under gdb in order to gain kernel symbols as root
    if [ $USER != 'root' ]; then
        echo "gdb --command=$HOMEDIR/gdbcmds --args gdb" >> rc.local

        # Copy the symbols found under root
        echo "mv /tmp/gdb.symbols /tmp/gdb.symbols.root" >> rc.local

        # Remove the modules and memory map for this execution since we only care about
        # symbols
        echo "rm /tmp/gdb.modules" >> rc.local
        echo "rm /tmp/gdb.vmmap" >> rc.local
    fi

    # If user is not root, run gdb under the given user
    if [ $USER != 'root' ]; then
        echo "su $USER -c '" >> rc.local
    fi

    # Create the script to start on boot
    echo -n "gdb --command=$HOMEDIR/gdbcmds --args $HOMEDIR/`basename $1` "  >> rc.local
    shift 1

    # Add the rest of the arguments to the script
    while [ $# -gt 0 ]
    do
        if [ -f $1 ];
        then
            # If an argument is a file, copy the file into the image
            e2cp -p $1 /qemu_snapshot/IMAGE/bookworm.img:$HOMEDIR/`basename $1`

            echo -n "$HOMEDIR/`basename $1` " >> rc.local
        elif [ -d $1 ];
        then
            # If an argument is a directory, copy the entire directory into the image
            e2cp -r $1 /qemu_snapshot/IMAGE/bookworm.img:$HOMEDIR
            echo -n "$HOMEDIR/`basename $1` " >> rc.local
        else
            # Argument is not a file, use the argument as normal
            echo -n "$1 " >> rc.local
        fi

        # Shift to the next argument
        shift 1
    done

    # If user is not root, close the command executed
    if [ $USER != 'root' ]; then
        echo "'" >> rc.local
    fi

    # Add a newline
    echo "" >> rc.local

    # Copy the GDB output files back to the local directory
    echo "cp /tmp/gdb* $HOMEDIR" >> rc.local

    # Ensure the output files are actually written to the image
    echo "sync" >> rc.local

    # Status check after GDB exits to see if the files are written
    echo "ls -la $HOMEDIR"  >> rc.local

    # Make the script executable and owned by root
    sudo chmod +x rc.local
    sudo chown root:root rc.local
fi

if [[ "$LIBFUZZER" ]]; then 
    echo "LIBFUZZER SNAPSHOT DETECTED"
    echo "Taking a snapshot at LLVMFuzzerTestOneInput"

    # Ignore leak detection. 
    echo 'set environment ASAN_OPTIONS=detect_leaks=0' > gdbcmds

    # Stop at the first chance in the target in order to enable the breakpoint on LLVMFuzzerTestOneInput
    echo 'start'                         >> gdbcmds
    echo 'del *'                         >> gdbcmds
    echo 'x/16xb LLVMFuzzerTestOneInput' >> gdbcmds

    # Remove all coverage trace from libfuzzer since we are using breakpoint coverage in Snapchange
    echo 'set {unsigned char}(__sanitizer_cov_trace_cmp1)=0xc3'          >> gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_cmp2)=0xc3'          >> gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_cmp4)=0xc3'          >> gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_cmp8)=0xc3'          >> gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_const_cmp1)=0xc3'    >> gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_const_cmp2)=0xc3'    >> gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_const_cmp4)=0xc3'    >> gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_const_cmp8)=0xc3'    >> gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_div4)=0xc3'          >> gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_div8)=0xc3'          >> gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_gep)=0xc3'           >> gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_pc_guard)=0xc3'      >> gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_pc_guard_init)=0xc3' >> gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_pc_indir)=0xc3'      >> gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_switch)=0xc3'        >> gdbcmds

    # Insert (int3 ; vmcall) on the LLVMFuzzerTestOneInput 
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x0)=0xcc' >> gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x1)=0x0f' >> gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x2)=0x01' >> gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x3)=0xc1' >> gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x4)=0xcd' >> gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x5)=0xcd' >> gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x6)=0xcd' >> gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x7)=0xcd' >> gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x8)=0xcd' >> gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x9)=0xcd' >> gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0xa)=0xcd' >> gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0xb)=0xcd' >> gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0xc)=0xcd' >> gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0xd)=0xcd' >> gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0xe)=0xcd' >> gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0xf)=0xcd' >> gdbcmds

    # Continue execution until the LLVMFuzzerTestOneInput and take the snapshot as normal
    echo 'continue'                                         >> gdbcmds
    echo "source $HOMEDIR/gdbsnapshot.py"                   >> gdbcmds
    echo 'ni'                                               >> gdbcmds
    echo 'ni'                                               >> gdbcmds
    echo 'quit'                                             >> gdbcmds
else
    # Default snapshot implementation that expects (int3 ; vmcall) to be in the target
    # 
    # Execute to the first int3, execute the gdbsnapshot, execute vmcall, then exit
    echo 'run'                            >> gdbcmds
    echo "source $HOMEDIR/gdbsnapshot.py" >> gdbcmds
    echo 'ni'                             >> gdbcmds
    echo 'ni'                             >> gdbcmds
    echo 'quit'                           >> gdbcmds
fi

# Copy the rc.local into the image
e2cp -p rc.local /qemu_snapshot/IMAGE/bookworm.img:/etc/rc.local 
e2cp -p gdbcmds /qemu_snapshot/IMAGE/bookworm.img:/root/gdbcmds
e2cp -p /qemu_snapshot/gdbsnapshot.py /qemu_snapshot/IMAGE/bookworm.img:/root/gdbsnapshot.py

# gdbcmds
e2cp -p /qemu_snapshot/IMAGE/bookworm.img:/root/gdbcmds \-

# Take the snapshot
echo "[+] Taking the snapshot"
cd /qemu_snapshot
./snapshot.sh
tail vm.log

# Init the output fuzzer directory
mkdir -p fuzzer/src

# Move the snapshot directory to the fuzzer directory
mv output fuzzer/snapshot

# Copy the binary to the snapshot directory
cp $BINARY fuzzer/snapshot/`basename $BINARY`.bin

if [[ "$LIBFUZZER" ]]; then 
    # Use the libfuzzer template fuzzer
    mv src/fuzzer.rs.libfuzzer fuzzer/src/fuzzer.rs

    # Restore the original bytes at the LLVMFuzzerTestOneInput bytes
    r2 -w -q -c "/x cc0f01c1cdcdcdcdcdcdcdcdcdcdcdcd ; wx $BYTES @@ hit0*" ./fuzzer/snapshot/fuzzvm.physmem
else
    # Default to the normal fuzzer template
    mv src/fuzzer.rs fuzzer/src/fuzzer.rs
fi

# Begin the fuzzer with the SNAPSHOT output from the vm.log
COMMENTS=`grep SNAPSHOT vm.log | sed 's_^_// _g' | tr '\n' '\r'`
echo "Found snapshot comments in vm.log:"
echo $COMMENTS

# Slight hack to sed a multiline string
sed -z "s_REPLACEMECOMMENTS_${COMMENTS}_" fuzzer/src/fuzzer.rs | tr '\r' '\n' > /tmp/.fuzzer.rs
mv /tmp/.fuzzer.rs fuzzer/src/fuzzer.rs

# Replace the RIP for the snapshot
# RIP=0000000000401362 RFL=00000306 [-----P-] CPL=3 II=0 A20=1 SMM=0 HLT=0
NEWRIP=`grep RIP fuzzer/snapshot/*qemuregs | cut -d' ' -f1 | cut -d'=' -f2`
echo "Found RIP in snapshot: $NEWRIP"
sed  -i "s/REPLACEMERIP/0x${NEWRIP}/" fuzzer/src/fuzzer.rs

# Replace the CR3 for the snapshot
# 16:CR0=80050033 CR2=00007f8814613610 CR3=00000000084be000 CR4=000006f0
NEWCR3=`grep CR3 fuzzer/snapshot/*qemuregs | cut -d' ' -f3 | cut -d'=' -f2`
echo "Found CR3 in snapshot: $NEWCR3"
sed -i "s/REPLACEMECR3/0x${NEWCR3}/" fuzzer/src/fuzzer.rs

# Move the template source for this snapshot
mv src/main.rs fuzzer/src/main.rs
mv src/Cargo.toml fuzzer/Cargo.toml

# Copy out the GDB files from the image
e2cp /qemu_snapshot/IMAGE/bookworm.img:/tmp/gdb.symbols fuzzer/snapshot
e2cp /qemu_snapshot/IMAGE/bookworm.img:/tmp/gdb.modules fuzzer/snapshot
e2cp /qemu_snapshot/IMAGE/bookworm.img:/tmp/gdb.vmmap fuzzer/snapshot

# Copy the snapshot directory to the output directory
echo "[+] Copying out the snapshot directory"
if [ -d /out/fuzzer ]; then
    OUTDIR=/out/fuzzer_`date --iso-8601=seconds`
    mv fuzzer $OUTDIR

    # Make the permissions of the output directory to the binary
    chown -R --reference=$BINARY $OUTDIR
    echo "[+] Snapshot found in $OUTDIR"
else
    mv fuzzer /out
    chown -R --reference=$BINARY /out/fuzzer

    # Make the permissions of the output directory to the binary
    echo "[+] Snapshot found in /out/fuzzer"
fi

ls -la /out
