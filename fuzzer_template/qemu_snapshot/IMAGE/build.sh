#!/bin/bash

# Variables affected by options
DIR=chroot
ARCH=$(uname -m)
RELEASE=bookworm
FEATURE=minimal
SEEK=2047
PERF=false
OUT=output
USER=root


# 
if [ $USER = 'root' ]; then
    HOMEDIR=/root
else
    HOMEDIR=/home/$USER

fi

# Make the directory to hold the original binary to copy into the snapshot directory
sudo mkdir -p $DIR$HOMEDIR

# If given any new arguments, rewrite the rc.local boot script
if [ $# -gt 0 ];
then
    # Remove previous snapshot script
    sudo rm $DIR/etc/rc.local || true
 
    # Copy the binary into the root directory of the image
    sudo cp $1 $DIR$HOMEDIR/`basename $1`

    # Make the directory to hold the original binary to copy into the snapshot directory
    mkdir -p $OUT

    # Copy the binary into the output directory
    sudo cp $1 $OUT/`basename $1`.bin

    # Make the copied binary executable
    sudo chmod +x $DIR$HOMEDIR/`basename $1`

    # Init the rc.local script
    echo "#!/bin/sh -e"  | sudo tee -a $DIR/etc/rc.local

    # Enable the snapshot
    echo "export SNAPSHOT=1" | sudo tee -a $DIR/etc/rc.local

    # If user is not root, run gdb under gdb in order to gain kernel symbols as root
    if [ $USER != 'root' ]; then
        echo "gdb --command=$HOMEDIR/gdbcmds --args gdb" | sudo tee -a $DIR/etc/rc.local

        # Copy the symbols found under root
        echo "mv /tmp/gdb.symbols /tmp/gdb.symbols.root" | sudo tee -a $DIR/etc/rc.local

        # Remove the modules and memory map for this execution since we only care about
        # symbols
        echo "rm /tmp/gdb.modules" | sudo tee -a $DIR/etc/rc.local
        echo "rm /tmp/gdb.vmmap" | sudo tee -a $DIR/etc/rc.local
    fi

    # If user is not root, run gdb under the given user
    if [ $USER != 'root' ]; then
        echo "su $USER -c '" | sudo tee -a $DIR/etc/rc.local
    fi

    # Create the script to start on boot
    echo -n "gdb --command=$HOMEDIR/gdbcmds --args $HOMEDIR/`basename $1` "  | sudo tee -a $DIR/etc/rc.local
    shift 1

    # Add the rest of the arguments to the script
    while [ $# -gt 0 ]
    do
        if [ -f $1 ];
        then
            # If an argument is a file, copy the file into the image
            sudo cp $1 $DIR$HOMEDIR/`basename $1`
            echo -n "$HOMEDIR/`basename $1` " | sudo tee -a $DIR/etc/rc.local
        elif [ -d $1 ];
        then
            # If an argument is a directory, copy the entire directory into the image
            sudo cp -r $1 $DIR$HOMEDIR
            echo -n "$HOMEDIR/`basename $1` " | sudo tee -a $DIR/etc/rc.local
        else
            # Argument is not a file, use the argument as normal
            echo -n "$1 " | sudo tee -a $DIR/etc/rc.local
        fi

        # Shift to the next argument
        shift 1
    done

    # If user is not root, close the command executed
    if [ $USER != 'root' ]; then
        echo "'" | sudo tee -a $DIR/etc/rc.local
    fi

    # Add a newline
    echo "" | sudo tee -a $DIR/etc/rc.local

    # Copy the GDB output files back to the local directory
    echo "cp /tmp/gdb* $HOMEDIR"  | sudo tee -a $DIR/etc/rc.local

    # Ensure the output files are actually written to the image
    echo "sync" | sudo tee -a $DIR/etc/rc.local

    # Status check after GDB exits to see if the files are written
    echo "ls -la $HOMEDIR"  | sudo tee -a $DIR/etc/rc.local

    # Make the script executable and owned by root
    sudo chmod +x $DIR/etc/rc.local
    sudo chown root:root $DIR/etc/rc.local

fi

# Add newline to thes script
echo "" | sudo tee -a $DIR/etc/rc.local

# Copy in the gdbsnapshot.py
sudo cp ../gdbsnapshot.py $DIR$HOMEDIR/gdbsnapshot.py

tail $DIR$HOMEDIR/gdbsnapshot.py

# Try to remove the old gdbcmds since we are writing a new one below
sudo rm $DIR$HOMEDIR/gdbcmds || true

if [[ "$LIBFUZZER" ]]; then 
    echo "LIBFUZZER SNAPSHOT DETECTED"
    echo "Taking a snapshot at LLVMFuzzerTestOneInput"

    # Ignore leak detection. 
    echo 'set environment ASAN_OPTIONS=detect_leaks=0' | sudo tee -a $DIR$HOMEDIR/gdbcmds

    # Stop at the first chance in the target in order to enable the breakpoint on LLVMFuzzerTestOneInput
    echo 'start'                         | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'del *'                         | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'x/16xb LLVMFuzzerTestOneInput' | sudo tee -a $DIR$HOMEDIR/gdbcmds

    # Remove all coverage trace from libfuzzer since we are using breakpoint coverage in Snapchange
    echo 'set {unsigned char}(__sanitizer_cov_trace_const_cmp4+0)=0xc3'  | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_cmp)=0xc3'           | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_cmp1)=0xc3'          | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_cmp2)=0xc3'          | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_cmp4)=0xc3'          | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_cmp8)=0xc3'          | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_const_cmp1)=0xc3'    | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_const_cmp2)=0xc3'    | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_const_cmp4)=0xc3'    | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_const_cmp8)=0xc3'    | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_div4)=0xc3'          | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_div8)=0xc3'          | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_gep)=0xc3'           | sudo tee -a $DIR$HOMEDIR/gdbcmds
    # echo 'set {unsigned char}(__sanitizer_cov_trace_pc)=0xc3'            | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_pc_guard)=0xc3'      | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_pc_guard_init)=0xc3' | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_pc_indir)=0xc3'      | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(__sanitizer_cov_trace_switch)=0xc3'        | sudo tee -a $DIR$HOMEDIR/gdbcmds

    # Insert (int3 ; vmcall) on the LLVMFuzzerTestOneInput 
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x0)=0xcc' | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x1)=0x0f' | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x2)=0x01' | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x3)=0xc1' | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x4)=0xcd' | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x5)=0xcd' | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x6)=0xcd' | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x7)=0xcd' | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x8)=0xcd' | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0x9)=0xcd' | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0xa)=0xcd' | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0xb)=0xcd' | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0xc)=0xcd' | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0xd)=0xcd' | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0xe)=0xcd' | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'set {unsigned char}(LLVMFuzzerTestOneInput+0xf)=0xcd' | sudo tee -a $DIR$HOMEDIR/gdbcmds

    # Continue execution until the LLVMFuzzerTestOneInput and take the snapshot as normal
    echo 'continue'                                         | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo "source $HOMEDIR/gdbsnapshot.py"                   | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'ni'                                               | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'ni'                                               | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'quit'                                             | sudo tee -a $DIR$HOMEDIR/gdbcmds
else
    # Default snapshot implementation that expects (int3 ; vmcall) to be in the target
    # 
    # Execute to the first int3, execute the gdbsnapshot, execute vmcall, then exit
    echo 'run'                            | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo "source $HOMEDIR/gdbsnapshot.py" | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'ni'                           | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'ni'                           | sudo tee -a $DIR$HOMEDIR/gdbcmds
    echo 'quit'                           | sudo tee -a $DIR$HOMEDIR/gdbcmds
fi


# Sanity check the script was written properly
echo "!!! Sanity check the startup script !!!"
cat $DIR/etc/rc.local
echo "!!! Sanity check the startup script !!!"

# Display the home directory as a sanity check
echo "!!! Sanity check the home directory !!!"
sudo ls -la $DIR$HOMEDIR
echo "!!! Sanity check the home directory !!!"

# Build a disk image
dd if=/dev/zero of=$RELEASE.img bs=1M seek=$SEEK count=1
sudo mkfs.ext4 -F $RELEASE.img
sudo mkdir -p /mnt/$DIR
sudo mount -o loop $RELEASE.img /mnt/$DIR
sudo cp -a $DIR/. /mnt/$DIR/.
sudo umount /mnt/$DIR
