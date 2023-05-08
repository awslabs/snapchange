#!/bin/bash

# Directory to output snapshot files
OUTPUT=output

# Delete the old OUTPUT directory if it exists
if [[ -d $OUTPUT ]]
then
    rm -rf $OUTPUT
fi

# Create the output directory
mkdir -p $OUTPUT

# If there are files in the ./IMAGE/output directory from build.sh, copy the .bin files
if [[ -d ./IMAGE/output ]]
then
    for f in $(find bin$ ./IMAGE/output -type f); do 
        echo "Found $f.. Copying .bin files into $OUTPUT"
        cp $f $OUTPUT
    done
fi

# Copy over the `vmlinux` into the output directory
cp linux/vmlinux $OUTPUT

# Start the VM
./utils/start.sh &

sleep 1

# While the VM is booting, wait for the login prompt. Once the login prompt is shown,
# extarct the gdb output and kill the VM
while true; do
    # Login prompt signals that the /etc/rc.local script executed and can extract output
    grep "linux login:" vm.log 2>&1 >/dev/null

    # Status code of 0 means the login prompt was found in the vm.log
    if [ $? -eq 0 ]; then
        echo "[*] Finished booting.. extracting gdb output";
        ./utils/extract.sh

        echo "[*] Moving the snapshot data into $OUTPUT"
        mv fuzzvm.* $OUTPUT
        mv gdb.* $OUTPUT

        echo "[*] Found the following files"
        ls -la $OUTPUT

        echo "[*] Found this SNAPSHOT output from the vm log"
        grep SNAPSHOT vm.log

        echo "[*] Killing the VM"
        ./utils/kill.sh

        echo "Done!"
        break
    fi

    echo "[snapshot.sh] Waiting for login prompt.."
    sleep 2
done

# Create the reset script for the snapshot
cp ./utils/reset_snapshot.sh $OUTPUT/reset.sh
