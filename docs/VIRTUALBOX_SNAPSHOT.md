# VirtualBox Snapshotting

VirtualBox comes with a debugger for the hypervisor itself which has two commands
particularly useful for snapshotting:

* `writecore`: Contains the register state of the guest at the time of the snapshot
* `.pgmphystofile`: Writes the raw physical memory to disk

The corefile written during `writecore` also contains the physical memory as well, but
requires just a bit more parsing to dump into the raw format. `.pgmphystofile` gives the
same information at the same time as taking the snapshot, but parsing the corefile to get
the raw physical memory is also possible.

## Starting VirtualBox

The VirtualBox debugger can be started by the command line. 

```
❯ VirtualBoxVM --debug-commmand-line --start-running --startvm "YOUR VM NAME" 
```

## Guest state

The snapshot taken must be at a specific known instruction and not an arbitrary location
in a target process. Even if a target process is running and `writecore` is executed,
VirtualBox might or might not take a coredump of the target process at a specific point
that we care about (could take a coredump of VirtualBox itself or some other thread in
the system).

To help mitigate this, we can insert an infinite loop into a target process to give us
more time to take a controlled snapshot. One method of achiving this is to execute a
target process under a debugger:

* Execute the target to the instruction that where the snapshot will be taken. 
* Store the current 6 bytes of `RIP` they will be patched out shortly
* Overwrite `RIP` with `pause ; jmp -4` to force an infinite loop
* Continue execution of the guest
* With the guest now infinitely looping, execute the `writecore` and `.pgmphystofile` 
  commands in the VirtualBox debugger
* Parse the coredump file using `parse_vbcore` and make sure RIP matches the guest RIP.
  This is usually enough to make sure the snapshot was taken at the correct location.

These are now the files used with the infrastructure to start fuzzing. 

Two options now to un-patch the infinite loop:

* Locate the patched bytes in the physical memory dump and restore them 
* Patch them back in the target each iteration of the fuzzer


## gdbsnapshot.py

There is an included snapshot utility for GDB found in this repository.

```
sudo gdb ./target_process
... Execute process to the snapshot location ...
source gdbsnapshot.py
```

This will dump the patched RIP bytes, write the userspace memory map, and dump the found
symbols of the userspace modules as well as kernel symbols into a json file used by the
infrastructure.
