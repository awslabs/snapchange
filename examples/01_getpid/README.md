# Tutorial 1 - Basic usage tutorial

This tutorial is a walkthrough of:

    * Taking a snapshot of a target using `qemu_snapshot`
    * Writing a fuzzer
    * Watching coverage analysis and blockers
    * Using a hook to force a condition
    * Finding a crash

_There is an included `./make_example.sh` script to build and snapshot this example. This script
goes through each of the steps described below._

## Target overview

The following code is the target for this tutorial:

```c
// Example test case for snapshot fuzzing
//
// Test the ability to write arbitrary memory and registers into a snapshot
//
// clang -ggdb -O0 example1.c -o example1

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void fuzzme(char* data) {
    int pid    = getpid();

    // Correct solution: data == "fuzzmetosolveme!", pid == 0xdeadbeef
    if (data[0]  == 'f') {
    if (data[1]  == 'u') {
    if (data[2]  == 'z') {
    if (data[3]  == 'z') {
    if (data[4]  == 'm') {
    if (data[5]  == 'e') {
    if (data[6]  == 't') {
    if (data[7]  == 'o') {
    if (data[8]  == 's') {
    if (data[9]  == 'o') {
    if (data[10] == 'l') {
    if (data[11] == 'v') {
    if (data[12] == 'e') {
    if (data[13] == 'm') {
    if (data[14] == 'e') {
    if (data[15] == '!') {
        pid = getpid();
        if (pid == 0xdeadbeef) {
            *(int*)0xcafecafe = 0x41414141;
        }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }

    return;
}

int main() {
    char* data = "aaaaaaaaaaaaaaaa";

    // Print the memory buffer address and pid address for fuzzing
    printf("SNAPSHOT Data buffer: %p\n", data);

    // Ensure the stdout has been flushed
    fflush(stdout);

    // Snapshot taken here
    if(getenv("SNAPSHOT") != (void*)0) { __asm("int3 ; vmcall"); }

    // Call the fuzzme function
    fuzzme(data);

    return 0;
}
```

There are two main goals for the target:

* Mutate a simple string 
* Modify the return pid of `getpid` syscall to be `0xdeadbeef` to force a crash

Note how the snapshot mechanism is added to the source code. 

```c
// Snapshot taken here
if(getenv("SNAPSHOT") != (void*)0) { __asm("int3 ; vmcall"); }
```

The `int3 ; vmcall` is how the snapshot will trigger. The `int3` is used for `gdb` to 
catch the snapshot and write symbols and memory map to disk. The `vmcall` instruction 
will trigger `QEMU` itself to write the physical memory and register state to disk. The
`strcmp(getenv("SNAPSHOT") != (void*)0)` is to allow runtime triggering of the snapshot 
mechanism.

The target also prints the memory address of the `data` buffer. These
addresses are important for knowing where to write the fuzz case in the snapshot.

The compiled binary used is `example1`. Let's begin with taking the snapshot.

## Snapshot

The `qemu_snapshot` project is how we will take a snapshot for this project. Briefly, the
project will build a Linux kernel, a patched QEMU which enables snapshotting via
`vmcall` instruction, and a Debian disk with the target binary running during boot under
`gdb`.

The fuzzer template included in snapchange contains scripts that facilitates:

    * Building the harness for a target
    * Taking a snapshot of the harness using `qemu_snapshot`
    * Generating a fuzzer.rs template, filling in information for this specific snapshot
    * Generating coverage breakpoints using `bn_snapchange.py` (or radare2)

Copy the fuzzer template (containing `qemu_snapshot`) and target source code from Snapchange as this example's repository:

```sh
$ cp -r -L <snapchange_dir>/fuzzer_template snapchange-example-01
$ cp <snapchange_dir>/examples/01_getpid/example1.c snapchange-example-01
$ cd snapchange-example-01
```

Add snapchange path as a dependency:

```sh
$ cargo add snapchange --path <snapchange_dir>
```

Modify the `snapchange-example-01/create_snapshot.sh` to build and use the example1 binary.

```sh
# Build the harness for this target
build_harness() {
  if [ ! -f example1 ]; then
      clang -ggdb -O0 example1.c -o example1
  fi
}
```

```sh
# Take the snapshot
take_snapshot() {
  # Build the image to execute the harness on start
  pushd ./qemu_snapshot/IMAGE
  ./build.sh ../../example1
  popd

  # Take the snapshot
  pushd ./qemu_snapshot
  ./snapshot.sh
  popd
}
```

```sh
# Create the coverage breakpoints and analysis 
create_coverage_breakpoints() {
  # Attempt to create the coverage breakpoints and analysis
  # Our example1 binary is renamed to example1.bin in ./snapshot
  if [ ! -f "./snapshot/example1.bin.covbps" ]; then 
    # Binary Ninja
    python3 bn_snapchange.py --bps --analysis ./snapshot/example1.bin

    # radare2
    # r2 -q -c 'aa ; afb @@ *' ./snapshot/example1.bin | cut -d' ' -f1 | sort | uniq > ./snapshot/example1.bin.covbps
  fi
}
```

Execute the `./create_snapshot.sh` script to build and take the snapshot of the target.

```sh
./create_snapshot.sh
```

Here we should see lots of kernel debug messages. At the end of snapshot, we should see a
listing of the `snapshot` directory:

```
[*] Finished booting.. extracting gdb output
[*] Moving the snapshot data into output
[*] Found the following files
total 2170816
drwxrwxr-x  2 ubuntu ubuntu       4096 Sep 19 21:08 .
drwxrwxr-x  9 ubuntu ubuntu       4096 Sep 19 21:08 ..
-rwxr-xr-x  1 ubuntu ubuntu      17776 Sep 19 21:07 example1.bin
-rw-rw-r--  1 ubuntu ubuntu 2147483647 Sep 19 21:08 fuzzvm.physmem
-rw-rw-r--  1 ubuntu ubuntu       2359 Sep 19 21:08 fuzzvm.qemuregs
-rw-r--r--. 1 ubuntu ubuntu        118 Sep 19 21:08 gdb.modules
-rw-r--r--. 1 ubuntu ubuntu    8951070 Sep 19 21:08 gdb.symbols
-rw-r--r--. 1 ubuntu ubuntu       2186 Sep 19 21:08 gdb.vmmap
-rwxrwxr-x  1 ubuntu ubuntu   73646312 Sep 19 21:07 vmlinux
```

We should see the following files in the `output` directory:

* `fuzzvm.physmem` - Physical memory snapshot
* `fuzzvm.qemuregs` - Register state
* `gdb.modules` - Loaded modules
* `gdb.symbols` - Found symbols
* `gdb.vmmap` - Memory map of the target process

Lastly, `qemu_snapshot` will display lines containing `SNAPSHOT from QEMU's log file. This is
mostly as a method of quickly finding the output written during the targets execution.

```
[*] Found this SNAPSHOT output from the vm log
[   21.756932] rc.local[193]: SNAPSHOT Data buffer: 0x402004 
[*] Killing the VM
```

This output tells us that the data buffer to fuzz is located at `0x402004` in the
snapshot. 

## Snapchange fuzzing

Each fuzzer must set two associated values: `START_ADDRESS` and `MAX_INPUT_LENGTH`. 
The `START_ADDRESS` provides a sanity check that the fuzzer and snapshot are paired 
correctly. The `START_ADDRESS` can be found in the `RIP` register in 
`./snapshot/fuzzvm.qemuregs`. 

The `MAX_INPUT_LENGTH` is the maximum length for a mutated input. 
 For this example, the maximum input length to generate is `16` bytes, the length of the 
buffer in the original target source code.

The `CR3` is the initial page table used by the snapshot. It can be found in the `CR3` register
in `./snapshot/fuzzvm.qemuregs`. This is mostly a helper variable used throughout the fuzzer.

The `RIP` and `CR3` values are automatically populated at the end of the `create_snapshot.sh` script.

```rust
// src/fuzzer.rs
const CR3: usize = <YOUR_CR3>
impl Fuzzer for Example1Fuzzer {
    type Input = Vec<u8>;
    const START_ADDRESS: u64 = 0x401362;
    const MAX_INPUT_LENGTH: usize = 16;
```

Let's rebuild `snapchange` now with the fuzzer initialized.

```sh
cargo build --release
```

With the fuzzer initialized, we can begin exploring `snapchange` and how to fuzz the
target.

## Snapchange command line

`snapchange` provides a few utilities to help in the fuzzing process. The first is to
attempt to translate and disassemble instructions at a specific address.

```sh
$ cargo run -r -- --help
```

```sh
Usage: Example01_getpid [OPTIONS] <COMMAND>

Commands:
  fuzz      Fuzz a project
  project   Gather data about the project
  trace     Collect a single step trace for an input
  minimize  Minimize an input by size or trace length
  coverage  Gather coverage for an input
  help      Print this message or the help of the given subcommand(s)

Options:
  -p, --project <PROJECT>  Path to the directory containing the target snapshot state. See documentation for the necessary files [default: ./snapshot]
  -v, --verbose...         More output per occurrence
  -q, --quiet...           Less output per occurrence
  -h, --help               Print help information
```

For example, we can `translate` the starting instruction to see what is going to be
executed first.

```sh
cargo run -r -- project translate
```

```sh
[2022-09-19T21:13:13Z INFO  snapchange::commands::project] Translating VirtAddr 0x401362 Cr3 0x84be000
[2022-09-19T21:13:13Z INFO  snapchange::commands::project] VirtAddr 0x401362 -> PhysAddr 0xad4d362
 HEXDUMP
---- address -----   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F    0123456789ABCDEF
0x0000000000401362: 48 8b 7d f0 e8 f5 fd ff ff 31 c0 48 83 c4 20 5d  | H.}......1.H...]
0x0000000000401372: c3 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00 f3 0f  | .f..............
0x0000000000401422: ** repeated line(s) **
 POTENTIAL INSTRUCTIONS
0x0000000000401362: 488b7df0           example1!main+0x62                              | mov rdi, qword ptr [rbp-0x10]
0x0000000000401366: e8f5fdffff         example1!main+0x66                              | call 0xfffffffffffffdfa
0x000000000040136b: 31c0               example1!main+0x6b                              | xor eax, eax
0x000000000040136d: 4883c420           example1!main+0x6d                              | add rsp, 0x20
0x0000000000401371: 5d                 example1!main+0x71                              | pop rbp
0x0000000000401372: c3                 example1!main+0x72                              | ret
```

Here we see the virtual address to physical address translation, the bytes found at the
translated physical address, and the attempted disassembly of those bytes. 

If we go backwards `4` bytes (from `0x401362` -> `0x40135e`), we should see the snapshot trigger instructions of 
`int3; vmcall`:

```sh
cargo run -r -- project translate 0x40135e
```

```
0x000000000040135e: cc                 example1!main+0x5e                              | int3
0x000000000040135f: 0f01c1             example1!main+0x5f                              | vmcall
0x0000000000401362: 488b7df0           example1!main+0x62                              | mov rdi, qword ptr [rbp-0x10]
0x0000000000401366: e8f5fdffff         example1!main+0x66                              | call 0xfffffffffffffdfa
0x000000000040136b: 31c0               example1!main+0x6b                              | xor eax, eax
0x000000000040136d: 4883c420           example1!main+0x6d                              | add rsp, 0x20
```

`translate` can be used as a sanity check that the snapshot was taken properly.

Let's setup the fuzzer now to fuzz the target.

## Fuzzing with snapchange - Finding the string

When taking the snapshot, we noted the memory address that is needed to fuzz:
    
* Data buffer: 0x402004 

_If using the `./make_example.sh` script, this data buffer address is found in the comments at the top of src/fuzzer.rs_

In the fuzzer, the `set_input` function is the function responsible for setting the given
mutated input into the target for the current fuzz case. For now, let's write the mutated 
input into the `data` buffer.

```rust
// src/fuzzer.rs
fn set_input(&mut self, input: &[u8], fuzzvm: &mut FuzzVm) -> Result<()> {
    // Write the mutated input
    fuzzvm.write_bytes_dirty(VirtAddr(0x402004), CR3, &input)?;
    Ok(())
}
```

Each virtual address must always be accompanied by the page table which translates the
virtual address. This page table can be found in the `CR3` register in 
`./snapshot/fuzzvm.qemuregs`.

The other useful setting to set is when to trigger a reset of the fuzz case. `snapchange`
calls these `reset breakpoints`. In this target, if we ever return from the current 
function, we know the fuzz case is finished and we want to start a different fuzz case. 
Using the `translate` function, we can find the address of the `ret` from the function.

```
$ cargo run -r -- project translate 0x40135e --instrs 10

POTENTIAL INSTRUCTIONS
0x000000000040135e: cc                 example1!main+0x5e                              | int3
0x000000000040135f: 0f01c1             example1!main+0x5f                              | vmcall
0x0000000000401362: 488b7df0           example1!main+0x62                              | mov rdi, qword ptr [rbp-0x10]
0x0000000000401366: e8f5fdffff         example1!main+0x66                              | call 0xfffffffffffffdfa
0x000000000040136b: 31c0               example1!main+0x6b                              | xor eax, eax
0x000000000040136d: 4883c420           example1!main+0x6d                              | add rsp, 0x20
0x0000000000401371: 5d                 example1!main+0x71                              | pop rbp
0x0000000000401372: c3                 example1!main+0x72                              | ret
[...]
```

We can set a `reset_breakpoint` as `0x401371` such that, if `0x401371` is ever executed,
to immediately exit the VM and start a new fuzz case. (Reminder, your `cr3` value will
probably be different than the one here)

```rust
// src/fuzzer/current_fuzzer.rs 
fn reset_breakpoints(&self) -> Option<&[BreakpointLookup]> {
    Some(&[
        BreakpointLookup::Address(VirtAddr(0x401371), CR3),
    ])
}
```

_If using the `./make_example.sh` script, this CR3 variable is auto-populated at the top of the src/fuzzer.rs file_

Let's rebuild `snapchange` and start fuzzing with `4` cores.

```sh
cargo run -r -- fuzz --cores 4
```

The terminal UI should come up with some useful statistics. Quickly, it should be seen
that no coverage is being found. 

`snapchange` currently relies on breakpoint coverage for determining coverage. This
format is just a `.covbps` file in the `project directory` containing a list of all
addresses that, if hit, signal a coverage hit. Typically, this is a list of basic blocks
in the target.

There is a [Binary Ninja](https://binary.ninja) script available 
[here](../../bn_snapchange.py) to generate basic block coverage, but any 
method of getting basic block coverage will work. For this tutorial there is already a 
`example1.covbps` for the target available in this directory. 

There is also a [radare2](https://github.com/radare2/radare2) command in the
`<snapchange_dir>/examples/01_getpid/Makefile` to generate similar data:

```Makefile
r2covbps: all
    r2 -q -c 'aa ; s main ; afb' example1 | cut -d' ' -f1 > example1.covbps
```

Let's copy that `example1.covbps` file into the output directory.


This file is a list of basic block addresses used as coverage breakpoints.

```sh
(ins)$ head example1.covbps
0x401000
0x401016
0x401014
0x401030
0x401036
...
```

For now, also copy over the `example1.coverage_analysis` file as well (for use later)

```sh
cp <SNAPCHANGE_DIR>/examples/01_getpid/example1.covbps ./snapshot cp <SNAPCHANGE_DIR>/examples/01_getpid/example1.coverage_analysis ./snapshot
```

Restarting the fuzzer should start to show more coverage.

```sh
cargo run -r -- fuzz --cores 4
```

NOTE: In the terminal UI, press `l` to move over to the coverage analysis panel to monitor
where the fuzzer is currently blocked. Looking at the `fuzzme`

```sh
29: 0x4011a6 example1!fuzzme+0x46 /home/ubuntu/snapchange/examples/01_getpid/example1.c:20:9
19: 0x4011fb example1!fuzzme+0x9b /home/ubuntu/snapchange/examples/01_getpid/example1.c:25:9
13: 0x40122e example1!fuzzme+0xce /home/ubuntu/snapchange/examples/01_getpid/example1.c:28:9
...
```

Eventually, we should see the string found in the `snapshot/current_corpus` as
`fuzzmetosolveme!`. The fuzzer is now stuck at the `pid == 0xdeadbeef` check.  Let's get
a single step trace of this input to see how we can bypass this check

## Fuzzing with snapchange - Hooking getpid

Single step traces can be really useful for analysis and triage as well as seeing what an
input is doing in the target.

Let's gather a trace of the corpus file containing the password `fuzzmetosolveme!`. In
this case, the file is `aed424a9`

```
(ins)$ xxd aed424a9
┌────────┬─────────────────────────┬─────────────────────────┬────────┬────────┐
│00000000│ 66 75 7a 7a 6d 65 74 6f ┊ 73 6f 6c 76 65 6d 65 21 │fuzzmeto┊solveme!│
└────────┴─────────────────────────┴─────────────────────────┴────────┴────────┘
```

```sh
cargo run -r -- trace ./snapshot/current_corpus/aed424a9
```

This will execute the given input gathering a single step trace.

```
[2022-09-19T21:41:33Z INFO  snapchange::commands::trace] Writing func trace file: "./traces/aed424a9_trace"
```

Checking this trace, we can see where the `getpid` result is checked against
`0xdeadbeef`.

```sh
$ cat ./traces/aed424a9_trace

ITERATION 1355 0xffffffffa7800f86 0x084be000 | restore_regs_and_return_to_kernel+0x1b                       
    test byte ptr [rsp+0x20], 0x4 
    [RSP:0xfffffe0000002fd8+0x20=0xfffffe0000002ff8 size:UInt8->0x2b]] 
    ??_Immediate8_?? [f6, 44, 24, 20, 04]
<snip>
ITERATION 1358 0x00007ffff7e94da7 0x084be000 | libc.so.6!__GI___getpid+0x7                                  
    ret 
    [c3]
ITERATION 1359 0x0000000000401288 0x084be000 | example1!fuzzme+0x128                                        
    mov dword ptr [rbp-0xc], eax 
    [RBP:0x7fffffffebe0+0xfffffffffffffff4=0x100007fffffffebd4]] 
    EAX:0xc1
    [89, 45, f4]
    /home/ubuntu/snapchange/examples/01_getpid/example1.c:33:13
ITERATION 1360 0x000000000040128b 0x084be000 | example1!fuzzme+0x12b                                        
    cmp dword ptr [rbp-0xc], 0xdeadbeef 
    [RBP:0x7fffffffebe0+0xfffffffffffffff4=0x7fffffffebd4 size:UInt32->0xc1]] 
    ??_Immediate32_?? [81, 7d, f4, ef, be, ad, de]
    /home/ubuntu/snapchange/examples/01_getpid/example1.c:34:17
```

The single step trace is a verbose trace with the register state of the
relevant instructions for the given step. Here we see where `getpid` is executed
in the kernel as well as the return back to userspace.

At address `0x401288`, the result from `getpid` (currently in `eax`) is written to the
stack at `rbp-0xc`. Let's hook this address and change `eax` from whatever `getpid`
returns to the value the target wants of `0xdeadbeef`.

Two options are available for hooking instructions: by address or by symbol. Let's hook
by symbols for this example. In our fuzzer, we can set a `Breakpoint` of type
`SymbolOffset`. The function is called before the hooked instruction is executed. 

The hook function is given the current `FuzzVm` of the guest being executed. We can set
`rax` to `0xdeadbeef` to force `getpid` to emulate returning this value. This function
also returns an `Execution`. In this case, we want the VM to `Continue` execution (and
not `Reset`), so we return `Execution::Continue` in order for snapchage to know to
continue executing the VM.

```rust
fn breakpoints(&self) -> Option<&[Breakpoint]> {
    Some(&[
        // ITERATION 1359 0x0000000000401288 0x084be000 | example1!fuzzme+0x128                                        
        //     mov dword ptr [rbp-0xc], eax 
        Breakpoint {
            lookup:  BreakpointLookup::SymbolOffset("example1!fuzzme", 0x128), 
            bp_type: BreakpointType::Repeated,
            bp_hook: |fuzzvm: &mut FuzzVm, input, _fuzzer| { 
                // Set rax to 0xdeadbeef
                fuzzvm.set_rax(0xdead_beef);
                Ok(Execution::Continue)
            }
        },
    ])
}
```

Restarting fuzzing again should result in the passing of this conditional, hitting the
crashing point.

Moving the TUI over to the `Crashes` tab (using `Right` arrow or `k`) should show a newly 
discovered crash:

```
┌Found crashes────────────────────────────────────────────┐
│SIGSEGV_addr_0xcafecafe_code_AddressNotMappedToObject    │
```

We can check the crashing cases in `./snapshot/crashes` (using [fd](https://github.com/sharkdp/fd))

```
$ fd --type file . ./snapshot/crashes
./snapshot/crashes/SIGSEGV_addr_0xcafecafe_code_AddressNotMappedToObject/c2b9b72428f4059c
```

We see a `SIGSEGV` crashing at address `0xcafecafe`. We can then trace this crashing
input to get the crashing trace.

```
cargo run -r -- trace ./snapshot/crashes/SIGSEGV_addr_0xcafecafe_code_AddressNotMappedToObject/c2b9b72428f4059c
```

```
$ tail -n 40 ./traces/aed424a9_trace

ITERATION 1362 0x0000000000401298 0x084be000 | example1!fuzzme+0x138
    mov eax, 0xcafecafe
    EAX:0xdeadbeef
    ??_Immediate32_?? [b8, fe, ca, fe, ca]
    /home/ubuntu/snapchange/examples/01_getpid/example1.c:35:31
ITERATION 1363 0x000000000040129d 0x084be000 | example1!fuzzme+0x13d
    mov dword ptr [rax], 0x41414141
    [RAX:0xcafecafe]
    ??_Immediate32_?? [c7, 00, 41, 41, 41, 41]
    /home/ubuntu/snapchange/examples/01_getpid/example1.c:35:31
ITERATION 1364 0xffffffffa6a7fde0 0x084be000 | force_sig_fault+0x0
    mov rcx, qword ptr gs:[0x1ad00]
    RCX:0x1
    [None:0x0+0x1ad00=0x1ad00 size:UInt64->????]]
    [65, 48, 8b, 0c, 25, 00, ad, 01, 00]
```

And there's the crashing instruction.

## Conclusion

Here we took a look at some of the basics of `snapchange`:

* Taking a snapshot of a target using `qemu_snapshot`
* Writing a simple fuzzer for the target by writing mutated bytes
* Examining into the target snapshot using `translate`
* Watching the coverage analysis tracker update to show the current coverage blockers
* Getting a single step trace for an input using `trace`


# Bonus - Other breakpoints

There are other breakpoints we could get to achieve the same goal of returning
`0xdeadbeef` from `getpid`.

We could emulate the call to `getpid` and never call the actual function. Here, we hook
at the `getpid` symbol and then emulate the call itself while faking return back to the
target.

```rust
fn breakpoints(&self) -> Option<&[Breakpoint]> {
    Some(&[
        // ITERATION 650 0x00007ffff7e94da0 0x084be000 | libc.so.6!__GI___getpid+0x0
        //     mov eax, 0x27 
        Breakpoint {
            lookup:   BreakpointLookup::SymbolOffset("libc.so.6!__GI___getpid", 0x0), 
            bp_type: BreakpointType::Repeated,
            bp_hook: |fuzzvm: &mut FuzzVm, _input, _fuzzer| { 
                // Set the return value to 0xdeadbeef
                fuzzvm.set_rax(0xdead_beef);

                // Fake an immediate return from the function by setting RIP to the
                // value popped from the stack (this assumes the function was entered
                // via a `call`)
                fuzzvm.fake_immediate_return()?;

                // Continue execution
                Ok(Execution::Continue)
            }
        },
    ])
}
```

We could also hook in the syscall itself and change when the `pid` value is read. Here is
the exact location in the syscall where the pid of `0xc1` is read (taken from the
original trace).

```
ITERATION 1152 0xffffffffa6a8fa19 0x084be000 | __task_pid_nr_ns+0x89                                        
    mov r12d, dword ptr [rax+0x60] 
    R12D:0x0
    [RAX:0xffff94f1c2776f00+0x60=0xffff94f1c2776f60 size:UInt32->0xc1]] 
    [44, 8b, 60, 60]
```

We can switch up the breakpoint here and use the exact address of this instruction that
we are wanting to hook.


```rust
fn breakpoints(&self) -> Option<&[Breakpoint]> {
    Some(&[
        // ITERATION 1152 0xffffffffa6a8fa19 0x084be000 | __task_pid_nr_ns+0x89
        //     mov r12d, dword ptr [rax+0x60] 
        //     R12D:0x0
        //     [RAX:0xffff94f1c2776f00+0x60=0xffff94f1c2776f60 size:UInt32->0xc1]] 
        Breakpoint {
            lookup:  BreakpointLookup::Address(VirtAddr(0xffffffffa6a8fa19), Cr3(0x084be000)),
            bp_type: BreakpointType::Repeated,
            bp_hook: |fuzzvm: &mut FuzzVm, _input, _fuzzer| { 
                // mov r12d, dword ptr [rax+0x60] 
                // 0xc1 is currently at [rax + 0x60]. Overwrite this value with
                // 0xdeadbeef

                // Get the current `rax` value
                let rax = fuzzvm.rax();
                let val: u32 = 0xdeadbeef;

                // Write the wanted 0xdeadbeef in the memory location read in the
                // kernel
                fuzzvm.write_bytes_dirty(VirtAddr(rax + 0x60), Cr3(0x84be000), 
                    &val.to_le_bytes())?;

                // Continue execution
                Ok(Execution::Continue)
            }
        },
    ])
}
```
