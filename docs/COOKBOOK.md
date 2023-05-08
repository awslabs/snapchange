# Snapchange quick reference commands

Below are a set of quick reference commands available in Snapchange.

## Fuzz commands

### Fuzz a project using 4 cores
 
```
$ cargo run -r -- fuzz -c 4
```

### Fuzz a project using 32 cores with a `target_snapshot` directory holding the snapshot
 
```
$ cargo run -r -- fuzz -c 32 -p ./target_snapshot
```

### Fuzz a project using 2 cores with a non-default corpus directory
 
```
$ cargo run -r -- fuzz -c 2 -i ./initial_corpus
```

### Fuzz a project using 8 cores with a 10 second timeout
 
```
$ cargo run -r -- fuzz -c 8 --timeout 10s
```

### Generate HTML coverage of the current fuzzer state

```
$ genhtml -o coverage_html ./snapshot/coverage.lcov
$ cd coverage_html
$ python3 -m http.server 2222
# Browse to http://127.0.0.1:2222
```

## Trace commands

### Single step trace the given crash file
 
```
$ cargo run -r -- trace ./crashing_input
```

```
$ cat ./snapshot/traces/crashing_input_trace
$ cat ./snapshot/traces/crashing_input.func_trace_0
```

<details>
    <summary>Further explanation</summary>

* `_trace` - Contains the verbose single step execution trace

Example:

    INSTRUCTION 000 0x0000000000401362 0x084be000 | example1!main+0x62
        mov rdi, qword ptr [rbp-0x10]
        RDI:0x7fffffffef11 -> 0x313d544f48535041
        [RBP:0x7fffffffec10+0xfffffffffffffff0=0x7fffffffec00 size:UInt64->0x402004]]
        [48, 8b, 7d, f0]
        /home/ubuntu/snapchange/examples/01_getpid/example1.c:70:12
    INSTRUCTION 001 0x0000000000401366 0x084be000 | example1!main+0x66
        call 0xfffffffffffffdfa
        ??_NearBranch64_?? [e8, f5, fd, ff, ff]
        /home/ubuntu/snapchange/examples/01_getpid/example1.c:70:5
    INSTRUCTION 002 0x0000000000401160 0x084be000 | example1!fuzzme+0x0
        push rbp
        RBP:0x7fffffffec10 -> 0x1
        [55]
        /home/ubuntu/snapchange/examples/01_getpid/example1.c:13:0
    INSTRUCTION 003 0x0000000000401161 0x084be000 | example1!fuzzme+0x1
        mov rbp, rsp
        RBP:0x7fffffffec10 -> 0x1
        RSP:0x7fffffffebe0 -> 0x7fffffffec10 -> 0x1
        [48, 89, e5]

* `.func_trace_0` - Contains a very crude function call graph of the execution. Always displays 4 function arguments regardless of function. 
Attempts to display the return value from the function.

Example:

    example1!fuzzme(0x402004, 0x402031, 0x6, 0x1) : "    /home/ubuntu/snapchange/examples/01_getpid/example1.c:13:0\n" = NORET
     example1!_init+0x46(0x402004, 0x402031, 0x6, 0x1) = NORET
      ld-linux-x86-64.so.2!_dl_fixup(0x7ffff7ffe240, 0x1, 0x6, 0x1) = 0x7ffff7e94da0
       ld-linux-x86-64.so.2!_dl_lookup_symbol_x(0x400402, 0x7ffff7ffe240, 0x7fffffffe930, 0x7ffff7ffe5b0) = 0x7ffff7fbf000
        ld-linux-x86-64.so.2!do_lookup_x(0x400402, 0xff878ec2, 0x7fffffffe890, 0x400360) = 0x1
         ld-linux-x86-64.so.2!check_match(0x400402, 0x400360, 0x7ffff7fbf580, 0x1) = 0x7ffff7dc5730
          ld-linux-x86-64.so.2!strcmp(0x7ffff7dd89ba, 0x400402, 0x1, 0x2) = 0x0
          ld-linux-x86-64.so.2!strcmp(0x7ffff7ddc2e7, 0x400430, 0x6, 0x0) = 0x0
      entry_SYSCALL_64(0x402004, 0x402031, 0x6, 0x7ffff7e94da7) = NORET
       do_syscall_64(0xffffb8bb402dff58, 0x27, 0x0, 0x0) = 0xc1
        syscall_enter_from_user_mode(0xffffb8bb402dff58, 0x27, 0x0, 0x0) = 0x27
        __x86_indirect_thunk_array(0xffffb8bb402dff58, 0x40, 0xffffffffffffffff, 0x0) = 0xc1
         __x86_indirect_thunk_array+0xc(0xffffb8bb402dff58, 0x40, 0xffffffffffffffff, 0x0) = 0xffffffffa6a82db0
         __task_pid_nr_ns(0xffff94f1c755ba00, 0x1, 0x0, 0x0) = 0xc1
          __rcu_read_lock(0xffff94f1c755ba00, 0x1, 0x0, 0x0) = 0x1
          __rcu_read_unlock(0xffff94f1c755ba00, 0x1, 0x0, 0x0) = 0x0
        syscall_exit_to_user_mode(0xffffb8bb402dff58, 0x1, 0x0, 0x0) = 0xc1
         syscall_exit_to_user_mode+0x4(0xffffb8bb402dff58, 0x1, 0x0, 0x0) = 0xffff94f1c755ba00
          syscall_exit_work(0xffffb8bb402dff58, 0x40, 0x0, 0x0) = 0xffff94f1c755ba00
           exit_to_user_mode_prepare(0xffffb8bb402dff58, 0x1, 0x7ffff7e94da7, 0x0) = 0xffff94f1c755ba00
</details>

### Execute a single input without single step
 
```
$ cargo run -r -- trace ./crashing_input --no-single-step
```

```
$ cat ./snapshot/traces/crashing_input_trace.no_single_step
```

<details>
    <summary>Further explanation</summary>

Sometimes it is nice to execute a single input through the snapshot and see the state
during reset. Using breakpoints that log messages, it is nice to be able to quickly
dump debug messages for a particular set of inputs.
</details>

## Minimize commands

### Minimize an input based on input size

```
$ cargo run -r -- minimize ./crashing_input
```

```
$ cat ./crashing_input.min_by_size
```

### Minimize an input based on input size using 5000 iterations per minimization stage

```
$ cargo run -r -- minimize ./crashing_input --iterations-per-stage 5000
```

```
$ cat ./crashing_input.min_by_size
```
<details>
    <summary>Further explanation</summary>

By default each minimization stage is performed 1000 times. This number can be
changed to allow more chance to minimize an input further.
</details>

## Coverage commands

### Gather coverage for a single input

```
$ cargo run -r -- coverage ./crashing_input
```

```
$ cat coverages/crashing_input/crashing_input.coverage_lighthouse
$ cat coverages/crashing_input/crashing_input.coverage_symbols
$ cat coverages/crashing_input/crashing_input.coverage_addrs
$ cat coverages/crashing_input/crashing_input.lcov
```

<details>
    <summary>Further explanation</summary>

* `.coverage_addrs` - The coverage breakpoints hit by the input

    ```
    0x401020
    0x401040
    0x401160
    0x401184
    0x401195
    ```

* `.coverage_lighthouse` - The coverage breakpoints hit by the input in a module+offset format for [Lighthouse](https://github.com/gaasedelen/lighthouse)

    ```
    example1+1020
    example1+1040
    example1+1160
    example1+1184
    ```

* `.coverage_symsols` - The coverage breakpoints hit by the input as module!symbol along with source code lines if available

    ```
    example1!main+0x62 /home/ubuntu/snapchange/examples/01_getpid/example1.c:70:12
    example1!fuzzme+0x0 /home/ubuntu/snapchange/examples/01_getpid/example1.c:13:0
    example1!_init+0x40
    example1!_init+0x20
    example1!fuzzme+0x24 /home/ubuntu/snapchange/examples/01_getpid/example1.c:18:9
    example1!fuzzme+0x35 /home/ubuntu/snapchange/examples/01_getpid/example1.c:19:9
    ```

* `.lcov` - The coverage breakpoints hit by the input in `.lcov` format to be used to help visualize the coverage with `genhtml` or `vim-lcov`

    ```
    TN:
    SF:/home/ubuntu/snapchange/examples/01_getpid/example1.c
    DA:13,1
    DA:18,0
    DA:19,0
    DA:20,0
    DA:21,0
    DA:22,0
    DA:23,0
    ```

</details>

## Project commands

### Translate the virtual address `0x401362`

This command will display the physical address of the given virtual address as well as
dump the physical bytes and attempt to decode the instructions found at the virtual
address.

```
$ cargo run -r -- project translate 0x401362
```
<details>
    <summary>Output</summary>

    [2022-12-09T21:06:55Z INFO  snapchange::memory] Open memory backing: 0x7f7037a8b000..0x7f7137a8b000
    [2022-12-09T21:06:55Z INFO  snapchange::commands::project] Translating VirtAddr 0x401362 Cr3 0x84be000
    [2022-12-09T21:06:55Z INFO  snapchange::commands::project] VirtAddr 0x401362 -> PhysAddr 0xad4d362
     HEXDUMP
    ---- address -----   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F    0123456789ABCDEF
    0x0000000000401362: 48 8b 7d f0 e8 f5 fd ff ff 31 c0 48 83 c4 20 5d  | H.}......1.H...]
    0x0000000000401372: c3 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00 f3 0f  | .f..............
    0x0000000000401382: 1e fa 41 57 4c 8d 3d 83 2a 00 00 41 56 49 89 d6  | ..AWL.=.*..AVI..
    0x0000000000401392: 41 55 49 89 f5 41 54 41 89 fc 55 48 8d 2d 74 2a  | AUI..ATA..UH.-t*
     POTENTIAL INSTRUCTIONS
    0x0000000000401362: 488b7df0           example1!main+0x62                              | mov rdi, qword ptr [rbp-0x10]
    0x0000000000401366: e8f5fdffff         example1!main+0x66                              | call 0xfffffffffffffdfa
    0x000000000040136b: 31c0               example1!main+0x6b                              | xor eax, eax
    0x000000000040136d: 4883c420           example1!main+0x6d                              | add rsp, 0x20
    0x0000000000401371: 5d                 example1!main+0x71                              | pop rbp
    0x0000000000401372: c3                 example1!main+0x72                              | ret

</details>

### Translate the virtual address `0x401362` and display `100` instructions instead of `20`

```
$ cargo run -r -- project translate 0x401362 --instrs 100
```

### Get the instruction bytes and instructions at the `example1!main` symbol

```
$ cargo run -r -- project translate 'example1!main'
```

<details>
    <summary>Output</summary>

     HEXDUMP
    ---- address -----   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F    0123456789ABCDEF
    0x0000000000401300: 55 48 89 e5 48 83 ec 20 c7 45 fc 00 00 00 00 48  | UH..H....E.....H
    0x0000000000401310: b8 04 20 40 00 00 00 00 00 48 89 45 f0 48 8b 75  | ...@.....H.E.H.u
    0x0000000000401320: f0 48 bf 15 20 40 00 00 00 00 00 b0 00 e8 1e fd  | .H...@..........
    0x0000000000401330: ff ff 48 8b 3c 25 48 40 40 00 89 45 ec e8 1e fd  | ..H.<%H@@..E....
     POTENTIAL INSTRUCTIONS
    0x0000000000401300: 55                     example1!main+0x0                               | push rbp
    0x0000000000401301: 4889e5                 example1!main+0x1                               | mov rbp, rsp
    0x0000000000401304: 4883ec20               example1!main+0x4                               | sub rsp, 0x20
    0x0000000000401308: c745fc00000000         example1!main+0x8                               | mov dword ptr [rbp-0x4], 0x0
    0x000000000040130f: 48b80420400000000000   example1!main+0xf                               | mov rax, 0x402004
    0x0000000000401319: 488945f0               example1!main+0x19                              | mov qword ptr [rbp-0x10], rax

</details>

### Translate a virtual address using a different CR3

```
$ cargo run -r -- project translate 0x401362 --cr3 0xdeadbeef
```

### Permanently write 4 nops (byte `0x90`) at virtual address `0x401362` in the snapshot memory

This will permanently modify the snapshot physical memory. This is useful for patching the
snapshot to adjust behavior without needed a breakpoint in the fuzzer which has a 
performance hit, depending on how often the breakpoint is triggered. A common use case is
returning out of logging functions if the logging messages aren't needed during fuzzing.

```
$ cargo run -r -- project write-mem 0x401362 90909090
```

<details>
    <summary>Output</summary>

    [2022-12-09T21:18:59Z INFO  snapchange::memory] Open memory backing: 0x7f69ab1d4000..0x7f6aab1d4000
    [2022-12-09T21:18:59Z INFO  snapchange::commands::project] WriteMem { virt_addr: VirtAddr(401362), bytes: "90909090", cr3: None }
    [2022-12-09T21:18:59Z INFO  snapchange::commands::project] VirtAddr(401362)
     BYTES BEFORE
    ---- address -----   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F    0123456789ABCDEF
    0x0000000000401362: 48 8b 7d f0 e8 f5 fd ff ff 31 c0 48 83 c4 20 5d  | H.}......1.H...]
    0x0000000000401372: c3 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00 f3 0f  | .f..............
    0x0000000000401382: 1e fa 41 57 4c 8d 3d 83 2a 00 00 41 56 49 89 d6  | ..AWL.=.*..AVI..
    0x0000000000401392: 41 55 49 89 f5 41 54 41 89 fc 55 48 8d 2d 74 2a  | AUI..ATA..UH.-t*
    POTENTIAL INSTRUCTIONS BEFORE
    0x0000000000401362: 488b7df0           example1!main+0x62                              | mov rdi, qword ptr [rbp-0x10]
    0x0000000000401366: e8f5fdffff         example1!main+0x66                              | call 0xfffffffffffffdfa
    0x000000000040136b: 31c0               example1!main+0x6b                              | xor eax, eax
    0x000000000040136d: 4883c420           example1!main+0x6d                              | add rsp, 0x20
    0x0000000000401371: 5d                 example1!main+0x71                              | pop rbp

    [2022-12-09T21:18:59Z INFO  snapchange::commands::project] Writing 4 (0x4) bytes to 0x401362 0x84be000

     BYTES AFTER
    ---- address -----   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F    0123456789ABCDEF
    0x0000000000401362: 90 90 90 90 e8 f5 fd ff ff 31 c0 48 83 c4 20 5d  | .........1.H...]
    0x0000000000401372: c3 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00 f3 0f  | .f..............
    0x0000000000401382: 1e fa 41 57 4c 8d 3d 83 2a 00 00 41 56 49 89 d6  | ..AWL.=.*..AVI..
    0x0000000000401392: 41 55 49 89 f5 41 54 41 89 fc 55 48 8d 2d 74 2a  | AUI..ATA..UH.-t*
    POTENTIAL INSTRUCTIONS AFTER
    0x0000000000401362: 90                 example1!main+0x62                              | nop
    0x0000000000401363: 90                 example1!main+0x63                              | nop
    0x0000000000401364: 90                 example1!main+0x64                              | nop
    0x0000000000401365: 90                 example1!main+0x65                              | nop
    0x0000000000401366: e8f5fdffff         example1!main+0x66                              | call 0xfffffffffffffdfa
    0x000000000040136b: 31c0               example1!main+0x6b                              | xor eax, eax
    0x000000000040136d: 4883c420           example1!main+0x6d                              | add rsp, 0x20
    0x0000000000401371: 5d                 example1!main+0x71                              | pop rbp

</details>

### Permanently change the function `example1!IsAdmin` to always return `1`

```
$ rasm2 -b64 'xor eax, eax ; inc eax ; ret'
31c0ffc0c3

$ cargo run -r -- project write-mem 'example1!IsAdmin' 31c0ffc0c3
```


### Display all known symbols for the project

```
cargo run -r -- project symbols
```

```
0x0000000000000000 fixed_percpu_data
0x0000000000001000 cpu_debug_store
0x0000000000002000 irq_stack_backing_store
0x0000000000006000 cpu_tss_rw
0x000000000000b000 gdt_page
0x000000000000c000 exception_stacks
0x0000000000014000 entry_stack_storage
0x0000000000015000 espfix_waddr
0x0000000000015008 espfix_stack
0x0000000000015010 cpu_l2c_shared_map
```

### Display all known symbols for the `example1` module

```
cargo run -r -- project symbols | grep 'example1!'
```

```
0x0000000000401000 example1!_init
0x0000000000401070 example1!_start
0x00000000004010a0 example1!_dl_relocate_static_pie
0x00000000004010b0 example1!deregister_tm_clones
0x00000000004010e0 example1!register_tm_clones
0x0000000000401120 example1!__do_global_dtors_aux
0x0000000000401150 example1!frame_dummy
0x0000000000401160 example1!fuzzme
0x0000000000401300 example1!main
...
```
