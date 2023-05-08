# Input files

These files are read by Snapchange as inputs for a fuzzer

## Required input files

* `.physmem` - The physical memory of the target being replayed.

<details>
    <summary>Further explanation</summary>

This is a raw memory image such that byte at offset 0x1000 in the .physmem file represents the byte
at physical address 0x1000 in the original physical memory. 

</details>

* `.qemuregs` - The register state of the target taken using the `x86_cpu_dump_state` function in QEMU.

<details>
    <summary>Example</summary>

    RAX=00007fffffffef18 RBX=0000000000000000 RCX=0000000000000001 RDX=0000000000000006
    RSI=0000000000402031 RDI=00007fffffffef11 RBP=00007fffffffec10 RSP=00007fffffffebf0
    R8 =0000000000000000 R9 =000000000000003f R10=00007ffff7dcd3e0 R11=0000000000000000
    R12=00007fffffffed28 R13=0000000000401300 R14=0000000000000000 R15=00007ffff7ffd020
    RIP=0000000000401362 RFL=00000306 [-----P-] CPL=3 II=0 A20=1 SMM=0 HLT=0
    ES =0000 0000000000000000 00000000 00000000
    CS =0033 0000000000000000 ffffffff 00affb00 DPL=3 CS64 [-RA]
    SS =002b 0000000000000000 ffffffff 00cff300 DPL=3 DS   [-WA]
    DS =0000 0000000000000000 00000000 00000000
    FS =0000 00007ffff7fc05c0 00000000 00000000
    GS =0000 0000000000000000 00000000 00000000
    LDT=0000 0000000000000000 00000000 00008200 DPL=0 LDT
    TR =0040 fffffe0000003000 00004087 00008900 DPL=0 TSS64-avl
    GDT=     fffffe0000001000 0000007f
    IDT=     fffffe0000000000 00000fff
    CR0=80050033 CR2=00007f8814613610 CR3=00000000084be000 CR4=000006f0
    DR0=0000000000000000 DR1=0000000000000000 DR2=0000000000000000 DR3=0000000000000000 
    DR6=00000000ffff0ff0 DR7=0000000000000400
    CCS=0000000000000004 CCD=0000000000000000 CCO=EFLAGS
    EFER=0000000000000d01
    FCW=037f FSW=0000 [ST=0] FTW=00 MXCSR=00001f80
    FPR0=0000000000000000 0000 FPR1=0000000000000000 0000
    FPR2=0000000000000000 0000 FPR3=0000000000000000 0000
    FPR4=0000000000000000 0000 FPR5=0000000000000000 0000
    FPR6=0000000000000000 0000 FPR7=0000000000000000 0000
    XMM00=ffffff0000000000 ff00000000000000 XMM01=0101010000000000 01ffffffffffffff
    XMM02=0000000000000000 0000000000000000 XMM03=0000000000000000 0000000000000000
    XMM04=ffff0000000000ff 0000000000000000 XMM05=0000000000000000 0000000000000000
    XMM06=0000000000000000 0000000000000000 XMM07=0000000000000000 0000000000000000
    XMM08=0000000000000000 0000000000000000 XMM09=0000000000000000 0000000000000000
    XMM10=0000000000000000 0000000000000000 XMM11=0000000000000000 0000000000000000
    XMM12=0000000000000000 0000000000000000 XMM13=0000000000000000 0000000000000000
    XMM14=0000000000000000 0000000000000000 XMM15=0000000000000000 0000000000000000
    Code=e8 e8 dc fc ff ff 48 83 f8 00 0f 84 04 00 00 00 cc 0f 01 c1 <48> 8b 7d f0 e8 f5 fd ff ff 31 c0 48 83 c4 20 5d c3 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00
    APIC_BASE=fee00900
    EFER=d01
    STAR=23001000000000
    LSTAR=ffffffffa7800000
    CSTAR=ffffffffa78015a0
    SFMASK=257fd5
    KERNELGSBASE=ffff94f23dc00000
</details>

## Optional input files

* `.covbps` - Virtual addresses that are coverage breakpoints for a fuzzer. This is the main coverage mechanism in Snapchange.
On start, these breakpoints are inserted into physical guest memory. When these breakpoints are hit, a coverage event is triggered
and the breakpoint is removed from future test cases.

<details>
    <summary>Example</summary>

    0xdeadbeef
    deadbeef
    12341234
</details>

* `.symbols` - Mapping of virtual address to symbol string used by Snapchange for symbol resolution and debugging.

<details>
    <summary>Example</summary>

    [
        {"address": 0, "symbol": "fixed_percpu_data"}, 
        {"address": 4096, "symbol": "cpu_debug_store"}, 
        {"address": 8192, "symbol": "irq_stack_backing_store"}, 
        {"address": 24576, "symbol": "cpu_tss_rw"}, 
    ]
</details>

* `.modules` - Listing of modules currently loaded into the snapshot process.

<details>
    <summary>Example</summary>

    (Module Start, Module End, Module name)

    0x400000 0x405000 example1
    0x7ffff7dbe000 0x7ffff7fb2000 libc.so.6
    0x7ffff7fcb000 0x7ffff7fff000 ld-linux-x86-64.so.2
</details>

* `.bin` - Binary used by `addr2line` to query for file name and line numbers for debugging. This enables
source information to be presented in the `trace` output.

# Output files

These directories are created by Snapchange in the project directory:

* `crashes` - Directory where the found crashes are written
* `data` - Data on executions per second, coverage, and crashes over time
* `metadata` - Metadata on each new corpus input or crash

These files that are created by Snapchange in the project directory

* `coverage.addresses` - The raw addresses that have been hit during fuzzing of this project

<details>
    <summary>Example</summary>

    0x555555555090
    0x5555555551a9
    0x5555555551d0
    0x5555555551e3
</details>

* `coverage.lighthouse` - The coverage from `coverage.addresses` in a form to use with [Lighthouse](https://github.com/gaasedelen/lighthouse)

<details>
    <summary>Example</summary>

    example1+1090
    example1+11a9
    example1+11d0
    example1+11e3
    example1+11f6
</details>

* `coverage.lcov` - The coverage from `coverage.addresses` in LCOV form. Can be used with `genhtml` to visualize the coverage alongside the source.

<details>
    <summary>Example</summary>

    TN:
    SF:/home/ubuntu/snapchange-testing/examples/01_getpid/harness/example1.c
    DA:13,1
    DA:18,1
    DA:19,1
    DA:20,1
    DA:21,1
    DA:22,1
    DA:23,1
    DA:24,1
</details>
