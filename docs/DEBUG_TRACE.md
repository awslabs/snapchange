# Example debug trace

This is a trace of the following program:

```
// Example test case for snapshot fuzzing
//
// Test the ability to write arbitrary memory and registers into a snapshot
//
// gcc -g example1.c -o example1

#include <sys/types.h>
#include <unistd.h>

void main() {
    // SNAPSHOT TAKEN HERE
    __asm("int3");

    char* data = "aaaa";
    int pid    = getpid();

    // Correct solution: data == "fuzz", pid == 0xdeadbeef
    if (data[0] == 'f') {
    if (data[1] == 'u') {
    if (data[2] == 'z') {
    if (data[3] == 'z') {
    if (pid     == 0xdeadbeef) {
        *(int*)0xcafecafe = 0x41414141;
    }
    }
    }
    }
    }
}
```

```
ITERATION 000 0x0000555555555145 0x11115000 | example1!main+0x10 (0x555555555145)                          
    mov qword ptr [rbp-0x8], rax 
    [RBP:0x7fffffffeb90+0xfffffffffffffff8=0x100007fffffffeb88]] 
    RAX:example1!_IO_stdin_used+0x4 (0x555555556004) -> 'aaaa'
    [48, 89, 45, f8]
ITERATION 001 0x0000555555555149 0x11115000 | example1!main+0x14 (0x555555555149)                          
    call 0xfffffffffffffee7 
    ??_NearBranch64_?? [e8, e2, fe, ff, ff]
ITERATION 002 0x0000555555555030 0x11115000 | example1!_init+0x30 (0x555555555030)                         
    jmp qword ptr [rip+0x2fe2] 
    [RIP:0x555555555030+0x2fe8=0x555555558018]] 
    [ff, 25, e2, 2f, 00, 00]
ITERATION 003 0x0000555555555036 0x11115000 | example1!_init+0x36 (0x555555555036)                         
    push 0x0 
    ??_Immediate32to64_?? [68, 00, 00, 00, 00]
ITERATION 004 0x000055555555503b 0x11115000 | example1!_init+0x3b (0x55555555503b)                         
    jmp 0xffffffffffffffe5 
    ??_NearBranch64_?? [e9, e0, ff, ff, ff]
ITERATION 005 0x0000555555555020 0x11115000 | example1!_init+0x20 (0x555555555020)                         
    push qword ptr [rip+0x2fe2] 
    [RIP:0x555555555020+0x2fe8=0x555555558008size:UInt64->0x7ffff7ffe180]] 
    [ff, 35, e2, 2f, 00, 00]
ITERATION 006 0x0000555555555026 0x11115000 | example1!_init+0x26 (0x555555555026)                         
    jmp qword ptr [rip+0x2fe4] 
    [RIP:0x555555555026+0x2fea=0x555555558010]] 
    [ff, 25, e4, 2f, 00, 00]
ITERATION 007 0x00007ffff7fe84c0 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x0 (0x7ffff7fe84c0)   
    push rbx 
    RBX:0x0
    [53]
ITERATION 008 0x00007ffff7fe84c1 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x1 (0x7ffff7fe84c1)   
    mov rbx, rsp 
    RBX:0x0
    RSP:0x7fffffffeb60 -> 0x0
    [48, 89, e3]
ITERATION 009 0x00007ffff7fe84c4 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x4 (0x7ffff7fe84c4)   
    and rsp, 0xfffffffffffffff0 
    RSP:0x7fffffffeb60 -> 0x0
    ??_Immediate8to64_?? [48, 83, e4, f0]
ITERATION 010 0x00007ffff7fe84c8 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x8 (0x7ffff7fe84c8)   
    sub rsp, 0x240 
    RSP:0x7fffffffeb60 -> 0x0
    ??_Immediate32to64_?? [48, 81, ec, 40, 02, 00, 00]
ITERATION 011 0x00007ffff7fe84cf 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0xf (0x7ffff7fe84cf)   
    mov qword ptr [rsp], rax 
    [RSP:0x7fffffffe920] 
    RAX:[34mexample1!_IO_stdin_used+0x4 (0x555555556004)[39m -> 'aaaa'
    [48, 89, 04, 24]
ITERATION 012 0x00007ffff7fe84d3 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x13 (0x7ffff7fe84d3)  
    mov qword ptr [rsp+0x8], rcx 
    [RSP:0x7fffffffe920+0x8=0x7fffffffe928]] 
    RCX:[34mlibc-2.31.so!__exit_funcs+0x0 (0x7ffff7fbd718) -> libc-2.31.so!initial+0x0 (0x7ffff7fbfb00) -> 0x0
    [48, 89, 4c, 24, 08]
ITERATION 013 0x00007ffff7fe84d8 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x18 (0x7ffff7fe84d8)  
    mov qword ptr [rsp+0x10], rdx 
    [RSP:0x7fffffffe920+0x10=0x7fffffffe930]] 
    RDX:0x7fffffffec98 -> 0x7fffffffeead -> 'SHELL=/bin/bash'
    [48, 89, 54, 24, 10]
ITERATION 014 0x00007ffff7fe84dd 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x1d (0x7ffff7fe84dd)  
    mov qword ptr [rsp+0x18], rsi 
    [RSP:0x7fffffffe920+0x18=0x7fffffffe938]] 
    RSI:0x7fffffffec88 -> 0x7fffffffee9e -> '/root/example1'
    [48, 89, 74, 24, 18]
ITERATION 015 0x00007ffff7fe84e2 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x22 (0x7ffff7fe84e2)  
    mov qword ptr [rsp+0x20], rdi 
    [RSP:0x7fffffffe920+0x20=0x7fffffffe940]] 
    RDI:0x1
    [48, 89, 7c, 24, 20]
ITERATION 016 0x00007ffff7fe84e7 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x27 (0x7ffff7fe84e7)  
    mov qword ptr [rsp+0x28], r8 
    [RSP:0x7fffffffe920+0x28=0x7fffffffe948]] 
    R8:0x0
    [4c, 89, 44, 24, 28]
ITERATION 017 0x00007ffff7fe84ec 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x2c (0x7ffff7fe84ec)  
    mov qword ptr [rsp+0x30], r9 
    [RSP:0x7fffffffe920+0x30=0x7fffffffe950]] 
    R9:[34mld-2.31.so!_dl_fini+0x0 (0x7ffff7fe21b0)[39m -> 0x56415741e5894855
    [4c, 89, 4c, 24, 30]
ITERATION 018 0x00007ffff7fe84f1 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x31 (0x7ffff7fe84f1)  
    fxsave [rsp+0x40] 
    [RSP:0x7fffffffe920+0x40 TODO:Fxsave_m512byte ] 
    [0f, ae, 44, 24, 40]
ITERATION 019 0x00007ffff7fe84f6 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x36 (0x7ffff7fe84f6)  
    mov rsi, qword ptr [rbx+0x10] 
    RSI:0x7fffffffec88 -> 0x7fffffffee9e -> '/root/example1'
    [RBX:0x7fffffffeb60+0x10=0x7fffffffeb70size:UInt64->0x0]] 
    [48, 8b, 73, 10]
ITERATION 020 0x00007ffff7fe84fa 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x3a (0x7ffff7fe84fa)  
    mov rdi, qword ptr [rbx+0x8] 
    RDI:0x1
    [RBX:0x7fffffffeb60+0x8=0x7fffffffeb68size:UInt64->0x7ffff7ffe180]] 
    [48, 8b, 7b, 08]
ITERATION 021 0x00007ffff7fe84fe 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x3e (0x7ffff7fe84fe)  
    call 0xffffffffffff9052 
    ??_NearBranch64_?? [e8, 4d, 90, ff, ff]
ITERATION 022 0x00007ffff7fe1550 0x11115000 | ld-2.31.so!_dl_fixup+0x0 (0x7ffff7fe1550)                    
    push rbx 
    RBX:0x7fffffffeb60 -> 0x0
    [53]
ITERATION 023 0x00007ffff7fe1551 0x11115000 | ld-2.31.so!_dl_fixup+0x1 (0x7ffff7fe1551)                    
    mov r10, rdi 
    R10:0x0
    RDI:[34mld-2.31.so!_end+0x8 (0x7ffff7ffe180)[39m -> 0x555555554000 -> 'ELF'
    [49, 89, fa]
ITERATION 024 0x00007ffff7fe1554 0x11115000 | ld-2.31.so!_dl_fixup+0x4 (0x7ffff7fe1554)                    
    mov esi, esi 
    ESI:0x0
    ESI:0x0
    [89, f6]
ITERATION 025 0x00007ffff7fe1556 0x11115000 | ld-2.31.so!_dl_fixup+0x6 (0x7ffff7fe1556)                    
    lea rdx, [rsi+rsi*2] 
    RDX:0x7fffffffec98 -> 0x7fffffffeead -> 'SHELL=/bin/bash'
    [RSI:0x0+RSI:0x0*0x2] 
    [48, 8d, 14, 76]
ITERATION 026 0x00007ffff7fe155a 0x11115000 | ld-2.31.so!_dl_fixup+0xa (0x7ffff7fe155a)                    
    sub rsp, 0x10 
    RSP:0x7fffffffe910 -> 0x7fffffffeb60 -> 0x0
    ??_Immediate8to64_?? [48, 83, ec, 10]
ITERATION 027 0x00007ffff7fe155e 0x11115000 | ld-2.31.so!_dl_fixup+0xe (0x7ffff7fe155e)                    
    mov rax, qword ptr [rdi+0x68] 
    RAX:[34mexample1!_IO_stdin_used+0x4 (0x555555556004)[39m -> 'aaaa'
    [RDI:0x7ffff7ffe180+0x68=0x7ffff7ffe1e8size:UInt64->0x555555557e78]] 
    [48, 8b, 47, 68]
ITERATION 028 0x00007ffff7fe1562 0x11115000 | ld-2.31.so!_dl_fixup+0x12 (0x7ffff7fe1562)                   
    mov rdi, qword ptr [rax+0x8] 
    RDI:[34mld-2.31.so!_end+0x8 (0x7ffff7ffe180)[39m -> 0x555555554000 -> 'ELF'
    [RAX:0x555555557e78+0x8=0x555555557e80size:UInt64->0x5555555543d8]] 
    [48, 8b, 78, 08]
ITERATION 029 0x00007ffff7fe1566 0x11115000 | ld-2.31.so!_dl_fixup+0x16 (0x7ffff7fe1566)                   
    mov rax, qword ptr [r10+0xf8] 
    RAX:[34mexample1!_DYNAMIC+0x80 (0x555555557e78)[39m -> ''
    [R10:0x7ffff7ffe180+0xf8=0x7ffff7ffe278size:UInt64->0x555555557ef8]] 
    [49, 8b, 82, f8, 00, 00, 00]
ITERATION 030 0x00007ffff7fe156d 0x11115000 | ld-2.31.so!_dl_fixup+0x1d (0x7ffff7fe156d)                   
    mov rax, qword ptr [rax+0x8] 
    RAX:[34mexample1!_DYNAMIC+0x100 (0x555555557ef8)[39m -> ''
    [RAX:0x555555557ef8+0x8=0x555555557f00size:UInt64->0x555555554550]] 
    [48, 8b, 40, 08]
ITERATION 031 0x00007ffff7fe1571 0x11115000 | ld-2.31.so!_dl_fixup+0x21 (0x7ffff7fe1571)                   
    lea rsi, [rax+rdx*8] 
    RSI:0x0
    [RAX:0x555555554550+RDX:0x0*0x8] 
    [48, 8d, 34, d0]
ITERATION 032 0x00007ffff7fe1575 0x11115000 | ld-2.31.so!_dl_fixup+0x25 (0x7ffff7fe1575)                   
    mov rax, qword ptr [r10+0x70] 
    RAX:0x555555554550 -> '@'
    [R10:0x7ffff7ffe180+0x70=0x7ffff7ffe1f0size:UInt64->0x555555557e88]] 
    [49, 8b, 42, 70]
ITERATION 033 0x00007ffff7fe1579 0x11115000 | ld-2.31.so!_dl_fixup+0x29 (0x7ffff7fe1579)                   
    mov rcx, qword ptr [rsi+0x8] 
    RCX:[34mlibc-2.31.so!__exit_funcs+0x0 (0x7ffff7fbd718)[39m -> [34mlibc-2.31.so!initial+0x0 (0x7ffff7fbfb00)[39m -> 0x0
    [RSI:0x555555554550+0x8=0x555555554558size:UInt64->0x200000007]] 
    [48, 8b, 4e, 08]
ITERATION 034 0x00007ffff7fe157d 0x11115000 | ld-2.31.so!_dl_fixup+0x2d (0x7ffff7fe157d)                   
    mov rbx, qword ptr [rsi] 
    RBX:0x7fffffffeb60 -> 0x0
    [RSI:0x555555554550size:UInt64->0x4018]] 
    [48, 8b, 1e]
ITERATION 035 0x00007ffff7fe1580 0x11115000 | ld-2.31.so!_dl_fixup+0x30 (0x7ffff7fe1580)                   
    mov rax, qword ptr [rax+0x8] 
    RAX:[34mexample1!_DYNAMIC+0x90 (0x555555557e88)[39m -> ''
    [RAX:0x555555557e88+0x8=0x555555557e90size:UInt64->0x555555554330]] 
    [48, 8b, 40, 08]
ITERATION 036 0x00007ffff7fe1584 0x11115000 | ld-2.31.so!_dl_fixup+0x34 (0x7ffff7fe1584)                   
    mov rdx, rcx 
    RDX:0x0
    RCX:0x200000007
    [48, 89, ca]
ITERATION 037 0x00007ffff7fe1587 0x11115000 | ld-2.31.so!_dl_fixup+0x37 (0x7ffff7fe1587)                   
    shr rdx, 0x20 
    RDX:0x200000007
    ??_Immediate8_?? [48, c1, ea, 20]
ITERATION 038 0x00007ffff7fe158b 0x11115000 | ld-2.31.so!_dl_fixup+0x3b (0x7ffff7fe158b)                   
    lea r8, [rdx+rdx*2] 
    R8:0x0
    [RDX:0x2+RDX:0x2*0x2=0x6]] 
    [4c, 8d, 04, 52]
ITERATION 039 0x00007ffff7fe158f 0x11115000 | ld-2.31.so!_dl_fixup+0x3f (0x7ffff7fe158f)                   
    lea rax, [rax+r8*8] 
    RAX:0x555555554330 -> 0x0
    [RAX:0x555555554330+R8:0x6*0x8=0x555555554360]] 
    [4a, 8d, 04, c0]
ITERATION 040 0x00007ffff7fe1593 0x11115000 | ld-2.31.so!_dl_fixup+0x43 (0x7ffff7fe1593)                   
    mov r8, qword ptr [r10] 
    R8:0x6
    [R10:0x7ffff7ffe180size:UInt64->0x555555554000]] 
    [4d, 8b, 02]
ITERATION 041 0x00007ffff7fe1596 0x11115000 | ld-2.31.so!_dl_fixup+0x46 (0x7ffff7fe1596)                   
    mov qword ptr [rsp+0x8], rax 
    [RSP:0x7fffffffe900+0x8=0x7fffffffe908]] 
    RAX:0x555555554360 -> ''
    [48, 89, 44, 24, 08]
ITERATION 042 0x00007ffff7fe159b 0x11115000 | ld-2.31.so!_dl_fixup+0x4b (0x7ffff7fe159b)                   
    add rbx, r8 
    RBX:0x4018
    R8:0x555555554000 -> 'ELF'
    [4c, 01, c3]
ITERATION 043 0x00007ffff7fe159e 0x11115000 | ld-2.31.so!_dl_fixup+0x4e (0x7ffff7fe159e)                   
    cmp ecx, 0x7 
    ECX:0x7
    ??_Immediate8to32_?? [83, f9, 07]
ITERATION 044 0x00007ffff7fe15a1 0x11115000 | ld-2.31.so!_dl_fixup+0x51 (0x7ffff7fe15a1)                   
    jne 0x14d 
    ??_NearBranch64_?? [0f, 85, 47, 01, 00, 00]
ITERATION 045 0x00007ffff7fe15a7 0x11115000 | ld-2.31.so!_dl_fixup+0x57 (0x7ffff7fe15a7)                   
    test byte ptr [rax+0x5], 0x3 
    [RAX:0x555555554360+0x5=0x555555554365size:UInt8->0x0]] 
    ??_Immediate8_?? [f6, 40, 05, 03]
ITERATION 046 0x00007ffff7fe15ab 0x11115000 | ld-2.31.so!_dl_fixup+0x5b (0x7ffff7fe15ab)                   
    jne 0xe5 
    ??_NearBranch64_?? [0f, 85, df, 00, 00, 00]
ITERATION 047 0x00007ffff7fe15b1 0x11115000 | ld-2.31.so!_dl_fixup+0x61 (0x7ffff7fe15b1)                   
    mov r8, qword ptr [r10+0x1d0] 
    R8:0x555555554000 -> 'ELF'
    [R10:0x7ffff7ffe180+0x1d0=0x7ffff7ffe350size:UInt64->0x555555557f68]] 
    [4d, 8b, 82, d0, 01, 00, 00]
ITERATION 048 0x00007ffff7fe15b8 0x11115000 | ld-2.31.so!_dl_fixup+0x68 (0x7ffff7fe15b8)                   
    test r8, r8 
    R8:[34mexample1!_DYNAMIC+0x170 (0x555555557f68)[39m -> 0x6ffffff0
    R8:[34mexample1!_DYNAMIC+0x170 (0x555555557f68)[39m -> 0x6ffffff0
    [4d, 85, c0]
ITERATION 049 0x00007ffff7fe15bb 0x11115000 | ld-2.31.so!_dl_fixup+0x6b (0x7ffff7fe15bb)                   
    je 0x2e 
    ??_NearBranch64_?? [74, 2c]
ITERATION 050 0x00007ffff7fe15bd 0x11115000 | ld-2.31.so!_dl_fixup+0x6d (0x7ffff7fe15bd)                   
    mov rcx, qword ptr [r8+0x8] 
    RCX:0x200000007
    [R8:0x555555557f68+0x8=0x555555557f70size:UInt64->0x55555555445c]] 
    [49, 8b, 48, 08]
ITERATION 051 0x00007ffff7fe15c1 0x11115000 | ld-2.31.so!_dl_fixup+0x71 (0x7ffff7fe15c1)                   
    movzx edx, word ptr [rcx+rdx*2] 
    EDX:0x2
    [RCX:0x55555555445c+RDX:0x2*0x2=0x555555554460size:UInt16->0x2]] 
    [0f, b7, 14, 51]
ITERATION 052 0x00007ffff7fe15c5 0x11115000 | ld-2.31.so!_dl_fixup+0x75 (0x7ffff7fe15c5)                   
    and edx, 0x7fff 
    EDX:0x2
    ??_Immediate32_?? [81, e2, ff, 7f, 00, 00]
ITERATION 053 0x00007ffff7fe15cb 0x11115000 | ld-2.31.so!_dl_fixup+0x7b (0x7ffff7fe15cb)                   
    lea rcx, [rdx+rdx*2] 
    RCX:0x55555555445c -> 0x2000200000000
    [RDX:0x2+RDX:0x2*0x2=0x6]] 
    [48, 8d, 0c, 52]
ITERATION 054 0x00007ffff7fe15cf 0x11115000 | ld-2.31.so!_dl_fixup+0x7f (0x7ffff7fe15cf)                   
    mov rdx, qword ptr [r10+0x2e8] 
    RDX:0x2
    [R10:0x7ffff7ffe180+0x2e8=0x7ffff7ffe468size:UInt64->0x7ffff7fc4540]] 
    [49, 8b, 92, e8, 02, 00, 00]
ITERATION 055 0x00007ffff7fe15d6 0x11115000 | ld-2.31.so!_dl_fixup+0x86 (0x7ffff7fe15d6)                   
    lea r8, [rdx+rcx*8] 
    R8:[34mexample1!_DYNAMIC+0x170 (0x555555557f68)[39m -> 0x6ffffff0
    [RDX:0x7ffff7fc4540+RCX:0x6*0x8=0x7ffff7fc4570]] 
    [4c, 8d, 04, ca]
ITERATION 056 0x00007ffff7fe15da 0x11115000 | ld-2.31.so!_dl_fixup+0x8a (0x7ffff7fe15da)                   
    mov edx, 0x0 
    EDX:0xf7fc4540
    ??_Immediate32_?? [ba, 00, 00, 00, 00]
ITERATION 057 0x00007ffff7fe15df 0x11115000 | ld-2.31.so!_dl_fixup+0x8f (0x7ffff7fe15df)                   
    mov esi, dword ptr [r8+0x8] 
    ESI:0x55554550
    [R8:0x7ffff7fc4570+0x8=0x7ffff7fc4578size:UInt32->0x9691a75]] 
    [41, 8b, 70, 08]
ITERATION 058 0x00007ffff7fe15e3 0x11115000 | ld-2.31.so!_dl_fixup+0x93 (0x7ffff7fe15e3)                   
    test esi, esi 
    ESI:0x9691a75
    ESI:0x9691a75
    [85, f6]
ITERATION 059 0x00007ffff7fe15e5 0x11115000 | ld-2.31.so!_dl_fixup+0x95 (0x7ffff7fe15e5)                   
    cmove r8, rdx 
    R8:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0x1068 (0x7ffff7fc4570)[39m -> 0x55555555440b -> 'GLIBC_2.2.5'
    RDX:0x0
    [4c, 0f, 44, c2]
ITERATION 060 0x00007ffff7fe15e9 0x11115000 | ld-2.31.so!_dl_fixup+0x99 (0x7ffff7fe15e9)                   
    mov ecx, dword ptr fs:[0x18] 
    ECX:0x6
    [None:0x0+0x18=0x18size:UInt32->????]] 
    [64, 8b, 0c, 25, 18, 00, 00, 00]
ITERATION 061 0x00007ffff7fe15f1 0x11115000 | ld-2.31.so!_dl_fixup+0xa1 (0x7ffff7fe15f1)                   
    mov edx, 0x1 
    EDX:0x0
    ??_Immediate32_?? [ba, 01, 00, 00, 00]
ITERATION 062 0x00007ffff7fe15f6 0x11115000 | ld-2.31.so!_dl_fixup+0xa6 (0x7ffff7fe15f6)                   
    test ecx, ecx 
    ECX:0x0
    ECX:0x0
    [85, c9]
ITERATION 063 0x00007ffff7fe15f8 0x11115000 | ld-2.31.so!_dl_fixup+0xa8 (0x7ffff7fe15f8)                   
    jne 0xe0 
    ??_NearBranch64_?? [0f, 85, da, 00, 00, 00]
ITERATION 064 0x00007ffff7fe15fe 0x11115000 | ld-2.31.so!_dl_fixup+0xae (0x7ffff7fe15fe)                   
    lea r11, [rsp+0x8] 
    R11:0xc2
    [RSP:0x7fffffffe900+0x8=0x7fffffffe908]] 
    [4c, 8d, 5c, 24, 08]
ITERATION 065 0x00007ffff7fe1603 0x11115000 | ld-2.31.so!_dl_fixup+0xb3 (0x7ffff7fe1603)                   
    mov eax, dword ptr [rax] 
    EAX:0x55554360
    [RAX:0x555555554360size:UInt32->0x1]] 
    [8b, 00]
ITERATION 066 0x00007ffff7fe1605 0x11115000 | ld-2.31.so!_dl_fixup+0xb5 (0x7ffff7fe1605)                   
    mov r9d, 0x1 
    R9D:0xf7fe21b0
    ??_Immediate32_?? [41, b9, 01, 00, 00, 00]
ITERATION 067 0x00007ffff7fe160b 0x11115000 | ld-2.31.so!_dl_fixup+0xbb (0x7ffff7fe160b)                   
    mov rsi, r10 
    RSI:0x9691a75
    R10:[34mld-2.31.so!_end+0x8 (0x7ffff7ffe180)[39m -> 0x555555554000 -> 'ELF'
    [4c, 89, d6]
ITERATION 068 0x00007ffff7fe160e 0x11115000 | ld-2.31.so!_dl_fixup+0xbe (0x7ffff7fe160e)                   
    mov rcx, qword ptr [r10+0x390] 
    RCX:0x0
    [R10:0x7ffff7ffe180+0x390=0x7ffff7ffe510size:UInt64->0x7ffff7ffe4e8]] 
    [49, 8b, 8a, 90, 03, 00, 00]
ITERATION 069 0x00007ffff7fe1615 0x11115000 | ld-2.31.so!_dl_fixup+0xc5 (0x7ffff7fe1615)                   
    push 0x0 
    ??_Immediate8to64_?? [6a, 00]
ITERATION 070 0x00007ffff7fe1617 0x11115000 | ld-2.31.so!_dl_fixup+0xc7 (0x7ffff7fe1617)                   
    push rdx 
    RDX:0x1
    [52]
ITERATION 071 0x00007ffff7fe1618 0x11115000 | ld-2.31.so!_dl_fixup+0xc8 (0x7ffff7fe1618)                   
    add rdi, rax 
    RDI:0x5555555543d8 -> 0x64697074656700
    RAX:0x1
    [48, 01, c7]
ITERATION 072 0x00007ffff7fe161b 0x11115000 | ld-2.31.so!_dl_fixup+0xcb (0x7ffff7fe161b)                   
    mov rdx, r11 
    RDX:0x1
    R11:0x7fffffffe908 -> 0x555555554360 -> ''
    [4c, 89, da]
ITERATION 073 0x00007ffff7fe161e 0x11115000 | ld-2.31.so!_dl_fixup+0xce (0x7ffff7fe161e)                   
    call 0xffffffffffffb5a2 
    ??_NearBranch64_?? [e8, 9d, b5, ff, ff]
ITERATION 074 0x00007ffff7fdcbc0 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x0 (0x7ffff7fdcbc0)          
    push r15 
    R15:0x0
    [41, 57]
ITERATION 075 0x00007ffff7fdcbc2 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x2 (0x7ffff7fdcbc2)          
    push r14 
    R14:0x0
    [41, 56]
ITERATION 076 0x00007ffff7fdcbc4 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x4 (0x7ffff7fdcbc4)          
    push r13 
    R13:0x0
    [41, 55]
ITERATION 077 0x00007ffff7fdcbc6 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x6 (0x7ffff7fdcbc6)          
    mov r13, rdx 
    R13:0x0
    RDX:0x7fffffffe908 -> 0x555555554360 -> ''
    [49, 89, d5]
ITERATION 078 0x00007ffff7fdcbc9 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x9 (0x7ffff7fdcbc9)          
    push r12 
    R12:[34mexample1!_start+0x0 (0x555555555050)[39m -> 0x89485ed18949ed31
    [41, 54]
ITERATION 079 0x00007ffff7fdcbcb 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0xb (0x7ffff7fdcbcb)          
    mov r12, rdi 
    R12:[34mexample1!_start+0x0 (0x555555555050)[39m -> 0x89485ed18949ed31
    RDI:0x5555555543d9 -> 'getpid'
    [49, 89, fc]
ITERATION 080 0x00007ffff7fdcbce 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0xe (0x7ffff7fdcbce)          
    push rbp 
    RBP:0x7fffffffeb90 -> [34mexample1!__libc_csu_init+0x0 (0x5555555551a0)[39m -> 0x2c3f3d8d4c5741
    [55]
ITERATION 081 0x00007ffff7fdcbcf 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0xf (0x7ffff7fdcbcf)          
    push rbx 
    RBX:[34mexample1!_GLOBAL_OFFSET_TABLE_+0x18 (0x555555558018)[39m -> [34mexample1!_init+0x36 (0x555555555036)[39m -> 'h'
    [53]
ITERATION 082 0x00007ffff7fdcbd0 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x10 (0x7ffff7fdcbd0)         
    sub rsp, 0x98 
    RSP:0x7fffffffe8b8 -> [34mexample1!_GLOBAL_OFFSET_TABLE_+0x18 (0x555555558018)[39m ... 
    ??_Immediate32to64_?? [48, 81, ec, 98, 00, 00, 00]
ITERATION 083 0x00007ffff7fdcbd7 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x17 (0x7ffff7fdcbd7)         
    movzx edx, byte ptr [rdi] 
    EDX:0xffffe908
    [RDI:0x5555555543d9size:UInt8->0x67::g]] 
    [0f, b6, 17]
ITERATION 084 0x00007ffff7fdcbda 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x1a (0x7ffff7fdcbda)         
    mov qword ptr [rsp+0x10], rsi 
    [RSP:0x7fffffffe820+0x10=0x7fffffffe830]] 
    RSI:[34mld-2.31.so!_end+0x8 (0x7ffff7ffe180)[39m -> 0x555555554000 -> 'ELF'
    [48, 89, 74, 24, 10]
ITERATION 085 0x00007ffff7fdcbdf 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x1f (0x7ffff7fdcbdf)         
    mov qword ptr [rsp+0x20], rcx 
    [RSP:0x7fffffffe820+0x20=0x7fffffffe840]] 
    RCX:[34mld-2.31.so!_end+0x370 (0x7ffff7ffe4e8)[39m -> [34mld-2.31.so!_end+0x2c8 (0x7ffff7ffe440)[39m ... 
    [48, 89, 4c, 24, 20]
ITERATION 086 0x00007ffff7fdcbe4 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x24 (0x7ffff7fdcbe4)         
    mov qword ptr [rsp+0x8], r8 
    [RSP:0x7fffffffe820+0x8=0x7fffffffe828]] 
    R8:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0x1068 (0x7ffff7fc4570)[39m -> 0x55555555440b -> 'GLIBC_2.2.5'
    [4c, 89, 44, 24, 08]
ITERATION 087 0x00007ffff7fdcbe9 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x29 (0x7ffff7fdcbe9)         
    mov dword ptr [rsp+0x1c], r9d 
    [RSP:0x7fffffffe820+0x1c=0x7fffffffe83c]] 
    R9D:0x1
    [44, 89, 4c, 24, 1c]
ITERATION 088 0x00007ffff7fdcbee 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x2e (0x7ffff7fdcbee)         
    test dl, dl 
    DL:0x67
    DL:0x67
    [84, d2]
ITERATION 089 0x00007ffff7fdcbf0 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x30 (0x7ffff7fdcbf0)         
    je 0x240 
    ??_NearBranch64_?? [0f, 84, 3a, 02, 00, 00]
ITERATION 090 0x00007ffff7fdcbf6 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x36 (0x7ffff7fdcbf6)         
    mov rcx, rdi 
    RCX:[34mld-2.31.so!_end+0x370 (0x7ffff7ffe4e8)[39m -> [34mld-2.31.so!_end+0x2c8 (0x7ffff7ffe440)[39m ... 
    RDI:0x5555555543d9 -> 'getpid'
    [48, 89, f9]
ITERATION 091 0x00007ffff7fdcbf9 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x39 (0x7ffff7fdcbf9)         
    mov eax, 0x1505 
    EAX:0x1
    ??_Immediate32_?? [b8, 05, 15, 00, 00]
ITERATION 092 0x00007ffff7fdcbfe 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x3e (0x7ffff7fdcbfe)         
    nop 
    [66, 90]
ITERATION 093 0x00007ffff7fdcc00 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x40 (0x7ffff7fdcc00)         
    mov rsi, rax 
    RSI:[34mld-2.31.so!_end+0x8 (0x7ffff7ffe180)[39m -> 0x555555554000 -> 'ELF'
    RAX:0x1505
    [48, 89, c6]
ITERATION 094 0x00007ffff7fdcc03 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x43 (0x7ffff7fdcc03)         
    add rcx, 0x1 
    RCX:0x5555555543d9 -> 'getpid'
    ??_Immediate8to64_?? [48, 83, c1, 01]
ITERATION 095 0x00007ffff7fdcc07 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x47 (0x7ffff7fdcc07)         
    shl rsi, 0x5 
    RSI:0x1505
    ??_Immediate8_?? [48, c1, e6, 05]
ITERATION 096 0x00007ffff7fdcc0b 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x4b (0x7ffff7fdcc0b)         
    add rax, rsi 
    RAX:0x1505
    RSI:0x2a0a0
    [48, 01, f0]
ITERATION 097 0x00007ffff7fdcc0e 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x4e (0x7ffff7fdcc0e)         
    add rax, rdx 
    RAX:0x2b5a5
    RDX:0x67
    [48, 01, d0]
ITERATION 098 0x00007ffff7fdcc11 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x51 (0x7ffff7fdcc11)         
    movzx edx, byte ptr [rcx] 
    EDX:0x67
    [RCX:0x5555555543dasize:UInt8->0x65::e]] 
    [0f, b6, 11]
ITERATION 099 0x00007ffff7fdcc14 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x54 (0x7ffff7fdcc14)         
    test dl, dl 
    DL:0x65
    DL:0x65
    [84, d2]
ITERATION 100 0x00007ffff7fdcc16 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x56 (0x7ffff7fdcc16)         
    jne 0xffffffffffffffea 
    ??_NearBranch64_?? [75, e8]
ITERATION 101 0x00007ffff7fdcc00 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x40 (0x7ffff7fdcc00)         
    mov rsi, rax 
    RSI:0x2a0a0
    RAX:0x2b60c
    [48, 89, c6]
ITERATION 102 0x00007ffff7fdcc03 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x43 (0x7ffff7fdcc03)         
    add rcx, 0x1 
    RCX:0x5555555543da -> 'etpid'
    ??_Immediate8to64_?? [48, 83, c1, 01]
ITERATION 103 0x00007ffff7fdcc07 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x47 (0x7ffff7fdcc07)         
    shl rsi, 0x5 
    RSI:0x2b60c
    ??_Immediate8_?? [48, c1, e6, 05]
ITERATION 104 0x00007ffff7fdcc0b 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x4b (0x7ffff7fdcc0b)         
    add rax, rsi 
    RAX:0x2b60c
    RSI:0x56c180
    [48, 01, f0]
ITERATION 105 0x00007ffff7fdcc0e 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x4e (0x7ffff7fdcc0e)         
    add rax, rdx 
    RAX:0x59778c
    RDX:0x65
    [48, 01, d0]
ITERATION 106 0x00007ffff7fdcc11 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x51 (0x7ffff7fdcc11)         
    movzx edx, byte ptr [rcx] 
    EDX:0x65
    [RCX:0x5555555543dbsize:UInt8->0x74::t]] 
    [0f, b6, 11]
ITERATION 107 0x00007ffff7fdcc14 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x54 (0x7ffff7fdcc14)         
    test dl, dl 
    DL:0x74
    DL:0x74
    [84, d2]
ITERATION 108 0x00007ffff7fdcc16 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x56 (0x7ffff7fdcc16)         
    jne 0xffffffffffffffea 
    ??_NearBranch64_?? [75, e8]
ITERATION 109 0x00007ffff7fdcc00 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x40 (0x7ffff7fdcc00)         
    mov rsi, rax 
    RSI:0x56c180
    RAX:0x5977f1
    [48, 89, c6]
ITERATION 110 0x00007ffff7fdcc03 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x43 (0x7ffff7fdcc03)         
    add rcx, 0x1 
    RCX:0x5555555543db -> 'tpid'
    ??_Immediate8to64_?? [48, 83, c1, 01]
ITERATION 111 0x00007ffff7fdcc07 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x47 (0x7ffff7fdcc07)         
    shl rsi, 0x5 
    RSI:0x5977f1
    ??_Immediate8_?? [48, c1, e6, 05]
ITERATION 112 0x00007ffff7fdcc0b 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x4b (0x7ffff7fdcc0b)         
    add rax, rsi 
    RAX:0x5977f1
    RSI:0xb2efe20
    [48, 01, f0]
ITERATION 113 0x00007ffff7fdcc0e 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x4e (0x7ffff7fdcc0e)         
    add rax, rdx 
    RAX:0xb887611
    RDX:0x74
    [48, 01, d0]
ITERATION 114 0x00007ffff7fdcc11 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x51 (0x7ffff7fdcc11)         
    movzx edx, byte ptr [rcx] 
    EDX:0x74
    [RCX:0x5555555543dcsize:UInt8->0x70::p]] 
    [0f, b6, 11]
ITERATION 115 0x00007ffff7fdcc14 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x54 (0x7ffff7fdcc14)         
    test dl, dl 
    DL:0x70
    DL:0x70
    [84, d2]
ITERATION 116 0x00007ffff7fdcc16 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x56 (0x7ffff7fdcc16)         
    jne 0xffffffffffffffea 
    ??_NearBranch64_?? [75, e8]
ITERATION 117 0x00007ffff7fdcc00 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x40 (0x7ffff7fdcc00)         
    mov rsi, rax 
    RSI:0xb2efe20
    RAX:0xb887685
    [48, 89, c6]
ITERATION 118 0x00007ffff7fdcc03 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x43 (0x7ffff7fdcc03)         
    add rcx, 0x1 
    RCX:0x5555555543dc -> 'pid'
    ??_Immediate8to64_?? [48, 83, c1, 01]
ITERATION 119 0x00007ffff7fdcc07 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x47 (0x7ffff7fdcc07)         
    shl rsi, 0x5 
    RSI:0xb887685
    ??_Immediate8_?? [48, c1, e6, 05]
ITERATION 120 0x00007ffff7fdcc0b 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x4b (0x7ffff7fdcc0b)         
    add rax, rsi 
    RAX:0xb887685
    RSI:0x1710ed0a0
    [48, 01, f0]
ITERATION 121 0x00007ffff7fdcc0e 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x4e (0x7ffff7fdcc0e)         
    add rax, rdx 
    RAX:0x17c974725
    RDX:0x70
    [48, 01, d0]
ITERATION 122 0x00007ffff7fdcc11 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x51 (0x7ffff7fdcc11)         
    movzx edx, byte ptr [rcx] 
    EDX:0x70
    [RCX:0x5555555543ddsize:UInt8->0x69::i]] 
    [0f, b6, 11]
ITERATION 123 0x00007ffff7fdcc14 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x54 (0x7ffff7fdcc14)         
    test dl, dl 
    DL:0x69
    DL:0x69
    [84, d2]
ITERATION 124 0x00007ffff7fdcc16 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x56 (0x7ffff7fdcc16)         
    jne 0xffffffffffffffea 
    ??_NearBranch64_?? [75, e8]
ITERATION 125 0x00007ffff7fdcc00 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x40 (0x7ffff7fdcc00)         
    mov rsi, rax 
    RSI:0x1710ed0a0
    RAX:0x17c974795
    [48, 89, c6]
ITERATION 126 0x00007ffff7fdcc03 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x43 (0x7ffff7fdcc03)         
    add rcx, 0x1 
    RCX:0x5555555543dd -> 'id'
    ??_Immediate8to64_?? [48, 83, c1, 01]
ITERATION 127 0x00007ffff7fdcc07 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x47 (0x7ffff7fdcc07)         
    shl rsi, 0x5 
    RSI:0x17c974795
    ??_Immediate8_?? [48, c1, e6, 05]
ITERATION 128 0x00007ffff7fdcc0b 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x4b (0x7ffff7fdcc0b)         
    add rax, rsi 
    RAX:0x17c974795
    RSI:0x2f92e8f2a0
    [48, 01, f0]
ITERATION 129 0x00007ffff7fdcc0e 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x4e (0x7ffff7fdcc0e)         
    add rax, rdx 
    RAX:0x310f803a35
    RDX:0x69
    [48, 01, d0]
ITERATION 130 0x00007ffff7fdcc11 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x51 (0x7ffff7fdcc11)         
    movzx edx, byte ptr [rcx] 
    EDX:0x69
    [RCX:0x5555555543desize:UInt8->0x64::d]] 
    [0f, b6, 11]
ITERATION 131 0x00007ffff7fdcc14 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x54 (0x7ffff7fdcc14)         
    test dl, dl 
    DL:0x64
    DL:0x64
    [84, d2]
ITERATION 132 0x00007ffff7fdcc16 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x56 (0x7ffff7fdcc16)         
    jne 0xffffffffffffffea 
    ??_NearBranch64_?? [75, e8]
ITERATION 133 0x00007ffff7fdcc00 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x40 (0x7ffff7fdcc00)         
    mov rsi, rax 
    RSI:0x2f92e8f2a0
    RAX:0x310f803a9e
    [48, 89, c6]
ITERATION 134 0x00007ffff7fdcc03 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x43 (0x7ffff7fdcc03)         
    add rcx, 0x1 
    RCX:0x5555555543de -> 'd'
    ??_Immediate8to64_?? [48, 83, c1, 01]
ITERATION 135 0x00007ffff7fdcc07 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x47 (0x7ffff7fdcc07)         
    shl rsi, 0x5 
    RSI:0x310f803a9e
    ??_Immediate8_?? [48, c1, e6, 05]
ITERATION 136 0x00007ffff7fdcc0b 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x4b (0x7ffff7fdcc0b)         
    add rax, rsi 
    RAX:0x310f803a9e
    RSI:0x621f00753c0
    [48, 01, f0]
ITERATION 137 0x00007ffff7fdcc0e 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x4e (0x7ffff7fdcc0e)         
    add rax, rdx 
    RAX:0x652ff878e5e
    RDX:0x64
    [48, 01, d0]
ITERATION 138 0x00007ffff7fdcc11 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x51 (0x7ffff7fdcc11)         
    movzx edx, byte ptr [rcx] 
    EDX:0x64
    [RCX:0x5555555543dfsize:UInt8->0x0]] 
    [0f, b6, 11]
ITERATION 139 0x00007ffff7fdcc14 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x54 (0x7ffff7fdcc14)         
    test dl, dl 
    DL:0x0
    DL:0x0
    [84, d2]
ITERATION 140 0x00007ffff7fdcc16 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x56 (0x7ffff7fdcc16)         
    jne 0xffffffffffffffea 
    ??_NearBranch64_?? [75, e8]
ITERATION 141 0x00007ffff7fdcc18 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x58 (0x7ffff7fdcc18)         
    mov ebx, eax 
    EBX:0x55558018
    EAX:0xff878ec2
    [89, c3]
ITERATION 142 0x00007ffff7fdcc1a 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x5a (0x7ffff7fdcc1a)         
    add qword ptr [rip+0x20dae], 0x1 
    [RIP:0x7ffff7fdcc1a+0x20db6=0x7ffff7ffd9d0size:UInt64->0x59]] 
    ??_Immediate8to64_?? [48, 83, 05, ae, 0d, 02, 00, 01]
ITERATION 143 0x00007ffff7fdcc22 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x62 (0x7ffff7fdcc22)         
    mov eax, 0xffffffff 
    EAX:0xff878ec2
    ??_Immediate32_?? [b8, ff, ff, ff, ff]
ITERATION 144 0x00007ffff7fdcc27 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x67 (0x7ffff7fdcc27)         
    cmp qword ptr [rsp+0x8], 0x0 
    [RSP:0x7fffffffe820+0x8=0x7fffffffe828size:UInt64->0x7ffff7fc4570]] 
    ??_Immediate8to64_?? [48, 83, 7c, 24, 08, 00]
ITERATION 145 0x00007ffff7fdcc2d 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x6d (0x7ffff7fdcc2d)         
    mov qword ptr [rsp+0x40], rax 
    [RSP:0x7fffffffe820+0x40=0x7fffffffe860]] 
    RAX:0xffffffff
    [48, 89, 44, 24, 40]
ITERATION 146 0x00007ffff7fdcc32 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x72 (0x7ffff7fdcc32)         
    mov qword ptr [rsp+0x50], 0x0 
    [RSP:0x7fffffffe820+0x50=0x7fffffffe870]] 
    ??_Immediate32to64_?? [48, c7, 44, 24, 50, 00, 00, 00, 00]
ITERATION 147 0x00007ffff7fdcc3b 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x7b (0x7ffff7fdcc3b)         
    mov qword ptr [rsp+0x58], 0x0 
    [RSP:0x7fffffffe820+0x58=0x7fffffffe878]] 
    ??_Immediate32to64_?? [48, c7, 44, 24, 58, 00, 00, 00, 00]
ITERATION 148 0x00007ffff7fdcc44 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x84 (0x7ffff7fdcc44)         
    je 0x10 
    ??_NearBranch64_?? [74, 0e]
ITERATION 149 0x00007ffff7fdcc46 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x86 (0x7ffff7fdcc46)         
    test byte ptr [rsp+0xd0], 0x2 
    [RSP:0x7fffffffe820+0xd0=0x7fffffffe8f0size:UInt8->0x1]] 
    ??_Immediate8_?? [f6, 84, 24, d0, 00, 00, 00, 02]
ITERATION 150 0x00007ffff7fdcc4e 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x8e (0x7ffff7fdcc4e)         
    jne 0xbef 
    ??_NearBranch64_?? [0f, 85, e9, 0b, 00, 00]
ITERATION 151 0x00007ffff7fdcc54 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x94 (0x7ffff7fdcc54)         
    mov rax, qword ptr [rsp+0x20] 
    RAX:0xffffffff
    [RSP:0x7fffffffe820+0x20=0x7fffffffe840size:UInt64->0x7ffff7ffe4e8]] 
    [48, 8b, 44, 24, 20]
ITERATION 152 0x00007ffff7fdcc59 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x99 (0x7ffff7fdcc59)         
    mov rcx, qword ptr [r13] 
    RCX:0x5555555543df -> 0x665f6178635f5f00
    [R13:0x7fffffffe908size:UInt64->0x555555554360]] 
    [49, 8b, 4d, 00]
ITERATION 153 0x00007ffff7fdcc5d 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x9d (0x7ffff7fdcc5d)         
    cmp qword ptr [rsp+0xd8], 0x0 
    [RSP:0x7fffffffe820+0xd8=0x7fffffffe8f8size:UInt64->0x0]] 
    ??_Immediate8to64_?? [48, 83, bc, 24, d8, 00, 00, 00, 00]
ITERATION 154 0x00007ffff7fdcc66 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0xa6 (0x7ffff7fdcc66)         
    mov r9, qword ptr [rax] 
    R9:0x1
    [RAX:0x7ffff7ffe4e8size:UInt64->0x7ffff7ffe440]] 
    [4c, 8b, 08]
ITERATION 155 0x00007ffff7fdcc69 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0xa9 (0x7ffff7fdcc69)         
    jne 0x27f 
    ??_NearBranch64_?? [0f, 85, 79, 02, 00, 00]
ITERATION 156 0x00007ffff7fdcc6f 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0xaf (0x7ffff7fdcc6f)         
    test r9, r9 
    R9:[34mld-2.31.so!_end+0x2c8 (0x7ffff7ffe440)[39m ... 
    R9:[34mld-2.31.so!_end+0x2c8 (0x7ffff7ffe440)[39m ... 
    [4d, 85, c9]
ITERATION 157 0x00007ffff7fdcc72 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0xb2 (0x7ffff7fdcc72)         
    je 0x1ce 
    ??_NearBranch64_?? [0f, 84, c8, 01, 00, 00]
ITERATION 158 0x00007ffff7fdcc78 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0xb8 (0x7ffff7fdcc78)         
    mov qword ptr [rsp+0x28], 0x0 
    [RSP:0x7fffffffe820+0x28=0x7fffffffe848]] 
    ??_Immediate32to64_?? [48, c7, 44, 24, 28, 00, 00, 00, 00]
ITERATION 159 0x00007ffff7fdcc81 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0xc1 (0x7ffff7fdcc81)         
    mov rax, qword ptr [rsp+0x28] 
    RAX:[34mld-2.31.so!_end+0x370 (0x7ffff7ffe4e8)[39m -> [34mld-2.31.so!_end+0x2c8 (0x7ffff7ffe440)[39m ... 
    [RSP:0x7fffffffe820+0x28=0x7fffffffe848size:UInt64->0x0]] 
    [48, 8b, 44, 24, 28]
ITERATION 160 0x00007ffff7fdcc86 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0xc6 (0x7ffff7fdcc86)         
    mov rbp, qword ptr [rsp+0x20] 
    RBP:0x7fffffffeb90 -> [34mexample1!__libc_csu_init+0x0 (0x5555555551a0)[39m -> 0x2c3f3d8d4c5741
    [RSP:0x7fffffffe820+0x20=0x7fffffffe840size:UInt64->0x7ffff7ffe4e8]] 
    [48, 8b, 6c, 24, 20]
ITERATION 161 0x00007ffff7fdcc8b 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0xcb (0x7ffff7fdcc8b)         
    lea r15, [rsp+0x50] 
    R15:0x0
    [RSP:0x7fffffffe820+0x50=0x7fffffffe870]] 
    [4c, 8d, 7c, 24, 50]
ITERATION 162 0x00007ffff7fdcc90 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0xd0 (0x7ffff7fdcc90)         
    lea r14, [rsp+0x40] 
    R14:0x0
    [RSP:0x7fffffffe820+0x40=0x7fffffffe860]] 
    [4c, 8d, 74, 24, 40]
ITERATION 163 0x00007ffff7fdcc95 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0xd5 (0x7ffff7fdcc95)         
    jmp 0x1e 
    ??_NearBranch64_?? [eb, 1c]
ITERATION 164 0x00007ffff7fdccb3 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0xf3 (0x7ffff7fdccb3)         
    push qword ptr [rsp+0x10] 
    [RSP:0x7fffffffe820+0x10=0x7fffffffe830size:UInt64->0x7ffff7ffe180]] 
    [ff, 74, 24, 10]
ITERATION 165 0x00007ffff7fdccb7 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0xf7 (0x7ffff7fdccb7)         
    mov edi, dword ptr [rsp+0x24] 
    EDI:0x555543d9
    [RSP:0x7fffffffe818+0x24=0x7fffffffe83csize:UInt32->0x1]] 
    [8b, 7c, 24, 24]
ITERATION 166 0x00007ffff7fdccbb 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0xfb (0x7ffff7fdccbb)         
    mov r8, r15 
    R8:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0x1068 (0x7ffff7fc4570)[39m -> 0x55555555440b -> 'GLIBC_2.2.5'
    R15:0x7fffffffe870 -> 0x0
    [4d, 89, f8]
ITERATION 167 0x00007ffff7fdccbe 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0xfe (0x7ffff7fdccbe)         
    mov rdx, r14 
    RDX:0x0
    R14:0x7fffffffe860 -> 0xffffffff
    [4c, 89, f2]
ITERATION 168 0x00007ffff7fdccc1 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x101 (0x7ffff7fdccc1)        
    mov rsi, rbx 
    RSI:0x621f00753c0
    RBX:0xff878ec2
    [48, 89, de]
ITERATION 169 0x00007ffff7fdccc4 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x104 (0x7ffff7fdccc4)        
    push rdi 
    RDI:0x1
    [57]
ITERATION 170 0x00007ffff7fdccc5 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x105 (0x7ffff7fdccc5)        
    push qword ptr [rsp+0xe8] 
    [RSP:0x7fffffffe810+0xe8=0x7fffffffe8f8size:UInt64->0x0]] 
    [ff, b4, 24, e8, 00, 00, 00]
ITERATION 171 0x00007ffff7fdcccc 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x10c (0x7ffff7fdcccc)        
    mov edi, dword ptr [rsp+0xe8] 
    EDI:0x1
    [RSP:0x7fffffffe808+0xe8=0x7fffffffe8f0size:UInt32->0x1]] 
    [8b, bc, 24, e8, 00, 00, 00]
ITERATION 172 0x00007ffff7fdccd3 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x113 (0x7ffff7fdccd3)        
    push rdi 
    RDI:0x1
    [57]
ITERATION 173 0x00007ffff7fdccd4 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x114 (0x7ffff7fdccd4)        
    mov rdi, r12 
    RDI:0x1
    R12:0x5555555543d9 -> 'getpid'
    [4c, 89, e7]
ITERATION 174 0x00007ffff7fdccd7 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x117 (0x7ffff7fdccd7)        
    push qword ptr [rsp+0x28] 
    [RSP:0x7fffffffe800+0x28=0x7fffffffe828size:UInt64->0x7ffff7fc4570]] 
    [ff, 74, 24, 28]
ITERATION 175 0x00007ffff7fdccdb 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x11b (0x7ffff7fdccdb)        
    push rax 
    RAX:0x0
    [50]
ITERATION 176 0x00007ffff7fdccdc 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x11c (0x7ffff7fdccdc)        
    call 0xfffffffffffff324 
    ??_NearBranch64_?? [e8, 1f, f3, ff, ff]
ITERATION 177 0x00007ffff7fdc000 0x11115000 | ld-2.31.so!do_lookup_x+0x0 (0x7ffff7fdc000)                  
    push r15 
    R15:0x7fffffffe870 -> 0x0
    [41, 57]
ITERATION 178 0x00007ffff7fdc002 0x11115000 | ld-2.31.so!do_lookup_x+0x2 (0x7ffff7fdc002)                  
    push r14 
    R14:0x7fffffffe860 -> 0xffffffff
    [41, 56]
ITERATION 179 0x00007ffff7fdc004 0x11115000 | ld-2.31.so!do_lookup_x+0x4 (0x7ffff7fdc004)                  
    push r13 
    R13:0x7fffffffe908 -> 0x555555554360 -> ''
    [41, 55]
ITERATION 180 0x00007ffff7fdc006 0x11115000 | ld-2.31.so!do_lookup_x+0x6 (0x7ffff7fdc006)                  
    push r12 
    R12:0x5555555543d9 -> 'getpid'
    [41, 54]
ITERATION 181 0x00007ffff7fdc008 0x11115000 | ld-2.31.so!do_lookup_x+0x8 (0x7ffff7fdc008)                  
    push rbp 
    RBP:[34mld-2.31.so!_end+0x370 (0x7ffff7ffe4e8)[39m -> [34mld-2.31.so!_end+0x2c8 (0x7ffff7ffe440)[39m ... 
    [55]
ITERATION 182 0x00007ffff7fdc009 0x11115000 | ld-2.31.so!do_lookup_x+0x9 (0x7ffff7fdc009)                  
    push rbx 
    RBX:0xff878ec2
    [53]
ITERATION 183 0x00007ffff7fdc00a 0x11115000 | ld-2.31.so!do_lookup_x+0xa (0x7ffff7fdc00a)                  
    sub rsp, 0x88 
    RSP:0x7fffffffe7b8 -> 0xff878ec2
    ??_Immediate32to64_?? [48, 81, ec, 88, 00, 00, 00]
ITERATION 184 0x00007ffff7fdc011 0x11115000 | ld-2.31.so!do_lookup_x+0x11 (0x7ffff7fdc011)                 
    mov r12d, dword ptr [r9+0x8] 
    R12D:0x555543d9
    [R9:0x7ffff7ffe440+0x8=0x7ffff7ffe448size:UInt32->0x3]] 
    [45, 8b, 61, 08]
ITERATION 185 0x00007ffff7fdc015 0x11115000 | ld-2.31.so!do_lookup_x+0x15 (0x7ffff7fdc015)                 
    mov qword ptr [rsp+0x20], rdi 
    [RSP:0x7fffffffe730+0x20=0x7fffffffe750]] 
    RDI:0x5555555543d9 -> 'getpid'
    [48, 89, 7c, 24, 20]
ITERATION 186 0x00007ffff7fdc01a 0x11115000 | ld-2.31.so!do_lookup_x+0x1a (0x7ffff7fdc01a)                 
    mov rbp, qword ptr [rsp+0xc0] 
    RBP:[34mld-2.31.so!_end+0x370 (0x7ffff7ffe4e8)[39m -> [34mld-2.31.so!_end+0x2c8 (0x7ffff7ffe440)[39m ... 
    [RSP:0x7fffffffe730+0xc0=0x7fffffffe7f0size:UInt64->0x0]] 
    [48, 8b, ac, 24, c0, 00, 00, 00]
ITERATION 187 0x00007ffff7fdc022 0x11115000 | ld-2.31.so!do_lookup_x+0x22 (0x7ffff7fdc022)                 
    mov qword ptr [rsp+0x28], rsi 
    [RSP:0x7fffffffe730+0x28=0x7fffffffe758]] 
    RSI:0xff878ec2
    [48, 89, 74, 24, 28]
ITERATION 188 0x00007ffff7fdc027 0x11115000 | ld-2.31.so!do_lookup_x+0x27 (0x7ffff7fdc027)                 
    mov r15, qword ptr [rsp+0xd8] 
    R15:0x7fffffffe870 -> 0x0
    [RSP:0x7fffffffe730+0xd8=0x7fffffffe808size:UInt64->0x0]] 
    [4c, 8b, bc, 24, d8, 00, 00, 00]
ITERATION 189 0x00007ffff7fdc02f 0x11115000 | ld-2.31.so!do_lookup_x+0x2f (0x7ffff7fdc02f)                 
    mov qword ptr [rsp+0x58], rdx 
    [RSP:0x7fffffffe730+0x58=0x7fffffffe788]] 
    RDX:0x7fffffffe860 -> 0xffffffff
    [48, 89, 54, 24, 58]
ITERATION 190 0x00007ffff7fdc034 0x11115000 | ld-2.31.so!do_lookup_x+0x34 (0x7ffff7fdc034)                 
    mov r14d, dword ptr [rsp+0xe0] 
    R14D:0xffffe860
    [RSP:0x7fffffffe730+0xe0=0x7fffffffe810size:UInt32->0x1]] 
    [44, 8b, b4, 24, e0, 00, 00, 00]
ITERATION 191 0x00007ffff7fdc03c 0x11115000 | ld-2.31.so!do_lookup_x+0x3c (0x7ffff7fdc03c)                 
    mov qword ptr [rsp+0x50], rcx 
    [RSP:0x7fffffffe730+0x50=0x7fffffffe780]] 
    RCX:0x555555554360 -> ''
    [48, 89, 4c, 24, 50]
ITERATION 192 0x00007ffff7fdc041 0x11115000 | ld-2.31.so!do_lookup_x+0x41 (0x7ffff7fdc041)                 
    mov qword ptr [rsp+0x48], r8 
    [RSP:0x7fffffffe730+0x48=0x7fffffffe778]] 
    R8:0x7fffffffe870 -> 0x0
    [4c, 89, 44, 24, 48]
ITERATION 193 0x00007ffff7fdc046 0x11115000 | ld-2.31.so!do_lookup_x+0x46 (0x7ffff7fdc046)                 
    shr rsi, 0x6 
    RSI:0xff878ec2
    ??_Immediate8_?? [48, c1, ee, 06]
ITERATION 194 0x00007ffff7fdc04a 0x11115000 | ld-2.31.so!do_lookup_x+0x4a (0x7ffff7fdc04a)                 
    mov r13, qword ptr [r9] 
    R13:0x7fffffffe908 -> 0x555555554360 -> ''
    [R9:0x7ffff7ffe440size:UInt64->0x7ffff7fc4520]] 
    [4d, 8b, 29]
ITERATION 195 0x00007ffff7fdc04d 0x11115000 | ld-2.31.so!do_lookup_x+0x4d (0x7ffff7fdc04d)                 
    mov r11, r12 
    R11:0x7fffffffe908 -> 0x555555554360 -> ''
    R12:0x3
    [4d, 89, e3]
ITERATION 196 0x00007ffff7fdc050 0x11115000 | ld-2.31.so!do_lookup_x+0x50 (0x7ffff7fdc050)                 
    mov qword ptr [rsp+0x30], rsi 
    [RSP:0x7fffffffe730+0x30=0x7fffffffe760]] 
    RSI:0x3fe1e3b
    [48, 89, 74, 24, 30]
ITERATION 197 0x00007ffff7fdc055 0x11115000 | ld-2.31.so!do_lookup_x+0x55 (0x7ffff7fdc055)                 
    jmp 0x95 
    ??_NearBranch64_?? [e9, 90, 00, 00, 00]
ITERATION 198 0x00007ffff7fdc0ea 0x11115000 | ld-2.31.so!do_lookup_x+0xea (0x7ffff7fdc0ea)                 
    mov rax, qword ptr [r13+rbp*8] 
    RAX:0x0
    [R13:0x7ffff7fc4520+RBP:0x0*0x8size:UInt64->0x7ffff7ffe180]] 
    [49, 8b, 44, ed, 00]
ITERATION 199 0x00007ffff7fdc0ef 0x11115000 | ld-2.31.so!do_lookup_x+0xef (0x7ffff7fdc0ef)                 
    mov rbx, qword ptr [rax+0x28] 
    RBX:0xff878ec2
    [RAX:0x7ffff7ffe180+0x28=0x7ffff7ffe1a8size:UInt64->0x7ffff7ffe180]] 
    [48, 8b, 58, 28]
ITERATION 200 0x00007ffff7fdc0f3 0x11115000 | ld-2.31.so!do_lookup_x+0xf3 (0x7ffff7fdc0f3)                 
    cmp rbx, r15 
    RBX:[34mld-2.31.so!_end+0x8 (0x7ffff7ffe180)[39m -> 0x555555554000 -> 'ELF'
    R15:0x0
    [4c, 39, fb]
ITERATION 201 0x00007ffff7fdc0f6 0x11115000 | ld-2.31.so!do_lookup_x+0xf6 (0x7ffff7fdc0f6)                 
    je 0xffffffffffffffe7 
    ??_NearBranch64_?? [74, e5]
ITERATION 202 0x00007ffff7fdc0f8 0x11115000 | ld-2.31.so!do_lookup_x+0xf8 (0x7ffff7fdc0f8)                 
    mov eax, r14d 
    EAX:0xf7ffe180
    R14D:0x1
    [44, 89, f0]
ITERATION 203 0x00007ffff7fdc0fb 0x11115000 | ld-2.31.so!do_lookup_x+0xfb (0x7ffff7fdc0fb)                 
    and eax, 0x2 
    EAX:0x1
    ??_Immediate8to32_?? [83, e0, 02]
ITERATION 204 0x00007ffff7fdc0fe 0x11115000 | ld-2.31.so!do_lookup_x+0xfe (0x7ffff7fdc0fe)                 
    mov dword ptr [rsp+0x8], eax 
    [RSP:0x7fffffffe730+0x8=0x7fffffffe738]] 
    EAX:0x0
    [89, 44, 24, 08]
ITERATION 205 0x00007ffff7fdc102 0x11115000 | ld-2.31.so!do_lookup_x+0x102 (0x7ffff7fdc102)                
    je 0xb 
    ??_NearBranch64_?? [74, 09]
ITERATION 206 0x00007ffff7fdc10d 0x11115000 | ld-2.31.so!do_lookup_x+0x10d (0x7ffff7fdc10d)                
    test byte ptr [rbx+0x31d], 0x20 
    [RBX:0x7ffff7ffe180+0x31d=0x7ffff7ffe49dsize:UInt8->0x0]] 
    ??_Immediate8_?? [f6, 83, 1d, 03, 00, 00, 20]
ITERATION 207 0x00007ffff7fdc114 0x11115000 | ld-2.31.so!do_lookup_x+0x114 (0x7ffff7fdc114)                
    jne 0xffffffffffffffc9 
    ??_NearBranch64_?? [75, c7]
ITERATION 208 0x00007ffff7fdc116 0x11115000 | ld-2.31.so!do_lookup_x+0x116 (0x7ffff7fdc116)                
    test byte ptr [rip+0x204a3], 0x8 
    [RIP:0x7ffff7fdc116+0x204aa=0x7ffff7ffc5c0size:UInt8->0x0]] 
    ??_Immediate8_?? [f6, 05, a3, 04, 02, 00, 08]
ITERATION 209 0x00007ffff7fdc11d 0x11115000 | ld-2.31.so!do_lookup_x+0x11d (0x7ffff7fdc11d)                
    je 0xffffffffffffff43 
    ??_NearBranch64_?? [0f, 84, 3d, ff, ff, ff]
ITERATION 210 0x00007ffff7fdc060 0x11115000 | ld-2.31.so!do_lookup_x+0x60 (0x7ffff7fdc060)                 
    mov edx, dword ptr [rbx+0x2f4] 
    EDX:0xffffe860
    [RBX:0x7ffff7ffe180+0x2f4=0x7ffff7ffe474size:UInt32->0x2]] 
    [8b, 93, f4, 02, 00, 00]
ITERATION 211 0x00007ffff7fdc066 0x11115000 | ld-2.31.so!do_lookup_x+0x66 (0x7ffff7fdc066)                 
    test edx, edx 
    EDX:0x2
    EDX:0x2
    [85, d2]
ITERATION 212 0x00007ffff7fdc068 0x11115000 | ld-2.31.so!do_lookup_x+0x68 (0x7ffff7fdc068)                 
    je 0x75 
    ??_NearBranch64_?? [74, 73]
ITERATION 213 0x00007ffff7fdc06a 0x11115000 | ld-2.31.so!do_lookup_x+0x6a (0x7ffff7fdc06a)                 
    mov rax, qword ptr [rbx+0x70] 
    RAX:0x0
    [RBX:0x7ffff7ffe180+0x70=0x7ffff7ffe1f0size:UInt64->0x555555557e88]] 
    [48, 8b, 43, 70]
ITERATION 214 0x00007ffff7fdc06e 0x11115000 | ld-2.31.so!do_lookup_x+0x6e (0x7ffff7fdc06e)                 
    mov dword ptr [rsp+0x74], 0x0 
    [RSP:0x7fffffffe730+0x74=0x7fffffffe7a4]] 
    ??_Immediate32_?? [c7, 44, 24, 74, 00, 00, 00, 00]
ITERATION 215 0x00007ffff7fdc076 0x11115000 | ld-2.31.so!do_lookup_x+0x76 (0x7ffff7fdc076)                 
    mov qword ptr [rsp+0x78], 0x0 
    [RSP:0x7fffffffe730+0x78=0x7fffffffe7a8]] 
    ??_Immediate32to64_?? [48, c7, 44, 24, 78, 00, 00, 00, 00]
ITERATION 216 0x00007ffff7fdc07f 0x11115000 | ld-2.31.so!do_lookup_x+0x7f (0x7ffff7fdc07f)                 
    mov rax, qword ptr [rax+0x8] 
    RAX:[34mexample1!_DYNAMIC+0x90 (0x555555557e88)[39m -> ''
    [RAX:0x555555557e88+0x8=0x555555557e90size:UInt64->0x555555554330]] 
    [48, 8b, 40, 08]
ITERATION 217 0x00007ffff7fdc083 0x11115000 | ld-2.31.so!do_lookup_x+0x83 (0x7ffff7fdc083)                 
    mov qword ptr [rsp+0x18], rax 
    [RSP:0x7fffffffe730+0x18=0x7fffffffe748]] 
    RAX:0x555555554330 -> 0x0
    [48, 89, 44, 24, 18]
ITERATION 218 0x00007ffff7fdc088 0x11115000 | ld-2.31.so!do_lookup_x+0x88 (0x7ffff7fdc088)                 
    mov rax, qword ptr [rbx+0x68] 
    RAX:0x555555554330 -> 0x0
    [RBX:0x7ffff7ffe180+0x68=0x7ffff7ffe1e8size:UInt64->0x555555557e78]] 
    [48, 8b, 43, 68]
ITERATION 219 0x00007ffff7fdc08c 0x11115000 | ld-2.31.so!do_lookup_x+0x8c (0x7ffff7fdc08c)                 
    mov rax, qword ptr [rax+0x8] 
    RAX:[34mexample1!_DYNAMIC+0x80 (0x555555557e78)[39m -> ''
    [RAX:0x555555557e78+0x8=0x555555557e80size:UInt64->0x5555555543d8]] 
    [48, 8b, 40, 08]
ITERATION 220 0x00007ffff7fdc090 0x11115000 | ld-2.31.so!do_lookup_x+0x90 (0x7ffff7fdc090)                 
    mov qword ptr [rsp+0x10], rax 
    [RSP:0x7fffffffe730+0x10=0x7fffffffe740]] 
    RAX:0x5555555543d8 -> 0x64697074656700
    [48, 89, 44, 24, 10]
ITERATION 221 0x00007ffff7fdc095 0x11115000 | ld-2.31.so!do_lookup_x+0x95 (0x7ffff7fdc095)                 
    mov rax, qword ptr [rbx+0x300] 
    RAX:0x5555555543d8 -> 0x64697074656700
    [RBX:0x7ffff7ffe180+0x300=0x7ffff7ffe480size:UInt64->0x555555554318]] 
    [48, 8b, 83, 00, 03, 00, 00]
ITERATION 222 0x00007ffff7fdc09c 0x11115000 | ld-2.31.so!do_lookup_x+0x9c (0x7ffff7fdc09c)                 
    test rax, rax 
    RAX:0x555555554318 -> 0x810000
    RAX:0x555555554318 -> 0x810000
    [48, 85, c0]
ITERATION 223 0x00007ffff7fdc09f 0x11115000 | ld-2.31.so!do_lookup_x+0x9f (0x7ffff7fdc09f)                 
    je 0xd9 
    ??_NearBranch64_?? [0f, 84, d3, 00, 00, 00]
ITERATION 224 0x00007ffff7fdc0a5 0x11115000 | ld-2.31.so!do_lookup_x+0xa5 (0x7ffff7fdc0a5)                 
    mov rdi, qword ptr [rsp+0x28] 
    RDI:0x5555555543d9 -> 'getpid'
    [RSP:0x7fffffffe730+0x28=0x7fffffffe758size:UInt64->0xff878ec2]] 
    [48, 8b, 7c, 24, 28]
ITERATION 225 0x00007ffff7fdc0aa 0x11115000 | ld-2.31.so!do_lookup_x+0xaa (0x7ffff7fdc0aa)                 
    mov ecx, dword ptr [rsp+0x30] 
    ECX:0x55554360
    [RSP:0x7fffffffe730+0x30=0x7fffffffe760size:UInt32->0x3fe1e3b]] 
    [8b, 4c, 24, 30]
ITERATION 226 0x00007ffff7fdc0ae 0x11115000 | ld-2.31.so!do_lookup_x+0xae (0x7ffff7fdc0ae)                 
    and ecx, dword ptr [rbx+0x2f8] 
    ECX:0x3fe1e3b
    [RBX:0x7ffff7ffe180+0x2f8=0x7ffff7ffe478size:UInt32->0x0]] 
    [23, 8b, f8, 02, 00, 00]
ITERATION 227 0x00007ffff7fdc0b4 0x11115000 | ld-2.31.so!do_lookup_x+0xb4 (0x7ffff7fdc0b4)                 
    mov rax, qword ptr [rax+rcx*8] 
    RAX:0x555555554318 -> 0x810000
    [RAX:0x555555554318+RCX:0x0*0x8size:UInt64->0x810000]] 
    [48, 8b, 04, c8]
ITERATION 228 0x00007ffff7fdc0b8 0x11115000 | ld-2.31.so!do_lookup_x+0xb8 (0x7ffff7fdc0b8)                 
    mov ecx, dword ptr [rbx+0x2fc] 
    ECX:0x0
    [RBX:0x7ffff7ffe180+0x2fc=0x7ffff7ffe47csize:UInt32->0x6]] 
    [8b, 8b, fc, 02, 00, 00]
ITERATION 229 0x00007ffff7fdc0be 0x11115000 | ld-2.31.so!do_lookup_x+0xbe (0x7ffff7fdc0be)                 
    mov rsi, rdi 
    RSI:0x3fe1e3b
    RDI:0xff878ec2
    [48, 89, fe]
ITERATION 230 0x00007ffff7fdc0c1 0x11115000 | ld-2.31.so!do_lookup_x+0xc1 (0x7ffff7fdc0c1)                 
    shr rsi, cl 
    RSI:0xff878ec2
    CL:0x6
    [48, d3, ee]
ITERATION 231 0x00007ffff7fdc0c4 0x11115000 | ld-2.31.so!do_lookup_x+0xc4 (0x7ffff7fdc0c4)                 
    mov rcx, rsi 
    RCX:0x6
    RSI:0x3fe1e3b
    [48, 89, f1]
ITERATION 232 0x00007ffff7fdc0c7 0x11115000 | ld-2.31.so!do_lookup_x+0xc7 (0x7ffff7fdc0c7)                 
    mov rsi, rax 
    RSI:0x3fe1e3b
    RAX:0x810000
    [48, 89, c6]
ITERATION 233 0x00007ffff7fdc0ca 0x11115000 | ld-2.31.so!do_lookup_x+0xca (0x7ffff7fdc0ca)                 
    shr rsi, cl 
    RSI:0x810000
    CL:0x3b
    [48, d3, ee]
ITERATION 234 0x00007ffff7fdc0cd 0x11115000 | ld-2.31.so!do_lookup_x+0xcd (0x7ffff7fdc0cd)                 
    mov ecx, edi 
    ECX:0x3fe1e3b
    EDI:0xff878ec2
    [89, f9]
ITERATION 235 0x00007ffff7fdc0cf 0x11115000 | ld-2.31.so!do_lookup_x+0xcf (0x7ffff7fdc0cf)                 
    shr rax, cl 
    RAX:0x810000
    CL:0xc2
    [48, d3, e8]
ITERATION 236 0x00007ffff7fdc0d2 0x11115000 | ld-2.31.so!do_lookup_x+0xd2 (0x7ffff7fdc0d2)                 
    and rax, rsi 
    RAX:0x204000
    RSI:0x0
    [48, 21, f0]
ITERATION 237 0x00007ffff7fdc0d5 0x11115000 | ld-2.31.so!do_lookup_x+0xd5 (0x7ffff7fdc0d5)                 
    test al, 0x1 
    AL:0x0
    ??_Immediate8_?? [a8, 01]
ITERATION 238 0x00007ffff7fdc0d7 0x11115000 | ld-2.31.so!do_lookup_x+0xd7 (0x7ffff7fdc0d7)                 
    jne 0x1f9 
    ??_NearBranch64_?? [0f, 85, f3, 01, 00, 00]
ITERATION 239 0x00007ffff7fdc0dd 0x11115000 | ld-2.31.so!do_lookup_x+0xdd (0x7ffff7fdc0dd)                 
    add rbp, 0x1 
    RBP:0x0
    ??_Immediate8to64_?? [48, 83, c5, 01]
ITERATION 240 0x00007ffff7fdc0e1 0x11115000 | ld-2.31.so!do_lookup_x+0xe1 (0x7ffff7fdc0e1)                 
    cmp r11, rbp 
    R11:0x3
    RBP:0x1
    [49, 39, eb]
ITERATION 241 0x00007ffff7fdc0e4 0x11115000 | ld-2.31.so!do_lookup_x+0xe4 (0x7ffff7fdc0e4)                 
    jbe 0x2dc 
    ??_NearBranch64_?? [0f, 86, d6, 02, 00, 00]
ITERATION 242 0x00007ffff7fdc0ea 0x11115000 | ld-2.31.so!do_lookup_x+0xea (0x7ffff7fdc0ea)                 
    mov rax, qword ptr [r13+rbp*8] 
    RAX:0x0
    [R13:0x7ffff7fc4520+RBP:0x1*0x8=0x7ffff7fc4528size:UInt64->0x7ffff7fc4000]] 
    [49, 8b, 44, ed, 00]
ITERATION 243 0x00007ffff7fdc0ef 0x11115000 | ld-2.31.so!do_lookup_x+0xef (0x7ffff7fdc0ef)                 
    mov rbx, qword ptr [rax+0x28] 
    RBX:[34mld-2.31.so!_end+0x8 (0x7ffff7ffe180)[39m -> 0x555555554000 -> 'ELF'
    [RAX:0x7ffff7fc4000+0x28=0x7ffff7fc4028size:UInt64->0x7ffff7fc4000]] 
    [48, 8b, 58, 28]
ITERATION 244 0x00007ffff7fdc0f3 0x11115000 | ld-2.31.so!do_lookup_x+0xf3 (0x7ffff7fdc0f3)                 
    cmp rbx, r15 
    RBX:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0xaf8 (0x7ffff7fc4000)[39m -> 0x7ffff7dff000
    R15:0x0
    [4c, 39, fb]
ITERATION 245 0x00007ffff7fdc0f6 0x11115000 | ld-2.31.so!do_lookup_x+0xf6 (0x7ffff7fdc0f6)                 
    je 0xffffffffffffffe7 
    ??_NearBranch64_?? [74, e5]
ITERATION 246 0x00007ffff7fdc0f8 0x11115000 | ld-2.31.so!do_lookup_x+0xf8 (0x7ffff7fdc0f8)                 
    mov eax, r14d 
    EAX:0xf7fc4000
    R14D:0x1
    [44, 89, f0]
ITERATION 247 0x00007ffff7fdc0fb 0x11115000 | ld-2.31.so!do_lookup_x+0xfb (0x7ffff7fdc0fb)                 
    and eax, 0x2 
    EAX:0x1
    ??_Immediate8to32_?? [83, e0, 02]
ITERATION 248 0x00007ffff7fdc0fe 0x11115000 | ld-2.31.so!do_lookup_x+0xfe (0x7ffff7fdc0fe)                 
    mov dword ptr [rsp+0x8], eax 
    [RSP:0x7fffffffe730+0x8=0x7fffffffe738]] 
    EAX:0x0
    [89, 44, 24, 08]
ITERATION 249 0x00007ffff7fdc102 0x11115000 | ld-2.31.so!do_lookup_x+0x102 (0x7ffff7fdc102)                
    je 0xb 
    ??_NearBranch64_?? [74, 09]
ITERATION 250 0x00007ffff7fdc10d 0x11115000 | ld-2.31.so!do_lookup_x+0x10d (0x7ffff7fdc10d)                
    test byte ptr [rbx+0x31d], 0x20 
    [RBX:0x7ffff7fc4000+0x31d=0x7ffff7fc431dsize:UInt8->0x40]] 
    ??_Immediate8_?? [f6, 83, 1d, 03, 00, 00, 20]
ITERATION 251 0x00007ffff7fdc114 0x11115000 | ld-2.31.so!do_lookup_x+0x114 (0x7ffff7fdc114)                
    jne 0xffffffffffffffc9 
    ??_NearBranch64_?? [75, c7]
ITERATION 252 0x00007ffff7fdc116 0x11115000 | ld-2.31.so!do_lookup_x+0x116 (0x7ffff7fdc116)                
    test byte ptr [rip+0x204a3], 0x8 
    [RIP:0x7ffff7fdc116+0x204aa=0x7ffff7ffc5c0size:UInt8->0x0]] 
    ??_Immediate8_?? [f6, 05, a3, 04, 02, 00, 08]
ITERATION 253 0x00007ffff7fdc11d 0x11115000 | ld-2.31.so!do_lookup_x+0x11d (0x7ffff7fdc11d)                
    je 0xffffffffffffff43 
    ??_NearBranch64_?? [0f, 84, 3d, ff, ff, ff]
ITERATION 254 0x00007ffff7fdc060 0x11115000 | ld-2.31.so!do_lookup_x+0x60 (0x7ffff7fdc060)                 
    mov edx, dword ptr [rbx+0x2f4] 
    EDX:0x2
    [RBX:0x7ffff7fc4000+0x2f4=0x7ffff7fc42f4size:UInt32->0x3f3]] 
    [8b, 93, f4, 02, 00, 00]
ITERATION 255 0x00007ffff7fdc066 0x11115000 | ld-2.31.so!do_lookup_x+0x66 (0x7ffff7fdc066)                 
    test edx, edx 
    EDX:0x3f3
    EDX:0x3f3
    [85, d2]
ITERATION 256 0x00007ffff7fdc068 0x11115000 | ld-2.31.so!do_lookup_x+0x68 (0x7ffff7fdc068)                 
    je 0x75 
    ??_NearBranch64_?? [74, 73]
ITERATION 257 0x00007ffff7fdc06a 0x11115000 | ld-2.31.so!do_lookup_x+0x6a (0x7ffff7fdc06a)                 
    mov rax, qword ptr [rbx+0x70] 
    RAX:0x0
    [RBX:0x7ffff7fc4000+0x70=0x7ffff7fc4070size:UInt64->0x7ffff7fbcc00]] 
    [48, 8b, 43, 70]
ITERATION 258 0x00007ffff7fdc06e 0x11115000 | ld-2.31.so!do_lookup_x+0x6e (0x7ffff7fdc06e)                 
    mov dword ptr [rsp+0x74], 0x0 
    [RSP:0x7fffffffe730+0x74=0x7fffffffe7a4]] 
    ??_Immediate32_?? [c7, 44, 24, 74, 00, 00, 00, 00]
ITERATION 259 0x00007ffff7fdc076 0x11115000 | ld-2.31.so!do_lookup_x+0x76 (0x7ffff7fdc076)                 
    mov qword ptr [rsp+0x78], 0x0 
    [RSP:0x7fffffffe730+0x78=0x7fffffffe7a8]] 
    ??_Immediate32to64_?? [48, c7, 44, 24, 78, 00, 00, 00, 00]
ITERATION 260 0x00007ffff7fdc07f 0x11115000 | ld-2.31.so!do_lookup_x+0x7f (0x7ffff7fdc07f)                 
    mov rax, qword ptr [rax+0x8] 
    RAX:[34mlibc-2.31.so!_DYNAMIC+0x80 (0x7ffff7fbcc00)[39m -> ''
    [RAX:0x7ffff7fbcc00+0x8=0x7ffff7fbcc08size:UInt64->0x7ffff7e064d8]] 
    [48, 8b, 40, 08]
ITERATION 261 0x00007ffff7fdc083 0x11115000 | ld-2.31.so!do_lookup_x+0x83 (0x7ffff7fdc083)                 
    mov qword ptr [rsp+0x18], rax 
    [RSP:0x7fffffffe730+0x18=0x7fffffffe748]] 
    RAX:[34mlibc-2.31.so!catch_hook+0x7450 (0x7ffff7e064d8)[39m -> 0x0
    [48, 89, 44, 24, 18]
ITERATION 262 0x00007ffff7fdc088 0x11115000 | ld-2.31.so!do_lookup_x+0x88 (0x7ffff7fdc088)                 
    mov rax, qword ptr [rbx+0x68] 
    RAX:[34mlibc-2.31.so!catch_hook+0x7450 (0x7ffff7e064d8)[39m -> 0x0
    [RBX:0x7ffff7fc4000+0x68=0x7ffff7fc4068size:UInt64->0x7ffff7fbcbf0]] 
    [48, 8b, 43, 68]
ITERATION 263 0x00007ffff7fdc08c 0x11115000 | ld-2.31.so!do_lookup_x+0x8c (0x7ffff7fdc08c)                 
    mov rax, qword ptr [rax+0x8] 
    RAX:[34mlibc-2.31.so!_DYNAMIC+0x70 (0x7ffff7fbcbf0)[39m -> ''
    [RAX:0x7ffff7fbcbf0+0x8=0x7ffff7fbcbf8size:UInt64->0x7ffff7e14308]] 
    [48, 8b, 40, 08]
ITERATION 264 0x00007ffff7fdc090 0x11115000 | ld-2.31.so!do_lookup_x+0x90 (0x7ffff7fdc090)                 
    mov qword ptr [rsp+0x10], rax 
    [RSP:0x7fffffffe730+0x10=0x7fffffffe740]] 
    RAX:[34mlibc-2.31.so!catch_hook+0x15280 (0x7ffff7e14308)[39m -> 0x6c5f755f72647800
    [48, 89, 44, 24, 10]
ITERATION 265 0x00007ffff7fdc095 0x11115000 | ld-2.31.so!do_lookup_x+0x95 (0x7ffff7fdc095)                 
    mov rax, qword ptr [rbx+0x300] 
    RAX:[34mlibc-2.31.so!catch_hook+0x15280 (0x7ffff7e14308)[39m -> 0x6c5f755f72647800
    [RBX:0x7ffff7fc4000+0x300=0x7ffff7fc4300size:UInt64->0x7ffff7e02830]] 
    [48, 8b, 83, 00, 03, 00, 00]
ITERATION 266 0x00007ffff7fdc09c 0x11115000 | ld-2.31.so!do_lookup_x+0x9c (0x7ffff7fdc09c)                 
    test rax, rax 
    RAX:[34mlibc-2.31.so!catch_hook+0x37a8 (0x7ffff7e02830)[39m -> 0x10220a044103000
    RAX:[34mlibc-2.31.so!catch_hook+0x37a8 (0x7ffff7e02830)[39m -> 0x10220a044103000
    [48, 85, c0]
ITERATION 267 0x00007ffff7fdc09f 0x11115000 | ld-2.31.so!do_lookup_x+0x9f (0x7ffff7fdc09f)                 
    je 0xd9 
    ??_NearBranch64_?? [0f, 84, d3, 00, 00, 00]
ITERATION 268 0x00007ffff7fdc0a5 0x11115000 | ld-2.31.so!do_lookup_x+0xa5 (0x7ffff7fdc0a5)                 
    mov rdi, qword ptr [rsp+0x28] 
    RDI:0xff878ec2
    [RSP:0x7fffffffe730+0x28=0x7fffffffe758size:UInt64->0xff878ec2]] 
    [48, 8b, 7c, 24, 28]
ITERATION 269 0x00007ffff7fdc0aa 0x11115000 | ld-2.31.so!do_lookup_x+0xaa (0x7ffff7fdc0aa)                 
    mov ecx, dword ptr [rsp+0x30] 
    ECX:0xff878ec2
    [RSP:0x7fffffffe730+0x30=0x7fffffffe760size:UInt32->0x3fe1e3b]] 
    [8b, 4c, 24, 30]
ITERATION 270 0x00007ffff7fdc0ae 0x11115000 | ld-2.31.so!do_lookup_x+0xae (0x7ffff7fdc0ae)                 
    and ecx, dword ptr [rbx+0x2f8] 
    ECX:0x3fe1e3b
    [RBX:0x7ffff7fc4000+0x2f8=0x7ffff7fc42f8size:UInt32->0xff]] 
    [23, 8b, f8, 02, 00, 00]
ITERATION 271 0x00007ffff7fdc0b4 0x11115000 | ld-2.31.so!do_lookup_x+0xb4 (0x7ffff7fdc0b4)                 
    mov rax, qword ptr [rax+rcx*8] 
    RAX:[34mlibc-2.31.so!catch_hook+0x37a8 (0x7ffff7e02830)[39m -> 0x10220a044103000
    [RAX:0x7ffff7e02830+RCX:0x3b*0x8=0x7ffff7e02a08size:UInt64->0x7a467011c4b001a5]] 
    [48, 8b, 04, c8]
ITERATION 272 0x00007ffff7fdc0b8 0x11115000 | ld-2.31.so!do_lookup_x+0xb8 (0x7ffff7fdc0b8)                 
    mov ecx, dword ptr [rbx+0x2fc] 
    ECX:0x3b
    [RBX:0x7ffff7fc4000+0x2fc=0x7ffff7fc42fcsize:UInt32->0xe]] 
    [8b, 8b, fc, 02, 00, 00]
ITERATION 273 0x00007ffff7fdc0be 0x11115000 | ld-2.31.so!do_lookup_x+0xbe (0x7ffff7fdc0be)                 
    mov rsi, rdi 
    RSI:0x0
    RDI:0xff878ec2
    [48, 89, fe]
ITERATION 274 0x00007ffff7fdc0c1 0x11115000 | ld-2.31.so!do_lookup_x+0xc1 (0x7ffff7fdc0c1)                 
    shr rsi, cl 
    RSI:0xff878ec2
    CL:0xe
    [48, d3, ee]
ITERATION 275 0x00007ffff7fdc0c4 0x11115000 | ld-2.31.so!do_lookup_x+0xc4 (0x7ffff7fdc0c4)                 
    mov rcx, rsi 
    RCX:0xe
    RSI:0x3fe1e
    [48, 89, f1]
ITERATION 276 0x00007ffff7fdc0c7 0x11115000 | ld-2.31.so!do_lookup_x+0xc7 (0x7ffff7fdc0c7)                 
    mov rsi, rax 
    RSI:0x3fe1e
    RAX:0x7a467011c4b001a5
    [48, 89, c6]
ITERATION 277 0x00007ffff7fdc0ca 0x11115000 | ld-2.31.so!do_lookup_x+0xca (0x7ffff7fdc0ca)                 
    shr rsi, cl 
    RSI:0x7a467011c4b001a5
    CL:0x1e
    [48, d3, ee]
ITERATION 278 0x00007ffff7fdc0cd 0x11115000 | ld-2.31.so!do_lookup_x+0xcd (0x7ffff7fdc0cd)                 
    mov ecx, edi 
    ECX:0x3fe1e
    EDI:0xff878ec2
    [89, f9]
ITERATION 279 0x00007ffff7fdc0cf 0x11115000 | ld-2.31.so!do_lookup_x+0xcf (0x7ffff7fdc0cf)                 
    shr rax, cl 
    RAX:0x7a467011c4b001a5
    CL:0xc2
    [48, d3, e8]
ITERATION 280 0x00007ffff7fdc0d2 0x11115000 | ld-2.31.so!do_lookup_x+0xd2 (0x7ffff7fdc0d2)                 
    and rax, rsi 
    RAX:0x1e919c04712c0069
    RSI:0x1e919c047
    [48, 21, f0]
ITERATION 281 0x00007ffff7fdc0d5 0x11115000 | ld-2.31.so!do_lookup_x+0xd5 (0x7ffff7fdc0d5)                 
    test al, 0x1 
    AL:0x41
    ??_Immediate8_?? [a8, 01]
ITERATION 282 0x00007ffff7fdc0d7 0x11115000 | ld-2.31.so!do_lookup_x+0xd7 (0x7ffff7fdc0d7)                 
    jne 0x1f9 
    ??_NearBranch64_?? [0f, 85, f3, 01, 00, 00]
ITERATION 283 0x00007ffff7fdc2d0 0x11115000 | ld-2.31.so!do_lookup_x+0x2d0 (0x7ffff7fdc2d0)                
    mov ecx, edx 
    ECX:0xff878ec2
    EDX:0x3f3
    [89, d1]
ITERATION 284 0x00007ffff7fdc2d2 0x11115000 | ld-2.31.so!do_lookup_x+0x2d2 (0x7ffff7fdc2d2)                
    mov rax, rdi 
    RAX:0x61080041
    RDI:0xff878ec2
    [48, 89, f8]
ITERATION 285 0x00007ffff7fdc2d5 0x11115000 | ld-2.31.so!do_lookup_x+0x2d5 (0x7ffff7fdc2d5)                
    xor edx, edx 
    EDX:0x3f3
    EDX:0x3f3
    [31, d2]
ITERATION 286 0x00007ffff7fdc2d7 0x11115000 | ld-2.31.so!do_lookup_x+0x2d7 (0x7ffff7fdc2d7)                
    div rcx 
    RCX:0x3f3
    [48, f7, f1]
ITERATION 287 0x00007ffff7fdc2da 0x11115000 | ld-2.31.so!do_lookup_x+0x2da (0x7ffff7fdc2da)                
    mov rax, qword ptr [rbx+0x308] 
    RAX:0x40b42d
    [RBX:0x7ffff7fc4000+0x308=0x7ffff7fc4308size:UInt64->0x7ffff7e03030]] 
    [48, 8b, 83, 08, 03, 00, 00]
ITERATION 288 0x00007ffff7fdc2e1 0x11115000 | ld-2.31.so!do_lookup_x+0x2e1 (0x7ffff7fdc2e1)                
    mov eax, dword ptr [rax+rdx*4] 
    EAX:0xf7e03030
    [RAX:0x7ffff7e03030+RDX:0x10b*0x4=0x7ffff7e0345csize:UInt32->0x24a]] 
    [8b, 04, 90]
ITERATION 289 0x00007ffff7fdc2e4 0x11115000 | ld-2.31.so!do_lookup_x+0x2e4 (0x7ffff7fdc2e4)                
    test eax, eax 
    EAX:0x24a
    EAX:0x24a
    [85, c0]
ITERATION 290 0x00007ffff7fdc2e6 0x11115000 | ld-2.31.so!do_lookup_x+0x2e6 (0x7ffff7fdc2e6)                
    je 0xfffffffffffffdf7 
    ??_NearBranch64_?? [0f, 84, f1, fd, ff, ff]
ITERATION 291 0x00007ffff7fdc2ec 0x11115000 | ld-2.31.so!do_lookup_x+0x2ec (0x7ffff7fdc2ec)                
    mov rdx, qword ptr [rbx+0x310] 
    RDX:0x10b
    [RBX:0x7ffff7fc4000+0x310=0x7ffff7fc4310size:UInt64->0x7ffff7e03fcc]] 
    [48, 8b, 93, 10, 03, 00, 00]
ITERATION 292 0x00007ffff7fdc2f3 0x11115000 | ld-2.31.so!do_lookup_x+0x2f3 (0x7ffff7fdc2f3)                
    mov qword ptr [rsp+0x40], r13 
    [RSP:0x7fffffffe730+0x40=0x7fffffffe770]] 
    R13:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0x1018 (0x7ffff7fc4520)[39m -> [34mld-2.31.so!_end+0x8 (0x7ffff7ffe180)[39m ... 
    [4c, 89, 6c, 24, 40]
ITERATION 293 0x00007ffff7fdc2f8 0x11115000 | ld-2.31.so!do_lookup_x+0x2f8 (0x7ffff7fdc2f8)                
    mov qword ptr [rsp+0xc0], rbp 
    [RSP:0x7fffffffe730+0xc0=0x7fffffffe7f0]] 
    RBP:0x1
    [48, 89, ac, 24, c0, 00, 00, 00]
ITERATION 294 0x00007ffff7fdc300 0x11115000 | ld-2.31.so!do_lookup_x+0x300 (0x7ffff7fdc300)                
    mov r13, qword ptr [rsp+0x50] 
    R13:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0x1018 (0x7ffff7fc4520)[39m -> [34mld-2.31.so!_end+0x8 (0x7ffff7ffe180)[39m ... 
    [RSP:0x7fffffffe730+0x50=0x7fffffffe780size:UInt64->0x555555554360]] 
    [4c, 8b, 6c, 24, 50]
ITERATION 295 0x00007ffff7fdc305 0x11115000 | ld-2.31.so!do_lookup_x+0x305 (0x7ffff7fdc305)                
    mov ebp, r14d 
    EBP:0x1
    R14D:0x1
    [44, 89, f5]
ITERATION 296 0x00007ffff7fdc308 0x11115000 | ld-2.31.so!do_lookup_x+0x308 (0x7ffff7fdc308)                
    lea r12, [rdx+rax*4] 
    R12:0x3
    [RDX:0x7ffff7e03fcc+RAX:0x24a*0x4=0x7ffff7e048f4]] 
    [4c, 8d, 24, 82]
ITERATION 297 0x00007ffff7fdc30c 0x11115000 | ld-2.31.so!do_lookup_x+0x30c (0x7ffff7fdc30c)                
    lea rax, [rsp+0x74] 
    RAX:0x24a
    [RSP:0x7fffffffe730+0x74=0x7fffffffe7a4]] 
    [48, 8d, 44, 24, 74]
ITERATION 298 0x00007ffff7fdc311 0x11115000 | ld-2.31.so!do_lookup_x+0x311 (0x7ffff7fdc311)                
    mov qword ptr [rsp+0xd8], r15 
    [RSP:0x7fffffffe730+0xd8=0x7fffffffe808]] 
    R15:0x0
    [4c, 89, bc, 24, d8, 00, 00, 00]
ITERATION 299 0x00007ffff7fdc319 0x11115000 | ld-2.31.so!do_lookup_x+0x319 (0x7ffff7fdc319)                
    mov r14d, dword ptr [rsp+0xd0] 
    R14D:0x1
    [RSP:0x7fffffffe730+0xd0=0x7fffffffe800size:UInt32->0x1]] 
    [44, 8b, b4, 24, d0, 00, 00, 00]
ITERATION 300 0x00007ffff7fdc321 0x11115000 | ld-2.31.so!do_lookup_x+0x321 (0x7ffff7fdc321)                
    mov r15, rbx 
    R15:0x0
    RBX:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0xaf8 (0x7ffff7fc4000)[39m -> 0x7ffff7dff000
    [49, 89, df]
ITERATION 301 0x00007ffff7fdc324 0x11115000 | ld-2.31.so!do_lookup_x+0x324 (0x7ffff7fdc324)                
    mov qword ptr [rsp+0x38], rax 
    [RSP:0x7fffffffe730+0x38=0x7fffffffe768]] 
    RAX:0x7fffffffe7a4 -> 0x0
    [48, 89, 44, 24, 38]
ITERATION 302 0x00007ffff7fdc329 0x11115000 | ld-2.31.so!do_lookup_x+0x329 (0x7ffff7fdc329)                
    mov rbx, rdi 
    RBX:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0xaf8 (0x7ffff7fc4000)[39m -> 0x7ffff7dff000
    RDI:0xff878ec2
    [48, 89, fb]
ITERATION 303 0x00007ffff7fdc32c 0x11115000 | ld-2.31.so!do_lookup_x+0x32c (0x7ffff7fdc32c)                
    mov qword ptr [rsp+0x60], r11 
    [RSP:0x7fffffffe730+0x60=0x7fffffffe790]] 
    R11:0x3
    [4c, 89, 5c, 24, 60]
ITERATION 304 0x00007ffff7fdc331 0x11115000 | ld-2.31.so!do_lookup_x+0x331 (0x7ffff7fdc331)                
    jmp 0x14 
    ??_NearBranch64_?? [eb, 12]
ITERATION 305 0x00007ffff7fdc345 0x11115000 | ld-2.31.so!do_lookup_x+0x345 (0x7ffff7fdc345)                
    mov eax, dword ptr [r12] 
    EAX:0xffffe7a4
    [R12:0x7ffff7e048f4size:UInt32->0xaac080aa]] 
    [41, 8b, 04, 24]
ITERATION 306 0x00007ffff7fdc349 0x11115000 | ld-2.31.so!do_lookup_x+0x349 (0x7ffff7fdc349)                
    mov rdx, rax 
    RDX:[34mlibc-2.31.so!catch_hook+0x4f44 (0x7ffff7e03fcc)[39m -> '&	'
    RAX:0xaac080aa
    [48, 89, c2]
ITERATION 307 0x00007ffff7fdc34c 0x11115000 | ld-2.31.so!do_lookup_x+0x34c (0x7ffff7fdc34c)                
    xor rax, rbx 
    RAX:0xaac080aa
    RBX:0xff878ec2
    [48, 31, d8]
ITERATION 308 0x00007ffff7fdc34f 0x11115000 | ld-2.31.so!do_lookup_x+0x34f (0x7ffff7fdc34f)                
    shr rax, 0x1 
    RAX:0x55470e68
    ??_Immediate8_?? [48, d1, e8]
ITERATION 309 0x00007ffff7fdc352 0x11115000 | ld-2.31.so!do_lookup_x+0x352 (0x7ffff7fdc352)                
    jne 0xffffffffffffffe6 
    ??_NearBranch64_?? [75, e4]
ITERATION 310 0x00007ffff7fdc338 0x11115000 | ld-2.31.so!do_lookup_x+0x338 (0x7ffff7fdc338)                
    add r12, 0x4 
    R12:[34mlibc-2.31.so!catch_hook+0x586c (0x7ffff7e048f4)[39m -> 0xff878ec3aac080aa
    ??_Immediate8to64_?? [49, 83, c4, 04]
ITERATION 311 0x00007ffff7fdc33c 0x11115000 | ld-2.31.so!do_lookup_x+0x33c (0x7ffff7fdc33c)                
    and edx, 0x1 
    EDX:0xaac080aa
    ??_Immediate8to32_?? [83, e2, 01]
ITERATION 312 0x00007ffff7fdc33f 0x11115000 | ld-2.31.so!do_lookup_x+0x33f (0x7ffff7fdc33f)                
    jne 0x5f8 
    ??_NearBranch64_?? [0f, 85, f2, 05, 00, 00]
ITERATION 313 0x00007ffff7fdc345 0x11115000 | ld-2.31.so!do_lookup_x+0x345 (0x7ffff7fdc345)                
    mov eax, dword ptr [r12] 
    EAX:0x2aa38734
    [R12:0x7ffff7e048f8size:UInt32->0xff878ec3]] 
    [41, 8b, 04, 24]
ITERATION 314 0x00007ffff7fdc349 0x11115000 | ld-2.31.so!do_lookup_x+0x349 (0x7ffff7fdc349)                
    mov rdx, rax 
    RDX:0x0
    RAX:0xff878ec3
    [48, 89, c2]
ITERATION 315 0x00007ffff7fdc34c 0x11115000 | ld-2.31.so!do_lookup_x+0x34c (0x7ffff7fdc34c)                
    xor rax, rbx 
    RAX:0xff878ec3
    RBX:0xff878ec2
    [48, 31, d8]
ITERATION 316 0x00007ffff7fdc34f 0x11115000 | ld-2.31.so!do_lookup_x+0x34f (0x7ffff7fdc34f)                
    shr rax, 0x1 
    RAX:0x1
    ??_Immediate8_?? [48, d1, e8]
ITERATION 317 0x00007ffff7fdc352 0x11115000 | ld-2.31.so!do_lookup_x+0x352 (0x7ffff7fdc352)                
    jne 0xffffffffffffffe6 
    ??_NearBranch64_?? [75, e4]
ITERATION 318 0x00007ffff7fdc354 0x11115000 | ld-2.31.so!do_lookup_x+0x354 (0x7ffff7fdc354)                
    sub rsp, 0x8 
    RSP:0x7fffffffe730 -> 0xffffffff
    ??_Immediate8to64_?? [48, 83, ec, 08]
ITERATION 319 0x00007ffff7fdc358 0x11115000 | ld-2.31.so!do_lookup_x+0x358 (0x7ffff7fdc358)                
    mov rax, r12 
    RAX:0x0
    R12:[34mlibc-2.31.so!catch_hook+0x5870 (0x7ffff7e048f8)[39m -> 0x78e4792dff878ec3
    [4c, 89, e0]
ITERATION 320 0x00007ffff7fdc35b 0x11115000 | ld-2.31.so!do_lookup_x+0x35b (0x7ffff7fdc35b)                
    mov r8d, ebp 
    R8D:0xffffe870
    EBP:0x1
    [41, 89, e8]
ITERATION 321 0x00007ffff7fdc35e 0x11115000 | ld-2.31.so!do_lookup_x+0x35e (0x7ffff7fdc35e)                
    mov rsi, r13 
    RSI:0x1e919c047
    R13:0x555555554360 -> ''
    [4c, 89, ee]
ITERATION 322 0x00007ffff7fdc361 0x11115000 | ld-2.31.so!do_lookup_x+0x361 (0x7ffff7fdc361)                
    sub rax, qword ptr [r15+0x310] 
    RAX:[34mlibc-2.31.so!catch_hook+0x5870 (0x7ffff7e048f8)[39m -> 0x78e4792dff878ec3
    [R15:0x7ffff7fc4000+0x310=0x7ffff7fc4310size:UInt64->0x7ffff7e03fcc]] 
    [49, 2b, 87, 10, 03, 00, 00]
ITERATION 323 0x00007ffff7fdc368 0x11115000 | ld-2.31.so!do_lookup_x+0x368 (0x7ffff7fdc368)                
    push qword ptr [rsp+0x40] 
    [RSP:0x7fffffffe728+0x40=0x7fffffffe768size:UInt64->0x7fffffffe7a4]] 
    [ff, 74, 24, 40]
ITERATION 324 0x00007ffff7fdc36c 0x11115000 | ld-2.31.so!do_lookup_x+0x36c (0x7ffff7fdc36c)                
    sar rax, 0x2 
    RAX:0x92c
    ??_Immediate8_?? [48, c1, f8, 02]
ITERATION 325 0x00007ffff7fdc370 0x11115000 | ld-2.31.so!do_lookup_x+0x370 (0x7ffff7fdc370)                
    mov edx, eax 
    EDX:0xff878ec3
    EAX:0x24b
    [89, c2]
ITERATION 326 0x00007ffff7fdc372 0x11115000 | ld-2.31.so!do_lookup_x+0x372 (0x7ffff7fdc372)                
    lea rcx, [rsp+0x88] 
    RCX:0x3f3
    [RSP:0x7fffffffe720+0x88=0x7fffffffe7a8]] 
    [48, 8d, 8c, 24, 88, 00, 00, 00]
ITERATION 327 0x00007ffff7fdc37a 0x11115000 | ld-2.31.so!do_lookup_x+0x37a (0x7ffff7fdc37a)                
    lea rdx, [rdx+rdx*2] 
    RDX:0x24b
    [RDX:0x24b+RDX:0x24b*0x2=0x6e1]] 
    [48, 8d, 14, 52]
ITERATION 328 0x00007ffff7fdc37e 0x11115000 | ld-2.31.so!do_lookup_x+0x37e (0x7ffff7fdc37e)                
    push rcx 
    RCX:0x7fffffffe7a8 -> 0x0
    [51]
ITERATION 329 0x00007ffff7fdc37f 0x11115000 | ld-2.31.so!do_lookup_x+0x37f (0x7ffff7fdc37f)                
    mov ecx, r14d 
    ECX:0xffffe7a8
    R14D:0x1
    [44, 89, f1]
ITERATION 330 0x00007ffff7fdc382 0x11115000 | ld-2.31.so!do_lookup_x+0x382 (0x7ffff7fdc382)                
    push r15 
    R15:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0xaf8 (0x7ffff7fc4000)[39m -> 0x7ffff7dff000
    [41, 57]
ITERATION 331 0x00007ffff7fdc384 0x11115000 | ld-2.31.so!do_lookup_x+0x384 (0x7ffff7fdc384)                
    push qword ptr [rsp+0x30] 
    [RSP:0x7fffffffe710+0x30=0x7fffffffe740size:UInt64->0x7ffff7e14308]] 
    [ff, 74, 24, 30]
ITERATION 332 0x00007ffff7fdc388 0x11115000 | ld-2.31.so!do_lookup_x+0x388 (0x7ffff7fdc388)                
    push rax 
    RAX:0x24b
    [50]
ITERATION 333 0x00007ffff7fdc389 0x11115000 | ld-2.31.so!do_lookup_x+0x389 (0x7ffff7fdc389)                
    mov rax, qword ptr [rsp+0x48] 
    RAX:0x24b
    [RSP:0x7fffffffe700+0x48=0x7fffffffe748size:UInt64->0x7ffff7e064d8]] 
    [48, 8b, 44, 24, 48]
ITERATION 334 0x00007ffff7fdc38e 0x11115000 | ld-2.31.so!do_lookup_x+0x38e (0x7ffff7fdc38e)                
    mov rdi, qword ptr [rsp+0x50] 
    RDI:0xff878ec2
    [RSP:0x7fffffffe700+0x50=0x7fffffffe750size:UInt64->0x5555555543d9]] 
    [48, 8b, 7c, 24, 50]
ITERATION 335 0x00007ffff7fdc393 0x11115000 | ld-2.31.so!do_lookup_x+0x393 (0x7ffff7fdc393)                
    lea r9, [rax+rdx*8] 
    R9:[34mld-2.31.so!_end+0x2c8 (0x7ffff7ffe440)[39m ... 
    [RAX:0x7ffff7e064d8+RDX:0x6e1*0x8=0x7ffff7e09be0]] 
    [4c, 8d, 0c, d0]
ITERATION 336 0x00007ffff7fdc397 0x11115000 | ld-2.31.so!do_lookup_x+0x397 (0x7ffff7fdc397)                
    mov rdx, qword ptr [rsp+0xf8] 
    RDX:0x6e1
    [RSP:0x7fffffffe700+0xf8=0x7fffffffe7f8size:UInt64->0x7ffff7fc4570]] 
    [48, 8b, 94, 24, f8, 00, 00, 00]
ITERATION 337 0x00007ffff7fdc39f 0x11115000 | ld-2.31.so!do_lookup_x+0x39f (0x7ffff7fdc39f)                
    call 0xfffffffffffffad1 
    ??_NearBranch64_?? [e8, cc, fa, ff, ff]
ITERATION 338 0x00007ffff7fdbe70 0x11115000 | ld-2.31.so!check_match+0x0 (0x7ffff7fdbe70)                  
    push r14 
    R14:0x1
    [41, 56]
ITERATION 339 0x00007ffff7fdbe72 0x11115000 | ld-2.31.so!check_match+0x2 (0x7ffff7fdbe72)                  
    mov r10, rdi 
    R10:[34mld-2.31.so!_end+0x8 (0x7ffff7ffe180)[39m -> 0x555555554000 -> 'ELF'
    RDI:0x5555555543d9 -> 'getpid'
    [49, 89, fa]
ITERATION 340 0x00007ffff7fdbe75 0x11115000 | ld-2.31.so!check_match+0x5 (0x7ffff7fdbe75)                  
    push r13 
    R13:0x555555554360 -> ''
    [41, 55]
ITERATION 341 0x00007ffff7fdbe77 0x11115000 | ld-2.31.so!check_match+0x7 (0x7ffff7fdbe77)                  
    mov r13, rdx 
    R13:0x555555554360 -> ''
    RDX:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0x1068 (0x7ffff7fc4570)[39m -> 0x55555555440b -> 'GLIBC_2.2.5'
    [49, 89, d5]
ITERATION 342 0x00007ffff7fdbe7a 0x11115000 | ld-2.31.so!check_match+0xa (0x7ffff7fdbe7a)                  
    movzx edx, word ptr [r9+0x6] 
    EDX:0xf7fc4570
    [R9:0x7ffff7e09be0+0x6=0x7ffff7e09be6size:UInt16->0xe]] 
    [41, 0f, b7, 51, 06]
ITERATION 343 0x00007ffff7fdbe7f 0x11115000 | ld-2.31.so!check_match+0xf (0x7ffff7fdbe7f)                  
    push r12 
    R12:[34mlibc-2.31.so!catch_hook+0x5870 (0x7ffff7e048f8)[39m -> 0x78e4792dff878ec3
    [41, 54]
ITERATION 344 0x00007ffff7fdbe81 0x11115000 | ld-2.31.so!check_match+0x11 (0x7ffff7fdbe81)                 
    push rbp 
    RBP:0x1
    [55]
ITERATION 345 0x00007ffff7fdbe82 0x11115000 | ld-2.31.so!check_match+0x12 (0x7ffff7fdbe82)                 
    mov ebp, ecx 
    EBP:0x1
    ECX:0x1
    [89, cd]
ITERATION 346 0x00007ffff7fdbe84 0x11115000 | ld-2.31.so!check_match+0x14 (0x7ffff7fdbe84)                 
    movzx ecx, byte ptr [r9+0x4] 
    ECX:0x1
    [R9:0x7ffff7e09be0+0x4=0x7ffff7e09be4size:UInt8->0x22::"]] 
    [41, 0f, b6, 49, 04]
ITERATION 347 0x00007ffff7fdbe89 0x11115000 | ld-2.31.so!check_match+0x19 (0x7ffff7fdbe89)                 
    push rbx 
    RBX:0xff878ec2
    [53]
ITERATION 348 0x00007ffff7fdbe8a 0x11115000 | ld-2.31.so!check_match+0x1a (0x7ffff7fdbe8a)                 
    mov rbx, r9 
    RBX:0xff878ec2
    R9:[34mlibc-2.31.so!catch_hook+0xab58 (0x7ffff7e09be0)[39m -> 0xe0022000058d7
    [4c, 89, cb]
ITERATION 349 0x00007ffff7fdbe8d 0x11115000 | ld-2.31.so!check_match+0x1d (0x7ffff7fdbe8d)                 
    mov r12, qword ptr [rsp+0x40] 
    R12:[34mlibc-2.31.so!catch_hook+0x5870 (0x7ffff7e048f8)[39m -> 0x78e4792dff878ec3
    [RSP:0x7fffffffe6d0+0x40=0x7fffffffe710size:UInt64->0x7ffff7fc4000]] 
    [4c, 8b, 64, 24, 40]
ITERATION 350 0x00007ffff7fdbe92 0x11115000 | ld-2.31.so!check_match+0x22 (0x7ffff7fdbe92)                 
    and ecx, 0xf 
    ECX:0x22
    ??_Immediate8to32_?? [83, e1, 0f]
ITERATION 351 0x00007ffff7fdbe95 0x11115000 | ld-2.31.so!check_match+0x25 (0x7ffff7fdbe95)                 
    cmp qword ptr [r9+0x8], 0x0 
    [R9:0x7ffff7e09be0+0x8=0x7ffff7e09be8size:UInt64->0xcc0d0]] 
    ??_Immediate8to64_?? [49, 83, 79, 08, 00]
ITERATION 352 0x00007ffff7fdbe9a 0x11115000 | ld-2.31.so!check_match+0x2a (0x7ffff7fdbe9a)                 
    je 0x10e 
    ??_NearBranch64_?? [0f, 84, 08, 01, 00, 00]
ITERATION 353 0x00007ffff7fdbea0 0x11115000 | ld-2.31.so!check_match+0x30 (0x7ffff7fdbea0)                 
    mov eax, 0x467 
    EAX:0xf7e064d8
    ??_Immediate32_?? [b8, 67, 04, 00, 00]
ITERATION 354 0x00007ffff7fdbea5 0x11115000 | ld-2.31.so!check_match+0x35 (0x7ffff7fdbea5)                 
    sar eax, cl 
    EAX:0x467
    CL:0x2
    [d3, f8]
ITERATION 355 0x00007ffff7fdbea7 0x11115000 | ld-2.31.so!check_match+0x37 (0x7ffff7fdbea7)                 
    not eax 
    EAX:0x119
    [f7, d0]
ITERATION 356 0x00007ffff7fdbea9 0x11115000 | ld-2.31.so!check_match+0x39 (0x7ffff7fdbea9)                 
    and eax, 0x1 
    EAX:0xfffffee6
    ??_Immediate8to32_?? [83, e0, 01]
ITERATION 357 0x00007ffff7fdbeac 0x11115000 | ld-2.31.so!check_match+0x3c (0x7ffff7fdbeac)                 
    test dx, dx 
    DX:0xe
    DX:0xe
    [66, 85, d2]
ITERATION 358 0x00007ffff7fdbeaf 0x11115000 | ld-2.31.so!check_match+0x3f (0x7ffff7fdbeaf)                 
    sete dl 
    DL:0xe
    [0f, 94, c2]
ITERATION 359 0x00007ffff7fdbeb2 0x11115000 | ld-2.31.so!check_match+0x42 (0x7ffff7fdbeb2)                 
    movzx edx, dl 
    EDX:0x0
    DL:0x0
    [0f, b6, d2]
ITERATION 360 0x00007ffff7fdbeb5 0x11115000 | ld-2.31.so!check_match+0x45 (0x7ffff7fdbeb5)                 
    and r8d, edx 
    R8D:0x1
    EDX:0x0
    [41, 21, d0]
ITERATION 361 0x00007ffff7fdbeb8 0x11115000 | ld-2.31.so!check_match+0x48 (0x7ffff7fdbeb8)                 
    or eax, r8d 
    EAX:0x0
    R8D:0x0
    [44, 09, c0]
ITERATION 362 0x00007ffff7fdbebb 0x11115000 | ld-2.31.so!check_match+0x4b (0x7ffff7fdbebb)                 
    jne 0xc5 
    ??_NearBranch64_?? [0f, 85, bf, 00, 00, 00]
ITERATION 363 0x00007ffff7fdbec1 0x11115000 | ld-2.31.so!check_match+0x51 (0x7ffff7fdbec1)                 
    cmp rbx, rsi 
    RBX:[34mlibc-2.31.so!catch_hook+0xab58 (0x7ffff7e09be0)[39m -> 0xe0022000058d7
    RSI:0x555555554360 -> ''
    [48, 39, f3]
ITERATION 364 0x00007ffff7fdbec4 0x11115000 | ld-2.31.so!check_match+0x54 (0x7ffff7fdbec4)                 
    je 0x19 
    ??_NearBranch64_?? [74, 17]
ITERATION 365 0x00007ffff7fdbec6 0x11115000 | ld-2.31.so!check_match+0x56 (0x7ffff7fdbec6)                 
    mov edi, dword ptr [rbx] 
    EDI:0x555543d9
    [RBX:0x7ffff7e09be0size:UInt32->0x58d7]] 
    [8b, 3b]
ITERATION 366 0x00007ffff7fdbec8 0x11115000 | ld-2.31.so!check_match+0x58 (0x7ffff7fdbec8)                 
    mov rsi, r10 
    RSI:0x555555554360 -> ''
    R10:0x5555555543d9 -> 'getpid'
    [4c, 89, d6]
ITERATION 367 0x00007ffff7fdbecb 0x11115000 | ld-2.31.so!check_match+0x5b (0x7ffff7fdbecb)                 
    add rdi, qword ptr [rsp+0x38] 
    RDI:0x58d7
    [RSP:0x7fffffffe6d0+0x38=0x7fffffffe708size:UInt64->0x7ffff7e14308]] 
    [48, 03, 7c, 24, 38]
ITERATION 368 0x00007ffff7fdbed0 0x11115000 | ld-2.31.so!check_match+0x60 (0x7ffff7fdbed0)                 
    call 0x122c0 
    ??_NearBranch64_?? [e8, bb, 22, 01, 00]
ITERATION 369 0x00007ffff7fee190 0x11115000 | ld-2.31.so!strcmp+0x0 (0x7ffff7fee190)                       
    mov ecx, esi 
    ECX:0x2
    ESI:0x555543d9
    [89, f1]
ITERATION 370 0x00007ffff7fee192 0x11115000 | ld-2.31.so!strcmp+0x2 (0x7ffff7fee192)                       
    mov eax, edi 
    EAX:0x0
    EDI:0xf7e19bdf
    [89, f8]
ITERATION 371 0x00007ffff7fee194 0x11115000 | ld-2.31.so!strcmp+0x4 (0x7ffff7fee194)                       
    and rcx, 0x3f 
    RCX:0x555543d9
    ??_Immediate8to64_?? [48, 83, e1, 3f]
ITERATION 372 0x00007ffff7fee198 0x11115000 | ld-2.31.so!strcmp+0x8 (0x7ffff7fee198)                       
    and rax, 0x3f 
    RAX:0xf7e19bdf
    ??_Immediate8to64_?? [48, 83, e0, 3f]
ITERATION 373 0x00007ffff7fee19c 0x11115000 | ld-2.31.so!strcmp+0xc (0x7ffff7fee19c)                       
    cmp ecx, 0x30 
    ECX:0x19
    ??_Immediate8to32_?? [83, f9, 30]
ITERATION 374 0x00007ffff7fee19f 0x11115000 | ld-2.31.so!strcmp+0xf (0x7ffff7fee19f)                       
    ja 0x41 
    ??_NearBranch64_?? [77, 3f]
ITERATION 375 0x00007ffff7fee1a1 0x11115000 | ld-2.31.so!strcmp+0x11 (0x7ffff7fee1a1)                      
    cmp eax, 0x30 
    EAX:0x1f
    ??_Immediate8to32_?? [83, f8, 30]
ITERATION 376 0x00007ffff7fee1a4 0x11115000 | ld-2.31.so!strcmp+0x14 (0x7ffff7fee1a4)                      
    ja 0x3c 
    ??_NearBranch64_?? [77, 3a]
ITERATION 377 0x00007ffff7fee1a6 0x11115000 | ld-2.31.so!strcmp+0x16 (0x7ffff7fee1a6)                      
    movlpd xmm1, qword ptr [rdi] 
    XMM1:0x2f2f2f2f2f2f2f2f
    [RDI:0x7ffff7e19bdfsize:Float64->0xffffffffffffffffffffffffffffffff]] 
    [66, 0f, 12, 0f]
ITERATION 378 0x00007ffff7fee1aa 0x11115000 | ld-2.31.so!strcmp+0x1a (0x7ffff7fee1aa)                      
    movlpd xmm2, qword ptr [rsi] 
    XMM2:0x0
    [RSI:0x5555555543d9size:Float64->0xffffffffffffffffffffffffffffffff]] 
    [66, 0f, 12, 16]
ITERATION 379 0x00007ffff7fee1ae 0x11115000 | ld-2.31.so!strcmp+0x1e (0x7ffff7fee1ae)                      
    movhpd xmm1, qword ptr [rdi+0x8] 
    XMM1:0x5f00646970746567
    [RDI:0x7ffff7e19bdf+0x8=0x7ffff7e19be7size:Float64->0xffffffffffffffffffffffffffffffff]] 
    [66, 0f, 16, 4f, 08]
ITERATION 380 0x00007ffff7fee1b3 0x11115000 | ld-2.31.so!strcmp+0x23 (0x7ffff7fee1b3)                      
    movhpd xmm2, qword ptr [rsi+0x8] 
    XMM2:0x5f00646970746567
    [RSI:0x5555555543d9+0x8=0x5555555543e1size:Float64->0xffffffffffffffffffffffffffffffff]] 
    [66, 0f, 16, 56, 08]
ITERATION 381 0x00007ffff7fee1b8 0x11115000 | ld-2.31.so!strcmp+0x28 (0x7ffff7fee1b8)                      
    pxor xmm0, xmm0 
    XMM0:0x0
    XMM0:0x0
    [66, 0f, ef, c0]
ITERATION 382 0x00007ffff7fee1bc 0x11115000 | ld-2.31.so!strcmp+0x2c (0x7ffff7fee1bc)                      
    pcmpeqb xmm0, xmm1 
    XMM0:0x0
    XMM1:0x5f00646970746567
    [66, 0f, 74, c1]
ITERATION 383 0x00007ffff7fee1c0 0x11115000 | ld-2.31.so!strcmp+0x30 (0x7ffff7fee1c0)                      
    pcmpeqb xmm1, xmm2 
    XMM1:0x5f00646970746567
    XMM2:0x5f00646970746567
    [66, 0f, 74, ca]
ITERATION 384 0x00007ffff7fee1c4 0x11115000 | ld-2.31.so!strcmp+0x34 (0x7ffff7fee1c4)                      
    psubb xmm1, xmm0 
    XMM1:0xffffffffffffffff
    XMM0:0xff000000000000
    [66, 0f, f8, c8]
ITERATION 385 0x00007ffff7fee1c8 0x11115000 | ld-2.31.so!strcmp+0x38 (0x7ffff7fee1c8)                      
    pmovmskb edx, xmm1 
    EDX:0x0
    XMM1:0xff00ffffffffffff
    [66, 0f, d7, d1]
ITERATION 386 0x00007ffff7fee1cc 0x11115000 | ld-2.31.so!strcmp+0x3c (0x7ffff7fee1cc)                      
    sub edx, 0xffff 
    EDX:0x1bf
    ??_Immediate32_?? [81, ea, ff, ff, 00, 00]
ITERATION 387 0x00007ffff7fee1d2 0x11115000 | ld-2.31.so!strcmp+0x42 (0x7ffff7fee1d2)                      
    jne 0x13ce 
    ??_NearBranch64_?? [0f, 85, c8, 13, 00, 00]
ITERATION 388 0x00007ffff7fef5a0 0x11115000 | ld-2.31.so!strcmp+0x1410 (0x7ffff7fef5a0)                    
    bsf rdx, rdx 
    RDX:0xffff01c0
    RDX:0xffff01c0
    [48, 0f, bc, d2]
ITERATION 389 0x00007ffff7fef5a4 0x11115000 | ld-2.31.so!strcmp+0x1414 (0x7ffff7fef5a4)                    
    movzx ecx, byte ptr [rsi+rdx] 
    ECX:0x19
    [RSI:0x5555555543d9+RDX:0x6=0x5555555543dfsize:UInt8->0x0]] 
    [0f, b6, 0c, 16]
ITERATION 390 0x00007ffff7fef5a8 0x11115000 | ld-2.31.so!strcmp+0x1418 (0x7ffff7fef5a8)                    
    movzx eax, byte ptr [rdi+rdx] 
    EAX:0x1f
    [RDI:0x7ffff7e19bdf+RDX:0x6=0x7ffff7e19be5size:UInt8->0x0]] 
    [0f, b6, 04, 17]
ITERATION 391 0x00007ffff7fef5ac 0x11115000 | ld-2.31.so!strcmp+0x141c (0x7ffff7fef5ac)                    
    sub eax, ecx 
    EAX:0x0
    ECX:0x0
    [29, c8]
ITERATION 392 0x00007ffff7fef5ae 0x11115000 | ld-2.31.so!strcmp+0x141e (0x7ffff7fef5ae)                    
    ret 
    [c3]
ITERATION 393 0x00007ffff7fdbed5 0x11115000 | ld-2.31.so!check_match+0x65 (0x7ffff7fdbed5)                 
    test eax, eax 
    EAX:0x0
    EAX:0x0
    [85, c0]
ITERATION 394 0x00007ffff7fdbed7 0x11115000 | ld-2.31.so!check_match+0x67 (0x7ffff7fdbed7)                 
    jne 0xa9 
    ??_NearBranch64_?? [0f, 85, a3, 00, 00, 00]
ITERATION 395 0x00007ffff7fdbedd 0x11115000 | ld-2.31.so!check_match+0x6d (0x7ffff7fdbedd)                 
    mov rax, qword ptr [r12+0x340] 
    RAX:0x0
    [R12:0x7ffff7fc4000+0x340=0x7ffff7fc4340size:UInt64->0x7ffff7e1a3ca]] 
    [49, 8b, 84, 24, 40, 03, 00, 00]
ITERATION 396 0x00007ffff7fdbee5 0x11115000 | ld-2.31.so!check_match+0x75 (0x7ffff7fdbee5)                 
    test r13, r13 
    R13:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0x1068 (0x7ffff7fc4570)[39m -> 0x55555555440b -> 'GLIBC_2.2.5'
    R13:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0x1068 (0x7ffff7fc4570)[39m -> 0x55555555440b -> 'GLIBC_2.2.5'
    [4d, 85, ed]
ITERATION 397 0x00007ffff7fdbee8 0x11115000 | ld-2.31.so!check_match+0x78 (0x7ffff7fdbee8)                 
    je 0x50 
    ??_NearBranch64_?? [74, 4e]
ITERATION 398 0x00007ffff7fdbeea 0x11115000 | ld-2.31.so!check_match+0x7a (0x7ffff7fdbeea)                 
    test rax, rax 
    RAX:[34mlibc-2.31.so!catch_hook+0x1b342 (0x7ffff7e1a3ca)[39m -> 0x21002100000000
    RAX:[34mlibc-2.31.so!catch_hook+0x1b342 (0x7ffff7e1a3ca)[39m -> 0x21002100000000
    [48, 85, c0]
ITERATION 399 0x00007ffff7fdbeed 0x11115000 | ld-2.31.so!check_match+0x7d (0x7ffff7fdbeed)                 
    je 0xd3 
    ??_NearBranch64_?? [0f, 84, cd, 00, 00, 00]
ITERATION 400 0x00007ffff7fdbef3 0x11115000 | ld-2.31.so!check_match+0x83 (0x7ffff7fdbef3)                 
    mov edx, dword ptr [rsp+0x30] 
    EDX:0x6
    [RSP:0x7fffffffe6d0+0x30=0x7fffffffe700size:UInt32->0x24b]] 
    [8b, 54, 24, 30]
ITERATION 401 0x00007ffff7fdbef7 0x11115000 | ld-2.31.so!check_match+0x87 (0x7ffff7fdbef7)                 
    movzx r14d, word ptr [rax+rdx*2] 
    R14D:0x1
    [RAX:0x7ffff7e1a3ca+RDX:0x24b*0x2=0x7ffff7e1a860size:UInt16->0x2]] 
    [44, 0f, b7, 34, 50]
ITERATION 402 0x00007ffff7fdbefc 0x11115000 | ld-2.31.so!check_match+0x8c (0x7ffff7fdbefc)                 
    mov rax, r14 
    RAX:[34mlibc-2.31.so!catch_hook+0x1b342 (0x7ffff7e1a3ca)[39m -> 0x21002100000000
    R14:0x2
    [4c, 89, f0]
ITERATION 403 0x00007ffff7fdbeff 0x11115000 | ld-2.31.so!check_match+0x8f (0x7ffff7fdbeff)                 
    and eax, 0x7fff 
    EAX:0x2
    ??_Immediate32_?? [25, ff, 7f, 00, 00]
ITERATION 404 0x00007ffff7fdbf04 0x11115000 | ld-2.31.so!check_match+0x94 (0x7ffff7fdbf04)                 
    lea rdx, [rax+rax*2] 
    RDX:0x24b
    [RAX:0x2+RAX:0x2*0x2=0x6]] 
    [48, 8d, 14, 40]
ITERATION 405 0x00007ffff7fdbf08 0x11115000 | ld-2.31.so!check_match+0x98 (0x7ffff7fdbf08)                 
    mov rax, qword ptr [r12+0x2e8] 
    RAX:0x2
    [R12:0x7ffff7fc4000+0x2e8=0x7ffff7fc42e8size:UInt64->0x7ffff7fc45e0]] 
    [49, 8b, 84, 24, e8, 02, 00, 00]
ITERATION 406 0x00007ffff7fdbf10 0x11115000 | ld-2.31.so!check_match+0xa0 (0x7ffff7fdbf10)                 
    lea rax, [rax+rdx*8] 
    RAX:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0x10d8 (0x7ffff7fc45e0)[39m -> 0x0
    [RAX:0x7ffff7fc45e0+RDX:0x6*0x8=0x7ffff7fc4610]] 
    [48, 8d, 04, d0]
ITERATION 407 0x00007ffff7fdbf14 0x11115000 | ld-2.31.so!check_match+0xa4 (0x7ffff7fdbf14)                 
    mov ebp, dword ptr [rax+0x8] 
    EBP:0x1
    [RAX:0x7ffff7fc4610+0x8=0x7ffff7fc4618size:UInt32->0x9691a75]] 
    [8b, 68, 08]
ITERATION 408 0x00007ffff7fdbf17 0x11115000 | ld-2.31.so!check_match+0xa7 (0x7ffff7fdbf17)                 
    cmp ebp, dword ptr [r13+0x8] 
    EBP:0x9691a75
    [R13:0x7ffff7fc4570+0x8=0x7ffff7fc4578size:UInt32->0x9691a75]] 
    [41, 3b, 6d, 08]
ITERATION 409 0x00007ffff7fdbf1b 0x11115000 | ld-2.31.so!check_match+0xab (0x7ffff7fdbf1b)                 
    je 0x75 
    ??_NearBranch64_?? [74, 73]
ITERATION 410 0x00007ffff7fdbf90 0x11115000 | ld-2.31.so!check_match+0x120 (0x7ffff7fdbf90)                
    mov rsi, qword ptr [r13] 
    RSI:0x5555555543d9 -> 'getpid'
    [R13:0x7ffff7fc4570size:UInt64->0x55555555440b]] 
    [49, 8b, 75, 00]
ITERATION 411 0x00007ffff7fdbf94 0x11115000 | ld-2.31.so!check_match+0x124 (0x7ffff7fdbf94)                
    mov rdi, qword ptr [rax] 
    RDI:[34mlibc-2.31.so!catch_hook+0x1ab57 (0x7ffff7e19bdf)[39m -> 'getpid'
    [RAX:0x7ffff7fc4610size:UInt64->0x7ffff7e1a273]] 
    [48, 8b, 38]
ITERATION 412 0x00007ffff7fdbf97 0x11115000 | ld-2.31.so!check_match+0x127 (0x7ffff7fdbf97)                
    call 0x121f9 
    ??_NearBranch64_?? [e8, f4, 21, 01, 00]
ITERATION 413 0x00007ffff7fee190 0x11115000 | ld-2.31.so!strcmp+0x0 (0x7ffff7fee190)                       
    mov ecx, esi 
    ECX:0x0
    ESI:0x5555440b
    [89, f1]
ITERATION 414 0x00007ffff7fee192 0x11115000 | ld-2.31.so!strcmp+0x2 (0x7ffff7fee192)                       
    mov eax, edi 
    EAX:0xf7fc4610
    EDI:0xf7e1a273
    [89, f8]
ITERATION 415 0x00007ffff7fee194 0x11115000 | ld-2.31.so!strcmp+0x4 (0x7ffff7fee194)                       
    and rcx, 0x3f 
    RCX:0x5555440b
    ??_Immediate8to64_?? [48, 83, e1, 3f]
ITERATION 416 0x00007ffff7fee198 0x11115000 | ld-2.31.so!strcmp+0x8 (0x7ffff7fee198)                       
    and rax, 0x3f 
    RAX:0xf7e1a273
    ??_Immediate8to64_?? [48, 83, e0, 3f]
ITERATION 417 0x00007ffff7fee19c 0x11115000 | ld-2.31.so!strcmp+0xc (0x7ffff7fee19c)                       
    cmp ecx, 0x30 
    ECX:0xb
    ??_Immediate8to32_?? [83, f9, 30]
ITERATION 418 0x00007ffff7fee19f 0x11115000 | ld-2.31.so!strcmp+0xf (0x7ffff7fee19f)                       
    ja 0x41 
    ??_NearBranch64_?? [77, 3f]
ITERATION 419 0x00007ffff7fee1a1 0x11115000 | ld-2.31.so!strcmp+0x11 (0x7ffff7fee1a1)                      
    cmp eax, 0x30 
    EAX:0x33
    ??_Immediate8to32_?? [83, f8, 30]
ITERATION 420 0x00007ffff7fee1a4 0x11115000 | ld-2.31.so!strcmp+0x14 (0x7ffff7fee1a4)                      
    ja 0x3c 
    ??_NearBranch64_?? [77, 3a]
ITERATION 421 0x00007ffff7fee1e0 0x11115000 | ld-2.31.so!strcmp+0x50 (0x7ffff7fee1e0)                      
    and rsi, 0xfffffffffffffff0 
    RSI:0x55555555440b -> 'GLIBC_2.2.5'
    ??_Immediate8to64_?? [48, 83, e6, f0]
ITERATION 422 0x00007ffff7fee1e4 0x11115000 | ld-2.31.so!strcmp+0x54 (0x7ffff7fee1e4)                      
    and rdi, 0xfffffffffffffff0 
    RDI:[34mlibc-2.31.so!catch_hook+0x1b1eb (0x7ffff7e1a273)[39m -> 'GLIBC_2.2.5'
    ??_Immediate8to64_?? [48, 83, e7, f0]
ITERATION 423 0x00007ffff7fee1e8 0x11115000 | ld-2.31.so!strcmp+0x58 (0x7ffff7fee1e8)                      
    mov edx, 0xffff 
    EDX:0x6
    ??_Immediate32_?? [ba, ff, ff, 00, 00]
ITERATION 424 0x00007ffff7fee1ed 0x11115000 | ld-2.31.so!strcmp+0x5d (0x7ffff7fee1ed)                      
    xor r8d, r8d 
    R8D:0x0
    R8D:0x0
    [45, 31, c0]
ITERATION 425 0x00007ffff7fee1f0 0x11115000 | ld-2.31.so!strcmp+0x60 (0x7ffff7fee1f0)                      
    and ecx, 0xf 
    ECX:0xb
    ??_Immediate8to32_?? [83, e1, 0f]
ITERATION 426 0x00007ffff7fee1f3 0x11115000 | ld-2.31.so!strcmp+0x63 (0x7ffff7fee1f3)                      
    and eax, 0xf 
    EAX:0x33
    ??_Immediate8to32_?? [83, e0, 0f]
ITERATION 427 0x00007ffff7fee1f6 0x11115000 | ld-2.31.so!strcmp+0x66 (0x7ffff7fee1f6)                      
    cmp ecx, eax 
    ECX:0xb
    EAX:0x3
    [39, c1]
ITERATION 428 0x00007ffff7fee1f8 0x11115000 | ld-2.31.so!strcmp+0x68 (0x7ffff7fee1f8)                      
    je 0x28 
    ??_NearBranch64_?? [74, 26]
ITERATION 429 0x00007ffff7fee1fa 0x11115000 | ld-2.31.so!strcmp+0x6a (0x7ffff7fee1fa)                      
    ja 0x9 
    ??_NearBranch64_?? [77, 07]
ITERATION 430 0x00007ffff7fee203 0x11115000 | ld-2.31.so!strcmp+0x73 (0x7ffff7fee203)                      
    lea r9, [rax+0xf] 
    R9:[34mlibc-2.31.so!catch_hook+0xab58 (0x7ffff7e09be0)[39m -> 0xe0022000058d7
    [RAX:0x3+0xf=0x12]] 
    [4c, 8d, 48, 0f]
ITERATION 431 0x00007ffff7fee207 0x11115000 | ld-2.31.so!strcmp+0x77 (0x7ffff7fee207)                      
    sub r9, rcx 
    R9:0x12
    RCX:0xb
    [49, 29, c9]
ITERATION 432 0x00007ffff7fee20a 0x11115000 | ld-2.31.so!strcmp+0x7a (0x7ffff7fee20a)                      
    lea r10, [rip+0x5d17] 
    R10:0x5555555543d9 -> 'getpid'
    [RIP:0x7ffff7fee20a+0x5d1e=0x7ffff7ff3f28]] 
    [4c, 8d, 15, 17, 5d, 00, 00]
ITERATION 433 0x00007ffff7fee211 0x11115000 | ld-2.31.so!strcmp+0x81 (0x7ffff7fee211)                      
    movsxd r9, dword ptr [r10+r9*4] 
    R9:0x7
    [R10:0x7ffff7ff3f28+R9:0x7*0x4=0x7ffff7ff3f44size:Int32->0xffffffffffffffffffffffffffffac58]] 
    [4f, 63, 0c, 8a]
ITERATION 434 0x00007ffff7fee215 0x11115000 | ld-2.31.so!strcmp+0x85 (0x7ffff7fee215)                      
    lea r10, [r10+r9] 
    R10:[34mld-2.31.so!auxvars.0+0x548 (0x7ffff7ff3f28)[39m -> 0xffffa4d8ffffa398
    [R10:0x7ffff7ff3f28+R9:0xffffffffffffac58=0x100007ffff7feeb80]] 
    [4f, 8d, 14, 0a]
ITERATION 435 0x00007ffff7fee219 0x11115000 | ld-2.31.so!strcmp+0x89 (0x7ffff7fee219)                      
    jmp r10 
    R10:[34mld-2.31.so!strcmp+0x9f0 (0x7ffff7feeb80)[39m -> 0x176f0f66c0ef0f66
    [41, ff, e2]
ITERATION 436 0x00007ffff7feeb80 0x11115000 | ld-2.31.so!strcmp+0x9f0 (0x7ffff7feeb80)                     
    pxor xmm0, xmm0 
    XMM0:0xff000000000000
    XMM0:0xff000000000000
    [66, 0f, ef, c0]
ITERATION 437 0x00007ffff7feeb84 0x11115000 | ld-2.31.so!strcmp+0x9f4 (0x7ffff7feeb84)                     
    movdqa xmm2, xmmword ptr [rdi] 
    XMM2:0x5f00646970746567
    [RDI:0x7ffff7e1a270size:Packed128_UInt32->0x4700352e322e325f4342494c4700362e]] 
    [66, 0f, 6f, 17]
ITERATION 438 0x00007ffff7feeb88 0x11115000 | ld-2.31.so!strcmp+0x9f8 (0x7ffff7feeb88)                     
    movdqa xmm1, xmmword ptr [rsi] 
    XMM1:0xff00ffffffffffff
    [RSI:0x555555554400size:Packed128_UInt32->0x4342494c4700362e6f732e6362696c00]] 
    [66, 0f, 6f, 0e]
ITERATION 439 0x00007ffff7feeb8c 0x11115000 | ld-2.31.so!strcmp+0x9fc (0x7ffff7feeb8c)                     
    pcmpeqb xmm0, xmm1 
    XMM0:0x0
    XMM1:0x6f732e6362696c00
    [66, 0f, 74, c1]
ITERATION 440 0x00007ffff7feeb90 0x11115000 | ld-2.31.so!strcmp+0xa00 (0x7ffff7feeb90)                     
    pslldq xmm2, 0x8 
    XMM2:0x4342494c4700362e
    ??_Immediate8_?? [66, 0f, 73, fa, 08]
ITERATION 441 0x00007ffff7feeb95 0x11115000 | ld-2.31.so!strcmp+0xa05 (0x7ffff7feeb95)                     
    pcmpeqb xmm2, xmm1 
    XMM2:0x0
    XMM1:0x6f732e6362696c00
    [66, 0f, 74, d1]
ITERATION 442 0x00007ffff7feeb99 0x11115000 | ld-2.31.so!strcmp+0xa09 (0x7ffff7feeb99)                     
    psubb xmm2, xmm0 
    XMM2:0xff
    XMM0:0xff
    [66, 0f, f8, d0]
ITERATION 443 0x00007ffff7feeb9d 0x11115000 | ld-2.31.so!strcmp+0xa0d (0x7ffff7feeb9d)                     
    pmovmskb r9d, xmm2 
    R9D:0xffffac58
    XMM2:0x0
    [66, 44, 0f, d7, ca]
ITERATION 444 0x00007ffff7feeba2 0x11115000 | ld-2.31.so!strcmp+0xa12 (0x7ffff7feeba2)                     
    shr edx, cl 
    EDX:0xffff
    CL:0xb
    [d3, ea]
ITERATION 445 0x00007ffff7feeba4 0x11115000 | ld-2.31.so!strcmp+0xa14 (0x7ffff7feeba4)                     
    shr r9d, cl 
    R9D:0xfb00
    CL:0xb
    [41, d3, e9]
ITERATION 446 0x00007ffff7feeba7 0x11115000 | ld-2.31.so!strcmp+0xa17 (0x7ffff7feeba7)                     
    sub edx, r9d 
    EDX:0x1f
    R9D:0x1f
    [44, 29, ca]
ITERATION 447 0x00007ffff7feebaa 0x11115000 | ld-2.31.so!strcmp+0xa1a (0x7ffff7feebaa)                     
    jne 0x9db 
    ??_NearBranch64_?? [0f, 85, d5, 09, 00, 00]
ITERATION 448 0x00007ffff7feebb0 0x11115000 | ld-2.31.so!strcmp+0xa20 (0x7ffff7feebb0)                     
    movdqa xmm3, xmmword ptr [rdi] 
    XMM3:0x0
    [RDI:0x7ffff7e1a270size:Packed128_UInt32->0x4700352e322e325f4342494c4700362e]] 
    [66, 0f, 6f, 1f]
ITERATION 449 0x00007ffff7feebb4 0x11115000 | ld-2.31.so!strcmp+0xa24 (0x7ffff7feebb4)                     
    pxor xmm0, xmm0 
    XMM0:0xff
    XMM0:0xff
    [66, 0f, ef, c0]
ITERATION 450 0x00007ffff7feebb8 0x11115000 | ld-2.31.so!strcmp+0xa28 (0x7ffff7feebb8)                     
    mov rcx, 0x10 
    RCX:0xb
    ??_Immediate32to64_?? [48, c7, c1, 10, 00, 00, 00]
ITERATION 451 0x00007ffff7feebbf 0x11115000 | ld-2.31.so!strcmp+0xa2f (0x7ffff7feebbf)                     
    mov r9d, 0x8 
    R9D:0x1f
    ??_Immediate32_?? [41, b9, 08, 00, 00, 00]
ITERATION 452 0x00007ffff7feebc5 0x11115000 | ld-2.31.so!strcmp+0xa35 (0x7ffff7feebc5)                     
    lea r10, [rdi+0x8] 
    R10:[34mld-2.31.so!strcmp+0x9f0 (0x7ffff7feeb80)[39m -> 0x176f0f66c0ef0f66
    [RDI:0x7ffff7e1a270+0x8=0x7ffff7e1a278]] 
    [4c, 8d, 57, 08]
ITERATION 453 0x00007ffff7feebc9 0x11115000 | ld-2.31.so!strcmp+0xa39 (0x7ffff7feebc9)                     
    and r10, 0xfff 
    R10:[34mlibc-2.31.so!catch_hook+0x1b1f0 (0x7ffff7e1a278)[39m -> '_2.2.5'
    ??_Immediate32to64_?? [49, 81, e2, ff, 0f, 00, 00]
ITERATION 454 0x00007ffff7feebd0 0x11115000 | ld-2.31.so!strcmp+0xa40 (0x7ffff7feebd0)                     
    sub r10, 0x1000 
    R10:0x278
    ??_Immediate32to64_?? [49, 81, ea, 00, 10, 00, 00]
ITERATION 455 0x00007ffff7feebd7 0x11115000 | ld-2.31.so!strcmp+0xa47 (0x7ffff7feebd7)                     
    nop word ptr [rax+rax] 
    [RAX:0x3+RAX:0x3] 
    [66, 0f, 1f, 84, 00, 00, 00, 00, 00]
ITERATION 456 0x00007ffff7feebe0 0x11115000 | ld-2.31.so!strcmp+0xa50 (0x7ffff7feebe0)                     
    add r10, 0x10 
    R10:0xfffffffffffff278
    ??_Immediate8to64_?? [49, 83, c2, 10]
ITERATION 457 0x00007ffff7feebe4 0x11115000 | ld-2.31.so!strcmp+0xa54 (0x7ffff7feebe4)                     
    jg 0x9c 
    ??_NearBranch64_?? [0f, 8f, 96, 00, 00, 00]
ITERATION 458 0x00007ffff7feebea 0x11115000 | ld-2.31.so!strcmp+0xa5a (0x7ffff7feebea)                     
    movdqa xmm1, xmmword ptr [rsi+rcx] 
    XMM1:0x6f732e6362696c00
    [RSI:0x555555554400+RCX:0x10=0x555555554410size:Packed128_UInt32->0x657265645f4d54495f00352e322e325f]] 
    [66, 0f, 6f, 0c, 0e]
ITERATION 459 0x00007ffff7feebef 0x11115000 | ld-2.31.so!strcmp+0xa5f (0x7ffff7feebef)                     
    movdqa xmm2, xmmword ptr [rdi+rcx] 
    XMM2:0x0
    [RDI:0x7ffff7e1a270+RCX:0x10=0x7ffff7e1a280size:Packed128_UInt32->0x4342494c4700362e322e325f4342494c]] 
    [66, 0f, 6f, 14, 0f]
ITERATION 460 0x00007ffff7feebf4 0x11115000 | ld-2.31.so!strcmp+0xa64 (0x7ffff7feebf4)                     
    movdqa xmm4, xmm2 
    XMM4:0x0
    XMM2:0x322e325f4342494c
    [66, 0f, 6f, e2]
ITERATION 461 0x00007ffff7feebf8 0x11115000 | ld-2.31.so!strcmp+0xa68 (0x7ffff7feebf8)                     
    psrldq xmm3, 0x8 
    XMM3:0x4342494c4700362e
    ??_Immediate8_?? [66, 0f, 73, db, 08]
ITERATION 462 0x00007ffff7feebfd 0x11115000 | ld-2.31.so!strcmp+0xa6d (0x7ffff7feebfd)                     
    pslldq xmm2, 0x8 
    XMM2:0x322e325f4342494c
    ??_Immediate8_?? [66, 0f, 73, fa, 08]
ITERATION 463 0x00007ffff7feec02 0x11115000 | ld-2.31.so!strcmp+0xa72 (0x7ffff7feec02)                     
    por xmm2, xmm3 
    XMM2:0x0
    XMM3:0x4700352e322e325f
    [66, 0f, eb, d3]
ITERATION 464 0x00007ffff7feec06 0x11115000 | ld-2.31.so!strcmp+0xa76 (0x7ffff7feec06)                     
    pcmpeqb xmm0, xmm1 
    XMM0:0x0
    XMM1:0x5f00352e322e325f
    [66, 0f, 74, c1]
ITERATION 465 0x00007ffff7feec0a 0x11115000 | ld-2.31.so!strcmp+0xa7a (0x7ffff7feec0a)                     
    pcmpeqb xmm1, xmm2 
    XMM1:0x5f00352e322e325f
    XMM2:0x4700352e322e325f
    [66, 0f, 74, ca]
ITERATION 466 0x00007ffff7feec0e 0x11115000 | ld-2.31.so!strcmp+0xa7e (0x7ffff7feec0e)                     
    psubb xmm1, xmm0 
    XMM1:0xffffffffffffff
    XMM0:0xff000000000000
    [66, 0f, f8, c8]
ITERATION 467 0x00007ffff7feec12 0x11115000 | ld-2.31.so!strcmp+0xa82 (0x7ffff7feec12)                     
    pmovmskb edx, xmm1 
    EDX:0x0
    XMM1:0xffffffffffff
    [66, 0f, d7, d1]
ITERATION 468 0x00007ffff7feec16 0x11115000 | ld-2.31.so!strcmp+0xa86 (0x7ffff7feec16)                     
    sub edx, 0xffff 
    EDX:0x3f
    ??_Immediate32_?? [81, ea, ff, ff, 00, 00]
ITERATION 469 0x00007ffff7feec1c 0x11115000 | ld-2.31.so!strcmp+0xa8c (0x7ffff7feec1c)                     
    jne 0x964 
    ??_NearBranch64_?? [0f, 85, 5e, 09, 00, 00]
ITERATION 470 0x00007ffff7fef580 0x11115000 | ld-2.31.so!strcmp+0x13f0 (0x7ffff7fef580)                    
    lea rax, [r9+rcx-0x10] 
    RAX:0x3
    [R9:0x8+RCX:0x10+0xfffffffffffffff0=0x10000000000000008]] 
    [49, 8d, 44, 09, f0]
ITERATION 471 0x00007ffff7fef585 0x11115000 | ld-2.31.so!strcmp+0x13f5 (0x7ffff7fef585)                    
    lea rdi, [rdi+rax] 
    RDI:[34mlibc-2.31.so!catch_hook+0x1b1e8 (0x7ffff7e1a270)[39m -> '.6'
    [RDI:0x7ffff7e1a270+RAX:0x8=0x7ffff7e1a278]] 
    [48, 8d, 3c, 07]
ITERATION 472 0x00007ffff7fef589 0x11115000 | ld-2.31.so!strcmp+0x13f9 (0x7ffff7fef589)                    
    lea rsi, [rsi+rcx] 
    RSI:0x555555554400 -> 0x6f732e6362696c00
    [RSI:0x555555554400+RCX:0x10=0x555555554410]] 
    [48, 8d, 34, 0e]
ITERATION 473 0x00007ffff7fef58d 0x11115000 | ld-2.31.so!strcmp+0x13fd (0x7ffff7fef58d)                    
    test r8d, r8d 
    R8D:0x0
    R8D:0x0
    [45, 85, c0]
ITERATION 474 0x00007ffff7fef590 0x11115000 | ld-2.31.so!strcmp+0x1400 (0x7ffff7fef590)                    
    je 0x10 
    ??_NearBranch64_?? [74, 0e]
ITERATION 475 0x00007ffff7fef5a0 0x11115000 | ld-2.31.so!strcmp+0x1410 (0x7ffff7fef5a0)                    
    bsf rdx, rdx 
    RDX:0xffff0040
    RDX:0xffff0040
    [48, 0f, bc, d2]
ITERATION 476 0x00007ffff7fef5a4 0x11115000 | ld-2.31.so!strcmp+0x1414 (0x7ffff7fef5a4)                    
    movzx ecx, byte ptr [rsi+rdx] 
    ECX:0x10
    [RSI:0x555555554410+RDX:0x6=0x555555554416size:UInt8->0x0]] 
    [0f, b6, 0c, 16]
ITERATION 477 0x00007ffff7fef5a8 0x11115000 | ld-2.31.so!strcmp+0x1418 (0x7ffff7fef5a8)                    
    movzx eax, byte ptr [rdi+rdx] 
    EAX:0x8
    [RDI:0x7ffff7e1a278+RDX:0x6=0x7ffff7e1a27esize:UInt8->0x0]] 
    [0f, b6, 04, 17]
ITERATION 478 0x00007ffff7fef5ac 0x11115000 | ld-2.31.so!strcmp+0x141c (0x7ffff7fef5ac)                    
    sub eax, ecx 
    EAX:0x0
    ECX:0x0
    [29, c8]
ITERATION 479 0x00007ffff7fef5ae 0x11115000 | ld-2.31.so!strcmp+0x141e (0x7ffff7fef5ae)                    
    ret 
    [c3]
ITERATION 480 0x00007ffff7fdbf9c 0x11115000 | ld-2.31.so!check_match+0x12c (0x7ffff7fdbf9c)                
    test eax, eax 
    EAX:0x0
    EAX:0x0
    [85, c0]
ITERATION 481 0x00007ffff7fdbf9e 0x11115000 | ld-2.31.so!check_match+0x12e (0x7ffff7fdbf9e)                
    je 0xffffffffffffff8b 
    ??_NearBranch64_?? [74, 89]
ITERATION 482 0x00007ffff7fdbf29 0x11115000 | ld-2.31.so!check_match+0xb9 (0x7ffff7fdbf29)                 
    mov rax, rbx 
    RAX:0x0
    RBX:[34mlibc-2.31.so!catch_hook+0xab58 (0x7ffff7e09be0)[39m -> 0xe0022000058d7
    [48, 89, d8]
ITERATION 483 0x00007ffff7fdbf2c 0x11115000 | ld-2.31.so!check_match+0xbc (0x7ffff7fdbf2c)                 
    pop rbx 
    RBX:[34mlibc-2.31.so!catch_hook+0xab58 (0x7ffff7e09be0)[39m -> 0xe0022000058d7
    [5b]
ITERATION 484 0x00007ffff7fdbf2d 0x11115000 | ld-2.31.so!check_match+0xbd (0x7ffff7fdbf2d)                 
    pop rbp 
    RBP:0x9691a75
    [5d]
ITERATION 485 0x00007ffff7fdbf2e 0x11115000 | ld-2.31.so!check_match+0xbe (0x7ffff7fdbf2e)                 
    pop r12 
    R12:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0xaf8 (0x7ffff7fc4000)[39m -> 0x7ffff7dff000
    [41, 5c]
ITERATION 486 0x00007ffff7fdbf30 0x11115000 | ld-2.31.so!check_match+0xc0 (0x7ffff7fdbf30)                 
    pop r13 
    R13:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0x1068 (0x7ffff7fc4570)[39m -> 0x55555555440b -> 'GLIBC_2.2.5'
    [41, 5d]
ITERATION 487 0x00007ffff7fdbf32 0x11115000 | ld-2.31.so!check_match+0xc2 (0x7ffff7fdbf32)                 
    pop r14 
    R14:0x2
    [41, 5e]
ITERATION 488 0x00007ffff7fdbf34 0x11115000 | ld-2.31.so!check_match+0xc4 (0x7ffff7fdbf34)                 
    ret 
    [c3]
ITERATION 489 0x00007ffff7fdc3a4 0x11115000 | ld-2.31.so!do_lookup_x+0x3a4 (0x7ffff7fdc3a4)                
    add rsp, 0x30 
    RSP:0x7fffffffe700 -> 'K'
    ??_Immediate8to64_?? [48, 83, c4, 30]
ITERATION 490 0x00007ffff7fdc3a8 0x11115000 | ld-2.31.so!do_lookup_x+0x3a8 (0x7ffff7fdc3a8)                
    test rax, rax 
    RAX:[34mlibc-2.31.so!catch_hook+0xab58 (0x7ffff7e09be0)[39m -> 0xe0022000058d7
    RAX:[34mlibc-2.31.so!catch_hook+0xab58 (0x7ffff7e09be0)[39m -> 0xe0022000058d7
    [48, 85, c0]
ITERATION 491 0x00007ffff7fdc3ab 0x11115000 | ld-2.31.so!do_lookup_x+0x3ab (0x7ffff7fdc3ab)                
    jne 0x6f5 
    ??_NearBranch64_?? [0f, 85, ef, 06, 00, 00]
ITERATION 492 0x00007ffff7fdcaa0 0x11115000 | ld-2.31.so!do_lookup_x+0xaa0 (0x7ffff7fdcaa0)                
    mov rbx, r15 
    RBX:0xff878ec2
    R15:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0xaf8 (0x7ffff7fc4000)[39m -> 0x7ffff7dff000
    [4c, 89, fb]
ITERATION 493 0x00007ffff7fdcaa3 0x11115000 | ld-2.31.so!do_lookup_x+0xaa3 (0x7ffff7fdcaa3)                
    mov r14d, ebp 
    R14D:0x1
    EBP:0x1
    [41, 89, ee]
ITERATION 494 0x00007ffff7fdcaa6 0x11115000 | ld-2.31.so!do_lookup_x+0xaa6 (0x7ffff7fdcaa6)                
    mov r13, qword ptr [rsp+0x40] 
    R13:0x555555554360 -> ''
    [RSP:0x7fffffffe730+0x40=0x7fffffffe770size:UInt64->0x7ffff7fc4520]] 
    [4c, 8b, 6c, 24, 40]
ITERATION 495 0x00007ffff7fdcaab 0x11115000 | ld-2.31.so!do_lookup_x+0xaab (0x7ffff7fdcaab)                
    mov r11, qword ptr [rsp+0x60] 
    R11:0x3
    [RSP:0x7fffffffe730+0x60=0x7fffffffe790size:UInt64->0x3]] 
    [4c, 8b, 5c, 24, 60]
ITERATION 496 0x00007ffff7fdcab0 0x11115000 | ld-2.31.so!do_lookup_x+0xab0 (0x7ffff7fdcab0)                
    mov r15, qword ptr [rsp+0xd8] 
    R15:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0xaf8 (0x7ffff7fc4000)[39m -> 0x7ffff7dff000
    [RSP:0x7fffffffe730+0xd8=0x7fffffffe808size:UInt64->0x0]] 
    [4c, 8b, bc, 24, d8, 00, 00, 00]
ITERATION 497 0x00007ffff7fdcab8 0x11115000 | ld-2.31.so!do_lookup_x+0xab8 (0x7ffff7fdcab8)                
    mov rbp, qword ptr [rsp+0xc0] 
    RBP:0x1
    [RSP:0x7fffffffe730+0xc0=0x7fffffffe7f0size:UInt64->0x1]] 
    [48, 8b, ac, 24, c0, 00, 00, 00]
ITERATION 498 0x00007ffff7fdcac0 0x11115000 | ld-2.31.so!do_lookup_x+0xac0 (0x7ffff7fdcac0)                
    mov r9, rax 
    R9:0x8
    RAX:[34mlibc-2.31.so!catch_hook+0xab58 (0x7ffff7e09be0)[39m -> 0xe0022000058d7
    [49, 89, c1]
ITERATION 499 0x00007ffff7fdcac3 0x11115000 | ld-2.31.so!do_lookup_x+0xac3 (0x7ffff7fdcac3)                
    jmp 0xfffffffffffff7ad 
    ??_NearBranch64_?? [e9, a8, f7, ff, ff]
ITERATION 500 0x00007ffff7fdc270 0x11115000 | ld-2.31.so!do_lookup_x+0x270 (0x7ffff7fdc270)                
    cmp qword ptr [rsp+0xe8], 0x0 
    [RSP:0x7fffffffe730+0xe8=0x7fffffffe818size:UInt64->0x7ffff7ffe180]] 
    ??_Immediate8to64_?? [48, 83, bc, 24, e8, 00, 00, 00, 00]
ITERATION 501 0x00007ffff7fdc279 0x11115000 | ld-2.31.so!do_lookup_x+0x279 (0x7ffff7fdc279)                
    je 0x15f 
    ??_NearBranch64_?? [0f, 84, 59, 01, 00, 00]
ITERATION 502 0x00007ffff7fdc27f 0x11115000 | ld-2.31.so!do_lookup_x+0x27f (0x7ffff7fdc27f)                
    movzx eax, byte ptr [r9+0x5] 
    EAX:0xf7e09be0
    [R9:0x7ffff7e09be0+0x5=0x7ffff7e09be5size:UInt8->0x0]] 
    [41, 0f, b6, 41, 05]
ITERATION 503 0x00007ffff7fdc284 0x11115000 | ld-2.31.so!do_lookup_x+0x284 (0x7ffff7fdc284)                
    and eax, 0x3 
    EAX:0x0
    ??_Immediate8to32_?? [83, e0, 03]
ITERATION 504 0x00007ffff7fdc287 0x11115000 | ld-2.31.so!do_lookup_x+0x287 (0x7ffff7fdc287)                
    sub eax, 0x1 
    EAX:0x0
    ??_Immediate8to32_?? [83, e8, 01]
ITERATION 505 0x00007ffff7fdc28a 0x11115000 | ld-2.31.so!do_lookup_x+0x28a (0x7ffff7fdc28a)                
    cmp eax, 0x1 
    EAX:0xffffffff
    ??_Immediate8to32_?? [83, f8, 01]
ITERATION 506 0x00007ffff7fdc28d 0x11115000 | ld-2.31.so!do_lookup_x+0x28d (0x7ffff7fdc28d)                
    jbe 0xfffffffffffffe50 
    ??_NearBranch64_?? [0f, 86, 4a, fe, ff, ff]
ITERATION 507 0x00007ffff7fdc293 0x11115000 | ld-2.31.so!do_lookup_x+0x293 (0x7ffff7fdc293)                
    movzx eax, byte ptr [r9+0x4] 
    EAX:0xffffffff
    [R9:0x7ffff7e09be0+0x4=0x7ffff7e09be4size:UInt8->0x22::"]] 
    [41, 0f, b6, 41, 04]
ITERATION 508 0x00007ffff7fdc298 0x11115000 | ld-2.31.so!do_lookup_x+0x298 (0x7ffff7fdc298)                
    shr al, 0x4 
    AL:0x22
    ??_Immediate8_?? [c0, e8, 04]
ITERATION 509 0x00007ffff7fdc29b 0x11115000 | ld-2.31.so!do_lookup_x+0x29b (0x7ffff7fdc29b)                
    cmp al, 0x2 
    AL:0x2
    ??_Immediate8_?? [3c, 02]
ITERATION 510 0x00007ffff7fdc29d 0x11115000 | ld-2.31.so!do_lookup_x+0x29d (0x7ffff7fdc29d)                
    je 0x233 
    ??_NearBranch64_?? [0f, 84, 2d, 02, 00, 00]
ITERATION 511 0x00007ffff7fdc4d0 0x11115000 | ld-2.31.so!do_lookup_x+0x4d0 (0x7ffff7fdc4d0)                
    mov ecx, dword ptr [rip+0x20136] 
    ECX:0x0
    [RIP:0x7ffff7fdc4d0+0x2013c=0x7ffff7ffc60csize:UInt32->0x0]] 
    [8b, 0d, 36, 01, 02, 00]
ITERATION 512 0x00007ffff7fdc4d6 0x11115000 | ld-2.31.so!do_lookup_x+0x4d6 (0x7ffff7fdc4d6)                
    test ecx, ecx 
    ECX:0x0
    ECX:0x0
    [85, c9]
ITERATION 513 0x00007ffff7fdc4d8 0x11115000 | ld-2.31.so!do_lookup_x+0x4d8 (0x7ffff7fdc4d8)                
    je 0xfffffffffffffddb 
    ??_NearBranch64_?? [0f, 84, d5, fd, ff, ff]
ITERATION 514 0x00007ffff7fdc2b3 0x11115000 | ld-2.31.so!do_lookup_x+0x2b3 (0x7ffff7fdc2b3)                
    mov rax, qword ptr [rsp+0x48] 
    RAX:0x2
    [RSP:0x7fffffffe730+0x48=0x7fffffffe778size:UInt64->0x7fffffffe870]] 
    [48, 8b, 44, 24, 48]
ITERATION 515 0x00007ffff7fdc2b8 0x11115000 | ld-2.31.so!do_lookup_x+0x2b8 (0x7ffff7fdc2b8)                
    mov qword ptr [rax], r9 
    [RAX:0x7fffffffe870] 
    R9:[34mlibc-2.31.so!catch_hook+0xab58 (0x7ffff7e09be0)[39m -> 0xe0022000058d7
    [4c, 89, 08]
ITERATION 516 0x00007ffff7fdc2bb 0x11115000 | ld-2.31.so!do_lookup_x+0x2bb (0x7ffff7fdc2bb)                
    mov qword ptr [rax+0x8], rbx 
    [RAX:0x7fffffffe870+0x8=0x7fffffffe878]] 
    RBX:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0xaf8 (0x7ffff7fc4000)[39m -> 0x7ffff7dff000
    [48, 89, 58, 08]
ITERATION 517 0x00007ffff7fdc2bf 0x11115000 | ld-2.31.so!do_lookup_x+0x2bf (0x7ffff7fdc2bf)                
    mov eax, 0x1 
    EAX:0xffffe870
    ??_Immediate32_?? [b8, 01, 00, 00, 00]
ITERATION 518 0x00007ffff7fdc2c4 0x11115000 | ld-2.31.so!do_lookup_x+0x2c4 (0x7ffff7fdc2c4)                
    jmp 0xfe 
    ??_NearBranch64_?? [e9, f9, 00, 00, 00]
ITERATION 519 0x00007ffff7fdc3c2 0x11115000 | ld-2.31.so!do_lookup_x+0x3c2 (0x7ffff7fdc3c2)                
    add rsp, 0x88 
    RSP:0x7fffffffe730 -> 0xffffffff
    ??_Immediate32to64_?? [48, 81, c4, 88, 00, 00, 00]
ITERATION 520 0x00007ffff7fdc3c9 0x11115000 | ld-2.31.so!do_lookup_x+0x3c9 (0x7ffff7fdc3c9)                
    pop rbx 
    RBX:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0xaf8 (0x7ffff7fc4000)[39m -> 0x7ffff7dff000
    [5b]
ITERATION 521 0x00007ffff7fdc3ca 0x11115000 | ld-2.31.so!do_lookup_x+0x3ca (0x7ffff7fdc3ca)                
    pop rbp 
    RBP:0x1
    [5d]
ITERATION 522 0x00007ffff7fdc3cb 0x11115000 | ld-2.31.so!do_lookup_x+0x3cb (0x7ffff7fdc3cb)                
    pop r12 
    R12:[34mlibc-2.31.so!catch_hook+0x5870 (0x7ffff7e048f8)[39m -> 0x78e4792dff878ec3
    [41, 5c]
ITERATION 523 0x00007ffff7fdc3cd 0x11115000 | ld-2.31.so!do_lookup_x+0x3cd (0x7ffff7fdc3cd)                
    pop r13 
    R13:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0x1018 (0x7ffff7fc4520)[39m -> [34mld-2.31.so!_end+0x8 (0x7ffff7ffe180)[39m ... 
    [41, 5d]
ITERATION 524 0x00007ffff7fdc3cf 0x11115000 | ld-2.31.so!do_lookup_x+0x3cf (0x7ffff7fdc3cf)                
    pop r14 
    R14:0x1
    [41, 5e]
ITERATION 525 0x00007ffff7fdc3d1 0x11115000 | ld-2.31.so!do_lookup_x+0x3d1 (0x7ffff7fdc3d1)                
    pop r15 
    R15:0x0
    [41, 5f]
ITERATION 526 0x00007ffff7fdc3d3 0x11115000 | ld-2.31.so!do_lookup_x+0x3d3 (0x7ffff7fdc3d3)                
    ret 
    [c3]
ITERATION 527 0x00007ffff7fdcce1 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x121 (0x7ffff7fdcce1)        
    add rsp, 0x30 
    RSP:0x7fffffffe7f0 -> ''
    ??_Immediate8to64_?? [48, 83, c4, 30]
ITERATION 528 0x00007ffff7fdcce5 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x125 (0x7ffff7fdcce5)        
    test eax, eax 
    EAX:0x1
    EAX:0x1
    [85, c0]
ITERATION 529 0x00007ffff7fdcce7 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x127 (0x7ffff7fdcce7)        
    je 0xffffffffffffffb9 
    ??_NearBranch64_?? [74, b7]
ITERATION 530 0x00007ffff7fdcce9 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x129 (0x7ffff7fdcce9)        
    mov rcx, qword ptr [r13] 
    RCX:0x0
    [R13:0x7fffffffe908size:UInt64->0x555555554360]] 
    [49, 8b, 4d, 00]
ITERATION 531 0x00007ffff7fdcced 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x12d (0x7ffff7fdcced)        
    cmp qword ptr [rsp+0x50], 0x0 
    [RSP:0x7fffffffe820+0x50=0x7fffffffe870size:UInt64->0x7ffff7e09be0]] 
    ??_Immediate8to64_?? [48, 83, 7c, 24, 50, 00]
ITERATION 532 0x00007ffff7fdccf3 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x133 (0x7ffff7fdccf3)        
    je 0x14d 
    ??_NearBranch64_?? [0f, 84, 47, 01, 00, 00]
ITERATION 533 0x00007ffff7fdccf9 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x139 (0x7ffff7fdccf9)        
    test rcx, rcx 
    RCX:0x555555554360 -> ''
    RCX:0x555555554360 -> ''
    [48, 85, c9]
ITERATION 534 0x00007ffff7fdccfc 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x13c (0x7ffff7fdccfc)        
    je 0xd 
    ??_NearBranch64_?? [74, 0b]
ITERATION 535 0x00007ffff7fdccfe 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x13e (0x7ffff7fdccfe)        
    movzx eax, byte ptr [rcx+0x5] 
    EAX:0x1
    [RCX:0x555555554360+0x5=0x555555554365size:UInt8->0x0]] 
    [0f, b6, 41, 05]
ITERATION 536 0x00007ffff7fdcd02 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x142 (0x7ffff7fdcd02)        
    and eax, 0x3 
    EAX:0x0
    ??_Immediate8to32_?? [83, e0, 03]
ITERATION 537 0x00007ffff7fdcd05 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x145 (0x7ffff7fdcd05)        
    cmp al, 0x3 
    AL:0x0
    ??_Immediate8_?? [3c, 03]
ITERATION 538 0x00007ffff7fdcd07 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x147 (0x7ffff7fdcd07)        
    je 0x61 
    ??_NearBranch64_?? [74, 5f]
ITERATION 539 0x00007ffff7fdcd09 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x149 (0x7ffff7fdcd09)        
    mov r14, qword ptr [rsp+0x58] 
    R14:0x7fffffffe860 -> 0xffffffff
    [RSP:0x7fffffffe820+0x58=0x7fffffffe878size:UInt64->0x7ffff7fc4000]] 
    [4c, 8b, 74, 24, 58]
ITERATION 540 0x00007ffff7fdcd0e 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x14e (0x7ffff7fdcd0e)        
    xor ebx, ebx 
    EBX:0xff878ec2
    EBX:0xff878ec2
    [31, db]
ITERATION 541 0x00007ffff7fdcd10 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x150 (0x7ffff7fdcd10)        
    movzx eax, byte ptr [r14+0x31c] 
    EAX:0x0
    [R14:0x7ffff7fc4000+0x31c=0x7ffff7fc431csize:UInt8->0x1d]] 
    [41, 0f, b6, 86, 1c, 03, 00, 00]
ITERATION 542 0x00007ffff7fdcd18 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x158 (0x7ffff7fdcd18)        
    and eax, 0x3 
    EAX:0x1d
    ??_Immediate8to32_?? [83, e0, 03]
ITERATION 543 0x00007ffff7fdcd1b 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x15b (0x7ffff7fdcd1b)        
    cmp al, 0x2 
    AL:0x1
    ??_Immediate8_?? [3c, 02]
ITERATION 544 0x00007ffff7fdcd1d 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x15d (0x7ffff7fdcd1d)        
    je 0x3d8 
    ??_NearBranch64_?? [0f, 84, d2, 03, 00, 00]
ITERATION 545 0x00007ffff7fdcd23 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x163 (0x7ffff7fdcd23)        
    mov edi, dword ptr [r14+0x3dc] 
    EDI:0xf7e1a278
    [R14:0x7ffff7fc4000+0x3dc=0x7ffff7fc43dcsize:UInt32->0x1]] 
    [41, 8b, be, dc, 03, 00, 00]
ITERATION 546 0x00007ffff7fdcd2a 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x16a (0x7ffff7fdcd2a)        
    test edi, edi 
    EDI:0x1
    EDI:0x1
    [85, ff]
ITERATION 547 0x00007ffff7fdcd2c 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x16c (0x7ffff7fdcd2c)        
    je 0x3b9 
    ??_NearBranch64_?? [0f, 84, b3, 03, 00, 00]
ITERATION 548 0x00007ffff7fdcd32 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x172 (0x7ffff7fdcd32)        
    mov eax, dword ptr [rip+0x1f888] 
    EAX:0x1
    [RIP:0x7ffff7fdcd32+0x1f88e=0x7ffff7ffc5c0size:UInt32->0x0]] 
    [8b, 05, 88, f8, 01, 00]
ITERATION 549 0x00007ffff7fdcd38 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x178 (0x7ffff7fdcd38)        
    test eax, 0x804 
    EAX:0x0
    ??_Immediate32_?? [a9, 04, 08, 00, 00]
ITERATION 550 0x00007ffff7fdcd3d 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x17d (0x7ffff7fdcd3d)        
    jne 0x1e7 
    ??_NearBranch64_?? [0f, 85, e1, 01, 00, 00]
ITERATION 551 0x00007ffff7fdcd43 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x183 (0x7ffff7fdcd43)        
    mov rax, qword ptr [rsp+0x50] 
    RAX:0x0
    [RSP:0x7fffffffe820+0x50=0x7fffffffe870size:UInt64->0x7ffff7e09be0]] 
    [48, 8b, 44, 24, 50]
ITERATION 552 0x00007ffff7fdcd48 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x188 (0x7ffff7fdcd48)        
    mov qword ptr [r13], rax 
    [R13:0x7fffffffe908] 
    RAX:[34mlibc-2.31.so!catch_hook+0xab58 (0x7ffff7e09be0)[39m -> 0xe0022000058d7
    [49, 89, 45, 00]
ITERATION 553 0x00007ffff7fdcd4c 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x18c (0x7ffff7fdcd4c)        
    add rsp, 0x98 
    RSP:0x7fffffffe820 -> [34mld-2.31.so!_end+0x370 (0x7ffff7ffe4e8)[39m -> [34mld-2.31.so!_end+0x2c8 (0x7ffff7ffe440)[39m ... 
    ??_Immediate32to64_?? [48, 81, c4, 98, 00, 00, 00]
ITERATION 554 0x00007ffff7fdcd53 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x193 (0x7ffff7fdcd53)        
    mov rax, r14 
    RAX:[34mlibc-2.31.so!catch_hook+0xab58 (0x7ffff7e09be0)[39m -> 0xe0022000058d7
    R14:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0xaf8 (0x7ffff7fc4000)[39m -> 0x7ffff7dff000
    [4c, 89, f0]
ITERATION 555 0x00007ffff7fdcd56 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x196 (0x7ffff7fdcd56)        
    pop rbx 
    RBX:0x0
    [5b]
ITERATION 556 0x00007ffff7fdcd57 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x197 (0x7ffff7fdcd57)        
    pop rbp 
    RBP:[34mld-2.31.so!_end+0x370 (0x7ffff7ffe4e8)[39m -> [34mld-2.31.so!_end+0x2c8 (0x7ffff7ffe440)[39m ... 
    [5d]
ITERATION 557 0x00007ffff7fdcd58 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x198 (0x7ffff7fdcd58)        
    pop r12 
    R12:0x5555555543d9 -> 'getpid'
    [41, 5c]
ITERATION 558 0x00007ffff7fdcd5a 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x19a (0x7ffff7fdcd5a)        
    pop r13 
    R13:0x7fffffffe908 -> [34mlibc-2.31.so!catch_hook+0xab58 (0x7ffff7e09be0)[39m -> 0xe0022000058d7
    [41, 5d]
ITERATION 559 0x00007ffff7fdcd5c 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x19c (0x7ffff7fdcd5c)        
    pop r14 
    R14:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0xaf8 (0x7ffff7fc4000)[39m -> 0x7ffff7dff000
    [41, 5e]
ITERATION 560 0x00007ffff7fdcd5e 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x19e (0x7ffff7fdcd5e)        
    pop r15 
    R15:0x7fffffffe870 -> [34mlibc-2.31.so!catch_hook+0xab58 (0x7ffff7e09be0)[39m -> 0xe0022000058d7
    [41, 5f]
ITERATION 561 0x00007ffff7fdcd60 0x11115000 | ld-2.31.so!_dl_lookup_symbol_x+0x1a0 (0x7ffff7fdcd60)        
    ret 
    [c3]
ITERATION 562 0x00007ffff7fe1623 0x11115000 | ld-2.31.so!_dl_fixup+0xd3 (0x7ffff7fe1623)                   
    mov r9, rax 
    R9:[34mlibc-2.31.so!catch_hook+0xab58 (0x7ffff7e09be0)[39m -> 0xe0022000058d7
    RAX:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0xaf8 (0x7ffff7fc4000)[39m -> 0x7ffff7dff000
    [49, 89, c1]
ITERATION 563 0x00007ffff7fe1626 0x11115000 | ld-2.31.so!_dl_fixup+0xd6 (0x7ffff7fe1626)                   
    mov eax, dword ptr fs:[0x18] 
    EAX:0xf7fc4000
    [None:0x0+0x18=0x18size:UInt32->????]] 
    [64, 8b, 04, 25, 18, 00, 00, 00]
ITERATION 564 0x00007ffff7fe162e 0x11115000 | ld-2.31.so!_dl_fixup+0xde (0x7ffff7fe162e)                   
    pop rdx 
    RDX:0x6
    [5a]
ITERATION 565 0x00007ffff7fe162f 0x11115000 | ld-2.31.so!_dl_fixup+0xdf (0x7ffff7fe162f)                   
    pop rcx 
    RCX:0x555555554360 -> ''
    [59]
ITERATION 566 0x00007ffff7fe1630 0x11115000 | ld-2.31.so!_dl_fixup+0xe0 (0x7ffff7fe1630)                   
    test eax, eax 
    EAX:0x0
    EAX:0x0
    [85, c0]
ITERATION 567 0x00007ffff7fe1632 0x11115000 | ld-2.31.so!_dl_fixup+0xe2 (0x7ffff7fe1632)                   
    jne 0x6e 
    ??_NearBranch64_?? [75, 6c]
ITERATION 568 0x00007ffff7fe1634 0x11115000 | ld-2.31.so!_dl_fixup+0xe4 (0x7ffff7fe1634)                   
    mov rax, qword ptr [rsp+0x8] 
    RAX:0x0
    [RSP:0x7fffffffe900+0x8=0x7fffffffe908size:UInt64->0x7ffff7e09be0]] 
    [48, 8b, 44, 24, 08]
ITERATION 569 0x00007ffff7fe1639 0x11115000 | ld-2.31.so!_dl_fixup+0xe9 (0x7ffff7fe1639)                   
    xor r8d, r8d 
    R8D:0x0
    R8D:0x0
    [45, 31, c0]
ITERATION 570 0x00007ffff7fe163c 0x11115000 | ld-2.31.so!_dl_fixup+0xec (0x7ffff7fe163c)                   
    test rax, rax 
    RAX:[34mlibc-2.31.so!catch_hook+0xab58 (0x7ffff7e09be0)[39m -> 0xe0022000058d7
    RAX:[34mlibc-2.31.so!catch_hook+0xab58 (0x7ffff7e09be0)[39m -> 0xe0022000058d7
    [48, 85, c0]
ITERATION 571 0x00007ffff7fe163f 0x11115000 | ld-2.31.so!_dl_fixup+0xef (0x7ffff7fe163f)                   
    je 0x20 
    ??_NearBranch64_?? [74, 1e]
ITERATION 572 0x00007ffff7fe1641 0x11115000 | ld-2.31.so!_dl_fixup+0xf1 (0x7ffff7fe1641)                   
    cmp word ptr [rax+0x6], 0xfff1 
    [RAX:0x7ffff7e09be0+0x6=0x7ffff7e09be6size:UInt16->0xe]] 
    ??_Immediate8to16_?? [66, 83, 78, 06, f1]
ITERATION 573 0x00007ffff7fe1646 0x11115000 | ld-2.31.so!_dl_fixup+0xf6 (0x7ffff7fe1646)                   
    je 0x32 
    ??_NearBranch64_?? [74, 30]
ITERATION 574 0x00007ffff7fe1648 0x11115000 | ld-2.31.so!_dl_fixup+0xf8 (0x7ffff7fe1648)                   
    test r9, r9 
    R9:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0xaf8 (0x7ffff7fc4000)[39m -> 0x7ffff7dff000
    R9:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0xaf8 (0x7ffff7fc4000)[39m -> 0x7ffff7dff000
    [4d, 85, c9]
ITERATION 575 0x00007ffff7fe164b 0x11115000 | ld-2.31.so!_dl_fixup+0xfb (0x7ffff7fe164b)                   
    je 0x2d 
    ??_NearBranch64_?? [74, 2b]
ITERATION 576 0x00007ffff7fe164d 0x11115000 | ld-2.31.so!_dl_fixup+0xfd (0x7ffff7fe164d)                   
    mov r8, qword ptr [r9] 
    R8:0x0
    [R9:0x7ffff7fc4000size:UInt64->0x7ffff7dff000]] 
    [4d, 8b, 01]
ITERATION 577 0x00007ffff7fe1650 0x11115000 | ld-2.31.so!_dl_fixup+0x100 (0x7ffff7fe1650)                  
    add r8, qword ptr [rax+0x8] 
    R8:0x7ffff7dff000
    [RAX:0x7ffff7e09be0+0x8=0x7ffff7e09be8size:UInt64->0xcc0d0]] 
    [4c, 03, 40, 08]
ITERATION 578 0x00007ffff7fe1654 0x11115000 | ld-2.31.so!_dl_fixup+0x104 (0x7ffff7fe1654)                  
    movzx eax, byte ptr [rax+0x4] 
    EAX:0xf7e09be0
    [RAX:0x7ffff7e09be0+0x4=0x7ffff7e09be4size:UInt8->0x22::"]] 
    [0f, b6, 40, 04]
ITERATION 579 0x00007ffff7fe1658 0x11115000 | ld-2.31.so!_dl_fixup+0x108 (0x7ffff7fe1658)                  
    and eax, 0xf 
    EAX:0x22
    ??_Immediate8to32_?? [83, e0, 0f]
ITERATION 580 0x00007ffff7fe165b 0x11115000 | ld-2.31.so!_dl_fixup+0x10b (0x7ffff7fe165b)                  
    cmp al, 0xa 
    AL:0x2
    ??_Immediate8_?? [3c, 0a]
ITERATION 581 0x00007ffff7fe165d 0x11115000 | ld-2.31.so!_dl_fixup+0x10d (0x7ffff7fe165d)                  
    je 0x23 
    ??_NearBranch64_?? [74, 21]
ITERATION 582 0x00007ffff7fe165f 0x11115000 | ld-2.31.so!_dl_fixup+0x10f (0x7ffff7fe165f)                  
    mov eax, dword ptr [rip+0x1afa3] 
    EAX:0x2
    [RIP:0x7ffff7fe165f+0x1afa9=0x7ffff7ffc608size:UInt32->0x0]] 
    [8b, 05, a3, af, 01, 00]
ITERATION 583 0x00007ffff7fe1665 0x11115000 | ld-2.31.so!_dl_fixup+0x115 (0x7ffff7fe1665)                  
    test eax, eax 
    EAX:0x0
    EAX:0x0
    [85, c0]
ITERATION 584 0x00007ffff7fe1667 0x11115000 | ld-2.31.so!_dl_fixup+0x117 (0x7ffff7fe1667)                  
    jne 0x5 
    ??_NearBranch64_?? [75, 03]
ITERATION 585 0x00007ffff7fe1669 0x11115000 | ld-2.31.so!_dl_fixup+0x119 (0x7ffff7fe1669)                  
    mov qword ptr [rbx], r8 
    [RBX:0x555555558018] 
    R8:0x7ffff7ecb0d0
    [4c, 89, 03]
ITERATION 586 0x00007ffff7fe166c 0x11115000 | ld-2.31.so!_dl_fixup+0x11c (0x7ffff7fe166c)                  
    add rsp, 0x10 
    RSP:0x7fffffffe900 -> [34mlibc-2.31.so!__stop___libc_freeres_ptrs+0x2038 (0x7ffff7fc5540)[39m ... 
    ??_Immediate8to64_?? [48, 83, c4, 10]
ITERATION 587 0x00007ffff7fe1670 0x11115000 | ld-2.31.so!_dl_fixup+0x120 (0x7ffff7fe1670)                  
    mov rax, r8 
    RAX:0x0
    R8:0x7ffff7ecb0d0
    [4c, 89, c0]
ITERATION 588 0x00007ffff7fe1673 0x11115000 | ld-2.31.so!_dl_fixup+0x123 (0x7ffff7fe1673)                  
    pop rbx 
    RBX:[34mexample1!_GLOBAL_OFFSET_TABLE_+0x18 (0x555555558018)[39m -> 0x7ffff7ecb0d0
    [5b]
ITERATION 589 0x00007ffff7fe1674 0x11115000 | ld-2.31.so!_dl_fixup+0x124 (0x7ffff7fe1674)                  
    ret 
    [c3]
ITERATION 590 0x00007ffff7fe8503 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x43 (0x7ffff7fe8503)  
    mov r11, rax 
    R11:0x3
    RAX:0x7ffff7ecb0d0
    [49, 89, c3]
ITERATION 591 0x00007ffff7fe8506 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x46 (0x7ffff7fe8506)  
    fxrstor [rsp+0x40] 
    [RSP:0x7fffffffe920+0x40 TODO:Fxrstor_m512byte ] 
    [0f, ae, 4c, 24, 40]
ITERATION 592 0x00007ffff7fe850b 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x4b (0x7ffff7fe850b)  
    mov r9, qword ptr [rsp+0x30] 
    R9:[34mlibc-2.31.so!__stop___libc_freeres_ptrs+0xaf8 (0x7ffff7fc4000)[39m -> 0x7ffff7dff000
    [RSP:0x7fffffffe920+0x30=0x7fffffffe950size:UInt64->0x7ffff7fe21b0]] 
    [4c, 8b, 4c, 24, 30]
ITERATION 593 0x00007ffff7fe8510 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x50 (0x7ffff7fe8510)  
    mov r8, qword ptr [rsp+0x28] 
    R8:0x7ffff7ecb0d0
    [RSP:0x7fffffffe920+0x28=0x7fffffffe948size:UInt64->0x0]] 
    [4c, 8b, 44, 24, 28]
ITERATION 594 0x00007ffff7fe8515 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x55 (0x7ffff7fe8515)  
    mov rdi, qword ptr [rsp+0x20] 
    RDI:0x1
    [RSP:0x7fffffffe920+0x20=0x7fffffffe940size:UInt64->0x1]] 
    [48, 8b, 7c, 24, 20]
ITERATION 595 0x00007ffff7fe851a 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x5a (0x7ffff7fe851a)  
    mov rsi, qword ptr [rsp+0x18] 
    RSI:0x555555554410 -> '_2.2.5'
    [RSP:0x7fffffffe920+0x18=0x7fffffffe938size:UInt64->0x7fffffffec88]] 
    [48, 8b, 74, 24, 18]
ITERATION 596 0x00007ffff7fe851f 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x5f (0x7ffff7fe851f)  
    mov rdx, qword ptr [rsp+0x10] 
    RDX:0x1
    [RSP:0x7fffffffe920+0x10=0x7fffffffe930size:UInt64->0x7fffffffec98]] 
    [48, 8b, 54, 24, 10]
ITERATION 597 0x00007ffff7fe8524 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x64 (0x7ffff7fe8524)  
    mov rcx, qword ptr [rsp+0x8] 
    RCX:0x0
    [RSP:0x7fffffffe920+0x8=0x7fffffffe928size:UInt64->0x7ffff7fbd718]] 
    [48, 8b, 4c, 24, 08]
ITERATION 598 0x00007ffff7fe8529 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x69 (0x7ffff7fe8529)  
    mov rax, qword ptr [rsp] 
    RAX:0x7ffff7ecb0d0
    [RSP:0x7fffffffe920size:UInt64->0x555555556004]] 
    [48, 8b, 04, 24]
ITERATION 599 0x00007ffff7fe852d 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x6d (0x7ffff7fe852d)  
    mov rsp, rbx 
    RSP:0x7fffffffe920 -> [34mexample1!_IO_stdin_used+0x4 (0x555555556004)[39m -> 'aaaa'
    RBX:0x7fffffffeb60 -> 0x0
    [48, 89, dc]
ITERATION 600 0x00007ffff7fe8530 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x70 (0x7ffff7fe8530)  
    mov rbx, qword ptr [rsp] 
    RBX:0x7fffffffeb60 -> 0x0
    [RSP:0x7fffffffeb60size:UInt64->0x0]] 
    [48, 8b, 1c, 24]
ITERATION 601 0x00007ffff7fe8534 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x74 (0x7ffff7fe8534)  
    add rsp, 0x18 
    RSP:0x7fffffffeb60 -> 0x0
    ??_Immediate8to64_?? [48, 83, c4, 18]
ITERATION 602 0x00007ffff7fe8538 0x11115000 | ld-2.31.so!_dl_runtime_resolve_fxsave+0x78 (0x7ffff7fe8538)  
    bnd jmp r11 
    R11:0x7ffff7ecb0d0
    [f2, 41, ff, e3]
ITERATION 603 0x00007ffff7ecb0d0 0x11115000 | libc-2.31.so!__GI___getpid+0x0 (0x7ffff7ecb0d0)              
    ???
ITERATION 604 0x00007ffff7ecb0d5 0x11115000 | libc-2.31.so!__GI___getpid+0x5 (0x7ffff7ecb0d5)              
    syscall 
    [0f, 05]
ITERATION 605 0xffffffff83a00000 0x11115000 | entry_SYSCALL_64+0x0 (0xffffffff83a00000)                    
    swapgs 
    [0f, 01, f8]
ITERATION 606 0xffffffff83a00003 0x11115000 | entry_SYSCALL_64+0x3 (0xffffffff83a00003)                    
    mov qword ptr gs:[0xa014], rsp 
    [None:0x0+0xa014=0xa014]] 
    RSP:0x7fffffffeb78 -> [34mexample1!main+0x19 (0x55555555514e)[39m -> 0xff8458b48f44589
    [65, 48, 89, 24, 25, 14, a0, 00, 00]
ITERATION 607 0xffffffff83a0000c 0x11115000 | entry_SYSCALL_64+0xc (0xffffffff83a0000c)                    
    nop 
    [66, 90]
ITERATION 608 0xffffffff83a0000e 0x11115000 | entry_SYSCALL_64+0xe (0xffffffff83a0000e)                    
    mov rsp, cr3 
    RSP:0x7fffffffeb78 -> [34mexample1!main+0x19 (0x55555555514e)[39m -> 0xff8458b48f44589
    CR3:0x11115000
    [0f, 20, dc]
ITERATION 609 0xffffffff83a00011 0x11115000 | entry_SYSCALL_64+0x11 (0xffffffff83a00011)                   
    nop dword ptr [rax+rax] 
    [RAX:0x27+RAX:0x27] 
    [0f, 1f, 44, 00, 00]
ITERATION 610 0xffffffff83a00016 0x11115000 | entry_SYSCALL_64+0x16 (0xffffffff83a00016)                   
    and rsp, 0xffffffffffffe7ff 
    RSP:0x11115000
    ??_Immediate32to64_?? [48, 81, e4, ff, e7, ff, ff]
ITERATION 611 0xffffffff83a0001d 0x11115000 | entry_SYSCALL_64+0x1d (0xffffffff83a0001d)                   
    mov cr3, rsp 
    CR3:0x11115000
    RSP:0x11114000
    [0f, 22, dc]
ITERATION 612 0xffffffff83a00020 0x11114000 | entry_SYSCALL_64+0x20 (0xffffffff83a00020)                   
    mov rsp, qword ptr gs:[0x1fd90] 
    RSP:0x11114000
    [None:0x0+0x1fd90=0x1fd90size:UInt64->????]] 
    [65, 48, 8b, 24, 25, 90, fd, 01, 00]
ITERATION 613 0xffffffff83a00029 0x11114000 | entry_SYSCALL_64_safe_stack+0x0 (0xffffffff83a00029)         
    push 0x2b 
    ??_Immediate8to64_?? [6a, 2b]
ITERATION 614 0xffffffff83a0002b 0x11114000 | entry_SYSCALL_64_safe_stack+0x2 (0xffffffff83a0002b)         
    push qword ptr gs:[0xa014] 
    [None:0x0+0xa014=0xa014size:UInt64->????]] 
    [65, ff, 34, 25, 14, a0, 00, 00]
ITERATION 615 0xffffffff83a00033 0x11114000 | entry_SYSCALL_64_safe_stack+0xa (0xffffffff83a00033)         
    push r11 
    R11:0x106
    [41, 53]
ITERATION 616 0xffffffff83a00035 0x11114000 | entry_SYSCALL_64_safe_stack+0xc (0xffffffff83a00035)         
    push 0x33 
    ??_Immediate8to64_?? [6a, 33]
ITERATION 617 0xffffffff83a00037 0x11114000 | entry_SYSCALL_64_safe_stack+0xe (0xffffffff83a00037)         
    push rcx 
    RCX:[34mlibc-2.31.so!__GI___getpid+0x7 (0x7ffff7ecb0d7)[39m -> 0x841f0fc3
    [51]
ITERATION 618 0xffffffff83a00038 0x11114000 | entry_SYSCALL_64_after_hwframe+0x0 (0xffffffff83a00038)      
    push rax 
    RAX:0x27
    [50]
ITERATION 619 0xffffffff83a00039 0x11114000 | entry_SYSCALL_64_after_hwframe+0x1 (0xffffffff83a00039)      
    push rdi 
    RDI:0x1
    [57]
ITERATION 620 0xffffffff83a0003a 0x11114000 | entry_SYSCALL_64_after_hwframe+0x2 (0xffffffff83a0003a)      
    push rsi 
    RSI:0x7fffffffec88 -> 0x7fffffffee9e -> '/root/example1'
    [56]
ITERATION 621 0xffffffff83a0003b 0x11114000 | entry_SYSCALL_64_after_hwframe+0x3 (0xffffffff83a0003b)      
    push rdx 
    RDX:0x7fffffffec98 -> 0x7fffffffeead -> 'SHELL=/bin/bash'
    [52]
ITERATION 622 0xffffffff83a0003c 0x11114000 | entry_SYSCALL_64_after_hwframe+0x4 (0xffffffff83a0003c)      
    push rcx 
    RCX:[34mlibc-2.31.so!__GI___getpid+0x7 (0x7ffff7ecb0d7)[39m -> 0x841f0fc3
    [51]
ITERATION 623 0xffffffff83a0003d 0x11114000 | entry_SYSCALL_64_after_hwframe+0x5 (0xffffffff83a0003d)      
    push 0xffffffffffffffda 
    ??_Immediate8to64_?? [6a, da]
ITERATION 624 0xffffffff83a0003f 0x11114000 | entry_SYSCALL_64_after_hwframe+0x7 (0xffffffff83a0003f)      
    push r8 
    R8:0x0
    [41, 50]
ITERATION 625 0xffffffff83a00041 0x11114000 | entry_SYSCALL_64_after_hwframe+0x9 (0xffffffff83a00041)      
    push r9 
    R9:[34mld-2.31.so!_dl_fini+0x0 (0x7ffff7fe21b0)[39m -> 0x56415741e5894855
    [41, 51]
ITERATION 626 0xffffffff83a00043 0x11114000 | entry_SYSCALL_64_after_hwframe+0xb (0xffffffff83a00043)      
    push r10 
    R10:0xfffffffffffff288
    [41, 52]
ITERATION 627 0xffffffff83a00045 0x11114000 | entry_SYSCALL_64_after_hwframe+0xd (0xffffffff83a00045)      
    push r11 
    R11:0x106
    [41, 53]
ITERATION 628 0xffffffff83a00047 0x11114000 | entry_SYSCALL_64_after_hwframe+0xf (0xffffffff83a00047)      
    push rbx 
    RBX:0x0
    [53]
ITERATION 629 0xffffffff83a00048 0x11114000 | entry_SYSCALL_64_after_hwframe+0x10 (0xffffffff83a00048)     
    push rbp 
    RBP:0x7fffffffeb90 -> [34mexample1!__libc_csu_init+0x0 (0x5555555551a0)[39m -> 0x2c3f3d8d4c5741
    [55]
ITERATION 630 0xffffffff83a00049 0x11114000 | entry_SYSCALL_64_after_hwframe+0x11 (0xffffffff83a00049)     
    push r12 
    R12:[34mexample1!_start+0x0 (0x555555555050)[39m -> 0x89485ed18949ed31
    [41, 54]
ITERATION 631 0xffffffff83a0004b 0x11114000 | entry_SYSCALL_64_after_hwframe+0x13 (0xffffffff83a0004b)     
    push r13 
    R13:0x0
    [41, 55]
ITERATION 632 0xffffffff83a0004d 0x11114000 | entry_SYSCALL_64_after_hwframe+0x15 (0xffffffff83a0004d)     
    push r14 
    R14:0x0
    [41, 56]
ITERATION 633 0xffffffff83a0004f 0x11114000 | entry_SYSCALL_64_after_hwframe+0x17 (0xffffffff83a0004f)     
    push r15 
    R15:0x0
    [41, 57]
ITERATION 634 0xffffffff83a00051 0x11114000 | entry_SYSCALL_64_after_hwframe+0x19 (0xffffffff83a00051)     
    xor edx, edx 
    EDX:0xffffec98
    EDX:0xffffec98
    [31, d2]
ITERATION 635 0xffffffff83a00053 0x11114000 | entry_SYSCALL_64_after_hwframe+0x1b (0xffffffff83a00053)     
    xor ecx, ecx 
    ECX:0xf7ecb0d7
    ECX:0xf7ecb0d7
    [31, c9]
ITERATION 636 0xffffffff83a00055 0x11114000 | entry_SYSCALL_64_after_hwframe+0x1d (0xffffffff83a00055)     
    xor r8d, r8d 
    R8D:0x0
    R8D:0x0
    [45, 31, c0]
ITERATION 637 0xffffffff83a00058 0x11114000 | entry_SYSCALL_64_after_hwframe+0x20 (0xffffffff83a00058)     
    xor r9d, r9d 
    R9D:0xf7fe21b0
    R9D:0xf7fe21b0
    [45, 31, c9]
ITERATION 638 0xffffffff83a0005b 0x11114000 | entry_SYSCALL_64_after_hwframe+0x23 (0xffffffff83a0005b)     
    xor r10d, r10d 
    R10D:0xfffff288
    R10D:0xfffff288
    [45, 31, d2]
ITERATION 639 0xffffffff83a0005e 0x11114000 | entry_SYSCALL_64_after_hwframe+0x26 (0xffffffff83a0005e)     
    xor r11d, r11d 
    R11D:0x106
    R11D:0x106
    [45, 31, db]
ITERATION 640 0xffffffff83a00061 0x11114000 | entry_SYSCALL_64_after_hwframe+0x29 (0xffffffff83a00061)     
    xor ebx, ebx 
    EBX:0x0
    EBX:0x0
    [31, db]
ITERATION 641 0xffffffff83a00063 0x11114000 | entry_SYSCALL_64_after_hwframe+0x2b (0xffffffff83a00063)     
    xor ebp, ebp 
    EBP:0xffffeb90
    EBP:0xffffeb90
    [31, ed]
ITERATION 642 0xffffffff83a00065 0x11114000 | entry_SYSCALL_64_after_hwframe+0x2d (0xffffffff83a00065)     
    xor r12d, r12d 
    R12D:0x55555050
    R12D:0x55555050
    [45, 31, e4]
ITERATION 643 0xffffffff83a00068 0x11114000 | entry_SYSCALL_64_after_hwframe+0x30 (0xffffffff83a00068)     
    xor r13d, r13d 
    R13D:0x0
    R13D:0x0
    [45, 31, ed]
ITERATION 644 0xffffffff83a0006b 0x11114000 | entry_SYSCALL_64_after_hwframe+0x33 (0xffffffff83a0006b)     
    xor r14d, r14d 
    R14D:0x0
    R14D:0x0
    [45, 31, f6]
ITERATION 645 0xffffffff83a0006e 0x11114000 | entry_SYSCALL_64_after_hwframe+0x36 (0xffffffff83a0006e)     
    xor r15d, r15d 
    R15D:0x0
    R15D:0x0
    [45, 31, ff]
ITERATION 646 0xffffffff83a00071 0x11114000 | entry_SYSCALL_64_after_hwframe+0x39 (0xffffffff83a00071)     
    mov rdi, rsp 
    RDI:0x1
    RSP:0xffffc90000a1ff58 -> 0x0
    [48, 89, e7]
ITERATION 647 0xffffffff83a00074 0x11114000 | entry_SYSCALL_64_after_hwframe+0x3c (0xffffffff83a00074)     
    movsxd rsi, eax 
    RSI:0x7fffffffec88 -> 0x7fffffffee9e -> '/root/example1'
    EAX:0x27
    [48, 63, f0]
ITERATION 648 0xffffffff83a00077 0x11114000 | entry_SYSCALL_64_after_hwframe+0x3f (0xffffffff83a00077)     
    call 0xffffffffffde81f9 
    ??_NearBranch64_?? [e8, f4, 81, de, ff]
ITERATION 649 0xffffffff837e8270 0x11114000 | do_syscall_64+0x0 (0xffffffff837e8270)                       
    push rbp 
    RBP:0x0
    [55]
ITERATION 650 0xffffffff837e8271 0x11114000 | do_syscall_64+0x1 (0xffffffff837e8271)                       
    mov rbp, rsp 
    RBP:0x0
    RSP:0xffffc90000a1ff48 -> 0x0
    [48, 89, e5]
ITERATION 651 0xffffffff837e8274 0x11114000 | do_syscall_64+0x4 (0xffffffff837e8274)                       
    push r12 
    R12:0x0
    [41, 54]
ITERATION 652 0xffffffff837e8276 0x11114000 | do_syscall_64+0x6 (0xffffffff837e8276)                       
    mov r12, rdi 
    R12:0x0
    RDI:0xffffc90000a1ff58 -> 0x0
    [49, 89, fc]
ITERATION 653 0xffffffff837e8279 0x11114000 | do_syscall_64+0x9 (0xffffffff837e8279)                       
    nop 
    [66, 90]
ITERATION 654 0xffffffff837e827b 0x11114000 | do_syscall_64+0xb (0xffffffff837e827b)                       
    movsxd rsi, esi 
    RSI:0x27
    ESI:0x27
    [48, 63, f6]
ITERATION 655 0xffffffff837e827e 0x11114000 | do_syscall_64+0xe (0xffffffff837e827e)                       
    mov rdi, r12 
    RDI:0xffffc90000a1ff58 -> 0x0
    R12:0xffffc90000a1ff58 -> 0x0
    [4c, 89, e7]
ITERATION 656 0xffffffff837e8281 0x11114000 | do_syscall_64+0x11 (0xffffffff837e8281)                      
    call 0x388f 
    ??_NearBranch64_?? [e8, 8a, 38, 00, 00]
ITERATION 657 0xffffffff837ebb10 0x11114000 | syscall_enter_from_user_mode+0x0 (0xffffffff837ebb10)        
    push rbp 
    RBP:0xffffc90000a1ff48 -> 0x0
    [55]
ITERATION 658 0xffffffff837ebb11 0x11114000 | syscall_enter_from_user_mode+0x1 (0xffffffff837ebb11)        
    mov r8, rsi 
    R8:0x0
    RSI:0x27
    [49, 89, f0]
ITERATION 659 0xffffffff837ebb14 0x11114000 | syscall_enter_from_user_mode+0x4 (0xffffffff837ebb14)        
    mov rbp, rsp 
    RBP:0xffffc90000a1ff48 -> 0x0
    RSP:0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [48, 89, e5]
ITERATION 660 0xffffffff837ebb17 0x11114000 | syscall_enter_from_user_mode+0x7 (0xffffffff837ebb17)        
    sti 
    [fb]
ITERATION 661 0xffffffff837ebb18 0x11114000 | syscall_enter_from_user_mode+0x8 (0xffffffff837ebb18)        
    nop word ptr [rax+rax] 
    [RAX:0x27+RAX:0x27] 
    [66, 0f, 1f, 44, 00, 00]
ITERATION 662 0xffffffff837ebb1e 0x11114000 | syscall_enter_from_user_mode+0xe (0xffffffff837ebb1e)        
    mov rax, qword ptr gs:[0x1fdc0] 
    RAX:0x27
    [None:0x0+0x1fdc0=0x1fdc0size:UInt64->????]] 
    [65, 48, 8b, 04, 25, c0, fd, 01, 00]
ITERATION 663 0xffffffff837ebb27 0x11114000 | syscall_enter_from_user_mode+0x17 (0xffffffff837ebb27)       
    mov rsi, qword ptr [rax+0x8] 
    RSI:0x27
    [RAX:0xffff888007674300+0x8=0xffff888007674308size:UInt64->0x0]] 
    [48, 8b, 70, 08]
ITERATION 664 0xffffffff837ebb2b 0x11114000 | syscall_enter_from_user_mode+0x1b (0xffffffff837ebb2b)       
    test sil, 0x3f 
    SIL:0x0
    ??_Immediate8_?? [40, f6, c6, 3f]
ITERATION 665 0xffffffff837ebb2f 0x11114000 | syscall_enter_from_user_mode+0x1f (0xffffffff837ebb2f)       
    jne 0x7 
    ??_NearBranch64_?? [75, 05]
ITERATION 666 0xffffffff837ebb31 0x11114000 | syscall_enter_from_user_mode+0x21 (0xffffffff837ebb31)       
    mov rax, r8 
    RAX:0xffff888007674300 -> 0x0
    R8:0x27
    [4c, 89, c0]
ITERATION 667 0xffffffff837ebb34 0x11114000 | syscall_enter_from_user_mode+0x24 (0xffffffff837ebb34)       
    pop rbp 
    RBP:0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [5d]
ITERATION 668 0xffffffff837ebb35 0x11114000 | syscall_enter_from_user_mode+0x25 (0xffffffff837ebb35)       
    ret 
    [c3]
ITERATION 669 0xffffffff837e8286 0x11114000 | do_syscall_64+0x16 (0xffffffff837e8286)                      
    cmp eax, 0x1c0 
    EAX:0x27
    ??_Immediate32_?? [3d, c0, 01, 00, 00]
ITERATION 670 0xffffffff837e828b 0x11114000 | do_syscall_64+0x1b (0xffffffff837e828b)                      
    ja 0x56 
    ??_NearBranch64_?? [77, 54]
ITERATION 671 0xffffffff837e828d 0x11114000 | do_syscall_64+0x1d (0xffffffff837e828d)                      
    mov edx, eax 
    EDX:0x0
    EAX:0x27
    [89, c2]
ITERATION 672 0xffffffff837e828f 0x11114000 | do_syscall_64+0x1f (0xffffffff837e828f)                      
    cmp rdx, 0x1c1 
    RDX:0x27
    ??_Immediate32to64_?? [48, 81, fa, c1, 01, 00, 00]
ITERATION 673 0xffffffff837e8296 0x11114000 | do_syscall_64+0x26 (0xffffffff837e8296)                      
    sbb rdx, rdx 
    RDX:0x27
    RDX:0x27
    [48, 19, d2]
ITERATION 674 0xffffffff837e8299 0x11114000 | do_syscall_64+0x29 (0xffffffff837e8299)                      
    and eax, edx 
    EAX:0x27
    EDX:0xffffffff
    [21, d0]
ITERATION 675 0xffffffff837e829b 0x11114000 | do_syscall_64+0x2b (0xffffffff837e829b)                      
    mov rdi, r12 
    RDI:0xffffc90000a1ff58 -> 0x0
    R12:0xffffc90000a1ff58 -> 0x0
    [4c, 89, e7]
ITERATION 676 0xffffffff837e829e 0x11114000 | do_syscall_64+0x2e (0xffffffff837e829e)                      
    mov rax, qword ptr [rax*8-0x7c1fc540] 
    RAX:0x27
    [None:0x0+RAX:0x27*0x8+0xffffffff83e03ac0=0xffffffff83e03bf8size:UInt64->0xffffffff81212fc0]] 
    [48, 8b, 04, c5, c0, 3a, e0, 83]
ITERATION 677 0xffffffff837e82a6 0x11114000 | do_syscall_64+0x36 (0xffffffff837e82a6)                      
    call 0x41a53a 
    ??_NearBranch64_?? [e8, 35, a5, 41, 00]
ITERATION 678 0xffffffff83c027e0 0x11114000 | __x86_indirect_thunk_rax+0x0 (0xffffffff83c027e0)            
    call 0xc 
    ??_NearBranch64_?? [e8, 07, 00, 00, 00]
ITERATION 679 0xffffffff83c027ec 0x11114000 | __x86_indirect_thunk_rax+0xc (0xffffffff83c027ec)            
    mov qword ptr [rsp], rax 
    [RSP:0xffffc90000a1ff30] 
    RAX:[34m__do_sys_getpid+0x0 (0xffffffff81212fc0)[39m -> 'D'
    [48, 89, 04, 24]
ITERATION 680 0xffffffff83c027f0 0x11114000 | __x86_indirect_thunk_rax+0x10 (0xffffffff83c027f0)           
    ret 
    [c3]
ITERATION 681 0xffffffff81212fc0 0x11114000 | __do_sys_getpid+0x0 (0xffffffff81212fc0)                     
    nop dword ptr [rax+rax] 
    [RAX:0xffffffff81212fc0+RAX:0xffffffff81212fc0] 
    [0f, 1f, 44, 00, 00]
ITERATION 682 0xffffffff81212fc5 0x11114000 | __do_sys_getpid+0x5 (0xffffffff81212fc5)                     
    push rbp 
    RBP:0xffffc90000a1ff48 -> 0x0
    [55]
ITERATION 683 0xffffffff81212fc6 0x11114000 | __do_sys_getpid+0x6 (0xffffffff81212fc6)                     
    xor edx, edx 
    EDX:0xffffffff
    EDX:0xffffffff
    [31, d2]
ITERATION 684 0xffffffff81212fc8 0x11114000 | __do_sys_getpid+0x8 (0xffffffff81212fc8)                     
    mov esi, 0x1 
    ESI:0x0
    ??_Immediate32_?? [be, 01, 00, 00, 00]
ITERATION 685 0xffffffff81212fcd 0x11114000 | __do_sys_getpid+0xd (0xffffffff81212fcd)                     
    mov rdi, qword ptr gs:[0x1fdc0] 
    RDI:0xffffc90000a1ff58 -> 0x0
    [None:0x0+0x1fdc0=0x1fdc0size:UInt64->????]] 
    [65, 48, 8b, 3c, 25, c0, fd, 01, 00]
ITERATION 686 0xffffffff81212fd6 0x11114000 | __do_sys_getpid+0x16 (0xffffffff81212fd6)                    
    mov rbp, rsp 
    RBP:0xffffc90000a1ff48 -> 0x0
    RSP:0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [48, 89, e5]
ITERATION 687 0xffffffff81212fd9 0x11114000 | __do_sys_getpid+0x19 (0xffffffff81212fd9)                    
    call 0x2c757 
    ??_NearBranch64_?? [e8, 52, c7, 02, 00]
ITERATION 688 0xffffffff8123f730 0x11114000 | __task_pid_nr_ns+0x0 (0xffffffff8123f730)                    
    nop dword ptr [rax+rax] 
    [RAX:0xffffffff81212fc0+RAX:0xffffffff81212fc0] 
    [0f, 1f, 44, 00, 00]
ITERATION 689 0xffffffff8123f735 0x11114000 | __task_pid_nr_ns+0x5 (0xffffffff8123f735)                    
    push rbp 
    RBP:0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [55]
ITERATION 690 0xffffffff8123f736 0x11114000 | __task_pid_nr_ns+0x6 (0xffffffff8123f736)                    
    inc dword ptr gs:[rip+0x7ede0643] 
    [RIP:0xffffffff8123f736+0x7ede064a=0x1fd80size:UInt32->????]] 
    [65, ff, 05, 43, 06, de, 7e]
ITERATION 691 0xffffffff8123f73d 0x11114000 | __task_pid_nr_ns+0xd (0xffffffff8123f73d)                    
    mov rbp, rsp 
    RBP:0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    RSP:0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [48, 89, e5]
ITERATION 692 0xffffffff8123f740 0x11114000 | __task_pid_nr_ns+0x10 (0xffffffff8123f740)                   
    push r14 
    R14:0x0
    [41, 56]
ITERATION 693 0xffffffff8123f742 0x11114000 | __task_pid_nr_ns+0x12 (0xffffffff8123f742)                   
    push r13 
    R13:0x0
    [41, 55]
ITERATION 694 0xffffffff8123f744 0x11114000 | __task_pid_nr_ns+0x14 (0xffffffff8123f744)                   
    mov r13d, esi 
    R13D:0x0
    ESI:0x1
    [41, 89, f5]
ITERATION 695 0xffffffff8123f747 0x11114000 | __task_pid_nr_ns+0x17 (0xffffffff8123f747)                   
    push r12 
    R12:0xffffc90000a1ff58 -> 0x0
    [41, 54]
ITERATION 696 0xffffffff8123f749 0x11114000 | __task_pid_nr_ns+0x19 (0xffffffff8123f749)                   
    mov r12, rdi 
    R12:0xffffc90000a1ff58 -> 0x0
    RDI:0xffff888007674300 -> 0x0
    [49, 89, fc]
ITERATION 697 0xffffffff8123f74c 0x11114000 | __task_pid_nr_ns+0x1c (0xffffffff8123f74c)                   
    push rbx 
    RBX:0x0
    [53]
ITERATION 698 0xffffffff8123f74d 0x11114000 | __task_pid_nr_ns+0x1d (0xffffffff8123f74d)                   
    mov rbx, rdx 
    RBX:0x0
    RDX:0x0
    [48, 89, d3]
ITERATION 699 0xffffffff8123f750 0x11114000 | __task_pid_nr_ns+0x20 (0xffffffff8123f750)                   
    push 0xffffffff8123f735 
    ??_Immediate32to64_?? [68, 35, f7, 23, 81]
ITERATION 700 0xffffffff8123f755 0x11114000 | __task_pid_nr_ns+0x25 (0xffffffff8123f755)                   
    xor r9d, r9d 
    R9D:0x0
    R9D:0x0
    [45, 31, c9]
ITERATION 701 0xffffffff8123f758 0x11114000 | __task_pid_nr_ns+0x28 (0xffffffff8123f758)                   
    xor r8d, r8d 
    R8D:0x27
    R8D:0x27
    [45, 31, c0]
ITERATION 702 0xffffffff8123f75b 0x11114000 | __task_pid_nr_ns+0x2b (0xffffffff8123f75b)                   
    mov ecx, 0x2 
    ECX:0x0
    ??_Immediate32_?? [b9, 02, 00, 00, 00]
ITERATION 703 0xffffffff8123f760 0x11114000 | __task_pid_nr_ns+0x30 (0xffffffff8123f760)                   
    xor edx, edx 
    EDX:0x0
    EDX:0x0
    [31, d2]
ITERATION 704 0xffffffff8123f762 0x11114000 | __task_pid_nr_ns+0x32 (0xffffffff8123f762)                   
    xor esi, esi 
    ESI:0x1
    ESI:0x1
    [31, f6]
ITERATION 705 0xffffffff8123f764 0x11114000 | __task_pid_nr_ns+0x34 (0xffffffff8123f764)                   
    mov rdi, 0xffffffff8505b580 
    RDI:0xffff888007674300 -> 0x0
    ??_Immediate32to64_?? [48, c7, c7, 80, b5, 05, 85]
ITERATION 706 0xffffffff8123f76b 0x11114000 | __task_pid_nr_ns+0x3b (0xffffffff8123f76b)                   
    call 0xf1655 
    ??_NearBranch64_?? [e8, 50, 16, 0f, 00]
ITERATION 707 0xffffffff81330dc0 0x11114000 | lock_acquire+0x0 (0xffffffff81330dc0)                        
    push rbp 
    RBP:0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [55]
ITERATION 708 0xffffffff81330dc1 0x11114000 | lock_acquire+0x1 (0xffffffff81330dc1)                        
    mov rbp, rsp 
    RBP:0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    RSP:0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [48, 89, e5]
ITERATION 709 0xffffffff81330dc4 0x11114000 | lock_acquire+0x4 (0xffffffff81330dc4)                        
    push r15 
    R15:0x0
    [41, 57]
ITERATION 710 0xffffffff81330dc6 0x11114000 | lock_acquire+0x6 (0xffffffff81330dc6)                        
    mov r15d, ecx 
    R15D:0x0
    ECX:0x2
    [41, 89, cf]
ITERATION 711 0xffffffff81330dc9 0x11114000 | lock_acquire+0x9 (0xffffffff81330dc9)                        
    push r14 
    R14:0x0
    [41, 56]
ITERATION 712 0xffffffff81330dcb 0x11114000 | lock_acquire+0xb (0xffffffff81330dcb)                        
    mov r14d, edx 
    R14D:0x0
    EDX:0x0
    [41, 89, d6]
ITERATION 713 0xffffffff81330dce 0x11114000 | lock_acquire+0xe (0xffffffff81330dce)                        
    push r13 
    R13:0x1
    [41, 55]
ITERATION 714 0xffffffff81330dd0 0x11114000 | lock_acquire+0x10 (0xffffffff81330dd0)                       
    mov r13d, esi 
    R13D:0x1
    ESI:0x0
    [41, 89, f5]
ITERATION 715 0xffffffff81330dd3 0x11114000 | lock_acquire+0x13 (0xffffffff81330dd3)                       
    push r12 
    R12:0xffff888007674300 -> 0x0
    [41, 54]
ITERATION 716 0xffffffff81330dd5 0x11114000 | lock_acquire+0x15 (0xffffffff81330dd5)                       
    mov r12, rdi 
    R12:0xffff888007674300 -> 0x0
    RDI:[34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    [49, 89, fc]
ITERATION 717 0xffffffff81330dd8 0x11114000 | lock_acquire+0x18 (0xffffffff81330dd8)                       
    push rbx 
    RBX:0x0
    [53]
ITERATION 718 0xffffffff81330dd9 0x11114000 | lock_acquire+0x19 (0xffffffff81330dd9)                       
    mov rbx, r9 
    RBX:0x0
    R9:0x0
    [4c, 89, cb]
ITERATION 719 0xffffffff81330ddc 0x11114000 | lock_acquire+0x1c (0xffffffff81330ddc)                       
    sub rsp, 0x10 
    RSP:0xffffc90000a1fec0 -> 0x0
    ??_Immediate8to64_?? [48, 83, ec, 10]
ITERATION 720 0xffffffff81330de0 0x11114000 | lock_acquire+0x20 (0xffffffff81330de0)                       
    nop dword ptr [rax+rax] 
    [RAX:0xffffffff81212fc0+RAX:0xffffffff81212fc0] 
    [0f, 1f, 44, 00, 00]
ITERATION 721 0xffffffff81330de5 0x11114000 | lock_acquire+0x25 (0xffffffff81330de5)                       
    mov edx, dword ptr gs:[rip+0x7ece877c] 
    EDX:0x0
    [RIP:0xffffffff81330de5+0x7ece8783=0x19568size:UInt32->????]] 
    [65, 8b, 15, 7c, 87, ce, 7e]
ITERATION 722 0xffffffff81330dec 0x11114000 | lock_acquire+0x2c (0xffffffff81330dec)                       
    mov edx, edx 
    EDX:0x0
    EDX:0x0
    [89, d2]
ITERATION 723 0xffffffff81330dee 0x11114000 | lock_acquire+0x2e (0xffffffff81330dee)                       
    mov esi, 0x8 
    ESI:0x0
    ??_Immediate32_?? [be, 08, 00, 00, 00]
ITERATION 724 0xffffffff81330df3 0x11114000 | lock_acquire+0x33 (0xffffffff81330df3)                       
    mov rax, rdx 
    RAX:[34m__do_sys_getpid+0x0 (0xffffffff81212fc0)[39m -> 'D'
    RDX:0x0
    [48, 89, d0]
ITERATION 725 0xffffffff81330df6 0x11114000 | lock_acquire+0x36 (0xffffffff81330df6)                       
    mov qword ptr [rbp-0x30], rdx 
    [RBP:0xffffc90000a1fee8+0xffffffffffffffd0=0x1ffffc90000a1feb8]] 
    RDX:0x0
    [48, 89, 55, d0]
ITERATION 726 0xffffffff81330dfa 0x11114000 | lock_acquire+0x3a (0xffffffff81330dfa)                       
    sar rax, 0x6 
    RAX:0x0
    ??_Immediate8_?? [48, c1, f8, 06]
ITERATION 727 0xffffffff81330dfe 0x11114000 | lock_acquire+0x3e (0xffffffff81330dfe)                       
    lea rdi, [rax*8-0x7a775f20] 
    RDI:[34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    [None:0x0+RAX:0x0*0x8+0xffffffff8588a0e0=0xffffffff8588a0e0]] 
    [48, 8d, 3c, c5, e0, a0, 88, 85]
ITERATION 728 0xffffffff81330e06 0x11114000 | lock_acquire+0x46 (0xffffffff81330e06)                       
    call 0x60af3a 
    ??_NearBranch64_?? [e8, 35, af, 60, 00]
ITERATION 729 0xffffffff8193bd40 0x11114000 | __kasan_check_read+0x0 (0xffffffff8193bd40)                  
    push rbp 
    RBP:0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [55]
ITERATION 730 0xffffffff8193bd41 0x11114000 | __kasan_check_read+0x1 (0xffffffff8193bd41)                  
    mov esi, esi 
    ESI:0x8
    ESI:0x8
    [89, f6]
ITERATION 731 0xffffffff8193bd43 0x11114000 | __kasan_check_read+0x3 (0xffffffff8193bd43)                  
    xor edx, edx 
    EDX:0x0
    EDX:0x0
    [31, d2]
ITERATION 732 0xffffffff8193bd45 0x11114000 | __kasan_check_read+0x5 (0xffffffff8193bd45)                  
    mov rbp, rsp 
    RBP:0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    RSP:0xffffc90000a1fea0 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [48, 89, e5]
ITERATION 733 0xffffffff8193bd48 0x11114000 | __kasan_check_read+0x8 (0xffffffff8193bd48)                  
    mov rcx, qword ptr [rbp+0x8] 
    RCX:0x2
    [RBP:0xffffc90000a1fea0+0x8=0xffffc90000a1fea8size:UInt64->0xffffffff81330e0b]] 
    [48, 8b, 4d, 08]
ITERATION 734 0xffffffff8193bd4c 0x11114000 | __kasan_check_read+0xc (0xffffffff8193bd4c)                  
    call 0xfffffffffffff784 
    ??_NearBranch64_?? [e8, 7f, f7, ff, ff]
ITERATION 735 0xffffffff8193b4d0 0x11114000 | kasan_check_range+0x0 (0xffffffff8193b4d0)                   
    test rsi, rsi 
    RSI:0x8
    RSI:0x8
    [48, 85, f6]
ITERATION 736 0xffffffff8193b4d3 0x11114000 | kasan_check_range+0x3 (0xffffffff8193b4d3)                   
    je 0x199 
    ??_NearBranch64_?? [0f, 84, 93, 01, 00, 00]
ITERATION 737 0xffffffff8193b4d9 0x11114000 | kasan_check_range+0x9 (0xffffffff8193b4d9)                   
    push rbp 
    RBP:0xffffc90000a1fea0 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [55]
ITERATION 738 0xffffffff8193b4da 0x11114000 | kasan_check_range+0xa (0xffffffff8193b4da)                   
    mov r10, rdi 
    R10:0x0
    RDI:[34m__cpu_online_mask+0x0 (0xffffffff8588a0e0)[39m -> ''
    [49, 89, fa]
ITERATION 739 0xffffffff8193b4dd 0x11114000 | kasan_check_range+0xd (0xffffffff8193b4dd)                   
    movzx edx, dl 
    EDX:0x0
    DL:0x0
    [0f, b6, d2]
ITERATION 740 0xffffffff8193b4e0 0x11114000 | kasan_check_range+0x10 (0xffffffff8193b4e0)                  
    mov rbp, rsp 
    RBP:0xffffc90000a1fea0 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    RSP:0xffffc90000a1fe90 -> 0xffffc90000a1fea0 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [48, 89, e5]
ITERATION 741 0xffffffff8193b4e3 0x11114000 | kasan_check_range+0x13 (0xffffffff8193b4e3)                  
    push r13 
    R13:0x0
    [41, 55]
ITERATION 742 0xffffffff8193b4e5 0x11114000 | kasan_check_range+0x15 (0xffffffff8193b4e5)                  
    push r12 
    R12:[34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    [41, 54]
ITERATION 743 0xffffffff8193b4e7 0x11114000 | kasan_check_range+0x17 (0xffffffff8193b4e7)                  
    push rbx 
    RBX:0x0
    [53]
ITERATION 744 0xffffffff8193b4e8 0x11114000 | kasan_check_range+0x18 (0xffffffff8193b4e8)                  
    add r10, rsi 
    R10:[34m__cpu_online_mask+0x0 (0xffffffff8588a0e0)[39m -> ''
    RSI:0x8
    [49, 01, f2]
ITERATION 745 0xffffffff8193b4eb 0x11114000 | kasan_check_range+0x1b (0xffffffff8193b4eb)                  
    jb 0x16c 
    ??_NearBranch64_?? [0f, 82, 66, 01, 00, 00]
ITERATION 746 0xffffffff8193b4f1 0x11114000 | kasan_check_range+0x21 (0xffffffff8193b4f1)                  
    jmp 0xc2 
    ??_NearBranch64_?? [e9, bd, 00, 00, 00]
ITERATION 747 0xffffffff8193b5b3 0x11114000 | kasan_check_range+0xe3 (0xffffffff8193b5b3)                  
    mov rax, 0xffff800000000000 
    RAX:0x0
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, 80, ff, ff]
ITERATION 748 0xffffffff8193b5bd 0x11114000 | kasan_check_range+0xed (0xffffffff8193b5bd)                  
    jmp 0xffffffffffffff43 
    ??_NearBranch64_?? [e9, 3e, ff, ff, ff]
ITERATION 749 0xffffffff8193b500 0x11114000 | kasan_check_range+0x30 (0xffffffff8193b500)                  
    cmp rax, rdi 
    RAX:0xffff800000000000
    RDI:[34m__cpu_online_mask+0x0 (0xffffffff8588a0e0)[39m -> ''
    [48, 39, f8]
ITERATION 750 0xffffffff8193b503 0x11114000 | kasan_check_range+0x33 (0xffffffff8193b503)                  
    ja 0x154 
    ??_NearBranch64_?? [0f, 87, 4e, 01, 00, 00]
ITERATION 751 0xffffffff8193b509 0x11114000 | kasan_check_range+0x39 (0xffffffff8193b509)                  
    sub r10, 0x1 
    R10:[34m__cpu_online_mask+0x8 (0xffffffff8588a0e8)[39m -> 0x0
    ??_Immediate8to64_?? [49, 83, ea, 01]
ITERATION 752 0xffffffff8193b50d 0x11114000 | kasan_check_range+0x3d (0xffffffff8193b50d)                  
    mov r8, rdi 
    R8:0x0
    RDI:[34m__cpu_online_mask+0x0 (0xffffffff8588a0e0)[39m -> ''
    [49, 89, f8]
ITERATION 753 0xffffffff8193b510 0x11114000 | kasan_check_range+0x40 (0xffffffff8193b510)                  
    mov rax, 0xdffffc0000000000 
    RAX:0xffff800000000000
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 754 0xffffffff8193b51a 0x11114000 | kasan_check_range+0x4a (0xffffffff8193b51a)                  
    mov r11, r10 
    R11:0x0
    R10:[34m__cpu_online_mask+0x7 (0xffffffff8588a0e7)[39m -> 0x0
    [4d, 89, d3]
ITERATION 755 0xffffffff8193b51d 0x11114000 | kasan_check_range+0x4d (0xffffffff8193b51d)                  
    shr r8, 0x3 
    R8:[34m__cpu_online_mask+0x0 (0xffffffff8588a0e0)[39m -> ''
    ??_Immediate8_?? [49, c1, e8, 03]
ITERATION 756 0xffffffff8193b521 0x11114000 | kasan_check_range+0x51 (0xffffffff8193b521)                  
    shr r11, 0x3 
    R11:[34m__cpu_online_mask+0x7 (0xffffffff8588a0e7)[39m -> 0x0
    ??_Immediate8_?? [49, c1, eb, 03]
ITERATION 757 0xffffffff8193b525 0x11114000 | kasan_check_range+0x55 (0xffffffff8193b525)                  
    lea r12, [r8+rax] 
    R12:[34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    [R8:0x1ffffffff0b1141c+RAX:0xdffffc0000000000=0xfffffbfff0b1141c]] 
    [4d, 8d, 24, 00]
ITERATION 758 0xffffffff8193b529 0x11114000 | kasan_check_range+0x59 (0xffffffff8193b529)                  
    add r11, rax 
    R11:0x1ffffffff0b1141c
    RAX:0xdffffc0000000000
    [49, 01, c3]
ITERATION 759 0xffffffff8193b52c 0x11114000 | kasan_check_range+0x5c (0xffffffff8193b52c)                  
    mov rax, r12 
    RAX:0xdffffc0000000000
    R12:0xfffffbfff0b1141c -> 0x0
    [4c, 89, e0]
ITERATION 760 0xffffffff8193b52f 0x11114000 | kasan_check_range+0x5f (0xffffffff8193b52f)                  
    lea rbx, [r11+0x1] 
    RBX:0x0
    [R11:0xfffffbfff0b1141c+0x1=0xfffffbfff0b1141d]] 
    [49, 8d, 5b, 01]
ITERATION 761 0xffffffff8193b533 0x11114000 | kasan_check_range+0x63 (0xffffffff8193b533)                  
    mov r9, rbx 
    R9:0x0
    RBX:0xfffffbfff0b1141d -> 0x0
    [49, 89, d9]
ITERATION 762 0xffffffff8193b536 0x11114000 | kasan_check_range+0x66 (0xffffffff8193b536)                  
    sub r9, r12 
    R9:0xfffffbfff0b1141d -> 0x0
    R12:0xfffffbfff0b1141c -> 0x0
    [4d, 29, e1]
ITERATION 763 0xffffffff8193b539 0x11114000 | kasan_check_range+0x69 (0xffffffff8193b539)                  
    cmp r9, 0x10 
    R9:0x1
    ??_Immediate8to64_?? [49, 83, f9, 10]
ITERATION 764 0xffffffff8193b53d 0x11114000 | kasan_check_range+0x6d (0xffffffff8193b53d)                  
    jle 0xde 
    ??_NearBranch64_?? [0f, 8e, d8, 00, 00, 00]
ITERATION 765 0xffffffff8193b61b 0x11114000 | kasan_check_range+0x14b (0xffffffff8193b61b)                 
    test r9, r9 
    R9:0x1
    R9:0x1
    [4d, 85, c9]
ITERATION 766 0xffffffff8193b61e 0x11114000 | kasan_check_range+0x14e (0xffffffff8193b61e)                 
    je 0xffffffffffffffed 
    ??_NearBranch64_?? [74, eb]
ITERATION 767 0xffffffff8193b620 0x11114000 | kasan_check_range+0x150 (0xffffffff8193b620)                 
    add r9, r12 
    R9:0x1
    R12:0xfffffbfff0b1141c -> 0x0
    [4d, 01, e1]
ITERATION 768 0xffffffff8193b623 0x11114000 | kasan_check_range+0x153 (0xffffffff8193b623)                 
    jmp 0xb 
    ??_NearBranch64_?? [eb, 09]
ITERATION 769 0xffffffff8193b62e 0x11114000 | kasan_check_range+0x15e (0xffffffff8193b62e)                 
    cmp byte ptr [rax], 0x0 
    [RAX:0xfffffbfff0b1141csize:UInt8->0x0]] 
    ??_Immediate8_?? [80, 38, 00]
ITERATION 770 0xffffffff8193b631 0x11114000 | kasan_check_range+0x161 (0xffffffff8193b631)                 
    je 0xfffffffffffffff4 
    ??_NearBranch64_?? [74, f2]
ITERATION 771 0xffffffff8193b625 0x11114000 | kasan_check_range+0x155 (0xffffffff8193b625)                 
    add rax, 0x1 
    RAX:0xfffffbfff0b1141c -> 0x0
    ??_Immediate8to64_?? [48, 83, c0, 01]
ITERATION 772 0xffffffff8193b629 0x11114000 | kasan_check_range+0x159 (0xffffffff8193b629)                 
    cmp rax, r9 
    RAX:0xfffffbfff0b1141d -> 0x0
    R9:0xfffffbfff0b1141d -> 0x0
    [4c, 39, c8]
ITERATION 773 0xffffffff8193b62c 0x11114000 | kasan_check_range+0x15c (0xffffffff8193b62c)                 
    je 0xffffffffffffffdf 
    ??_NearBranch64_?? [74, dd]
ITERATION 774 0xffffffff8193b60b 0x11114000 | kasan_check_range+0x13b (0xffffffff8193b60b)                 
    mov r8d, 0x1 
    R8D:0xf0b1141c
    ??_Immediate32_?? [41, b8, 01, 00, 00, 00]
ITERATION 775 0xffffffff8193b611 0x11114000 | kasan_check_range+0x141 (0xffffffff8193b611)                 
    pop rbx 
    RBX:0xfffffbfff0b1141d -> 0x0
    [5b]
ITERATION 776 0xffffffff8193b612 0x11114000 | kasan_check_range+0x142 (0xffffffff8193b612)                 
    pop r12 
    R12:0xfffffbfff0b1141c -> 0x0
    [41, 5c]
ITERATION 777 0xffffffff8193b614 0x11114000 | kasan_check_range+0x144 (0xffffffff8193b614)                 
    mov eax, r8d 
    EAX:0xf0b1141d
    R8D:0x1
    [44, 89, c0]
ITERATION 778 0xffffffff8193b617 0x11114000 | kasan_check_range+0x147 (0xffffffff8193b617)                 
    pop r13 
    R13:0x0
    [41, 5d]
ITERATION 779 0xffffffff8193b619 0x11114000 | kasan_check_range+0x149 (0xffffffff8193b619)                 
    pop rbp 
    RBP:0xffffc90000a1fe90 -> 0xffffc90000a1fea0 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [5d]
ITERATION 780 0xffffffff8193b61a 0x11114000 | kasan_check_range+0x14a (0xffffffff8193b61a)                 
    ret 
    [c3]
ITERATION 781 0xffffffff8193bd51 0x11114000 | __kasan_check_read+0x11 (0xffffffff8193bd51)                 
    pop rbp 
    RBP:0xffffc90000a1fea0 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [5d]
ITERATION 782 0xffffffff8193bd52 0x11114000 | __kasan_check_read+0x12 (0xffffffff8193bd52)                 
    ret 
    [c3]
ITERATION 783 0xffffffff81330e0b 0x11114000 | lock_acquire+0x4b (0xffffffff81330e0b)                       
    mov rdx, qword ptr [rbp-0x30] 
    RDX:0x0
    [RBP:0xffffc90000a1fee8+0xffffffffffffffd0=0xffffc90000a1feb8size:UInt64->0x0]] 
    [48, 8b, 55, d0]
ITERATION 784 0xffffffff81330e0f 0x11114000 | lock_acquire+0x4f (0xffffffff81330e0f)                       
    bt qword ptr [rip+0x45592c9], rdx 
    [RIP:0xffffffff81330e0f+0x45592d1=0xffffffff8588a0e0]] 
    RDX:0x0
    [48, 0f, a3, 15, c9, 92, 55, 04]
ITERATION 785 0xffffffff81330e17 0x11114000 | lock_acquire+0x57 (0xffffffff81330e17)                       
    jb 0x1ba 
    ??_NearBranch64_?? [0f, 82, b4, 01, 00, 00]
ITERATION 786 0xffffffff81330fd1 0x11114000 | lock_acquire+0x211 (0xffffffff81330fd1)                      
    inc dword ptr gs:[rip+0x7eceeda8] 
    [RIP:0xffffffff81330fd1+0x7eceedaf=0x1fd80size:UInt32->????]] 
    [65, ff, 05, a8, ed, ce, 7e]
ITERATION 787 0xffffffff81330fd8 0x11114000 | lock_acquire+0x218 (0xffffffff81330fd8)                      
    mov rax, qword ptr [rip+0x450d1e1] 
    RAX:0x1
    [RIP:0xffffffff81330fd8+0x450d1e8=0xffffffff8583e1c0size:UInt64->0x0]] 
    [48, 8b, 05, e1, d1, 50, 04]
ITERATION 788 0xffffffff81330fdf 0x11114000 | lock_acquire+0x21f (0xffffffff81330fdf)                      
    dec dword ptr gs:[rip+0x7eceed9a] 
    [RIP:0xffffffff81330fdf+0x7eceeda1=0x1fd80size:UInt32->????]] 
    [65, ff, 0d, 9a, ed, ce, 7e]
ITERATION 789 0xffffffff81330fe6 0x11114000 | lock_acquire+0x226 (0xffffffff81330fe6)                      
    jmp 0xfffffffffffffe37 
    ??_NearBranch64_?? [e9, 32, fe, ff, ff]
ITERATION 790 0xffffffff81330e1d 0x11114000 | lock_acquire+0x5d (0xffffffff81330e1d)                       
    mov rax, 0xffffffff85891e2c 
    RAX:0x0
    ??_Immediate32to64_?? [48, c7, c0, 2c, 1e, 89, 85]
ITERATION 791 0xffffffff81330e24 0x11114000 | lock_acquire+0x64 (0xffffffff81330e24)                       
    mov rdx, 0xdffffc0000000000 
    RDX:0x0
    ??_Immediate64_?? [48, ba, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 792 0xffffffff81330e2e 0x11114000 | lock_acquire+0x6e (0xffffffff81330e2e)                       
    mov rcx, rax 
    RCX:[34mlock_acquire+0x4b (0xffffffff81330e0b)[39m -> 0x15a30f48d0558b48
    RAX:[34mdebug_locks+0x0 (0xffffffff85891e2c)[39m -> ''
    [48, 89, c1]
ITERATION 793 0xffffffff81330e31 0x11114000 | lock_acquire+0x71 (0xffffffff81330e31)                       
    and eax, 0x7 
    EAX:0x85891e2c
    ??_Immediate8to32_?? [83, e0, 07]
ITERATION 794 0xffffffff81330e34 0x11114000 | lock_acquire+0x74 (0xffffffff81330e34)                       
    shr rcx, 0x3 
    RCX:[34mdebug_locks+0x0 (0xffffffff85891e2c)[39m -> ''
    ??_Immediate8_?? [48, c1, e9, 03]
ITERATION 795 0xffffffff81330e38 0x11114000 | lock_acquire+0x78 (0xffffffff81330e38)                       
    add eax, 0x3 
    EAX:0x4
    ??_Immediate8to32_?? [83, c0, 03]
ITERATION 796 0xffffffff81330e3b 0x11114000 | lock_acquire+0x7b (0xffffffff81330e3b)                       
    movzx edx, byte ptr [rcx+rdx] 
    EDX:0x0
    [RCX:0x1ffffffff0b123c5+RDX:0xdffffc0000000000=0xfffffbfff0b123c5size:UInt8->0x0]] 
    [0f, b6, 14, 11]
ITERATION 797 0xffffffff81330e3f 0x11114000 | lock_acquire+0x7f (0xffffffff81330e3f)                       
    cmp al, dl 
    AL:0x7
    DL:0x0
    [38, d0]
ITERATION 798 0xffffffff81330e41 0x11114000 | lock_acquire+0x81 (0xffffffff81330e41)                       
    jl 0xa 
    ??_NearBranch64_?? [7c, 08]
ITERATION 799 0xffffffff81330e43 0x11114000 | lock_acquire+0x83 (0xffffffff81330e43)                       
    test dl, dl 
    DL:0x0
    DL:0x0
    [84, d2]
ITERATION 800 0xffffffff81330e45 0x11114000 | lock_acquire+0x85 (0xffffffff81330e45)                       
    jne 0x1d8 
    ??_NearBranch64_?? [0f, 85, d2, 01, 00, 00]
ITERATION 801 0xffffffff81330e4b 0x11114000 | lock_acquire+0x8b (0xffffffff81330e4b)                       
    mov edx, dword ptr [rip+0x4560fdb] 
    EDX:0x0
    [RIP:0xffffffff81330e4b+0x4560fe1=0xffffffff85891e2csize:UInt32->0x1]] 
    [8b, 15, db, 0f, 56, 04]
ITERATION 802 0xffffffff81330e51 0x11114000 | lock_acquire+0x91 (0xffffffff81330e51)                       
    test edx, edx 
    EDX:0x1
    EDX:0x1
    [85, d2]
ITERATION 803 0xffffffff81330e53 0x11114000 | lock_acquire+0x93 (0xffffffff81330e53)                       
    je 0xd3 
    ??_NearBranch64_?? [0f, 84, cd, 00, 00, 00]
ITERATION 804 0xffffffff81330e59 0x11114000 | lock_acquire+0x99 (0xffffffff81330e59)                       
    mov eax, dword ptr gs:[rip+0x7ecefea0] 
    EAX:0x7
    [RIP:0xffffffff81330e59+0x7ecefea7=0x20d00size:UInt32->????]] 
    [65, 8b, 05, a0, fe, ce, 7e]
ITERATION 805 0xffffffff81330e60 0x11114000 | lock_acquire+0xa0 (0xffffffff81330e60)                       
    test eax, eax 
    EAX:0x0
    EAX:0x0
    [85, c0]
ITERATION 806 0xffffffff81330e62 0x11114000 | lock_acquire+0xa2 (0xffffffff81330e62)                       
    jne 0xc4 
    ??_NearBranch64_?? [0f, 85, be, 00, 00, 00]
ITERATION 807 0xffffffff81330e68 0x11114000 | lock_acquire+0xa8 (0xffffffff81330e68)                       
    mov rdx, qword ptr gs:[0x1fdc0] 
    RDX:0x1
    [None:0x0+0x1fdc0=0x1fdc0size:UInt64->????]] 
    [65, 48, 8b, 14, 25, c0, fd, 01, 00]
ITERATION 808 0xffffffff81330e71 0x11114000 | lock_acquire+0xb1 (0xffffffff81330e71)                       
    lea rdi, [rdx+0xd0c] 
    RDI:[34m__cpu_online_mask+0x0 (0xffffffff8588a0e0)[39m -> ''
    [RDX:0xffff888007674300+0xd0c=0xffff88800767500c]] 
    [48, 8d, ba, 0c, 0d, 00, 00]
ITERATION 809 0xffffffff81330e78 0x11114000 | lock_acquire+0xb8 (0xffffffff81330e78)                       
    mov rax, 0xdffffc0000000000 
    RAX:0x0
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 810 0xffffffff81330e82 0x11114000 | lock_acquire+0xc2 (0xffffffff81330e82)                       
    mov rcx, rdi 
    RCX:0x1ffffffff0b123c5
    RDI:0xffff88800767500c -> 0xffffffff00000000
    [48, 89, f9]
ITERATION 811 0xffffffff81330e85 0x11114000 | lock_acquire+0xc5 (0xffffffff81330e85)                       
    shr rcx, 0x3 
    RCX:0xffff88800767500c -> 0xffffffff00000000
    ??_Immediate8_?? [48, c1, e9, 03]
ITERATION 812 0xffffffff81330e89 0x11114000 | lock_acquire+0xc9 (0xffffffff81330e89)                       
    movzx ecx, byte ptr [rcx+rax] 
    ECX:0xecea01
    [RCX:0x1ffff11000ecea01+RAX:0xdffffc0000000000=0xffffed1000ecea01size:UInt8->0x0]] 
    [0f, b6, 0c, 01]
ITERATION 813 0xffffffff81330e8d 0x11114000 | lock_acquire+0xcd (0xffffffff81330e8d)                       
    mov rax, rdi 
    RAX:0xdffffc0000000000
    RDI:0xffff88800767500c -> 0xffffffff00000000
    [48, 89, f8]
ITERATION 814 0xffffffff81330e90 0x11114000 | lock_acquire+0xd0 (0xffffffff81330e90)                       
    and eax, 0x7 
    EAX:0x767500c
    ??_Immediate8to32_?? [83, e0, 07]
ITERATION 815 0xffffffff81330e93 0x11114000 | lock_acquire+0xd3 (0xffffffff81330e93)                       
    add eax, 0x3 
    EAX:0x4
    ??_Immediate8to32_?? [83, c0, 03]
ITERATION 816 0xffffffff81330e96 0x11114000 | lock_acquire+0xd6 (0xffffffff81330e96)                       
    cmp al, cl 
    AL:0x7
    CL:0x0
    [38, c8]
ITERATION 817 0xffffffff81330e98 0x11114000 | lock_acquire+0xd8 (0xffffffff81330e98)                       
    jl 0xa 
    ??_NearBranch64_?? [7c, 08]
ITERATION 818 0xffffffff81330e9a 0x11114000 | lock_acquire+0xda (0xffffffff81330e9a)                       
    test cl, cl 
    CL:0x0
    CL:0x0
    [84, c9]
ITERATION 819 0xffffffff81330e9c 0x11114000 | lock_acquire+0xdc (0xffffffff81330e9c)                       
    jne 0x192 
    ??_NearBranch64_?? [0f, 85, 8c, 01, 00, 00]
ITERATION 820 0xffffffff81330ea2 0x11114000 | lock_acquire+0xe2 (0xffffffff81330ea2)                       
    mov eax, dword ptr [rdx+0xd0c] 
    EAX:0x7
    [RDX:0xffff888007674300+0xd0c=0xffff88800767500csize:UInt32->0x0]] 
    [8b, 82, 0c, 0d, 00, 00]
ITERATION 821 0xffffffff81330ea8 0x11114000 | lock_acquire+0xe8 (0xffffffff81330ea8)                       
    test eax, eax 
    EAX:0x0
    EAX:0x0
    [85, c0]
ITERATION 822 0xffffffff81330eaa 0x11114000 | lock_acquire+0xea (0xffffffff81330eaa)                       
    jne 0x7c 
    ??_NearBranch64_?? [75, 7a]
ITERATION 823 0xffffffff81330eac 0x11114000 | lock_acquire+0xec (0xffffffff81330eac)                       
    pushfq 
    [9c]
ITERATION 824 0xffffffff81330ead 0x11114000 | lock_acquire+0xed (0xffffffff81330ead)                       
    pop rax 
    RAX:0x0
    [58]
ITERATION 825 0xffffffff81330eae 0x11114000 | lock_acquire+0xee (0xffffffff81330eae)                       
    nop dword ptr [rax+rax] 
    [RAX:0x346+RAX:0x346] 
    [0f, 1f, 44, 00, 00]
ITERATION 826 0xffffffff81330eb3 0x11114000 | lock_acquire+0xf3 (0xffffffff81330eb3)                       
    mov rdx, rax 
    RDX:0xffff888007674300 -> 0x0
    RAX:0x346
    [48, 89, c2]
ITERATION 827 0xffffffff81330eb6 0x11114000 | lock_acquire+0xf6 (0xffffffff81330eb6)                       
    cli 
    [fa]
ITERATION 828 0xffffffff81330eb7 0x11114000 | lock_acquire+0xf7 (0xffffffff81330eb7)                       
    nop word ptr [rax+rax] 
    [RAX:0x346+RAX:0x346] 
    [66, 0f, 1f, 44, 00, 00]
ITERATION 829 0xffffffff81330ebd 0x11114000 | lock_acquire+0xfd (0xffffffff81330ebd)                       
    inc dword ptr gs:[rip+0x7ecefe3c] 
    [RIP:0xffffffff81330ebd+0x7ecefe43=0x20d00size:UInt32->????]] 
    [65, ff, 05, 3c, fe, ce, 7e]
ITERATION 830 0xffffffff81330ec4 0x11114000 | lock_acquire+0x104 (0xffffffff81330ec4)                      
    and edx, 0x200 
    EDX:0x346
    ??_Immediate32_?? [81, e2, 00, 02, 00, 00]
ITERATION 831 0xffffffff81330eca 0x11114000 | lock_acquire+0x10a (0xffffffff81330eca)                      
    mov r9, rbx 
    R9:0xfffffbfff0b1141d -> 0x0
    RBX:0x0
    [49, 89, d9]
ITERATION 832 0xffffffff81330ecd 0x11114000 | lock_acquire+0x10d (0xffffffff81330ecd)                      
    mov ecx, r15d 
    ECX:0x0
    R15D:0x2
    [44, 89, f9]
ITERATION 833 0xffffffff81330ed0 0x11114000 | lock_acquire+0x110 (0xffffffff81330ed0)                      
    mov esi, r13d 
    ESI:0x8
    R13D:0x0
    [44, 89, ee]
ITERATION 834 0xffffffff81330ed3 0x11114000 | lock_acquire+0x113 (0xffffffff81330ed3)                      
    mov qword ptr [rbp-0x30], rdx 
    [RBP:0xffffc90000a1fee8+0xffffffffffffffd0=0x1ffffc90000a1feb8]] 
    RDX:0x200
    [48, 89, 55, d0]
ITERATION 835 0xffffffff81330ed7 0x11114000 | lock_acquire+0x117 (0xffffffff81330ed7)                      
    sete r8b 
    R8L:0x1
    [41, 0f, 94, c0]
ITERATION 836 0xffffffff81330edb 0x11114000 | lock_acquire+0x11b (0xffffffff81330edb)                      
    mov edx, r14d 
    EDX:0x200
    R14D:0x0
    [44, 89, f2]
ITERATION 837 0xffffffff81330ede 0x11114000 | lock_acquire+0x11e (0xffffffff81330ede)                      
    mov rdi, r12 
    RDI:0xffff88800767500c -> 0xffffffff00000000
    R12:[34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    [4c, 89, e7]
ITERATION 838 0xffffffff81330ee1 0x11114000 | lock_acquire+0x121 (0xffffffff81330ee1)                      
    push 0x0 
    ??_Immediate8to64_?? [6a, 00]
ITERATION 839 0xffffffff81330ee3 0x11114000 | lock_acquire+0x123 (0xffffffff81330ee3)                      
    movzx r8d, r8b 
    R8D:0x0
    R8L:0x0
    [45, 0f, b6, c0]
ITERATION 840 0xffffffff81330ee7 0x11114000 | lock_acquire+0x127 (0xffffffff81330ee7)                      
    push 0x0 
    ??_Immediate8to64_?? [6a, 00]
ITERATION 841 0xffffffff81330ee9 0x11114000 | lock_acquire+0x129 (0xffffffff81330ee9)                      
    push qword ptr [rbp+0x10] 
    [RBP:0xffffc90000a1fee8+0x10=0xffffc90000a1fef8size:UInt64->0xffffffff8123f735]] 
    [ff, 75, 10]
ITERATION 842 0xffffffff81330eec 0x11114000 | lock_acquire+0x12c (0xffffffff81330eec)                      
    call 0xffffffffffffdbe4 
    ??_NearBranch64_?? [e8, df, db, ff, ff]
ITERATION 843 0xffffffff8132ead0 0x11114000 | __lock_acquire.isra.0+0x0 (0xffffffff8132ead0)               
    push rbp 
    RBP:0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [55]
ITERATION 844 0xffffffff8132ead1 0x11114000 | __lock_acquire.isra.0+0x1 (0xffffffff8132ead1)               
    mov rax, qword ptr gs:[0x1fdc0] 
    RAX:0x346
    [None:0x0+0x1fdc0=0x1fdc0size:UInt64->????]] 
    [65, 48, 8b, 04, 25, c0, fd, 01, 00]
ITERATION 845 0xffffffff8132eada 0x11114000 | __lock_acquire.isra.0+0xa (0xffffffff8132eada)               
    mov rbp, rsp 
    RBP:0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    RSP:0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [48, 89, e5]
ITERATION 846 0xffffffff8132eadd 0x11114000 | __lock_acquire.isra.0+0xd (0xffffffff8132eadd)               
    push r15 
    R15:0x2
    [41, 57]
ITERATION 847 0xffffffff8132eadf 0x11114000 | __lock_acquire.isra.0+0xf (0xffffffff8132eadf)               
    push r14 
    R14:0x0
    [41, 56]
ITERATION 848 0xffffffff8132eae1 0x11114000 | __lock_acquire.isra.0+0x11 (0xffffffff8132eae1)              
    push r13 
    R13:0x0
    [41, 55]
ITERATION 849 0xffffffff8132eae3 0x11114000 | __lock_acquire.isra.0+0x13 (0xffffffff8132eae3)              
    mov r13, rdi 
    R13:0x0
    RDI:[34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    [49, 89, fd]
ITERATION 850 0xffffffff8132eae6 0x11114000 | __lock_acquire.isra.0+0x16 (0xffffffff8132eae6)              
    push r12 
    R12:[34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    [41, 54]
ITERATION 851 0xffffffff8132eae8 0x11114000 | __lock_acquire.isra.0+0x18 (0xffffffff8132eae8)              
    mov r12, r9 
    R12:[34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    R9:0x0
    [4d, 89, cc]
ITERATION 852 0xffffffff8132eaeb 0x11114000 | __lock_acquire.isra.0+0x1b (0xffffffff8132eaeb)              
    push rbx 
    RBX:0x0
    [53]
ITERATION 853 0xffffffff8132eaec 0x11114000 | __lock_acquire.isra.0+0x1c (0xffffffff8132eaec)              
    mov ebx, ecx 
    EBX:0x0
    ECX:0x2
    [89, cb]
ITERATION 854 0xffffffff8132eaee 0x11114000 | __lock_acquire.isra.0+0x1e (0xffffffff8132eaee)              
    sub rsp, 0x58 
    RSP:0xffffc90000a1fe60 -> 0x0
    ??_Immediate8to64_?? [48, 83, ec, 58]
ITERATION 855 0xffffffff8132eaf2 0x11114000 | __lock_acquire.isra.0+0x22 (0xffffffff8132eaf2)              
    mov dword ptr [rbp-0x48], edx 
    [RBP:0xffffc90000a1fe88+0xffffffffffffffb8=0x1ffffc90000a1fe40]] 
    EDX:0x0
    [89, 55, b8]
ITERATION 856 0xffffffff8132eaf5 0x11114000 | __lock_acquire.isra.0+0x25 (0xffffffff8132eaf5)              
    mov rdx, 0xffffffff85891e2c 
    RDX:0x0
    ??_Immediate32to64_?? [48, c7, c2, 2c, 1e, 89, 85]
ITERATION 857 0xffffffff8132eafc 0x11114000 | __lock_acquire.isra.0+0x2c (0xffffffff8132eafc)              
    mov qword ptr [rbp-0x30], rax 
    [RBP:0xffffc90000a1fe88+0xffffffffffffffd0=0x1ffffc90000a1fe58]] 
    RAX:0xffff888007674300 -> 0x0
    [48, 89, 45, d0]
ITERATION 858 0xffffffff8132eb00 0x11114000 | __lock_acquire.isra.0+0x30 (0xffffffff8132eb00)              
    shr rdx, 0x3 
    RDX:[34mdebug_locks+0x0 (0xffffffff85891e2c)[39m -> ''
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 859 0xffffffff8132eb04 0x11114000 | __lock_acquire.isra.0+0x34 (0xffffffff8132eb04)              
    mov rax, 0xdffffc0000000000 
    RAX:0xffff888007674300 -> 0x0
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 860 0xffffffff8132eb0e 0x11114000 | __lock_acquire.isra.0+0x3e (0xffffffff8132eb0e)              
    movzx edx, byte ptr [rdx+rax] 
    EDX:0xf0b123c5
    [RDX:0x1ffffffff0b123c5+RAX:0xdffffc0000000000=0xfffffbfff0b123c5size:UInt8->0x0]] 
    [0f, b6, 14, 02]
ITERATION 861 0xffffffff8132eb12 0x11114000 | __lock_acquire.isra.0+0x42 (0xffffffff8132eb12)              
    mov rax, 0xffffffff85891e2c 
    RAX:0xdffffc0000000000
    ??_Immediate32to64_?? [48, c7, c0, 2c, 1e, 89, 85]
ITERATION 862 0xffffffff8132eb19 0x11114000 | __lock_acquire.isra.0+0x49 (0xffffffff8132eb19)              
    mov dword ptr [rbp-0x50], r8d 
    [RBP:0xffffc90000a1fe88+0xffffffffffffffb0=0x1ffffc90000a1fe38]] 
    R8D:0x0
    [44, 89, 45, b0]
ITERATION 863 0xffffffff8132eb1d 0x11114000 | __lock_acquire.isra.0+0x4d (0xffffffff8132eb1d)              
    and eax, 0x7 
    EAX:0x85891e2c
    ??_Immediate8to32_?? [83, e0, 07]
ITERATION 864 0xffffffff8132eb20 0x11114000 | __lock_acquire.isra.0+0x50 (0xffffffff8132eb20)              
    add eax, 0x3 
    EAX:0x4
    ??_Immediate8to32_?? [83, c0, 03]
ITERATION 865 0xffffffff8132eb23 0x11114000 | __lock_acquire.isra.0+0x53 (0xffffffff8132eb23)              
    cmp al, dl 
    AL:0x7
    DL:0x0
    [38, d0]
ITERATION 866 0xffffffff8132eb25 0x11114000 | __lock_acquire.isra.0+0x55 (0xffffffff8132eb25)              
    jl 0xa 
    ??_NearBranch64_?? [7c, 08]
ITERATION 867 0xffffffff8132eb27 0x11114000 | __lock_acquire.isra.0+0x57 (0xffffffff8132eb27)              
    test dl, dl 
    DL:0x0
    DL:0x0
    [84, d2]
ITERATION 868 0xffffffff8132eb29 0x11114000 | __lock_acquire.isra.0+0x59 (0xffffffff8132eb29)              
    jne 0xa66 
    ??_NearBranch64_?? [0f, 85, 60, 0a, 00, 00]
ITERATION 869 0xffffffff8132eb2f 0x11114000 | __lock_acquire.isra.0+0x5f (0xffffffff8132eb2f)              
    mov r14d, dword ptr [rip+0x45632f6] 
    R14D:0x0
    [RIP:0xffffffff8132eb2f+0x45632fd=0xffffffff85891e2csize:UInt32->0x1]] 
    [44, 8b, 35, f6, 32, 56, 04]
ITERATION 870 0xffffffff8132eb36 0x11114000 | __lock_acquire.isra.0+0x66 (0xffffffff8132eb36)              
    test r14d, r14d 
    R14D:0x1
    R14D:0x1
    [45, 85, f6]
ITERATION 871 0xffffffff8132eb39 0x11114000 | __lock_acquire.isra.0+0x69 (0xffffffff8132eb39)              
    je 0x70b 
    ??_NearBranch64_?? [0f, 84, 05, 07, 00, 00]
ITERATION 872 0xffffffff8132eb3f 0x11114000 | __lock_acquire.isra.0+0x6f (0xffffffff8132eb3f)              
    cmp esi, 0x1 
    ESI:0x0
    ??_Immediate8to32_?? [83, fe, 01]
ITERATION 873 0xffffffff8132eb42 0x11114000 | __lock_acquire.isra.0+0x72 (0xffffffff8132eb42)              
    jbe 0x717 
    ??_NearBranch64_?? [0f, 86, 11, 07, 00, 00]
ITERATION 874 0xffffffff8132f259 0x11114000 | __lock_acquire.isra.0+0x789 (0xffffffff8132f259)             
    mov rax, 0xdffffc0000000000 
    RAX:0x7
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 875 0xffffffff8132f263 0x11114000 | __lock_acquire.isra.0+0x793 (0xffffffff8132f263)             
    mov r14d, esi 
    R14D:0x1
    ESI:0x0
    [41, 89, f6]
ITERATION 876 0xffffffff8132f266 0x11114000 | __lock_acquire.isra.0+0x796 (0xffffffff8132f266)             
    lea rdi, [r13+r14*8+0x8] 
    RDI:[34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    [R13:0xffffffff8505b580+R14:0x0*0x8+0x8=0xffffffff8505b588]] 
    [4b, 8d, 7c, f5, 08]
ITERATION 877 0xffffffff8132f26b 0x11114000 | __lock_acquire.isra.0+0x79b (0xffffffff8132f26b)             
    mov rdx, rdi 
    RDX:0x0
    RDI:[34mrcu_lock_map+0x8 (0xffffffff8505b588)[39m -> [34mlock_classes+0x180 (0xffffffff85d2b640)[39m -> 0x0
    [48, 89, fa]
ITERATION 878 0xffffffff8132f26e 0x11114000 | __lock_acquire.isra.0+0x79e (0xffffffff8132f26e)             
    shr rdx, 0x3 
    RDX:[34mrcu_lock_map+0x8 (0xffffffff8505b588)[39m -> [34mlock_classes+0x180 (0xffffffff85d2b640)[39m -> 0x0
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 879 0xffffffff8132f272 0x11114000 | __lock_acquire.isra.0+0x7a2 (0xffffffff8132f272)             
    cmp byte ptr [rdx+rax], 0x0 
    [RDX:0x1ffffffff0a0b6b1+RAX:0xdffffc0000000000=0xfffffbfff0a0b6b1size:UInt8->0x0]] 
    ??_Immediate8_?? [80, 3c, 02, 00]
ITERATION 880 0xffffffff8132f276 0x11114000 | __lock_acquire.isra.0+0x7a6 (0xffffffff8132f276)             
    jne 0x6ac 
    ??_NearBranch64_?? [0f, 85, a6, 06, 00, 00]
ITERATION 881 0xffffffff8132f27c 0x11114000 | __lock_acquire.isra.0+0x7ac (0xffffffff8132f27c)             
    mov r14, qword ptr [r13+r14*8+0x8] 
    R14:0x0
    [R13:0xffffffff8505b580+R14:0x0*0x8+0x8=0xffffffff8505b588size:UInt64->0xffffffff85d2b640]] 
    [4f, 8b, 74, f5, 08]
ITERATION 882 0xffffffff8132f281 0x11114000 | __lock_acquire.isra.0+0x7b1 (0xffffffff8132f281)             
    test r14, r14 
    R14:[34mlock_classes+0x180 (0xffffffff85d2b640)[39m -> 0x0
    R14:[34mlock_classes+0x180 (0xffffffff85d2b640)[39m -> 0x0
    [4d, 85, f6]
ITERATION 883 0xffffffff8132f284 0x11114000 | __lock_acquire.isra.0+0x7b4 (0xffffffff8132f284)             
    jne 0xfffffffffffff8da 
    ??_NearBranch64_?? [0f, 85, d4, f8, ff, ff]
ITERATION 884 0xffffffff8132eb5e 0x11114000 | __lock_acquire.isra.0+0x8e (0xffffffff8132eb5e)              
    sub r14, 0xffffffff85d2b4c0 
    R14:[34mlock_classes+0x180 (0xffffffff85d2b640)[39m -> 0x0
    ??_Immediate32to64_?? [49, 81, ee, c0, b4, d2, 85]
ITERATION 885 0xffffffff8132eb65 0x11114000 | __lock_acquire.isra.0+0x95 (0xffffffff8132eb65)              
    mov rax, 0xaaaaaaaaaaaaaaab 
    RAX:0xdffffc0000000000
    ??_Immediate64_?? [48, b8, ab, aa, aa, aa, aa, aa, aa, aa]
ITERATION 886 0xffffffff8132eb6f 0x11114000 | __lock_acquire.isra.0+0x9f (0xffffffff8132eb6f)              
    sar r14, 0x6 
    R14:0x180
    ??_Immediate8_?? [49, c1, fe, 06]
ITERATION 887 0xffffffff8132eb73 0x11114000 | __lock_acquire.isra.0+0xa3 (0xffffffff8132eb73)              
    imul r14, rax 
    R14:0x6
    RAX:0xaaaaaaaaaaaaaaab
    [4c, 0f, af, f0]
ITERATION 888 0xffffffff8132eb77 0x11114000 | __lock_acquire.isra.0+0xa7 (0xffffffff8132eb77)              
    movsxd r11, r14d 
    R11:0xfffffbfff0b1141c -> 0x0
    R14D:0x2
    [4d, 63, de]
ITERATION 889 0xffffffff8132eb7a 0x11114000 | __lock_acquire.isra.0+0xaa (0xffffffff8132eb7a)              
    inc qword ptr gs:[r11*8+0x20d88] 
    [None:0x0+R11:0x2*0x8+0x20d88=0x20d98size:UInt64->????]] 
    [65, 4a, ff, 04, dd, 88, 0d, 02, 00]
ITERATION 890 0xffffffff8132eb83 0x11114000 | __lock_acquire.isra.0+0xb3 (0xffffffff8132eb83)              
    mov rax, qword ptr [rbp-0x30] 
    RAX:0xaaaaaaaaaaaaaaab
    [RBP:0xffffc90000a1fe88+0xffffffffffffffd0=0xffffc90000a1fe58size:UInt64->0xffff888007674300]] 
    [48, 8b, 45, d0]
ITERATION 891 0xffffffff8132eb87 0x11114000 | __lock_acquire.isra.0+0xb7 (0xffffffff8132eb87)              
    add rax, 0xd08 
    RAX:0xffff888007674300 -> 0x0
    ??_Immediate32to64_?? [48, 05, 08, 0d, 00, 00]
ITERATION 892 0xffffffff8132eb8d 0x11114000 | __lock_acquire.isra.0+0xbd (0xffffffff8132eb8d)              
    mov rdx, rax 
    RDX:0x1ffffffff0a0b6b1
    RAX:0xffff888007675008 -> 0x0
    [48, 89, c2]
ITERATION 893 0xffffffff8132eb90 0x11114000 | __lock_acquire.isra.0+0xc0 (0xffffffff8132eb90)              
    mov qword ptr [rbp-0x58], rax 
    [RBP:0xffffc90000a1fe88+0xffffffffffffffa8=0x1ffffc90000a1fe30]] 
    RAX:0xffff888007675008 -> 0x0
    [48, 89, 45, a8]
ITERATION 894 0xffffffff8132eb94 0x11114000 | __lock_acquire.isra.0+0xc4 (0xffffffff8132eb94)              
    mov rax, 0xdffffc0000000000 
    RAX:0xffff888007675008 -> 0x0
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 895 0xffffffff8132eb9e 0x11114000 | __lock_acquire.isra.0+0xce (0xffffffff8132eb9e)              
    shr rdx, 0x3 
    RDX:0xffff888007675008 -> 0x0
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 896 0xffffffff8132eba2 0x11114000 | __lock_acquire.isra.0+0xd2 (0xffffffff8132eba2)              
    movzx eax, byte ptr [rdx+rax] 
    EAX:0x0
    [RDX:0x1ffff11000ecea01+RAX:0xdffffc0000000000=0xffffed1000ecea01size:UInt8->0x0]] 
    [0f, b6, 04, 02]
ITERATION 897 0xffffffff8132eba6 0x11114000 | __lock_acquire.isra.0+0xd6 (0xffffffff8132eba6)              
    test al, al 
    AL:0x0
    AL:0x0
    [84, c0]
ITERATION 898 0xffffffff8132eba8 0x11114000 | __lock_acquire.isra.0+0xd8 (0xffffffff8132eba8)              
    je 0xa 
    ??_NearBranch64_?? [74, 08]
ITERATION 899 0xffffffff8132ebb2 0x11114000 | __lock_acquire.isra.0+0xe2 (0xffffffff8132ebb2)              
    mov rax, qword ptr [rbp-0x30] 
    RAX:0x0
    [RBP:0xffffc90000a1fe88+0xffffffffffffffd0=0xffffc90000a1fe58size:UInt64->0xffff888007674300]] 
    [48, 8b, 45, d0]
ITERATION 900 0xffffffff8132ebb6 0x11114000 | __lock_acquire.isra.0+0xe6 (0xffffffff8132ebb6)              
    mov rdx, 0xffffffff860b81e0 
    RDX:0x1ffff11000ecea01
    ??_Immediate32to64_?? [48, c7, c2, e0, 81, 0b, 86]
ITERATION 901 0xffffffff8132ebbd 0x11114000 | __lock_acquire.isra.0+0xed (0xffffffff8132ebbd)              
    shr rdx, 0x3 
    RDX:[34moops_in_progress+0x0 (0xffffffff860b81e0)[39m -> 0x0
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 902 0xffffffff8132ebc1 0x11114000 | __lock_acquire.isra.0+0xf1 (0xffffffff8132ebc1)              
    mov eax, dword ptr [rax+0xd08] 
    EAX:0x7674300
    [RAX:0xffff888007674300+0xd08=0xffff888007675008size:UInt32->0x0]] 
    [8b, 80, 08, 0d, 00, 00]
ITERATION 903 0xffffffff8132ebc7 0x11114000 | __lock_acquire.isra.0+0xf7 (0xffffffff8132ebc7)              
    mov dword ptr [rbp-0x38], eax 
    [RBP:0xffffc90000a1fe88+0xffffffffffffffc8=0x1ffffc90000a1fe50]] 
    EAX:0x0
    [89, 45, c8]
ITERATION 904 0xffffffff8132ebca 0x11114000 | __lock_acquire.isra.0+0xfa (0xffffffff8132ebca)              
    mov rax, 0xdffffc0000000000 
    RAX:0x0
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 905 0xffffffff8132ebd4 0x11114000 | __lock_acquire.isra.0+0x104 (0xffffffff8132ebd4)             
    movzx edx, byte ptr [rdx+rax] 
    EDX:0xf0c1703c
    [RDX:0x1ffffffff0c1703c+RAX:0xdffffc0000000000=0xfffffbfff0c1703csize:UInt8->0x4]] 
    [0f, b6, 14, 02]
ITERATION 906 0xffffffff8132ebd8 0x11114000 | __lock_acquire.isra.0+0x108 (0xffffffff8132ebd8)             
    mov rax, 0xffffffff860b81e0 
    RAX:0xdffffc0000000000
    ??_Immediate32to64_?? [48, c7, c0, e0, 81, 0b, 86]
ITERATION 907 0xffffffff8132ebdf 0x11114000 | __lock_acquire.isra.0+0x10f (0xffffffff8132ebdf)             
    and eax, 0x7 
    EAX:0x860b81e0
    ??_Immediate8to32_?? [83, e0, 07]
ITERATION 908 0xffffffff8132ebe2 0x11114000 | __lock_acquire.isra.0+0x112 (0xffffffff8132ebe2)             
    add eax, 0x3 
    EAX:0x0
    ??_Immediate8to32_?? [83, c0, 03]
ITERATION 909 0xffffffff8132ebe5 0x11114000 | __lock_acquire.isra.0+0x115 (0xffffffff8132ebe5)             
    cmp al, dl 
    AL:0x3
    DL:0x4
    [38, d0]
ITERATION 910 0xffffffff8132ebe7 0x11114000 | __lock_acquire.isra.0+0x117 (0xffffffff8132ebe7)             
    jl 0xa 
    ??_NearBranch64_?? [7c, 08]
ITERATION 911 0xffffffff8132ebf1 0x11114000 | __lock_acquire.isra.0+0x121 (0xffffffff8132ebf1)             
    cmp dword ptr [rbp-0x38], 0x2f 
    [RBP:0xffffc90000a1fe88+0xffffffffffffffc8=0xffffc90000a1fe50size:UInt32->0x0]] 
    ??_Immediate8to32_?? [83, 7d, c8, 2f]
ITERATION 912 0xffffffff8132ebf5 0x11114000 | __lock_acquire.isra.0+0x125 (0xffffffff8132ebf5)             
    mov r8d, dword ptr [rip+0x4d895e4] 
    R8D:0x0
    [RIP:0xffffffff8132ebf5+0x4d895eb=0xffffffff860b81e0size:UInt32->0x0]] 
    [44, 8b, 05, e4, 95, d8, 04]
ITERATION 913 0xffffffff8132ebfc 0x11114000 | __lock_acquire.isra.0+0x12c (0xffffffff8132ebfc)             
    jbe 0xb 
    ??_NearBranch64_?? [76, 09]
ITERATION 914 0xffffffff8132ec07 0x11114000 | __lock_acquire.isra.0+0x137 (0xffffffff8132ec07)             
    mov edx, dword ptr [rbp-0x38] 
    EDX:0x4
    [RBP:0xffffc90000a1fe88+0xffffffffffffffc8=0xffffc90000a1fe50size:UInt32->0x0]] 
    [8b, 55, c8]
ITERATION 915 0xffffffff8132ec0a 0x11114000 | __lock_acquire.isra.0+0x13a (0xffffffff8132ec0a)             
    mov rax, qword ptr [rbp-0x30] 
    RAX:0x3
    [RBP:0xffffc90000a1fe88+0xffffffffffffffd0=0xffffc90000a1fe58size:UInt64->0xffff888007674300]] 
    [48, 8b, 45, d0]
ITERATION 916 0xffffffff8132ec0e 0x11114000 | __lock_acquire.isra.0+0x13e (0xffffffff8132ec0e)             
    lea r10, [rdx+rdx*4] 
    R10:[34m__cpu_online_mask+0x7 (0xffffffff8588a0e7)[39m -> 0x0
    [RDX:0x0+RDX:0x0*0x4] 
    [4c, 8d, 14, 92]
ITERATION 917 0xffffffff8132ec12 0x11114000 | __lock_acquire.isra.0+0x142 (0xffffffff8132ec12)             
    add rax, 0xd10 
    RAX:0xffff888007674300 -> 0x0
    ??_Immediate32to64_?? [48, 05, 10, 0d, 00, 00]
ITERATION 918 0xffffffff8132ec18 0x11114000 | __lock_acquire.isra.0+0x148 (0xffffffff8132ec18)             
    lea r15, [r10*8] 
    R15:0x2
    [None:0x0+R10:0x0*0x8] 
    [4e, 8d, 3c, d5, 00, 00, 00, 00]
ITERATION 919 0xffffffff8132ec20 0x11114000 | __lock_acquire.isra.0+0x150 (0xffffffff8132ec20)             
    test edx, edx 
    EDX:0x0
    EDX:0x0
    [85, d2]
ITERATION 920 0xffffffff8132ec22 0x11114000 | __lock_acquire.isra.0+0x152 (0xffffffff8132ec22)             
    je 0x45 
    ??_NearBranch64_?? [74, 43]
ITERATION 921 0xffffffff8132ec67 0x11114000 | __lock_acquire.isra.0+0x197 (0xffffffff8132ec67)             
    add r15, rax 
    R15:0x0
    RAX:0xffff888007675010 -> 0xffffffffffffffff
    [49, 01, c7]
ITERATION 922 0xffffffff8132ec6a 0x11114000 | __lock_acquire.isra.0+0x19a (0xffffffff8132ec6a)             
    mov eax, r14d 
    EAX:0x7675010
    R14D:0x2
    [44, 89, f0]
ITERATION 923 0xffffffff8132ec6d 0x11114000 | __lock_acquire.isra.0+0x19d (0xffffffff8132ec6d)             
    and ax, 0x1fff 
    AX:0x2
    ??_Immediate16_?? [66, 25, ff, 1f]
ITERATION 924 0xffffffff8132ec71 0x11114000 | __lock_acquire.isra.0+0x1a1 (0xffffffff8132ec71)             
    mov word ptr [rbp-0x40], ax 
    [RBP:0xffffc90000a1fe88+0xffffffffffffffc0=0x1ffffc90000a1fe48]] 
    AX:0x2
    [66, 89, 45, c0]
ITERATION 925 0xffffffff8132ec75 0x11114000 | __lock_acquire.isra.0+0x1a5 (0xffffffff8132ec75)             
    lea rax, [r15+0x20] 
    RAX:0x2
    [R15:0xffff888007675010+0x20=0xffff888007675030]] 
    [49, 8d, 47, 20]
ITERATION 926 0xffffffff8132ec79 0x11114000 | __lock_acquire.isra.0+0x1a9 (0xffffffff8132ec79)             
    mov rdx, rax 
    RDX:0x0
    RAX:0xffff888007675030 -> 0x18179
    [48, 89, c2]
ITERATION 927 0xffffffff8132ec7c 0x11114000 | __lock_acquire.isra.0+0x1ac (0xffffffff8132ec7c)             
    mov qword ptr [rbp-0x68], rax 
    [RBP:0xffffc90000a1fe88+0xffffffffffffff98=0x1ffffc90000a1fe20]] 
    RAX:0xffff888007675030 -> 0x18179
    [48, 89, 45, 98]
ITERATION 928 0xffffffff8132ec80 0x11114000 | __lock_acquire.isra.0+0x1b0 (0xffffffff8132ec80)             
    mov rax, 0xdffffc0000000000 
    RAX:0xffff888007675030 -> 0x18179
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 929 0xffffffff8132ec8a 0x11114000 | __lock_acquire.isra.0+0x1ba (0xffffffff8132ec8a)             
    shr rdx, 0x3 
    RDX:0xffff888007675030 -> 0x18179
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 930 0xffffffff8132ec8e 0x11114000 | __lock_acquire.isra.0+0x1be (0xffffffff8132ec8e)             
    movzx eax, byte ptr [rdx+rax] 
    EAX:0x0
    [RDX:0x1ffff11000ecea06+RAX:0xdffffc0000000000=0xffffed1000ecea06size:UInt8->0x0]] 
    [0f, b6, 04, 02]
ITERATION 931 0xffffffff8132ec92 0x11114000 | __lock_acquire.isra.0+0x1c2 (0xffffffff8132ec92)             
    test al, al 
    AL:0x0
    AL:0x0
    [84, c0]
ITERATION 932 0xffffffff8132ec94 0x11114000 | __lock_acquire.isra.0+0x1c4 (0xffffffff8132ec94)             
    je 0xa 
    ??_NearBranch64_?? [74, 08]
ITERATION 933 0xffffffff8132ec9e 0x11114000 | __lock_acquire.isra.0+0x1ce (0xffffffff8132ec9e)             
    movzx eax, word ptr [r15+0x20] 
    EAX:0x0
    [R15:0xffff888007675010+0x20=0xffff888007675030size:UInt16->0x8179]] 
    [41, 0f, b7, 47, 20]
ITERATION 934 0xffffffff8132eca3 0x11114000 | __lock_acquire.isra.0+0x1d3 (0xffffffff8132eca3)             
    lea rdi, [r15+0x8] 
    RDI:[34mrcu_lock_map+0x8 (0xffffffff8505b588)[39m -> [34mlock_classes+0x180 (0xffffffff85d2b640)[39m -> 0x0
    [R15:0xffff888007675010+0x8=0xffff888007675018]] 
    [49, 8d, 7f, 08]
ITERATION 935 0xffffffff8132eca7 0x11114000 | __lock_acquire.isra.0+0x1d7 (0xffffffff8132eca7)             
    mov rdx, rdi 
    RDX:0x1ffff11000ecea06
    RDI:0xffff888007675018 -> [34mdo_user_addr_fault+0x1fd (0xffffffff8118039d)[39m -> 'D'
    [48, 89, fa]
ITERATION 936 0xffffffff8132ecaa 0x11114000 | __lock_acquire.isra.0+0x1da (0xffffffff8132ecaa)             
    and ax, 0xe000 
    AX:0x8179
    ??_Immediate16_?? [66, 25, 00, e0]
ITERATION 937 0xffffffff8132ecae 0x11114000 | __lock_acquire.isra.0+0x1de (0xffffffff8132ecae)             
    or ax, word ptr [rbp-0x40] 
    AX:0x8000
    [RBP:0xffffc90000a1fe88+0xffffffffffffffc0=0xffffc90000a1fe48size:UInt16->0x2]] 
    [66, 0b, 45, c0]
ITERATION 938 0xffffffff8132ecb2 0x11114000 | __lock_acquire.isra.0+0x1e2 (0xffffffff8132ecb2)             
    shr rdx, 0x3 
    RDX:0xffff888007675018 -> [34mdo_user_addr_fault+0x1fd (0xffffffff8118039d)[39m -> 'D'
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 939 0xffffffff8132ecb6 0x11114000 | __lock_acquire.isra.0+0x1e6 (0xffffffff8132ecb6)             
    mov word ptr [r15+0x20], ax 
    [R15:0xffff888007675010+0x20=0xffff888007675030]] 
    AX:0x8002
    [66, 41, 89, 47, 20]
ITERATION 940 0xffffffff8132ecbb 0x11114000 | __lock_acquire.isra.0+0x1eb (0xffffffff8132ecbb)             
    mov rax, 0xdffffc0000000000 
    RAX:0x8002
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 941 0xffffffff8132ecc5 0x11114000 | __lock_acquire.isra.0+0x1f5 (0xffffffff8132ecc5)             
    cmp byte ptr [rdx+rax], 0x0 
    [RDX:0x1ffff11000ecea03+RAX:0xdffffc0000000000=0xffffed1000ecea03size:UInt8->0x0]] 
    ??_Immediate8_?? [80, 3c, 02, 00]
ITERATION 942 0xffffffff8132ecc9 0x11114000 | __lock_acquire.isra.0+0x1f9 (0xffffffff8132ecc9)             
    jne 0xa6a 
    ??_NearBranch64_?? [0f, 85, 64, 0a, 00, 00]
ITERATION 943 0xffffffff8132eccf 0x11114000 | __lock_acquire.isra.0+0x1ff (0xffffffff8132eccf)             
    mov rax, qword ptr [rbp+0x10] 
    RAX:0xdffffc0000000000
    [RBP:0xffffc90000a1fe88+0x10=0xffffc90000a1fe98size:UInt64->0xffffffff8123f735]] 
    [48, 8b, 45, 10]
ITERATION 944 0xffffffff8132ecd3 0x11114000 | __lock_acquire.isra.0+0x203 (0xffffffff8132ecd3)             
    lea rdi, [r15+0x10] 
    RDI:0xffff888007675018 -> [34mdo_user_addr_fault+0x1fd (0xffffffff8118039d)[39m -> 'D'
    [R15:0xffff888007675010+0x10=0xffff888007675020]] 
    [49, 8d, 7f, 10]
ITERATION 945 0xffffffff8132ecd7 0x11114000 | __lock_acquire.isra.0+0x207 (0xffffffff8132ecd7)             
    mov rdx, rdi 
    RDX:0x1ffff11000ecea03
    RDI:0xffff888007675020 -> 0xffff8880112d2b28 -> [34muv_hub_nmi_list+0x480 (0xffffffff85cd6ea0)[39m -> 0x0
    [48, 89, fa]
ITERATION 946 0xffffffff8132ecda 0x11114000 | __lock_acquire.isra.0+0x20a (0xffffffff8132ecda)             
    mov qword ptr [r15+0x8], rax 
    [R15:0xffff888007675010+0x8=0xffff888007675018]] 
    RAX:[34m__task_pid_nr_ns+0x5 (0xffffffff8123f735)[39m -> 0x7ede064305ff6555
    [49, 89, 47, 08]
ITERATION 947 0xffffffff8132ecde 0x11114000 | __lock_acquire.isra.0+0x20e (0xffffffff8132ecde)             
    shr rdx, 0x3 
    RDX:0xffff888007675020 -> 0xffff8880112d2b28 -> [34muv_hub_nmi_list+0x480 (0xffffffff85cd6ea0)[39m -> 0x0
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 948 0xffffffff8132ece2 0x11114000 | __lock_acquire.isra.0+0x212 (0xffffffff8132ece2)             
    mov rax, 0xdffffc0000000000 
    RAX:[34m__task_pid_nr_ns+0x5 (0xffffffff8123f735)[39m -> 0x7ede064305ff6555
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 949 0xffffffff8132ecec 0x11114000 | __lock_acquire.isra.0+0x21c (0xffffffff8132ecec)             
    cmp byte ptr [rdx+rax], 0x0 
    [RDX:0x1ffff11000ecea04+RAX:0xdffffc0000000000=0xffffed1000ecea04size:UInt8->0x0]] 
    ??_Immediate8_?? [80, 3c, 02, 00]
ITERATION 950 0xffffffff8132ecf0 0x11114000 | __lock_acquire.isra.0+0x220 (0xffffffff8132ecf0)             
    jne 0xaa4 
    ??_NearBranch64_?? [0f, 85, 9e, 0a, 00, 00]
ITERATION 951 0xffffffff8132ecf6 0x11114000 | __lock_acquire.isra.0+0x226 (0xffffffff8132ecf6)             
    lea rax, [r15+0x18] 
    RAX:0xdffffc0000000000
    [R15:0xffff888007675010+0x18=0xffff888007675028]] 
    [49, 8d, 47, 18]
ITERATION 952 0xffffffff8132ecfa 0x11114000 | __lock_acquire.isra.0+0x22a (0xffffffff8132ecfa)             
    mov qword ptr [r15+0x10], r13 
    [R15:0xffff888007675010+0x10=0xffff888007675020]] 
    R13:[34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    [4d, 89, 6f, 10]
ITERATION 953 0xffffffff8132ecfe 0x11114000 | __lock_acquire.isra.0+0x22e (0xffffffff8132ecfe)             
    mov rdx, rax 
    RDX:0x1ffff11000ecea04
    RAX:0xffff888007675028 -> 0x0
    [48, 89, c2]
ITERATION 954 0xffffffff8132ed01 0x11114000 | __lock_acquire.isra.0+0x231 (0xffffffff8132ed01)             
    mov qword ptr [rbp-0x80], rax 
    [RBP:0xffffc90000a1fe88+0xffffffffffffff80=0x1ffffc90000a1fe08]] 
    RAX:0xffff888007675028 -> 0x0
    [48, 89, 45, 80]
ITERATION 955 0xffffffff8132ed05 0x11114000 | __lock_acquire.isra.0+0x235 (0xffffffff8132ed05)             
    mov rax, 0xdffffc0000000000 
    RAX:0xffff888007675028 -> 0x0
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 956 0xffffffff8132ed0f 0x11114000 | __lock_acquire.isra.0+0x23f (0xffffffff8132ed0f)             
    shr rdx, 0x3 
    RDX:0xffff888007675028 -> 0x0
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 957 0xffffffff8132ed13 0x11114000 | __lock_acquire.isra.0+0x243 (0xffffffff8132ed13)             
    cmp byte ptr [rdx+rax], 0x0 
    [RDX:0x1ffff11000ecea05+RAX:0xdffffc0000000000=0xffffed1000ecea05size:UInt8->0x0]] 
    ??_Immediate8_?? [80, 3c, 02, 00]
ITERATION 958 0xffffffff8132ed17 0x11114000 | __lock_acquire.isra.0+0x247 (0xffffffff8132ed17)             
    jne 0xa5f 
    ??_NearBranch64_?? [0f, 85, 59, 0a, 00, 00]
ITERATION 959 0xffffffff8132ed1d 0x11114000 | __lock_acquire.isra.0+0x24d (0xffffffff8132ed1d)             
    mov eax, ebx 
    EAX:0x0
    EBX:0x2
    [89, d8]
ITERATION 960 0xffffffff8132ed1f 0x11114000 | __lock_acquire.isra.0+0x24f (0xffffffff8132ed1f)             
    mov edx, dword ptr [rbp-0x48] 
    EDX:0xecea05
    [RBP:0xffffc90000a1fe88+0xffffffffffffffb8=0xffffc90000a1fe40size:UInt32->0x0]] 
    [8b, 55, b8]
ITERATION 961 0xffffffff8132ed22 0x11114000 | __lock_acquire.isra.0+0x252 (0xffffffff8132ed22)             
    lea rdi, [r15+0x24] 
    RDI:0xffff888007675020 -> [34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    [R15:0xffff888007675010+0x24=0xffff888007675034]] 
    [49, 8d, 7f, 24]
ITERATION 962 0xffffffff8132ed26 0x11114000 | __lock_acquire.isra.0+0x256 (0xffffffff8132ed26)             
    mov qword ptr [r15+0x18], r12 
    [R15:0xffff888007675010+0x18=0xffff888007675028]] 
    R12:0x0
    [4d, 89, 67, 18]
ITERATION 963 0xffffffff8132ed2a 0x11114000 | __lock_acquire.isra.0+0x25a (0xffffffff8132ed2a)             
    and eax, 0x3 
    EAX:0x2
    ??_Immediate8to32_?? [83, e0, 03]
ITERATION 964 0xffffffff8132ed2d 0x11114000 | __lock_acquire.isra.0+0x25d (0xffffffff8132ed2d)             
    mov byte ptr [rbp-0x60], al 
    [RBP:0xffffc90000a1fe88+0xffffffffffffffa0=0x1ffffc90000a1fe28]] 
    AL:0x2
    [88, 45, a0]
ITERATION 965 0xffffffff8132ed30 0x11114000 | __lock_acquire.isra.0+0x260 (0xffffffff8132ed30)             
    mov eax, ebx 
    EAX:0x2
    EBX:0x2
    [89, d8]
ITERATION 966 0xffffffff8132ed32 0x11114000 | __lock_acquire.isra.0+0x262 (0xffffffff8132ed32)             
    shl edx, 0xf 
    EDX:0x0
    ??_Immediate8_?? [c1, e2, 0f]
ITERATION 967 0xffffffff8132ed35 0x11114000 | __lock_acquire.isra.0+0x265 (0xffffffff8132ed35)             
    shl eax, 0x10 
    EAX:0x2
    ??_Immediate8_?? [c1, e0, 10]
ITERATION 968 0xffffffff8132ed38 0x11114000 | __lock_acquire.isra.0+0x268 (0xffffffff8132ed38)             
    movzx ebx, dx 
    EBX:0x2
    DX:0x0
    [0f, b7, da]
ITERATION 969 0xffffffff8132ed3b 0x11114000 | __lock_acquire.isra.0+0x26b (0xffffffff8132ed3b)             
    mov edx, dword ptr [r15+0x20] 
    EDX:0x0
    [R15:0xffff888007675010+0x20=0xffff888007675030size:UInt32->0x18002]] 
    [41, 8b, 57, 20]
ITERATION 970 0xffffffff8132ed3f 0x11114000 | __lock_acquire.isra.0+0x26f (0xffffffff8132ed3f)             
    and eax, 0x30000 
    EAX:0x20000
    ??_Immediate32_?? [25, 00, 00, 03, 00]
ITERATION 971 0xffffffff8132ed44 0x11114000 | __lock_acquire.isra.0+0x274 (0xffffffff8132ed44)             
    or eax, ebx 
    EAX:0x20000
    EBX:0x0
    [09, d8]
ITERATION 972 0xffffffff8132ed46 0x11114000 | __lock_acquire.isra.0+0x276 (0xffffffff8132ed46)             
    mov ebx, dword ptr [rbp-0x50] 
    EBX:0x0
    [RBP:0xffffc90000a1fe88+0xffffffffffffffb0=0xffffc90000a1fe38size:UInt32->0x0]] 
    [8b, 5d, b0]
ITERATION 973 0xffffffff8132ed49 0x11114000 | __lock_acquire.isra.0+0x279 (0xffffffff8132ed49)             
    and edx, 0x1fff 
    EDX:0x18002
    ??_Immediate32_?? [81, e2, ff, 1f, 00, 00]
ITERATION 974 0xffffffff8132ed4f 0x11114000 | __lock_acquire.isra.0+0x27f (0xffffffff8132ed4f)             
    shl ebx, 0x13 
    EBX:0x0
    ??_Immediate8_?? [c1, e3, 13]
ITERATION 975 0xffffffff8132ed52 0x11114000 | __lock_acquire.isra.0+0x282 (0xffffffff8132ed52)             
    or eax, ebx 
    EAX:0x20000
    EBX:0x0
    [09, d8]
ITERATION 976 0xffffffff8132ed54 0x11114000 | __lock_acquire.isra.0+0x284 (0xffffffff8132ed54)             
    mov ebx, dword ptr [rbp+0x18] 
    EBX:0x0
    [RBP:0xffffc90000a1fe88+0x18=0xffffc90000a1fea0size:UInt32->0x0]] 
    [8b, 5d, 18]
ITERATION 977 0xffffffff8132ed57 0x11114000 | __lock_acquire.isra.0+0x287 (0xffffffff8132ed57)             
    shl ebx, 0x14 
    EBX:0x0
    ??_Immediate8_?? [c1, e3, 14]
ITERATION 978 0xffffffff8132ed5a 0x11114000 | __lock_acquire.isra.0+0x28a (0xffffffff8132ed5a)             
    or eax, ebx 
    EAX:0x20000
    EBX:0x0
    [09, d8]
ITERATION 979 0xffffffff8132ed5c 0x11114000 | __lock_acquire.isra.0+0x28c (0xffffffff8132ed5c)             
    or eax, edx 
    EAX:0x20000
    EDX:0x2
    [09, d0]
ITERATION 980 0xffffffff8132ed5e 0x11114000 | __lock_acquire.isra.0+0x28e (0xffffffff8132ed5e)             
    mov rdx, rdi 
    RDX:0x2
    RDI:0xffff888007675034 -> 0x7c1fc5a200000000
    [48, 89, fa]
ITERATION 981 0xffffffff8132ed61 0x11114000 | __lock_acquire.isra.0+0x291 (0xffffffff8132ed61)             
    mov dword ptr [r15+0x20], eax 
    [R15:0xffff888007675010+0x20=0xffff888007675030]] 
    EAX:0x20002
    [41, 89, 47, 20]
ITERATION 982 0xffffffff8132ed65 0x11114000 | __lock_acquire.isra.0+0x295 (0xffffffff8132ed65)             
    shr rdx, 0x3 
    RDX:0xffff888007675034 -> 0x7c1fc5a200000000
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 983 0xffffffff8132ed69 0x11114000 | __lock_acquire.isra.0+0x299 (0xffffffff8132ed69)             
    mov rax, 0xdffffc0000000000 
    RAX:0x20002
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 984 0xffffffff8132ed73 0x11114000 | __lock_acquire.isra.0+0x2a3 (0xffffffff8132ed73)             
    movzx edx, byte ptr [rdx+rax] 
    EDX:0xecea06
    [RDX:0x1ffff11000ecea06+RAX:0xdffffc0000000000=0xffffed1000ecea06size:UInt8->0x0]] 
    [0f, b6, 14, 02]
ITERATION 985 0xffffffff8132ed77 0x11114000 | __lock_acquire.isra.0+0x2a7 (0xffffffff8132ed77)             
    mov rax, rdi 
    RAX:0xdffffc0000000000
    RDI:0xffff888007675034 -> 0x7c1fc5a200000000
    [48, 89, f8]
ITERATION 986 0xffffffff8132ed7a 0x11114000 | __lock_acquire.isra.0+0x2aa (0xffffffff8132ed7a)             
    and eax, 0x7 
    EAX:0x7675034
    ??_Immediate8to32_?? [83, e0, 07]
ITERATION 987 0xffffffff8132ed7d 0x11114000 | __lock_acquire.isra.0+0x2ad (0xffffffff8132ed7d)             
    add eax, 0x3 
    EAX:0x4
    ??_Immediate8to32_?? [83, c0, 03]
ITERATION 988 0xffffffff8132ed80 0x11114000 | __lock_acquire.isra.0+0x2b0 (0xffffffff8132ed80)             
    cmp al, dl 
    AL:0x7
    DL:0x0
    [38, d0]
ITERATION 989 0xffffffff8132ed82 0x11114000 | __lock_acquire.isra.0+0x2b2 (0xffffffff8132ed82)             
    jl 0xa 
    ??_NearBranch64_?? [7c, 08]
ITERATION 990 0xffffffff8132ed84 0x11114000 | __lock_acquire.isra.0+0x2b4 (0xffffffff8132ed84)             
    test dl, dl 
    DL:0x0
    DL:0x0
    [84, d2]
ITERATION 991 0xffffffff8132ed86 0x11114000 | __lock_acquire.isra.0+0x2b6 (0xffffffff8132ed86)             
    jne 0x7ef 
    ??_NearBranch64_?? [0f, 85, e9, 07, 00, 00]
ITERATION 992 0xffffffff8132ed8c 0x11114000 | __lock_acquire.isra.0+0x2bc (0xffffffff8132ed8c)             
    mov eax, dword ptr [rbp+0x20] 
    EAX:0x7
    [RBP:0xffffc90000a1fe88+0x20=0xffffc90000a1fea8size:UInt32->0x0]] 
    [8b, 45, 20]
ITERATION 993 0xffffffff8132ed8f 0x11114000 | __lock_acquire.isra.0+0x2bf (0xffffffff8132ed8f)             
    mov dword ptr [r15+0x24], eax 
    [R15:0xffff888007675010+0x24=0xffff888007675034]] 
    EAX:0x0
    [41, 89, 47, 24]
ITERATION 994 0xffffffff8132ed93 0x11114000 | __lock_acquire.isra.0+0x2c3 (0xffffffff8132ed93)             
    test r8d, r8d 
    R8D:0x0
    R8D:0x0
    [45, 85, c0]
ITERATION 995 0xffffffff8132ed96 0x11114000 | __lock_acquire.isra.0+0x2c6 (0xffffffff8132ed96)             
    je 0x36d 
    ??_NearBranch64_?? [0f, 84, 67, 03, 00, 00]
ITERATION 996 0xffffffff8132f103 0x11114000 | __lock_acquire.isra.0+0x633 (0xffffffff8132f103)             
    test r11, r11 
    R11:0x2
    R11:0x2
    [4d, 85, db]
ITERATION 997 0xffffffff8132f106 0x11114000 | __lock_acquire.isra.0+0x636 (0xffffffff8132f106)             
    lea rax, [r11+0x3f] 
    RAX:0x0
    [R11:0x2+0x3f=0x41]] 
    [49, 8d, 43, 3f]
ITERATION 998 0xffffffff8132f10a 0x11114000 | __lock_acquire.isra.0+0x63a (0xffffffff8132f10a)             
    mov esi, 0x8 
    ESI:0x0
    ??_Immediate32_?? [be, 08, 00, 00, 00]
ITERATION 999 0xffffffff8132f10f 0x11114000 | __lock_acquire.isra.0+0x63f (0xffffffff8132f10f)             
    mov qword ptr [rbp-0x40], r11 
    [RBP:0xffffc90000a1fe88+0xffffffffffffffc0=0x1ffffc90000a1fe48]] 
    R11:0x2
    [4c, 89, 5d, c0]
ITERATION 1000 0xffffffff8132f113 0x11114000 | __lock_acquire.isra.0+0x643 (0xffffffff8132f113)             
    cmovns rax, r11 
    RAX:0x41
    R11:0x2
    [49, 0f, 49, c3]
ITERATION 1001 0xffffffff8132f117 0x11114000 | __lock_acquire.isra.0+0x647 (0xffffffff8132f117)             
    sar rax, 0x6 
    RAX:0x2
    ??_Immediate8_?? [48, c1, f8, 06]
ITERATION 1002 0xffffffff8132f11b 0x11114000 | __lock_acquire.isra.0+0x64b (0xffffffff8132f11b)             
    lea rdi, [rax*8-0x7a2d4f60] 
    RDI:0xffff888007675034 -> 0x7c1fc5a200000000
    [None:0x0+RAX:0x0*0x8+0xffffffff85d2b0a0=0xffffffff85d2b0a0]] 
    [48, 8d, 3c, c5, a0, b0, d2, 85]
ITERATION 1003 0xffffffff8132f123 0x11114000 | __lock_acquire.isra.0+0x653 (0xffffffff8132f123)             
    call 0x60cc1d 
    ??_NearBranch64_?? [e8, 18, cc, 60, 00]
ITERATION 1004 0xffffffff8193bd40 0x11114000 | __kasan_check_read+0x0 (0xffffffff8193bd40)                  
    push rbp 
    RBP:0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [55]
ITERATION 1005 0xffffffff8193bd41 0x11114000 | __kasan_check_read+0x1 (0xffffffff8193bd41)                  
    mov esi, esi 
    ESI:0x8
    ESI:0x8
    [89, f6]
ITERATION 1006 0xffffffff8193bd43 0x11114000 | __kasan_check_read+0x3 (0xffffffff8193bd43)                  
    xor edx, edx 
    EDX:0x0
    EDX:0x0
    [31, d2]
ITERATION 1007 0xffffffff8193bd45 0x11114000 | __kasan_check_read+0x5 (0xffffffff8193bd45)                  
    mov rbp, rsp 
    RBP:0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    RSP:0xffffc90000a1fdf8 -> 0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [48, 89, e5]
ITERATION 1008 0xffffffff8193bd48 0x11114000 | __kasan_check_read+0x8 (0xffffffff8193bd48)                  
    mov rcx, qword ptr [rbp+0x8] 
    RCX:0x2
    [RBP:0xffffc90000a1fdf8+0x8=0xffffc90000a1fe00size:UInt64->0xffffffff8132f128]] 
    [48, 8b, 4d, 08]
ITERATION 1009 0xffffffff8193bd4c 0x11114000 | __kasan_check_read+0xc (0xffffffff8193bd4c)                  
    call 0xfffffffffffff784 
    ??_NearBranch64_?? [e8, 7f, f7, ff, ff]
ITERATION 1010 0xffffffff8193b4d0 0x11114000 | kasan_check_range+0x0 (0xffffffff8193b4d0)                   
    test rsi, rsi 
    RSI:0x8
    RSI:0x8
    [48, 85, f6]
ITERATION 1011 0xffffffff8193b4d3 0x11114000 | kasan_check_range+0x3 (0xffffffff8193b4d3)                   
    je 0x199 
    ??_NearBranch64_?? [0f, 84, 93, 01, 00, 00]
ITERATION 1012 0xffffffff8193b4d9 0x11114000 | kasan_check_range+0x9 (0xffffffff8193b4d9)                   
    push rbp 
    RBP:0xffffc90000a1fdf8 -> 0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [55]
ITERATION 1013 0xffffffff8193b4da 0x11114000 | kasan_check_range+0xa (0xffffffff8193b4da)                   
    mov r10, rdi 
    R10:0x0
    RDI:[34mlock_classes_in_use+0x0 (0xffffffff85d2b0a0)[39m -> 0xffffffffffffffff
    [49, 89, fa]
ITERATION 1014 0xffffffff8193b4dd 0x11114000 | kasan_check_range+0xd (0xffffffff8193b4dd)                   
    movzx edx, dl 
    EDX:0x0
    DL:0x0
    [0f, b6, d2]
ITERATION 1015 0xffffffff8193b4e0 0x11114000 | kasan_check_range+0x10 (0xffffffff8193b4e0)                  
    mov rbp, rsp 
    RBP:0xffffc90000a1fdf8 -> 0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    RSP:0xffffc90000a1fde8 -> 0xffffc90000a1fdf8 -> 0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 ... 
    [48, 89, e5]
ITERATION 1016 0xffffffff8193b4e3 0x11114000 | kasan_check_range+0x13 (0xffffffff8193b4e3)                  
    push r13 
    R13:[34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    [41, 55]
ITERATION 1017 0xffffffff8193b4e5 0x11114000 | kasan_check_range+0x15 (0xffffffff8193b4e5)                  
    push r12 
    R12:0x0
    [41, 54]
ITERATION 1018 0xffffffff8193b4e7 0x11114000 | kasan_check_range+0x17 (0xffffffff8193b4e7)                  
    push rbx 
    RBX:0x0
    [53]
ITERATION 1019 0xffffffff8193b4e8 0x11114000 | kasan_check_range+0x18 (0xffffffff8193b4e8)                  
    add r10, rsi 
    R10:[34mlock_classes_in_use+0x0 (0xffffffff85d2b0a0)[39m -> 0xffffffffffffffff
    RSI:0x8
    [49, 01, f2]
ITERATION 1020 0xffffffff8193b4eb 0x11114000 | kasan_check_range+0x1b (0xffffffff8193b4eb)                  
    jb 0x16c 
    ??_NearBranch64_?? [0f, 82, 66, 01, 00, 00]
ITERATION 1021 0xffffffff8193b4f1 0x11114000 | kasan_check_range+0x21 (0xffffffff8193b4f1)                  
    jmp 0xc2 
    ??_NearBranch64_?? [e9, bd, 00, 00, 00]
ITERATION 1022 0xffffffff8193b5b3 0x11114000 | kasan_check_range+0xe3 (0xffffffff8193b5b3)                  
    mov rax, 0xffff800000000000 
    RAX:0x0
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, 80, ff, ff]
ITERATION 1023 0xffffffff8193b5bd 0x11114000 | kasan_check_range+0xed (0xffffffff8193b5bd)                  
    jmp 0xffffffffffffff43 
    ??_NearBranch64_?? [e9, 3e, ff, ff, ff]
ITERATION 1024 0xffffffff8193b500 0x11114000 | kasan_check_range+0x30 (0xffffffff8193b500)                  
    cmp rax, rdi 
    RAX:0xffff800000000000
    RDI:[34mlock_classes_in_use+0x0 (0xffffffff85d2b0a0)[39m -> 0xffffffffffffffff
    [48, 39, f8]
ITERATION 1025 0xffffffff8193b503 0x11114000 | kasan_check_range+0x33 (0xffffffff8193b503)                  
    ja 0x154 
    ??_NearBranch64_?? [0f, 87, 4e, 01, 00, 00]
ITERATION 1026 0xffffffff8193b509 0x11114000 | kasan_check_range+0x39 (0xffffffff8193b509)                  
    sub r10, 0x1 
    R10:[34mlock_classes_in_use+0x8 (0xffffffff85d2b0a8)[39m -> 0xffffffffffffffff
    ??_Immediate8to64_?? [49, 83, ea, 01]
ITERATION 1027 0xffffffff8193b50d 0x11114000 | kasan_check_range+0x3d (0xffffffff8193b50d)                  
    mov r8, rdi 
    R8:0x0
    RDI:[34mlock_classes_in_use+0x0 (0xffffffff85d2b0a0)[39m -> 0xffffffffffffffff
    [49, 89, f8]
ITERATION 1028 0xffffffff8193b510 0x11114000 | kasan_check_range+0x40 (0xffffffff8193b510)                  
    mov rax, 0xdffffc0000000000 
    RAX:0xffff800000000000
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1029 0xffffffff8193b51a 0x11114000 | kasan_check_range+0x4a (0xffffffff8193b51a)                  
    mov r11, r10 
    R11:0x2
    R10:[34mlock_classes_in_use+0x7 (0xffffffff85d2b0a7)[39m -> 0xffffffffffffffff
    [4d, 89, d3]
ITERATION 1030 0xffffffff8193b51d 0x11114000 | kasan_check_range+0x4d (0xffffffff8193b51d)                  
    shr r8, 0x3 
    R8:[34mlock_classes_in_use+0x0 (0xffffffff85d2b0a0)[39m -> 0xffffffffffffffff
    ??_Immediate8_?? [49, c1, e8, 03]
ITERATION 1031 0xffffffff8193b521 0x11114000 | kasan_check_range+0x51 (0xffffffff8193b521)                  
    shr r11, 0x3 
    R11:[34mlock_classes_in_use+0x7 (0xffffffff85d2b0a7)[39m -> 0xffffffffffffffff
    ??_Immediate8_?? [49, c1, eb, 03]
ITERATION 1032 0xffffffff8193b525 0x11114000 | kasan_check_range+0x55 (0xffffffff8193b525)                  
    lea r12, [r8+rax] 
    R12:0x0
    [R8:0x1ffffffff0ba5614+RAX:0xdffffc0000000000=0xfffffbfff0ba5614]] 
    [4d, 8d, 24, 00]
ITERATION 1033 0xffffffff8193b529 0x11114000 | kasan_check_range+0x59 (0xffffffff8193b529)                  
    add r11, rax 
    R11:0x1ffffffff0ba5614
    RAX:0xdffffc0000000000
    [49, 01, c3]
ITERATION 1034 0xffffffff8193b52c 0x11114000 | kasan_check_range+0x5c (0xffffffff8193b52c)                  
    mov rax, r12 
    RAX:0xdffffc0000000000
    R12:0xfffffbfff0ba5614 -> 0x0
    [4c, 89, e0]
ITERATION 1035 0xffffffff8193b52f 0x11114000 | kasan_check_range+0x5f (0xffffffff8193b52f)                  
    lea rbx, [r11+0x1] 
    RBX:0x0
    [R11:0xfffffbfff0ba5614+0x1=0xfffffbfff0ba5615]] 
    [49, 8d, 5b, 01]
ITERATION 1036 0xffffffff8193b533 0x11114000 | kasan_check_range+0x63 (0xffffffff8193b533)                  
    mov r9, rbx 
    R9:0x0
    RBX:0xfffffbfff0ba5615 -> 0x0
    [49, 89, d9]
ITERATION 1037 0xffffffff8193b536 0x11114000 | kasan_check_range+0x66 (0xffffffff8193b536)                  
    sub r9, r12 
    R9:0xfffffbfff0ba5615 -> 0x0
    R12:0xfffffbfff0ba5614 -> 0x0
    [4d, 29, e1]
ITERATION 1038 0xffffffff8193b539 0x11114000 | kasan_check_range+0x69 (0xffffffff8193b539)                  
    cmp r9, 0x10 
    R9:0x1
    ??_Immediate8to64_?? [49, 83, f9, 10]
ITERATION 1039 0xffffffff8193b53d 0x11114000 | kasan_check_range+0x6d (0xffffffff8193b53d)                  
    jle 0xde 
    ??_NearBranch64_?? [0f, 8e, d8, 00, 00, 00]
ITERATION 1040 0xffffffff8193b61b 0x11114000 | kasan_check_range+0x14b (0xffffffff8193b61b)                 
    test r9, r9 
    R9:0x1
    R9:0x1
    [4d, 85, c9]
ITERATION 1041 0xffffffff8193b61e 0x11114000 | kasan_check_range+0x14e (0xffffffff8193b61e)                 
    je 0xffffffffffffffed 
    ??_NearBranch64_?? [74, eb]
ITERATION 1042 0xffffffff8193b620 0x11114000 | kasan_check_range+0x150 (0xffffffff8193b620)                 
    add r9, r12 
    R9:0x1
    R12:0xfffffbfff0ba5614 -> 0x0
    [4d, 01, e1]
ITERATION 1043 0xffffffff8193b623 0x11114000 | kasan_check_range+0x153 (0xffffffff8193b623)                 
    jmp 0xb 
    ??_NearBranch64_?? [eb, 09]
ITERATION 1044 0xffffffff8193b62e 0x11114000 | kasan_check_range+0x15e (0xffffffff8193b62e)                 
    cmp byte ptr [rax], 0x0 
    [RAX:0xfffffbfff0ba5614size:UInt8->0x0]] 
    ??_Immediate8_?? [80, 38, 00]
ITERATION 1045 0xffffffff8193b631 0x11114000 | kasan_check_range+0x161 (0xffffffff8193b631)                 
    je 0xfffffffffffffff4 
    ??_NearBranch64_?? [74, f2]
ITERATION 1046 0xffffffff8193b625 0x11114000 | kasan_check_range+0x155 (0xffffffff8193b625)                 
    add rax, 0x1 
    RAX:0xfffffbfff0ba5614 -> 0x0
    ??_Immediate8to64_?? [48, 83, c0, 01]
ITERATION 1047 0xffffffff8193b629 0x11114000 | kasan_check_range+0x159 (0xffffffff8193b629)                 
    cmp rax, r9 
    RAX:0xfffffbfff0ba5615 -> 0x0
    R9:0xfffffbfff0ba5615 -> 0x0
    [4c, 39, c8]
ITERATION 1048 0xffffffff8193b62c 0x11114000 | kasan_check_range+0x15c (0xffffffff8193b62c)                 
    je 0xffffffffffffffdf 
    ??_NearBranch64_?? [74, dd]
ITERATION 1049 0xffffffff8193b60b 0x11114000 | kasan_check_range+0x13b (0xffffffff8193b60b)                 
    mov r8d, 0x1 
    R8D:0xf0ba5614
    ??_Immediate32_?? [41, b8, 01, 00, 00, 00]
ITERATION 1050 0xffffffff8193b611 0x11114000 | kasan_check_range+0x141 (0xffffffff8193b611)                 
    pop rbx 
    RBX:0xfffffbfff0ba5615 -> 0x0
    [5b]
ITERATION 1051 0xffffffff8193b612 0x11114000 | kasan_check_range+0x142 (0xffffffff8193b612)                 
    pop r12 
    R12:0xfffffbfff0ba5614 -> 0x0
    [41, 5c]
ITERATION 1052 0xffffffff8193b614 0x11114000 | kasan_check_range+0x144 (0xffffffff8193b614)                 
    mov eax, r8d 
    EAX:0xf0ba5615
    R8D:0x1
    [44, 89, c0]
ITERATION 1053 0xffffffff8193b617 0x11114000 | kasan_check_range+0x147 (0xffffffff8193b617)                 
    pop r13 
    R13:[34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    [41, 5d]
ITERATION 1054 0xffffffff8193b619 0x11114000 | kasan_check_range+0x149 (0xffffffff8193b619)                 
    pop rbp 
    RBP:0xffffc90000a1fde8 -> 0xffffc90000a1fdf8 -> 0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 ... 
    [5d]
ITERATION 1055 0xffffffff8193b61a 0x11114000 | kasan_check_range+0x14a (0xffffffff8193b61a)                 
    ret 
    [c3]
ITERATION 1056 0xffffffff8193bd51 0x11114000 | __kasan_check_read+0x11 (0xffffffff8193bd51)                 
    pop rbp 
    RBP:0xffffc90000a1fdf8 -> 0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [5d]
ITERATION 1057 0xffffffff8193bd52 0x11114000 | __kasan_check_read+0x12 (0xffffffff8193bd52)                 
    ret 
    [c3]
ITERATION 1058 0xffffffff8132f128 0x11114000 | __lock_acquire.isra.0+0x658 (0xffffffff8132f128)             
    mov r11, qword ptr [rbp-0x40] 
    R11:0xfffffbfff0ba5614 -> 0x0
    [RBP:0xffffc90000a1fe88+0xffffffffffffffc0=0xffffc90000a1fe48size:UInt64->0x2]] 
    [4c, 8b, 5d, c0]
ITERATION 1059 0xffffffff8132f12c 0x11114000 | __lock_acquire.isra.0+0x65c (0xffffffff8132f12c)             
    bt qword ptr [rip+0x49fbf6c], r11 
    [RIP:0xffffffff8132f12c+0x49fbf74=0xffffffff85d2b0a0]] 
    R11:0x2
    [4c, 0f, a3, 1d, 6c, bf, 9f, 04]
ITERATION 1060 0xffffffff8132f134 0x11114000 | __lock_acquire.isra.0+0x664 (0xffffffff8132f134)             
    jae 0x48b 
    ??_NearBranch64_?? [0f, 83, 85, 04, 00, 00]
ITERATION 1061 0xffffffff8132f13a 0x11114000 | __lock_acquire.isra.0+0x66a (0xffffffff8132f13a)             
    mov rax, qword ptr [rbp-0x30] 
    RAX:0x1
    [RBP:0xffffc90000a1fe88+0xffffffffffffffd0=0xffffc90000a1fe58size:UInt64->0xffff888007674300]] 
    [48, 8b, 45, d0]
ITERATION 1062 0xffffffff8132f13e 0x11114000 | __lock_acquire.isra.0+0x66e (0xffffffff8132f13e)             
    add rax, 0xd00 
    RAX:0xffff888007674300 -> 0x0
    ??_Immediate32to64_?? [48, 05, 00, 0d, 00, 00]
ITERATION 1063 0xffffffff8132f144 0x11114000 | __lock_acquire.isra.0+0x674 (0xffffffff8132f144)             
    mov rdx, rax 
    RDX:0x0
    RAX:0xffff888007675000 -> 0xffffffffffffffff
    [48, 89, c2]
ITERATION 1064 0xffffffff8132f147 0x11114000 | __lock_acquire.isra.0+0x677 (0xffffffff8132f147)             
    mov qword ptr [rbp-0x50], rax 
    [RBP:0xffffc90000a1fe88+0xffffffffffffffb0=0x1ffffc90000a1fe38]] 
    RAX:0xffff888007675000 -> 0xffffffffffffffff
    [48, 89, 45, b0]
ITERATION 1065 0xffffffff8132f14b 0x11114000 | __lock_acquire.isra.0+0x67b (0xffffffff8132f14b)             
    mov rax, 0xdffffc0000000000 
    RAX:0xffff888007675000 -> 0xffffffffffffffff
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1066 0xffffffff8132f155 0x11114000 | __lock_acquire.isra.0+0x685 (0xffffffff8132f155)             
    shr rdx, 0x3 
    RDX:0xffff888007675000 -> 0xffffffffffffffff
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1067 0xffffffff8132f159 0x11114000 | __lock_acquire.isra.0+0x689 (0xffffffff8132f159)             
    cmp byte ptr [rdx+rax], 0x0 
    [RDX:0x1ffff11000ecea00+RAX:0xdffffc0000000000=0xffffed1000ecea00size:UInt8->0x0]] 
    ??_Immediate8_?? [80, 3c, 02, 00]
ITERATION 1068 0xffffffff8132f15d 0x11114000 | __lock_acquire.isra.0+0x68d (0xffffffff8132f15d)             
    jne 0x7aa 
    ??_NearBranch64_?? [0f, 85, a4, 07, 00, 00]
ITERATION 1069 0xffffffff8132f163 0x11114000 | __lock_acquire.isra.0+0x693 (0xffffffff8132f163)             
    mov rax, qword ptr [rbp-0x30] 
    RAX:0xdffffc0000000000
    [RBP:0xffffc90000a1fe88+0xffffffffffffffd0=0xffffc90000a1fe58size:UInt64->0xffff888007674300]] 
    [48, 8b, 45, d0]
ITERATION 1070 0xffffffff8132f167 0x11114000 | __lock_acquire.isra.0+0x697 (0xffffffff8132f167)             
    mov rdx, 0xffffffff860b81e0 
    RDX:0x1ffff11000ecea00
    ??_Immediate32to64_?? [48, c7, c2, e0, 81, 0b, 86]
ITERATION 1071 0xffffffff8132f16e 0x11114000 | __lock_acquire.isra.0+0x69e (0xffffffff8132f16e)             
    shr rdx, 0x3 
    RDX:[34moops_in_progress+0x0 (0xffffffff860b81e0)[39m -> 0x0
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1072 0xffffffff8132f172 0x11114000 | __lock_acquire.isra.0+0x6a2 (0xffffffff8132f172)             
    mov rax, qword ptr [rax+0xd00] 
    RAX:0xffff888007674300 -> 0x0
    [RAX:0xffff888007674300+0xd00=0xffff888007675000size:UInt64->0xffffffffffffffff]] 
    [48, 8b, 80, 00, 0d, 00, 00]
ITERATION 1073 0xffffffff8132f179 0x11114000 | __lock_acquire.isra.0+0x6a9 (0xffffffff8132f179)             
    mov qword ptr [rbp-0x48], rax 
    [RBP:0xffffc90000a1fe88+0xffffffffffffffb8=0x1ffffc90000a1fe40]] 
    RAX:0xffffffffffffffff
    [48, 89, 45, b8]
ITERATION 1074 0xffffffff8132f17d 0x11114000 | __lock_acquire.isra.0+0x6ad (0xffffffff8132f17d)             
    mov rax, 0xdffffc0000000000 
    RAX:0xffffffffffffffff
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1075 0xffffffff8132f187 0x11114000 | __lock_acquire.isra.0+0x6b7 (0xffffffff8132f187)             
    movzx edx, byte ptr [rdx+rax] 
    EDX:0xf0c1703c
    [RDX:0x1ffffffff0c1703c+RAX:0xdffffc0000000000=0xfffffbfff0c1703csize:UInt8->0x4]] 
    [0f, b6, 14, 02]
ITERATION 1076 0xffffffff8132f18b 0x11114000 | __lock_acquire.isra.0+0x6bb (0xffffffff8132f18b)             
    mov rax, 0xffffffff860b81e0 
    RAX:0xdffffc0000000000
    ??_Immediate32to64_?? [48, c7, c0, e0, 81, 0b, 86]
ITERATION 1077 0xffffffff8132f192 0x11114000 | __lock_acquire.isra.0+0x6c2 (0xffffffff8132f192)             
    and eax, 0x7 
    EAX:0x860b81e0
    ??_Immediate8to32_?? [83, e0, 07]
ITERATION 1078 0xffffffff8132f195 0x11114000 | __lock_acquire.isra.0+0x6c5 (0xffffffff8132f195)             
    add eax, 0x3 
    EAX:0x0
    ??_Immediate8to32_?? [83, c0, 03]
ITERATION 1079 0xffffffff8132f198 0x11114000 | __lock_acquire.isra.0+0x6c8 (0xffffffff8132f198)             
    cmp al, dl 
    AL:0x3
    DL:0x4
    [38, d0]
ITERATION 1080 0xffffffff8132f19a 0x11114000 | __lock_acquire.isra.0+0x6ca (0xffffffff8132f19a)             
    jl 0xa 
    ??_NearBranch64_?? [7c, 08]
ITERATION 1081 0xffffffff8132f1a4 0x11114000 | __lock_acquire.isra.0+0x6d4 (0xffffffff8132f1a4)             
    mov eax, dword ptr [rbp-0x38] 
    EAX:0x3
    [RBP:0xffffc90000a1fe88+0xffffffffffffffc8=0xffffc90000a1fe50size:UInt32->0x0]] 
    [8b, 45, c8]
ITERATION 1082 0xffffffff8132f1a7 0x11114000 | __lock_acquire.isra.0+0x6d7 (0xffffffff8132f1a7)             
    or eax, dword ptr [rip+0x4d89033] 
    EAX:0x0
    [RIP:0xffffffff8132f1a7+0x4d89039=0xffffffff860b81e0size:UInt32->0x0]] 
    [0b, 05, 33, 90, d8, 04]
ITERATION 1083 0xffffffff8132f1ad 0x11114000 | __lock_acquire.isra.0+0x6dd (0xffffffff8132f1ad)             
    jne 0xd 
    ??_NearBranch64_?? [75, 0b]
ITERATION 1084 0xffffffff8132f1af 0x11114000 | __lock_acquire.isra.0+0x6df (0xffffffff8132f1af)             
    cmp qword ptr [rbp-0x48], 0xffffffffffffffff 
    [RBP:0xffffc90000a1fe88+0xffffffffffffffb8=0xffffc90000a1fe40size:UInt64->0xffffffffffffffff]] 
    ??_Immediate8to64_?? [48, 83, 7d, b8, ff]
ITERATION 1085 0xffffffff8132f1b4 0x11114000 | __lock_acquire.isra.0+0x6e4 (0xffffffff8132f1b4)             
    jne 0x470 
    ??_NearBranch64_?? [0f, 85, 6a, 04, 00, 00]
ITERATION 1086 0xffffffff8132f1ba 0x11114000 | __lock_acquire.isra.0+0x6ea (0xffffffff8132f1ba)             
    mov rax, 0xdffffc0000000000 
    RAX:0x0
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1087 0xffffffff8132f1c4 0x11114000 | __lock_acquire.isra.0+0x6f4 (0xffffffff8132f1c4)             
    mov rdx, qword ptr [rbp-0x68] 
    RDX:0x4
    [RBP:0xffffc90000a1fe88+0xffffffffffffff98=0xffffc90000a1fe20size:UInt64->0xffff888007675030]] 
    [48, 8b, 55, 98]
ITERATION 1088 0xffffffff8132f1c8 0x11114000 | __lock_acquire.isra.0+0x6f8 (0xffffffff8132f1c8)             
    shr rdx, 0x3 
    RDX:0xffff888007675030 -> ''
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1089 0xffffffff8132f1cc 0x11114000 | __lock_acquire.isra.0+0x6fc (0xffffffff8132f1cc)             
    movzx eax, byte ptr [rdx+rax] 
    EAX:0x0
    [RDX:0x1ffff11000ecea06+RAX:0xdffffc0000000000=0xffffed1000ecea06size:UInt8->0x0]] 
    [0f, b6, 04, 02]
ITERATION 1090 0xffffffff8132f1d0 0x11114000 | __lock_acquire.isra.0+0x700 (0xffffffff8132f1d0)             
    test al, al 
    AL:0x0
    AL:0x0
    [84, c0]
ITERATION 1091 0xffffffff8132f1d2 0x11114000 | __lock_acquire.isra.0+0x702 (0xffffffff8132f1d2)             
    je 0xa 
    ??_NearBranch64_?? [74, 08]
ITERATION 1092 0xffffffff8132f1dc 0x11114000 | __lock_acquire.isra.0+0x70c (0xffffffff8132f1dc)             
    movzx eax, word ptr [r15+0x20] 
    EAX:0x0
    [R15:0xffff888007675010+0x20=0xffff888007675030size:UInt16->0x2]] 
    [41, 0f, b7, 47, 20]
ITERATION 1093 0xffffffff8132f1e1 0x11114000 | __lock_acquire.isra.0+0x711 (0xffffffff8132f1e1)             
    and ax, 0x1fff 
    AX:0x2
    ??_Immediate16_?? [66, 25, ff, 1f]
ITERATION 1094 0xffffffff8132f1e5 0x11114000 | __lock_acquire.isra.0+0x715 (0xffffffff8132f1e5)             
    mov word ptr [rbp-0x40], ax 
    [RBP:0xffffc90000a1fe88+0xffffffffffffffc0=0x1ffffc90000a1fe48]] 
    AX:0x2
    [66, 89, 45, c0]
ITERATION 1095 0xffffffff8132f1e9 0x11114000 | __lock_acquire.isra.0+0x719 (0xffffffff8132f1e9)             
    movzx eax, byte ptr [r15+0x22] 
    EAX:0x2
    [R15:0xffff888007675010+0x22=0xffff888007675032size:UInt8->0x2]] 
    [41, 0f, b6, 47, 22]
ITERATION 1096 0xffffffff8132f1ee 0x11114000 | __lock_acquire.isra.0+0x71e (0xffffffff8132f1ee)             
    and eax, 0x3 
    EAX:0x2
    ??_Immediate8to32_?? [83, e0, 03]
ITERATION 1097 0xffffffff8132f1f1 0x11114000 | __lock_acquire.isra.0+0x721 (0xffffffff8132f1f1)             
    mov byte ptr [rbp-0x60], al 
    [RBP:0xffffc90000a1fe88+0xffffffffffffffa0=0x1ffffc90000a1fe28]] 
    AL:0x2
    [88, 45, a0]
ITERATION 1098 0xffffffff8132f1f4 0x11114000 | __lock_acquire.isra.0+0x724 (0xffffffff8132f1f4)             
    jmp 0xfffffffffffffbe0 
    ??_NearBranch64_?? [e9, db, fb, ff, ff]
ITERATION 1099 0xffffffff8132edd4 0x11114000 | __lock_acquire.isra.0+0x304 (0xffffffff8132edd4)             
    mov rax, 0xdffffc0000000000 
    RAX:0x2
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1100 0xffffffff8132edde 0x11114000 | __lock_acquire.isra.0+0x30e (0xffffffff8132edde)             
    mov rdx, r15 
    RDX:0x1ffff11000ecea06
    R15:0xffff888007675010 -> 0xffffffffffffffff
    [4c, 89, fa]
ITERATION 1101 0xffffffff8132ede1 0x11114000 | __lock_acquire.isra.0+0x311 (0xffffffff8132ede1)             
    shr rdx, 0x3 
    RDX:0xffff888007675010 -> 0xffffffffffffffff
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1102 0xffffffff8132ede5 0x11114000 | __lock_acquire.isra.0+0x315 (0xffffffff8132ede5)             
    cmp byte ptr [rdx+rax], 0x0 
    [RDX:0x1ffff11000ecea02+RAX:0xdffffc0000000000=0xffffed1000ecea02size:UInt8->0x0]] 
    ??_Immediate8_?? [80, 3c, 02, 00]
ITERATION 1103 0xffffffff8132ede9 0x11114000 | __lock_acquire.isra.0+0x319 (0xffffffff8132ede9)             
    jne 0x972 
    ??_NearBranch64_?? [0f, 85, 6c, 09, 00, 00]
ITERATION 1104 0xffffffff8132edef 0x11114000 | __lock_acquire.isra.0+0x31f (0xffffffff8132edef)             
    mov rax, qword ptr [rbp-0x48] 
    RAX:0xdffffc0000000000
    [RBP:0xffffc90000a1fe88+0xffffffffffffffb8=0xffffc90000a1fe40size:UInt64->0xffffffffffffffff]] 
    [48, 8b, 45, b8]
ITERATION 1105 0xffffffff8132edf3 0x11114000 | __lock_acquire.isra.0+0x323 (0xffffffff8132edf3)             
    mov qword ptr [r15], rax 
    [R15:0xffff888007675010] 
    RAX:0xffffffffffffffff
    [49, 89, 07]
ITERATION 1106 0xffffffff8132edf6 0x11114000 | __lock_acquire.isra.0+0x326 (0xffffffff8132edf6)             
    test r12, r12 
    R12:0x0
    R12:0x0
    [4d, 85, e4]
ITERATION 1107 0xffffffff8132edf9 0x11114000 | __lock_acquire.isra.0+0x329 (0xffffffff8132edf9)             
    je 0xbb 
    ??_NearBranch64_?? [0f, 84, b5, 00, 00, 00]
ITERATION 1108 0xffffffff8132eeb4 0x11114000 | __lock_acquire.isra.0+0x3e4 (0xffffffff8132eeb4)             
    mov r13, 0xffffffff85891e28 
    R13:[34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    ??_Immediate32to64_?? [49, c7, c5, 28, 1e, 89, 85]
ITERATION 1109 0xffffffff8132eebb 0x11114000 | __lock_acquire.isra.0+0x3eb (0xffffffff8132eebb)             
    mov rax, 0xdffffc0000000000 
    RAX:0xffffffffffffffff
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1110 0xffffffff8132eec5 0x11114000 | __lock_acquire.isra.0+0x3f5 (0xffffffff8132eec5)             
    mov rdx, r13 
    RDX:0x1ffff11000ecea02
    R13:[34mdebug_locks_silent+0x0 (0xffffffff85891e28)[39m -> 0x100000000
    [4c, 89, ea]
ITERATION 1111 0xffffffff8132eec8 0x11114000 | __lock_acquire.isra.0+0x3f8 (0xffffffff8132eec8)             
    shr rdx, 0x3 
    RDX:[34mdebug_locks_silent+0x0 (0xffffffff85891e28)[39m -> 0x100000000
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1112 0xffffffff8132eecc 0x11114000 | __lock_acquire.isra.0+0x3fc (0xffffffff8132eecc)             
    movzx edx, byte ptr [rdx+rax] 
    EDX:0xf0b123c5
    [RDX:0x1ffffffff0b123c5+RAX:0xdffffc0000000000=0xfffffbfff0b123c5size:UInt8->0x0]] 
    [0f, b6, 14, 02]
ITERATION 1113 0xffffffff8132eed0 0x11114000 | __lock_acquire.isra.0+0x400 (0xffffffff8132eed0)             
    mov rax, r13 
    RAX:0xdffffc0000000000
    R13:[34mdebug_locks_silent+0x0 (0xffffffff85891e28)[39m -> 0x100000000
    [4c, 89, e8]
ITERATION 1114 0xffffffff8132eed3 0x11114000 | __lock_acquire.isra.0+0x403 (0xffffffff8132eed3)             
    and eax, 0x7 
    EAX:0x85891e28
    ??_Immediate8to32_?? [83, e0, 07]
ITERATION 1115 0xffffffff8132eed6 0x11114000 | __lock_acquire.isra.0+0x406 (0xffffffff8132eed6)             
    add eax, 0x3 
    EAX:0x0
    ??_Immediate8to32_?? [83, c0, 03]
ITERATION 1116 0xffffffff8132eed9 0x11114000 | __lock_acquire.isra.0+0x409 (0xffffffff8132eed9)             
    cmp al, dl 
    AL:0x3
    DL:0x0
    [38, d0]
ITERATION 1117 0xffffffff8132eedb 0x11114000 | __lock_acquire.isra.0+0x40b (0xffffffff8132eedb)             
    jl 0xa 
    ??_NearBranch64_?? [7c, 08]
ITERATION 1118 0xffffffff8132eedd 0x11114000 | __lock_acquire.isra.0+0x40d (0xffffffff8132eedd)             
    test dl, dl 
    DL:0x0
    DL:0x0
    [84, d2]
ITERATION 1119 0xffffffff8132eedf 0x11114000 | __lock_acquire.isra.0+0x40f (0xffffffff8132eedf)             
    jne 0xa36 
    ??_NearBranch64_?? [0f, 85, 30, 0a, 00, 00]
ITERATION 1120 0xffffffff8132eee5 0x11114000 | __lock_acquire.isra.0+0x415 (0xffffffff8132eee5)             
    mov r9d, dword ptr [rip+0x4562f3c] 
    R9D:0xf0ba5615
    [RIP:0xffffffff8132eee5+0x4562f43=0xffffffff85891e28size:UInt32->0x0]] 
    [44, 8b, 0d, 3c, 2f, 56, 04]
ITERATION 1121 0xffffffff8132eeec 0x11114000 | __lock_acquire.isra.0+0x41c (0xffffffff8132eeec)             
    test r9d, r9d 
    R9D:0x0
    R9D:0x0
    [45, 85, c9]
ITERATION 1122 0xffffffff8132eeef 0x11114000 | __lock_acquire.isra.0+0x41f (0xffffffff8132eeef)             
    jne 0xa2 
    ??_NearBranch64_?? [0f, 85, 9c, 00, 00, 00]
ITERATION 1123 0xffffffff8132eef5 0x11114000 | __lock_acquire.isra.0+0x425 (0xffffffff8132eef5)             
    mov r8d, dword ptr [rbp-0x38] 
    R8D:0x1
    [RBP:0xffffc90000a1fe88+0xffffffffffffffc8=0xffffc90000a1fe50size:UInt32->0x0]] 
    [44, 8b, 45, c8]
ITERATION 1124 0xffffffff8132eef9 0x11114000 | __lock_acquire.isra.0+0x429 (0xffffffff8132eef9)             
    test r8d, r8d 
    R8D:0x0
    R8D:0x0
    [45, 85, c0]
ITERATION 1125 0xffffffff8132eefc 0x11114000 | __lock_acquire.isra.0+0x42c (0xffffffff8132eefc)             
    jne 0x492 
    ??_NearBranch64_?? [0f, 85, 8c, 04, 00, 00]
ITERATION 1126 0xffffffff8132ef02 0x11114000 | __lock_acquire.isra.0+0x432 (0xffffffff8132ef02)             
    mov rax, 0xdffffc0000000000 
    RAX:0x3
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1127 0xffffffff8132ef0c 0x11114000 | __lock_acquire.isra.0+0x43c (0xffffffff8132ef0c)             
    mov rdx, qword ptr [rbp-0x68] 
    RDX:0x0
    [RBP:0xffffc90000a1fe88+0xffffffffffffff98=0xffffc90000a1fe20size:UInt64->0xffff888007675030]] 
    [48, 8b, 55, 98]
ITERATION 1128 0xffffffff8132ef10 0x11114000 | __lock_acquire.isra.0+0x440 (0xffffffff8132ef10)             
    shr rdx, 0x3 
    RDX:0xffff888007675030 -> ''
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1129 0xffffffff8132ef14 0x11114000 | __lock_acquire.isra.0+0x444 (0xffffffff8132ef14)             
    movzx eax, byte ptr [rdx+rax] 
    EAX:0x0
    [RDX:0x1ffff11000ecea06+RAX:0xdffffc0000000000=0xffffed1000ecea06size:UInt8->0x0]] 
    [0f, b6, 04, 02]
ITERATION 1130 0xffffffff8132ef18 0x11114000 | __lock_acquire.isra.0+0x448 (0xffffffff8132ef18)             
    test al, al 
    AL:0x0
    AL:0x0
    [84, c0]
ITERATION 1131 0xffffffff8132ef1a 0x11114000 | __lock_acquire.isra.0+0x44a (0xffffffff8132ef1a)             
    je 0xa 
    ??_NearBranch64_?? [74, 08]
ITERATION 1132 0xffffffff8132ef24 0x11114000 | __lock_acquire.isra.0+0x454 (0xffffffff8132ef24)             
    movzx ebx, word ptr [r15+0x20] 
    EBX:0x0
    [R15:0xffff888007675010+0x20=0xffff888007675030size:UInt16->0x2]] 
    [41, 0f, b7, 5f, 20]
ITERATION 1133 0xffffffff8132ef29 0x11114000 | __lock_acquire.isra.0+0x459 (0xffffffff8132ef29)             
    and bx, 0x1fff 
    BX:0x2
    ??_Immediate16_?? [66, 81, e3, ff, 1f]
ITERATION 1134 0xffffffff8132ef2e 0x11114000 | __lock_acquire.isra.0+0x45e (0xffffffff8132ef2e)             
    movzx ebx, bx 
    EBX:0x2
    BX:0x2
    [0f, b7, db]
ITERATION 1135 0xffffffff8132ef31 0x11114000 | __lock_acquire.isra.0+0x461 (0xffffffff8132ef31)             
    mov esi, 0x8 
    ESI:0x8
    ??_Immediate32_?? [be, 08, 00, 00, 00]
ITERATION 1136 0xffffffff8132ef36 0x11114000 | __lock_acquire.isra.0+0x466 (0xffffffff8132ef36)             
    mov rax, rbx 
    RAX:0x0
    RBX:0x2
    [48, 89, d8]
ITERATION 1137 0xffffffff8132ef39 0x11114000 | __lock_acquire.isra.0+0x469 (0xffffffff8132ef39)             
    sar rax, 0x6 
    RAX:0x2
    ??_Immediate8_?? [48, c1, f8, 06]
ITERATION 1138 0xffffffff8132ef3d 0x11114000 | __lock_acquire.isra.0+0x46d (0xffffffff8132ef3d)             
    lea rdi, [rax*8-0x7a2d4f60] 
    RDI:[34mlock_classes_in_use+0x0 (0xffffffff85d2b0a0)[39m -> 0xffffffffffffffff
    [None:0x0+RAX:0x0*0x8+0xffffffff85d2b0a0=0xffffffff85d2b0a0]] 
    [48, 8d, 3c, c5, a0, b0, d2, 85]
ITERATION 1139 0xffffffff8132ef45 0x11114000 | __lock_acquire.isra.0+0x475 (0xffffffff8132ef45)             
    call 0x60cdfb 
    ??_NearBranch64_?? [e8, f6, cd, 60, 00]
ITERATION 1140 0xffffffff8193bd40 0x11114000 | __kasan_check_read+0x0 (0xffffffff8193bd40)                  
    push rbp 
    RBP:0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [55]
ITERATION 1141 0xffffffff8193bd41 0x11114000 | __kasan_check_read+0x1 (0xffffffff8193bd41)                  
    mov esi, esi 
    ESI:0x8
    ESI:0x8
    [89, f6]
ITERATION 1142 0xffffffff8193bd43 0x11114000 | __kasan_check_read+0x3 (0xffffffff8193bd43)                  
    xor edx, edx 
    EDX:0xecea06
    EDX:0xecea06
    [31, d2]
ITERATION 1143 0xffffffff8193bd45 0x11114000 | __kasan_check_read+0x5 (0xffffffff8193bd45)                  
    mov rbp, rsp 
    RBP:0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    RSP:0xffffc90000a1fdf8 -> 0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [48, 89, e5]
ITERATION 1144 0xffffffff8193bd48 0x11114000 | __kasan_check_read+0x8 (0xffffffff8193bd48)                  
    mov rcx, qword ptr [rbp+0x8] 
    RCX:[34m__lock_acquire.isra.0+0x658 (0xffffffff8132f128)[39m -> 0x1da30f4cc05d8b4c
    [RBP:0xffffc90000a1fdf8+0x8=0xffffc90000a1fe00size:UInt64->0xffffffff8132ef4a]] 
    [48, 8b, 4d, 08]
ITERATION 1145 0xffffffff8193bd4c 0x11114000 | __kasan_check_read+0xc (0xffffffff8193bd4c)                  
    call 0xfffffffffffff784 
    ??_NearBranch64_?? [e8, 7f, f7, ff, ff]
ITERATION 1146 0xffffffff8193b4d0 0x11114000 | kasan_check_range+0x0 (0xffffffff8193b4d0)                   
    test rsi, rsi 
    RSI:0x8
    RSI:0x8
    [48, 85, f6]
ITERATION 1147 0xffffffff8193b4d3 0x11114000 | kasan_check_range+0x3 (0xffffffff8193b4d3)                   
    je 0x199 
    ??_NearBranch64_?? [0f, 84, 93, 01, 00, 00]
ITERATION 1148 0xffffffff8193b4d9 0x11114000 | kasan_check_range+0x9 (0xffffffff8193b4d9)                   
    push rbp 
    RBP:0xffffc90000a1fdf8 -> 0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [55]
ITERATION 1149 0xffffffff8193b4da 0x11114000 | kasan_check_range+0xa (0xffffffff8193b4da)                   
    mov r10, rdi 
    R10:[34mlock_classes_in_use+0x7 (0xffffffff85d2b0a7)[39m -> 0xffffffffffffffff
    RDI:[34mlock_classes_in_use+0x0 (0xffffffff85d2b0a0)[39m -> 0xffffffffffffffff
    [49, 89, fa]
ITERATION 1150 0xffffffff8193b4dd 0x11114000 | kasan_check_range+0xd (0xffffffff8193b4dd)                   
    movzx edx, dl 
    EDX:0x0
    DL:0x0
    [0f, b6, d2]
ITERATION 1151 0xffffffff8193b4e0 0x11114000 | kasan_check_range+0x10 (0xffffffff8193b4e0)                  
    mov rbp, rsp 
    RBP:0xffffc90000a1fdf8 -> 0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    RSP:0xffffc90000a1fde8 -> 0xffffc90000a1fdf8 -> 0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 ... 
    [48, 89, e5]
ITERATION 1152 0xffffffff8193b4e3 0x11114000 | kasan_check_range+0x13 (0xffffffff8193b4e3)                  
    push r13 
    R13:[34mdebug_locks_silent+0x0 (0xffffffff85891e28)[39m -> 0x100000000
    [41, 55]
ITERATION 1153 0xffffffff8193b4e5 0x11114000 | kasan_check_range+0x15 (0xffffffff8193b4e5)                  
    push r12 
    R12:0x0
    [41, 54]
ITERATION 1154 0xffffffff8193b4e7 0x11114000 | kasan_check_range+0x17 (0xffffffff8193b4e7)                  
    push rbx 
    RBX:0x2
    [53]
ITERATION 1155 0xffffffff8193b4e8 0x11114000 | kasan_check_range+0x18 (0xffffffff8193b4e8)                  
    add r10, rsi 
    R10:[34mlock_classes_in_use+0x0 (0xffffffff85d2b0a0)[39m -> 0xffffffffffffffff
    RSI:0x8
    [49, 01, f2]
ITERATION 1156 0xffffffff8193b4eb 0x11114000 | kasan_check_range+0x1b (0xffffffff8193b4eb)                  
    jb 0x16c 
    ??_NearBranch64_?? [0f, 82, 66, 01, 00, 00]
ITERATION 1157 0xffffffff8193b4f1 0x11114000 | kasan_check_range+0x21 (0xffffffff8193b4f1)                  
    jmp 0xc2 
    ??_NearBranch64_?? [e9, bd, 00, 00, 00]
ITERATION 1158 0xffffffff8193b5b3 0x11114000 | kasan_check_range+0xe3 (0xffffffff8193b5b3)                  
    mov rax, 0xffff800000000000 
    RAX:0x0
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, 80, ff, ff]
ITERATION 1159 0xffffffff8193b5bd 0x11114000 | kasan_check_range+0xed (0xffffffff8193b5bd)                  
    jmp 0xffffffffffffff43 
    ??_NearBranch64_?? [e9, 3e, ff, ff, ff]
ITERATION 1160 0xffffffff8193b500 0x11114000 | kasan_check_range+0x30 (0xffffffff8193b500)                  
    cmp rax, rdi 
    RAX:0xffff800000000000
    RDI:[34mlock_classes_in_use+0x0 (0xffffffff85d2b0a0)[39m -> 0xffffffffffffffff
    [48, 39, f8]
ITERATION 1161 0xffffffff8193b503 0x11114000 | kasan_check_range+0x33 (0xffffffff8193b503)                  
    ja 0x154 
    ??_NearBranch64_?? [0f, 87, 4e, 01, 00, 00]
ITERATION 1162 0xffffffff8193b509 0x11114000 | kasan_check_range+0x39 (0xffffffff8193b509)                  
    sub r10, 0x1 
    R10:[34mlock_classes_in_use+0x8 (0xffffffff85d2b0a8)[39m -> 0xffffffffffffffff
    ??_Immediate8to64_?? [49, 83, ea, 01]
ITERATION 1163 0xffffffff8193b50d 0x11114000 | kasan_check_range+0x3d (0xffffffff8193b50d)                  
    mov r8, rdi 
    R8:0x0
    RDI:[34mlock_classes_in_use+0x0 (0xffffffff85d2b0a0)[39m -> 0xffffffffffffffff
    [49, 89, f8]
ITERATION 1164 0xffffffff8193b510 0x11114000 | kasan_check_range+0x40 (0xffffffff8193b510)                  
    mov rax, 0xdffffc0000000000 
    RAX:0xffff800000000000
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1165 0xffffffff8193b51a 0x11114000 | kasan_check_range+0x4a (0xffffffff8193b51a)                  
    mov r11, r10 
    R11:0x2
    R10:[34mlock_classes_in_use+0x7 (0xffffffff85d2b0a7)[39m -> 0xffffffffffffffff
    [4d, 89, d3]
ITERATION 1166 0xffffffff8193b51d 0x11114000 | kasan_check_range+0x4d (0xffffffff8193b51d)                  
    shr r8, 0x3 
    R8:[34mlock_classes_in_use+0x0 (0xffffffff85d2b0a0)[39m -> 0xffffffffffffffff
    ??_Immediate8_?? [49, c1, e8, 03]
ITERATION 1167 0xffffffff8193b521 0x11114000 | kasan_check_range+0x51 (0xffffffff8193b521)                  
    shr r11, 0x3 
    R11:[34mlock_classes_in_use+0x7 (0xffffffff85d2b0a7)[39m -> 0xffffffffffffffff
    ??_Immediate8_?? [49, c1, eb, 03]
ITERATION 1168 0xffffffff8193b525 0x11114000 | kasan_check_range+0x55 (0xffffffff8193b525)                  
    lea r12, [r8+rax] 
    R12:0x0
    [R8:0x1ffffffff0ba5614+RAX:0xdffffc0000000000=0xfffffbfff0ba5614]] 
    [4d, 8d, 24, 00]
ITERATION 1169 0xffffffff8193b529 0x11114000 | kasan_check_range+0x59 (0xffffffff8193b529)                  
    add r11, rax 
    R11:0x1ffffffff0ba5614
    RAX:0xdffffc0000000000
    [49, 01, c3]
ITERATION 1170 0xffffffff8193b52c 0x11114000 | kasan_check_range+0x5c (0xffffffff8193b52c)                  
    mov rax, r12 
    RAX:0xdffffc0000000000
    R12:0xfffffbfff0ba5614 -> 0x0
    [4c, 89, e0]
ITERATION 1171 0xffffffff8193b52f 0x11114000 | kasan_check_range+0x5f (0xffffffff8193b52f)                  
    lea rbx, [r11+0x1] 
    RBX:0x2
    [R11:0xfffffbfff0ba5614+0x1=0xfffffbfff0ba5615]] 
    [49, 8d, 5b, 01]
ITERATION 1172 0xffffffff8193b533 0x11114000 | kasan_check_range+0x63 (0xffffffff8193b533)                  
    mov r9, rbx 
    R9:0x0
    RBX:0xfffffbfff0ba5615 -> 0x0
    [49, 89, d9]
ITERATION 1173 0xffffffff8193b536 0x11114000 | kasan_check_range+0x66 (0xffffffff8193b536)                  
    sub r9, r12 
    R9:0xfffffbfff0ba5615 -> 0x0
    R12:0xfffffbfff0ba5614 -> 0x0
    [4d, 29, e1]
ITERATION 1174 0xffffffff8193b539 0x11114000 | kasan_check_range+0x69 (0xffffffff8193b539)                  
    cmp r9, 0x10 
    R9:0x1
    ??_Immediate8to64_?? [49, 83, f9, 10]
ITERATION 1175 0xffffffff8193b53d 0x11114000 | kasan_check_range+0x6d (0xffffffff8193b53d)                  
    jle 0xde 
    ??_NearBranch64_?? [0f, 8e, d8, 00, 00, 00]
ITERATION 1176 0xffffffff8193b61b 0x11114000 | kasan_check_range+0x14b (0xffffffff8193b61b)                 
    test r9, r9 
    R9:0x1
    R9:0x1
    [4d, 85, c9]
ITERATION 1177 0xffffffff8193b61e 0x11114000 | kasan_check_range+0x14e (0xffffffff8193b61e)                 
    je 0xffffffffffffffed 
    ??_NearBranch64_?? [74, eb]
ITERATION 1178 0xffffffff8193b620 0x11114000 | kasan_check_range+0x150 (0xffffffff8193b620)                 
    add r9, r12 
    R9:0x1
    R12:0xfffffbfff0ba5614 -> 0x0
    [4d, 01, e1]
ITERATION 1179 0xffffffff8193b623 0x11114000 | kasan_check_range+0x153 (0xffffffff8193b623)                 
    jmp 0xb 
    ??_NearBranch64_?? [eb, 09]
ITERATION 1180 0xffffffff8193b62e 0x11114000 | kasan_check_range+0x15e (0xffffffff8193b62e)                 
    cmp byte ptr [rax], 0x0 
    [RAX:0xfffffbfff0ba5614size:UInt8->0x0]] 
    ??_Immediate8_?? [80, 38, 00]
ITERATION 1181 0xffffffff8193b631 0x11114000 | kasan_check_range+0x161 (0xffffffff8193b631)                 
    je 0xfffffffffffffff4 
    ??_NearBranch64_?? [74, f2]
ITERATION 1182 0xffffffff8193b625 0x11114000 | kasan_check_range+0x155 (0xffffffff8193b625)                 
    add rax, 0x1 
    RAX:0xfffffbfff0ba5614 -> 0x0
    ??_Immediate8to64_?? [48, 83, c0, 01]
ITERATION 1183 0xffffffff8193b629 0x11114000 | kasan_check_range+0x159 (0xffffffff8193b629)                 
    cmp rax, r9 
    RAX:0xfffffbfff0ba5615 -> 0x0
    R9:0xfffffbfff0ba5615 -> 0x0
    [4c, 39, c8]
ITERATION 1184 0xffffffff8193b62c 0x11114000 | kasan_check_range+0x15c (0xffffffff8193b62c)                 
    je 0xffffffffffffffdf 
    ??_NearBranch64_?? [74, dd]
ITERATION 1185 0xffffffff8193b60b 0x11114000 | kasan_check_range+0x13b (0xffffffff8193b60b)                 
    mov r8d, 0x1 
    R8D:0xf0ba5614
    ??_Immediate32_?? [41, b8, 01, 00, 00, 00]
ITERATION 1186 0xffffffff8193b611 0x11114000 | kasan_check_range+0x141 (0xffffffff8193b611)                 
    pop rbx 
    RBX:0xfffffbfff0ba5615 -> 0x0
    [5b]
ITERATION 1187 0xffffffff8193b612 0x11114000 | kasan_check_range+0x142 (0xffffffff8193b612)                 
    pop r12 
    R12:0xfffffbfff0ba5614 -> 0x0
    [41, 5c]
ITERATION 1188 0xffffffff8193b614 0x11114000 | kasan_check_range+0x144 (0xffffffff8193b614)                 
    mov eax, r8d 
    EAX:0xf0ba5615
    R8D:0x1
    [44, 89, c0]
ITERATION 1189 0xffffffff8193b617 0x11114000 | kasan_check_range+0x147 (0xffffffff8193b617)                 
    pop r13 
    R13:[34mdebug_locks_silent+0x0 (0xffffffff85891e28)[39m -> 0x100000000
    [41, 5d]
ITERATION 1190 0xffffffff8193b619 0x11114000 | kasan_check_range+0x149 (0xffffffff8193b619)                 
    pop rbp 
    RBP:0xffffc90000a1fde8 -> 0xffffc90000a1fdf8 -> 0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 ... 
    [5d]
ITERATION 1191 0xffffffff8193b61a 0x11114000 | kasan_check_range+0x14a (0xffffffff8193b61a)                 
    ret 
    [c3]
ITERATION 1192 0xffffffff8193bd51 0x11114000 | __kasan_check_read+0x11 (0xffffffff8193bd51)                 
    pop rbp 
    RBP:0xffffc90000a1fdf8 -> 0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [5d]
ITERATION 1193 0xffffffff8193bd52 0x11114000 | __kasan_check_read+0x12 (0xffffffff8193bd52)                 
    ret 
    [c3]
ITERATION 1194 0xffffffff8132ef4a 0x11114000 | __lock_acquire.isra.0+0x47a (0xffffffff8132ef4a)             
    bt qword ptr [rip+0x49fc14e], rbx 
    [RIP:0xffffffff8132ef4a+0x49fc156=0xffffffff85d2b0a0]] 
    RBX:0x2
    [48, 0f, a3, 1d, 4e, c1, 9f, 04]
ITERATION 1195 0xffffffff8132ef52 0x11114000 | __lock_acquire.isra.0+0x482 (0xffffffff8132ef52)             
    jae 0x54c 
    ??_NearBranch64_?? [0f, 83, 46, 05, 00, 00]
ITERATION 1196 0xffffffff8132ef58 0x11114000 | __lock_acquire.isra.0+0x488 (0xffffffff8132ef58)             
    lea rbx, [rbx+rbx*2] 
    RBX:0x2
    [RBX:0x2+RBX:0x2*0x2=0x6]] 
    [48, 8d, 1c, 5b]
ITERATION 1197 0xffffffff8132ef5c 0x11114000 | __lock_acquire.isra.0+0x48c (0xffffffff8132ef5c)             
    shl rbx, 0x6 
    RBX:0x6
    ??_Immediate8_?? [48, c1, e3, 06]
ITERATION 1198 0xffffffff8132ef60 0x11114000 | __lock_acquire.isra.0+0x490 (0xffffffff8132ef60)             
    add rbx, 0xffffffff85d2b4c0 
    RBX:0x180
    ??_Immediate32to64_?? [48, 81, c3, c0, b4, d2, 85]
ITERATION 1199 0xffffffff8132ef67 0x11114000 | __lock_acquire.isra.0+0x497 (0xffffffff8132ef67)             
    mov rax, 0xdffffc0000000000 
    RAX:0x1
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1200 0xffffffff8132ef71 0x11114000 | __lock_acquire.isra.0+0x4a1 (0xffffffff8132ef71)             
    lea rdi, [rbx+0x40] 
    RDI:[34mlock_classes_in_use+0x0 (0xffffffff85d2b0a0)[39m -> 0xffffffffffffffff
    [RBX:0xffffffff85d2b640+0x40=0xffffffff85d2b680]] 
    [48, 8d, 7b, 40]
ITERATION 1201 0xffffffff8132ef75 0x11114000 | __lock_acquire.isra.0+0x4a5 (0xffffffff8132ef75)             
    mov rdx, rdi 
    RDX:0x0
    RDI:[34mlock_classes+0x1c0 (0xffffffff85d2b680)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    [48, 89, fa]
ITERATION 1202 0xffffffff8132ef78 0x11114000 | __lock_acquire.isra.0+0x4a8 (0xffffffff8132ef78)             
    shr rdx, 0x3 
    RDX:[34mlock_classes+0x1c0 (0xffffffff85d2b680)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1203 0xffffffff8132ef7c 0x11114000 | __lock_acquire.isra.0+0x4ac (0xffffffff8132ef7c)             
    cmp byte ptr [rdx+rax], 0x0 
    [RDX:0x1ffffffff0ba56d0+RAX:0xdffffc0000000000=0xfffffbfff0ba56d0size:UInt8->0x0]] 
    ??_Immediate8_?? [80, 3c, 02, 00]
ITERATION 1204 0xffffffff8132ef80 0x11114000 | __lock_acquire.isra.0+0x4b0 (0xffffffff8132ef80)             
    jne 0x82e 
    ??_NearBranch64_?? [0f, 85, 28, 08, 00, 00]
ITERATION 1205 0xffffffff8132ef86 0x11114000 | __lock_acquire.isra.0+0x4b6 (0xffffffff8132ef86)             
    cmp qword ptr [rbx+0x40], 0x0 
    [RBX:0xffffffff85d2b640+0x40=0xffffffff85d2b680size:UInt64->0xffffffff860d9aa0]] 
    ??_Immediate8to64_?? [48, 83, 7b, 40, 00]
ITERATION 1206 0xffffffff8132ef8b 0x11114000 | __lock_acquire.isra.0+0x4bb (0xffffffff8132ef8b)             
    je 0x556 
    ??_NearBranch64_?? [0f, 84, 50, 05, 00, 00]
ITERATION 1207 0xffffffff8132ef91 0x11114000 | __lock_acquire.isra.0+0x4c1 (0xffffffff8132ef91)             
    mov rsi, qword ptr [rbp-0x48] 
    RSI:0x8
    [RBP:0xffffc90000a1fe88+0xffffffffffffffb8=0xffffc90000a1fe40size:UInt64->0xffffffffffffffff]] 
    [48, 8b, 75, b8]
ITERATION 1208 0xffffffff8132ef95 0x11114000 | __lock_acquire.isra.0+0x4c5 (0xffffffff8132ef95)             
    movzx r14d, word ptr [rbp-0x60] 
    R14D:0x2
    [RBP:0xffffc90000a1fe88+0xffffffffffffffa0=0xffffc90000a1fe28size:UInt16->0x8a02]] 
    [44, 0f, b7, 75, a0]
ITERATION 1209 0xffffffff8132ef9a 0x11114000 | __lock_acquire.isra.0+0x4ca (0xffffffff8132ef9a)             
    mov rax, rsi 
    RAX:0xdffffc0000000000
    RSI:0xffffffffffffffff
    [48, 89, f0]
ITERATION 1210 0xffffffff8132ef9d 0x11114000 | __lock_acquire.isra.0+0x4cd (0xffffffff8132ef9d)             
    shl r14d, 0xd 
    R14D:0x8a02
    ??_Immediate8_?? [41, c1, e6, 0d]
ITERATION 1211 0xffffffff8132efa1 0x11114000 | __lock_acquire.isra.0+0x4d1 (0xffffffff8132efa1)             
    or r14w, word ptr [rbp-0x40] 
    R14W:0x4000
    [RBP:0xffffc90000a1fe88+0xffffffffffffffc0=0xffffc90000a1fe48size:UInt16->0x2]] 
    [66, 44, 0b, 75, c0]
ITERATION 1212 0xffffffff8132efa6 0x11114000 | __lock_acquire.isra.0+0x4d6 (0xffffffff8132efa6)             
    mov r15d, esi 
    R15D:0x7675010
    ESI:0xffffffff
    [41, 89, f7]
ITERATION 1213 0xffffffff8132efa9 0x11114000 | __lock_acquire.isra.0+0x4d9 (0xffffffff8132efa9)             
    shr rax, 0x20 
    RAX:0xffffffffffffffff
    ??_Immediate8_?? [48, c1, e8, 20]
ITERATION 1214 0xffffffff8132efad 0x11114000 | __lock_acquire.isra.0+0x4dd (0xffffffff8132efad)             
    movsx r14d, r14w 
    R14D:0x11404002
    R14W:0x4002
    [45, 0f, bf, f6]
ITERATION 1215 0xffffffff8132efb1 0x11114000 | __lock_acquire.isra.0+0x4e1 (0xffffffff8132efb1)             
    mov edx, r14d 
    EDX:0xf0ba56d0
    R14D:0x4002
    [44, 89, f2]
ITERATION 1216 0xffffffff8132efb4 0x11114000 | __lock_acquire.isra.0+0x4e4 (0xffffffff8132efb4)             
    mov r14d, eax 
    R14D:0x4002
    EAX:0xffffffff
    [41, 89, c6]
ITERATION 1217 0xffffffff8132efb7 0x11114000 | __lock_acquire.isra.0+0x4e7 (0xffffffff8132efb7)             
    sub edx, eax 
    EDX:0x4002
    EAX:0xffffffff
    [29, c2]
ITERATION 1218 0xffffffff8132efb9 0x11114000 | __lock_acquire.isra.0+0x4e9 (0xffffffff8132efb9)             
    rol r14d, 0x4 
    R14D:0xffffffff
    ??_Immediate8_?? [41, c1, c6, 04]
ITERATION 1219 0xffffffff8132efbd 0x11114000 | __lock_acquire.isra.0+0x4ed (0xffffffff8132efbd)             
    xor r14d, edx 
    R14D:0xffffffff
    EDX:0x4003
    [41, 31, d6]
ITERATION 1220 0xffffffff8132efc0 0x11114000 | __lock_acquire.isra.0+0x4f0 (0xffffffff8132efc0)             
    lea edx, [rax+rsi] 
    EDX:0x4003
    [RAX:0xffffffff+RSI:0xffffffffffffffff=0x100000000fffffffe]] 
    [8d, 14, 30]
ITERATION 1221 0xffffffff8132efc3 0x11114000 | __lock_acquire.isra.0+0x4f3 (0xffffffff8132efc3)             
    mov eax, r14d 
    EAX:0xffffffff
    R14D:0xffffbffc
    [44, 89, f0]
ITERATION 1222 0xffffffff8132efc6 0x11114000 | __lock_acquire.isra.0+0x4f6 (0xffffffff8132efc6)             
    sub r15d, r14d 
    R15D:0xffffffff
    R14D:0xffffbffc
    [45, 29, f7]
ITERATION 1223 0xffffffff8132efc9 0x11114000 | __lock_acquire.isra.0+0x4f9 (0xffffffff8132efc9)             
    add r14d, edx 
    R14D:0xffffbffc
    EDX:0xfffffffe
    [41, 01, d6]
ITERATION 1224 0xffffffff8132efcc 0x11114000 | __lock_acquire.isra.0+0x4fc (0xffffffff8132efcc)             
    rol eax, 0x6 
    EAX:0xffffbffc
    ??_Immediate8_?? [c1, c0, 06]
ITERATION 1225 0xffffffff8132efcf 0x11114000 | __lock_acquire.isra.0+0x4ff (0xffffffff8132efcf)             
    xor r15d, eax 
    R15D:0x4003
    EAX:0xffefff3f
    [41, 31, c7]
ITERATION 1226 0xffffffff8132efd2 0x11114000 | __lock_acquire.isra.0+0x502 (0xffffffff8132efd2)             
    mov eax, r15d 
    EAX:0xffefff3f
    R15D:0xffefbf3c
    [44, 89, f8]
ITERATION 1227 0xffffffff8132efd5 0x11114000 | __lock_acquire.isra.0+0x505 (0xffffffff8132efd5)             
    sub edx, r15d 
    EDX:0xfffffffe
    R15D:0xffefbf3c
    [44, 29, fa]
ITERATION 1228 0xffffffff8132efd8 0x11114000 | __lock_acquire.isra.0+0x508 (0xffffffff8132efd8)             
    add r15d, r14d 
    R15D:0xffefbf3c
    R14D:0xffffbffa
    [45, 01, f7]
ITERATION 1229 0xffffffff8132efdb 0x11114000 | __lock_acquire.isra.0+0x50b (0xffffffff8132efdb)             
    rol eax, 0x8 
    EAX:0xffefbf3c
    ??_Immediate8_?? [c1, c0, 08]
ITERATION 1230 0xffffffff8132efde 0x11114000 | __lock_acquire.isra.0+0x50e (0xffffffff8132efde)             
    xor eax, edx 
    EAX:0xefbf3cff
    EDX:0x1040c2
    [31, d0]
ITERATION 1231 0xffffffff8132efe0 0x11114000 | __lock_acquire.isra.0+0x510 (0xffffffff8132efe0)             
    mov edx, eax 
    EDX:0x1040c2
    EAX:0xefaf7c3d
    [89, c2]
ITERATION 1232 0xffffffff8132efe2 0x11114000 | __lock_acquire.isra.0+0x512 (0xffffffff8132efe2)             
    sub r14d, eax 
    R14D:0xffffbffa
    EAX:0xefaf7c3d
    [41, 29, c6]
ITERATION 1233 0xffffffff8132efe5 0x11114000 | __lock_acquire.isra.0+0x515 (0xffffffff8132efe5)             
    add eax, r15d 
    EAX:0xefaf7c3d
    R15D:0xffef7f36
    [44, 01, f8]
ITERATION 1234 0xffffffff8132efe8 0x11114000 | __lock_acquire.isra.0+0x518 (0xffffffff8132efe8)             
    rol edx, 0x10 
    EDX:0xefaf7c3d
    ??_Immediate8_?? [c1, c2, 10]
ITERATION 1235 0xffffffff8132efeb 0x11114000 | __lock_acquire.isra.0+0x51b (0xffffffff8132efeb)             
    xor r14d, edx 
    R14D:0x105043bd
    EDX:0x7c3defaf
    [41, 31, d6]
ITERATION 1236 0xffffffff8132efee 0x11114000 | __lock_acquire.isra.0+0x51e (0xffffffff8132efee)             
    mov edx, r14d 
    EDX:0x7c3defaf
    R14D:0x6c6dac12
    [44, 89, f2]
ITERATION 1237 0xffffffff8132eff1 0x11114000 | __lock_acquire.isra.0+0x521 (0xffffffff8132eff1)             
    sub r15d, r14d 
    R15D:0xffef7f36
    R14D:0x6c6dac12
    [45, 29, f7]
ITERATION 1238 0xffffffff8132eff4 0x11114000 | __lock_acquire.isra.0+0x524 (0xffffffff8132eff4)             
    add r14d, eax 
    R14D:0x6c6dac12
    EAX:0xef9efb73
    [41, 01, c6]
ITERATION 1239 0xffffffff8132eff7 0x11114000 | __lock_acquire.isra.0+0x527 (0xffffffff8132eff7)             
    ror edx, 0xd 
    EDX:0x6c6dac12
    ??_Immediate8_?? [c1, ca, 0d]
ITERATION 1240 0xffffffff8132effa 0x11114000 | __lock_acquire.isra.0+0x52a (0xffffffff8132effa)             
    xor r15d, edx 
    R15D:0x9381d324
    EDX:0x6093636d
    [41, 31, d7]
ITERATION 1241 0xffffffff8132effd 0x11114000 | __lock_acquire.isra.0+0x52d (0xffffffff8132effd)             
    mov edx, eax 
    EDX:0x6093636d
    EAX:0xef9efb73
    [89, c2]
ITERATION 1242 0xffffffff8132efff 0x11114000 | __lock_acquire.isra.0+0x52f (0xffffffff8132efff)             
    mov ebx, r15d 
    EBX:0x85d2b640
    R15D:0xf312b049
    [44, 89, fb]
ITERATION 1243 0xffffffff8132f002 0x11114000 | __lock_acquire.isra.0+0x532 (0xffffffff8132f002)             
    sub edx, r15d 
    EDX:0xef9efb73
    R15D:0xf312b049
    [44, 29, fa]
ITERATION 1244 0xffffffff8132f005 0x11114000 | __lock_acquire.isra.0+0x535 (0xffffffff8132f005)             
    lea eax, [r14+r15] 
    EAX:0xef9efb73
    [R14:0x5c0ca785+R15:0xf312b049=0x14f1f57ce]] 
    [43, 8d, 04, 3e]
ITERATION 1245 0xffffffff8132f009 0x11114000 | __lock_acquire.isra.0+0x539 (0xffffffff8132f009)             
    rol ebx, 0x4 
    EBX:0xf312b049
    ??_Immediate8_?? [c1, c3, 04]
ITERATION 1246 0xffffffff8132f00c 0x11114000 | __lock_acquire.isra.0+0x53c (0xffffffff8132f00c)             
    xor ebx, edx 
    EBX:0x312b049f
    EDX:0xfc8c4b2a
    [31, d3]
ITERATION 1247 0xffffffff8132f00e 0x11114000 | __lock_acquire.isra.0+0x53e (0xffffffff8132f00e)             
    mov rdx, qword ptr [rbp-0x50] 
    RDX:0xfc8c4b2a
    [RBP:0xffffc90000a1fe88+0xffffffffffffffb0=0xffffc90000a1fe38size:UInt64->0xffff888007675000]] 
    [48, 8b, 55, b0]
ITERATION 1248 0xffffffff8132f012 0x11114000 | __lock_acquire.isra.0+0x542 (0xffffffff8132f012)             
    shl rbx, 0x20 
    RBX:0xcda74fb5
    ??_Immediate8_?? [48, c1, e3, 20]
ITERATION 1249 0xffffffff8132f016 0x11114000 | __lock_acquire.isra.0+0x546 (0xffffffff8132f016)             
    or rbx, rax 
    RBX:0xcda74fb500000000
    RAX:0x4f1f57ce
    [48, 09, c3]
ITERATION 1250 0xffffffff8132f019 0x11114000 | __lock_acquire.isra.0+0x549 (0xffffffff8132f019)             
    shr rdx, 0x3 
    RDX:0xffff888007675000 -> 0xffffffffffffffff
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1251 0xffffffff8132f01d 0x11114000 | __lock_acquire.isra.0+0x54d (0xffffffff8132f01d)             
    mov rax, 0xdffffc0000000000 
    RAX:0x4f1f57ce
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1252 0xffffffff8132f027 0x11114000 | __lock_acquire.isra.0+0x557 (0xffffffff8132f027)             
    cmp byte ptr [rdx+rax], 0x0 
    [RDX:0x1ffff11000ecea00+RAX:0xdffffc0000000000=0xffffed1000ecea00size:UInt8->0x0]] 
    ??_Immediate8_?? [80, 3c, 02, 00]
ITERATION 1253 0xffffffff8132f02b 0x11114000 | __lock_acquire.isra.0+0x55b (0xffffffff8132f02b)             
    jne 0x890 
    ??_NearBranch64_?? [0f, 85, 8a, 08, 00, 00]
ITERATION 1254 0xffffffff8132f031 0x11114000 | __lock_acquire.isra.0+0x561 (0xffffffff8132f031)             
    mov rax, qword ptr [rbp-0x30] 
    RAX:0xdffffc0000000000
    [RBP:0xffffc90000a1fe88+0xffffffffffffffd0=0xffffc90000a1fe58size:UInt64->0xffff888007674300]] 
    [48, 8b, 45, d0]
ITERATION 1255 0xffffffff8132f035 0x11114000 | __lock_acquire.isra.0+0x565 (0xffffffff8132f035)             
    mov rdx, qword ptr [rbp-0x58] 
    RDX:0x1ffff11000ecea00
    [RBP:0xffffc90000a1fe88+0xffffffffffffffa8=0xffffc90000a1fe30size:UInt64->0xffff888007675008]] 
    [48, 8b, 55, a8]
ITERATION 1256 0xffffffff8132f039 0x11114000 | __lock_acquire.isra.0+0x569 (0xffffffff8132f039)             
    mov qword ptr [rax+0xd00], rbx 
    [RAX:0xffff888007674300+0xd00=0xffff888007675000]] 
    RBX:0xcda74fb54f1f57ce
    [48, 89, 98, 00, 0d, 00, 00]
ITERATION 1257 0xffffffff8132f040 0x11114000 | __lock_acquire.isra.0+0x570 (0xffffffff8132f040)             
    shr rdx, 0x3 
    RDX:0xffff888007675008 -> 0x0
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1258 0xffffffff8132f044 0x11114000 | __lock_acquire.isra.0+0x574 (0xffffffff8132f044)             
    mov rax, 0xdffffc0000000000 
    RAX:0xffff888007674300 -> 0x0
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1259 0xffffffff8132f04e 0x11114000 | __lock_acquire.isra.0+0x57e (0xffffffff8132f04e)             
    movzx eax, byte ptr [rdx+rax] 
    EAX:0x0
    [RDX:0x1ffff11000ecea01+RAX:0xdffffc0000000000=0xffffed1000ecea01size:UInt8->0x0]] 
    [0f, b6, 04, 02]
ITERATION 1260 0xffffffff8132f052 0x11114000 | __lock_acquire.isra.0+0x582 (0xffffffff8132f052)             
    test al, al 
    AL:0x0
    AL:0x0
    [84, c0]
ITERATION 1261 0xffffffff8132f054 0x11114000 | __lock_acquire.isra.0+0x584 (0xffffffff8132f054)             
    je 0xa 
    ??_NearBranch64_?? [74, 08]
ITERATION 1262 0xffffffff8132f05e 0x11114000 | __lock_acquire.isra.0+0x58e (0xffffffff8132f05e)             
    mov rax, qword ptr [rbp-0x30] 
    RAX:0x0
    [RBP:0xffffc90000a1fe88+0xffffffffffffffd0=0xffffc90000a1fe58size:UInt64->0xffff888007674300]] 
    [48, 8b, 45, d0]
ITERATION 1263 0xffffffff8132f062 0x11114000 | __lock_acquire.isra.0+0x592 (0xffffffff8132f062)             
    add dword ptr [rax+0xd08], 0x1 
    [RAX:0xffff888007674300+0xd08=0xffff888007675008size:UInt32->0x0]] 
    ??_Immediate8to32_?? [83, 80, 08, 0d, 00, 00, 01]
ITERATION 1264 0xffffffff8132f069 0x11114000 | __lock_acquire.isra.0+0x599 (0xffffffff8132f069)             
    mov rdi, rax 
    RDI:[34mlock_classes+0x1c0 (0xffffffff85d2b680)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    RAX:0xffff888007674300 -> 0x0
    [48, 89, c7]
ITERATION 1265 0xffffffff8132f06c 0x11114000 | __lock_acquire.isra.0+0x59c (0xffffffff8132f06c)             
    call 0xffffffffffffc1d4 
    ??_NearBranch64_?? [e8, cf, c1, ff, ff]
ITERATION 1266 0xffffffff8132b240 0x11114000 | check_chain_key+0x0 (0xffffffff8132b240)                     
    push rbp 
    RBP:0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [55]
ITERATION 1267 0xffffffff8132b241 0x11114000 | check_chain_key+0x1 (0xffffffff8132b241)                     
    lea rax, [rdi+0xd08] 
    RAX:0xffff888007674300 -> 0x0
    [RDI:0xffff888007674300+0xd08=0xffff888007675008]] 
    [48, 8d, 87, 08, 0d, 00, 00]
ITERATION 1268 0xffffffff8132b248 0x11114000 | check_chain_key+0x8 (0xffffffff8132b248)                     
    mov r9, rdi 
    R9:0xfffffbfff0ba5615 -> 0x0
    RDI:0xffff888007674300 -> 0x0
    [49, 89, f9]
ITERATION 1269 0xffffffff8132b24b 0x11114000 | check_chain_key+0xb (0xffffffff8132b24b)                     
    mov rdx, rax 
    RDX:0x1ffff11000ecea01
    RAX:0xffff888007675008 -> ''
    [48, 89, c2]
ITERATION 1270 0xffffffff8132b24e 0x11114000 | check_chain_key+0xe (0xffffffff8132b24e)                     
    shr rdx, 0x3 
    RDX:0xffff888007675008 -> ''
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1271 0xffffffff8132b252 0x11114000 | check_chain_key+0x12 (0xffffffff8132b252)                    
    mov rbp, rsp 
    RBP:0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    RSP:0xffffc90000a1fdf8 -> 0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [48, 89, e5]
ITERATION 1272 0xffffffff8132b255 0x11114000 | check_chain_key+0x15 (0xffffffff8132b255)                    
    push r15 
    R15:0xf312b049
    [41, 57]
ITERATION 1273 0xffffffff8132b257 0x11114000 | check_chain_key+0x17 (0xffffffff8132b257)                    
    push r14 
    R14:0x5c0ca785
    [41, 56]
ITERATION 1274 0xffffffff8132b259 0x11114000 | check_chain_key+0x19 (0xffffffff8132b259)                    
    push r13 
    R13:[34mdebug_locks_silent+0x0 (0xffffffff85891e28)[39m -> 0x100000000
    [41, 55]
ITERATION 1275 0xffffffff8132b25b 0x11114000 | check_chain_key+0x1b (0xffffffff8132b25b)                    
    push r12 
    R12:0x0
    [41, 54]
ITERATION 1276 0xffffffff8132b25d 0x11114000 | check_chain_key+0x1d (0xffffffff8132b25d)                    
    push rbx 
    RBX:0xcda74fb54f1f57ce
    [53]
ITERATION 1277 0xffffffff8132b25e 0x11114000 | check_chain_key+0x1e (0xffffffff8132b25e)                    
    sub rsp, 0x30 
    RSP:0xffffc90000a1fdd0 -> 0xcda74fb54f1f57ce
    ??_Immediate8to64_?? [48, 83, ec, 30]
ITERATION 1278 0xffffffff8132b262 0x11114000 | check_chain_key+0x22 (0xffffffff8132b262)                    
    mov qword ptr [rbp-0x58], rax 
    [RBP:0xffffc90000a1fdf8+0xffffffffffffffa8=0x1ffffc90000a1fda0]] 
    RAX:0xffff888007675008 -> ''
    [48, 89, 45, a8]
ITERATION 1279 0xffffffff8132b266 0x11114000 | check_chain_key+0x26 (0xffffffff8132b266)                    
    mov rax, 0xdffffc0000000000 
    RAX:0xffff888007675008 -> ''
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1280 0xffffffff8132b270 0x11114000 | check_chain_key+0x30 (0xffffffff8132b270)                    
    movzx eax, byte ptr [rdx+rax] 
    EAX:0x0
    [RDX:0x1ffff11000ecea01+RAX:0xdffffc0000000000=0xffffed1000ecea01size:UInt8->0x0]] 
    [0f, b6, 04, 02]
ITERATION 1281 0xffffffff8132b274 0x11114000 | check_chain_key+0x34 (0xffffffff8132b274)                    
    test al, al 
    AL:0x0
    AL:0x0
    [84, c0]
ITERATION 1282 0xffffffff8132b276 0x11114000 | check_chain_key+0x36 (0xffffffff8132b276)                    
    je 0xa 
    ??_NearBranch64_?? [74, 08]
ITERATION 1283 0xffffffff8132b280 0x11114000 | check_chain_key+0x40 (0xffffffff8132b280)                    
    mov edx, dword ptr [r9+0xd08] 
    EDX:0xecea01
    [R9:0xffff888007674300+0xd08=0xffff888007675008size:UInt32->0x1]] 
    [41, 8b, 91, 08, 0d, 00, 00]
ITERATION 1284 0xffffffff8132b287 0x11114000 | check_chain_key+0x47 (0xffffffff8132b287)                    
    test edx, edx 
    EDX:0x1
    EDX:0x1
    [85, d2]
ITERATION 1285 0xffffffff8132b289 0x11114000 | check_chain_key+0x49 (0xffffffff8132b289)                    
    je 0x22b 
    ??_NearBranch64_?? [0f, 84, 25, 02, 00, 00]
ITERATION 1286 0xffffffff8132b28f 0x11114000 | check_chain_key+0x4f (0xffffffff8132b28f)                    
    mov r11, 0xffffffff860b81e0 
    R11:0xfffffbfff0ba5614 -> 0x0
    ??_Immediate32to64_?? [49, c7, c3, e0, 81, 0b, 86]
ITERATION 1287 0xffffffff8132b296 0x11114000 | check_chain_key+0x56 (0xffffffff8132b296)                    
    xor r14d, r14d 
    R14D:0x5c0ca785
    R14D:0x5c0ca785
    [45, 31, f6]
ITERATION 1288 0xffffffff8132b299 0x11114000 | check_chain_key+0x59 (0xffffffff8132b299)                    
    xor r13d, r13d 
    R13D:0x85891e28
    R13D:0x85891e28
    [45, 31, ed]
ITERATION 1289 0xffffffff8132b29c 0x11114000 | check_chain_key+0x5c (0xffffffff8132b29c)                    
    mov r15, 0xdffffc0000000000 
    R15:0xf312b049
    ??_Immediate64_?? [49, bf, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1290 0xffffffff8132b2a6 0x11114000 | check_chain_key+0x66 (0xffffffff8132b2a6)                    
    mov r10, r11 
    R10:[34mlock_classes_in_use+0x7 (0xffffffff85d2b0a7)[39m -> 0xffffffffffffffff
    R11:[34moops_in_progress+0x0 (0xffffffff860b81e0)[39m -> 0x0
    [4d, 89, da]
ITERATION 1291 0xffffffff8132b2a9 0x11114000 | check_chain_key+0x69 (0xffffffff8132b2a9)                    
    lea rcx, [r9+0xd10] 
    RCX:[34m__lock_acquire.isra.0+0x47a (0xffffffff8132ef4a)[39m -> 0x49fc14e1da30f48
    [R9:0xffff888007674300+0xd10=0xffff888007675010]] 
    [49, 8d, 89, 10, 0d, 00, 00]
ITERATION 1292 0xffffffff8132b2b0 0x11114000 | check_chain_key+0x70 (0xffffffff8132b2b0)                    
    mov r12, 0xffffffffffffffff 
    R12:0x0
    ??_Immediate32to64_?? [49, c7, c4, ff, ff, ff, ff]
ITERATION 1293 0xffffffff8132b2b7 0x11114000 | check_chain_key+0x77 (0xffffffff8132b2b7)                    
    shr r10, 0x3 
    R10:[34moops_in_progress+0x0 (0xffffffff860b81e0)[39m -> 0x0
    ??_Immediate8_?? [49, c1, ea, 03]
ITERATION 1294 0xffffffff8132b2bb 0x11114000 | check_chain_key+0x7b (0xffffffff8132b2bb)                    
    add r10, r15 
    R10:0x1ffffffff0c1703c
    R15:0xdffffc0000000000
    [4d, 01, fa]
ITERATION 1295 0xffffffff8132b2be 0x11114000 | check_chain_key+0x7e (0xffffffff8132b2be)                    
    jmp 0x8a 
    ??_NearBranch64_?? [e9, 85, 00, 00, 00]
ITERATION 1296 0xffffffff8132b348 0x11114000 | check_chain_key+0x108 (0xffffffff8132b348)                   
    mov eax, r14d 
    EAX:0x0
    R14D:0x0
    [44, 89, f0]
ITERATION 1297 0xffffffff8132b34b 0x11114000 | check_chain_key+0x10b (0xffffffff8132b34b)                   
    mov rdx, r13 
    RDX:0x1
    R13:0x0
    [4c, 89, ea]
ITERATION 1298 0xffffffff8132b34e 0x11114000 | check_chain_key+0x10e (0xffffffff8132b34e)                   
    lea rax, [rax+rax*4] 
    RAX:0x0
    [RAX:0x0+RAX:0x0*0x4] 
    [48, 8d, 04, 80]
ITERATION 1299 0xffffffff8132b352 0x11114000 | check_chain_key+0x112 (0xffffffff8132b352)                   
    lea r13, [rcx+rax*8] 
    R13:0x0
    [RCX:0xffff888007675010+RAX:0x0*0x8] 
    [4c, 8d, 2c, c1]
ITERATION 1300 0xffffffff8132b356 0x11114000 | check_chain_key+0x116 (0xffffffff8132b356)                   
    mov rax, r13 
    RAX:0x0
    R13:0xffff888007675010 -> 0xffffffffffffffff
    [4c, 89, e8]
ITERATION 1301 0xffffffff8132b359 0x11114000 | check_chain_key+0x119 (0xffffffff8132b359)                   
    shr rax, 0x3 
    RAX:0xffff888007675010 -> 0xffffffffffffffff
    ??_Immediate8_?? [48, c1, e8, 03]
ITERATION 1302 0xffffffff8132b35d 0x11114000 | check_chain_key+0x11d (0xffffffff8132b35d)                   
    cmp byte ptr [rax+r15], 0x0 
    [RAX:0x1ffff11000ecea02+R15:0xdffffc0000000000=0xffffed1000ecea02size:UInt8->0x0]] 
    ??_Immediate8_?? [42, 80, 3c, 38, 00]
ITERATION 1303 0xffffffff8132b362 0x11114000 | check_chain_key+0x122 (0xffffffff8132b362)                   
    jne 0x306 
    ??_NearBranch64_?? [0f, 85, 00, 03, 00, 00]
ITERATION 1304 0xffffffff8132b368 0x11114000 | check_chain_key+0x128 (0xffffffff8132b368)                   
    cmp qword ptr [r13], r12 
    [R13:0xffff888007675010size:UInt64->0xffffffffffffffff]] 
    R12:0xffffffffffffffff
    [4d, 39, 65, 00]
ITERATION 1305 0xffffffff8132b36c 0x11114000 | check_chain_key+0x12c (0xffffffff8132b36c)                   
    jne 0x194 
    ??_NearBranch64_?? [0f, 85, 8e, 01, 00, 00]
ITERATION 1306 0xffffffff8132b372 0x11114000 | check_chain_key+0x132 (0xffffffff8132b372)                   
    mov rax, r11 
    RAX:0x1ffff11000ecea02
    R11:[34moops_in_progress+0x0 (0xffffffff860b81e0)[39m -> 0x0
    [4c, 89, d8]
ITERATION 1307 0xffffffff8132b375 0x11114000 | check_chain_key+0x135 (0xffffffff8132b375)                   
    movzx esi, byte ptr [r10] 
    ESI:0xffffffff
    [R10:0xfffffbfff0c1703csize:UInt8->0x4]] 
    [41, 0f, b6, 32]
ITERATION 1308 0xffffffff8132b379 0x11114000 | check_chain_key+0x139 (0xffffffff8132b379)                   
    and eax, 0x7 
    EAX:0x860b81e0
    ??_Immediate8to32_?? [83, e0, 07]
ITERATION 1309 0xffffffff8132b37c 0x11114000 | check_chain_key+0x13c (0xffffffff8132b37c)                   
    add eax, 0x3 
    EAX:0x0
    ??_Immediate8to32_?? [83, c0, 03]
ITERATION 1310 0xffffffff8132b37f 0x11114000 | check_chain_key+0x13f (0xffffffff8132b37f)                   
    cmp al, sil 
    AL:0x3
    SIL:0x4
    [40, 38, f0]
ITERATION 1311 0xffffffff8132b382 0x11114000 | check_chain_key+0x142 (0xffffffff8132b382)                   
    jl 0xb 
    ??_NearBranch64_?? [7c, 09]
ITERATION 1312 0xffffffff8132b38d 0x11114000 | check_chain_key+0x14d (0xffffffff8132b38d)                   
    lea r8, [r13+0x20] 
    R8:0x1
    [R13:0xffff888007675010+0x20=0xffff888007675030]] 
    [4d, 8d, 45, 20]
ITERATION 1313 0xffffffff8132b391 0x11114000 | check_chain_key+0x151 (0xffffffff8132b391)                   
    mov ebx, dword ptr [rip+0x4d8ce49] 
    EBX:0x4f1f57ce
    [RIP:0xffffffff8132b391+0x4d8ce4f=0xffffffff860b81e0size:UInt32->0x0]] 
    [8b, 1d, 49, ce, d8, 04]
ITERATION 1314 0xffffffff8132b397 0x11114000 | check_chain_key+0x157 (0xffffffff8132b397)                   
    mov rax, r8 
    RAX:0x3
    R8:0xffff888007675030 -> ''
    [4c, 89, c0]
ITERATION 1315 0xffffffff8132b39a 0x11114000 | check_chain_key+0x15a (0xffffffff8132b39a)                   
    shr rax, 0x3 
    RAX:0xffff888007675030 -> ''
    ??_Immediate8_?? [48, c1, e8, 03]
ITERATION 1316 0xffffffff8132b39e 0x11114000 | check_chain_key+0x15e (0xffffffff8132b39e)                   
    movzx eax, byte ptr [rax+r15] 
    EAX:0xecea06
    [RAX:0x1ffff11000ecea06+R15:0xdffffc0000000000=0xffffed1000ecea06size:UInt8->0x0]] 
    [42, 0f, b6, 04, 38]
ITERATION 1317 0xffffffff8132b3a3 0x11114000 | check_chain_key+0x163 (0xffffffff8132b3a3)                   
    test al, al 
    AL:0x0
    AL:0x0
    [84, c0]
ITERATION 1318 0xffffffff8132b3a5 0x11114000 | check_chain_key+0x165 (0xffffffff8132b3a5)                   
    je 0xa 
    ??_NearBranch64_?? [74, 08]
ITERATION 1319 0xffffffff8132b3af 0x11114000 | check_chain_key+0x16f (0xffffffff8132b3af)                   
    movzx eax, word ptr [r13+0x20] 
    EAX:0x0
    [R13:0xffff888007675010+0x20=0xffff888007675030size:UInt16->0x2]] 
    [41, 0f, b7, 45, 20]
ITERATION 1320 0xffffffff8132b3b4 0x11114000 | check_chain_key+0x174 (0xffffffff8132b3b4)                   
    and ax, 0x1fff 
    AX:0x2
    ??_Immediate16_?? [66, 25, ff, 1f]
ITERATION 1321 0xffffffff8132b3b8 0x11114000 | check_chain_key+0x178 (0xffffffff8132b3b8)                   
    test ebx, ebx 
    EBX:0x0
    EBX:0x0
    [85, db]
ITERATION 1322 0xffffffff8132b3ba 0x11114000 | check_chain_key+0x17a (0xffffffff8132b3ba)                   
    je 0x7b 
    ??_NearBranch64_?? [74, 79]
ITERATION 1323 0xffffffff8132b435 0x11114000 | check_chain_key+0x1f5 (0xffffffff8132b435)                   
    movzx ebx, ax 
    EBX:0x0
    AX:0x2
    [0f, b7, d8]
ITERATION 1324 0xffffffff8132b438 0x11114000 | check_chain_key+0x1f8 (0xffffffff8132b438)                   
    mov esi, 0x8 
    ESI:0x4
    ??_Immediate32_?? [be, 08, 00, 00, 00]
ITERATION 1325 0xffffffff8132b43d 0x11114000 | check_chain_key+0x1fd (0xffffffff8132b43d)                   
    mov qword ptr [rbp-0x50], r10 
    [RBP:0xffffc90000a1fdf8+0xffffffffffffffb0=0x1ffffc90000a1fda8]] 
    R10:0xfffffbfff0c1703c -> 0xf9f9f9f9f9f9f904 -> 0x0
    [4c, 89, 55, b0]
ITERATION 1326 0xffffffff8132b441 0x11114000 | check_chain_key+0x201 (0xffffffff8132b441)                   
    mov rax, rbx 
    RAX:0x2
    RBX:0x2
    [48, 89, d8]
ITERATION 1327 0xffffffff8132b444 0x11114000 | check_chain_key+0x204 (0xffffffff8132b444)                   
    mov qword ptr [rbp-0x48], r9 
    [RBP:0xffffc90000a1fdf8+0xffffffffffffffb8=0x1ffffc90000a1fdb0]] 
    R9:0xffff888007674300 -> 0x0
    [4c, 89, 4d, b8]
ITERATION 1328 0xffffffff8132b448 0x11114000 | check_chain_key+0x208 (0xffffffff8132b448)                   
    sar rax, 0x6 
    RAX:0x2
    ??_Immediate8_?? [48, c1, f8, 06]
ITERATION 1329 0xffffffff8132b44c 0x11114000 | check_chain_key+0x20c (0xffffffff8132b44c)                   
    mov qword ptr [rbp-0x40], rdx 
    [RBP:0xffffc90000a1fdf8+0xffffffffffffffc0=0x1ffffc90000a1fdb8]] 
    RDX:0x0
    [48, 89, 55, c0]
ITERATION 1330 0xffffffff8132b450 0x11114000 | check_chain_key+0x210 (0xffffffff8132b450)                   
    lea rdi, [rax*8-0x7a2d4f60] 
    RDI:0xffff888007674300 -> 0x0
    [None:0x0+RAX:0x0*0x8+0xffffffff85d2b0a0=0xffffffff85d2b0a0]] 
    [48, 8d, 3c, c5, a0, b0, d2, 85]
ITERATION 1331 0xffffffff8132b458 0x11114000 | check_chain_key+0x218 (0xffffffff8132b458)                   
    mov qword ptr [rbp-0x38], rcx 
    [RBP:0xffffc90000a1fdf8+0xffffffffffffffc8=0x1ffffc90000a1fdc0]] 
    RCX:0xffff888007675010 -> 0xffffffffffffffff
    [48, 89, 4d, c8]
ITERATION 1332 0xffffffff8132b45c 0x11114000 | check_chain_key+0x21c (0xffffffff8132b45c)                   
    mov qword ptr [rbp-0x30], r8 
    [RBP:0xffffc90000a1fdf8+0xffffffffffffffd0=0x1ffffc90000a1fdc8]] 
    R8:0xffff888007675030 -> ''
    [4c, 89, 45, d0]
ITERATION 1333 0xffffffff8132b460 0x11114000 | check_chain_key+0x220 (0xffffffff8132b460)                   
    call 0x6108e0 
    ??_NearBranch64_?? [e8, db, 08, 61, 00]
ITERATION 1334 0xffffffff8193bd40 0x11114000 | __kasan_check_read+0x0 (0xffffffff8193bd40)                  
    push rbp 
    RBP:0xffffc90000a1fdf8 -> 0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [55]
ITERATION 1335 0xffffffff8193bd41 0x11114000 | __kasan_check_read+0x1 (0xffffffff8193bd41)                  
    mov esi, esi 
    ESI:0x8
    ESI:0x8
    [89, f6]
ITERATION 1336 0xffffffff8193bd43 0x11114000 | __kasan_check_read+0x3 (0xffffffff8193bd43)                  
    xor edx, edx 
    EDX:0x0
    EDX:0x0
    [31, d2]
ITERATION 1337 0xffffffff8193bd45 0x11114000 | __kasan_check_read+0x5 (0xffffffff8193bd45)                  
    mov rbp, rsp 
    RBP:0xffffc90000a1fdf8 -> 0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    RSP:0xffffc90000a1fd90 -> 0xffffc90000a1fdf8 -> 0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 ... 
    [48, 89, e5]
ITERATION 1338 0xffffffff8193bd48 0x11114000 | __kasan_check_read+0x8 (0xffffffff8193bd48)                  
    mov rcx, qword ptr [rbp+0x8] 
    RCX:0xffff888007675010 -> 0xffffffffffffffff
    [RBP:0xffffc90000a1fd90+0x8=0xffffc90000a1fd98size:UInt64->0xffffffff8132b465]] 
    [48, 8b, 4d, 08]
ITERATION 1339 0xffffffff8193bd4c 0x11114000 | __kasan_check_read+0xc (0xffffffff8193bd4c)                  
    call 0xfffffffffffff784 
    ??_NearBranch64_?? [e8, 7f, f7, ff, ff]
ITERATION 1340 0xffffffff8193b4d0 0x11114000 | kasan_check_range+0x0 (0xffffffff8193b4d0)                   
    test rsi, rsi 
    RSI:0x8
    RSI:0x8
    [48, 85, f6]
ITERATION 1341 0xffffffff8193b4d3 0x11114000 | kasan_check_range+0x3 (0xffffffff8193b4d3)                   
    je 0x199 
    ??_NearBranch64_?? [0f, 84, 93, 01, 00, 00]
ITERATION 1342 0xffffffff8193b4d9 0x11114000 | kasan_check_range+0x9 (0xffffffff8193b4d9)                   
    push rbp 
    RBP:0xffffc90000a1fd90 -> 0xffffc90000a1fdf8 -> 0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 ... 
    [55]
ITERATION 1343 0xffffffff8193b4da 0x11114000 | kasan_check_range+0xa (0xffffffff8193b4da)                   
    mov r10, rdi 
    R10:0xfffffbfff0c1703c -> 0xf9f9f9f9f9f9f904 -> 0x0
    RDI:[34mlock_classes_in_use+0x0 (0xffffffff85d2b0a0)[39m -> 0xffffffffffffffff
    [49, 89, fa]
ITERATION 1344 0xffffffff8193b4dd 0x11114000 | kasan_check_range+0xd (0xffffffff8193b4dd)                   
    movzx edx, dl 
    EDX:0x0
    DL:0x0
    [0f, b6, d2]
ITERATION 1345 0xffffffff8193b4e0 0x11114000 | kasan_check_range+0x10 (0xffffffff8193b4e0)                  
    mov rbp, rsp 
    RBP:0xffffc90000a1fd90 -> 0xffffc90000a1fdf8 -> 0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 ... 
    RSP:0xffffc90000a1fd80 -> 0xffffc90000a1fd90 -> 0xffffc90000a1fdf8 -> 0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 ... 
    [48, 89, e5]
ITERATION 1346 0xffffffff8193b4e3 0x11114000 | kasan_check_range+0x13 (0xffffffff8193b4e3)                  
    push r13 
    R13:0xffff888007675010 -> 0xffffffffffffffff
    [41, 55]
ITERATION 1347 0xffffffff8193b4e5 0x11114000 | kasan_check_range+0x15 (0xffffffff8193b4e5)                  
    push r12 
    R12:0xffffffffffffffff
    [41, 54]
ITERATION 1348 0xffffffff8193b4e7 0x11114000 | kasan_check_range+0x17 (0xffffffff8193b4e7)                  
    push rbx 
    RBX:0x2
    [53]
ITERATION 1349 0xffffffff8193b4e8 0x11114000 | kasan_check_range+0x18 (0xffffffff8193b4e8)                  
    add r10, rsi 
    R10:[34mlock_classes_in_use+0x0 (0xffffffff85d2b0a0)[39m -> 0xffffffffffffffff
    RSI:0x8
    [49, 01, f2]
ITERATION 1350 0xffffffff8193b4eb 0x11114000 | kasan_check_range+0x1b (0xffffffff8193b4eb)                  
    jb 0x16c 
    ??_NearBranch64_?? [0f, 82, 66, 01, 00, 00]
ITERATION 1351 0xffffffff8193b4f1 0x11114000 | kasan_check_range+0x21 (0xffffffff8193b4f1)                  
    jmp 0xc2 
    ??_NearBranch64_?? [e9, bd, 00, 00, 00]
ITERATION 1352 0xffffffff8193b5b3 0x11114000 | kasan_check_range+0xe3 (0xffffffff8193b5b3)                  
    mov rax, 0xffff800000000000 
    RAX:0x0
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, 80, ff, ff]
ITERATION 1353 0xffffffff8193b5bd 0x11114000 | kasan_check_range+0xed (0xffffffff8193b5bd)                  
    jmp 0xffffffffffffff43 
    ??_NearBranch64_?? [e9, 3e, ff, ff, ff]
ITERATION 1354 0xffffffff8193b500 0x11114000 | kasan_check_range+0x30 (0xffffffff8193b500)                  
    cmp rax, rdi 
    RAX:0xffff800000000000
    RDI:[34mlock_classes_in_use+0x0 (0xffffffff85d2b0a0)[39m -> 0xffffffffffffffff
    [48, 39, f8]
ITERATION 1355 0xffffffff8193b503 0x11114000 | kasan_check_range+0x33 (0xffffffff8193b503)                  
    ja 0x154 
    ??_NearBranch64_?? [0f, 87, 4e, 01, 00, 00]
ITERATION 1356 0xffffffff8193b509 0x11114000 | kasan_check_range+0x39 (0xffffffff8193b509)                  
    sub r10, 0x1 
    R10:[34mlock_classes_in_use+0x8 (0xffffffff85d2b0a8)[39m -> 0xffffffffffffffff
    ??_Immediate8to64_?? [49, 83, ea, 01]
ITERATION 1357 0xffffffff8193b50d 0x11114000 | kasan_check_range+0x3d (0xffffffff8193b50d)                  
    mov r8, rdi 
    R8:0xffff888007675030 -> ''
    RDI:[34mlock_classes_in_use+0x0 (0xffffffff85d2b0a0)[39m -> 0xffffffffffffffff
    [49, 89, f8]
ITERATION 1358 0xffffffff8193b510 0x11114000 | kasan_check_range+0x40 (0xffffffff8193b510)                  
    mov rax, 0xdffffc0000000000 
    RAX:0xffff800000000000
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1359 0xffffffff8193b51a 0x11114000 | kasan_check_range+0x4a (0xffffffff8193b51a)                  
    mov r11, r10 
    R11:[34moops_in_progress+0x0 (0xffffffff860b81e0)[39m -> 0x0
    R10:[34mlock_classes_in_use+0x7 (0xffffffff85d2b0a7)[39m -> 0xffffffffffffffff
    [4d, 89, d3]
ITERATION 1360 0xffffffff8193b51d 0x11114000 | kasan_check_range+0x4d (0xffffffff8193b51d)                  
    shr r8, 0x3 
    R8:[34mlock_classes_in_use+0x0 (0xffffffff85d2b0a0)[39m -> 0xffffffffffffffff
    ??_Immediate8_?? [49, c1, e8, 03]
ITERATION 1361 0xffffffff8193b521 0x11114000 | kasan_check_range+0x51 (0xffffffff8193b521)                  
    shr r11, 0x3 
    R11:[34mlock_classes_in_use+0x7 (0xffffffff85d2b0a7)[39m -> 0xffffffffffffffff
    ??_Immediate8_?? [49, c1, eb, 03]
ITERATION 1362 0xffffffff8193b525 0x11114000 | kasan_check_range+0x55 (0xffffffff8193b525)                  
    lea r12, [r8+rax] 
    R12:0xffffffffffffffff
    [R8:0x1ffffffff0ba5614+RAX:0xdffffc0000000000=0xfffffbfff0ba5614]] 
    [4d, 8d, 24, 00]
ITERATION 1363 0xffffffff8193b529 0x11114000 | kasan_check_range+0x59 (0xffffffff8193b529)                  
    add r11, rax 
    R11:0x1ffffffff0ba5614
    RAX:0xdffffc0000000000
    [49, 01, c3]
ITERATION 1364 0xffffffff8193b52c 0x11114000 | kasan_check_range+0x5c (0xffffffff8193b52c)                  
    mov rax, r12 
    RAX:0xdffffc0000000000
    R12:0xfffffbfff0ba5614 -> 0x0
    [4c, 89, e0]
ITERATION 1365 0xffffffff8193b52f 0x11114000 | kasan_check_range+0x5f (0xffffffff8193b52f)                  
    lea rbx, [r11+0x1] 
    RBX:0x2
    [R11:0xfffffbfff0ba5614+0x1=0xfffffbfff0ba5615]] 
    [49, 8d, 5b, 01]
ITERATION 1366 0xffffffff8193b533 0x11114000 | kasan_check_range+0x63 (0xffffffff8193b533)                  
    mov r9, rbx 
    R9:0xffff888007674300 -> 0x0
    RBX:0xfffffbfff0ba5615 -> 0x0
    [49, 89, d9]
ITERATION 1367 0xffffffff8193b536 0x11114000 | kasan_check_range+0x66 (0xffffffff8193b536)                  
    sub r9, r12 
    R9:0xfffffbfff0ba5615 -> 0x0
    R12:0xfffffbfff0ba5614 -> 0x0
    [4d, 29, e1]
ITERATION 1368 0xffffffff8193b539 0x11114000 | kasan_check_range+0x69 (0xffffffff8193b539)                  
    cmp r9, 0x10 
    R9:0x1
    ??_Immediate8to64_?? [49, 83, f9, 10]
ITERATION 1369 0xffffffff8193b53d 0x11114000 | kasan_check_range+0x6d (0xffffffff8193b53d)                  
    jle 0xde 
    ??_NearBranch64_?? [0f, 8e, d8, 00, 00, 00]
ITERATION 1370 0xffffffff8193b61b 0x11114000 | kasan_check_range+0x14b (0xffffffff8193b61b)                 
    test r9, r9 
    R9:0x1
    R9:0x1
    [4d, 85, c9]
ITERATION 1371 0xffffffff8193b61e 0x11114000 | kasan_check_range+0x14e (0xffffffff8193b61e)                 
    je 0xffffffffffffffed 
    ??_NearBranch64_?? [74, eb]
ITERATION 1372 0xffffffff8193b620 0x11114000 | kasan_check_range+0x150 (0xffffffff8193b620)                 
    add r9, r12 
    R9:0x1
    R12:0xfffffbfff0ba5614 -> 0x0
    [4d, 01, e1]
ITERATION 1373 0xffffffff8193b623 0x11114000 | kasan_check_range+0x153 (0xffffffff8193b623)                 
    jmp 0xb 
    ??_NearBranch64_?? [eb, 09]
ITERATION 1374 0xffffffff8193b62e 0x11114000 | kasan_check_range+0x15e (0xffffffff8193b62e)                 
    cmp byte ptr [rax], 0x0 
    [RAX:0xfffffbfff0ba5614size:UInt8->0x0]] 
    ??_Immediate8_?? [80, 38, 00]
ITERATION 1375 0xffffffff8193b631 0x11114000 | kasan_check_range+0x161 (0xffffffff8193b631)                 
    je 0xfffffffffffffff4 
    ??_NearBranch64_?? [74, f2]
ITERATION 1376 0xffffffff8193b625 0x11114000 | kasan_check_range+0x155 (0xffffffff8193b625)                 
    add rax, 0x1 
    RAX:0xfffffbfff0ba5614 -> 0x0
    ??_Immediate8to64_?? [48, 83, c0, 01]
ITERATION 1377 0xffffffff8193b629 0x11114000 | kasan_check_range+0x159 (0xffffffff8193b629)                 
    cmp rax, r9 
    RAX:0xfffffbfff0ba5615 -> 0x0
    R9:0xfffffbfff0ba5615 -> 0x0
    [4c, 39, c8]
ITERATION 1378 0xffffffff8193b62c 0x11114000 | kasan_check_range+0x15c (0xffffffff8193b62c)                 
    je 0xffffffffffffffdf 
    ??_NearBranch64_?? [74, dd]
ITERATION 1379 0xffffffff8193b60b 0x11114000 | kasan_check_range+0x13b (0xffffffff8193b60b)                 
    mov r8d, 0x1 
    R8D:0xf0ba5614
    ??_Immediate32_?? [41, b8, 01, 00, 00, 00]
ITERATION 1380 0xffffffff8193b611 0x11114000 | kasan_check_range+0x141 (0xffffffff8193b611)                 
    pop rbx 
    RBX:0xfffffbfff0ba5615 -> 0x0
    [5b]
ITERATION 1381 0xffffffff8193b612 0x11114000 | kasan_check_range+0x142 (0xffffffff8193b612)                 
    pop r12 
    R12:0xfffffbfff0ba5614 -> 0x0
    [41, 5c]
ITERATION 1382 0xffffffff8193b614 0x11114000 | kasan_check_range+0x144 (0xffffffff8193b614)                 
    mov eax, r8d 
    EAX:0xf0ba5615
    R8D:0x1
    [44, 89, c0]
ITERATION 1383 0xffffffff8193b617 0x11114000 | kasan_check_range+0x147 (0xffffffff8193b617)                 
    pop r13 
    R13:0xffff888007675010 -> 0xffffffffffffffff
    [41, 5d]
ITERATION 1384 0xffffffff8193b619 0x11114000 | kasan_check_range+0x149 (0xffffffff8193b619)                 
    pop rbp 
    RBP:0xffffc90000a1fd80 -> 0xffffc90000a1fd90 -> 0xffffc90000a1fdf8 -> 0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 ... 
    [5d]
ITERATION 1385 0xffffffff8193b61a 0x11114000 | kasan_check_range+0x14a (0xffffffff8193b61a)                 
    ret 
    [c3]
ITERATION 1386 0xffffffff8193bd51 0x11114000 | __kasan_check_read+0x11 (0xffffffff8193bd51)                 
    pop rbp 
    RBP:0xffffc90000a1fd90 -> 0xffffc90000a1fdf8 -> 0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 ... 
    [5d]
ITERATION 1387 0xffffffff8193bd52 0x11114000 | __kasan_check_read+0x12 (0xffffffff8193bd52)                 
    ret 
    [c3]
ITERATION 1388 0xffffffff8132b465 0x11114000 | check_chain_key+0x225 (0xffffffff8132b465)                   
    bt qword ptr [rip+0x49ffc33], rbx 
    [RIP:0xffffffff8132b465+0x49ffc3b=0xffffffff85d2b0a0]] 
    RBX:0x2
    [48, 0f, a3, 1d, 33, fc, 9f, 04]
ITERATION 1389 0xffffffff8132b46d 0x11114000 | check_chain_key+0x22d (0xffffffff8132b46d)                   
    jae 0x10b 
    ??_NearBranch64_?? [0f, 83, 05, 01, 00, 00]
ITERATION 1390 0xffffffff8132b473 0x11114000 | check_chain_key+0x233 (0xffffffff8132b473)                   
    mov r8, qword ptr [rbp-0x30] 
    R8:0x1
    [RBP:0xffffc90000a1fdf8+0xffffffffffffffd0=0xffffc90000a1fdc8size:UInt64->0xffff888007675030]] 
    [4c, 8b, 45, d0]
ITERATION 1391 0xffffffff8132b477 0x11114000 | check_chain_key+0x237 (0xffffffff8132b477)                   
    mov rcx, qword ptr [rbp-0x38] 
    RCX:[34mcheck_chain_key+0x225 (0xffffffff8132b465)[39m -> 0x49ffc331da30f48
    [RBP:0xffffc90000a1fdf8+0xffffffffffffffc8=0xffffc90000a1fdc0size:UInt64->0xffff888007675010]] 
    [48, 8b, 4d, c8]
ITERATION 1392 0xffffffff8132b47b 0x11114000 | check_chain_key+0x23b (0xffffffff8132b47b)                   
    mov r11, 0xffffffff860b81e0 
    R11:0xfffffbfff0ba5614 -> 0x0
    ??_Immediate32to64_?? [49, c7, c3, e0, 81, 0b, 86]
ITERATION 1393 0xffffffff8132b482 0x11114000 | check_chain_key+0x242 (0xffffffff8132b482)                   
    mov rdx, qword ptr [rbp-0x40] 
    RDX:0x0
    [RBP:0xffffc90000a1fdf8+0xffffffffffffffc0=0xffffc90000a1fdb8size:UInt64->0x0]] 
    [48, 8b, 55, c0]
ITERATION 1394 0xffffffff8132b486 0x11114000 | check_chain_key+0x246 (0xffffffff8132b486)                   
    mov r9, qword ptr [rbp-0x48] 
    R9:0xfffffbfff0ba5615 -> 0x0
    [RBP:0xffffc90000a1fdf8+0xffffffffffffffb8=0xffffc90000a1fdb0size:UInt64->0xffff888007674300]] 
    [4c, 8b, 4d, b8]
ITERATION 1395 0xffffffff8132b48a 0x11114000 | check_chain_key+0x24a (0xffffffff8132b48a)                   
    mov rax, r8 
    RAX:0x1
    R8:0xffff888007675030 -> ''
    [4c, 89, c0]
ITERATION 1396 0xffffffff8132b48d 0x11114000 | check_chain_key+0x24d (0xffffffff8132b48d)                   
    mov r10, qword ptr [rbp-0x50] 
    R10:[34mlock_classes_in_use+0x7 (0xffffffff85d2b0a7)[39m -> 0xffffffffffffffff
    [RBP:0xffffc90000a1fdf8+0xffffffffffffffb0=0xffffc90000a1fda8size:UInt64->0xfffffbfff0c1703c]] 
    [4c, 8b, 55, b0]
ITERATION 1397 0xffffffff8132b491 0x11114000 | check_chain_key+0x251 (0xffffffff8132b491)                   
    shr rax, 0x3 
    RAX:0xffff888007675030 -> ''
    ??_Immediate8_?? [48, c1, e8, 03]
ITERATION 1398 0xffffffff8132b495 0x11114000 | check_chain_key+0x255 (0xffffffff8132b495)                   
    movzx eax, byte ptr [rax+r15] 
    EAX:0xecea06
    [RAX:0x1ffff11000ecea06+R15:0xdffffc0000000000=0xffffed1000ecea06size:UInt8->0x0]] 
    [42, 0f, b6, 04, 38]
ITERATION 1399 0xffffffff8132b49a 0x11114000 | check_chain_key+0x25a (0xffffffff8132b49a)                   
    test al, al 
    AL:0x0
    AL:0x0
    [84, c0]
ITERATION 1400 0xffffffff8132b49c 0x11114000 | check_chain_key+0x25c (0xffffffff8132b49c)                   
    je 0xa 
    ??_NearBranch64_?? [74, 08]
ITERATION 1401 0xffffffff8132b4a6 0x11114000 | check_chain_key+0x266 (0xffffffff8132b4a6)                   
    movzx eax, word ptr [r13+0x20] 
    EAX:0x0
    [R13:0xffff888007675010+0x20=0xffff888007675030size:UInt16->0x2]] 
    [41, 0f, b7, 45, 20]
ITERATION 1402 0xffffffff8132b4ab 0x11114000 | check_chain_key+0x26b (0xffffffff8132b4ab)                   
    and ax, 0x1fff 
    AX:0x2
    ??_Immediate16_?? [66, 25, ff, 1f]
ITERATION 1403 0xffffffff8132b4af 0x11114000 | check_chain_key+0x26f (0xffffffff8132b4af)                   
    jmp 0xffffffffffffff0d 
    ??_NearBranch64_?? [e9, 08, ff, ff, ff]
ITERATION 1404 0xffffffff8132b3bc 0x11114000 | check_chain_key+0x17c (0xffffffff8132b3bc)                   
    test rdx, rdx 
    RDX:0x0
    RDX:0x0
    [48, 85, d2]
ITERATION 1405 0xffffffff8132b3bf 0x11114000 | check_chain_key+0x17f (0xffffffff8132b3bf)                   
    je 0x5b 
    ??_NearBranch64_?? [74, 59]
ITERATION 1406 0xffffffff8132b41a 0x11114000 | check_chain_key+0x1da (0xffffffff8132b41a)                   
    mov r8, r12 
    R8:0xffff888007675030 -> ''
    R12:0xffffffffffffffff
    [4d, 89, e0]
ITERATION 1407 0xffffffff8132b41d 0x11114000 | check_chain_key+0x1dd (0xffffffff8132b41d)                   
    mov edx, r12d 
    EDX:0x0
    R12D:0xffffffff
    [44, 89, e2]
ITERATION 1408 0xffffffff8132b420 0x11114000 | check_chain_key+0x1e0 (0xffffffff8132b420)                   
    shr r8, 0x20 
    R8:0xffffffffffffffff
    ??_Immediate8_?? [49, c1, e8, 20]
ITERATION 1409 0xffffffff8132b424 0x11114000 | check_chain_key+0x1e4 (0xffffffff8132b424)                   
    mov esi, r8d 
    ESI:0x8
    R8D:0xffffffff
    [44, 89, c6]
ITERATION 1410 0xffffffff8132b427 0x11114000 | check_chain_key+0x1e7 (0xffffffff8132b427)                   
    mov edi, r8d 
    EDI:0x85d2b0a0
    R8D:0xffffffff
    [44, 89, c7]
ITERATION 1411 0xffffffff8132b42a 0x11114000 | check_chain_key+0x1ea (0xffffffff8132b42a)                   
    add r12d, r8d 
    R12D:0xffffffff
    R8D:0xffffffff
    [45, 01, c4]
ITERATION 1412 0xffffffff8132b42d 0x11114000 | check_chain_key+0x1ed (0xffffffff8132b42d)                   
    rol esi, 0x4 
    ESI:0xffffffff
    ??_Immediate8_?? [c1, c6, 04]
ITERATION 1413 0xffffffff8132b430 0x11114000 | check_chain_key+0x1f0 (0xffffffff8132b430)                   
    jmp 0xfffffffffffffea8 
    ??_NearBranch64_?? [e9, a3, fe, ff, ff]
ITERATION 1414 0xffffffff8132b2d8 0x11114000 | check_chain_key+0x98 (0xffffffff8132b2d8)                    
    movzx ebx, byte ptr [r13+0x22] 
    EBX:0x2
    [R13:0xffff888007675010+0x22=0xffff888007675032size:UInt8->0x2]] 
    [41, 0f, b6, 5d, 22]
ITERATION 1415 0xffffffff8132b2dd 0x11114000 | check_chain_key+0x9d (0xffffffff8132b2dd)                    
    add r14d, 0x1 
    R14D:0x0
    ??_Immediate8to32_?? [41, 83, c6, 01]
ITERATION 1416 0xffffffff8132b2e1 0x11114000 | check_chain_key+0xa1 (0xffffffff8132b2e1)                    
    and ebx, 0x3 
    EBX:0x2
    ??_Immediate8to32_?? [83, e3, 03]
ITERATION 1417 0xffffffff8132b2e4 0x11114000 | check_chain_key+0xa4 (0xffffffff8132b2e4)                    
    shl ebx, 0xd 
    EBX:0x2
    ??_Immediate8_?? [c1, e3, 0d]
ITERATION 1418 0xffffffff8132b2e7 0x11114000 | check_chain_key+0xa7 (0xffffffff8132b2e7)                    
    or ebx, eax 
    EBX:0x4000
    EAX:0x2
    [09, c3]
ITERATION 1419 0xffffffff8132b2e9 0x11114000 | check_chain_key+0xa9 (0xffffffff8132b2e9)                    
    movsx ebx, bx 
    EBX:0x4002
    BX:0x4002
    [0f, bf, db]
ITERATION 1420 0xffffffff8132b2ec 0x11114000 | check_chain_key+0xac (0xffffffff8132b2ec)                    
    sub ebx, edi 
    EBX:0x4002
    EDI:0xffffffff
    [29, fb]
ITERATION 1421 0xffffffff8132b2ee 0x11114000 | check_chain_key+0xae (0xffffffff8132b2ee)                    
    xor ebx, esi 
    EBX:0x4003
    ESI:0xffffffff
    [31, f3]
ITERATION 1422 0xffffffff8132b2f0 0x11114000 | check_chain_key+0xb0 (0xffffffff8132b2f0)                    
    mov eax, ebx 
    EAX:0x2
    EBX:0xffffbffc
    [89, d8]
ITERATION 1423 0xffffffff8132b2f2 0x11114000 | check_chain_key+0xb2 (0xffffffff8132b2f2)                    
    sub edx, ebx 
    EDX:0xffffffff
    EBX:0xffffbffc
    [29, da]
ITERATION 1424 0xffffffff8132b2f4 0x11114000 | check_chain_key+0xb4 (0xffffffff8132b2f4)                    
    add ebx, r12d 
    EBX:0xffffbffc
    R12D:0xfffffffe
    [44, 01, e3]
ITERATION 1425 0xffffffff8132b2f7 0x11114000 | check_chain_key+0xb7 (0xffffffff8132b2f7)                    
    rol eax, 0x6 
    EAX:0xffffbffc
    ??_Immediate8_?? [c1, c0, 06]
ITERATION 1426 0xffffffff8132b2fa 0x11114000 | check_chain_key+0xba (0xffffffff8132b2fa)                    
    xor edx, eax 
    EDX:0x4003
    EAX:0xffefff3f
    [31, c2]
ITERATION 1427 0xffffffff8132b2fc 0x11114000 | check_chain_key+0xbc (0xffffffff8132b2fc)                    
    mov eax, edx 
    EAX:0xffefff3f
    EDX:0xffefbf3c
    [89, d0]
ITERATION 1428 0xffffffff8132b2fe 0x11114000 | check_chain_key+0xbe (0xffffffff8132b2fe)                    
    sub r12d, edx 
    R12D:0xfffffffe
    EDX:0xffefbf3c
    [41, 29, d4]
ITERATION 1429 0xffffffff8132b301 0x11114000 | check_chain_key+0xc1 (0xffffffff8132b301)                    
    add edx, ebx 
    EDX:0xffefbf3c
    EBX:0xffffbffa
    [01, da]
ITERATION 1430 0xffffffff8132b303 0x11114000 | check_chain_key+0xc3 (0xffffffff8132b303)                    
    rol eax, 0x8 
    EAX:0xffefbf3c
    ??_Immediate8_?? [c1, c0, 08]
ITERATION 1431 0xffffffff8132b306 0x11114000 | check_chain_key+0xc6 (0xffffffff8132b306)                    
    xor r12d, eax 
    R12D:0x1040c2
    EAX:0xefbf3cff
    [41, 31, c4]
ITERATION 1432 0xffffffff8132b309 0x11114000 | check_chain_key+0xc9 (0xffffffff8132b309)                    
    mov eax, r12d 
    EAX:0xefbf3cff
    R12D:0xefaf7c3d
    [44, 89, e0]
ITERATION 1433 0xffffffff8132b30c 0x11114000 | check_chain_key+0xcc (0xffffffff8132b30c)                    
    sub ebx, r12d 
    EBX:0xffffbffa
    R12D:0xefaf7c3d
    [44, 29, e3]
ITERATION 1434 0xffffffff8132b30f 0x11114000 | check_chain_key+0xcf (0xffffffff8132b30f)                    
    rol eax, 0x10 
    EAX:0xefaf7c3d
    ??_Immediate8_?? [c1, c0, 10]
ITERATION 1435 0xffffffff8132b312 0x11114000 | check_chain_key+0xd2 (0xffffffff8132b312)                    
    xor ebx, eax 
    EBX:0x105043bd
    EAX:0x7c3defaf
    [31, c3]
ITERATION 1436 0xffffffff8132b314 0x11114000 | check_chain_key+0xd4 (0xffffffff8132b314)                    
    lea eax, [r12+rdx] 
    EAX:0x7c3defaf
    [R12:0xefaf7c3d+RDX:0xffef7f36=0x1ef9efb73]] 
    [41, 8d, 04, 14]
ITERATION 1437 0xffffffff8132b318 0x11114000 | check_chain_key+0xd8 (0xffffffff8132b318)                    
    mov esi, ebx 
    ESI:0xffffffff
    EBX:0x6c6dac12
    [89, de]
ITERATION 1438 0xffffffff8132b31a 0x11114000 | check_chain_key+0xda (0xffffffff8132b31a)                    
    sub edx, ebx 
    EDX:0xffef7f36
    EBX:0x6c6dac12
    [29, da]
ITERATION 1439 0xffffffff8132b31c 0x11114000 | check_chain_key+0xdc (0xffffffff8132b31c)                    
    add ebx, eax 
    EBX:0x6c6dac12
    EAX:0xef9efb73
    [01, c3]
ITERATION 1440 0xffffffff8132b31e 0x11114000 | check_chain_key+0xde (0xffffffff8132b31e)                    
    ror esi, 0xd 
    ESI:0x6c6dac12
    ??_Immediate8_?? [c1, ce, 0d]
ITERATION 1441 0xffffffff8132b321 0x11114000 | check_chain_key+0xe1 (0xffffffff8132b321)                    
    xor edx, esi 
    EDX:0x9381d324
    ESI:0x6093636d
    [31, f2]
ITERATION 1442 0xffffffff8132b323 0x11114000 | check_chain_key+0xe3 (0xffffffff8132b323)                    
    mov esi, eax 
    ESI:0x6093636d
    EAX:0xef9efb73
    [89, c6]
ITERATION 1443 0xffffffff8132b325 0x11114000 | check_chain_key+0xe5 (0xffffffff8132b325)                    
    mov r12d, edx 
    R12D:0xefaf7c3d
    EDX:0xf312b049
    [41, 89, d4]
ITERATION 1444 0xffffffff8132b328 0x11114000 | check_chain_key+0xe8 (0xffffffff8132b328)                    
    sub esi, edx 
    ESI:0xef9efb73
    EDX:0xf312b049
    [29, d6]
ITERATION 1445 0xffffffff8132b32a 0x11114000 | check_chain_key+0xea (0xffffffff8132b32a)                    
    lea eax, [rbx+rdx] 
    EAX:0xef9efb73
    [RBX:0x5c0ca785+RDX:0xf312b049=0x14f1f57ce]] 
    [8d, 04, 13]
ITERATION 1446 0xffffffff8132b32d 0x11114000 | check_chain_key+0xed (0xffffffff8132b32d)                    
    rol r12d, 0x4 
    R12D:0xf312b049
    ??_Immediate8_?? [41, c1, c4, 04]
ITERATION 1447 0xffffffff8132b331 0x11114000 | check_chain_key+0xf1 (0xffffffff8132b331)                    
    xor r12d, esi 
    R12D:0x312b049f
    ESI:0xfc8c4b2a
    [41, 31, f4]
ITERATION 1448 0xffffffff8132b334 0x11114000 | check_chain_key+0xf4 (0xffffffff8132b334)                    
    shl r12, 0x20 
    R12:0xcda74fb5
    ??_Immediate8_?? [49, c1, e4, 20]
ITERATION 1449 0xffffffff8132b338 0x11114000 | check_chain_key+0xf8 (0xffffffff8132b338)                    
    or r12, rax 
    R12:0xcda74fb500000000
    RAX:0x4f1f57ce
    [49, 09, c4]
ITERATION 1450 0xffffffff8132b33b 0x11114000 | check_chain_key+0xfb (0xffffffff8132b33b)                    
    cmp dword ptr [r9+0xd08], r14d 
    [R9:0xffff888007674300+0xd08=0xffff888007675008size:UInt32->0x1]] 
    R14D:0x1
    [45, 39, b1, 08, 0d, 00, 00]
ITERATION 1451 0xffffffff8132b342 0x11114000 | check_chain_key+0x102 (0xffffffff8132b342)                   
    jbe 0x17c 
    ??_NearBranch64_?? [0f, 86, 76, 01, 00, 00]
ITERATION 1452 0xffffffff8132b4be 0x11114000 | check_chain_key+0x27e (0xffffffff8132b4be)                   
    lea r13, [r9+0xd00] 
    R13:0xffff888007675010 -> 0xffffffffffffffff
    [R9:0xffff888007674300+0xd00=0xffff888007675000]] 
    [4d, 8d, a9, 00, 0d, 00, 00]
ITERATION 1453 0xffffffff8132b4c5 0x11114000 | check_chain_key+0x285 (0xffffffff8132b4c5)                   
    mov rax, 0xdffffc0000000000 
    RAX:0x4f1f57ce
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1454 0xffffffff8132b4cf 0x11114000 | check_chain_key+0x28f (0xffffffff8132b4cf)                   
    mov rdx, r13 
    RDX:0xf312b049
    R13:0xffff888007675000 -> 0xcda74fb54f1f57ce
    [4c, 89, ea]
ITERATION 1455 0xffffffff8132b4d2 0x11114000 | check_chain_key+0x292 (0xffffffff8132b4d2)                   
    shr rdx, 0x3 
    RDX:0xffff888007675000 -> 0xcda74fb54f1f57ce
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1456 0xffffffff8132b4d6 0x11114000 | check_chain_key+0x296 (0xffffffff8132b4d6)                   
    cmp byte ptr [rdx+rax], 0x0 
    [RDX:0x1ffff11000ecea00+RAX:0xdffffc0000000000=0xffffed1000ecea00size:UInt8->0x0]] 
    ??_Immediate8_?? [80, 3c, 02, 00]
ITERATION 1457 0xffffffff8132b4da 0x11114000 | check_chain_key+0x29a (0xffffffff8132b4da)                   
    jne 0x33f 
    ??_NearBranch64_?? [0f, 85, 39, 03, 00, 00]
ITERATION 1458 0xffffffff8132b4e0 0x11114000 | check_chain_key+0x2a0 (0xffffffff8132b4e0)                   
    cmp qword ptr [r9+0xd00], r12 
    [R9:0xffff888007674300+0xd00=0xffff888007675000size:UInt64->0xcda74fb54f1f57ce]] 
    R12:0xcda74fb54f1f57ce
    [4d, 39, a1, 00, 0d, 00, 00]
ITERATION 1459 0xffffffff8132b4e7 0x11114000 | check_chain_key+0x2a7 (0xffffffff8132b4e7)                   
    mov qword ptr [rbp-0x30], r9 
    [RBP:0xffffc90000a1fdf8+0xffffffffffffffd0=0x1ffffc90000a1fdc8]] 
    R9:0xffff888007674300 -> 0x0
    [4c, 89, 4d, d0]
ITERATION 1460 0xffffffff8132b4eb 0x11114000 | check_chain_key+0x2ab (0xffffffff8132b4eb)                   
    jne 0xf0 
    ??_NearBranch64_?? [0f, 85, ea, 00, 00, 00]
ITERATION 1461 0xffffffff8132b4f1 0x11114000 | check_chain_key+0x2b1 (0xffffffff8132b4f1)                   
    add rsp, 0x30 
    RSP:0xffffc90000a1fda0 -> 0xffff888007675008 -> ''
    ??_Immediate8to64_?? [48, 83, c4, 30]
ITERATION 1462 0xffffffff8132b4f5 0x11114000 | check_chain_key+0x2b5 (0xffffffff8132b4f5)                   
    pop rbx 
    RBX:0x5c0ca785
    [5b]
ITERATION 1463 0xffffffff8132b4f6 0x11114000 | check_chain_key+0x2b6 (0xffffffff8132b4f6)                   
    pop r12 
    R12:0xcda74fb54f1f57ce
    [41, 5c]
ITERATION 1464 0xffffffff8132b4f8 0x11114000 | check_chain_key+0x2b8 (0xffffffff8132b4f8)                   
    pop r13 
    R13:0xffff888007675000 -> 0xcda74fb54f1f57ce
    [41, 5d]
ITERATION 1465 0xffffffff8132b4fa 0x11114000 | check_chain_key+0x2ba (0xffffffff8132b4fa)                   
    pop r14 
    R14:0x1
    [41, 5e]
ITERATION 1466 0xffffffff8132b4fc 0x11114000 | check_chain_key+0x2bc (0xffffffff8132b4fc)                   
    pop r15 
    R15:0xdffffc0000000000
    [41, 5f]
ITERATION 1467 0xffffffff8132b4fe 0x11114000 | check_chain_key+0x2be (0xffffffff8132b4fe)                   
    pop rbp 
    RBP:0xffffc90000a1fdf8 -> 0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [5d]
ITERATION 1468 0xffffffff8132b4ff 0x11114000 | check_chain_key+0x2bf (0xffffffff8132b4ff)                   
    ret 
    [c3]
ITERATION 1469 0xffffffff8132f071 0x11114000 | __lock_acquire.isra.0+0x5a1 (0xffffffff8132f071)             
    mov rdx, 0xffffffff85891e2c 
    RDX:0x1ffff11000ecea00
    ??_Immediate32to64_?? [48, c7, c2, 2c, 1e, 89, 85]
ITERATION 1470 0xffffffff8132f078 0x11114000 | __lock_acquire.isra.0+0x5a8 (0xffffffff8132f078)             
    mov rax, 0xdffffc0000000000 
    RAX:0xdffffc0000000000
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1471 0xffffffff8132f082 0x11114000 | __lock_acquire.isra.0+0x5b2 (0xffffffff8132f082)             
    shr rdx, 0x3 
    RDX:[34mdebug_locks+0x0 (0xffffffff85891e2c)[39m -> ''
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1472 0xffffffff8132f086 0x11114000 | __lock_acquire.isra.0+0x5b6 (0xffffffff8132f086)             
    movzx edx, byte ptr [rdx+rax] 
    EDX:0xf0b123c5
    [RDX:0x1ffffffff0b123c5+RAX:0xdffffc0000000000=0xfffffbfff0b123c5size:UInt8->0x0]] 
    [0f, b6, 14, 02]
ITERATION 1473 0xffffffff8132f08a 0x11114000 | __lock_acquire.isra.0+0x5ba (0xffffffff8132f08a)             
    mov rax, 0xffffffff85891e2c 
    RAX:0xdffffc0000000000
    ??_Immediate32to64_?? [48, c7, c0, 2c, 1e, 89, 85]
ITERATION 1474 0xffffffff8132f091 0x11114000 | __lock_acquire.isra.0+0x5c1 (0xffffffff8132f091)             
    and eax, 0x7 
    EAX:0x85891e2c
    ??_Immediate8to32_?? [83, e0, 07]
ITERATION 1475 0xffffffff8132f094 0x11114000 | __lock_acquire.isra.0+0x5c4 (0xffffffff8132f094)             
    add eax, 0x3 
    EAX:0x4
    ??_Immediate8to32_?? [83, c0, 03]
ITERATION 1476 0xffffffff8132f097 0x11114000 | __lock_acquire.isra.0+0x5c7 (0xffffffff8132f097)             
    cmp al, dl 
    AL:0x7
    DL:0x0
    [38, d0]
ITERATION 1477 0xffffffff8132f099 0x11114000 | __lock_acquire.isra.0+0x5c9 (0xffffffff8132f099)             
    jl 0xa 
    ??_NearBranch64_?? [7c, 08]
ITERATION 1478 0xffffffff8132f09b 0x11114000 | __lock_acquire.isra.0+0x5cb (0xffffffff8132f09b)             
    test dl, dl 
    DL:0x0
    DL:0x0
    [84, d2]
ITERATION 1479 0xffffffff8132f09d 0x11114000 | __lock_acquire.isra.0+0x5cd (0xffffffff8132f09d)             
    jne 0x80d 
    ??_NearBranch64_?? [0f, 85, 07, 08, 00, 00]
ITERATION 1480 0xffffffff8132f0a3 0x11114000 | __lock_acquire.isra.0+0x5d3 (0xffffffff8132f0a3)             
    mov eax, dword ptr [rip+0x4562d83] 
    EAX:0x7
    [RIP:0xffffffff8132f0a3+0x4562d89=0xffffffff85891e2csize:UInt32->0x1]] 
    [8b, 05, 83, 2d, 56, 04]
ITERATION 1481 0xffffffff8132f0a9 0x11114000 | __lock_acquire.isra.0+0x5d9 (0xffffffff8132f0a9)             
    test eax, eax 
    EAX:0x1
    EAX:0x1
    [85, c0]
ITERATION 1482 0xffffffff8132f0ab 0x11114000 | __lock_acquire.isra.0+0x5db (0xffffffff8132f0ab)             
    je 0x199 
    ??_NearBranch64_?? [0f, 84, 93, 01, 00, 00]
ITERATION 1483 0xffffffff8132f0b1 0x11114000 | __lock_acquire.isra.0+0x5e1 (0xffffffff8132f0b1)             
    mov rax, 0xdffffc0000000000 
    RAX:0x1
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1484 0xffffffff8132f0bb 0x11114000 | __lock_acquire.isra.0+0x5eb (0xffffffff8132f0bb)             
    mov rdx, qword ptr [rbp-0x58] 
    RDX:0x0
    [RBP:0xffffc90000a1fe88+0xffffffffffffffa8=0xffffc90000a1fe30size:UInt64->0xffff888007675008]] 
    [48, 8b, 55, a8]
ITERATION 1485 0xffffffff8132f0bf 0x11114000 | __lock_acquire.isra.0+0x5ef (0xffffffff8132f0bf)             
    shr rdx, 0x3 
    RDX:0xffff888007675008 -> ''
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1486 0xffffffff8132f0c3 0x11114000 | __lock_acquire.isra.0+0x5f3 (0xffffffff8132f0c3)             
    movzx eax, byte ptr [rdx+rax] 
    EAX:0x0
    [RDX:0x1ffff11000ecea01+RAX:0xdffffc0000000000=0xffffed1000ecea01size:UInt8->0x0]] 
    [0f, b6, 04, 02]
ITERATION 1487 0xffffffff8132f0c7 0x11114000 | __lock_acquire.isra.0+0x5f7 (0xffffffff8132f0c7)             
    test al, al 
    AL:0x0
    AL:0x0
    [84, c0]
ITERATION 1488 0xffffffff8132f0c9 0x11114000 | __lock_acquire.isra.0+0x5f9 (0xffffffff8132f0c9)             
    je 0xa 
    ??_NearBranch64_?? [74, 08]
ITERATION 1489 0xffffffff8132f0d3 0x11114000 | __lock_acquire.isra.0+0x603 (0xffffffff8132f0d3)             
    mov rax, qword ptr [rbp-0x30] 
    RAX:0x0
    [RBP:0xffffc90000a1fe88+0xffffffffffffffd0=0xffffc90000a1fe58size:UInt64->0xffff888007674300]] 
    [48, 8b, 45, d0]
ITERATION 1490 0xffffffff8132f0d7 0x11114000 | __lock_acquire.isra.0+0x607 (0xffffffff8132f0d7)             
    mov eax, dword ptr [rax+0xd08] 
    EAX:0x7674300
    [RAX:0xffff888007674300+0xd08=0xffff888007675008size:UInt32->0x1]] 
    [8b, 80, 08, 0d, 00, 00]
ITERATION 1491 0xffffffff8132f0dd 0x11114000 | __lock_acquire.isra.0+0x60d (0xffffffff8132f0dd)             
    cmp eax, 0x2f 
    EAX:0x1
    ??_Immediate8to32_?? [83, f8, 2f]
ITERATION 1492 0xffffffff8132f0e0 0x11114000 | __lock_acquire.isra.0+0x610 (0xffffffff8132f0e0)             
    ja 0x23e9356 
    ??_NearBranch64_?? [0f, 87, 50, 93, 3e, 02]
ITERATION 1493 0xffffffff8132f0e6 0x11114000 | __lock_acquire.isra.0+0x616 (0xffffffff8132f0e6)             
    cmp eax, dword ptr [rip+0x49afdd4] 
    EAX:0x1
    [RIP:0xffffffff8132f0e6+0x49afdda=0xffffffff85cdeec0size:UInt32->0xd]] 
    [3b, 05, d4, fd, 9a, 04]
ITERATION 1494 0xffffffff8132f0ec 0x11114000 | __lock_acquire.isra.0+0x61c (0xffffffff8132f0ec)             
    mov r13d, 0x1 
    R13D:0x85891e28
    ??_Immediate32_?? [41, bd, 01, 00, 00, 00]
ITERATION 1495 0xffffffff8132f0f2 0x11114000 | __lock_acquire.isra.0+0x622 (0xffffffff8132f0f2)             
    jbe 0x155 
    ??_NearBranch64_?? [0f, 86, 4f, 01, 00, 00]
ITERATION 1496 0xffffffff8132f247 0x11114000 | __lock_acquire.isra.0+0x777 (0xffffffff8132f247)             
    add rsp, 0x58 
    RSP:0xffffc90000a1fe08 -> 0xffff888007675028 -> 0x0
    ??_Immediate8to64_?? [48, 83, c4, 58]
ITERATION 1497 0xffffffff8132f24b 0x11114000 | __lock_acquire.isra.0+0x77b (0xffffffff8132f24b)             
    mov eax, r13d 
    EAX:0x1
    R13D:0x1
    [44, 89, e8]
ITERATION 1498 0xffffffff8132f24e 0x11114000 | __lock_acquire.isra.0+0x77e (0xffffffff8132f24e)             
    pop rbx 
    RBX:0xcda74fb54f1f57ce
    [5b]
ITERATION 1499 0xffffffff8132f24f 0x11114000 | __lock_acquire.isra.0+0x77f (0xffffffff8132f24f)             
    pop r12 
    R12:0x0
    [41, 5c]
ITERATION 1500 0xffffffff8132f251 0x11114000 | __lock_acquire.isra.0+0x781 (0xffffffff8132f251)             
    pop r13 
    R13:0x1
    [41, 5d]
ITERATION 1501 0xffffffff8132f253 0x11114000 | __lock_acquire.isra.0+0x783 (0xffffffff8132f253)             
    pop r14 
    R14:0x5c0ca785
    [41, 5e]
ITERATION 1502 0xffffffff8132f255 0x11114000 | __lock_acquire.isra.0+0x785 (0xffffffff8132f255)             
    pop r15 
    R15:0xf312b049
    [41, 5f]
ITERATION 1503 0xffffffff8132f257 0x11114000 | __lock_acquire.isra.0+0x787 (0xffffffff8132f257)             
    pop rbp 
    RBP:0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [5d]
ITERATION 1504 0xffffffff8132f258 0x11114000 | __lock_acquire.isra.0+0x788 (0xffffffff8132f258)             
    ret 
    [c3]
ITERATION 1505 0xffffffff81330ef1 0x11114000 | lock_acquire+0x131 (0xffffffff81330ef1)                      
    mov eax, 0xffffffff 
    EAX:0x1
    ??_Immediate32_?? [b8, ff, ff, ff, ff]
ITERATION 1506 0xffffffff81330ef6 0x11114000 | lock_acquire+0x136 (0xffffffff81330ef6)                      
    add rsp, 0x18 
    RSP:0xffffc90000a1fe98 -> [34m__task_pid_nr_ns+0x5 (0xffffffff8123f735)[39m -> 0x7ede064305ff6555
    ??_Immediate8to64_?? [48, 83, c4, 18]
ITERATION 1507 0xffffffff81330efa 0x11114000 | lock_acquire+0x13a (0xffffffff81330efa)                      
    xadd dword ptr gs:[rip+0x7ecefdfe], eax 
    [RIP:0xffffffff81330efa+0x7ecefe06=0x20d00size:UInt32->????]] 
    EAX:0xffffffff
    [65, 0f, c1, 05, fe, fd, ce, 7e]
ITERATION 1508 0xffffffff81330f02 0x11114000 | lock_acquire+0x142 (0xffffffff81330f02)                      
    cmp eax, 0x1 
    EAX:0x1
    ??_Immediate8to32_?? [83, f8, 01]
ITERATION 1509 0xffffffff81330f05 0x11114000 | lock_acquire+0x145 (0xffffffff81330f05)                      
    jne 0x106 
    ??_NearBranch64_?? [0f, 85, 00, 01, 00, 00]
ITERATION 1510 0xffffffff81330f0b 0x11114000 | lock_acquire+0x14b (0xffffffff81330f0b)                      
    pushfq 
    [9c]
ITERATION 1511 0xffffffff81330f0c 0x11114000 | lock_acquire+0x14c (0xffffffff81330f0c)                      
    pop rax 
    RAX:0x1
    [58]
ITERATION 1512 0xffffffff81330f0d 0x11114000 | lock_acquire+0x14d (0xffffffff81330f0d)                      
    nop dword ptr [rax+rax] 
    [RAX:0x146+RAX:0x146] 
    [0f, 1f, 44, 00, 00]
ITERATION 1513 0xffffffff81330f12 0x11114000 | lock_acquire+0x152 (0xffffffff81330f12)                      
    test ah, 0x2 
    AH:0x1
    ??_Immediate8_?? [f6, c4, 02]
ITERATION 1514 0xffffffff81330f15 0x11114000 | lock_acquire+0x155 (0xffffffff81330f15)                      
    jne 0xec 
    ??_NearBranch64_?? [0f, 85, e6, 00, 00, 00]
ITERATION 1515 0xffffffff81330f1b 0x11114000 | lock_acquire+0x15b (0xffffffff81330f1b)                      
    cmp qword ptr [rbp-0x30], 0x0 
    [RBP:0xffffc90000a1fee8+0xffffffffffffffd0=0xffffc90000a1feb8size:UInt64->0x200]] 
    ??_Immediate8to64_?? [48, 83, 7d, d0, 00]
ITERATION 1516 0xffffffff81330f20 0x11114000 | lock_acquire+0x160 (0xffffffff81330f20)                      
    jne 0xcb 
    ??_NearBranch64_?? [0f, 85, c5, 00, 00, 00]
ITERATION 1517 0xffffffff81330feb 0x11114000 | lock_acquire+0x22b (0xffffffff81330feb)                      
    sti 
    [fb]
ITERATION 1518 0xffffffff81330fec 0x11114000 | lock_acquire+0x22c (0xffffffff81330fec)                      
    nop word ptr [rax+rax] 
    [RAX:0x146+RAX:0x146] 
    [66, 0f, 1f, 44, 00, 00]
ITERATION 1519 0xffffffff81330ff2 0x11114000 | lock_acquire+0x232 (0xffffffff81330ff2)                      
    lea rsp, [rbp-0x28] 
    RSP:0xffffc90000a1feb0 -> 0xffffc90000a1ff58 -> 0x0
    [RBP:0xffffc90000a1fee8+0xffffffffffffffd8=0x1ffffc90000a1fec0]] 
    [48, 8d, 65, d8]
ITERATION 1520 0xffffffff81330ff6 0x11114000 | lock_acquire+0x236 (0xffffffff81330ff6)                      
    pop rbx 
    RBX:0x0
    [5b]
ITERATION 1521 0xffffffff81330ff7 0x11114000 | lock_acquire+0x237 (0xffffffff81330ff7)                      
    pop r12 
    R12:[34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    [41, 5c]
ITERATION 1522 0xffffffff81330ff9 0x11114000 | lock_acquire+0x239 (0xffffffff81330ff9)                      
    pop r13 
    R13:0x0
    [41, 5d]
ITERATION 1523 0xffffffff81330ffb 0x11114000 | lock_acquire+0x23b (0xffffffff81330ffb)                      
    pop r14 
    R14:0x0
    [41, 5e]
ITERATION 1524 0xffffffff81330ffd 0x11114000 | lock_acquire+0x23d (0xffffffff81330ffd)                      
    pop r15 
    R15:0x2
    [41, 5f]
ITERATION 1525 0xffffffff81330fff 0x11114000 | lock_acquire+0x23f (0xffffffff81330fff)                      
    pop rbp 
    RBP:0xffffc90000a1fee8 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [5d]
ITERATION 1526 0xffffffff81331000 0x11114000 | lock_acquire+0x240 (0xffffffff81331000)                      
    ret 
    [c3]
ITERATION 1527 0xffffffff8123f770 0x11114000 | __task_pid_nr_ns+0x40 (0xffffffff8123f770)                   
    pop rax 
    RAX:0x146
    [58]
ITERATION 1528 0xffffffff8123f771 0x11114000 | __task_pid_nr_ns+0x41 (0xffffffff8123f771)                   
    test rbx, rbx 
    RBX:0x0
    RBX:0x0
    [48, 85, db]
ITERATION 1529 0xffffffff8123f774 0x11114000 | __task_pid_nr_ns+0x44 (0xffffffff8123f774)                   
    je 0x14b 
    ??_NearBranch64_?? [0f, 84, 45, 01, 00, 00]
ITERATION 1530 0xffffffff8123f8bf 0x11114000 | __task_pid_nr_ns+0x18f (0xffffffff8123f8bf)                  
    mov rbx, qword ptr gs:[0x1fdc0] 
    RBX:0x0
    [None:0x0+0x1fdc0=0x1fdc0size:UInt64->????]] 
    [65, 48, 8b, 1c, 25, c0, fd, 01, 00]
ITERATION 1531 0xffffffff8123f8c8 0x11114000 | __task_pid_nr_ns+0x198 (0xffffffff8123f8c8)                  
    lea rdi, [rbx+0x990] 
    RDI:0xffffffff
    [RBX:0xffff888007674300+0x990=0xffff888007674c90]] 
    [48, 8d, bb, 90, 09, 00, 00]
ITERATION 1532 0xffffffff8123f8cf 0x11114000 | __task_pid_nr_ns+0x19f (0xffffffff8123f8cf)                  
    mov rax, 0xdffffc0000000000 
    RAX:[34m__task_pid_nr_ns+0x5 (0xffffffff8123f735)[39m -> 0x7ede064305ff6555
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1533 0xffffffff8123f8d9 0x11114000 | __task_pid_nr_ns+0x1a9 (0xffffffff8123f8d9)                  
    mov rdx, rdi 
    RDX:0x1ffff11000ecea01
    RDI:0xffff888007674c90 -> 0xffff8880075f5b40 -> ''
    [48, 89, fa]
ITERATION 1534 0xffffffff8123f8dc 0x11114000 | __task_pid_nr_ns+0x1ac (0xffffffff8123f8dc)                  
    shr rdx, 0x3 
    RDX:0xffff888007674c90 -> 0xffff8880075f5b40 -> ''
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1535 0xffffffff8123f8e0 0x11114000 | __task_pid_nr_ns+0x1b0 (0xffffffff8123f8e0)                  
    cmp byte ptr [rdx+rax], 0x0 
    [RDX:0x1ffff11000ece992+RAX:0xdffffc0000000000=0xffffed1000ece992size:UInt8->0x0]] 
    ??_Immediate8_?? [80, 3c, 02, 00]
ITERATION 1536 0xffffffff8123f8e4 0x11114000 | __task_pid_nr_ns+0x1b4 (0xffffffff8123f8e4)                  
    jne 0xfe 
    ??_NearBranch64_?? [0f, 85, f8, 00, 00, 00]
ITERATION 1537 0xffffffff8123f8ea 0x11114000 | __task_pid_nr_ns+0x1ba (0xffffffff8123f8ea)                  
    mov rbx, qword ptr [rbx+0x990] 
    RBX:0xffff888007674300 -> 0x0
    [RBX:0xffff888007674300+0x990=0xffff888007674c90size:UInt64->0xffff8880075f5b40]] 
    [48, 8b, 9b, 90, 09, 00, 00]
ITERATION 1538 0xffffffff8123f8f1 0x11114000 | __task_pid_nr_ns+0x1c1 (0xffffffff8123f8f1)                  
    test rbx, rbx 
    RBX:0xffff8880075f5b40 -> ''
    RBX:0xffff8880075f5b40 -> ''
    [48, 85, db]
ITERATION 1539 0xffffffff8123f8f4 0x11114000 | __task_pid_nr_ns+0x1c4 (0xffffffff8123f8f4)                  
    je 0xfffffffffffffe86 
    ??_NearBranch64_?? [0f, 84, 80, fe, ff, ff]
ITERATION 1540 0xffffffff8123f8fa 0x11114000 | __task_pid_nr_ns+0x1ca (0xffffffff8123f8fa)                  
    mov rax, 0xdffffc0000000000 
    RAX:0xdffffc0000000000
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1541 0xffffffff8123f904 0x11114000 | __task_pid_nr_ns+0x1d4 (0xffffffff8123f904)                  
    lea rdi, [rbx+0x4] 
    RDI:0xffff888007674c90 -> 0xffff8880075f5b40 -> ''
    [RBX:0xffff8880075f5b40+0x4=0xffff8880075f5b44]] 
    [48, 8d, 7b, 04]
ITERATION 1542 0xffffffff8123f908 0x11114000 | __task_pid_nr_ns+0x1d8 (0xffffffff8123f908)                  
    mov rdx, rdi 
    RDX:0x1ffff11000ece992
    RDI:0xffff8880075f5b44 -> 0x0
    [48, 89, fa]
ITERATION 1543 0xffffffff8123f90b 0x11114000 | __task_pid_nr_ns+0x1db (0xffffffff8123f90b)                  
    shr rdx, 0x3 
    RDX:0xffff8880075f5b44 -> 0x0
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1544 0xffffffff8123f90f 0x11114000 | __task_pid_nr_ns+0x1df (0xffffffff8123f90f)                  
    movzx edx, byte ptr [rdx+rax] 
    EDX:0xebeb68
    [RDX:0x1ffff11000ebeb68+RAX:0xdffffc0000000000=0xffffed1000ebeb68size:UInt8->0x0]] 
    [0f, b6, 14, 02]
ITERATION 1545 0xffffffff8123f913 0x11114000 | __task_pid_nr_ns+0x1e3 (0xffffffff8123f913)                  
    mov rax, rdi 
    RAX:0xdffffc0000000000
    RDI:0xffff8880075f5b44 -> 0x0
    [48, 89, f8]
ITERATION 1546 0xffffffff8123f916 0x11114000 | __task_pid_nr_ns+0x1e6 (0xffffffff8123f916)                  
    and eax, 0x7 
    EAX:0x75f5b44
    ??_Immediate8to32_?? [83, e0, 07]
ITERATION 1547 0xffffffff8123f919 0x11114000 | __task_pid_nr_ns+0x1e9 (0xffffffff8123f919)                  
    add eax, 0x3 
    EAX:0x4
    ??_Immediate8to32_?? [83, c0, 03]
ITERATION 1548 0xffffffff8123f91c 0x11114000 | __task_pid_nr_ns+0x1ec (0xffffffff8123f91c)                  
    cmp al, dl 
    AL:0x7
    DL:0x0
    [38, d0]
ITERATION 1549 0xffffffff8123f91e 0x11114000 | __task_pid_nr_ns+0x1ee (0xffffffff8123f91e)                  
    jl 0xa 
    ??_NearBranch64_?? [7c, 08]
ITERATION 1550 0xffffffff8123f920 0x11114000 | __task_pid_nr_ns+0x1f0 (0xffffffff8123f920)                  
    test dl, dl 
    DL:0x0
    DL:0x0
    [84, d2]
ITERATION 1551 0xffffffff8123f922 0x11114000 | __task_pid_nr_ns+0x1f2 (0xffffffff8123f922)                  
    jne 0x95 
    ??_NearBranch64_?? [0f, 85, 8f, 00, 00, 00]
ITERATION 1552 0xffffffff8123f928 0x11114000 | __task_pid_nr_ns+0x1f8 (0xffffffff8123f928)                  
    mov r14d, dword ptr [rbx+0x4] 
    R14D:0x0
    [RBX:0xffff8880075f5b40+0x4=0xffff8880075f5b44size:UInt32->0x0]] 
    [44, 8b, 73, 04]
ITERATION 1553 0xffffffff8123f92c 0x11114000 | __task_pid_nr_ns+0x1fc (0xffffffff8123f92c)                  
    lea rax, [r14+0xd] 
    RAX:0x7
    [R14:0x0+0xd=0xd]] 
    [49, 8d, 46, 0d]
ITERATION 1554 0xffffffff8123f930 0x11114000 | __task_pid_nr_ns+0x200 (0xffffffff8123f930)                  
    shl rax, 0x4 
    RAX:0xd
    ??_Immediate8_?? [48, c1, e0, 04]
ITERATION 1555 0xffffffff8123f934 0x11114000 | __task_pid_nr_ns+0x204 (0xffffffff8123f934)                  
    lea rdi, [rbx+rax+0x8] 
    RDI:0xffff8880075f5b44 -> 0x0
    [RBX:0xffff8880075f5b40+RAX:0xd0+0x8=0xffff8880075f5c18]] 
    [48, 8d, 7c, 03, 08]
ITERATION 1556 0xffffffff8123f939 0x11114000 | __task_pid_nr_ns+0x209 (0xffffffff8123f939)                  
    mov rax, 0xdffffc0000000000 
    RAX:0xd0
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1557 0xffffffff8123f943 0x11114000 | __task_pid_nr_ns+0x213 (0xffffffff8123f943)                  
    mov rdx, rdi 
    RDX:0x0
    RDI:0xffff8880075f5c18 -> [34minit_pid_ns+0x0 (0xffffffff84f3cf00)[39m -> 0xdead4ead00000000
    [48, 89, fa]
ITERATION 1558 0xffffffff8123f946 0x11114000 | __task_pid_nr_ns+0x216 (0xffffffff8123f946)                  
    shr rdx, 0x3 
    RDX:0xffff8880075f5c18 -> [34minit_pid_ns+0x0 (0xffffffff84f3cf00)[39m -> 0xdead4ead00000000
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1559 0xffffffff8123f94a 0x11114000 | __task_pid_nr_ns+0x21a (0xffffffff8123f94a)                  
    cmp byte ptr [rdx+rax], 0x0 
    [RDX:0x1ffff11000ebeb83+RAX:0xdffffc0000000000=0xffffed1000ebeb83size:UInt8->0x0]] 
    ??_Immediate8_?? [80, 3c, 02, 00]
ITERATION 1560 0xffffffff8123f94e 0x11114000 | __task_pid_nr_ns+0x21e (0xffffffff8123f94e)                  
    jne 0x9e 
    ??_NearBranch64_?? [0f, 85, 98, 00, 00, 00]
ITERATION 1561 0xffffffff8123f954 0x11114000 | __task_pid_nr_ns+0x224 (0xffffffff8123f954)                  
    shl r14, 0x4 
    R14:0x0
    ??_Immediate8_?? [49, c1, e6, 04]
ITERATION 1562 0xffffffff8123f958 0x11114000 | __task_pid_nr_ns+0x228 (0xffffffff8123f958)                  
    mov rbx, qword ptr [r14+rbx+0xd8] 
    RBX:0xffff8880075f5b40 -> ''
    [R14:0x0+RBX:0xffff8880075f5b40+0xd8=0xffff8880075f5c18size:UInt64->0xffffffff84f3cf00]] 
    [49, 8b, 9c, 1e, d8, 00, 00, 00]
ITERATION 1563 0xffffffff8123f960 0x11114000 | __task_pid_nr_ns+0x230 (0xffffffff8123f960)                  
    jmp 0xfffffffffffffe1a 
    ??_NearBranch64_?? [e9, 15, fe, ff, ff]
ITERATION 1564 0xffffffff8123f77a 0x11114000 | __task_pid_nr_ns+0x4a (0xffffffff8123f77a)                   
    test r13d, r13d 
    R13D:0x1
    R13D:0x1
    [45, 85, ed]
ITERATION 1565 0xffffffff8123f77d 0x11114000 | __task_pid_nr_ns+0x4d (0xffffffff8123f77d)                   
    jne 0x10a 
    ??_NearBranch64_?? [0f, 85, 04, 01, 00, 00]
ITERATION 1566 0xffffffff8123f887 0x11114000 | __task_pid_nr_ns+0x157 (0xffffffff8123f887)                  
    lea rdi, [r12+0xb98] 
    RDI:0xffff8880075f5c18 -> [34minit_pid_ns+0x0 (0xffffffff84f3cf00)[39m -> 0xdead4ead00000000
    [R12:0xffff888007674300+0xb98=0xffff888007674e98]] 
    [49, 8d, bc, 24, 98, 0b, 00, 00]
ITERATION 1567 0xffffffff8123f88f 0x11114000 | __task_pid_nr_ns+0x15f (0xffffffff8123f88f)                  
    mov rax, 0xdffffc0000000000 
    RAX:0xdffffc0000000000
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1568 0xffffffff8123f899 0x11114000 | __task_pid_nr_ns+0x169 (0xffffffff8123f899)                  
    mov rdx, rdi 
    RDX:0x1ffff11000ebeb83
    RDI:0xffff888007674e98 -> 0xffff8880112da1c0 -> ''
    [48, 89, fa]
ITERATION 1569 0xffffffff8123f89c 0x11114000 | __task_pid_nr_ns+0x16c (0xffffffff8123f89c)                  
    shr rdx, 0x3 
    RDX:0xffff888007674e98 -> 0xffff8880112da1c0 -> ''
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1570 0xffffffff8123f8a0 0x11114000 | __task_pid_nr_ns+0x170 (0xffffffff8123f8a0)                  
    cmp byte ptr [rdx+rax], 0x0 
    [RDX:0x1ffff11000ece9d3+RAX:0xdffffc0000000000=0xffffed1000ece9d3size:UInt8->0x0]] 
    ??_Immediate8_?? [80, 3c, 02, 00]
ITERATION 1571 0xffffffff8123f8a4 0x11114000 | __task_pid_nr_ns+0x174 (0xffffffff8123f8a4)                  
    jne 0x109 
    ??_NearBranch64_?? [0f, 85, 03, 01, 00, 00]
ITERATION 1572 0xffffffff8123f8aa 0x11114000 | __task_pid_nr_ns+0x17a (0xffffffff8123f8aa)                  
    mov rax, qword ptr [r12+0xb98] 
    RAX:0xdffffc0000000000
    [R12:0xffff888007674300+0xb98=0xffff888007674e98size:UInt64->0xffff8880112da1c0]] 
    [49, 8b, 84, 24, 98, 0b, 00, 00]
ITERATION 1573 0xffffffff8123f8b2 0x11114000 | __task_pid_nr_ns+0x182 (0xffffffff8123f8b2)                  
    lea r12, [rax+r13*8+0x198] 
    R12:0xffff888007674300 -> 0x0
    [RAX:0xffff8880112da1c0+R13:0x1*0x8+0x198=0xffff8880112da360]] 
    [4e, 8d, a4, e8, 98, 01, 00, 00]
ITERATION 1574 0xffffffff8123f8ba 0x11114000 | __task_pid_nr_ns+0x18a (0xffffffff8123f8ba)                  
    jmp 0xfffffffffffffed0 
    ??_NearBranch64_?? [e9, cb, fe, ff, ff]
ITERATION 1575 0xffffffff8123f78a 0x11114000 | __task_pid_nr_ns+0x5a (0xffffffff8123f78a)                   
    mov rax, 0xdffffc0000000000 
    RAX:0xffff8880112da1c0 -> ''
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1576 0xffffffff8123f794 0x11114000 | __task_pid_nr_ns+0x64 (0xffffffff8123f794)                   
    mov rdx, r12 
    RDX:0x1ffff11000ece9d3
    R12:0xffff8880112da360 -> 0xffff8880075f5b40 -> ''
    [4c, 89, e2]
ITERATION 1577 0xffffffff8123f797 0x11114000 | __task_pid_nr_ns+0x67 (0xffffffff8123f797)                   
    shr rdx, 0x3 
    RDX:0xffff8880112da360 -> 0xffff8880075f5b40 -> ''
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1578 0xffffffff8123f79b 0x11114000 | __task_pid_nr_ns+0x6b (0xffffffff8123f79b)                   
    cmp byte ptr [rdx+rax], 0x0 
    [RDX:0x1ffff1100225b46c+RAX:0xdffffc0000000000=0xffffed100225b46csize:UInt8->0x0]] 
    ??_Immediate8_?? [80, 3c, 02, 00]
ITERATION 1579 0xffffffff8123f79f 0x11114000 | __task_pid_nr_ns+0x6f (0xffffffff8123f79f)                   
    jne 0x222 
    ??_NearBranch64_?? [0f, 85, 1c, 02, 00, 00]
ITERATION 1580 0xffffffff8123f7a5 0x11114000 | __task_pid_nr_ns+0x75 (0xffffffff8123f7a5)                   
    mov r13, qword ptr [r12] 
    R13:0x1
    [R12:0xffff8880112da360size:UInt64->0xffff8880075f5b40]] 
    [4d, 8b, 2c, 24]
ITERATION 1581 0xffffffff8123f7a9 0x11114000 | __task_pid_nr_ns+0x79 (0xffffffff8123f7a9)                   
    test r13, r13 
    R13:0xffff8880075f5b40 -> ''
    R13:0xffff8880075f5b40 -> ''
    [4d, 85, ed]
ITERATION 1582 0xffffffff8123f7ac 0x11114000 | __task_pid_nr_ns+0x7c (0xffffffff8123f7ac)                   
    je 0xa9 
    ??_NearBranch64_?? [0f, 84, a3, 00, 00, 00]
ITERATION 1583 0xffffffff8123f7b2 0x11114000 | __task_pid_nr_ns+0x82 (0xffffffff8123f7b2)                   
    lea rdi, [rbx+0x80] 
    RDI:0xffff888007674e98 -> 0xffff8880112da1c0 -> ''
    [RBX:0xffffffff84f3cf00+0x80=0xffffffff84f3cf80]] 
    [48, 8d, bb, 80, 00, 00, 00]
ITERATION 1584 0xffffffff8123f7b9 0x11114000 | __task_pid_nr_ns+0x89 (0xffffffff8123f7b9)                   
    mov rax, 0xdffffc0000000000 
    RAX:0xdffffc0000000000
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1585 0xffffffff8123f7c3 0x11114000 | __task_pid_nr_ns+0x93 (0xffffffff8123f7c3)                   
    mov rdx, rdi 
    RDX:0x1ffff1100225b46c
    RDI:[34minit_pid_ns+0x80 (0xffffffff84f3cf80)[39m -> 0x0
    [48, 89, fa]
ITERATION 1586 0xffffffff8123f7c6 0x11114000 | __task_pid_nr_ns+0x96 (0xffffffff8123f7c6)                   
    shr rdx, 0x3 
    RDX:[34minit_pid_ns+0x80 (0xffffffff84f3cf80)[39m -> 0x0
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1587 0xffffffff8123f7ca 0x11114000 | __task_pid_nr_ns+0x9a (0xffffffff8123f7ca)                   
    movzx eax, byte ptr [rdx+rax] 
    EAX:0x0
    [RDX:0x1ffffffff09e79f0+RAX:0xdffffc0000000000=0xfffffbfff09e79f0size:UInt8->0x0]] 
    [0f, b6, 04, 02]
ITERATION 1588 0xffffffff8123f7ce 0x11114000 | __task_pid_nr_ns+0x9e (0xffffffff8123f7ce)                   
    test al, al 
    AL:0x0
    AL:0x0
    [84, c0]
ITERATION 1589 0xffffffff8123f7d0 0x11114000 | __task_pid_nr_ns+0xa0 (0xffffffff8123f7d0)                   
    je 0xa 
    ??_NearBranch64_?? [74, 08]
ITERATION 1590 0xffffffff8123f7da 0x11114000 | __task_pid_nr_ns+0xaa (0xffffffff8123f7da)                   
    lea rdi, [r13+0x4] 
    RDI:[34minit_pid_ns+0x80 (0xffffffff84f3cf80)[39m -> 0x0
    [R13:0xffff8880075f5b40+0x4=0xffff8880075f5b44]] 
    [49, 8d, 7d, 04]
ITERATION 1591 0xffffffff8123f7de 0x11114000 | __task_pid_nr_ns+0xae (0xffffffff8123f7de)                   
    mov r12d, dword ptr [rbx+0x80] 
    R12D:0x112da360
    [RBX:0xffffffff84f3cf00+0x80=0xffffffff84f3cf80size:UInt32->0x0]] 
    [44, 8b, a3, 80, 00, 00, 00]
ITERATION 1592 0xffffffff8123f7e5 0x11114000 | __task_pid_nr_ns+0xb5 (0xffffffff8123f7e5)                   
    mov rax, 0xdffffc0000000000 
    RAX:0x0
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1593 0xffffffff8123f7ef 0x11114000 | __task_pid_nr_ns+0xbf (0xffffffff8123f7ef)                   
    mov rdx, rdi 
    RDX:0x1ffffffff09e79f0
    RDI:0xffff8880075f5b44 -> 0x0
    [48, 89, fa]
ITERATION 1594 0xffffffff8123f7f2 0x11114000 | __task_pid_nr_ns+0xc2 (0xffffffff8123f7f2)                   
    shr rdx, 0x3 
    RDX:0xffff8880075f5b44 -> 0x0
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1595 0xffffffff8123f7f6 0x11114000 | __task_pid_nr_ns+0xc6 (0xffffffff8123f7f6)                   
    movzx edx, byte ptr [rdx+rax] 
    EDX:0xebeb68
    [RDX:0x1ffff11000ebeb68+RAX:0xdffffc0000000000=0xffffed1000ebeb68size:UInt8->0x0]] 
    [0f, b6, 14, 02]
ITERATION 1596 0xffffffff8123f7fa 0x11114000 | __task_pid_nr_ns+0xca (0xffffffff8123f7fa)                   
    mov rax, rdi 
    RAX:0xdffffc0000000000
    RDI:0xffff8880075f5b44 -> 0x0
    [48, 89, f8]
ITERATION 1597 0xffffffff8123f7fd 0x11114000 | __task_pid_nr_ns+0xcd (0xffffffff8123f7fd)                   
    and eax, 0x7 
    EAX:0x75f5b44
    ??_Immediate8to32_?? [83, e0, 07]
ITERATION 1598 0xffffffff8123f800 0x11114000 | __task_pid_nr_ns+0xd0 (0xffffffff8123f800)                   
    add eax, 0x3 
    EAX:0x4
    ??_Immediate8to32_?? [83, c0, 03]
ITERATION 1599 0xffffffff8123f803 0x11114000 | __task_pid_nr_ns+0xd3 (0xffffffff8123f803)                   
    cmp al, dl 
    AL:0x7
    DL:0x0
    [38, d0]
ITERATION 1600 0xffffffff8123f805 0x11114000 | __task_pid_nr_ns+0xd5 (0xffffffff8123f805)                   
    jl 0xa 
    ??_NearBranch64_?? [7c, 08]
ITERATION 1601 0xffffffff8123f807 0x11114000 | __task_pid_nr_ns+0xd7 (0xffffffff8123f807)                   
    test dl, dl 
    DL:0x0
    DL:0x0
    [84, d2]
ITERATION 1602 0xffffffff8123f809 0x11114000 | __task_pid_nr_ns+0xd9 (0xffffffff8123f809)                   
    jne 0x19a 
    ??_NearBranch64_?? [0f, 85, 94, 01, 00, 00]
ITERATION 1603 0xffffffff8123f80f 0x11114000 | __task_pid_nr_ns+0xdf (0xffffffff8123f80f)                   
    cmp r12d, dword ptr [r13+0x4] 
    R12D:0x0
    [R13:0xffff8880075f5b40+0x4=0xffff8880075f5b44size:UInt32->0x0]] 
    [45, 3b, 65, 04]
ITERATION 1604 0xffffffff8123f813 0x11114000 | __task_pid_nr_ns+0xe3 (0xffffffff8123f813)                   
    ja 0x42 
    ??_NearBranch64_?? [77, 40]
ITERATION 1605 0xffffffff8123f815 0x11114000 | __task_pid_nr_ns+0xe5 (0xffffffff8123f815)                   
    lea rax, [r12+0xd] 
    RAX:0x7
    [R12:0x0+0xd=0xd]] 
    [49, 8d, 44, 24, 0d]
ITERATION 1606 0xffffffff8123f81a 0x11114000 | __task_pid_nr_ns+0xea (0xffffffff8123f81a)                   
    shl rax, 0x4 
    RAX:0xd
    ??_Immediate8_?? [48, c1, e0, 04]
ITERATION 1607 0xffffffff8123f81e 0x11114000 | __task_pid_nr_ns+0xee (0xffffffff8123f81e)                   
    lea rdi, [r13+rax+0x8] 
    RDI:0xffff8880075f5b44 -> 0x0
    [R13:0xffff8880075f5b40+RAX:0xd0+0x8=0xffff8880075f5c18]] 
    [49, 8d, 7c, 05, 08]
ITERATION 1608 0xffffffff8123f823 0x11114000 | __task_pid_nr_ns+0xf3 (0xffffffff8123f823)                   
    mov rax, 0xdffffc0000000000 
    RAX:0xd0
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1609 0xffffffff8123f82d 0x11114000 | __task_pid_nr_ns+0xfd (0xffffffff8123f82d)                   
    mov rdx, rdi 
    RDX:0x0
    RDI:0xffff8880075f5c18 -> [34minit_pid_ns+0x0 (0xffffffff84f3cf00)[39m -> 0xdead4ead00000000
    [48, 89, fa]
ITERATION 1610 0xffffffff8123f830 0x11114000 | __task_pid_nr_ns+0x100 (0xffffffff8123f830)                  
    shr rdx, 0x3 
    RDX:0xffff8880075f5c18 -> [34minit_pid_ns+0x0 (0xffffffff84f3cf00)[39m -> 0xdead4ead00000000
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1611 0xffffffff8123f834 0x11114000 | __task_pid_nr_ns+0x104 (0xffffffff8123f834)                  
    cmp byte ptr [rdx+rax], 0x0 
    [RDX:0x1ffff11000ebeb83+RAX:0xdffffc0000000000=0xffffed1000ebeb83size:UInt8->0x0]] 
    ??_Immediate8_?? [80, 3c, 02, 00]
ITERATION 1612 0xffffffff8123f838 0x11114000 | __task_pid_nr_ns+0x108 (0xffffffff8123f838)                  
    jne 0x196 
    ??_NearBranch64_?? [0f, 85, 90, 01, 00, 00]
ITERATION 1613 0xffffffff8123f83e 0x11114000 | __task_pid_nr_ns+0x10e (0xffffffff8123f83e)                  
    mov r14, r12 
    R14:0x0
    R12:0x0
    [4d, 89, e6]
ITERATION 1614 0xffffffff8123f841 0x11114000 | __task_pid_nr_ns+0x111 (0xffffffff8123f841)                  
    shl r14, 0x4 
    R14:0x0
    ??_Immediate8_?? [49, c1, e6, 04]
ITERATION 1615 0xffffffff8123f845 0x11114000 | __task_pid_nr_ns+0x115 (0xffffffff8123f845)                  
    add r14, r13 
    R14:0x0
    R13:0xffff8880075f5b40 -> ''
    [4d, 01, ee]
ITERATION 1616 0xffffffff8123f848 0x11114000 | __task_pid_nr_ns+0x118 (0xffffffff8123f848)                  
    cmp rbx, qword ptr [r14+0xd8] 
    RBX:[34minit_pid_ns+0x0 (0xffffffff84f3cf00)[39m -> 0xdead4ead00000000
    [R14:0xffff8880075f5b40+0xd8=0xffff8880075f5c18size:UInt64->0xffffffff84f3cf00]] 
    [49, 3b, 9e, d8, 00, 00, 00]
ITERATION 1617 0xffffffff8123f84f 0x11114000 | __task_pid_nr_ns+0x11f (0xffffffff8123f84f)                  
    je 0x116 
    ??_NearBranch64_?? [0f, 84, 10, 01, 00, 00]
ITERATION 1618 0xffffffff8123f965 0x11114000 | __task_pid_nr_ns+0x235 (0xffffffff8123f965)                  
    mov rax, 0xdffffc0000000000 
    RAX:0xdffffc0000000000
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1619 0xffffffff8123f96f 0x11114000 | __task_pid_nr_ns+0x23f (0xffffffff8123f96f)                  
    add r12, 0xd 
    R12:0x0
    ??_Immediate8to64_?? [49, 83, c4, 0d]
ITERATION 1620 0xffffffff8123f973 0x11114000 | __task_pid_nr_ns+0x243 (0xffffffff8123f973)                  
    shl r12, 0x4 
    R12:0xd
    ??_Immediate8_?? [49, c1, e4, 04]
ITERATION 1621 0xffffffff8123f977 0x11114000 | __task_pid_nr_ns+0x247 (0xffffffff8123f977)                  
    add r12, r13 
    R12:0xd0
    R13:0xffff8880075f5b40 -> ''
    [4d, 01, ec]
ITERATION 1622 0xffffffff8123f97a 0x11114000 | __task_pid_nr_ns+0x24a (0xffffffff8123f97a)                  
    mov rdx, r12 
    RDX:0x1ffff11000ebeb83
    R12:0xffff8880075f5c10 -> 'z'
    [4c, 89, e2]
ITERATION 1623 0xffffffff8123f97d 0x11114000 | __task_pid_nr_ns+0x24d (0xffffffff8123f97d)                  
    shr rdx, 0x3 
    RDX:0xffff8880075f5c10 -> 'z'
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1624 0xffffffff8123f981 0x11114000 | __task_pid_nr_ns+0x251 (0xffffffff8123f981)                  
    movzx eax, byte ptr [rdx+rax] 
    EAX:0x0
    [RDX:0x1ffff11000ebeb82+RAX:0xdffffc0000000000=0xffffed1000ebeb82size:UInt8->0x0]] 
    [0f, b6, 04, 02]
ITERATION 1625 0xffffffff8123f985 0x11114000 | __task_pid_nr_ns+0x255 (0xffffffff8123f985)                  
    test al, al 
    AL:0x0
    AL:0x0
    [84, c0]
ITERATION 1626 0xffffffff8123f987 0x11114000 | __task_pid_nr_ns+0x257 (0xffffffff8123f987)                  
    je 0x6 
    ??_NearBranch64_?? [74, 04]
ITERATION 1627 0xffffffff8123f98d 0x11114000 | __task_pid_nr_ns+0x25d (0xffffffff8123f98d)                  
    mov r12d, dword ptr [r14+0xd0] 
    R12D:0x75f5c10
    [R14:0xffff8880075f5b40+0xd0=0xffff8880075f5c10size:UInt32->0x17a]] 
    [45, 8b, a6, d0, 00, 00, 00]
ITERATION 1628 0xffffffff8123f994 0x11114000 | __task_pid_nr_ns+0x264 (0xffffffff8123f994)                  
    jmp 0xfffffffffffffec4 
    ??_NearBranch64_?? [e9, bf, fe, ff, ff]
ITERATION 1629 0xffffffff8123f858 0x11114000 | __task_pid_nr_ns+0x128 (0xffffffff8123f858)                  
    dec dword ptr gs:[rip+0x7ede0521] 
    [RIP:0xffffffff8123f858+0x7ede0528=0x1fd80size:UInt32->????]] 
    [65, ff, 0d, 21, 05, de, 7e]
ITERATION 1630 0xffffffff8123f85f 0x11114000 | __task_pid_nr_ns+0x12f (0xffffffff8123f85f)                  
    call 0x150581 
    ??_NearBranch64_?? [e8, 7c, 05, 15, 00]
ITERATION 1631 0xffffffff8138fde0 0x11114000 | rcu_read_unlock_strict+0x0 (0xffffffff8138fde0)              
    nop dword ptr [rax+rax] 
    [RAX:0x0+RAX:0x0] 
    [0f, 1f, 44, 00, 00]
ITERATION 1632 0xffffffff8138fde5 0x11114000 | rcu_read_unlock_strict+0x5 (0xffffffff8138fde5)              
    push rbp 
    RBP:0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [55]
ITERATION 1633 0xffffffff8138fde6 0x11114000 | rcu_read_unlock_strict+0x6 (0xffffffff8138fde6)              
    mov rbp, rsp 
    RBP:0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    RSP:0xffffc90000a1fef0 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [48, 89, e5]
ITERATION 1634 0xffffffff8138fde9 0x11114000 | rcu_read_unlock_strict+0x9 (0xffffffff8138fde9)              
    pop rbp 
    RBP:0xffffc90000a1fef0 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [5d]
ITERATION 1635 0xffffffff8138fdea 0x11114000 | rcu_read_unlock_strict+0xa (0xffffffff8138fdea)              
    ret 
    [c3]
ITERATION 1636 0xffffffff8123f864 0x11114000 | __task_pid_nr_ns+0x134 (0xffffffff8123f864)                  
    mov rsi, 0xffffffff8123f858 
    RSI:0xfc8c4b2a
    ??_Immediate32to64_?? [48, c7, c6, 58, f8, 23, 81]
ITERATION 1637 0xffffffff8123f86b 0x11114000 | __task_pid_nr_ns+0x13b (0xffffffff8123f86b)                  
    mov rdi, 0xffffffff8505b580 
    RDI:0xffff8880075f5c18 -> [34minit_pid_ns+0x0 (0xffffffff84f3cf00)[39m -> 0xdead4ead00000000
    ??_Immediate32to64_?? [48, c7, c7, 80, b5, 05, 85]
ITERATION 1638 0xffffffff8123f872 0x11114000 | __task_pid_nr_ns+0x142 (0xffffffff8123f872)                  
    call 0xf0d9e 
    ??_NearBranch64_?? [e8, 99, 0d, 0f, 00]
ITERATION 1639 0xffffffff81330610 0x11114000 | lock_release+0x0 (0xffffffff81330610)                        
    mov rax, 0xdffffc0000000000 
    RAX:0x0
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1640 0xffffffff8133061a 0x11114000 | lock_release+0xa (0xffffffff8133061a)                        
    push rbp 
    RBP:0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [55]
ITERATION 1641 0xffffffff8133061b 0x11114000 | lock_release+0xb (0xffffffff8133061b)                        
    mov rbp, rsp 
    RBP:0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    RSP:0xffffc90000a1fef0 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [48, 89, e5]
ITERATION 1642 0xffffffff8133061e 0x11114000 | lock_release+0xe (0xffffffff8133061e)                        
    push r15 
    R15:0x0
    [41, 57]
ITERATION 1643 0xffffffff81330620 0x11114000 | lock_release+0x10 (0xffffffff81330620)                       
    push r14 
    R14:0xffff8880075f5b40 -> ''
    [41, 56]
ITERATION 1644 0xffffffff81330622 0x11114000 | lock_release+0x12 (0xffffffff81330622)                       
    lea r14, [rbp-0x28] 
    R14:0xffff8880075f5b40 -> ''
    [RBP:0xffffc90000a1fef0+0xffffffffffffffd8=0x1ffffc90000a1fec8]] 
    [4c, 8d, 75, d8]
ITERATION 1645 0xffffffff81330626 0x11114000 | lock_release+0x16 (0xffffffff81330626)                       
    push r13 
    R13:0xffff8880075f5b40 -> ''
    [41, 55]
ITERATION 1646 0xffffffff81330628 0x11114000 | lock_release+0x18 (0xffffffff81330628)                       
    mov r13, rsi 
    R13:0xffff8880075f5b40 -> ''
    RSI:[34m__task_pid_nr_ns+0x128 (0xffffffff8123f858)[39m -> 0xe87ede05210dff65
    [49, 89, f5]
ITERATION 1647 0xffffffff8133062b 0x11114000 | lock_release+0x1b (0xffffffff8133062b)                       
    push r12 
    R12:0x17a
    [41, 54]
ITERATION 1648 0xffffffff8133062d 0x11114000 | lock_release+0x1d (0xffffffff8133062d)                       
    mov r12, rdi 
    R12:0x17a
    RDI:[34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    [49, 89, fc]
ITERATION 1649 0xffffffff81330630 0x11114000 | lock_release+0x20 (0xffffffff81330630)                       
    push rbx 
    RBX:[34minit_pid_ns+0x0 (0xffffffff84f3cf00)[39m -> 0xdead4ead00000000
    [53]
ITERATION 1650 0xffffffff81330631 0x11114000 | lock_release+0x21 (0xffffffff81330631)                       
    lea rbx, [rbp-0xa8] 
    RBX:[34minit_pid_ns+0x0 (0xffffffff84f3cf00)[39m -> 0xdead4ead00000000
    [RBP:0xffffc90000a1fef0+0xffffffffffffff58=0x1ffffc90000a1fe48]] 
    [48, 8d, 9d, 58, ff, ff, ff]
ITERATION 1651 0xffffffff81330638 0x11114000 | lock_release+0x28 (0xffffffff81330638)                       
    shr rbx, 0x3 
    RBX:0xffffc90000a1fe48 -> ''
    ??_Immediate8_?? [48, c1, eb, 03]
ITERATION 1652 0xffffffff8133063c 0x11114000 | lock_release+0x2c (0xffffffff8133063c)                       
    add rax, rbx 
    RAX:0xdffffc0000000000
    RBX:0x1ffff92000143fc9 -> 0x0
    [48, 01, d8]
ITERATION 1653 0xffffffff8133063f 0x11114000 | lock_release+0x2f (0xffffffff8133063f)                       
    sub rsp, 0xa0 
    RSP:0xffffc90000a1fec8 -> [34minit_pid_ns+0x0 (0xffffffff84f3cf00)[39m -> 0xdead4ead00000000
    ??_Immediate32to64_?? [48, 81, ec, a0, 00, 00, 00]
ITERATION 1654 0xffffffff81330646 0x11114000 | lock_release+0x36 (0xffffffff81330646)                       
    mov qword ptr [rbp-0xa8], 0x41b58ab3 
    [RBP:0xffffc90000a1fef0+0xffffffffffffff58=0x1ffffc90000a1fe48]] 
    ??_Immediate32to64_?? [48, c7, 85, 58, ff, ff, ff, b3, 8a, b5, 41]
ITERATION 1655 0xffffffff81330651 0x11114000 | lock_release+0x41 (0xffffffff81330651)                       
    mov qword ptr [rbp-0xa0], 0xffffffff84657b00 
    [RBP:0xffffc90000a1fef0+0xffffffffffffff60=0x1ffffc90000a1fe50]] 
    ??_Immediate32to64_?? [48, c7, 85, 60, ff, ff, ff, 00, 7b, 65, 84]
ITERATION 1656 0xffffffff8133065c 0x11114000 | lock_release+0x4c (0xffffffff8133065c)                       
    mov qword ptr [rbp-0x98], 0xffffffff81330610 
    [RBP:0xffffc90000a1fef0+0xffffffffffffff68=0x1ffffc90000a1fe58]] 
    ??_Immediate32to64_?? [48, c7, 85, 68, ff, ff, ff, 10, 06, 33, 81]
ITERATION 1657 0xffffffff81330667 0x11114000 | lock_release+0x57 (0xffffffff81330667)                       
    mov dword ptr [rax], 0xf1f1f1f1 
    [RAX:0xfffff52000143fc9] 
    ??_Immediate32_?? [c7, 00, f1, f1, f1, f1]
ITERATION 1658 0xffffffff8133066d 0x11114000 | lock_release+0x5d (0xffffffff8133066d)                       
    mov dword ptr [rax+0x4], 0xf204f1f1 
    [RAX:0xfffff52000143fc9+0x4=0xfffff52000143fcd]] 
    ??_Immediate32_?? [c7, 40, 04, f1, f1, 04, f2]
ITERATION 1659 0xffffffff81330674 0x11114000 | lock_release+0x64 (0xffffffff81330674)                       
    mov dword ptr [rax+0x8], 0xf3f3f304 
    [RAX:0xfffff52000143fc9+0x8=0xfffff52000143fd1]] 
    ??_Immediate32_?? [c7, 40, 08, 04, f3, f3, f3]
ITERATION 1660 0xffffffff8133067b 0x11114000 | lock_release+0x6b (0xffffffff8133067b)                       
    mov rax, qword ptr gs:[0x28] 
    RAX:0xfffff52000143fc9 -> 0xf204f1f1f1f1f1f1
    [None:0x0+0x28=0x28size:UInt64->????]] 
    [65, 48, 8b, 04, 25, 28, 00, 00, 00]
ITERATION 1661 0xffffffff81330684 0x11114000 | lock_release+0x74 (0xffffffff81330684)                       
    mov qword ptr [rbp-0x30], rax 
    [RBP:0xffffc90000a1fef0+0xffffffffffffffd0=0x1ffffc90000a1fec0]] 
    RAX:0x45d4480925b42200
    [48, 89, 45, d0]
ITERATION 1662 0xffffffff81330688 0x11114000 | lock_release+0x78 (0xffffffff81330688)                       
    xor eax, eax 
    EAX:0x25b42200
    EAX:0x25b42200
    [31, c0]
ITERATION 1663 0xffffffff8133068a 0x11114000 | lock_release+0x7a (0xffffffff8133068a)                       
    nop dword ptr [rax+rax] 
    [RAX:0x0+RAX:0x0] 
    [0f, 1f, 44, 00, 00]
ITERATION 1664 0xffffffff8133068f 0x11114000 | lock_release+0x7f (0xffffffff8133068f)                       
    mov r15d, dword ptr gs:[rip+0x7ece8ed1] 
    R15D:0x0
    [RIP:0xffffffff8133068f+0x7ece8ed9=0x19568size:UInt32->????]] 
    [65, 44, 8b, 3d, d1, 8e, ce, 7e]
ITERATION 1665 0xffffffff81330697 0x11114000 | lock_release+0x87 (0xffffffff81330697)                       
    mov r15d, r15d 
    R15D:0x0
    R15D:0x0
    [45, 89, ff]
ITERATION 1666 0xffffffff8133069a 0x11114000 | lock_release+0x8a (0xffffffff8133069a)                       
    mov esi, 0x8 
    ESI:0x8123f858
    ??_Immediate32_?? [be, 08, 00, 00, 00]
ITERATION 1667 0xffffffff8133069f 0x11114000 | lock_release+0x8f (0xffffffff8133069f)                       
    mov rax, r15 
    RAX:0x0
    R15:0x0
    [4c, 89, f8]
ITERATION 1668 0xffffffff813306a2 0x11114000 | lock_release+0x92 (0xffffffff813306a2)                       
    sar rax, 0x6 
    RAX:0x0
    ??_Immediate8_?? [48, c1, f8, 06]
ITERATION 1669 0xffffffff813306a6 0x11114000 | lock_release+0x96 (0xffffffff813306a6)                       
    lea rdi, [rax*8-0x7a775f20] 
    RDI:[34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    [None:0x0+RAX:0x0*0x8+0xffffffff8588a0e0=0xffffffff8588a0e0]] 
    [48, 8d, 3c, c5, e0, a0, 88, 85]
ITERATION 1670 0xffffffff813306ae 0x11114000 | lock_release+0x9e (0xffffffff813306ae)                       
    call 0x60b692 
    ??_NearBranch64_?? [e8, 8d, b6, 60, 00]
ITERATION 1671 0xffffffff8193bd40 0x11114000 | __kasan_check_read+0x0 (0xffffffff8193bd40)                  
    push rbp 
    RBP:0xffffc90000a1fef0 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [55]
ITERATION 1672 0xffffffff8193bd41 0x11114000 | __kasan_check_read+0x1 (0xffffffff8193bd41)                  
    mov esi, esi 
    ESI:0x8
    ESI:0x8
    [89, f6]
ITERATION 1673 0xffffffff8193bd43 0x11114000 | __kasan_check_read+0x3 (0xffffffff8193bd43)                  
    xor edx, edx 
    EDX:0xebeb82
    EDX:0xebeb82
    [31, d2]
ITERATION 1674 0xffffffff8193bd45 0x11114000 | __kasan_check_read+0x5 (0xffffffff8193bd45)                  
    mov rbp, rsp 
    RBP:0xffffc90000a1fef0 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    RSP:0xffffc90000a1fe18 -> 0xffffc90000a1fef0 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [48, 89, e5]
ITERATION 1675 0xffffffff8193bd48 0x11114000 | __kasan_check_read+0x8 (0xffffffff8193bd48)                  
    mov rcx, qword ptr [rbp+0x8] 
    RCX:0xffff888007675010 -> 0xffffffffffffffff
    [RBP:0xffffc90000a1fe18+0x8=0xffffc90000a1fe20size:UInt64->0xffffffff813306b3]] 
    [48, 8b, 4d, 08]
ITERATION 1676 0xffffffff8193bd4c 0x11114000 | __kasan_check_read+0xc (0xffffffff8193bd4c)                  
    call 0xfffffffffffff784 
    ??_NearBranch64_?? [e8, 7f, f7, ff, ff]
ITERATION 1677 0xffffffff8193b4d0 0x11114000 | kasan_check_range+0x0 (0xffffffff8193b4d0)                   
    test rsi, rsi 
    RSI:0x8
    RSI:0x8
    [48, 85, f6]
ITERATION 1678 0xffffffff8193b4d3 0x11114000 | kasan_check_range+0x3 (0xffffffff8193b4d3)                   
    je 0x199 
    ??_NearBranch64_?? [0f, 84, 93, 01, 00, 00]
ITERATION 1679 0xffffffff8193b4d9 0x11114000 | kasan_check_range+0x9 (0xffffffff8193b4d9)                   
    push rbp 
    RBP:0xffffc90000a1fe18 -> 0xffffc90000a1fef0 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [55]
ITERATION 1680 0xffffffff8193b4da 0x11114000 | kasan_check_range+0xa (0xffffffff8193b4da)                   
    mov r10, rdi 
    R10:0xfffffbfff0c1703c -> 0xf9f9f9f9f9f9f904 -> 0x0
    RDI:[34m__cpu_online_mask+0x0 (0xffffffff8588a0e0)[39m -> ''
    [49, 89, fa]
ITERATION 1681 0xffffffff8193b4dd 0x11114000 | kasan_check_range+0xd (0xffffffff8193b4dd)                   
    movzx edx, dl 
    EDX:0x0
    DL:0x0
    [0f, b6, d2]
ITERATION 1682 0xffffffff8193b4e0 0x11114000 | kasan_check_range+0x10 (0xffffffff8193b4e0)                  
    mov rbp, rsp 
    RBP:0xffffc90000a1fe18 -> 0xffffc90000a1fef0 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    RSP:0xffffc90000a1fe08 -> 0xffffc90000a1fe18 -> 0xffffc90000a1fef0 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [48, 89, e5]
ITERATION 1683 0xffffffff8193b4e3 0x11114000 | kasan_check_range+0x13 (0xffffffff8193b4e3)                  
    push r13 
    R13:[34m__task_pid_nr_ns+0x128 (0xffffffff8123f858)[39m -> 0xe87ede05210dff65
    [41, 55]
ITERATION 1684 0xffffffff8193b4e5 0x11114000 | kasan_check_range+0x15 (0xffffffff8193b4e5)                  
    push r12 
    R12:[34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    [41, 54]
ITERATION 1685 0xffffffff8193b4e7 0x11114000 | kasan_check_range+0x17 (0xffffffff8193b4e7)                  
    push rbx 
    RBX:0x1ffff92000143fc9 -> 0x0
    [53]
ITERATION 1686 0xffffffff8193b4e8 0x11114000 | kasan_check_range+0x18 (0xffffffff8193b4e8)                  
    add r10, rsi 
    R10:[34m__cpu_online_mask+0x0 (0xffffffff8588a0e0)[39m -> ''
    RSI:0x8
    [49, 01, f2]
ITERATION 1687 0xffffffff8193b4eb 0x11114000 | kasan_check_range+0x1b (0xffffffff8193b4eb)                  
    jb 0x16c 
    ??_NearBranch64_?? [0f, 82, 66, 01, 00, 00]
ITERATION 1688 0xffffffff8193b4f1 0x11114000 | kasan_check_range+0x21 (0xffffffff8193b4f1)                  
    jmp 0xc2 
    ??_NearBranch64_?? [e9, bd, 00, 00, 00]
ITERATION 1689 0xffffffff8193b5b3 0x11114000 | kasan_check_range+0xe3 (0xffffffff8193b5b3)                  
    mov rax, 0xffff800000000000 
    RAX:0x0
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, 80, ff, ff]
ITERATION 1690 0xffffffff8193b5bd 0x11114000 | kasan_check_range+0xed (0xffffffff8193b5bd)                  
    jmp 0xffffffffffffff43 
    ??_NearBranch64_?? [e9, 3e, ff, ff, ff]
ITERATION 1691 0xffffffff8193b500 0x11114000 | kasan_check_range+0x30 (0xffffffff8193b500)                  
    cmp rax, rdi 
    RAX:0xffff800000000000
    RDI:[34m__cpu_online_mask+0x0 (0xffffffff8588a0e0)[39m -> ''
    [48, 39, f8]
ITERATION 1692 0xffffffff8193b503 0x11114000 | kasan_check_range+0x33 (0xffffffff8193b503)                  
    ja 0x154 
    ??_NearBranch64_?? [0f, 87, 4e, 01, 00, 00]
ITERATION 1693 0xffffffff8193b509 0x11114000 | kasan_check_range+0x39 (0xffffffff8193b509)                  
    sub r10, 0x1 
    R10:[34m__cpu_online_mask+0x8 (0xffffffff8588a0e8)[39m -> 0x0
    ??_Immediate8to64_?? [49, 83, ea, 01]
ITERATION 1694 0xffffffff8193b50d 0x11114000 | kasan_check_range+0x3d (0xffffffff8193b50d)                  
    mov r8, rdi 
    R8:0xffffffff
    RDI:[34m__cpu_online_mask+0x0 (0xffffffff8588a0e0)[39m -> ''
    [49, 89, f8]
ITERATION 1695 0xffffffff8193b510 0x11114000 | kasan_check_range+0x40 (0xffffffff8193b510)                  
    mov rax, 0xdffffc0000000000 
    RAX:0xffff800000000000
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1696 0xffffffff8193b51a 0x11114000 | kasan_check_range+0x4a (0xffffffff8193b51a)                  
    mov r11, r10 
    R11:[34moops_in_progress+0x0 (0xffffffff860b81e0)[39m -> 0x0
    R10:[34m__cpu_online_mask+0x7 (0xffffffff8588a0e7)[39m -> 0x0
    [4d, 89, d3]
ITERATION 1697 0xffffffff8193b51d 0x11114000 | kasan_check_range+0x4d (0xffffffff8193b51d)                  
    shr r8, 0x3 
    R8:[34m__cpu_online_mask+0x0 (0xffffffff8588a0e0)[39m -> ''
    ??_Immediate8_?? [49, c1, e8, 03]
ITERATION 1698 0xffffffff8193b521 0x11114000 | kasan_check_range+0x51 (0xffffffff8193b521)                  
    shr r11, 0x3 
    R11:[34m__cpu_online_mask+0x7 (0xffffffff8588a0e7)[39m -> 0x0
    ??_Immediate8_?? [49, c1, eb, 03]
ITERATION 1699 0xffffffff8193b525 0x11114000 | kasan_check_range+0x55 (0xffffffff8193b525)                  
    lea r12, [r8+rax] 
    R12:[34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    [R8:0x1ffffffff0b1141c+RAX:0xdffffc0000000000=0xfffffbfff0b1141c]] 
    [4d, 8d, 24, 00]
ITERATION 1700 0xffffffff8193b529 0x11114000 | kasan_check_range+0x59 (0xffffffff8193b529)                  
    add r11, rax 
    R11:0x1ffffffff0b1141c
    RAX:0xdffffc0000000000
    [49, 01, c3]
ITERATION 1701 0xffffffff8193b52c 0x11114000 | kasan_check_range+0x5c (0xffffffff8193b52c)                  
    mov rax, r12 
    RAX:0xdffffc0000000000
    R12:0xfffffbfff0b1141c -> 0x0
    [4c, 89, e0]
ITERATION 1702 0xffffffff8193b52f 0x11114000 | kasan_check_range+0x5f (0xffffffff8193b52f)                  
    lea rbx, [r11+0x1] 
    RBX:0x1ffff92000143fc9 -> 0x0
    [R11:0xfffffbfff0b1141c+0x1=0xfffffbfff0b1141d]] 
    [49, 8d, 5b, 01]
ITERATION 1703 0xffffffff8193b533 0x11114000 | kasan_check_range+0x63 (0xffffffff8193b533)                  
    mov r9, rbx 
    R9:0xffff888007674300 -> 0x0
    RBX:0xfffffbfff0b1141d -> 0x0
    [49, 89, d9]
ITERATION 1704 0xffffffff8193b536 0x11114000 | kasan_check_range+0x66 (0xffffffff8193b536)                  
    sub r9, r12 
    R9:0xfffffbfff0b1141d -> 0x0
    R12:0xfffffbfff0b1141c -> 0x0
    [4d, 29, e1]
ITERATION 1705 0xffffffff8193b539 0x11114000 | kasan_check_range+0x69 (0xffffffff8193b539)                  
    cmp r9, 0x10 
    R9:0x1
    ??_Immediate8to64_?? [49, 83, f9, 10]
ITERATION 1706 0xffffffff8193b53d 0x11114000 | kasan_check_range+0x6d (0xffffffff8193b53d)                  
    jle 0xde 
    ??_NearBranch64_?? [0f, 8e, d8, 00, 00, 00]
ITERATION 1707 0xffffffff8193b61b 0x11114000 | kasan_check_range+0x14b (0xffffffff8193b61b)                 
    test r9, r9 
    R9:0x1
    R9:0x1
    [4d, 85, c9]
ITERATION 1708 0xffffffff8193b61e 0x11114000 | kasan_check_range+0x14e (0xffffffff8193b61e)                 
    je 0xffffffffffffffed 
    ??_NearBranch64_?? [74, eb]
ITERATION 1709 0xffffffff8193b620 0x11114000 | kasan_check_range+0x150 (0xffffffff8193b620)                 
    add r9, r12 
    R9:0x1
    R12:0xfffffbfff0b1141c -> 0x0
    [4d, 01, e1]
ITERATION 1710 0xffffffff8193b623 0x11114000 | kasan_check_range+0x153 (0xffffffff8193b623)                 
    jmp 0xb 
    ??_NearBranch64_?? [eb, 09]
ITERATION 1711 0xffffffff8193b62e 0x11114000 | kasan_check_range+0x15e (0xffffffff8193b62e)                 
    cmp byte ptr [rax], 0x0 
    [RAX:0xfffffbfff0b1141csize:UInt8->0x0]] 
    ??_Immediate8_?? [80, 38, 00]
ITERATION 1712 0xffffffff8193b631 0x11114000 | kasan_check_range+0x161 (0xffffffff8193b631)                 
    je 0xfffffffffffffff4 
    ??_NearBranch64_?? [74, f2]
ITERATION 1713 0xffffffff8193b625 0x11114000 | kasan_check_range+0x155 (0xffffffff8193b625)                 
    add rax, 0x1 
    RAX:0xfffffbfff0b1141c -> 0x0
    ??_Immediate8to64_?? [48, 83, c0, 01]
ITERATION 1714 0xffffffff8193b629 0x11114000 | kasan_check_range+0x159 (0xffffffff8193b629)                 
    cmp rax, r9 
    RAX:0xfffffbfff0b1141d -> 0x0
    R9:0xfffffbfff0b1141d -> 0x0
    [4c, 39, c8]
ITERATION 1715 0xffffffff8193b62c 0x11114000 | kasan_check_range+0x15c (0xffffffff8193b62c)                 
    je 0xffffffffffffffdf 
    ??_NearBranch64_?? [74, dd]
ITERATION 1716 0xffffffff8193b60b 0x11114000 | kasan_check_range+0x13b (0xffffffff8193b60b)                 
    mov r8d, 0x1 
    R8D:0xf0b1141c
    ??_Immediate32_?? [41, b8, 01, 00, 00, 00]
ITERATION 1717 0xffffffff8193b611 0x11114000 | kasan_check_range+0x141 (0xffffffff8193b611)                 
    pop rbx 
    RBX:0xfffffbfff0b1141d -> 0x0
    [5b]
ITERATION 1718 0xffffffff8193b612 0x11114000 | kasan_check_range+0x142 (0xffffffff8193b612)                 
    pop r12 
    R12:0xfffffbfff0b1141c -> 0x0
    [41, 5c]
ITERATION 1719 0xffffffff8193b614 0x11114000 | kasan_check_range+0x144 (0xffffffff8193b614)                 
    mov eax, r8d 
    EAX:0xf0b1141d
    R8D:0x1
    [44, 89, c0]
ITERATION 1720 0xffffffff8193b617 0x11114000 | kasan_check_range+0x147 (0xffffffff8193b617)                 
    pop r13 
    R13:[34m__task_pid_nr_ns+0x128 (0xffffffff8123f858)[39m -> 0xe87ede05210dff65
    [41, 5d]
ITERATION 1721 0xffffffff8193b619 0x11114000 | kasan_check_range+0x149 (0xffffffff8193b619)                 
    pop rbp 
    RBP:0xffffc90000a1fe08 -> 0xffffc90000a1fe18 -> 0xffffc90000a1fef0 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [5d]
ITERATION 1722 0xffffffff8193b61a 0x11114000 | kasan_check_range+0x14a (0xffffffff8193b61a)                 
    ret 
    [c3]
ITERATION 1723 0xffffffff8193bd51 0x11114000 | __kasan_check_read+0x11 (0xffffffff8193bd51)                 
    pop rbp 
    RBP:0xffffc90000a1fe18 -> 0xffffc90000a1fef0 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [5d]
ITERATION 1724 0xffffffff8193bd52 0x11114000 | __kasan_check_read+0x12 (0xffffffff8193bd52)                 
    ret 
    [c3]
ITERATION 1725 0xffffffff813306b3 0x11114000 | lock_release+0xa3 (0xffffffff813306b3)                       
    bt qword ptr [rip+0x4559a25], r15 
    [RIP:0xffffffff813306b3+0x4559a2d=0xffffffff8588a0e0]] 
    R15:0x0
    [4c, 0f, a3, 3d, 25, 9a, 55, 04]
ITERATION 1726 0xffffffff813306bb 0x11114000 | lock_release+0xab (0xffffffff813306bb)                       
    jb 0x3c5 
    ??_NearBranch64_?? [0f, 82, bf, 03, 00, 00]
ITERATION 1727 0xffffffff81330a80 0x11114000 | lock_release+0x470 (0xffffffff81330a80)                      
    inc dword ptr gs:[rip+0x7ecef2f9] 
    [RIP:0xffffffff81330a80+0x7ecef300=0x1fd80size:UInt32->????]] 
    [65, ff, 05, f9, f2, ce, 7e]
ITERATION 1728 0xffffffff81330a87 0x11114000 | lock_release+0x477 (0xffffffff81330a87)                      
    mov rax, qword ptr [rip+0x450d6d2] 
    RAX:0x1
    [RIP:0xffffffff81330a87+0x450d6d9=0xffffffff8583e160size:UInt64->0x0]] 
    [48, 8b, 05, d2, d6, 50, 04]
ITERATION 1729 0xffffffff81330a8e 0x11114000 | lock_release+0x47e (0xffffffff81330a8e)                      
    dec dword ptr gs:[rip+0x7ecef2eb] 
    [RIP:0xffffffff81330a8e+0x7ecef2f2=0x1fd80size:UInt32->????]] 
    [65, ff, 0d, eb, f2, ce, 7e]
ITERATION 1730 0xffffffff81330a95 0x11114000 | lock_release+0x485 (0xffffffff81330a95)                      
    jmp 0xfffffffffffffc2c 
    ??_NearBranch64_?? [e9, 27, fc, ff, ff]
ITERATION 1731 0xffffffff813306c1 0x11114000 | lock_release+0xb1 (0xffffffff813306c1)                       
    mov rdx, 0xffffffff85891e2c 
    RDX:0x0
    ??_Immediate32to64_?? [48, c7, c2, 2c, 1e, 89, 85]
ITERATION 1732 0xffffffff813306c8 0x11114000 | lock_release+0xb8 (0xffffffff813306c8)                       
    mov rax, 0xdffffc0000000000 
    RAX:0x0
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1733 0xffffffff813306d2 0x11114000 | lock_release+0xc2 (0xffffffff813306d2)                       
    mov rcx, rdx 
    RCX:[34mlock_release+0xa3 (0xffffffff813306b3)[39m -> 0x4559a253da30f4c
    RDX:[34mdebug_locks+0x0 (0xffffffff85891e2c)[39m -> ''
    [48, 89, d1]
ITERATION 1734 0xffffffff813306d5 0x11114000 | lock_release+0xc5 (0xffffffff813306d5)                       
    shr rcx, 0x3 
    RCX:[34mdebug_locks+0x0 (0xffffffff85891e2c)[39m -> ''
    ??_Immediate8_?? [48, c1, e9, 03]
ITERATION 1735 0xffffffff813306d9 0x11114000 | lock_release+0xc9 (0xffffffff813306d9)                       
    movzx ecx, byte ptr [rcx+rax] 
    ECX:0xf0b123c5
    [RCX:0x1ffffffff0b123c5+RAX:0xdffffc0000000000=0xfffffbfff0b123c5size:UInt8->0x0]] 
    [0f, b6, 0c, 01]
ITERATION 1736 0xffffffff813306dd 0x11114000 | lock_release+0xcd (0xffffffff813306dd)                       
    mov rax, rdx 
    RAX:0xdffffc0000000000
    RDX:[34mdebug_locks+0x0 (0xffffffff85891e2c)[39m -> ''
    [48, 89, d0]
ITERATION 1737 0xffffffff813306e0 0x11114000 | lock_release+0xd0 (0xffffffff813306e0)                       
    and eax, 0x7 
    EAX:0x85891e2c
    ??_Immediate8to32_?? [83, e0, 07]
ITERATION 1738 0xffffffff813306e3 0x11114000 | lock_release+0xd3 (0xffffffff813306e3)                       
    add eax, 0x3 
    EAX:0x4
    ??_Immediate8to32_?? [83, c0, 03]
ITERATION 1739 0xffffffff813306e6 0x11114000 | lock_release+0xd6 (0xffffffff813306e6)                       
    cmp al, cl 
    AL:0x7
    CL:0x0
    [38, c8]
ITERATION 1740 0xffffffff813306e8 0x11114000 | lock_release+0xd8 (0xffffffff813306e8)                       
    jl 0xa 
    ??_NearBranch64_?? [7c, 08]
ITERATION 1741 0xffffffff813306ea 0x11114000 | lock_release+0xda (0xffffffff813306ea)                       
    test cl, cl 
    CL:0x0
    CL:0x0
    [84, c9]
ITERATION 1742 0xffffffff813306ec 0x11114000 | lock_release+0xdc (0xffffffff813306ec)                       
    jne 0x4d2 
    ??_NearBranch64_?? [0f, 85, cc, 04, 00, 00]
ITERATION 1743 0xffffffff813306f2 0x11114000 | lock_release+0xe2 (0xffffffff813306f2)                       
    mov r8d, dword ptr [rip+0x4561733] 
    R8D:0x1
    [RIP:0xffffffff813306f2+0x456173a=0xffffffff85891e2csize:UInt32->0x1]] 
    [44, 8b, 05, 33, 17, 56, 04]
ITERATION 1744 0xffffffff813306f9 0x11114000 | lock_release+0xe9 (0xffffffff813306f9)                       
    test r8d, r8d 
    R8D:0x1
    R8D:0x1
    [45, 85, c0]
ITERATION 1745 0xffffffff813306fc 0x11114000 | lock_release+0xec (0xffffffff813306fc)                       
    je 0x344 
    ??_NearBranch64_?? [0f, 84, 3e, 03, 00, 00]
ITERATION 1746 0xffffffff81330702 0x11114000 | lock_release+0xf2 (0xffffffff81330702)                       
    mov eax, dword ptr gs:[rip+0x7ecf05f7] 
    EAX:0x7
    [RIP:0xffffffff81330702+0x7ecf05fe=0x20d00size:UInt32->????]] 
    [65, 8b, 05, f7, 05, cf, 7e]
ITERATION 1747 0xffffffff81330709 0x11114000 | lock_release+0xf9 (0xffffffff81330709)                       
    test eax, eax 
    EAX:0x0
    EAX:0x0
    [85, c0]
ITERATION 1748 0xffffffff8133070b 0x11114000 | lock_release+0xfb (0xffffffff8133070b)                       
    jne 0x335 
    ??_NearBranch64_?? [0f, 85, 2f, 03, 00, 00]
ITERATION 1749 0xffffffff81330711 0x11114000 | lock_release+0x101 (0xffffffff81330711)                      
    mov r15, qword ptr gs:[0x1fdc0] 
    R15:0x0
    [None:0x0+0x1fdc0=0x1fdc0size:UInt64->????]] 
    [65, 4c, 8b, 3c, 25, c0, fd, 01, 00]
ITERATION 1750 0xffffffff8133071a 0x11114000 | lock_release+0x10a (0xffffffff8133071a)                      
    lea rdi, [r15+0xd0c] 
    RDI:[34m__cpu_online_mask+0x0 (0xffffffff8588a0e0)[39m -> ''
    [R15:0xffff888007674300+0xd0c=0xffff88800767500c]] 
    [49, 8d, bf, 0c, 0d, 00, 00]
ITERATION 1751 0xffffffff81330721 0x11114000 | lock_release+0x111 (0xffffffff81330721)                      
    mov rax, 0xdffffc0000000000 
    RAX:0x0
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1752 0xffffffff8133072b 0x11114000 | lock_release+0x11b (0xffffffff8133072b)                      
    mov rcx, rdi 
    RCX:0x0
    RDI:0xffff88800767500c -> 0xffffffff00000000
    [48, 89, f9]
ITERATION 1753 0xffffffff8133072e 0x11114000 | lock_release+0x11e (0xffffffff8133072e)                      
    shr rcx, 0x3 
    RCX:0xffff88800767500c -> 0xffffffff00000000
    ??_Immediate8_?? [48, c1, e9, 03]
ITERATION 1754 0xffffffff81330732 0x11114000 | lock_release+0x122 (0xffffffff81330732)                      
    movzx ecx, byte ptr [rcx+rax] 
    ECX:0xecea01
    [RCX:0x1ffff11000ecea01+RAX:0xdffffc0000000000=0xffffed1000ecea01size:UInt8->0x0]] 
    [0f, b6, 0c, 01]
ITERATION 1755 0xffffffff81330736 0x11114000 | lock_release+0x126 (0xffffffff81330736)                      
    mov rax, rdi 
    RAX:0xdffffc0000000000
    RDI:0xffff88800767500c -> 0xffffffff00000000
    [48, 89, f8]
ITERATION 1756 0xffffffff81330739 0x11114000 | lock_release+0x129 (0xffffffff81330739)                      
    and eax, 0x7 
    EAX:0x767500c
    ??_Immediate8to32_?? [83, e0, 07]
ITERATION 1757 0xffffffff8133073c 0x11114000 | lock_release+0x12c (0xffffffff8133073c)                      
    add eax, 0x3 
    EAX:0x4
    ??_Immediate8to32_?? [83, c0, 03]
ITERATION 1758 0xffffffff8133073f 0x11114000 | lock_release+0x12f (0xffffffff8133073f)                      
    cmp al, cl 
    AL:0x7
    CL:0x0
    [38, c8]
ITERATION 1759 0xffffffff81330741 0x11114000 | lock_release+0x131 (0xffffffff81330741)                      
    jl 0xa 
    ??_NearBranch64_?? [7c, 08]
ITERATION 1760 0xffffffff81330743 0x11114000 | lock_release+0x133 (0xffffffff81330743)                      
    test cl, cl 
    CL:0x0
    CL:0x0
    [84, c9]
ITERATION 1761 0xffffffff81330745 0x11114000 | lock_release+0x135 (0xffffffff81330745)                      
    jne 0x605 
    ??_NearBranch64_?? [0f, 85, ff, 05, 00, 00]
ITERATION 1762 0xffffffff8133074b 0x11114000 | lock_release+0x13b (0xffffffff8133074b)                      
    mov edi, dword ptr [r15+0xd0c] 
    EDI:0x767500c
    [R15:0xffff888007674300+0xd0c=0xffff88800767500csize:UInt32->0x0]] 
    [41, 8b, bf, 0c, 0d, 00, 00]
ITERATION 1763 0xffffffff81330752 0x11114000 | lock_release+0x142 (0xffffffff81330752)                      
    test edi, edi 
    EDI:0x0
    EDI:0x0
    [85, ff]
ITERATION 1764 0xffffffff81330754 0x11114000 | lock_release+0x144 (0xffffffff81330754)                      
    jne 0x2ec 
    ??_NearBranch64_?? [0f, 85, e6, 02, 00, 00]
ITERATION 1765 0xffffffff8133075a 0x11114000 | lock_release+0x14a (0xffffffff8133075a)                      
    pushfq 
    [9c]
ITERATION 1766 0xffffffff8133075b 0x11114000 | lock_release+0x14b (0xffffffff8133075b)                      
    pop rax 
    RAX:0x7
    [58]
ITERATION 1767 0xffffffff8133075c 0x11114000 | lock_release+0x14c (0xffffffff8133075c)                      
    nop dword ptr [rax+rax] 
    [RAX:0x346+RAX:0x346] 
    [0f, 1f, 44, 00, 00]
ITERATION 1768 0xffffffff81330761 0x11114000 | lock_release+0x151 (0xffffffff81330761)                      
    mov qword ptr [rbp-0xb0], rax 
    [RBP:0xffffc90000a1fef0+0xffffffffffffff50=0x1ffffc90000a1fe40]] 
    RAX:0x346
    [48, 89, 85, 50, ff, ff, ff]
ITERATION 1769 0xffffffff81330768 0x11114000 | lock_release+0x158 (0xffffffff81330768)                      
    cli 
    [fa]
ITERATION 1770 0xffffffff81330769 0x11114000 | lock_release+0x159 (0xffffffff81330769)                      
    nop word ptr [rax+rax] 
    [RAX:0x346+RAX:0x346] 
    [66, 0f, 1f, 44, 00, 00]
ITERATION 1771 0xffffffff8133076f 0x11114000 | lock_release+0x15f (0xffffffff8133076f)                      
    mov rcx, rdx 
    RCX:0x0
    RDX:[34mdebug_locks+0x0 (0xffffffff85891e2c)[39m -> ''
    [48, 89, d1]
ITERATION 1772 0xffffffff81330772 0x11114000 | lock_release+0x162 (0xffffffff81330772)                      
    mov dword ptr [r14-0x50], 0x1 
    [R14:0xffffc90000a1fec8+0xffffffffffffffb0=0x1ffffc90000a1fe78]] 
    ??_Immediate32_?? [41, c7, 46, b0, 01, 00, 00, 00]
ITERATION 1773 0xffffffff8133077a 0x11114000 | lock_release+0x16a (0xffffffff8133077a)                      
    and edx, 0x7 
    EDX:0x85891e2c
    ??_Immediate8to32_?? [83, e2, 07]
ITERATION 1774 0xffffffff8133077d 0x11114000 | lock_release+0x16d (0xffffffff8133077d)                      
    mov rax, 0xdffffc0000000000 
    RAX:0x346
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1775 0xffffffff81330787 0x11114000 | lock_release+0x177 (0xffffffff81330787)                      
    shr rcx, 0x3 
    RCX:[34mdebug_locks+0x0 (0xffffffff85891e2c)[39m -> ''
    ??_Immediate8_?? [48, c1, e9, 03]
ITERATION 1776 0xffffffff8133078b 0x11114000 | lock_release+0x17b (0xffffffff8133078b)                      
    add edx, 0x3 
    EDX:0x4
    ??_Immediate8to32_?? [83, c2, 03]
ITERATION 1777 0xffffffff8133078e 0x11114000 | lock_release+0x17e (0xffffffff8133078e)                      
    inc dword ptr gs:[rip+0x7ecf056b] 
    [RIP:0xffffffff8133078e+0x7ecf0572=0x20d00size:UInt32->????]] 
    [65, ff, 05, 6b, 05, cf, 7e]
ITERATION 1778 0xffffffff81330795 0x11114000 | lock_release+0x185 (0xffffffff81330795)                      
    movzx eax, byte ptr [rcx+rax] 
    EAX:0x0
    [RCX:0x1ffffffff0b123c5+RAX:0xdffffc0000000000=0xfffffbfff0b123c5size:UInt8->0x0]] 
    [0f, b6, 04, 01]
ITERATION 1779 0xffffffff81330799 0x11114000 | lock_release+0x189 (0xffffffff81330799)                      
    mov r15, qword ptr gs:[0x1fdc0] 
    R15:0xffff888007674300 -> 0x0
    [None:0x0+0x1fdc0=0x1fdc0size:UInt64->????]] 
    [65, 4c, 8b, 3c, 25, c0, fd, 01, 00]
ITERATION 1780 0xffffffff813307a2 0x11114000 | lock_release+0x192 (0xffffffff813307a2)                      
    cmp dl, al 
    DL:0x7
    AL:0x0
    [38, c2]
ITERATION 1781 0xffffffff813307a4 0x11114000 | lock_release+0x194 (0xffffffff813307a4)                      
    jl 0xa 
    ??_NearBranch64_?? [7c, 08]
ITERATION 1782 0xffffffff813307a6 0x11114000 | lock_release+0x196 (0xffffffff813307a6)                      
    test al, al 
    AL:0x0
    AL:0x0
    [84, c0]
ITERATION 1783 0xffffffff813307a8 0x11114000 | lock_release+0x198 (0xffffffff813307a8)                      
    jne 0x4f2 
    ??_NearBranch64_?? [0f, 85, ec, 04, 00, 00]
ITERATION 1784 0xffffffff813307ae 0x11114000 | lock_release+0x19e (0xffffffff813307ae)                      
    mov esi, dword ptr [rip+0x4561678] 
    ESI:0x8
    [RIP:0xffffffff813307ae+0x456167e=0xffffffff85891e2csize:UInt32->0x1]] 
    [8b, 35, 78, 16, 56, 04]
ITERATION 1785 0xffffffff813307b4 0x11114000 | lock_release+0x1a4 (0xffffffff813307b4)                      
    test esi, esi 
    ESI:0x1
    ESI:0x1
    [85, f6]
ITERATION 1786 0xffffffff813307b6 0x11114000 | lock_release+0x1a6 (0xffffffff813307b6)                      
    je 0x250 
    ??_NearBranch64_?? [0f, 84, 4a, 02, 00, 00]
ITERATION 1787 0xffffffff813307bc 0x11114000 | lock_release+0x1ac (0xffffffff813307bc)                      
    lea r10, [r15+0xd08] 
    R10:[34m__cpu_online_mask+0x7 (0xffffffff8588a0e7)[39m -> 0x0
    [R15:0xffff888007674300+0xd08=0xffff888007675008]] 
    [4d, 8d, 97, 08, 0d, 00, 00]
ITERATION 1788 0xffffffff813307c3 0x11114000 | lock_release+0x1b3 (0xffffffff813307c3)                      
    mov rax, 0xdffffc0000000000 
    RAX:0x0
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1789 0xffffffff813307cd 0x11114000 | lock_release+0x1bd (0xffffffff813307cd)                      
    mov rdx, r10 
    RDX:0x7
    R10:0xffff888007675008 -> ''
    [4c, 89, d2]
ITERATION 1790 0xffffffff813307d0 0x11114000 | lock_release+0x1c0 (0xffffffff813307d0)                      
    shr rdx, 0x3 
    RDX:0xffff888007675008 -> ''
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1791 0xffffffff813307d4 0x11114000 | lock_release+0x1c4 (0xffffffff813307d4)                      
    movzx eax, byte ptr [rdx+rax] 
    EAX:0x0
    [RDX:0x1ffff11000ecea01+RAX:0xdffffc0000000000=0xffffed1000ecea01size:UInt8->0x0]] 
    [0f, b6, 04, 02]
ITERATION 1792 0xffffffff813307d8 0x11114000 | lock_release+0x1c8 (0xffffffff813307d8)                      
    test al, al 
    AL:0x0
    AL:0x0
    [84, c0]
ITERATION 1793 0xffffffff813307da 0x11114000 | lock_release+0x1ca (0xffffffff813307da)                      
    je 0xa 
    ??_NearBranch64_?? [74, 08]
ITERATION 1794 0xffffffff813307e4 0x11114000 | lock_release+0x1d4 (0xffffffff813307e4)                      
    mov r9d, dword ptr [r15+0xd08] 
    R9D:0xf0b1141d
    [R15:0xffff888007674300+0xd08=0xffff888007675008size:UInt32->0x1]] 
    [45, 8b, 8f, 08, 0d, 00, 00]
ITERATION 1795 0xffffffff813307eb 0x11114000 | lock_release+0x1db (0xffffffff813307eb)                      
    test r9d, r9d 
    R9D:0x1
    R9D:0x1
    [45, 85, c9]
ITERATION 1796 0xffffffff813307ee 0x11114000 | lock_release+0x1de (0xffffffff813307ee)                      
    je 0x33e 
    ??_NearBranch64_?? [0f, 84, 38, 03, 00, 00]
ITERATION 1797 0xffffffff813307f4 0x11114000 | lock_release+0x1e4 (0xffffffff813307f4)                      
    mov edx, r9d 
    EDX:0xecea01
    R9D:0x1
    [44, 89, ca]
ITERATION 1798 0xffffffff813307f7 0x11114000 | lock_release+0x1e7 (0xffffffff813307f7)                      
    lea rcx, [r14-0x40] 
    RCX:0x1ffffffff0b123c5
    [R14:0xffffc90000a1fec8+0xffffffffffffffc0=0x1ffffc90000a1fe88]] 
    [49, 8d, 4e, c0]
ITERATION 1799 0xffffffff813307fb 0x11114000 | lock_release+0x1eb (0xffffffff813307fb)                      
    mov rsi, r12 
    RSI:0x1
    R12:[34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    [4c, 89, e6]
ITERATION 1800 0xffffffff813307fe 0x11114000 | lock_release+0x1ee (0xffffffff813307fe)                      
    mov rdi, r15 
    RDI:0x0
    R15:0xffff888007674300 -> 0x0
    [4c, 89, ff]
ITERATION 1801 0xffffffff81330801 0x11114000 | lock_release+0x1f1 (0xffffffff81330801)                      
    mov qword ptr [rbp-0xc0], r10 
    [RBP:0xffffc90000a1fef0+0xffffffffffffff40=0x1ffffc90000a1fe30]] 
    R10:0xffff888007675008 -> ''
    [4c, 89, 95, 40, ff, ff, ff]
ITERATION 1802 0xffffffff81330808 0x11114000 | lock_release+0x1f8 (0xffffffff81330808)                      
    mov dword ptr [rbp-0xb8], r9d 
    [RBP:0xffffc90000a1fef0+0xffffffffffffff48=0x1ffffc90000a1fe38]] 
    R9D:0x1
    [44, 89, 8d, 48, ff, ff, ff]
ITERATION 1803 0xffffffff8133080f 0x11114000 | lock_release+0x1ff (0xffffffff8133080f)                      
    call 0xffffffffffff96b1 
    ??_NearBranch64_?? [e8, ac, 96, ff, ff]
ITERATION 1804 0xffffffff81329ec0 0x11114000 | find_held_lock+0x0 (0xffffffff81329ec0)                      
    push rbp 
    RBP:0xffffc90000a1fef0 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [55]
ITERATION 1805 0xffffffff81329ec1 0x11114000 | find_held_lock+0x1 (0xffffffff81329ec1)                      
    mov rbp, rsp 
    RBP:0xffffc90000a1fef0 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    RSP:0xffffc90000a1fe18 -> 0xffffc90000a1fef0 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [48, 89, e5]
ITERATION 1806 0xffffffff81329ec4 0x11114000 | find_held_lock+0x4 (0xffffffff81329ec4)                      
    push r15 
    R15:0xffff888007674300 -> 0x0
    [41, 57]
ITERATION 1807 0xffffffff81329ec6 0x11114000 | find_held_lock+0x6 (0xffffffff81329ec6)                      
    lea r15d, [rdx-0x1] 
    R15D:0x7674300
    [RDX:0x1+0xffffffffffffffff=0x10000000000000000]] 
    [44, 8d, 7a, ff]
ITERATION 1808 0xffffffff81329eca 0x11114000 | find_held_lock+0xa (0xffffffff81329eca)                      
    push r14 
    R14:0xffffc90000a1fec8 -> [34minit_pid_ns+0x0 (0xffffffff84f3cf00)[39m -> 0xdead4ead00000000
    [41, 56]
ITERATION 1809 0xffffffff81329ecc 0x11114000 | find_held_lock+0xc (0xffffffff81329ecc)                      
    movsxd rax, r15d 
    RAX:0x0
    R15D:0x0
    [49, 63, c7]
ITERATION 1810 0xffffffff81329ecf 0x11114000 | find_held_lock+0xf (0xffffffff81329ecf)                      
    push r13 
    R13:[34m__task_pid_nr_ns+0x128 (0xffffffff8123f858)[39m -> 0xe87ede05210dff65
    [41, 55]
ITERATION 1811 0xffffffff81329ed1 0x11114000 | find_held_lock+0x11 (0xffffffff81329ed1)                     
    lea rax, [rax+rax*4] 
    RAX:0x0
    [RAX:0x0+RAX:0x0*0x4] 
    [48, 8d, 04, 80]
ITERATION 1812 0xffffffff81329ed5 0x11114000 | find_held_lock+0x15 (0xffffffff81329ed5)                     
    mov r13, rsi 
    R13:[34m__task_pid_nr_ns+0x128 (0xffffffff8123f858)[39m -> 0xe87ede05210dff65
    RSI:[34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    [49, 89, f5]
ITERATION 1813 0xffffffff81329ed8 0x11114000 | find_held_lock+0x18 (0xffffffff81329ed8)                     
    push r12 
    R12:[34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    [41, 54]
ITERATION 1814 0xffffffff81329eda 0x11114000 | find_held_lock+0x1a (0xffffffff81329eda)                     
    lea r12, [rdi+rax*8+0xd10] 
    R12:[34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    [RDI:0xffff888007674300+RAX:0x0*0x8+0xd10=0xffff888007675010]] 
    [4c, 8d, a4, c7, 10, 0d, 00, 00]
ITERATION 1815 0xffffffff81329ee2 0x11114000 | find_held_lock+0x22 (0xffffffff81329ee2)                     
    push rbx 
    RBX:0x1ffff92000143fc9 -> 0x0
    [53]
ITERATION 1816 0xffffffff81329ee3 0x11114000 | find_held_lock+0x23 (0xffffffff81329ee3)                     
    mov rdi, r12 
    RDI:0xffff888007674300 -> 0x0
    R12:0xffff888007675010 -> 0xffffffffffffffff
    [4c, 89, e7]
ITERATION 1817 0xffffffff81329ee6 0x11114000 | find_held_lock+0x26 (0xffffffff81329ee6)                     
    mov ebx, edx 
    EBX:0x143fc9
    EDX:0x1
    [89, d3]
ITERATION 1818 0xffffffff81329ee8 0x11114000 | find_held_lock+0x28 (0xffffffff81329ee8)                     
    sub rsp, 0x8 
    RSP:0xffffc90000a1fdf0 -> 0x1ffff92000143fc9 -> 0x0
    ??_Immediate8to64_?? [48, 83, ec, 08]
ITERATION 1819 0xffffffff81329eec 0x11114000 | find_held_lock+0x2c (0xffffffff81329eec)                     
    mov qword ptr [rbp-0x30], rcx 
    [RBP:0xffffc90000a1fe18+0xffffffffffffffd0=0x1ffffc90000a1fde8]] 
    RCX:0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0x0
    [48, 89, 4d, d0]
ITERATION 1820 0xffffffff81329ef0 0x11114000 | find_held_lock+0x30 (0xffffffff81329ef0)                     
    call 0x24c1660 
    ??_NearBranch64_?? [e8, 5b, 16, 4c, 02]
ITERATION 1821 0xffffffff837eb550 0x11114000 | match_held_lock+0x0 (0xffffffff837eb550)                     
    push rbp 
    RBP:0xffffc90000a1fe18 -> 0xffffc90000a1fef0 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [55]
ITERATION 1822 0xffffffff837eb551 0x11114000 | match_held_lock+0x1 (0xffffffff837eb551)                     
    mov rbp, rsp 
    RBP:0xffffc90000a1fe18 -> 0xffffc90000a1fef0 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    RSP:0xffffc90000a1fdd8 -> 0xffffc90000a1fe18 -> 0xffffc90000a1fef0 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [48, 89, e5]
ITERATION 1823 0xffffffff837eb554 0x11114000 | match_held_lock+0x4 (0xffffffff837eb554)                     
    push rbx 
    RBX:0x1
    [53]
ITERATION 1824 0xffffffff837eb555 0x11114000 | match_held_lock+0x5 (0xffffffff837eb555)                     
    mov rbx, rdi 
    RBX:0x1
    RDI:0xffff888007675010 -> 0xffffffffffffffff
    [48, 89, fb]
ITERATION 1825 0xffffffff837eb558 0x11114000 | match_held_lock+0x8 (0xffffffff837eb558)                     
    sub rsp, 0x8 
    RSP:0xffffc90000a1fdd0 -> ''
    ??_Immediate8to64_?? [48, 83, ec, 08]
ITERATION 1826 0xffffffff837eb55c 0x11114000 | match_held_lock+0xc (0xffffffff837eb55c)                     
    cmp qword ptr [rdi+0x10], rsi 
    [RDI:0xffff888007675010+0x10=0xffff888007675020size:UInt64->0xffffffff8505b580]] 
    RSI:[34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    [48, 39, 77, 10]
ITERATION 1827 0xffffffff837eb560 0x11114000 | match_held_lock+0x10 (0xffffffff837eb560)                    
    je 0x72 
    ??_NearBranch64_?? [74, 70]
ITERATION 1828 0xffffffff837eb5d2 0x11114000 | match_held_lock+0x82 (0xffffffff837eb5d2)                    
    add rsp, 0x8 
    RSP:0xffffc90000a1fdc8 -> 0xffff888007674300 -> 0x0
    ??_Immediate8to64_?? [48, 83, c4, 08]
ITERATION 1829 0xffffffff837eb5d6 0x11114000 | match_held_lock+0x86 (0xffffffff837eb5d6)                    
    mov eax, 0x1 
    EAX:0x0
    ??_Immediate32_?? [b8, 01, 00, 00, 00]
ITERATION 1830 0xffffffff837eb5db 0x11114000 | match_held_lock+0x8b (0xffffffff837eb5db)                    
    pop rbx 
    RBX:0xffff888007675010 -> 0xffffffffffffffff
    [5b]
ITERATION 1831 0xffffffff837eb5dc 0x11114000 | match_held_lock+0x8c (0xffffffff837eb5dc)                    
    pop rbp 
    RBP:0xffffc90000a1fdd8 -> 0xffffc90000a1fe18 -> 0xffffc90000a1fef0 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [5d]
ITERATION 1832 0xffffffff837eb5dd 0x11114000 | match_held_lock+0x8d (0xffffffff837eb5dd)                    
    ret 
    [c3]
ITERATION 1833 0xffffffff81329ef5 0x11114000 | find_held_lock+0x35 (0xffffffff81329ef5)                     
    test eax, eax 
    EAX:0x1
    EAX:0x1
    [85, c0]
ITERATION 1834 0xffffffff81329ef7 0x11114000 | find_held_lock+0x37 (0xffffffff81329ef7)                     
    jne 0x93 
    ??_NearBranch64_?? [0f, 85, 8d, 00, 00, 00]
ITERATION 1835 0xffffffff81329f8a 0x11114000 | find_held_lock+0xca (0xffffffff81329f8a)                     
    mov rax, 0xdffffc0000000000 
    RAX:0x1
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1836 0xffffffff81329f94 0x11114000 | find_held_lock+0xd4 (0xffffffff81329f94)                     
    mov rsi, qword ptr [rbp-0x30] 
    RSI:[34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    [RBP:0xffffc90000a1fe18+0xffffffffffffffd0=0xffffc90000a1fde8size:UInt64->0xffffc90000a1fe88]] 
    [48, 8b, 75, d0]
ITERATION 1837 0xffffffff81329f98 0x11114000 | find_held_lock+0xd8 (0xffffffff81329f98)                     
    mov rdx, rsi 
    RDX:0x1
    RSI:0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0x0
    [48, 89, f2]
ITERATION 1838 0xffffffff81329f9b 0x11114000 | find_held_lock+0xdb (0xffffffff81329f9b)                     
    shr rdx, 0x3 
    RDX:0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0x0
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1839 0xffffffff81329f9f 0x11114000 | find_held_lock+0xdf (0xffffffff81329f9f)                     
    movzx edx, byte ptr [rdx+rax] 
    EDX:0x143fd1
    [RDX:0x1ffff92000143fd1+RAX:0xdffffc0000000000=0xfffff52000143fd1size:UInt8->0x4]] 
    [0f, b6, 14, 02]
ITERATION 1840 0xffffffff81329fa3 0x11114000 | find_held_lock+0xe3 (0xffffffff81329fa3)                     
    mov rax, rsi 
    RAX:0xdffffc0000000000
    RSI:0xffffc90000a1fe88 -> 0xffffc90000a1fee8 -> 0x0
    [48, 89, f0]
ITERATION 1841 0xffffffff81329fa6 0x11114000 | find_held_lock+0xe6 (0xffffffff81329fa6)                     
    and eax, 0x7 
    EAX:0xa1fe88
    ??_Immediate8to32_?? [83, e0, 07]
ITERATION 1842 0xffffffff81329fa9 0x11114000 | find_held_lock+0xe9 (0xffffffff81329fa9)                     
    add eax, 0x3 
    EAX:0x0
    ??_Immediate8to32_?? [83, c0, 03]
ITERATION 1843 0xffffffff81329fac 0x11114000 | find_held_lock+0xec (0xffffffff81329fac)                     
    cmp al, dl 
    AL:0x3
    DL:0x4
    [38, d0]
ITERATION 1844 0xffffffff81329fae 0x11114000 | find_held_lock+0xee (0xffffffff81329fae)                     
    jl 0x6 
    ??_NearBranch64_?? [7c, 04]
ITERATION 1845 0xffffffff81329fb4 0x11114000 | find_held_lock+0xf4 (0xffffffff81329fb4)                     
    mov rax, qword ptr [rbp-0x30] 
    RAX:0x3
    [RBP:0xffffc90000a1fe18+0xffffffffffffffd0=0xffffc90000a1fde8size:UInt64->0xffffc90000a1fe88]] 
    [48, 8b, 45, d0]
ITERATION 1846 0xffffffff81329fb8 0x11114000 | find_held_lock+0xf8 (0xffffffff81329fb8)                     
    mov dword ptr [rax], r15d 
    [RAX:0xffffc90000a1fe88] 
    R15D:0x0
    [44, 89, 38]
ITERATION 1847 0xffffffff81329fbb 0x11114000 | find_held_lock+0xfb (0xffffffff81329fbb)                     
    add rsp, 0x8 
    RSP:0xffffc90000a1fde8 -> 0xffffc90000a1fe88 -> 0xffffc90000000000 -> 0x0
    ??_Immediate8to64_?? [48, 83, c4, 08]
ITERATION 1848 0xffffffff81329fbf 0x11114000 | find_held_lock+0xff (0xffffffff81329fbf)                     
    mov rax, r12 
    RAX:0xffffc90000a1fe88 -> 0xffffc90000000000 -> 0x0
    R12:0xffff888007675010 -> 0xffffffffffffffff
    [4c, 89, e0]
ITERATION 1849 0xffffffff81329fc2 0x11114000 | find_held_lock+0x102 (0xffffffff81329fc2)                    
    pop rbx 
    RBX:0x1
    [5b]
ITERATION 1850 0xffffffff81329fc3 0x11114000 | find_held_lock+0x103 (0xffffffff81329fc3)                    
    pop r12 
    R12:0xffff888007675010 -> 0xffffffffffffffff
    [41, 5c]
ITERATION 1851 0xffffffff81329fc5 0x11114000 | find_held_lock+0x105 (0xffffffff81329fc5)                    
    pop r13 
    R13:[34mrcu_lock_map+0x0 (0xffffffff8505b580)[39m -> [34mrcu_lock_key+0x0 (0xffffffff860d9aa0)[39m -> 0x0
    [41, 5d]
ITERATION 1852 0xffffffff81329fc7 0x11114000 | find_held_lock+0x107 (0xffffffff81329fc7)                    
    pop r14 
    R14:0xffffc90000a1fec8 -> [34minit_pid_ns+0x0 (0xffffffff84f3cf00)[39m -> 0xdead4ead00000000
    [41, 5e]
ITERATION 1853 0xffffffff81329fc9 0x11114000 | find_held_lock+0x109 (0xffffffff81329fc9)                    
    pop r15 
    R15:0x0
    [41, 5f]
ITERATION 1854 0xffffffff81329fcb 0x11114000 | find_held_lock+0x10b (0xffffffff81329fcb)                    
    pop rbp 
    RBP:0xffffc90000a1fe18 -> 0xffffc90000a1fef0 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [5d]
ITERATION 1855 0xffffffff81329fcc 0x11114000 | find_held_lock+0x10c (0xffffffff81329fcc)                    
    ret 
    [c3]
ITERATION 1856 0xffffffff81330814 0x11114000 | lock_release+0x204 (0xffffffff81330814)                      
    mov r9d, dword ptr [rbp-0xb8] 
    R9D:0x1
    [RBP:0xffffc90000a1fef0+0xffffffffffffff48=0xffffc90000a1fe38size:UInt32->0x1]] 
    [44, 8b, 8d, 48, ff, ff, ff]
ITERATION 1857 0xffffffff8133081b 0x11114000 | lock_release+0x20b (0xffffffff8133081b)                      
    mov r10, qword ptr [rbp-0xc0] 
    R10:0xffff888007675008 -> ''
    [RBP:0xffffc90000a1fef0+0xffffffffffffff40=0xffffc90000a1fe30size:UInt64->0xffff888007675008]] 
    [4c, 8b, 95, 40, ff, ff, ff]
ITERATION 1858 0xffffffff81330822 0x11114000 | lock_release+0x212 (0xffffffff81330822)                      
    test rax, rax 
    RAX:0xffff888007675010 -> 0xffffffffffffffff
    RAX:0xffff888007675010 -> 0xffffffffffffffff
    [48, 85, c0]
ITERATION 1859 0xffffffff81330825 0x11114000 | lock_release+0x215 (0xffffffff81330825)                      
    je 0x307 
    ??_NearBranch64_?? [0f, 84, 01, 03, 00, 00]
ITERATION 1860 0xffffffff8133082b 0x11114000 | lock_release+0x21b (0xffffffff8133082b)                      
    mov rdx, 0xdffffc0000000000 
    RDX:0x4
    ??_Immediate64_?? [48, ba, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1861 0xffffffff81330835 0x11114000 | lock_release+0x225 (0xffffffff81330835)                      
    lea rdi, [rax+0x24] 
    RDI:0xffff888007675010 -> 0xffffffffffffffff
    [RAX:0xffff888007675010+0x24=0xffff888007675034]] 
    [48, 8d, 78, 24]
ITERATION 1862 0xffffffff81330839 0x11114000 | lock_release+0x229 (0xffffffff81330839)                      
    mov rcx, rdi 
    RCX:0xffffc90000a1fe88 -> 0xffffc90000000000 -> 0x0
    RDI:0xffff888007675034 -> 0x7c1fc5a200000000
    [48, 89, f9]
ITERATION 1863 0xffffffff8133083c 0x11114000 | lock_release+0x22c (0xffffffff8133083c)                      
    shr rcx, 0x3 
    RCX:0xffff888007675034 -> 0x7c1fc5a200000000
    ??_Immediate8_?? [48, c1, e9, 03]
ITERATION 1864 0xffffffff81330840 0x11114000 | lock_release+0x230 (0xffffffff81330840)                      
    movzx ecx, byte ptr [rcx+rdx] 
    ECX:0xecea06
    [RCX:0x1ffff11000ecea06+RDX:0xdffffc0000000000=0xffffed1000ecea06size:UInt8->0x0]] 
    [0f, b6, 0c, 11]
ITERATION 1865 0xffffffff81330844 0x11114000 | lock_release+0x234 (0xffffffff81330844)                      
    mov rdx, rdi 
    RDX:0xdffffc0000000000
    RDI:0xffff888007675034 -> 0x7c1fc5a200000000
    [48, 89, fa]
ITERATION 1866 0xffffffff81330847 0x11114000 | lock_release+0x237 (0xffffffff81330847)                      
    and edx, 0x7 
    EDX:0x7675034
    ??_Immediate8to32_?? [83, e2, 07]
ITERATION 1867 0xffffffff8133084a 0x11114000 | lock_release+0x23a (0xffffffff8133084a)                      
    add edx, 0x3 
    EDX:0x4
    ??_Immediate8to32_?? [83, c2, 03]
ITERATION 1868 0xffffffff8133084d 0x11114000 | lock_release+0x23d (0xffffffff8133084d)                      
    cmp dl, cl 
    DL:0x7
    CL:0x0
    [38, ca]
ITERATION 1869 0xffffffff8133084f 0x11114000 | lock_release+0x23f (0xffffffff8133084f)                      
    jl 0xa 
    ??_NearBranch64_?? [7c, 08]
ITERATION 1870 0xffffffff81330851 0x11114000 | lock_release+0x241 (0xffffffff81330851)                      
    test cl, cl 
    CL:0x0
    CL:0x0
    [84, c9]
ITERATION 1871 0xffffffff81330853 0x11114000 | lock_release+0x243 (0xffffffff81330853)                      
    jne 0x48c 
    ??_NearBranch64_?? [0f, 85, 86, 04, 00, 00]
ITERATION 1872 0xffffffff81330859 0x11114000 | lock_release+0x249 (0xffffffff81330859)                      
    mov ecx, dword ptr [rax+0x24] 
    ECX:0x0
    [RAX:0xffff888007675010+0x24=0xffff888007675034size:UInt32->0x0]] 
    [8b, 48, 24]
ITERATION 1873 0xffffffff8133085c 0x11114000 | lock_release+0x24c (0xffffffff8133085c)                      
    test ecx, ecx 
    ECX:0x0
    ECX:0x0
    [85, c9]
ITERATION 1874 0xffffffff8133085e 0x11114000 | lock_release+0x24e (0xffffffff8133085e)                      
    jne 0x3df 
    ??_NearBranch64_?? [0f, 85, d9, 03, 00, 00]
ITERATION 1875 0xffffffff81330864 0x11114000 | lock_release+0x254 (0xffffffff81330864)                      
    mov rdx, 0xdffffc0000000000 
    RDX:0x7
    ??_Immediate64_?? [48, ba, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1876 0xffffffff8133086e 0x11114000 | lock_release+0x25e (0xffffffff8133086e)                      
    lea rdi, [rax+0x22] 
    RDI:0xffff888007675034 -> 0x7c1fc5a200000000
    [RAX:0xffff888007675010+0x22=0xffff888007675032]] 
    [48, 8d, 78, 22]
ITERATION 1877 0xffffffff81330872 0x11114000 | lock_release+0x262 (0xffffffff81330872)                      
    mov rcx, rdi 
    RCX:0x0
    RDI:0xffff888007675032 -> ''
    [48, 89, f9]
ITERATION 1878 0xffffffff81330875 0x11114000 | lock_release+0x265 (0xffffffff81330875)                      
    shr rcx, 0x3 
    RCX:0xffff888007675032 -> ''
    ??_Immediate8_?? [48, c1, e9, 03]
ITERATION 1879 0xffffffff81330879 0x11114000 | lock_release+0x269 (0xffffffff81330879)                      
    movzx ecx, byte ptr [rcx+rdx] 
    ECX:0xecea06
    [RCX:0x1ffff11000ecea06+RDX:0xdffffc0000000000=0xffffed1000ecea06size:UInt8->0x0]] 
    [0f, b6, 0c, 11]
ITERATION 1880 0xffffffff8133087d 0x11114000 | lock_release+0x26d (0xffffffff8133087d)                      
    mov rdx, rdi 
    RDX:0xdffffc0000000000
    RDI:0xffff888007675032 -> ''
    [48, 89, fa]
ITERATION 1881 0xffffffff81330880 0x11114000 | lock_release+0x270 (0xffffffff81330880)                      
    and edx, 0x7 
    EDX:0x7675032
    ??_Immediate8to32_?? [83, e2, 07]
ITERATION 1882 0xffffffff81330883 0x11114000 | lock_release+0x273 (0xffffffff81330883)                      
    add edx, 0x1 
    EDX:0x2
    ??_Immediate8to32_?? [83, c2, 01]
ITERATION 1883 0xffffffff81330886 0x11114000 | lock_release+0x276 (0xffffffff81330886)                      
    cmp dl, cl 
    DL:0x3
    CL:0x0
    [38, ca]
ITERATION 1884 0xffffffff81330888 0x11114000 | lock_release+0x278 (0xffffffff81330888)                      
    jl 0xa 
    ??_NearBranch64_?? [7c, 08]
ITERATION 1885 0xffffffff8133088a 0x11114000 | lock_release+0x27a (0xffffffff8133088a)                      
    test cl, cl 
    CL:0x0
    CL:0x0
    [84, c9]
ITERATION 1886 0xffffffff8133088c 0x11114000 | lock_release+0x27c (0xffffffff8133088c)                      
    jne 0x41f 
    ??_NearBranch64_?? [0f, 85, 19, 04, 00, 00]
ITERATION 1887 0xffffffff81330892 0x11114000 | lock_release+0x282 (0xffffffff81330892)                      
    test word ptr [rax+0x22], 0xfff0 
    [RAX:0xffff888007675010+0x22=0xffff888007675032size:UInt16->0x2]] 
    ??_Immediate16_?? [66, f7, 40, 22, f0, ff]
ITERATION 1888 0xffffffff81330898 0x11114000 | lock_release+0x288 (0xffffffff81330898)                      
    je 0x39 
    ??_NearBranch64_?? [74, 37]
ITERATION 1889 0xffffffff813308d1 0x11114000 | lock_release+0x2c1 (0xffffffff813308d1)                      
    mov rcx, r10 
    RCX:0x0
    R10:0xffff888007675008 -> ''
    [4c, 89, d1]
ITERATION 1890 0xffffffff813308d4 0x11114000 | lock_release+0x2c4 (0xffffffff813308d4)                      
    mov r12d, dword ptr [r14-0x40] 
    R12D:0x8505b580
    [R14:0xffffc90000a1fec8+0xffffffffffffffc0=0xffffc90000a1fe88size:UInt32->0x0]] 
    [45, 8b, 66, c0]
ITERATION 1891 0xffffffff813308d8 0x11114000 | lock_release+0x2c8 (0xffffffff813308d8)                      
    mov rdx, 0xdffffc0000000000 
    RDX:0x3
    ??_Immediate64_?? [48, ba, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1892 0xffffffff813308e2 0x11114000 | lock_release+0x2d2 (0xffffffff813308e2)                      
    shr rcx, 0x3 
    RCX:0xffff888007675008 -> ''
    ??_Immediate8_?? [48, c1, e9, 03]
ITERATION 1893 0xffffffff813308e6 0x11114000 | lock_release+0x2d6 (0xffffffff813308e6)                      
    movzx edx, byte ptr [rcx+rdx] 
    EDX:0x0
    [RCX:0x1ffff11000ecea01+RDX:0xdffffc0000000000=0xffffed1000ecea01size:UInt8->0x0]] 
    [0f, b6, 14, 11]
ITERATION 1894 0xffffffff813308ea 0x11114000 | lock_release+0x2da (0xffffffff813308ea)                      
    test dl, dl 
    DL:0x0
    DL:0x0
    [84, d2]
ITERATION 1895 0xffffffff813308ec 0x11114000 | lock_release+0x2dc (0xffffffff813308ec)                      
    je 0xb 
    ??_NearBranch64_?? [74, 09]
ITERATION 1896 0xffffffff813308f7 0x11114000 | lock_release+0x2e7 (0xffffffff813308f7)                      
    mov rcx, rax 
    RCX:0x1ffff11000ecea01
    RAX:0xffff888007675010 -> 0xffffffffffffffff
    [48, 89, c1]
ITERATION 1897 0xffffffff813308fa 0x11114000 | lock_release+0x2ea (0xffffffff813308fa)                      
    mov dword ptr [r15+0xd08], r12d 
    [R15:0xffff888007674300+0xd08=0xffff888007675008]] 
    R12D:0x0
    [45, 89, a7, 08, 0d, 00, 00]
ITERATION 1898 0xffffffff81330901 0x11114000 | lock_release+0x2f1 (0xffffffff81330901)                      
    mov rdx, 0xdffffc0000000000 
    RDX:0x0
    ??_Immediate64_?? [48, ba, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1899 0xffffffff8133090b 0x11114000 | lock_release+0x2fb (0xffffffff8133090b)                      
    shr rcx, 0x3 
    RCX:0xffff888007675010 -> 0xffffffffffffffff
    ??_Immediate8_?? [48, c1, e9, 03]
ITERATION 1900 0xffffffff8133090f 0x11114000 | lock_release+0x2ff (0xffffffff8133090f)                      
    cmp byte ptr [rcx+rdx], 0x0 
    [RCX:0x1ffff11000ecea02+RDX:0xdffffc0000000000=0xffffed1000ecea02size:UInt8->0x0]] 
    ??_Immediate8_?? [80, 3c, 11, 00]
ITERATION 1901 0xffffffff81330913 0x11114000 | lock_release+0x303 (0xffffffff81330913)                      
    jne 0x400 
    ??_NearBranch64_?? [0f, 85, fa, 03, 00, 00]
ITERATION 1902 0xffffffff81330919 0x11114000 | lock_release+0x309 (0xffffffff81330919)                      
    lea rdi, [r15+0xd00] 
    RDI:0xffff888007675032 -> ''
    [R15:0xffff888007674300+0xd00=0xffff888007675000]] 
    [49, 8d, bf, 00, 0d, 00, 00]
ITERATION 1903 0xffffffff81330920 0x11114000 | lock_release+0x310 (0xffffffff81330920)                      
    mov r13, qword ptr [rax] 
    R13:[34m__task_pid_nr_ns+0x128 (0xffffffff8123f858)[39m -> 0xe87ede05210dff65
    [RAX:0xffff888007675010size:UInt64->0xffffffffffffffff]] 
    [4c, 8b, 28]
ITERATION 1904 0xffffffff81330923 0x11114000 | lock_release+0x313 (0xffffffff81330923)                      
    mov rax, 0xdffffc0000000000 
    RAX:0xffff888007675010 -> 0xffffffffffffffff
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1905 0xffffffff8133092d 0x11114000 | lock_release+0x31d (0xffffffff8133092d)                      
    mov rdx, rdi 
    RDX:0xdffffc0000000000
    RDI:0xffff888007675000 -> 0xcda74fb54f1f57ce
    [48, 89, fa]
ITERATION 1906 0xffffffff81330930 0x11114000 | lock_release+0x320 (0xffffffff81330930)                      
    shr rdx, 0x3 
    RDX:0xffff888007675000 -> 0xcda74fb54f1f57ce
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1907 0xffffffff81330934 0x11114000 | lock_release+0x324 (0xffffffff81330934)                      
    cmp byte ptr [rdx+rax], 0x0 
    [RDX:0x1ffff11000ecea00+RAX:0xdffffc0000000000=0xffffed1000ecea00size:UInt8->0x0]] 
    ??_Immediate8_?? [80, 3c, 02, 00]
ITERATION 1908 0xffffffff81330938 0x11114000 | lock_release+0x328 (0xffffffff81330938)                      
    jne 0x423 
    ??_NearBranch64_?? [0f, 85, 1d, 04, 00, 00]
ITERATION 1909 0xffffffff8133093e 0x11114000 | lock_release+0x32e (0xffffffff8133093e)                      
    lea eax, [r9-0x1] 
    EAX:0x0
    [R9:0x1+0xffffffffffffffff=0x10000000000000000]] 
    [41, 8d, 41, ff]
ITERATION 1910 0xffffffff81330942 0x11114000 | lock_release+0x332 (0xffffffff81330942)                      
    mov qword ptr [r15+0xd00], r13 
    [R15:0xffff888007674300+0xd00=0xffff888007675000]] 
    R13:0xffffffffffffffff
    [4d, 89, af, 00, 0d, 00, 00]
ITERATION 1911 0xffffffff81330949 0x11114000 | lock_release+0x339 (0xffffffff81330949)                      
    cmp eax, r12d 
    EAX:0x0
    R12D:0x0
    [44, 39, e0]
ITERATION 1912 0xffffffff8133094c 0x11114000 | lock_release+0x33c (0xffffffff8133094c)                      
    je 0x14e 
    ??_NearBranch64_?? [0f, 84, 48, 01, 00, 00]
ITERATION 1913 0xffffffff81330a9a 0x11114000 | lock_release+0x48a (0xffffffff81330a9a)                      
    mov rdi, qword ptr gs:[0x1fdc0] 
    RDI:0xffff888007675000 -> 0xffffffffffffffff
    [None:0x0+0x1fdc0=0x1fdc0size:UInt64->????]] 
    [65, 48, 8b, 3c, 25, c0, fd, 01, 00]
ITERATION 1914 0xffffffff81330aa3 0x11114000 | lock_release+0x493 (0xffffffff81330aa3)                      
    call 0xffffffffffffa79d 
    ??_NearBranch64_?? [e8, 98, a7, ff, ff]
ITERATION 1915 0xffffffff8132b240 0x11114000 | check_chain_key+0x0 (0xffffffff8132b240)                     
    push rbp 
    RBP:0xffffc90000a1fef0 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [55]
ITERATION 1916 0xffffffff8132b241 0x11114000 | check_chain_key+0x1 (0xffffffff8132b241)                     
    lea rax, [rdi+0xd08] 
    RAX:0x0
    [RDI:0xffff888007674300+0xd08=0xffff888007675008]] 
    [48, 8d, 87, 08, 0d, 00, 00]
ITERATION 1917 0xffffffff8132b248 0x11114000 | check_chain_key+0x8 (0xffffffff8132b248)                     
    mov r9, rdi 
    R9:0x1
    RDI:0xffff888007674300 -> 0x0
    [49, 89, f9]
ITERATION 1918 0xffffffff8132b24b 0x11114000 | check_chain_key+0xb (0xffffffff8132b24b)                     
    mov rdx, rax 
    RDX:0x1ffff11000ecea00
    RAX:0xffff888007675008 -> 0x0
    [48, 89, c2]
ITERATION 1919 0xffffffff8132b24e 0x11114000 | check_chain_key+0xe (0xffffffff8132b24e)                     
    shr rdx, 0x3 
    RDX:0xffff888007675008 -> 0x0
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1920 0xffffffff8132b252 0x11114000 | check_chain_key+0x12 (0xffffffff8132b252)                    
    mov rbp, rsp 
    RBP:0xffffc90000a1fef0 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    RSP:0xffffc90000a1fe18 -> 0xffffc90000a1fef0 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [48, 89, e5]
ITERATION 1921 0xffffffff8132b255 0x11114000 | check_chain_key+0x15 (0xffffffff8132b255)                    
    push r15 
    R15:0xffff888007674300 -> 0x0
    [41, 57]
ITERATION 1922 0xffffffff8132b257 0x11114000 | check_chain_key+0x17 (0xffffffff8132b257)                    
    push r14 
    R14:0xffffc90000a1fec8 -> [34minit_pid_ns+0x0 (0xffffffff84f3cf00)[39m -> 0xdead4ead00000000
    [41, 56]
ITERATION 1923 0xffffffff8132b259 0x11114000 | check_chain_key+0x19 (0xffffffff8132b259)                    
    push r13 
    R13:0xffffffffffffffff
    [41, 55]
ITERATION 1924 0xffffffff8132b25b 0x11114000 | check_chain_key+0x1b (0xffffffff8132b25b)                    
    push r12 
    R12:0x0
    [41, 54]
ITERATION 1925 0xffffffff8132b25d 0x11114000 | check_chain_key+0x1d (0xffffffff8132b25d)                    
    push rbx 
    RBX:0x1ffff92000143fc9 -> 0x0
    [53]
ITERATION 1926 0xffffffff8132b25e 0x11114000 | check_chain_key+0x1e (0xffffffff8132b25e)                    
    sub rsp, 0x30 
    RSP:0xffffc90000a1fdf0 -> 0x1ffff92000143fc9 -> 0x0
    ??_Immediate8to64_?? [48, 83, ec, 30]
ITERATION 1927 0xffffffff8132b262 0x11114000 | check_chain_key+0x22 (0xffffffff8132b262)                    
    mov qword ptr [rbp-0x58], rax 
    [RBP:0xffffc90000a1fe18+0xffffffffffffffa8=0x1ffffc90000a1fdc0]] 
    RAX:0xffff888007675008 -> 0x0
    [48, 89, 45, a8]
ITERATION 1928 0xffffffff8132b266 0x11114000 | check_chain_key+0x26 (0xffffffff8132b266)                    
    mov rax, 0xdffffc0000000000 
    RAX:0xffff888007675008 -> 0x0
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1929 0xffffffff8132b270 0x11114000 | check_chain_key+0x30 (0xffffffff8132b270)                    
    movzx eax, byte ptr [rdx+rax] 
    EAX:0x0
    [RDX:0x1ffff11000ecea01+RAX:0xdffffc0000000000=0xffffed1000ecea01size:UInt8->0x0]] 
    [0f, b6, 04, 02]
ITERATION 1930 0xffffffff8132b274 0x11114000 | check_chain_key+0x34 (0xffffffff8132b274)                    
    test al, al 
    AL:0x0
    AL:0x0
    [84, c0]
ITERATION 1931 0xffffffff8132b276 0x11114000 | check_chain_key+0x36 (0xffffffff8132b276)                    
    je 0xa 
    ??_NearBranch64_?? [74, 08]
ITERATION 1932 0xffffffff8132b280 0x11114000 | check_chain_key+0x40 (0xffffffff8132b280)                    
    mov edx, dword ptr [r9+0xd08] 
    EDX:0xecea01
    [R9:0xffff888007674300+0xd08=0xffff888007675008size:UInt32->0x0]] 
    [41, 8b, 91, 08, 0d, 00, 00]
ITERATION 1933 0xffffffff8132b287 0x11114000 | check_chain_key+0x47 (0xffffffff8132b287)                    
    test edx, edx 
    EDX:0x0
    EDX:0x0
    [85, d2]
ITERATION 1934 0xffffffff8132b289 0x11114000 | check_chain_key+0x49 (0xffffffff8132b289)                    
    je 0x22b 
    ??_NearBranch64_?? [0f, 84, 25, 02, 00, 00]
ITERATION 1935 0xffffffff8132b4b4 0x11114000 | check_chain_key+0x274 (0xffffffff8132b4b4)                   
    mov r12, 0xffffffffffffffff 
    R12:0x0
    ??_Immediate32to64_?? [49, c7, c4, ff, ff, ff, ff]
ITERATION 1936 0xffffffff8132b4bb 0x11114000 | check_chain_key+0x27b (0xffffffff8132b4bb)                   
    xor r14d, r14d 
    R14D:0xa1fec8
    R14D:0xa1fec8
    [45, 31, f6]
ITERATION 1937 0xffffffff8132b4be 0x11114000 | check_chain_key+0x27e (0xffffffff8132b4be)                   
    lea r13, [r9+0xd00] 
    R13:0xffffffffffffffff
    [R9:0xffff888007674300+0xd00=0xffff888007675000]] 
    [4d, 8d, a9, 00, 0d, 00, 00]
ITERATION 1938 0xffffffff8132b4c5 0x11114000 | check_chain_key+0x285 (0xffffffff8132b4c5)                   
    mov rax, 0xdffffc0000000000 
    RAX:0x0
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1939 0xffffffff8132b4cf 0x11114000 | check_chain_key+0x28f (0xffffffff8132b4cf)                   
    mov rdx, r13 
    RDX:0x0
    R13:0xffff888007675000 -> 0xffffffffffffffff
    [4c, 89, ea]
ITERATION 1940 0xffffffff8132b4d2 0x11114000 | check_chain_key+0x292 (0xffffffff8132b4d2)                   
    shr rdx, 0x3 
    RDX:0xffff888007675000 -> 0xffffffffffffffff
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 1941 0xffffffff8132b4d6 0x11114000 | check_chain_key+0x296 (0xffffffff8132b4d6)                   
    cmp byte ptr [rdx+rax], 0x0 
    [RDX:0x1ffff11000ecea00+RAX:0xdffffc0000000000=0xffffed1000ecea00size:UInt8->0x0]] 
    ??_Immediate8_?? [80, 3c, 02, 00]
ITERATION 1942 0xffffffff8132b4da 0x11114000 | check_chain_key+0x29a (0xffffffff8132b4da)                   
    jne 0x33f 
    ??_NearBranch64_?? [0f, 85, 39, 03, 00, 00]
ITERATION 1943 0xffffffff8132b4e0 0x11114000 | check_chain_key+0x2a0 (0xffffffff8132b4e0)                   
    cmp qword ptr [r9+0xd00], r12 
    [R9:0xffff888007674300+0xd00=0xffff888007675000size:UInt64->0xffffffffffffffff]] 
    R12:0xffffffffffffffff
    [4d, 39, a1, 00, 0d, 00, 00]
ITERATION 1944 0xffffffff8132b4e7 0x11114000 | check_chain_key+0x2a7 (0xffffffff8132b4e7)                   
    mov qword ptr [rbp-0x30], r9 
    [RBP:0xffffc90000a1fe18+0xffffffffffffffd0=0x1ffffc90000a1fde8]] 
    R9:0xffff888007674300 -> 0x0
    [4c, 89, 4d, d0]
ITERATION 1945 0xffffffff8132b4eb 0x11114000 | check_chain_key+0x2ab (0xffffffff8132b4eb)                   
    jne 0xf0 
    ??_NearBranch64_?? [0f, 85, ea, 00, 00, 00]
ITERATION 1946 0xffffffff8132b4f1 0x11114000 | check_chain_key+0x2b1 (0xffffffff8132b4f1)                   
    add rsp, 0x30 
    RSP:0xffffc90000a1fdc0 -> 0xffff888007675008 -> 0x0
    ??_Immediate8to64_?? [48, 83, c4, 30]
ITERATION 1947 0xffffffff8132b4f5 0x11114000 | check_chain_key+0x2b5 (0xffffffff8132b4f5)                   
    pop rbx 
    RBX:0x1ffff92000143fc9 -> 0x0
    [5b]
ITERATION 1948 0xffffffff8132b4f6 0x11114000 | check_chain_key+0x2b6 (0xffffffff8132b4f6)                   
    pop r12 
    R12:0xffffffffffffffff
    [41, 5c]
ITERATION 1949 0xffffffff8132b4f8 0x11114000 | check_chain_key+0x2b8 (0xffffffff8132b4f8)                   
    pop r13 
    R13:0xffff888007675000 -> 0xffffffffffffffff
    [41, 5d]
ITERATION 1950 0xffffffff8132b4fa 0x11114000 | check_chain_key+0x2ba (0xffffffff8132b4fa)                   
    pop r14 
    R14:0x0
    [41, 5e]
ITERATION 1951 0xffffffff8132b4fc 0x11114000 | check_chain_key+0x2bc (0xffffffff8132b4fc)                   
    pop r15 
    R15:0xffff888007674300 -> 0x0
    [41, 5f]
ITERATION 1952 0xffffffff8132b4fe 0x11114000 | check_chain_key+0x2be (0xffffffff8132b4fe)                   
    pop rbp 
    RBP:0xffffc90000a1fe18 -> 0xffffc90000a1fef0 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [5d]
ITERATION 1953 0xffffffff8132b4ff 0x11114000 | check_chain_key+0x2bf (0xffffffff8132b4ff)                   
    ret 
    [c3]
ITERATION 1954 0xffffffff81330aa8 0x11114000 | lock_release+0x498 (0xffffffff81330aa8)                      
    jmp 0xffffffffffffff5e 
    ??_NearBranch64_?? [e9, 59, ff, ff, ff]
ITERATION 1955 0xffffffff81330a06 0x11114000 | lock_release+0x3f6 (0xffffffff81330a06)                      
    mov eax, 0xffffffff 
    EAX:0x0
    ??_Immediate32_?? [b8, ff, ff, ff, ff]
ITERATION 1956 0xffffffff81330a0b 0x11114000 | lock_release+0x3fb (0xffffffff81330a0b)                      
    xadd dword ptr gs:[rip+0x7ecf02ed], eax 
    [RIP:0xffffffff81330a0b+0x7ecf02f5=0x20d00size:UInt32->????]] 
    EAX:0xffffffff
    [65, 0f, c1, 05, ed, 02, cf, 7e]
ITERATION 1957 0xffffffff81330a13 0x11114000 | lock_release+0x403 (0xffffffff81330a13)                      
    cmp eax, 0x1 
    EAX:0x1
    ??_Immediate8to32_?? [83, f8, 01]
ITERATION 1958 0xffffffff81330a16 0x11114000 | lock_release+0x406 (0xffffffff81330a16)                      
    jne 0x133 
    ??_NearBranch64_?? [0f, 85, 2d, 01, 00, 00]
ITERATION 1959 0xffffffff81330a1c 0x11114000 | lock_release+0x40c (0xffffffff81330a1c)                      
    pushfq 
    [9c]
ITERATION 1960 0xffffffff81330a1d 0x11114000 | lock_release+0x40d (0xffffffff81330a1d)                      
    pop rax 
    RAX:0x1
    [58]
ITERATION 1961 0xffffffff81330a1e 0x11114000 | lock_release+0x40e (0xffffffff81330a1e)                      
    nop dword ptr [rax+rax] 
    [RAX:0x146+RAX:0x146] 
    [0f, 1f, 44, 00, 00]
ITERATION 1962 0xffffffff81330a23 0x11114000 | lock_release+0x413 (0xffffffff81330a23)                      
    test ah, 0x2 
    AH:0x1
    ??_Immediate8_?? [f6, c4, 02]
ITERATION 1963 0xffffffff81330a26 0x11114000 | lock_release+0x416 (0xffffffff81330a26)                      
    jne 0x119 
    ??_NearBranch64_?? [0f, 85, 13, 01, 00, 00]
ITERATION 1964 0xffffffff81330a2c 0x11114000 | lock_release+0x41c (0xffffffff81330a2c)                      
    test qword ptr [rbp-0xb0], 0x200 
    [RBP:0xffffc90000a1fef0+0xffffffffffffff50=0xffffc90000a1fe40size:UInt64->0x346]] 
    ??_Immediate32to64_?? [48, f7, 85, 50, ff, ff, ff, 00, 02, 00, 00]
ITERATION 1965 0xffffffff81330a37 0x11114000 | lock_release+0x427 (0xffffffff81330a37)                      
    je 0x9 
    ??_NearBranch64_?? [74, 07]
ITERATION 1966 0xffffffff81330a39 0x11114000 | lock_release+0x429 (0xffffffff81330a39)                      
    sti 
    [fb]
ITERATION 1967 0xffffffff81330a3a 0x11114000 | lock_release+0x42a (0xffffffff81330a3a)                      
    nop word ptr [rax+rax] 
    [RAX:0x146+RAX:0x146] 
    [66, 0f, 1f, 44, 00, 00]
ITERATION 1968 0xffffffff81330a40 0x11114000 | lock_release+0x430 (0xffffffff81330a40)                      
    mov rax, 0xdffffc0000000000 
    RAX:0x146
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 1969 0xffffffff81330a4a 0x11114000 | lock_release+0x43a (0xffffffff81330a4a)                      
    add rbx, rax 
    RBX:0x1ffff92000143fc9 -> 0x0
    RAX:0xdffffc0000000000
    [48, 01, c3]
ITERATION 1970 0xffffffff81330a4d 0x11114000 | lock_release+0x43d (0xffffffff81330a4d)                      
    mov qword ptr [rbx], 0x0 
    [RBX:0xfffff52000143fc9] 
    ??_Immediate32to64_?? [48, c7, 03, 00, 00, 00, 00]
ITERATION 1971 0xffffffff81330a54 0x11114000 | lock_release+0x444 (0xffffffff81330a54)                      
    mov dword ptr [rbx+0x8], 0x0 
    [RBX:0xfffff52000143fc9+0x8=0xfffff52000143fd1]] 
    ??_Immediate32_?? [c7, 43, 08, 00, 00, 00, 00]
ITERATION 1972 0xffffffff81330a5b 0x11114000 | lock_release+0x44b (0xffffffff81330a5b)                      
    mov rax, qword ptr [rbp-0x30] 
    RAX:0xdffffc0000000000
    [RBP:0xffffc90000a1fef0+0xffffffffffffffd0=0xffffc90000a1fec0size:UInt64->0x45d4480925b42200]] 
    [48, 8b, 45, d0]
ITERATION 1973 0xffffffff81330a5f 0x11114000 | lock_release+0x44f (0xffffffff81330a5f)                      
    xor rax, qword ptr gs:[0x28] 
    RAX:0x45d4480925b42200
    [None:0x0+0x28=0x28size:UInt64->????]] 
    [65, 48, 33, 04, 25, 28, 00, 00, 00]
ITERATION 1974 0xffffffff81330a68 0x11114000 | lock_release+0x458 (0xffffffff81330a68)                      
    jne 0x22d 
    ??_NearBranch64_?? [0f, 85, 27, 02, 00, 00]
ITERATION 1975 0xffffffff81330a6e 0x11114000 | lock_release+0x45e (0xffffffff81330a6e)                      
    add rsp, 0xa0 
    RSP:0xffffc90000a1fe28 -> 0x41b58a02
    ??_Immediate32to64_?? [48, 81, c4, a0, 00, 00, 00]
ITERATION 1976 0xffffffff81330a75 0x11114000 | lock_release+0x465 (0xffffffff81330a75)                      
    pop rbx 
    RBX:0xfffff52000143fc9 -> 0x0
    [5b]
ITERATION 1977 0xffffffff81330a76 0x11114000 | lock_release+0x466 (0xffffffff81330a76)                      
    pop r12 
    R12:0x0
    [41, 5c]
ITERATION 1978 0xffffffff81330a78 0x11114000 | lock_release+0x468 (0xffffffff81330a78)                      
    pop r13 
    R13:0xffffffffffffffff
    [41, 5d]
ITERATION 1979 0xffffffff81330a7a 0x11114000 | lock_release+0x46a (0xffffffff81330a7a)                      
    pop r14 
    R14:0xffffc90000a1fec8 -> [34minit_pid_ns+0x0 (0xffffffff84f3cf00)[39m -> 0xdead4ead00000000
    [41, 5e]
ITERATION 1980 0xffffffff81330a7c 0x11114000 | lock_release+0x46c (0xffffffff81330a7c)                      
    pop r15 
    R15:0xffff888007674300 -> 0x0
    [41, 5f]
ITERATION 1981 0xffffffff81330a7e 0x11114000 | lock_release+0x46e (0xffffffff81330a7e)                      
    pop rbp 
    RBP:0xffffc90000a1fef0 -> 0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [5d]
ITERATION 1982 0xffffffff81330a7f 0x11114000 | lock_release+0x46f (0xffffffff81330a7f)                      
    ret 
    [c3]
ITERATION 1983 0xffffffff8123f877 0x11114000 | __task_pid_nr_ns+0x147 (0xffffffff8123f877)                  
    lea rsp, [rbp-0x20] 
    RSP:0xffffc90000a1ff00 -> 0x0
    [RBP:0xffffc90000a1ff20+0xffffffffffffffe0=0x1ffffc90000a1ff00]] 
    [48, 8d, 65, e0]
ITERATION 1984 0xffffffff8123f87b 0x11114000 | __task_pid_nr_ns+0x14b (0xffffffff8123f87b)                  
    mov eax, r12d 
    EAX:0x0
    R12D:0xdeadbeef
    [44, 89, e0]
ITERATION 1985 0xffffffff8123f87e 0x11114000 | __task_pid_nr_ns+0x14e (0xffffffff8123f87e)                  
    pop rbx 
    RBX:[34minit_pid_ns+0x0 (0xffffffff84f3cf00)[39m -> 0xdead4ead00000000
    [5b]
ITERATION 1986 0xffffffff8123f87f 0x11114000 | __task_pid_nr_ns+0x14f (0xffffffff8123f87f)                  
    pop r12 
    R12:0xdeadbeef
    [41, 5c]
ITERATION 1987 0xffffffff8123f881 0x11114000 | __task_pid_nr_ns+0x151 (0xffffffff8123f881)                  
    pop r13 
    R13:0xffff8880075f5b40 -> ''
    [41, 5d]
ITERATION 1988 0xffffffff8123f883 0x11114000 | __task_pid_nr_ns+0x153 (0xffffffff8123f883)                  
    pop r14 
    R14:0xffff8880075f5b40 -> ''
    [41, 5e]
ITERATION 1989 0xffffffff8123f885 0x11114000 | __task_pid_nr_ns+0x155 (0xffffffff8123f885)                  
    pop rbp 
    RBP:0xffffc90000a1ff20 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [5d]
ITERATION 1990 0xffffffff8123f886 0x11114000 | __task_pid_nr_ns+0x156 (0xffffffff8123f886)                  
    ret 
    [c3]
ITERATION 1991 0xffffffff81212fde 0x11114000 | __do_sys_getpid+0x1e (0xffffffff81212fde)                    
    pop rbp 
    RBP:0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [5d]
ITERATION 1992 0xffffffff81212fdf 0x11114000 | __do_sys_getpid+0x1f (0xffffffff81212fdf)                    
    cdqe 
    [48, 98]
ITERATION 1993 0xffffffff81212fe1 0x11114000 | __do_sys_getpid+0x21 (0xffffffff81212fe1)                    
    ret 
    [c3]
ITERATION 1994 0xffffffff837e82ab 0x11114000 | do_syscall_64+0x3b (0xffffffff837e82ab)                      
    mov qword ptr [r12+0x50], rax 
    [R12:0xffffc90000a1ff58+0x50=0xffffc90000a1ffa8]] 
    RAX:0xffffffffdeadbeef
    [49, 89, 44, 24, 50]
ITERATION 1995 0xffffffff837e82b0 0x11114000 | do_syscall_64+0x40 (0xffffffff837e82b0)                      
    mov rdi, r12 
    RDI:0xffff888007674300 -> 0x0
    R12:0xffffc90000a1ff58 -> 0x0
    [4c, 89, e7]
ITERATION 1996 0xffffffff837e82b3 0x11114000 | do_syscall_64+0x43 (0xffffffff837e82b3)                      
    call 0x38bd 
    ??_NearBranch64_?? [e8, b8, 38, 00, 00]
ITERATION 1997 0xffffffff837ebb70 0x11114000 | syscall_exit_to_user_mode+0x0 (0xffffffff837ebb70)           
    push rbp 
    RBP:0xffffc90000a1ff48 -> 0x0
    [55]
ITERATION 1998 0xffffffff837ebb71 0x11114000 | syscall_exit_to_user_mode+0x1 (0xffffffff837ebb71)           
    mov rax, qword ptr gs:[0x1fdc0] 
    RAX:0xffffffffdeadbeef
    [None:0x0+0x1fdc0=0x1fdc0size:UInt64->????]] 
    [65, 48, 8b, 04, 25, c0, fd, 01, 00]
ITERATION 1999 0xffffffff837ebb7a 0x11114000 | syscall_exit_to_user_mode+0xa (0xffffffff837ebb7a)           
    mov rbp, rsp 
    RBP:0xffffc90000a1ff48 -> 0x0
    RSP:0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [48, 89, e5]
ITERATION 2000 0xffffffff837ebb7d 0x11114000 | syscall_exit_to_user_mode+0xd (0xffffffff837ebb7d)           
    sub rsp, 0x8 
    RSP:0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    ??_Immediate8to64_?? [48, 83, ec, 08]
ITERATION 2001 0xffffffff837ebb81 0x11114000 | syscall_exit_to_user_mode+0x11 (0xffffffff837ebb81)          
    mov rsi, qword ptr [rax+0x8] 
    RSI:0xffffc90000a1fe88 -> 0xffffc90000000000 -> 0x0
    [RAX:0xffff888007674300+0x8=0xffff888007674308size:UInt64->0x0]] 
    [48, 8b, 70, 08]
ITERATION 2002 0xffffffff837ebb85 0x11114000 | syscall_exit_to_user_mode+0x15 (0xffffffff837ebb85)          
    test sil, 0x76 
    SIL:0x0
    ??_Immediate8_?? [40, f6, c6, 76]
ITERATION 2003 0xffffffff837ebb89 0x11114000 | syscall_exit_to_user_mode+0x19 (0xffffffff837ebb89)          
    jne 0x19 
    ??_NearBranch64_?? [75, 17]
ITERATION 2004 0xffffffff837ebb8b 0x11114000 | syscall_exit_to_user_mode+0x1b (0xffffffff837ebb8b)          
    cli 
    [fa]
ITERATION 2005 0xffffffff837ebb8c 0x11114000 | syscall_exit_to_user_mode+0x1c (0xffffffff837ebb8c)          
    nop word ptr [rax+rax] 
    [RAX:0xffff888007674300+RAX:0xffff888007674300] 
    [66, 0f, 1f, 44, 00, 00]
ITERATION 2006 0xffffffff837ebb92 0x11114000 | syscall_exit_to_user_mode+0x22 (0xffffffff837ebb92)          
    call 0xfffffffffdbcd4be 
    ??_NearBranch64_?? [e8, b9, d4, bc, fd]
ITERATION 2007 0xffffffff813b9050 0x11114000 | exit_to_user_mode_prepare+0x0 (0xffffffff813b9050)           
    nop dword ptr [rax+rax] 
    [RAX:0xffff888007674300+RAX:0xffff888007674300] 
    [0f, 1f, 44, 00, 00]
ITERATION 2008 0xffffffff813b9055 0x11114000 | exit_to_user_mode_prepare+0x5 (0xffffffff813b9055)           
    push rbp 
    RBP:0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [55]
ITERATION 2009 0xffffffff813b9056 0x11114000 | exit_to_user_mode_prepare+0x6 (0xffffffff813b9056)           
    mov rbp, rsp 
    RBP:0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    RSP:0xffffc90000a1ff18 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [48, 89, e5]
ITERATION 2010 0xffffffff813b9059 0x11114000 | exit_to_user_mode_prepare+0x9 (0xffffffff813b9059)           
    push r15 
    R15:0x0
    [41, 57]
ITERATION 2011 0xffffffff813b905b 0x11114000 | exit_to_user_mode_prepare+0xb (0xffffffff813b905b)           
    push r14 
    R14:0x0
    [41, 56]
ITERATION 2012 0xffffffff813b905d 0x11114000 | exit_to_user_mode_prepare+0xd (0xffffffff813b905d)           
    push r13 
    R13:0x0
    [41, 55]
ITERATION 2013 0xffffffff813b905f 0x11114000 | exit_to_user_mode_prepare+0xf (0xffffffff813b905f)           
    push r12 
    R12:0xffffc90000a1ff58 -> 0x0
    [41, 54]
ITERATION 2014 0xffffffff813b9061 0x11114000 | exit_to_user_mode_prepare+0x11 (0xffffffff813b9061)          
    push rbx 
    RBX:0x0
    [53]
ITERATION 2015 0xffffffff813b9062 0x11114000 | exit_to_user_mode_prepare+0x12 (0xffffffff813b9062)          
    mov r13, qword ptr gs:[0x1fdc0] 
    R13:0x0
    [None:0x0+0x1fdc0=0x1fdc0size:UInt64->????]] 
    [65, 4c, 8b, 2c, 25, c0, fd, 01, 00]
ITERATION 2016 0xffffffff813b906b 0x11114000 | exit_to_user_mode_prepare+0x1b (0xffffffff813b906b)          
    sub rsp, 0x8 
    RSP:0xffffc90000a1fef0 -> 0x0
    ??_Immediate8to64_?? [48, 83, ec, 08]
ITERATION 2017 0xffffffff813b906f 0x11114000 | exit_to_user_mode_prepare+0x1f (0xffffffff813b906f)          
    mov rbx, qword ptr [r13] 
    RBX:0x0
    [R13:0xffff888007674300size:UInt64->0x0]] 
    [49, 8b, 5d, 00]
ITERATION 2018 0xffffffff813b9073 0x11114000 | exit_to_user_mode_prepare+0x23 (0xffffffff813b9073)          
    test ebx, 0x2300e 
    EBX:0x0
    ??_Immediate32_?? [f7, c3, 0e, 30, 02, 00]
ITERATION 2019 0xffffffff813b9079 0x11114000 | exit_to_user_mode_prepare+0x29 (0xffffffff813b9079)          
    jne 0x6e 
    ??_NearBranch64_?? [75, 6c]
ITERATION 2020 0xffffffff813b907b 0x11114000 | exit_to_user_mode_prepare+0x2b (0xffffffff813b907b)          
    test bh, 0x8 
    BH:0x0
    ??_Immediate8_?? [f6, c7, 08]
ITERATION 2021 0xffffffff813b907e 0x11114000 | exit_to_user_mode_prepare+0x2e (0xffffffff813b907e)          
    jne 0x49 
    ??_NearBranch64_?? [75, 47]
ITERATION 2022 0xffffffff813b9080 0x11114000 | exit_to_user_mode_prepare+0x30 (0xffffffff813b9080)          
    test ebx, 0x400000 
    EBX:0x0
    ??_Immediate32_?? [f7, c3, 00, 00, 40, 00]
ITERATION 2023 0xffffffff813b9086 0x11114000 | exit_to_user_mode_prepare+0x36 (0xffffffff813b9086)          
    jne 0x4e 
    ??_NearBranch64_?? [75, 4c]
ITERATION 2024 0xffffffff813b9088 0x11114000 | exit_to_user_mode_prepare+0x38 (0xffffffff813b9088)          
    and bh, 0x40 
    BH:0x0
    ??_Immediate8_?? [80, e7, 40]
ITERATION 2025 0xffffffff813b908b 0x11114000 | exit_to_user_mode_prepare+0x3b (0xffffffff813b908b)          
    jne 0x55 
    ??_NearBranch64_?? [75, 53]
ITERATION 2026 0xffffffff813b908d 0x11114000 | exit_to_user_mode_prepare+0x3d (0xffffffff813b908d)          
    mov rax, qword ptr gs:[0x1fdc0] 
    RAX:0xffff888007674300 -> 0x0
    [None:0x0+0x1fdc0=0x1fdc0size:UInt64->????]] 
    [65, 48, 8b, 04, 25, c0, fd, 01, 00]
ITERATION 2027 0xffffffff813b9096 0x11114000 | exit_to_user_mode_prepare+0x46 (0xffffffff813b9096)          
    and dword ptr [rax+0x10], 0xfffffff9 
    [RAX:0xffff888007674300+0x10=0xffff888007674310size:UInt32->0x0]] 
    ??_Immediate8to32_?? [83, 60, 10, f9]
ITERATION 2028 0xffffffff813b909a 0x11114000 | exit_to_user_mode_prepare+0x4a (0xffffffff813b909a)          
    nop 
    [66, 90]
ITERATION 2029 0xffffffff813b909c 0x11114000 | exit_to_user_mode_prepare+0x4c (0xffffffff813b909c)          
    call 0xfffffffffff7c024 
    ??_NearBranch64_?? [e8, 1f, c0, f7, ff]
ITERATION 2030 0xffffffff813350c0 0x11114000 | lockdep_sys_exit+0x0 (0xffffffff813350c0)                    
    mov rax, 0xdffffc0000000000 
    RAX:0xffff888007674300 -> 0x0
    ??_Immediate64_?? [48, b8, 00, 00, 00, 00, 00, fc, ff, df]
ITERATION 2031 0xffffffff813350ca 0x11114000 | lockdep_sys_exit+0xa (0xffffffff813350ca)                    
    push rbp 
    RBP:0xffffc90000a1ff18 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [55]
ITERATION 2032 0xffffffff813350cb 0x11114000 | lockdep_sys_exit+0xb (0xffffffff813350cb)                    
    mov rbp, rsp 
    RBP:0xffffc90000a1ff18 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    RSP:0xffffc90000a1fed8 -> 0xffffc90000a1ff18 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [48, 89, e5]
ITERATION 2033 0xffffffff813350ce 0x11114000 | lockdep_sys_exit+0xe (0xffffffff813350ce)                    
    push r12 
    R12:0xffffc90000a1ff58 -> 0x0
    [41, 54]
ITERATION 2034 0xffffffff813350d0 0x11114000 | lockdep_sys_exit+0x10 (0xffffffff813350d0)                   
    mov r12, qword ptr gs:[0x1fdc0] 
    R12:0xffffc90000a1ff58 -> 0x0
    [None:0x0+0x1fdc0=0x1fdc0size:UInt64->????]] 
    [65, 4c, 8b, 24, 25, c0, fd, 01, 00]
ITERATION 2035 0xffffffff813350d9 0x11114000 | lockdep_sys_exit+0x19 (0xffffffff813350d9)                   
    lea rdi, [r12+0xd08] 
    RDI:0xffffc90000a1ff58 -> 0x0
    [R12:0xffff888007674300+0xd08=0xffff888007675008]] 
    [49, 8d, bc, 24, 08, 0d, 00, 00]
ITERATION 2036 0xffffffff813350e1 0x11114000 | lockdep_sys_exit+0x21 (0xffffffff813350e1)                   
    mov rdx, rdi 
    RDX:0x1ffff11000ecea00
    RDI:0xffff888007675008 -> 0x0
    [48, 89, fa]
ITERATION 2037 0xffffffff813350e4 0x11114000 | lockdep_sys_exit+0x24 (0xffffffff813350e4)                   
    shr rdx, 0x3 
    RDX:0xffff888007675008 -> 0x0
    ??_Immediate8_?? [48, c1, ea, 03]
ITERATION 2038 0xffffffff813350e8 0x11114000 | lockdep_sys_exit+0x28 (0xffffffff813350e8)                   
    movzx eax, byte ptr [rdx+rax] 
    EAX:0x0
    [RDX:0x1ffff11000ecea01+RAX:0xdffffc0000000000=0xffffed1000ecea01size:UInt8->0x0]] 
    [0f, b6, 04, 02]
ITERATION 2039 0xffffffff813350ec 0x11114000 | lockdep_sys_exit+0x2c (0xffffffff813350ec)                   
    test al, al 
    AL:0x0
    AL:0x0
    [84, c0]
ITERATION 2040 0xffffffff813350ee 0x11114000 | lockdep_sys_exit+0x2e (0xffffffff813350ee)                   
    je 0x6 
    ??_NearBranch64_?? [74, 04]
ITERATION 2041 0xffffffff813350f4 0x11114000 | lockdep_sys_exit+0x34 (0xffffffff813350f4)                   
    mov eax, dword ptr [r12+0xd08] 
    EAX:0x0
    [R12:0xffff888007674300+0xd08=0xffff888007675008size:UInt32->0x0]] 
    [41, 8b, 84, 24, 08, 0d, 00, 00]
ITERATION 2042 0xffffffff813350fc 0x11114000 | lockdep_sys_exit+0x3c (0xffffffff813350fc)                   
    test eax, eax 
    EAX:0x0
    EAX:0x0
    [85, c0]
ITERATION 2043 0xffffffff813350fe 0x11114000 | lockdep_sys_exit+0x3e (0xffffffff813350fe)                   
    jne 0x6 
    ??_NearBranch64_?? [75, 04]
ITERATION 2044 0xffffffff81335100 0x11114000 | lockdep_sys_exit+0x40 (0xffffffff81335100)                   
    pop r12 
    R12:0xffff888007674300 -> 0x0
    [41, 5c]
ITERATION 2045 0xffffffff81335102 0x11114000 | lockdep_sys_exit+0x42 (0xffffffff81335102)                   
    pop rbp 
    RBP:0xffffc90000a1fed8 -> 0xffffc90000a1ff18 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [5d]
ITERATION 2046 0xffffffff81335103 0x11114000 | lockdep_sys_exit+0x43 (0xffffffff81335103)                   
    ret 
    [c3]
ITERATION 2047 0xffffffff813b90a1 0x11114000 | exit_to_user_mode_prepare+0x51 (0xffffffff813b90a1)          
    add rsp, 0x8 
    RSP:0xffffc90000a1fee8 -> 0x0
    ??_Immediate8to64_?? [48, 83, c4, 08]
ITERATION 2048 0xffffffff813b90a5 0x11114000 | exit_to_user_mode_prepare+0x55 (0xffffffff813b90a5)          
    pop rbx 
    RBX:0x0
    [5b]
ITERATION 2049 0xffffffff813b90a6 0x11114000 | exit_to_user_mode_prepare+0x56 (0xffffffff813b90a6)          
    pop r12 
    R12:0xffffc90000a1ff58 -> 0x0
    [41, 5c]
ITERATION 2050 0xffffffff813b90a8 0x11114000 | exit_to_user_mode_prepare+0x58 (0xffffffff813b90a8)          
    pop r13 
    R13:0xffff888007674300 -> 0x0
    [41, 5d]
ITERATION 2051 0xffffffff813b90aa 0x11114000 | exit_to_user_mode_prepare+0x5a (0xffffffff813b90aa)          
    pop r14 
    R14:0x0
    [41, 5e]
ITERATION 2052 0xffffffff813b90ac 0x11114000 | exit_to_user_mode_prepare+0x5c (0xffffffff813b90ac)          
    pop r15 
    R15:0x0
    [41, 5f]
ITERATION 2053 0xffffffff813b90ae 0x11114000 | exit_to_user_mode_prepare+0x5e (0xffffffff813b90ae)          
    pop rbp 
    RBP:0xffffc90000a1ff18 -> 0xffffc90000a1ff30 -> 0xffffc90000a1ff48 -> 0x0
    [5d]
ITERATION 2054 0xffffffff813b90af 0x11114000 | exit_to_user_mode_prepare+0x5f (0xffffffff813b90af)          
    ret 
    [c3]
ITERATION 2055 0xffffffff837ebb97 0x11114000 | syscall_exit_to_user_mode+0x27 (0xffffffff837ebb97)          
    nop 
    [66, 90]
ITERATION 2056 0xffffffff837ebb99 0x11114000 | syscall_exit_to_user_mode+0x29 (0xffffffff837ebb99)          
    verw word ptr [rip+0x6d57a0] 
    [RIP:0xffffffff837ebb99+0x6d57a7] 
    [0f, 00, 2d, a0, 57, 6d, 00]
ITERATION 2057 0xffffffff837ebba0 0x11114000 | syscall_exit_to_user_mode+0x30 (0xffffffff837ebba0)          
    leave 
    [c9]
ITERATION 2058 0xffffffff837ebba1 0x11114000 | syscall_exit_to_user_mode+0x31 (0xffffffff837ebba1)          
    ret 
    [c3]
ITERATION 2059 0xffffffff837e82b8 0x11114000 | do_syscall_64+0x48 (0xffffffff837e82b8)                      
    mov r12, qword ptr [rbp-0x8] 
    R12:0xffffc90000a1ff58 -> 0x0
    [RBP:0xffffc90000a1ff48+0xfffffffffffffff8=0xffffc90000a1ff40size:UInt64->0x0]] 
    [4c, 8b, 65, f8]
ITERATION 2060 0xffffffff837e82bc 0x11114000 | do_syscall_64+0x4c (0xffffffff837e82bc)                      
    leave 
    [c9]
ITERATION 2061 0xffffffff837e82bd 0x11114000 | do_syscall_64+0x4d (0xffffffff837e82bd)                      
    ret 
    [c3]
ITERATION 2062 0xffffffff83a0007c 0x11114000 | entry_SYSCALL_64_after_hwframe+0x44 (0xffffffff83a0007c)     
    nop dword ptr [rax+rax] 
    [RAX:0x0+RAX:0x0] 
    [0f, 1f, 44, 00, 00]
ITERATION 2063 0xffffffff83a00081 0x11114000 | entry_SYSCALL_64_after_hwframe+0x49 (0xffffffff83a00081)     
    mov rcx, qword ptr [rsp+0x58] 
    RCX:0x1ffff11000ecea02
    [RSP:0xffffc90000a1ff58+0x58=0xffffc90000a1ffb0size:UInt64->0x7ffff7ecb0d7]] 
    [48, 8b, 4c, 24, 58]
ITERATION 2064 0xffffffff83a00086 0x11114000 | entry_SYSCALL_64_after_hwframe+0x4e (0xffffffff83a00086)     
    mov r11, qword ptr [rsp+0x80] 
    R11:0xfffffbfff0b1141c -> 0x0
    [RSP:0xffffc90000a1ff58+0x80=0xffffc90000a1ffd8size:UInt64->0x7ffff7ecb0d7]] 
    [4c, 8b, 9c, 24, 80, 00, 00, 00]
ITERATION 2065 0xffffffff83a0008e 0x11114000 | entry_SYSCALL_64_after_hwframe+0x56 (0xffffffff83a0008e)     
    cmp r11, rcx 
    R11:[34mlibc-2.31.so!__GI___getpid+0x7 (0x7ffff7ecb0d7)[39m -> 0x841f0fc3
    RCX:[34mlibc-2.31.so!__GI___getpid+0x7 (0x7ffff7ecb0d7)[39m -> 0x841f0fc3
    [49, 39, cb]
ITERATION 2066 0xffffffff83a00091 0x11114000 | entry_SYSCALL_64_after_hwframe+0x59 (0xffffffff83a00091)     
    jne 0xf5f 
    ??_NearBranch64_?? [0f, 85, 59, 0f, 00, 00]
ITERATION 2067 0xffffffff83a00097 0x11114000 | entry_SYSCALL_64_after_hwframe+0x5f (0xffffffff83a00097)     
    shl rcx, 0x10 
    RCX:[34mlibc-2.31.so!__GI___getpid+0x7 (0x7ffff7ecb0d7)[39m -> 0x841f0fc3
    ??_Immediate8_?? [48, c1, e1, 10]
ITERATION 2068 0xffffffff83a0009b 0x11114000 | entry_SYSCALL_64_after_hwframe+0x63 (0xffffffff83a0009b)     
    sar rcx, 0x10 
    RCX:0x7ffff7ecb0d70000
    ??_Immediate8_?? [48, c1, f9, 10]
ITERATION 2069 0xffffffff83a0009f 0x11114000 | entry_SYSCALL_64_after_hwframe+0x67 (0xffffffff83a0009f)     
    cmp r11, rcx 
    R11:[34mlibc-2.31.so!__GI___getpid+0x7 (0x7ffff7ecb0d7)[39m -> 0x841f0fc3
    RCX:[34mlibc-2.31.so!__GI___getpid+0x7 (0x7ffff7ecb0d7)[39m -> 0x841f0fc3
    [49, 39, cb]
ITERATION 2070 0xffffffff83a000a2 0x11114000 | entry_SYSCALL_64_after_hwframe+0x6a (0xffffffff83a000a2)     
    jne 0xf4e 
    ??_NearBranch64_?? [0f, 85, 48, 0f, 00, 00]
ITERATION 2071 0xffffffff83a000a8 0x11114000 | entry_SYSCALL_64_after_hwframe+0x70 (0xffffffff83a000a8)     
    cmp qword ptr [rsp+0x88], 0x33 
    [RSP:0xffffc90000a1ff58+0x88=0xffffc90000a1ffe0size:UInt64->0x33]] 
    ??_Immediate8to64_?? [48, 83, bc, 24, 88, 00, 00, 00, 33]
ITERATION 2072 0xffffffff83a000b1 0x11114000 | entry_SYSCALL_64_after_hwframe+0x79 (0xffffffff83a000b1)     
    jne 0xf3f 
    ??_NearBranch64_?? [0f, 85, 39, 0f, 00, 00]
ITERATION 2073 0xffffffff83a000b7 0x11114000 | entry_SYSCALL_64_after_hwframe+0x7f (0xffffffff83a000b7)     
    mov r11, qword ptr [rsp+0x30] 
    R11:[34mlibc-2.31.so!__GI___getpid+0x7 (0x7ffff7ecb0d7)[39m -> 0x841f0fc3
    [RSP:0xffffc90000a1ff58+0x30=0xffffc90000a1ff88size:UInt64->0x106]] 
    [4c, 8b, 5c, 24, 30]
ITERATION 2074 0xffffffff83a000bc 0x11114000 | entry_SYSCALL_64_after_hwframe+0x84 (0xffffffff83a000bc)     
    cmp qword ptr [rsp+0x90], r11 
    [RSP:0xffffc90000a1ff58+0x90=0xffffc90000a1ffe8size:UInt64->0x106]] 
    R11:0x106
    [4c, 39, 9c, 24, 90, 00, 00, 00]
ITERATION 2075 0xffffffff83a000c4 0x11114000 | entry_SYSCALL_64_after_hwframe+0x8c (0xffffffff83a000c4)     
    jne 0xf2c 
    ??_NearBranch64_?? [0f, 85, 26, 0f, 00, 00]
ITERATION 2076 0xffffffff83a000ca 0x11114000 | entry_SYSCALL_64_after_hwframe+0x92 (0xffffffff83a000ca)     
    test r11, 0x10100 
    R11:0x106
    ??_Immediate32to64_?? [49, f7, c3, 00, 01, 01, 00]
ITERATION 2077 0xffffffff83a000d1 0x11114000 | entry_SYSCALL_64_after_hwframe+0x99 (0xffffffff83a000d1)     
    jne 0xf1f 
    ??_NearBranch64_?? [0f, 85, 19, 0f, 00, 00]
ITERATION 2078 0xffffffff83a00ff0 0x11114000 | common_interrupt_return+0x0 (0xffffffff83a00ff0)             
    pop r15 
    R15:0x0
    [41, 5f]
ITERATION 2079 0xffffffff83a00ff2 0x11114000 | common_interrupt_return+0x2 (0xffffffff83a00ff2)             
    pop r14 
    R14:0x0
    [41, 5e]
ITERATION 2080 0xffffffff83a00ff4 0x11114000 | common_interrupt_return+0x4 (0xffffffff83a00ff4)             
    pop r13 
    R13:0x0
    [41, 5d]
ITERATION 2081 0xffffffff83a00ff6 0x11114000 | common_interrupt_return+0x6 (0xffffffff83a00ff6)             
    pop r12 
    R12:0x0
    [41, 5c]
ITERATION 2082 0xffffffff83a00ff8 0x11114000 | common_interrupt_return+0x8 (0xffffffff83a00ff8)             
    pop rbp 
    RBP:0x0
    [5d]
ITERATION 2083 0xffffffff83a00ff9 0x11114000 | common_interrupt_return+0x9 (0xffffffff83a00ff9)             
    pop rbx 
    RBX:0x0
    [5b]
ITERATION 2084 0xffffffff83a00ffa 0x11114000 | common_interrupt_return+0xa (0xffffffff83a00ffa)             
    pop r11 
    R11:0x106
    [41, 5b]
ITERATION 2085 0xffffffff83a00ffc 0x11114000 | common_interrupt_return+0xc (0xffffffff83a00ffc)             
    pop r10 
    R10:0xffff888007675008 -> 0x0
    [41, 5a]
ITERATION 2086 0xffffffff83a00ffe 0x11114000 | common_interrupt_return+0xe (0xffffffff83a00ffe)             
    pop r9 
    R9:0xffff888007674300 -> 0x0
    [41, 59]
ITERATION 2087 0xffffffff83a01000 0x11114000 | common_interrupt_return+0x10 (0xffffffff83a01000)            
    pop r8 
    R8:0x1
    [41, 58]
ITERATION 2088 0xffffffff83a01002 0x11114000 | common_interrupt_return+0x12 (0xffffffff83a01002)            
    pop rax 
    RAX:0x0
    [58]
ITERATION 2089 0xffffffff83a01003 0x11114000 | common_interrupt_return+0x13 (0xffffffff83a01003)            
    pop rcx 
    RCX:[34mlibc-2.31.so!__GI___getpid+0x7 (0x7ffff7ecb0d7)[39m -> 0x841f0fc3
    [59]
ITERATION 2090 0xffffffff83a01004 0x11114000 | common_interrupt_return+0x14 (0xffffffff83a01004)            
    pop rdx 
    RDX:0x1ffff11000ecea01
    [5a]
ITERATION 2091 0xffffffff83a01005 0x11114000 | common_interrupt_return+0x15 (0xffffffff83a01005)            
    pop rsi 
    RSI:0x0
    [5e]
ITERATION 2092 0xffffffff83a01006 0x11114000 | common_interrupt_return+0x16 (0xffffffff83a01006)            
    mov rdi, rsp 
    RDI:0xffff888007675008 -> 0x0
    RSP:0xffffc90000a1ffc8 -> 0x1
    [48, 89, e7]
ITERATION 2093 0xffffffff83a01009 0x11114000 | common_interrupt_return+0x19 (0xffffffff83a01009)            
    mov rsp, qword ptr gs:[0xa004] 
    RSP:0xffffc90000a1ffc8 -> 0x1
    [None:0x0+0xa004=0xa004size:UInt64->????]] 
    [65, 48, 8b, 24, 25, 04, a0, 00, 00]
ITERATION 2094 0xffffffff83a01012 0x11114000 | common_interrupt_return+0x22 (0xffffffff83a01012)            
    push qword ptr [rdi+0x30] 
    [RDI:0xffffc90000a1ffc8+0x30=0xffffc90000a1fff8size:UInt64->0x2b]] 
    [ff, 77, 30]
ITERATION 2095 0xffffffff83a01015 0x11114000 | common_interrupt_return+0x25 (0xffffffff83a01015)            
    push qword ptr [rdi+0x28] 
    [RDI:0xffffc90000a1ffc8+0x28=0xffffc90000a1fff0size:UInt64->0x7fffffffeb78]] 
    [ff, 77, 28]
ITERATION 2096 0xffffffff83a01018 0x11114000 | common_interrupt_return+0x28 (0xffffffff83a01018)            
    push qword ptr [rdi+0x20] 
    [RDI:0xffffc90000a1ffc8+0x20=0xffffc90000a1ffe8size:UInt64->0x106]] 
    [ff, 77, 20]
ITERATION 2097 0xffffffff83a0101b 0x11114000 | common_interrupt_return+0x2b (0xffffffff83a0101b)            
    push qword ptr [rdi+0x18] 
    [RDI:0xffffc90000a1ffc8+0x18=0xffffc90000a1ffe0size:UInt64->0x33]] 
    [ff, 77, 18]
ITERATION 2098 0xffffffff83a0101e 0x11114000 | common_interrupt_return+0x2e (0xffffffff83a0101e)            
    push qword ptr [rdi+0x10] 
    [RDI:0xffffc90000a1ffc8+0x10=0xffffc90000a1ffd8size:UInt64->0x7ffff7ecb0d7]] 
    [ff, 77, 10]
ITERATION 2099 0xffffffff83a01021 0x11114000 | common_interrupt_return+0x31 (0xffffffff83a01021)            
    push qword ptr [rdi] 
    [RDI:0xffffc90000a1ffc8size:UInt64->0x1]] 
    [ff, 37]
ITERATION 2100 0xffffffff83a01023 0x11114000 | common_interrupt_return+0x33 (0xffffffff83a01023)            
    push rax 
    RAX:0xffffffffdeadbeef
    [50]
ITERATION 2101 0xffffffff83a01024 0x11114000 | common_interrupt_return+0x34 (0xffffffff83a01024)            
    nop 
    [66, 90]
ITERATION 2102 0xffffffff83a01026 0x11114000 | common_interrupt_return+0x36 (0xffffffff83a01026)            
    mov rdi, cr3 
    RDI:0xffffc90000a1ffc8 -> 0x1
    CR3:0x11114000
    [0f, 20, df]
ITERATION 2103 0xffffffff83a01029 0x11114000 | common_interrupt_return+0x39 (0xffffffff83a01029)            
    jmp 0x36 
    ??_NearBranch64_?? [eb, 34]
ITERATION 2104 0xffffffff83a0105f 0x11114000 | common_interrupt_return+0x6f (0xffffffff83a0105f)            
    or rdi, 0x1000 
    RDI:0x11114000
    ??_Immediate32to64_?? [48, 81, cf, 00, 10, 00, 00]
ITERATION 2105 0xffffffff83a01066 0x11114000 | common_interrupt_return+0x76 (0xffffffff83a01066)            
    mov cr3, rdi 
    CR3:0x11114000
    RDI:0x11115000
    [0f, 22, df]
ITERATION 2106 0xffffffff83a01069 0x11115000 | common_interrupt_return+0x79 (0xffffffff83a01069)            
    pop rax 
    RAX:0xffffffffdeadbeef
    [58]
ITERATION 2107 0xffffffff83a0106a 0x11115000 | common_interrupt_return+0x7a (0xffffffff83a0106a)            
    pop rdi 
    RDI:0x11115000
    [5f]
ITERATION 2108 0xffffffff83a0106b 0x11115000 | common_interrupt_return+0x7b (0xffffffff83a0106b)            
    swapgs 
    [0f, 01, f8]
ITERATION 2109 0xffffffff83a0106e 0x11115000 | common_interrupt_return+0x7e (0xffffffff83a0106e)            
    jmp 0x32 
    ??_NearBranch64_?? [eb, 30]
ITERATION 2110 0xffffffff83a010a0 0x11115000 | native_iret+0x0 (0xffffffff83a010a0)                         
    test byte ptr [rsp+0x20], 0x4 
    [RSP:0xfffffe0000002fd8+0x20=0xfffffe0000002ff8size:UInt8->0x2b]] 
    ??_Immediate8_?? [f6, 44, 24, 20, 04]
ITERATION 2111 0xffffffff83a010a5 0x11115000 | native_iret+0x5 (0xffffffff83a010a5)                         
    jne 0x4 
    ??_NearBranch64_?? [75, 02]
ITERATION 2112 0xffffffff83a010a7 0x11115000 | native_irq_return_iret+0x0 (0xffffffff83a010a7)              
    iretq 
    [48, cf]
ITERATION 2113 0x00007ffff7ecb0d7 0x11115000 | libc-2.31.so!__GI___getpid+0x7 (0x7ffff7ecb0d7)              
    ret 
    [c3]
ITERATION 2114 0x000055555555514e 0x11115000 | example1!main+0x19 (0x55555555514e)                          
    mov dword ptr [rbp-0xc], eax 
    [RBP:0x7fffffffeb90+0xfffffffffffffff4=0x100007fffffffeb84]] 
    EAX:0xdeadbeef
    [89, 45, f4]
ITERATION 2115 0x0000555555555151 0x11115000 | example1!main+0x1c (0x555555555151)                          
    mov rax, qword ptr [rbp-0x8] 
    RAX:0xffffffffdeadbeef
    [RBP:0x7fffffffeb90+0xfffffffffffffff8=0x7fffffffeb88size:UInt64->0x555555556004]] 
    [48, 8b, 45, f8]
ITERATION 2116 0x0000555555555155 0x11115000 | example1!main+0x20 (0x555555555155)                          
    movzx eax, byte ptr [rax] 
    EAX:0x55556004
    [RAX:0x555555556004size:UInt8->0x61::a]] 
    [0f, b6, 00]
ITERATION 2117 0x0000555555555158 0x11115000 | example1!main+0x23 (0x555555555158)                          
    cmp al, 0x66 
    AL:0x61
    ??_Immediate8_?? [3c, 66]
ITERATION 2118 0x000055555555515a 0x11115000 | example1!main+0x25 (0x55555555515a)                          
    jne 0x43 
    ??_NearBranch64_?? [75, 41]
ITERATION 2119 0x000055555555519d 0x11115000 | example1!main+0x68 (0x55555555519d)                          
    nop 
    [90]
ITERATION 2120 0x000055555555519e 0x11115000 | example1!main+0x69 (0x55555555519e)                          
    leave 
    [c9]
ITERATION 2121 0x000055555555519f 0x11115000 | example1!main+0x6a (0x55555555519f)                          
    ret 
    [c3]
```
