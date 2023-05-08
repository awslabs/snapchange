#[inline(never)]
fn reset_guest() {
    panic!();
}

fn main() {
    const SCRATCH_SIZE: usize = 100 * 1024 * 1024;

    // Scratch space for writing structures
    let scratch = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            SCRATCH_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    } as usize;

    // Force all of the allocation to be loaded into memory
    let data = [0x41; SCRATCH_SIZE];

    unsafe {
        std::ptr::copy(data.as_ptr(), scratch as *mut u8, SCRATCH_SIZE);
    }

    println!(
        "SNAPSHOT Memory: {scratch:#x} Reset: {:p}",
        reset_guest as *const fn()
    );

    // Take the snapshot
    unsafe {
        std::arch::asm!("xor r10, r10 ; xor rcx, rcx", options(nostack));
        std::arch::asm!("int 0x3 ; vmcall", options(nostack));
    }

    // Execute the dirty pages and instructions for this benchmark
    // R9 - Memory that can be dirtied (should NOT have to be set in the benchmark fuzzer)
    // R10 - Number of pages to dirty (at least 1)
    // RCX - Number of instructions to execute (not including dirtying pages)
    unsafe {
        std::arch::asm!(
            r#"
            4:
            mov byte ptr [r9], 0x41
            add r9, 0x1000
            dec r10
            jnz 4b

            2:
            dec rcx
            jnz 2b
        "#,
            in("r9") scratch,
            options(nostack)
        );
    }

    // Call the function to reset the guest
    reset_guest();
}
