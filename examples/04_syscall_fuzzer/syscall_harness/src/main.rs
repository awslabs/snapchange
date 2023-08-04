const SCRATCH_SIZE: usize = 10 * 1024 * 1024;
const SHELLCODE_SIZE: usize = 1 * 1024 * 1024;

fn main() {
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

    // Clear the data in the scratch memory
    let data = [0x0; SCRATCH_SIZE];

    unsafe {
        std::ptr::copy(data.as_ptr(), scratch as *mut u8, SCRATCH_SIZE);
    }

    let shellcode = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            SHELLCODE_SIZE,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    } as usize;

    // Always return from the shellcode
    let data = [0xc3; SHELLCODE_SIZE];

    unsafe {
        std::ptr::copy(data.as_ptr(), shellcode as *mut u8, SHELLCODE_SIZE);
    }

    println!(
        "SNAPSHOT: Scratch memory: {:#x} Length: {SCRATCH_SIZE:#x}",
        scratch
    );
    println!(
        "SNAPSHOT: Shellcode: {:#x} Length: {SHELLCODE_SIZE:#x}",
        shellcode
    );

    unsafe {
        // Use the qemu_snapshot trigger
        std::arch::asm!("int 0x3 ; vmcall");

        // Call the shellcode
        let func: extern "C" fn() = std::mem::transmute(shellcode);
        func();
    };
}
