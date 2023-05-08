# Brief roadmap of the source files

Below is a brief roadmap of the source code and where to potentially start reading:

* `src/commands/[fuzz|minimize|trace|coverage|project].rs` - Contains the logic for each command
    - Each command follows roughly the same logic:

    ```
    Initialize a KVM environment
    Create a `FuzzVm` which executes and maintains the state of the Guest VM

    Prepare the Guest VM by mutating input or modifying state
    loop {
        Run the Guest VM (fuzzvm.run())
        Handle the exit condition of the VM (handle_vmexit)
        Save metadata
    }
    ```

* `src/fuzzvm.rs` - Provides `FuzzVm` to handle the main state of the Guest.
    - This struct is how a researcher can read/write state into the guest
    - Examples:
        - fuzzvm.read_bytes()
        - fuzzvm.read::<u32>()
        - fuzzvm.read::<[u8; 128]>()
        - fuzzvm.write_bytes()
        - fuzzvm.write::<u32>()
        - fuzzvm.write::<[u8; 128]>()
        - fuzzvm.rip() | fuzzvm.set_rip()
        - fuzzvm.rax() | fuzzvm.set_rax()
        - fuzzvm.hexdump()
        - fuzzvm.translate()
        - fuzzvm.print_context()

* `src/fuzzer.rs` - Provides the `Fuzzer` trait that each target specific fuzzer will implement
* `src/stats.rs` - Aggregates and displays the statistics from each core
