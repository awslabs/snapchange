# Function lifecycle

Below is the general callgraph of the fuzzing lifecycle. This is to show where in the
lifecycle a fuzzer is called.

_Note: Any `fuzzer.*` function is a function in the [`Fuzzer`] trait that a fuzzer can 
modify_

```rust
let mut input;

// Initialize a first input by mutating one of the input files in the corpus
fuzzer.mutate_input(&mut input);

// Provide the mutated input to the fuzzer to set into the guest VM
fuzzer.set_input(&input);

// Reset the fuzzer state
fuzzer.reset_fuzzer_state();

loop { 
    // Run the guest VM until a reset state
    loop {
        // Allow the guest to run until some VmExit occurs
        let ret = fuzzvm.run();

        // Handle the VmExit from running the guest VM
        let execution = handle_vmexit(ret);

        if execution is a reset state {
            break;
        }
    }

    if execution is a crashing state {
        fuzzer.handle_crash(&input);
    }

    if input generated new coverage {
        corpus.push(input);
    }
   
    // Reset the fuzzer state
    fuzzer.reset_fuzzer_state();

    // Initialize a next input by mutating one of the input files in the corpus
    fuzzer.mutate_input(&mut input);

    // Provide the mutated input to the fuzzer to set into the guest VM
    fuzzer.set_input(&input);
}
```
