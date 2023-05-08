//! Fuzzer template

#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]

use anyhow::Result;

use snapchange::addrs::{Cr3, VirtAddr};
use snapchange::fuzzer::{Breakpoint, BreakpointLookup, BreakpointType, Fuzzer};
use snapchange::fuzzvm::FuzzVm;
use snapchange::Execution;

REPLACEMECOMMENTS

const CR3: Cr3 = Cr3(REPLACEMECR3);

#[derive(Default)]
pub struct Example1Fuzzer {
    // Fuzzer specific data could go in here
}

impl Fuzzer for Example1Fuzzer {
    type Input = Vec<u8>;
    const START_ADDRESS: u64 = REPLACEMERIP;
    const MAX_INPUT_LENGTH: usize = 16;
    const MAX_MUTATIONS: u64 = 2;

    fn set_input(&mut self, input: &Self::Input, fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        // Write the mutated input
        fuzzvm.write_bytes_dirty(VirtAddr(REPLACEMEDATABUFFER), CR3, &input)?;

        Ok(())
    }

    fn breakpoints(&self) -> Option<&[Breakpoint<Self>]> {
        Some(&[
            // ITERATION 650 0x00007ffff7e94da0 0x084be000 | libc.so.6!__GI___getpid+0x0
            //     mov eax, 0x27
            Breakpoint {
                lookup: BreakpointLookup::SymbolOffset("libc.so.6!__GI___getpid", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, _input, _fuzzer| {
                    // Set the return value to 0xdeadbeef
                    fuzzvm.set_rax(0xdead_beef);

                    // Fake an immediate return from the function by setting RIP to the
                    // value popped from the stack (this assumes the function was entered
                    // via a `call`)
                    fuzzvm.fake_immediate_return()?;

                    // Continue execution
                    Ok(Execution::Continue)
                },
            },
        ])
    }
}
