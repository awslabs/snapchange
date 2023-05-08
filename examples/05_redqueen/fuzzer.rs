//! Fuzzer template

#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]

use anyhow::Result;

use snapchange::addrs::{Cr3, VirtAddr};
use snapchange::fuzzer::{Breakpoint, BreakpointLookup, BreakpointType, Fuzzer};
use snapchange::fuzzvm::FuzzVm;
use snapchange::{Execution, FuzzInput};

REPLACEMECOMMENTS

const CR3: Cr3 = Cr3(REPLACEMECR3);

// src/fuzzer.rs

#[derive(Default)]
pub struct Example05Fuzzer;

impl Fuzzer for Example05Fuzzer {
    type Input = Vec<u8>; // [0]
    const START_ADDRESS: u64 = REPLACEMERIP;
    const MAX_INPUT_LENGTH: usize = 0x400; // [1]

    fn set_input(&mut self, input: &Self::Input, fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        // Write the mutated input
        fuzzvm.write_bytes_dirty(VirtAddr(REPLACEMEBUFFER), CR3, input)?; // [2]

        Ok(())
    }

    fn breakpoints(&self) -> Option<&[Breakpoint<Self>]> {
        Some(&[
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

    fn redqueen_breakpoints(&self) -> Option<&[Breakpoint<Self>]> {
        crate::redqueen::redqueen_breakpoints::<Self>()
    }

    fn redqueen_breakpoint_addresses() -> &'static [u64] {
        crate::redqueen::redqueen_breakpoint_addresses()
    }
}
