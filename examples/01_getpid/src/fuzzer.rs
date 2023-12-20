//! Fuzzer template

#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]

use anyhow::Result;

use snapchange::addrs::{Cr3, VirtAddr};
use snapchange::fuzzer::{AddressLookup, Breakpoint, BreakpointType, Fuzzer};
use snapchange::fuzzvm::FuzzVm;
use snapchange::Execution;
use snapchange::InputWithMetadata;

use crate::constants;

const CR3: Cr3 = Cr3(constants::CR3);

#[derive(Default)]
pub struct Example1Fuzzer {
    // Fuzzer specific data could go in here
}

impl Fuzzer for Example1Fuzzer {
    type Input = Vec<u8>;
    const START_ADDRESS: u64 = constants::RIP;
    const MAX_INPUT_LENGTH: usize = 16;
    const MAX_MUTATIONS: u64 = 1;

    fn set_input(
        &mut self,
        input: &InputWithMetadata<Self::Input>,
        fuzzvm: &mut FuzzVm<Self>,
    ) -> Result<()> {
        // Write the mutated input
        fuzzvm.write_bytes_dirty(VirtAddr(constants::INPUT), CR3, &input)?;

        Ok(())
    }

    fn breakpoints(&self) -> Option<&[Breakpoint<Self>]> {
        Some(&[Breakpoint {
            lookup: AddressLookup::SymbolOffset("ld-musl-x86_64.so.1!getpid", 0x0),
            bp_type: BreakpointType::Repeated,
            bp_hook: |fuzzvm: &mut FuzzVm<Self>, _input, _fuzzer, _feedback| {
                // Set the return value to 0xdeadbeef
                fuzzvm.set_rax(0xdead_beef);

                // Fake an immediate return from the function by setting RIP to the
                // value popped from the stack (this assumes the function was entered
                // via a `call`)
                fuzzvm.fake_immediate_return()?;

                // Continue execution
                Ok(Execution::Continue)
            },
        }])
    }
}
