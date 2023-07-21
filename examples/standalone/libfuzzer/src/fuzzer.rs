//! Fuzzer template

#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]

use anyhow::Result;

use snapchange::addrs::VirtAddr;
use snapchange::fuzzer::Fuzzer;
use snapchange::fuzzvm::FuzzVm;

use crate::constants;

#[derive(Default)]
pub struct Example1Fuzzer {
    // Fuzzer specific data could go in here
}

impl Fuzzer for Example1Fuzzer {
    type Input = Vec<u8>;
    const START_ADDRESS: u64 = constants::RIP;
    const MAX_INPUT_LENGTH: usize = 1024;

    fn set_input(&mut self, input: &Self::Input, fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        // Restore RIP to before the `int3 ; vmcall` snapshot point
        fuzzvm.set_rip(fuzzvm.rip() - 4);

        // Set the data buffer to the current mutated input
        let buffer = fuzzvm.rdi();
        fuzzvm.write_bytes_dirty(VirtAddr(buffer), fuzzvm.cr3(), input)?;

        // Set the length of the input
        fuzzvm.set_rsi(input.len() as u64);

        Ok(())
    }
}
