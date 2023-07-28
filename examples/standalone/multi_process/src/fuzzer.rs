//! Fuzzer template

#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]

use anyhow::Result;

use snapchange::addrs::{Cr3, VirtAddr};
use snapchange::fuzzer::Fuzzer;
use snapchange::fuzzvm::FuzzVm;
use snapchange::Execution;

use crate::constants;

const CR3: Cr3 = Cr3(constants::CR3);

#[derive(Default)]
pub struct Example1Fuzzer {
    // Fuzzer specific data could go in here
}

impl Fuzzer for Example1Fuzzer {
    type Input = Vec<u8>;
    const START_ADDRESS: u64 = constants::RIP;
    // const INPUT_ADDRESS: u64 = constants::INPUT;
    const MAX_INPUT_LENGTH: usize = 16;
    const MAX_MUTATIONS: u64 = 2;

    fn set_input(&mut self, input: &Self::Input, fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        // Write the mutated input
        fuzzvm.write_bytes_dirty(VirtAddr(constants::INPUT), CR3, &input)?;

        Ok(())
    }
}
