//! Fuzzer template

#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]

use crate::constants;
use snapchange::prelude::*;
use snapchange::InputWithMetadata;

const CR3: Cr3 = Cr3(constants::CR3);

// src/fuzzer.rs

#[derive(Default)]
pub struct Example05Fuzzer;

impl Fuzzer for Example05Fuzzer {
    type Input = Vec<u8>; // [0]
    const START_ADDRESS: u64 = constants::RIP;
    const MAX_INPUT_LENGTH: usize = 0x400; // [1]
    const MIN_INPUT_LENGTH: usize = 0x3f0; // [1]
    const MAX_MUTATIONS: u64 = 3;

    fn set_input(
        &mut self,
        input: &InputWithMetadata<Self::Input>,
        fuzzvm: &mut FuzzVm<Self>,
    ) -> Result<()> {
        // Write the mutated input
        fuzzvm.write_bytes_dirty(VirtAddr(constants::INPUT), CR3, &input)?; // [2]

        Ok(())
    }
}
