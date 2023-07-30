//! Fuzzer template

#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]

use anyhow::Result;

use snapchange::fuzzer::Fuzzer;
use snapchange::fuzzvm::FuzzVm;

use crate::constants;

#[derive(Default)]
pub struct Example1Fuzzer {}

impl Fuzzer for Example1Fuzzer {
    type Input = Vec<u8>;
    const START_ADDRESS: u64 = constants::RIP;
    const MAX_INPUT_LENGTH: usize = 1024;

    fn set_input(&mut self, input: &Self::Input, fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        snapchange::utils::libfuzzer::set_input(&input[..], fuzzvm)
    }

    fn init_vm(&mut self, fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        snapchange::utils::libfuzzer::init_vm(fuzzvm)
    }
}
