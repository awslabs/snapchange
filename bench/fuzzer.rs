//! Fuzzer template

#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]

use anyhow::Result;

use snapchange::addrs::{Cr3, VirtAddr};
use snapchange::fuzzer::{Breakpoint, AddressLookup, BreakpointType, Fuzzer};
use snapchange::fuzzvm::FuzzVm;
use snapchange::Execution;

REPLACEMECOMMENTS

const CR3: Cr3 = Cr3(REPLACEMECR3);

#[derive(Default)]
pub struct BenchFuzzer  {
    // Fuzzer specific data could go in here
}

impl Fuzzer for BenchFuzzer {
    type Input = Vec<u8>;
    const START_ADDRESS: u64 = REPLACEMERIP;
    const MAX_INPUT_LENGTH: usize = 16;
    const MAX_MUTATIONS: u64 = 2;

    // R9 - Memory that can be dirtied (should NOT have to be set in the benchmark fuzzer)
    // R10 - Number of pages to dirty (at least 1)
    // RCX - Number of instructions to execute (not including dirtying pages)
    fn set_input(&mut self, input: &Self::Input, fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        let num_instrs = std::env::var("INSTRS")
            .expect("INSTRS not set")
            .parse::<u64>()?;
        let dirty_pages = std::env::var("PAGES")
            .expect("PAGES not set")
            .parse::<u64>()?;

        fuzzvm.set_r9(REPLACEMESCRATCH);
        fuzzvm.set_r10(dirty_pages);
        fuzzvm.set_rcx(num_instrs);

        Ok(())
    }

    fn reset_breakpoints(&self) -> Option<&[AddressLookup]> {
        Some(&[
            AddressLookup::Virtual(VirtAddr(REPLACEMERESET), CR3)
        ])
    }

    fn breakpoints(&self) -> Option<&[Breakpoint<Self>]> {
        if std::env::var("VMEXITS").unwrap_or("0".to_string()).parse::<u8>().unwrap() > 0 {
            Some(&[
                 Breakpoint {
                     lookup: AddressLookup::Virtual(VirtAddr(0x000055555555ca7a), CR3),
                     bp_type: BreakpointType::Repeated,
                     bp_hook: |fuzzvm: &mut FuzzVm<Self>, _input, _fuzzer| Ok(Execution::Continue)
                 }
            ])
        } else {
            None
        }
    }

}
