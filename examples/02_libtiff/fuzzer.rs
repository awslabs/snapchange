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
pub struct Example02Fuzzer {
    // Fuzzer specific data could go in here
}

impl Fuzzer for Example02Fuzzer {
    type Input = Vec<u8>;
    const START_ADDRESS: u64 = REPLACEMERIP;
    const MAX_INPUT_LENGTH: usize = 0x10000;

    fn set_input(&mut self, input: &Self::Input, fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        // Write the mutated input
        fuzzvm.write_bytes_dirty(VirtAddr(REPLACEMEBUFF), CR3, &input)?;

        // Set the size of the input
        fuzzvm.write::<u32>(VirtAddr(REPLACEMESIZE), CR3, input.len() as u32)?;

        Ok(())
    }

    fn reset_breakpoints(&self) -> Option<&[AddressLookup]> {
        Some(&[
            // Resolve reset breakpoints by address
            // AddressLookup::Virtual(VirtAddr(0x401371), CR3),

            // .. or by symbol lookup
            // AddressLookup::SymbolOffset("main", 0x1234)
        ])
    }

    fn crash_breakpoints(&self) -> Option<&[AddressLookup]> {
        Some(&[
            // Resolve crash breakpoints by address
            // AddressLookup::Virtual((VirtAddr(0x401371), CR3),

            // .. or by symbol lookup
            // AddressLookup::SymbolOffset("KillSystem", 0x1234)
        ])
    }

    fn breakpoints(&self) -> Option<&[Breakpoint<Self>]> {
        Some(&[
            Breakpoint {
                lookup: AddressLookup::SymbolOffset("tiffinfo!TIFFErrorExt", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, _fuzzer| {
                    fuzzvm.fake_immediate_return()?;
                    Ok(Execution::Continue)
                },
            },
            Breakpoint {
                lookup: AddressLookup::SymbolOffset("tiffinfo!TIFFWarningExt", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, _fuzzer| {
                    fuzzvm.fake_immediate_return()?;
                    Ok(Execution::Continue)
                },
            },
            Breakpoint {
                lookup: AddressLookup::SymbolOffset("tiffinfo!_tiffReadProc", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, _fuzzer| {
                    let fd = fuzzvm.rdi();
                    let buf = fuzzvm.rsi();
                    let size = fuzzvm.rdx() as usize;

                    if input.len() < size {
                        return Ok(Execution::Reset);
                    }

                    fuzzvm
                        .write_bytes_dirty(VirtAddr(buf), fuzzvm.cr3(), &input[..size])
                        .unwrap();

                    fuzzvm.set_rax(size as u64);

                    fuzzvm.fake_immediate_return().unwrap();

                    Ok(Execution::Continue)
                },
            },
        ])
    }
}
