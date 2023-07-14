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
pub struct TemplateFuzzer {
    // Fuzzer specific data could go in here
}

impl Fuzzer for TemplateFuzzer {
    type Input = Vec<u8>;
    const START_ADDRESS: u64 = REPLACEMERIP;
    const MAX_INPUT_LENGTH: usize = 1024;
    const MAX_MUTATIONS: u64 = 16;

    fn set_input(&mut self, input: &Self::Input, fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        // Write the mutated input
        // fuzzvm.write_bytes_dirty(VirtAddr(0x402004), CR3, &input)?;

        Ok(())
    }

    fn reset_breakpoints(&self) -> Option<&[BreakpointLookup]> {
        Some(&[
            // Resolve reset breakpoints by address
            // BreakpointLookup::Address(VirtAddr(0x401371), CR3),

            // .. or by symbol lookup
            // BreakpointLookup::SymbolOffset("main", 0x1234)
        ])
    }

    fn crash_breakpoints(&self) -> Option<&[BreakpointLookup]> {
        Some(&[
            // Resolve crash breakpoints by address
            // BreakpointLookup::Address((VirtAddr(0x401371), CR3),

            // .. or by symbol lookup
            // BreakpointLookup::SymbolOffset("KillSystem", 0x1234)
        ])
    }

    fn breakpoints(&self) -> Option<&[Breakpoint<Self>]> {
        Some(&[
            /*
            Breakpoint {
                lookup: BreakpointLookup::SymbolOffset("harness!symbol", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, _input, _fuzzer| {
                    fuzzvm.set_rax(1);
                    Ok(Execution::Continue)
                },
            },
            */

            /*
            Breakpoint {
               lookup:   BreakpointLookup::SymbolOffset("libc.so.6!__GI___getpid", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm, _input, _fuzzer| {
                    // Set the return value to 0xdeadbeef
                    fuzzvm.set_rax(0xdead_beef);

                    // Fake an immediate return from the function by setting RIP to the
                    // value popped from the stack (this assumes the function was entered
                    // via a `call`)
                    fuzzvm.fake_immediate_return()?;

                    // Continue execution
                    Ok(Execution::Continue)
                }
            },
            */

            /*
            Breakpoint {
               lookup:   BreakpointLookup::Address(VirtAddr(0xffffffffa6a8fa19), CR3),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm, _input, _fuzzer| {
                    // mov r12d, dword ptr [rax+0x60]
                    // 0xc1 is currently at [rax + 0x60]. Overwrite this value with
                    // 0xdeadbeef

                    // Get the current `rax` value
                    let rax = fuzzvm.rax();
                    let val: u32 = 0xdeadbeef;

                    // Write the wanted 0xdeadbeef in the memory location read in the
                    // kernel
                    fuzzvm.write_bytes_dirty(VirtAddr(rax + 0x60), CR3,
                        &val.to_le_bytes())?;

                    // Continue execution
                    Ok(Execution::Continue)
                }
            },
            */
        ])
    }

    /*
    fn redqueen_breakpoints(&self) -> Option<&[Breakpoint<Self>]> {
        redqueen_breakpoints::<Self>()
    }

    fn redqueen_breakpoint_addresses() -> &'static [u64] {
        redqueen_breakpoint_addresses()
    }
    */
}
