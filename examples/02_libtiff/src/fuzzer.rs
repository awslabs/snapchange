//! Fuzzer template

#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]

use anyhow::Result;

use snapchange::addrs::{Cr3, VirtAddr};
use snapchange::fuzz_input::InputWithMetadata;
use snapchange::fuzzer::{AddressLookup, Breakpoint, BreakpointType, Fuzzer};
use snapchange::fuzzvm::FuzzVm;
use snapchange::Execution;

use crate::constants;

const CR3: Cr3 = Cr3(constants::CR3);

#[derive(Default)]
pub struct Example02Fuzzer {
    // Fuzzer specific data could go in here
}

impl Fuzzer for Example02Fuzzer {
    type Input = Vec<u8>;
    const START_ADDRESS: u64 = constants::RIP;
    const MAX_INPUT_LENGTH: usize = 0x10000;

    fn init_snapshot(&mut self, fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        for symbol in ["tiffinfo!TIFFErrorExt", "tiffinfo!TIFFWarningExt"] {
            // Get the virtual address for each of these symbols
            if let Some((virt_addr, cr3)) = fuzzvm.get_symbol_address(symbol) {
                // Patch the first instruction of each symbol to immediately return
                //
                // This is slightly better than a breakpoint since we don't have to
                // exit the guest which is a bit more costly.
                let addr = AddressLookup::Virtual(virt_addr, cr3);
                fuzzvm.patch_bytes_permanent(addr, &[0xc3]);
            }
        }

        Ok(())
    }

    fn crash_breakpoints(&self) -> Option<&[AddressLookup]> {
        Some(&[
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asanL12ReportGlobalERK13__asan_globalPKc", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asan18ReportDeadlySignalERKN11__sanitizer13SignalContextE", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asan19ScopedInErrorReportD2Ev", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asan16ReportDoubleFreeEmPN11__sanitizer18BufferedStackTraceE", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asan27ReportNewDeleteTypeMismatchEmmmPN11__sanitizer18BufferedStackTraceE", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asan21ReportFreeNotMallocedEmPN11__sanitizer18BufferedStackTraceE", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asan23ReportAllocTypeMismatchEmPN11__sanitizer18BufferedStackTraceENS_9AllocTypeES3_", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asan30ReportMallocUsableSizeNotOwnedEmPN11__sanitizer18BufferedStackTraceE", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asan39ReportSanitizerGetAllocatedSizeNotOwnedEmPN11__sanitizer18BufferedStackTraceE", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asan20ReportCallocOverflowEmmPN11__sanitizer18BufferedStackTraceE", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asan26ReportReallocArrayOverflowEmmPN11__sanitizer18BufferedStackTraceE", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asan21ReportPvallocOverflowEmPN11__sanitizer18BufferedStackTraceE", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asan32ReportInvalidAllocationAlignmentEmPN11__sanitizer18BufferedStackTraceE", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asan34ReportInvalidAlignedAllocAlignmentEmmPN11__sanitizer18BufferedStackTraceE", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asan35ReportInvalidPosixMemalignAlignmentEmPN11__sanitizer18BufferedStackTraceE", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asan26ReportAllocationSizeTooBigEmmmPN11__sanitizer18BufferedStackTraceE", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asan22ReportRssLimitExceededEPN11__sanitizer18BufferedStackTraceE", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asan17ReportOutOfMemoryEmPN11__sanitizer18BufferedStackTraceE", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asan39ReportStringFunctionMemoryRangesOverlapEPKcS1_mS1_mPN11__sanitizer18BufferedStackTraceE", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asan32ReportStringFunctionSizeOverflowEmmPN11__sanitizer18BufferedStackTraceE", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asan18ReportODRViolationEPK13__asan_globaljS2_j", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asan25ReportMacMzReallocUnknownEmmPKcPN11__sanitizer18BufferedStackTraceE", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asan18ReportGenericErrorEmmmmbmjb", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asanL24ReportInvalidPointerPairEmmmmm", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asanL25ReportGenericErrorWrapperEmbiib", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asanL22MaybeReportLinuxPIEBugEv", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asan19ScopedInErrorReport14current_error_E", 0x0),

            AddressLookup::SymbolOffset("tiffinfo!__asan_report_load1_asm", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_load2_asm", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_load4_asm", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_load8_asm", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_load16_asm", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_store1_asm", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_store2_asm", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_store4_asm", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_store8_asm", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_store16_asm", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_error", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_present", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_get_report_pc", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_get_report_bp", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_get_report_sp", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_get_report_address", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_get_report_access_type", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_get_report_access_size", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_get_report_description", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_load1", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_exp_load1", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_load1_noabort", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_load2", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_exp_load2", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_load2_noabort", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_load4", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_exp_load4", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_load4_noabort", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_load8", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_exp_load8", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_load8_noabort", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_load16", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_exp_load16", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_load16_noabort", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_store1", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_exp_store1", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_store1_noabort", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_store2", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_exp_store2", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_store2_noabort", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_store4", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_exp_store4", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_store4_noabort", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_store8", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_exp_store8", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_store8_noabort", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_store16", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_exp_store16", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_store16_noabort", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_load_n", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_exp_load_n", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_load_n_noabort", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_store_n", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_exp_store_n", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!__asan_report_store_n_noabort", 0x0),
            AddressLookup::SymbolOffset("tiffinfo!_ZN6__asanL21error_report_callbackE", 0x0),
        ])
    }

    fn set_input(
        &mut self,
        input: &InputWithMetadata<Self::Input>,
        fuzzvm: &mut FuzzVm<Self>,
    ) -> Result<()> {
        // Write the mutated input
        fuzzvm.write_bytes_dirty(VirtAddr(constants::INPUT), CR3, &input)?;

        // Set the size of the input
        fuzzvm.write::<u32>(VirtAddr(constants::INPUT_ADDR), CR3, input.len() as u32)?;

        Ok(())
    }

    fn breakpoints(&self) -> Option<&[Breakpoint<Self>]> {
        Some(&[Breakpoint {
            lookup: AddressLookup::SymbolOffset("tiffinfo!_tiffReadProc", 0x0),
            bp_type: BreakpointType::Repeated,
            bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, _fuzzer, _feedback| {
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
        }])
    }
}
