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
    const MAX_MUTATIONS: u64 = 5;

    fn init_snapshot(&mut self, fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        const REMOVE_BRANCHLESS: bool = false;
        const REMOVE_REGULAR: bool = true;

        if REMOVE_REGULAR {
            for sym in [
                // "test_cmpsolves!const_i16_compares",
                // "test_cmpsolves!const_u16_compares",
                // "test_cmpsolves!const_i32_compares",
                // "test_cmpsolves!const_u32_compares",
                // "test_cmpsolves!const_i64_compares",
                // "test_cmpsolves!const_u64_compares",
                // "test_cmpsolves!const_strmemcmp",
                // "test_cmpsolves!const_f32_compares",
                // "test_cmpsolves!const_f64_compares",
                // "test_cmpsolves!const_long_double_compares",
                // "test_cmpsolves!u32_compare_within",
                // "test_cmpsolves!check_memcmp_within",
                // "test_cmpsolves!check_dynamic_compares",
                "test_cmpsolves!arithmetic_adjustments",
                // "test_cmpsolves!check_the_parity_byte",
                // "test_cmpsolves!check_the_sum",
            ] {
                // Move the data buffer to the return value and return
                // mov rax, rdi ; ret
                fuzzvm.patch_bytes_permanent(
                    AddressLookup::SymbolOffset(sym, 0x0),
                    &[0x48, 0x89, 0xf8, 0xc3],
                )?;
            }
        }

        if REMOVE_BRANCHLESS {
            for sym in [
                "test_cmpsolves!check_dynamic_branchless_compares",
                "test_cmpsolves!const_u64_compares_constanttime",
            ] {
                // Move the data buffer to the return value and return
                // mov rax, rdi ; ret
                fuzzvm.patch_bytes_permanent(
                    AddressLookup::SymbolOffset(sym, 0x0),
                    &[0x48, 0x89, 0xf8, 0xc3],
                )?;
            }
        }

        Ok(())
    }

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
