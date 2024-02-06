//! Fuzzer template

#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]

use crate::constants;
use snapchange::{input_types::TextInput, prelude::*};

const CR3: Cr3 = Cr3(constants::CR3);

#[derive(Default, Clone, Debug)]
pub struct JSTextFuzzer {}

impl Fuzzer for JSTextFuzzer {
    type Input = TextInput;
    const START_ADDRESS: u64 = constants::RIP;
    const MAX_INPUT_LENGTH: usize = 0x4000;
    const MAX_MUTATIONS: u64 = 16;

    fn set_input(
        &mut self,
        input: &InputWithMetadata<Self::Input>,
        fuzzvm: &mut FuzzVm<Self>,
    ) -> Result<()> {
        // truncate to the maximum input length.
        let ilen = std::cmp::min(input.data().len(), Self::MAX_INPUT_LENGTH - 1);
        let data = &input.data()[..ilen];
        fuzzvm.write_bytes_dirty(VirtAddr(constants::INPUT), CR3, data)?;
        // and we make sure that we have a zero terminator.
        fuzzvm.write_dirty(VirtAddr(constants::INPUT + ilen as u64), CR3, 0u8)?;
        Ok(())
    }

    fn init_snapshot(&mut self, fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        // disable printing code by placing immediate returns at the relevant functions.
        // this is faster than using breakpoints, since it doesn't require a hypercall.
        for sym in &[
            "ld-musl-x86_64.so.1!puts",
            "ld-musl-x86_64.so.1!fputs",
            "ld-musl-x86_64.so.1!fprintf",
            "ld-musl-x86_64.so.1!printf",
            "ld-musl-x86_64.so.1!putchar",
        ] {
            if fuzzvm
                .patch_bytes_permanent(AddressLookup::SymbolOffset(sym, 0), &[0xc3])
                .is_ok()
            {
                log::warn!("inserting immediate ret at sym {}", sym);
            } else {
                log::warn!("fail to set ret at sym {}", sym);
            }
        }

        Ok(())
    }
}
