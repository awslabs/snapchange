//! Fuzzer template

#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]

use anyhow::Result;
use rand::seq::SliceRandom;
use rand::Rng as _;

use snapchange::addrs::{Cr3, VirtAddr};
use snapchange::fuzzer::{AddressLookup, Breakpoint, BreakpointType, Fuzzer};
use snapchange::fuzzvm::FuzzVm;
use snapchange::rng::Rng;
use snapchange::{Execution, FuzzInput};

use crate::constants;

const CR3: Cr3 = Cr3(constants::CR3);

// src/fuzzer.rs

#[derive(Default)]
pub struct Example05Fuzzer;

impl Fuzzer for Example05Fuzzer {
    type Input = Vec<u8>; // [0]
    const START_ADDRESS: u64 = constants::RIP;
    const MAX_INPUT_LENGTH: usize = 0x400; // [1]

    fn set_input(&mut self, input: &Self::Input, fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        // Write the mutated input
        fuzzvm.write_bytes_dirty(VirtAddr(constants::INPUT), CR3, input)?; // [2]

        Ok(())
    }

    fn breakpoints(&self) -> Option<&[Breakpoint<Self>]> {
        Some(&[Breakpoint {
            lookup: AddressLookup::SymbolOffset("libc.so.6!__GI___getpid", 0x0),
            bp_type: BreakpointType::Repeated,
            bp_hook: |fuzzvm: &mut FuzzVm<Self>, _input, _fuzzer| {
                // Set the return value to 0xdeadbeef
                fuzzvm.set_rax(0xdead_beef);

                // Fake an immediate return from the function by setting RIP to the
                // value popped from the stack (this assumes the function was entered
                // via a `call`)
                fuzzvm.fake_immediate_return()?;

                // Continue execution
                Ok(Execution::Continue)
            },
        }])
    }

    fn schedule_next_input(
        &mut self,
        corpus: &[Self::Input],
        rng: &mut Rng,
        dictionary: &Option<Vec<Vec<u8>>>,
    ) -> Self::Input {
        /*
        // Favor the last input in the corpus since this is a progressive example
        if rng.gen_bool(0.8) {
            if let Some(last_input) = corpus.last().cloned() {
                return last_input;
            }
        }
        */

        // Small chance to make a new input
        if rng.next() % 0xffff == 42 {
            Self::Input::generate(corpus, rng, dictionary, Self::MAX_INPUT_LENGTH)
        } else {
            // Otherwise attempt to pick one from the corpus
            if let Some(input) = corpus.choose(rng) {
                input.clone()
            } else {
                // Default to generating a new input
                Self::Input::generate(corpus, rng, dictionary, Self::MAX_INPUT_LENGTH)
            }
        }
    }

    fn redqueen_breakpoints(&self) -> Option<&[Breakpoint<Self>]> {
        crate::redqueen::redqueen_breakpoints::<Self>()
    }

    fn redqueen_breakpoint_addresses() -> &'static [u64] {
        crate::redqueen::redqueen_breakpoint_addresses()
    }
}
