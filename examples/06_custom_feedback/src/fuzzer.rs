//! Fuzzer template

#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]

use anyhow::Result;
use rand::Rng as _;

use snapchange::addrs::{Cr3, VirtAddr};
use snapchange::fuzzer::{AddressLookup, Breakpoint, BreakpointType, Fuzzer};
use snapchange::fuzzvm::FuzzVm;
use snapchange::rng::Rng;
use snapchange::Execution;

use crate::constants;

const CR3: Cr3 = Cr3(constants::CR3);

#[derive(Default)]
pub struct MazeFuzzer {
    weights: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Wasd {
    W = 119,
    A = 97,
    S = 115,
    D = 100,
    X = 120,
    Y = 121,
    Stop = 0,
}

impl TryFrom<u8> for Wasd {
    type Error = anyhow::Error;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            b'w' | b'W' => Ok(Wasd::W),
            b'a' | b'A' => Ok(Wasd::A),
            b's' | b'S' => Ok(Wasd::S),
            b'd' | b'D' => Ok(Wasd::D),
            b'x' | b'X' => Ok(Wasd::X),
            b'y' | b'Y' => Ok(Wasd::Y),
            0 => Ok(Wasd::Stop),
            _ => Err(anyhow::anyhow!("Invalid WASD")),
        }
    }
}

impl rand::distributions::Distribution<Wasd> for rand::distributions::Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Wasd {
        match rng.gen_range(0..=9) {
            0 | 1 => Wasd::W,
            2 | 3 => Wasd::A,
            4 | 5 => Wasd::S,
            6 | 7 => Wasd::D,
            8 => Wasd::X,
            9 => Wasd::Y,
            _ => unreachable!("Distribution::sample invalid integer sampled"),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct WasdArray {
    data: Vec<Wasd>,
}

impl std::default::Default for WasdArray {
    fn default() -> Self {
        Self {
            data: vec![Wasd::Stop],
        }
    }
}

impl Fuzzer for MazeFuzzer {
    type Input = WasdArray;
    const START_ADDRESS: u64 = constants::RIP;
    const MAX_INPUT_LENGTH: usize = 1024;
    const MAX_MUTATIONS: u64 = 4;

    fn set_input(&mut self, input: &Self::Input, fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        let i = input.data.len().min(Self::MAX_INPUT_LENGTH - 1);
        let raw_input = unsafe { std::mem::transmute::<&[Wasd], &[u8]>(&input.data[..i]) };
        fuzzvm.write_bytes_dirty(VirtAddr(constants::INPUT), CR3, &raw_input)?;
        fuzzvm.write_dirty(VirtAddr(constants::INPUT + i as u64), CR3, 0u64)?;
        Ok(())
    }

    fn init_snapshot(&mut self, fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        for sym in &[
            "ld-musl-x86_64.so.1!puts",
            "ld-musl-x86_64.so.1!fputs",
            "ld-musl-x86_64.so.1!fprintf",
            "ld-musl-x86_64.so.1!printf",
            "maze.small!draw",
            "maze.small.nobt!draw",
            "maze.big!draw",
            "maze.big.nobt!draw",
        ] {
            if fuzzvm
                .patch_bytes_permanent(AddressLookup::SymbolOffset(sym, 0), &[0xc3])
                .is_ok()
            {
                log::warn!("inserting immediate ret at sym {}", sym);
            } else {
                log::warn!(" ret at sym {}", sym);
            }
        }
        Ok(())
    }

    fn reset_breakpoints(&self) -> Option<&[AddressLookup]> {
        Some(&[
            AddressLookup::SymbolOffset(constants::TARGET_BYE, 0x0),
            // AddressLookup::SymbolOffset("exit", 0x0)
        ])
    }

    fn breakpoints(&self) -> Option<&[Breakpoint<Self>]> {
        if cfg!(feature = "enable_feedback") {
            Some(&[
                // this breakpoint gathers the last (x, y) position in the maze. this is good enough
                // for the fuzzer to achieve it's goal of reaching the end of the maze.
                Breakpoint {
                    lookup: AddressLookup::SymbolOffset(constants::TARGET_LOOSE, 0x0),
                    bp_type: BreakpointType::Repeated,
                    bp_hook: |fuzzvm: &mut FuzzVm<Self>, _input, _fuzzer, feedback| {
                        if let Some(feedback) = feedback {
                            let x = fuzzvm.rsi() & 0xffff;
                            let y = fuzzvm.rdx() & 0xffff;
                            let pos = x | (y << 16);
                            if feedback.record(pos) {
                                log::info!("found new position: {:?}", (x, y));
                            }
                        }
                        fuzzvm.fake_immediate_return()?;
                        Ok(Execution::Reset)
                    },
                },
                // this breakpoint gathers the every (x, y) position in the maze that is reached
                // during the maze walk. If a newly encountered position is reached, the feedback
                // notices and saves the input.
                // However, with this breakpoint the execution speed will be dominated by coverage
                // breakpont handling. When backtracking in not allowed in the maze, it does not
                // matter, whether this is enabled or not, so it is better to disable it. With
                // backtracking we can identify inputs that reach any new positions, which can be
                // benefitial. In our experience, it is not for the mazes that we have here.
                #[cfg(feature = "feedback_on_every_pos")]
                Breakpoint {
                    lookup: AddressLookup::SymbolOffset(constants::TARGET_LOG_POS, 0x0),
                    bp_type: BreakpointType::Repeated,
                    bp_hook: |fuzzvm: &mut FuzzVm<Self>, _input, _fuzzer, feedback| {
                        if let Some(feedback) = feedback {
                            let x = fuzzvm.rdi() & 0xffff;
                            let y = fuzzvm.rsi() & 0xffff;
                            let pos = x | (y << 16);
                            if feedback.record(pos) {
                                log::info!("found new position: {:?}", (x, y));
                            }
                        }
                        fuzzvm.fake_immediate_return()?;
                        Ok(Execution::CoverageContinue)
                    },
                },
                // This breakpoint showcases custom feedback to minimize a string distance between
                // two memory values. We do not want to reverse the obfuscation of the secret code,
                // so we let the fuzzer discover the correct inputs by minimizing the distance
                // between the stored
                Breakpoint {
                    lookup: AddressLookup::SymbolOffset(constants::TARGET_EQ16, 0x0),
                    bp_type: BreakpointType::Repeated,
                    bp_hook: |fuzzvm: &mut FuzzVm<Self>, _input, _fuzzer, feedback| {
                        if let Some(feedback) = feedback {
                            let ptr_a = fuzzvm.rdi();
                            let ptr_b = fuzzvm.rsi();
                            let mut a = [0u8; 16];
                            fuzzvm.read_bytes(VirtAddr(ptr_a), fuzzvm.cr3(), &mut a)?;
                            let mut b = [0u8; 16];
                            fuzzvm.read_bytes(VirtAddr(ptr_b), fuzzvm.cr3(), &mut b)?;
                            if let Some(new_len) = feedback.record_min_prefix_dist(0u64, &a, &b) {
                                log::info!(
                                    "found new minimal code with len {}: {:?} vs. {:?}",
                                    new_len,
                                    a,
                                    b
                                );
                            }
                        }
                        Ok(Execution::Continue)
                    },
                },
            ])
        } else {
            None
        }
    }

    fn schedule_next_input(
        &mut self,
        corpus: &[Self::Input],
        feedback: &mut snapchange::feedback::FeedbackTracker,
        rng: &mut Rng,
        dictionary: &Option<Vec<Vec<u8>>>,
    ) -> Self::Input {
        // bring trait in scope
        use rand::distributions::Distribution;

        if corpus.len() == 0 {
            return <WasdArray as snapchange::FuzzInput>::generate(
                corpus,
                rng,
                dictionary,
                Self::MAX_INPUT_LENGTH,
            );
        }

        // this distribution makes it extremely likely that the last corpus entry is selected again
        // for fuzzing. This is usually the best strategy, since the last entry will be the one that
        // got the farthest in the maze.
        if self.weights.len() != corpus.len() {
            self.weights = (1u32..((corpus.len() + 1) as u32)).collect();
        }
        let dist = rand::distributions::WeightedIndex::new(&self.weights).unwrap();
        let idx = dist.sample(rng) as usize;
        if let Some(input) = corpus.get(idx) {
            input.clone()
        } else {
            // Default to generating a new input
            <WasdArray as snapchange::FuzzInput>::generate(
                corpus,
                rng,
                dictionary,
                Self::MAX_INPUT_LENGTH,
            )
        }
    }
}

impl<'a> WasdArray {
    fn copy_to_vec(&self, v: &mut Vec<u8>) {
        v.reserve(self.data.len());
        unsafe {
            v.extend_from_slice(std::mem::transmute::<&[Wasd], &[u8]>(&self.data[..]));
        }
    }
}

/// The mutator will randomly select one of these mutations when
#[derive(Debug, PartialEq, Copy, Clone)]
#[repr(u8)]
pub enum WasdFuzzOperation {
    Append,
    Replace,
    ReplaceLast,
    ReplaceLastMany,
    Remove,
    Insert,
    Splice,
}

impl rand::distributions::Distribution<WasdFuzzOperation> for rand::distributions::Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> WasdFuzzOperation {
        match rng.gen_range(0..=22) {
            0 | 1 | 2 | 3 => WasdFuzzOperation::Append,
            4 | 5 | 6 => WasdFuzzOperation::Replace,
            7 | 8 => WasdFuzzOperation::Remove,
            9 | 10 => WasdFuzzOperation::Insert,
            11 => WasdFuzzOperation::Splice,
            12 | 13 | 14 | 15 | 16 | 17 => WasdFuzzOperation::ReplaceLast,
            18 | 19 | 20 | 21 | 22 => WasdFuzzOperation::ReplaceLastMany,
            _ => unreachable!("Distribution::sample invalid integer sampled"),
        }
    }
}

impl snapchange::FuzzInput for WasdArray {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut v = Vec::with_capacity(bytes.len());
        for byte in bytes.iter().copied() {
            let wasd = Wasd::try_from(byte)?;
            v.push(wasd);
            if wasd == Wasd::Stop {
                break;
            }
        }
        Ok(WasdArray { data: v })
    }

    fn to_bytes(&self, output: &mut Vec<u8>) -> Result<()> {
        output.clear();
        self.copy_to_vec(output);
        Ok(())
    }

    fn generate(
        _corpus: &[Self],
        rng: &mut Rng,
        _dictionary: &Option<Vec<Vec<u8>>>,
        _max_length: usize,
    ) -> Self {
        // let len = rng.gen_range(1..=max_length);
        let len = 1;
        let mut data = vec![];
        for _ in 0..len {
            let d: Wasd = rng.gen();
            data.push(d);
        }
        WasdArray { data }
    }

    fn mutate(
        input: &mut Self,
        corpus: &[Self],
        rng: &mut Rng,
        _dictionary: &Option<Vec<Vec<u8>>>,
        max_length: usize,
        max_mutations: u64,
    ) -> Vec<String> {
        // Get the number of changes to make to the input
        let num_change: u64 = (rng.gen::<u64>() % max_mutations).max(1);

        // Mutations applied to this input
        let mut mutations: Vec<String> = Vec::new();

        let old_len = input.data.len();
        if input.data.len() > 0 {
            // Perform some number of mutations on the input
            for _ in 0..num_change {
                let op: WasdFuzzOperation = rng.gen();
                use WasdFuzzOperation::*;
                match op {
                    Append => {
                        let d: Wasd = rng.gen();
                        input.data.push(d);
                        mutations.push("Append".to_string());
                    }
                    Replace => {
                        let d: Wasd = rng.gen();
                        let i = rng.gen_range(0..input.data.len());
                        input.data[i] = d;
                        mutations.push("Replace".to_string());
                    }
                    ReplaceLast => {
                        let mut d: Wasd = rng.gen();
                        let last = *input.data.last().unwrap();
                        while last != d {
                            d = rng.gen();
                        }
                        *input.data.last_mut().unwrap() = d;
                        mutations.push("ReplaceLast".to_string());
                    }
                    ReplaceLastMany => {
                        let mut d: Wasd = rng.gen();
                        let last = *input.data.last().unwrap();
                        while last != d {
                            d = rng.gen();
                        }
                        *input.data.last_mut().unwrap() = d;
                        let count = rng.gen_range(0..10);
                        for _i in 0..count {
                            input.data.push(d);
                        }
                        mutations.push("ReplaceLastMany".to_string());
                    }
                    Remove => {
                        if input.data.len() > 2 {
                            let i = rng.gen_range(0..input.data.len());
                            input.data.remove(i);
                            mutations.push("Remove".to_string());
                        }
                    }
                    Insert => {
                        let d: Wasd = rng.gen();
                        let i = rng.gen_range(0..input.data.len());
                        input.data.insert(i, d);
                        mutations.push("Insert".to_string());
                    }
                    Splice => {
                        if !corpus.is_empty() {
                            let corpus_idx = rng.gen_range(0..corpus.len());
                            let other = &corpus[corpus_idx].data;
                            if !other.is_empty() {
                                let other_start = if other.len() == 1 {
                                    0
                                } else {
                                    rng.gen_range(0..(other.len() - 1))
                                };
                                let other_end = rng.gen_range(other_start..other.len());
                                if other_start != other_end {
                                    let splice_in = &other[other_start..other_end];

                                    let i = if input.data.len() == 1 {
                                        0
                                    } else {
                                        rng.gen_range(0..input.data.len() - 1)
                                    };
                                    let j = rng.gen_range(i..input.data.len());
                                    if i != j {
                                        // TODO: replace with two memcpy
                                        input.data = input
                                            .data
                                            .splice(i..j, splice_in.iter().copied())
                                            .collect();
                                        mutations.push("Splice".to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Ensure the input fits in the maximum length
            input.data.truncate(max_length);
        }

        if input.data.len() == old_len {
            let d: Wasd = rng.gen();
            input.data.push(d);
            mutations.push("Append".to_string());
        }

        // Return the mutation applied
        mutations
    }
}
