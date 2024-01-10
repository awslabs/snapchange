//! Fuzzer template

#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]

use snapchange::fuzz_input::MinimizerState;
use snapchange::prelude::*;
use std::sync::Arc;

use crate::constants;

const CR3: Cr3 = Cr3(constants::CR3);

/// Essentially a more restricted `u8`, that only allows the values that are allowed in the game
/// input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Wasd {
    W = b'w',
    A = b'a',
    S = b's',
    D = b'd',
    X = b'x',
    Y = b'y',
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
            0 | b'\n' | b' ' | b'\t' => Ok(Wasd::Stop),
            _ => Err(anyhow::anyhow!("Invalid WASD")),
        }
    }
}

// X | Y don't serve any immediate purpose in the first part of the maze game, so we make it less
// likely that they are generated.
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

/// Essentially a `Vec<u8>`, but it uses the more restricted [`Wasd`] enum.
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

#[derive(Clone, Copy, Debug, Hash, Default, PartialEq, Eq)]
pub enum WasdMinState {
    TruncateTo(usize),
    Delete(usize),
    Replace(usize, Wasd),
    #[default]
    End,
}

impl MinimizerState for WasdMinState {
    fn is_stop_state(&self) -> bool {
        matches!(self, Self::End)
    }
}

#[derive(Default)]
pub struct MazeFuzzer {
    /// this is used for input scheduling - assigning weights to each input. The latest corpus entry
    /// has the biggest weight, while the first one has the smallest. Essentially this one is a
    /// Range `0..corpus.len()`, but we cache it as a `Vec<u32>` here so that we don't allocate for
    /// every call the `schedule_next_input`.
    dist_len: usize,
    dist: Option<rand::distributions::WeightedIndex<u32>>,
}

impl Fuzzer for MazeFuzzer {
    type Input = WasdArray;
    const START_ADDRESS: u64 = constants::RIP;
    const MAX_INPUT_LENGTH: usize = 1024;
    const MAX_MUTATIONS: u64 = 4;

    fn set_input(
        &mut self,
        input: &InputWithMetadata<Self::Input>,
        fuzzvm: &mut FuzzVm<Self>,
    ) -> Result<()> {
        // although the WasdArray should never be too long, we truncate here again anyway.
        let i = input.data.len().min(Self::MAX_INPUT_LENGTH - 1);
        // then we write the array data.
        let raw_input = unsafe { std::mem::transmute::<&[Wasd], &[u8]>(&input.data[..i]) };
        fuzzvm.write_bytes_dirty(VirtAddr(constants::INPUT), CR3, &raw_input)?;
        // and we make sure that we have a zero terminator.
        fuzzvm.write_dirty(VirtAddr(constants::INPUT + i as u64), CR3, 0u64)?;
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
            "maze!draw",
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

        // configure snapshot for the right variant of the maze.
        if let Ok(use_maze) = std::env::var("USE_MAZE") {
            let use_maze: i32 = use_maze.parse()?;
            let (addr, cr3) = AddressLookup::SymbolOffset("maze!USE_MAZE", 0).get(fuzzvm)?;
            fuzzvm.write(addr, cr3, use_maze)?;
            log::info!(
                "using the {} maze",
                if use_maze == 1 { "big" } else { "small" }
            );
        } else {
            log::info!("using the small maze");
        }

        if let Ok(val) = std::env::var("MAZE_NO_BT") {
            let bt: u8 = val.parse()?;
            let (addr, cr3) = AddressLookup::SymbolOffset("maze!MAZE_NO_BT", 0).get(fuzzvm)?;
            fuzzvm.write(addr, cr3, bt)?;
            log::info!("set MAZE_NO_BT to {bt}");
        }

        if let Ok(val) = std::env::var("CHECK_CODE") {
            let cc: u8 = val.parse()?;
            let (addr, cr3) = AddressLookup::SymbolOffset("maze!CHECK_CODE", 0).get(fuzzvm)?;
            fuzzvm.write(addr, cr3, cc)?;
            log::info!("set CHECK_CODE to {cc}");
        }

        Ok(())
    }

    fn reset_breakpoints(&self) -> Option<&[AddressLookup]> {
        Some(&[AddressLookup::SymbolOffset("maze!bye", 0x0)])
    }

    fn breakpoints(&self) -> Option<&[Breakpoint<Self>]> {
        if cfg!(feature = "enable_feedback") {
            Some(&[
                // this breakpoint gathers the last (x, y) position in the maze. this is good enough
                // for the fuzzer to achieve it's goal of reaching the end of the maze.
                Breakpoint {
                    lookup: AddressLookup::SymbolOffset("maze!lose", 0x0),
                    bp_type: BreakpointType::Repeated,
                    bp_hook: |fuzzvm: &mut FuzzVm<Self>, _input, _fuzzer, feedback| {
                        if let Some(feedback) = feedback {
                            let x = (fuzzvm.rsi() & 0xffff) as u32;
                            let y = (fuzzvm.rdx() & 0xffff) as u32;
                            if feedback.record_pair(x, y) {
                                log::debug!("found new position: {:?}", (x, y));
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
                            let x = (fuzzvm.rsi() & 0xffff) as u32;
                            let y = (fuzzvm.rdx() & 0xffff) as u32;
                            if feedback.record_pair(x, y) {
                                log::info!("found new position: {:?}", (x, y));
                            }
                        }
                        fuzzvm.fake_immediate_return()?;
                        Ok(Execution::Continue)
                    },
                },
                // we also record the winning position as custom feedback, otherwise we only see the
                // position in the feedback when we lose.
                Breakpoint {
                    lookup: AddressLookup::SymbolOffset("maze!win", 0x0),
                    bp_type: BreakpointType::Repeated,
                    bp_hook: |fuzzvm: &mut FuzzVm<Self>, _input, _fuzzer, feedback| {
                        if let Some(feedback) = feedback {
                            let x = (fuzzvm.rdi() & 0xffff) as u32;
                            let y = (fuzzvm.rsi() & 0xffff) as u32;
                            if feedback.record_pair(x, y) {
                                log::info!("found new winning position: {:?}", (x, y));
                            }
                        }
                        Ok(Execution::Continue)
                    },
                },
                // This breakpoint showcases custom feedback to minimize a string distance between
                // two memory values. We do not want to manually reverse the obfuscation of the secret code,
                // so we let the fuzzer discover the correct inputs by minimizing the distance
                // between the stored value and the provided input.
                Breakpoint {
                    lookup: AddressLookup::SymbolOffset("maze!eq16", 0x0),
                    bp_type: BreakpointType::Repeated,
                    bp_hook: |fuzzvm: &mut FuzzVm<Self>, _input, _fuzzer, feedback| {
                        if let Some(feedback) = feedback {
                            let ptr_a = fuzzvm.rdi();
                            let ptr_b = fuzzvm.rsi();
                            let mut a = [0u8; 16];
                            fuzzvm.read_bytes(VirtAddr(ptr_a), fuzzvm.cr3(), &mut a)?;
                            let mut b = [0u8; 16];
                            fuzzvm.read_bytes(VirtAddr(ptr_b), fuzzvm.cr3(), &mut b)?;
                            if let Some(new_len) = feedback.record_prefix_dist(0u64, &a, &b) {
                                log::info!(
                                    "found new minimal code with distance {} - {:?} vs. {:?}",
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
        corpus: &[Arc<InputWithMetadata<Self::Input>>],
        _feedback: &mut snapchange::feedback::FeedbackTracker,
        rng: &mut Rng,
        dictionary: &Option<Vec<Vec<u8>>>,
    ) -> InputWithMetadata<Self::Input> {
        // bring trait in scope
        use rand::distributions::Distribution;

        // empty corpus -> generate a new input
        if corpus.len() == 0 {
            return <WasdArray as snapchange::FuzzInput>::generate(
                corpus,
                rng,
                dictionary,
                Self::MIN_INPUT_LENGTH,
                Self::MAX_INPUT_LENGTH,
            );
        }

        // we set up a distribution that makes it extremely likely that the last corpus entry is selected again
        // for fuzzing. This is usually the best strategy, since the last entry will be the one that
        // found the farthest in the maze. However, we will cache the distribution in `self` and
        // only update the distribution when there is a new corpus entry. The idea is that a new
        // corpus entry is a rare event, while input scheduling is happening in every fuzz loop
        // iteration, so we move the allocation out of the fuzz loop and cache it in `self`. This
        // avoids several allocations to create the WeightedIndex distribution.
        if self.dist_len != corpus.len() || self.dist.is_none() {
            // no weight should be zero, otherwise the probability of choosing that input is also
            // zero.
            let weights = 1u32..=(corpus.len() as u32);
            self.dist = Some(rand::distributions::WeightedIndex::new(weights).unwrap());
            self.dist_len = corpus.len();
        }
        let idx = self.dist.as_ref().unwrap().sample(rng) as usize;
        assert!(idx < corpus.len());
        // we can safely unwrap here, because corpus.len() > 0 and idx < corpus.len()
        corpus.get(idx).unwrap().fork()
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
    AppendMany,
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
        _corpus: &[Arc<InputWithMetadata<Self>>],
        rng: &mut Rng,
        _dictionary: &Option<Vec<Vec<u8>>>,
        _min_length: usize,
        _max_length: usize,
    ) -> InputWithMetadata<Self> {
        // Start with a random new direction
        let d: Wasd = rng.gen();
        InputWithMetadata::from_input(WasdArray { data: vec![d] })
    }

    fn mutate(
        input: &mut Self,
        corpus: &[Arc<InputWithMetadata<Self>>],
        rng: &mut Rng,
        _dictionary: &Option<Vec<Vec<u8>>>,
        _min_length: usize,
        max_length: usize,
        max_mutations: u64,
    ) -> Vec<String> {
        // Get the number of changes to make to the input
        let num_change: u64 = if max_mutations == 1 {
            1
        } else {
            rng.gen_range(1..max_mutations)
        };

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
                    AppendMany => {
                        let d: Wasd = rng.gen();
                        input.data.push(d);
                        let count = rng.gen_range(0..10);
                        for _i in 0..count {
                            input.data.push(d);
                        }
                        mutations.push("AppendMany".to_string());
                    }
                    Replace => {
                        let i = rng.gen_range(0..input.data.len());
                        loop {
                            let d: Wasd = rng.gen();
                            if input.data[i] != d {
                                input.data[i] = d;
                                break;
                            }
                        }
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
                            let other = &corpus[corpus_idx].input.data;
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

    // this is requrired to conform to snapchange's API
    type MinState = WasdMinState;
    /// dummy init minimize
    fn init_minimize(&mut self) -> (Self::MinState, MinimizeControlFlow) {
        (
            WasdMinState::TruncateTo(self.data.len().saturating_sub(1)),
            MinimizeControlFlow::ContinueFor(self.data.len().try_into().unwrap()),
        )
    }

    /// Minimize a `WasdArray` by truncating it, removing directions, or replacing directions.
    fn minimize(
        &mut self,
        state: &mut Self::MinState,
        current_iteration: u32,
        last_successful_iteration: u32,
        _rng: &mut Rng,
    ) -> MinimizeControlFlow {
        log::trace!("minimize state: {:?}", *state);
        
        // Cannot minimize an empty input
        if self.data.is_empty() {
            *state = WasdMinState::End;
            return MinimizeControlFlow::Stop;
        }

        use MinimizeControlFlow::*;
        use WasdMinState::*;

        // Perform the minimization strategy for this state
        let (cf, next) = match *state {
            TruncateTo(0) => {
                self.data.clear();
                (Continue, Delete(usize::MAX))
            }
            TruncateTo(new_len) => {
                if current_iteration == 0 || last_successful_iteration + 1 == current_iteration {
                    self.data.truncate(new_len);
                    (Continue, TruncateTo(new_len.saturating_sub(1)))
                } else {
                    // last truncation failed, so we skip further truncates
                    (Skip, Delete(usize::MAX))
                }
            }
            Delete(0) => {
                self.data.remove(0);
                (Continue, Replace(usize::MAX, Wasd::W)) // next state is Replace
            }
            Delete(index) => {
                let index = std::cmp::min(self.data.len() - 1, index);
                self.data.remove(index);
                (Continue, Delete(index.saturating_sub(1)))
            }
            Replace(0, val) => {
                let last_index = self.data.len() - 1;
                *self.data.get_mut(0).unwrap() = val;
                match val {
                    Wasd::W => (Continue, Replace(last_index, Wasd::A)),
                    Wasd::A => (Continue, Replace(last_index, Wasd::S)),
                    Wasd::S => (Continue, Replace(last_index, Wasd::D)),
                    Wasd::D => (Continue, Replace(last_index, Wasd::X)),
                    Wasd::X => (Continue, Replace(last_index, Wasd::Y)),
                    Wasd::Y => (Continue, End),
                    Wasd::Stop => (Stop, End),
                }
            }
            Replace(index, val) => {
                let index = std::cmp::min(self.data.len() - 1, index);
                if let Some(p) = self.data.get_mut(index) {
                    *p = val;
                    (Continue, Replace(index - 1, val))
                } else {
                    (Skip, Replace(self.data.len().saturating_sub(1), val))
                }
            }
            End => (Stop, End),
        };

        *state = next;
        cf
    }
}
