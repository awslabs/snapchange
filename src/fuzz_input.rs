//! Provides an abstraction around various types of fuzz inputs

use crate::expensive_mutators;
use crate::feedback::FeedbackLog;

use crate::mutators;
use crate::rng::Rng;

use anyhow::Result;
use rand::{Rng as _, RngCore};

use serde::{Deserialize, Serialize};
use serde_hex::{CompactPfx, SerHex};

use std::fmt::Debug;
use std::hash::Hash;
use std::path::Path;
use std::sync::{Arc, RwLock};

#[cfg(feature = "redqueen")]
use crate::cmp_analysis::RedqueenRule;

#[cfg(feature = "redqueen")]
use crate::cmp_analysis::RedqueenCoverage;

#[cfg(feature = "redqueen")]
use rustc_hash::FxHashSet;

/// Returned by the [`FuzzInput::minimize`] function to signal how to progress further.
#[derive(Debug, Clone, Copy, Default)]
pub enum MinimizeControlFlow {
    /// Continue with minimization
    #[default]
    Continue,
    /// Stop minimization after the current step
    Stop,
    /// Skip the current step, e.g., because the current minimization rule could not be applied.
    Skip,
    /// Continue minimization for at least that many steps.
    ContinueFor(u32),
}

impl MinimizeControlFlow {
    /// continue minimization for at least one more iteration
    pub fn one_more() -> Self {
        Self::ContinueFor(1)
    }

    /// continue minimization
    pub fn cont() -> Self {
        Self::Continue
    }

    /// stop minimization after current step
    pub fn stop() -> Self {
        Self::Stop
    }
}

/// An abstract input used in fuzzing. This trait provides methods for mutating, generating, and
/// minimizing an input. This trait also has required methods for enabling Redqueen analysis
/// for an input.
pub trait FuzzInput:
    Sized + Debug + Default + Clone + Send + Hash + Eq + std::panic::UnwindSafe
{
    /// Type that represents minimization state. Use [`NullMinimizerState`] if you do not have a
    /// useful state for your minimization algorithm. The state type must implement the
    /// [`MinimizerState`] trait.
    type MinState: MinimizerState + std::panic::RefUnwindSafe;

    /// Function signature for a mutator of this type
    #[allow(clippy::type_complexity)]
    type MutatorFunc = fn(
        input: &mut Self,
        corpus: &[Arc<InputWithMetadata<Self>>],
        rng: &mut Rng,
        dictionary: &Option<Vec<Vec<u8>>>,
    ) -> Option<String>;

    /// Read the input bytes as the implemented type
    ///
    /// # Errors
    ///
    /// * Failed to convert the given bytes to `Self`
    fn from_bytes(bytes: &[u8]) -> Result<Self>;

    /// Convert the implemented type as a `Vec<u8>`
    ///
    /// # Errors
    ///
    /// * Failed to serialize `Self` into the output bytes
    fn to_bytes(&self, output: &mut Vec<u8>) -> Result<()>;

    /// Mutate the current object using a `corpus`, `rng`, and `dictionary` that has a
    /// maximum length of `max_length`. Returns the list of mutations applied during this
    /// mutation
    fn mutate(
        input: &mut Self,
        corpus: &[Arc<InputWithMetadata<Self>>],
        rng: &mut Rng,
        dictionary: &Option<Vec<Vec<u8>>>,
        min_length: usize,
        max_length: usize,
        max_mutations: u64,
        #[cfg(feature = "redqueen")] redqueen_rules: Option<&FxHashSet<RedqueenRule>>,
    ) -> Vec<String>;

    /// Basic mutators available to mutate this fuzzer's input
    #[must_use]
    fn mutators() -> &'static [Self::MutatorFunc] {
        &[]
    }

    /// Expensive mutators available to mutate this fuzzer's input. These mutators are called
    /// less often on this type since they are potentially more costly
    #[must_use]
    fn expensive_mutators() -> &'static [Self::MutatorFunc] {
        &[]
    }

    /// Generate a random version of this type
    fn generate(
        corpus: &[Arc<InputWithMetadata<Self>>],
        rng: &mut Rng,
        dictionary: &Option<Vec<Vec<u8>>>,
        min_length: usize,
        max_length: usize,
    ) -> InputWithMetadata<Self>;

    /// init stateful minimization
    fn init_minimize(&mut self) -> (Self::MinState, MinimizeControlFlow) {
        panic!(
            "Minimize not implemented for {:?}",
            std::any::type_name::<Self>()
        );
    }

    /// Minimize the given `input` based on a minimization strategy
    fn minimize(
        &mut self,
        _state: &mut Self::MinState,
        _current_iteration: u32,
        _last_successful_iteration: u32,
        _rng: &mut Rng,
    ) -> MinimizeControlFlow {
        panic!(
            "Minimize not implemented for {:?}",
            std::any::type_name::<Self>()
        );
    }

    /// Get the hash for this input
    fn fuzz_hash(&self) -> u64 {
        crate::utils::calculate_hash(&self)
    }

    /// Type used to describe the locations in the input to apply a given rule
    #[cfg(feature = "redqueen")]
    type RuleCandidate: Debug;

    /// Apply the given [`RedqueenRule`] to the current input using the given candidate
    /// returning the mutation done
    #[cfg(feature = "redqueen")]
    fn apply_redqueen_rule(
        &mut self,
        _rule: &RedqueenRule,
        _candidate: &Self::RuleCandidate,
    ) -> Option<String> {
        panic!("Redqueen not implemented for this type. Please impl `apply_redqueen_rule`");
    }

    /// Upper bound for the ranges produced during increasing entropy for redqueen
    fn entropy_limit(&self) -> usize {
        panic!("Redqueen not implemented for this type. Please impl `entropy_limit`");
    }

    /// Increase entropy of the input between the given start and end values
    #[cfg(feature = "redqueen")]
    fn increase_entropy(&mut self, _rng: &mut Rng, _start: usize, _end: usize) -> Result<()> {
        panic!("Redqueen not implemented for this type. Please impl `increase_entropy`");
    }

    /// Get a list of all of the `RuleCandidate`s that the given `rule` can be applied to. These
    /// candidates are then passed to `apply_redqueen_rule` to deterministically search the
    /// applicable redqueen search space for this input
    #[cfg(feature = "redqueen")]
    fn get_redqueen_rule_candidates(&self, _rule: &RedqueenRule) -> Vec<Self::RuleCandidate> {
        panic!(
            "Redqueen not implemented for this type. Please impl `get_redqueen_rule_candidates`"
        );
    }

    /// Returns true if the given rule can be applied to this input. Used as a fast path instead of
    /// using get_redqueen_rule_candidates.
    #[cfg(feature = "redqueen")]
    fn has_redqueen_rule_candidates(&self, _rule: &RedqueenRule) -> bool {
        panic!(
            "Redqueen not implemented for this type. Please impl `has_redqueen_rule_candidates`"
        );
    }

    /// return some kind of entropy metric (e.g., byte entropy), if applicable.
    fn entropy_metric(&self) -> Option<f64> {
        None
    }

    /// return length of the input, if applicable.
    fn len(&self) -> Option<usize> {
        None
    }
}

/// This is the trait to implement when you want to do provide a type for stateful minimization.
/// See [`BytesMinimizeState`] for an example.
pub trait MinimizerState:
    Sized + Debug + Default + Clone + Send + Hash + Eq + std::panic::UnwindSafe
{
    /// Return true if the state is a stop state, i.e., there is nothing else to try.
    fn is_stop_state(&self) -> bool;
}

/// In case there is no useful minimization state, use this type as your minimization state.
///
/// ```rust,ignore
///
/// impl FuzzInput for YourType {
///    type MinState = NullMinimizerState;
///
///    fn init_minimize(&mut self) -> (Self::MinState, MinimizeControlFlow) {
///        NullMinimizerState::init()
///    }
///
/// }
/// ```
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct NullMinimizerState;

impl MinimizerState for NullMinimizerState {
    fn is_stop_state(&self) -> bool {
        false
    }
}

#[allow(dead_code)]
impl NullMinimizerState {
    /// to be used in [`FuzzInput::
    pub const fn init() -> (Self, MinimizeControlFlow) {
        (Self {}, MinimizeControlFlow::Continue)
    }
}

impl FuzzInput for Vec<u8> {
    #[cfg(feature = "redqueen")]
    type RuleCandidate = (usize, Endian);

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(bytes.to_vec())
    }

    fn to_bytes(&self, output: &mut Vec<u8>) -> Result<()> {
        // Write this Vec<u8> into the output allocation
        output.extend(self);

        Ok(())
    }

    fn mutate(
        input: &mut Self,
        corpus: &[Arc<InputWithMetadata<Self>>],
        rng: &mut Rng,
        dictionary: &Option<Vec<Vec<u8>>>,
        min_length: usize,
        max_length: usize,
        max_mutations: u64,
        #[cfg(feature = "redqueen")] redqueen_rules: Option<&FxHashSet<RedqueenRule>>,
    ) -> Vec<String> {
        // Get the number of changes to make to the input
        let num_change = (rng.next_u64() % max_mutations).max(1);

        // Mutations applied to this input
        let mut mutations: Vec<String> = Vec::new();

        // Perform some number of mutations on the input
        for _ in 0..num_change {
            // Special case the redqueen mutation if there are available rules
            #[cfg(feature = "redqueen")]
            if let Some(rules) = redqueen_rules {
                let total_mutators = Self::mutators().len() + Self::expensive_mutators().len();

                if !rules.is_empty() && rng.gen::<usize>() % total_mutators == 0 {
                    // Select one of the redqueen rules
                    let rule_index = rng.gen::<usize>() % rules.len();
                    let Some(curr_rule) = rules.iter().nth(rule_index) else {
                        continue;
                    };

                    // Select one of the possible locations in the input to apply this rule
                    let candidates = input.get_redqueen_rule_candidates(curr_rule);
                    if candidates.is_empty() {
                        /*
                        log::warn!(
                            "Found no candidates for this rule: {:#x} {curr_rule:x?}",
                            input.fuzz_hash()
                        );
                        */
                        continue;
                    }

                    let candidate_index = rng.gen::<usize>() % candidates.len();
                    let curr_candidate = &candidates[candidate_index];

                    // Apply the redqueen rule to the current input
                    if let Some(mutation) = input.apply_redqueen_rule(curr_rule, curr_candidate) {
                        mutations.push(format!("RQ_MUTATE_{mutation}"));
                    }

                    continue;
                }
            }

            // Choose which mutators to use for this mutation. Expensive mutators are
            // harder to hit since they are a bit more costly
            let curr_mutators = if rng.next_u64() % max_mutations * 5 == 0 {
                Self::expensive_mutators()
            } else {
                Self::mutators()
            };

            // Select one of the mutators
            let mutator_index = rng.gen::<usize>() % curr_mutators.len();
            let mutator_func = curr_mutators[mutator_index];

            // Execute the mutator
            if let Some(mutation) = mutator_func(input, corpus, rng, dictionary) {
                mutations.push(mutation);
            }
        }

        // Ensure the input fits in the maximum length
        input.truncate(max_length);

        // Extend the input to minimum length
        for _byte in 0..min_length.saturating_sub(input.len()) {
            input.push(rng.next() as u8);
        }

        // Return the mutation applied
        mutations
    }

    type MinState = BytesMinimizeState;

    fn init_minimize(&mut self) -> (Self::MinState, MinimizeControlFlow) {
        (
            if self.is_empty() {
                BytesMinimizeState::End
            } else {
                BytesMinimizeState::StartTruncate
            },
            MinimizeControlFlow::Continue,
        )
    }

    /// Minimize a `Vec<u8>` with a variety of different techniques
    fn minimize(
        &mut self,
        state: &mut Self::MinState,
        current_iteration: u32,
        last_successful_iteration: u32,
        rng: &mut Rng,
    ) -> MinimizeControlFlow {
        // Cannot minimize an empty input
        if self.is_empty() {
            *state = BytesMinimizeState::End;
            return MinimizeControlFlow::Stop;
        }
        let last_succeeded = current_iteration == (last_successful_iteration + 1);
        use BytesMinimizeState::*;
        let mut cf = MinimizeControlFlow::Continue;
        // Advance the state machine
        *state = match *state {
            // == deterministic minimization steps ===
            StartTruncate => {
                cf = MinimizeControlFlow::one_more();
                FindTruncate(0, self.len())
            }
            FindTruncate(low, high) => {
                if low < high && low < self.len() {
                    cf = MinimizeControlFlow::one_more();
                    let index = (low + high) / 2;
                    if last_succeeded {
                        FindTruncate(low, index - 1)
                    } else {
                        FindTruncate(index + 1, high)
                    }
                } else {
                    // otherwise we transition to the next strategy. Replace with a constant
                    // starting from the back. We start by replacing whole
                    if self.len() >= 8 {
                        cf = MinimizeControlFlow::ContinueFor((self.len() / 8).try_into().unwrap());
                        ReplaceConstBytes(self.len() - 8, &[b'A'; 8])
                    } else {
                        cf = MinimizeControlFlow::ContinueFor(self.len().try_into().unwrap());
                        Replace(self.len() - 1, b'A')
                    }
                }
            }
            ReplaceConstBytes(0, data) => {
                if data == [b'A'; 8] && self.len() >= 8 {
                    cf = MinimizeControlFlow::ContinueFor((self.len() / 8).try_into().unwrap());
                    ReplaceConstBytes(self.len() - 8, &[0_u8; 8])
                } else {
                    cf = MinimizeControlFlow::ContinueFor(self.len().try_into().unwrap());
                    Replace(self.len() - 1, 0)
                }
            }
            ReplaceConstBytes(index, data) => ReplaceConstBytes(index.saturating_sub(8), data),
            Replace(0, b'A') => {
                cf = MinimizeControlFlow::ContinueFor(self.len().try_into().unwrap());
                Replace(self.len() - 1, 0)
            }
            Replace(0, 0) => Slices,
            Replace(index, what) => Replace(index - 1, what),
            // == probabilistic minimization steps ===
            // loop endlessly between states as long as the fuzzer wants
            Slices => MultiBytes,
            MultiBytes => SingleBytes,
            SingleBytes => Slices,
            // == end state ===
            End => End,
        };

        log::trace!("minimize with {:?}", state);

        // Perform the minimization strategy for this state
        match *state {
            StartTruncate => {
                return MinimizeControlFlow::Skip;
            }
            FindTruncate(low, high) => {
                let index = (low + high) / 2;
                self.truncate(index);
            }
            ReplaceConstBytes(index, byte_slice) => {
                let repl_len = byte_slice.len();
                if self[index..].len() >= repl_len {
                    self[index..(index + repl_len)].copy_from_slice(byte_slice);
                } else {
                    return MinimizeControlFlow::Skip;
                }
            }
            Replace(index, byte) => {
                if let Some(b) = self.get_mut(index) {
                    if *b != byte {
                        *b = byte;
                    } else {
                        return MinimizeControlFlow::Skip;
                    }
                } else {
                    return MinimizeControlFlow::Skip;
                }
            }
            Slices => {
                let curr_input_len = self.len();

                let a = rng.gen_range(0..curr_input_len);
                let b = rng.gen_range(0..curr_input_len);
                let (first, second) = if a < b { (a, b) } else { (b, a) };
                self.splice(first..second, []);
            }
            MultiBytes => {
                let count = rng.gen_range(0u32..32);
                for _ in 0..count {
                    let curr_input_len = self.len();
                    if curr_input_len > 1 {
                        let index = rng.gen_range(0..curr_input_len);
                        self.remove(index);
                    } else {
                        break;
                    }
                }
            }
            SingleBytes => {
                let index = rng.gen_range(0..self.len());
                self.remove(index);
            }
            End => {
                return MinimizeControlFlow::Stop;
            }
        }

        if current_iteration > (3 * last_successful_iteration)
            && matches!(state, Slices | MultiBytes | SingleBytes)
        {
            log::debug!("At iteration {current_iteration} and no progress since {last_successful_iteration} - giving up");
            *state = End;
            MinimizeControlFlow::Stop
        } else {
            cf
        }
    }

    #[cfg(feature = "redqueen")]
    fn apply_redqueen_rule(
        &mut self,
        rule: &RedqueenRule,
        candidate: &Self::RuleCandidate,
    ) -> Option<String> {
        let (index, endian) = candidate;

        match rule {
            RedqueenRule::Primitive(from, to) => {
                // Use the minimum number of bytes to compare values (removing the leading zeros)
                let from_min_bytes = from.minimum_bytes();
                let new_size = to.minimum_bytes().max(from.minimum_bytes());
                let bytes: &[u8] = &to.as_bytes()[..new_size];

                if from_min_bytes == new_size {
                    // Ensure we can actually fit the rule in the current input
                    if *index + new_size >= self.len() {
                        return None;
                    }

                    match endian {
                        Endian::Little => {
                            self[*index..*index + new_size].copy_from_slice(&bytes);
                        }
                        Endian::Big => {
                            for (offset, byte) in bytes.iter().rev().enumerate() {
                                self[*index + offset] = *byte;
                            }
                        }
                    };
                } else {
                    // If the lengths are different, replace the from bytes with the to
                    // bytes via .splice()

                    /*
                    log::info!(
                        "Replacing {index:#x} {from:?} {:?} {:x?}",
                        *index..*index + from_min_bytes,
                        &bytes
                    );

                    let end = (*index + 0x10).min(self.len());
                    log::info!("BEFORE: {:x?}", &self[*index..end]);
                    */
                    match endian {
                        Endian::Little => {
                            self.splice(*index..*index + from_min_bytes, bytes.iter().copied());
                        }
                        Endian::Big => {
                            self.splice(
                                *index..*index + from_min_bytes,
                                bytes.iter().rev().copied(),
                            );
                        }
                    };
                    /*
                    let end = (*index + 0x10).min(self.len());
                    log::info!("AFTER: {:x?}", &self[*index..end]);
                    */
                }

                Some(format!("{to:x?}_offset_{index:#x}"))
            }
            RedqueenRule::SingleF32(_from, to) => {
                let size = to.len();

                // Ensure we can actually fit the rule in the current input
                if *index + size >= self.len() {
                    return None;
                }

                let bytes = to;

                match endian {
                    Endian::Little => {
                        self[*index..*index + size].copy_from_slice(bytes);
                    }
                    Endian::Big => {
                        for (offset, byte) in bytes.iter().rev().enumerate() {
                            self[*index + offset] = *byte;
                        }
                    }
                };

                Some(format!("f32_{to:x?}_offset_{index:#x}"))
            }
            RedqueenRule::SingleF64(_from, to) => {
                let size = to.len();

                // Ensure we can actually fit the rule in the current input
                if *index + size >= self.len() {
                    return None;
                }

                let bytes = to;

                match endian {
                    Endian::Little => {
                        self[*index..*index + size].copy_from_slice(bytes);
                    }
                    Endian::Big => {
                        for (offset, byte) in bytes.iter().rev().enumerate() {
                            self[*index + offset] = *byte;
                        }
                    }
                };

                Some(format!("f64_{to:x?}_offset_{index:#x}"))
            }
            RedqueenRule::SingleF80(_from, to) => {
                let size = to.len();

                // Ensure we can actually fit the rule in the current input
                if *index + size >= self.len() {
                    return None;
                }

                let val = extended::Extended::from_le_bytes(*to).to_f64();

                self[*index..*index + size].copy_from_slice(to);
                Some(format!("f80_{to:x?}_{val}_offset_{index:#x}"))
            }
            RedqueenRule::Bytes(from, to) => {
                let index: usize = *index;

                let len = if to.len() == from.len() {
                    // Both from and to are the same size, directly copy the bytes
                    let size = to.len();
                    self[index..index + size].copy_from_slice(to);

                    to.len()
                } else {
                    // If the "to" bytes is longer than the "from" needle, splice the "to" bytes
                    // where the from needle was
                    let mut new_length = self.len();
                    if to.len() > from.len() {
                        new_length += to.len() - from.len();
                    }
                    if from.len() > to.len() {
                        new_length -= from.len() - to.len();
                    }

                    let mut new_self = vec![0_u8; new_length];
                    new_self[..index].copy_from_slice(&self[..index]);
                    new_self[index..index + to.len()].copy_from_slice(to);
                    new_self[index + to.len()..].copy_from_slice(&self[index + from.len()..]);
                    *self = new_self;

                    new_length
                };

                Some(format!("Bytes_offset_{index:#x}_len_{len:#x}"))
            }
        }
    }

    #[cfg(feature = "redqueen")]
    fn entropy_limit(&self) -> usize {
        self.len()
    }

    #[allow(clippy::cast_possible_truncation, clippy::doc_markdown)]
    #[cfg(feature = "redqueen")]
    fn increase_entropy(&mut self, rng: &mut Rng, start: usize, end: usize) -> Result<()> {
        use rand::Fill;

        // Randomize these bytes
        Ok(self[start..end].try_fill(rng)?)
    }

    /// Get a list of all of the [`RuleCandidate`]s that the given `rule` can be applied to. These
    /// candidates are then passed to `apply_redqueen_rule` to deterministically search the
    /// applicable redqueen search space for this input
    #[allow(
        unused_variables,
        clippy::cast_possible_truncation,
        clippy::absurd_extreme_comparisons,
        clippy::unnecessary_cast
    )]
    #[cfg(feature = "redqueen")]
    fn get_redqueen_rule_candidates(&self, rule: &RedqueenRule) -> Vec<Self::RuleCandidate> {
        get_redqueen_rule_candidates_for_vec(self, rule, GetRuleMode::All)
    }

    #[cfg(feature = "redqueen")]
    fn has_redqueen_rule_candidates(&self, rule: &RedqueenRule) -> bool {
        !get_redqueen_rule_candidates_for_vec(self, rule, GetRuleMode::Fast).is_empty()
    }

    /// Current mutators available for mutation
    fn mutators() -> &'static [Self::MutatorFunc] {
        &[
            mutators::bit_flip,
            mutators::byte_flip,
            mutators::byte_delete,
            mutators::set_random_u8,
            mutators::set_random_u16,
            mutators::set_random_u32,
            mutators::set_random_u64,
            mutators::splice_corpus,
            mutators::byte_inc,
            mutators::byte_dec,
            mutators::splice_input,
            mutators::replace_with_interesting,
            mutators::set_input_slice,
            mutators::overwrite_from_dictionary,
            mutators::byte_insert,
        ]
    }

    /// Current expensive mutators available for mutation (typically those which allocate)
    fn expensive_mutators() -> &'static [Self::MutatorFunc] {
        &[
            expensive_mutators::splice_corpus_extend,
            expensive_mutators::splice_from_dictionary_extend,
            expensive_mutators::remove_slice,
        ]
    }

    /// Generate a random `Vec<u8>` of `max_length` size
    fn generate(
        _corpus: &[Arc<InputWithMetadata<Self>>],
        rng: &mut Rng,
        _dictionary: &Option<Vec<Vec<u8>>>,
        min_length: usize,
        max_length: usize,
    ) -> InputWithMetadata<Self> {
        debug_assert!(max_length > 1);

        // generate input with random length, but make it a power of two most of the time
        let mut len = rng.gen_range(min_length..max_length);
        if rng.gen_bool(0.8) {
            len = len.next_power_of_two().max(max_length);
        }

        // in 80% of the cases; generate high entropy random input
        let result = if rng.gen_bool(0.8) {
            let mut result = vec![0u8; len];
            rng.fill_bytes(&mut result);
            result
        } else {
            // in 10% use a low entropy input
            let b = 0x41 + rng.gen_range(0..26);
            vec![b; len]
        };
        InputWithMetadata::from_input(result)
    }

    /// return shannon byte entropy for the bytes slice
    fn entropy_metric(&self) -> Option<f64> {
        Some(crate::utils::byte_entropy(self))
    }

    /// just return the length of the current byte buffer
    fn len(&self) -> Option<usize> {
        Some(self.len())
    }
}

/// The mode to get redqueen rule candidates for Vec<u8>
#[cfg(feature = "redqueen")]
#[derive(Copy, Clone, Eq, PartialEq)]
enum GetRuleMode {
    /// Return from the function after the first found candidate
    Fast,

    /// Return after all candidates are found
    All,
}

/// Get the rule candidates for a Vec<u8>. If mode is Fast, return the candidates on the first found
/// candidate.
#[cfg(feature = "redqueen")]
fn get_redqueen_rule_candidates_for_vec(
    input: &Vec<u8>,
    rule: &RedqueenRule,
    mode: GetRuleMode,
) -> Vec<<Vec<u8> as FuzzInput>::RuleCandidate> {
    let mut candidates = Vec::new();

    let fast = matches!(mode, GetRuleMode::Fast);

    match rule {
        RedqueenRule::Primitive(from, _to) => {
            // Use the minimum number of bytes to compare values (removing the leading zeros)
            let from_min_bytes = from.minimum_bytes();
            // let to_min_bytes = to.minimum_bytes();

            let size = from_min_bytes;
            let from_le_bytes = &from.as_bytes()[..size];

            let same_big_endian = from_le_bytes
                .iter()
                .zip(from_le_bytes.iter().rev())
                .all(|(x, y)| *x == *y);

            for index in 0..input.len().saturating_sub(size) {
                let curr_window = &input[index..index + size];

                if curr_window == from_le_bytes {
                    candidates.push((index, Endian::Little));
                    if fast {
                        return candidates;
                    }
                }

                // Only look for big endian operand redqueen if big != little endians
                if !same_big_endian {
                    let from_be_bytes = from_le_bytes.iter().rev();

                    if curr_window.iter().zip(from_be_bytes).all(|(x, y)| *x == *y) {
                        candidates.push((index, Endian::Big));
                        if fast {
                            return candidates;
                        }
                    }
                }
            }
        }
        RedqueenRule::SingleF32(from, _to) => {
            if input.len() >= from.len() {
                for i in 0..input.len().saturating_sub(from.len() - 1) {
                    if &input[i..i + from.len()] == from.as_slice() {
                        candidates.push((i, Endian::Little));
                        if fast {
                            return candidates;
                        }
                    }
                }
            }
        }
        RedqueenRule::SingleF64(from, _to) => {
            if input.len() >= from.len() {
                for i in 0..input.len().saturating_sub(from.len() - 1) {
                    if &input[i..i + from.len()] == from {
                        candidates.push((i, Endian::Little));
                        if fast {
                            return candidates;
                        }
                    }
                }
            }
        }
        RedqueenRule::SingleF80(from, _to) => {
            if input.len() >= from.len() {
                for i in 0..input.len().saturating_sub(from.len() - 1) {
                    if &input[i..i + from.len()] == from {
                        candidates.push((i, Endian::Little));
                        if fast {
                            return candidates;
                        }
                    }
                }
            }
        }
        RedqueenRule::Bytes(from, _to) => {
            if input.len() >= from.len() {
                for i in 0..input.len().saturating_sub(from.len() - 1) {
                    if &input[i..i + from.len()] == from {
                        candidates.push((i, Endian::Little));
                        if fast {
                            return candidates;
                        }
                    }
                }
            }
        }
    }

    candidates
}

/// Stages for the minimization process of a byte string (e.g., `Vec<u8>`).
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum BytesMinimizeState {
    /// Start a binary search to identify the right length to truncate the testcase to.
    StartTruncate,

    /// Attempt to truncate to the given size.
    FindTruncate(usize, usize),

    /// Replace unused sub-slices in the input with a constant slice.
    ReplaceConstBytes(usize, &'static [u8]),

    /// Replace unused bytes in the input with a constant byte.
    Replace(usize, u8),

    /// Delete a randomly-selected sub-slice of the input to make the input smaller.
    Slices,

    /// Randomly select and delete multiple bytes in the input to make the input smaller.
    MultiBytes,

    /// Delete a single randomly-selected byte in the input to make the input smaller.
    SingleBytes,

    /// signal immediate stop of minimization.
    End,
}

impl MinimizerState for BytesMinimizeState {
    /// test if the given state represents a stop state
    fn is_stop_state(&self) -> bool {
        matches!(self, Self::End)
    }
}

impl Default for BytesMinimizeState {
    fn default() -> Self {
        Self::End
    }
}

/// Endianness for the redqueen rules
#[derive(Debug)]
pub enum Endian {
    /// Little endian
    Little,
    /// Big endian
    Big,
}

/// A particular type of new coverage
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CoverageType {
    /// Only a new address was found
    Address(u64),

    /// A new coverage with rflags and hit count provided by redqueen
    #[cfg(feature = "redqueen")]
    Redqueen(RedqueenCoverage),
}

/// Metadata about a crashing input or a new input that found new coverage.
#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub struct InputMetadata {
    /// Fuzz hash of the original file used for mutation
    #[serde(with = "SerHex::<CompactPfx>")]
    pub original_file: u64,

    /// Mutatation strategies used on this file
    pub mutations: Vec<String>,

    /// New coverage blocks hit by this input
    pub new_coverage: Vec<FeedbackLog>,

    /// Is this input the result of increased entropy
    pub entropy: bool,
}

/// An input tied with metadata about that input
pub struct InputWithMetadata<T: FuzzInput> {
    /// The input in question
    pub input: T,

    /// Metadata about this input
    pub metadata: RwLock<InputMetadata>,
}
impl<T: FuzzInput> std::panic::UnwindSafe for InputWithMetadata<T> {}
impl<T: FuzzInput> std::panic::RefUnwindSafe for InputWithMetadata<T> {}
unsafe impl<T: FuzzInput> Send for InputWithMetadata<T> {}
unsafe impl<T: FuzzInput> Sync for InputWithMetadata<T> {}

impl<T: FuzzInput> std::cmp::PartialEq for InputWithMetadata<T> {
    fn eq(&self, other: &Self) -> bool {
        self.input == other.input
    }
}
impl<T: FuzzInput> std::cmp::Eq for InputWithMetadata<T> {}

impl<T: FuzzInput> std::hash::Hash for InputWithMetadata<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.input.hash(state);
        self.metadata.read().unwrap().hash(state);
    }
}
impl<T: FuzzInput> std::default::Default for InputWithMetadata<T> {
    fn default() -> Self {
        Self {
            input: T::default(),
            metadata: RwLock::new(InputMetadata::default()),
        }
    }
}
impl<T: FuzzInput> std::ops::Deref for InputWithMetadata<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.input
    }
}
impl<T: FuzzInput> std::ops::DerefMut for InputWithMetadata<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.input
    }
}

impl<T: FuzzInput> InputWithMetadata<T> {
    /// Create an [`InputWithMetadata`] with empty metadata
    pub fn from_input(input: T) -> Self {
        Self {
            input,
            metadata: RwLock::new(InputMetadata {
                original_file: 0,
                mutations: Vec::new(),
                new_coverage: Vec::new(),
                entropy: false,
            }),
        }
    }

    /// Read an input from an input's path
    pub fn from_path(input_path: &Path, project_dir: &Path) -> Result<Self> {
        let input = T::from_bytes(&std::fs::read(input_path)?)?;
        let filename = crate::utils::hexdigest(&input);

        let metadata_path = project_dir.join("metadata").join(filename);

        let metadata = if metadata_path.exists() {
            let data = std::fs::read_to_string(metadata_path)?;
            serde_json::from_str(&data)?
        } else {
            InputMetadata::default()
        };

        Ok(Self {
            input,
            metadata: RwLock::new(metadata),
        })
    }

    /// Create a clone of this input with empty metadata and as the original input
    /// as the parent
    pub fn fork(&self) -> Self {
        Self {
            input: self.input.clone(),
            metadata: RwLock::new(InputMetadata {
                original_file: crate::utils::calculate_hash(&self),
                mutations: Vec::new(),
                new_coverage: Vec::new(),
                entropy: false,
            }),
        }
    }

    /// Serialize the input as bytes
    pub fn input_as_bytes(&self) -> Result<Vec<u8>> {
        let mut input_bytes: Vec<u8> = vec![];
        self.input.to_bytes(&mut input_bytes)?;
        Ok(input_bytes)
    }

    /// Serialize the metadata as json
    pub fn serialized_metadata(&self) -> Result<String> {
        let data = self.metadata.read().unwrap();
        Ok(serde_json::to_string(&*data)?)
    }

    /// Get the fuzz_hash of the underlying input
    pub fn fuzz_hash(&self) -> u64 {
        self.input.fuzz_hash()
    }

    /// Set the new coverage for this input
    pub fn add_new_coverage(&self, mut new_coverage: Vec<FeedbackLog>) {
        self.metadata
            .write()
            .unwrap()
            .new_coverage
            .append(&mut new_coverage);
    }

    /// Add the given mutation to this metadata
    pub fn add_mutation(&self, new_mutation: impl Into<String>) {
        self.metadata
            .write()
            .unwrap()
            .mutations
            .push(new_mutation.into());
    }
}
