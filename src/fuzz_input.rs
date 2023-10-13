//! Provides an abstraction around various types of fuzz inputs

#[cfg(feature = "redqueen")]
use crate::cmp_analysis::RedqueenRule;

#[cfg(feature = "redqueen")]
use crate::cmp_analysis::RedqueenRule::{SingleF32, SingleU16, SingleU32, SingleU64, SingleU8};

use crate::expensive_mutators;
use crate::mutators;
use crate::rng::Rng;
use crate::feedback::FeedbackLog;

use anyhow::Result;
use rand::{Rng as _, RngCore};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_hex::{CompactPfx, SerHex};
use std::fmt::Debug;
use std::hash::Hash;

/// An abstract input used in fuzzing. This trait provides methods for mutating, generating, and
/// minimizing an input. This trait also has required methods for enabling Redqueen analysis
/// for an input.
pub trait FuzzInput:
    Sized + Debug + Default + Clone + Send + Hash + Eq + std::panic::UnwindSafe
{
    /// Function signature for a mutator of this type
    #[allow(clippy::type_complexity)]
    type MutatorFunc = fn(
        input: &mut Self,
        corpus: &[Self],
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
        corpus: &[Self],
        rng: &mut Rng,
        dictionary: &Option<Vec<Vec<u8>>>,
        max_length: usize,
        max_mutations: u64,
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
        corpus: &[Self],
        rng: &mut Rng,
        dictionary: &Option<Vec<Vec<u8>>>,
        max_length: usize,
    ) -> Self;

    /// Minimize the given `input` based on a minimization strategy
    fn minimize(_input: &mut Self, _rng: &mut Rng) {
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

    /// Replace all instances of the `left` side of the given rule with random bytes
    #[cfg(feature = "redqueen")]
    fn increase_redqueen_entropy(&mut self, _rule: &RedqueenRule, _rng: &mut Rng) {
        panic!("Redqueen not implemented for this type. Please impl `increase_redqueen_entropy`");
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
}

impl FuzzInput for Vec<u8> {
    #[cfg(feature = "redqueen")]
    type RuleCandidate = (usize, Endian, RedqueenRule);

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
        corpus: &[Self],
        rng: &mut Rng,
        dictionary: &Option<Vec<Vec<u8>>>,
        max_length: usize,
        max_mutations: u64,
    ) -> Vec<String> {
        // Get the number of changes to make to the input
        let num_change = (rng.next_u64() % max_mutations).max(1);

        // Mutations applied to this input
        let mut mutations: Vec<String> = Vec::new();

        // Perform some number of mutations on the input
        for _ in 0..num_change {
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

        // Return the mutation applied
        mutations
    }

    #[cfg(feature = "redqueen")]
    fn apply_redqueen_rule(
        &mut self,
        _rule: &RedqueenRule,
        candidate: &Self::RuleCandidate,
    ) -> Option<String> {
        let (index, endian, rule) = candidate;

        /// Write the given `to` bytes into `self` at `index`
        macro_rules! apply_rule {
            ($ty:ty, $from:expr, $to:expr) => {{
                let size = std::mem::size_of::<$ty>();

                let bytes = match endian {
                    Endian::Little => $to.to_le_bytes(),
                    Endian::Big => $to.to_be_bytes(),
                };

                // Ensure we can actually fit the rule in the current input
                if *index + size >= self.len() {
                    return None;
                }

                self[*index..*index + size].copy_from_slice(&bytes);
                Some(format!("{rule:x?}_offset_{index:#x}"))
            }};
        }

        match rule {
            RedqueenRule::SingleU128(_from, to) => {
                apply_rule!(u128, from, to)
            }
            RedqueenRule::SingleU64(_from, to) => {
                apply_rule!(u64, from, to)
            }
            RedqueenRule::SingleU32(_from, to) => {
                apply_rule!(u32, from, to)
            }
            RedqueenRule::SingleU16(_from, to) => {
                apply_rule!(u16, from, to)
            }
            RedqueenRule::SingleU8(_from, to) => {
                apply_rule!(u8, from, to)
            }
            RedqueenRule::SingleF32(_from, to) => {
                let size = to.len();

                // Ensure we can actually fit the rule in the current input
                if *index + size >= self.len() {
                    return None;
                }

                self[*index..*index + size].copy_from_slice(to);
                Some(format!("{rule:x?}_offset_{index:#x}"))
            }
            RedqueenRule::SingleF64(_from, to) => {
                let size = to.len();

                // Ensure we can actually fit the rule in the current input
                if *index + size >= self.len() {
                    return None;
                }

                self[*index..*index + size].copy_from_slice(to);
                Some(format!("{rule:x?}_offset_{index:#x}"))
            }
            RedqueenRule::Bytes(from, to) => {
                let index: usize = *index;

                if to.len() == from.len() {
                    // Both from and to are the same size, directly copy the bytes
                    let size = to.len();
                    self[index..index + size].copy_from_slice(to);
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
                }

                Some(format!("Bytes_offset_{index:#x}"))
            }
        }
    }

    /// Replace all instances of the `left` side of the given rule with random bytes
    #[allow(clippy::cast_possible_truncation, clippy::doc_markdown)]
    #[cfg(feature = "redqueen")]
    fn increase_redqueen_entropy(&mut self, rule: &RedqueenRule, rng: &mut Rng) {
        /// If `needle` is found in the current bytes, replace that needle with random bytes
        /// in order to attempt to uniquely identify this particular location and reduce the
        /// number of candidates to apply when using redqueen
        ///
        /// Example:
        /// Input:     aaaabaaacaaadaaa
        /// Needle:    aa
        /// New Input: AQRWbIOacMDad9N
        macro_rules! entropy_rule {
            ($ty:ty, $size:literal, $needle:expr) => {{
                for i in 0..self.len() - $size {
                    if self[i..i + $size] == $needle.to_le_bytes() {
                        self[i..i + $size].copy_from_slice(&(rng.next() as $ty).to_le_bytes());
                    }

                    if $needle.to_le_bytes() != $needle.to_be_bytes() {
                        if self[i..i + $size] == $needle.to_be_bytes() {
                            self[i..i + $size].copy_from_slice(&(rng.next() as $ty).to_le_bytes());
                        }
                    }
                }
            }};
        }

        // Apply each rule by randomly setting the needle (left operand)
        match rule {
            RedqueenRule::SingleU128(needle, _) => {
                entropy_rule!(u128, 0x10, needle);
            }
            RedqueenRule::SingleU64(needle, _) => {
                entropy_rule!(u64, 8, needle);
            }
            RedqueenRule::SingleU32(needle, _) => {
                entropy_rule!(u32, 4, needle);
            }
            RedqueenRule::SingleU16(needle, _) => {
                entropy_rule!(u16, 2, needle);
            }
            RedqueenRule::SingleU8(needle, _) => {
                entropy_rule!(u8, 1, needle);
            }
            RedqueenRule::SingleF32(needle, _)
            | RedqueenRule::SingleF64(needle, _)
            | RedqueenRule::Bytes(needle, _) => {
                for i in 0..self.len() - needle.len() {
                    if &self[i..i + needle.len()] == needle.as_slice() {
                        for curr_byte in 0..needle.len() {
                            self[i + curr_byte] = rng.next() as u8;
                        }
                    }
                }
            }
        }
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
        let mut candidates = Vec::new();

        /// Search for the `orig_from` in the current self and, if found, insert it into
        /// the list of candidate rules
        macro_rules! find_needle {
            ($ty:ty, $orig_from:expr, $orig_to:expr, $rule:expr) => {{
                const SIZE: usize = std::mem::size_of::<$ty>();
                let from = $orig_from as $ty;
                let to = $orig_to as $ty;
                for i in 0..self.len().saturating_sub(SIZE) {
                    if self[i..i + SIZE] == from.to_le_bytes() {
                        candidates.push((i, Endian::Little, $rule));
                    }

                    // Only look for big endian operand redqueen if big != little endians
                    if from.to_le_bytes() != from.to_be_bytes() {
                        if self[i..i + SIZE] == from.to_be_bytes() {
                            candidates.push((i, Endian::Big, $rule));
                        }
                    }
                }
            }};
        }

        // For a given comparison parsed from binja, we can't know which part of the whole number
        // is being compared
        //
        // Example:
        // EAX - 0x41
        // EBX - 0xff
        // cmp eax, ebx
        //
        // Is this comparing the u8 values 0x41 to 0xff?
        // Or the bytes [0x41, 0x00, 0x00, 0x00] with [0xff, 0x00, 0x00, 0x00]?
        // For this reason, we add all the smaller rules that make up each larger type's rule.
        // So a u16 comparison will add a u16 rule and a u8 rule,
        // A u32 comparison will add a u32, u16, and u8 rule, ect.
        match rule {
            RedqueenRule::SingleU128(from, to) => {
                find_needle!(u128, *from, *to, rule.clone());
                if *from as u64 <= u64::MAX && *to as u64 <= u64::MAX {
                    find_needle!(u64, *from, *to, SingleU64(*from as u64, *to as u64));
                    if *from as u32 <= u32::MAX && *to as u32 <= u32::MAX {
                        find_needle!(u32, *from, *to, SingleU32(*from as u32, *to as u32));
                        if *from as u16 <= u16::MAX && *to as u16 <= u16::MAX {
                            find_needle!(u16, *from, *to, SingleU16(*from as u16, *to as u16));
                            if *from as u8 <= u8::MAX && *to as u8 <= u8::MAX {
                                find_needle!(u8, *from, *to, SingleU8(*from as u8, *to as u8));
                            }
                        }
                    }
                }
            }
            RedqueenRule::SingleU64(from, to) => {
                find_needle!(u64, *from, *to, rule.clone());
                if *from as u32 <= u32::MAX && *to as u32 <= u32::MAX {
                    find_needle!(u32, *from, *to, SingleU32(*from as u32, *to as u32));
                    if *from as u16 <= u16::MAX && *to as u16 <= u16::MAX {
                        find_needle!(u16, *from, *to, SingleU16(*from as u16, *to as u16));
                        if *from as u8 <= u8::MAX && *to as u8 <= u8::MAX {
                            find_needle!(u8, *from, *to, SingleU8(*from as u8, *to as u8));
                        }
                    }
                }
            }
            RedqueenRule::SingleU32(from, to) => {
                find_needle!(u32, *from, *to, SingleU32(*from as u32, *to as u32));
                if *from as u16 <= u16::MAX && *to as u16 <= u16::MAX {
                    find_needle!(u16, *from, *to, SingleU16(*from as u16, *to as u16));
                    if *from as u8 <= u8::MAX && *to as u8 <= u8::MAX {
                        find_needle!(u8, *from, *to, SingleU8(*from as u8, *to as u8));
                    }
                }
            }
            RedqueenRule::SingleU16(from, to) => {
                find_needle!(u16, *from, *to, SingleU16(*from as u16, *to as u16));
                if *from as u8 <= u8::MAX && *to as u8 <= u8::MAX {
                    find_needle!(u8, *from, *to, SingleU8(*from as u8, *to as u8));
                }
            }
            RedqueenRule::SingleU8(from, to) => {
                find_needle!(u8, *from, *to, SingleU8(*from as u8, *to as u8));
            }
            RedqueenRule::SingleF32(from, to) => {
                if self.len() >= from.len() {
                    for i in 0..self.len().saturating_sub(from.len() - 1) {
                        if &self[i..i + from.len()] == from.as_slice() {
                            candidates.push((i, Endian::Little, rule.clone()));
                        }
                    }
                }
            }
            RedqueenRule::SingleF64(from, to) => {
                if self.len() >= from.len() {
                    for i in 0..self.len().saturating_sub(from.len() - 1) {
                        if &self[i..i + from.len()] == from.as_slice() {
                            candidates.push((i, Endian::Little, rule.clone()));
                        }
                    }
                }

                assert!(from.len() == 8 && to.len() == 8);
                let from_dword = from[..4].to_vec();
                let to_dword = to[..4].to_vec();
                if self.len() >= from_dword.len() {
                    for i in 0..self.len().saturating_sub(from_dword.len() - 1) {
                        if &self[i..i + from_dword.len()] == from_dword.as_slice() {
                            candidates.push((
                                i,
                                Endian::Little,
                                SingleF32(from[..4].to_vec(), to[..4].to_vec()),
                            ));
                        }
                    }
                }
            }
            RedqueenRule::Bytes(from, to) => {
                if self.len() >= from.len() {
                    for i in 0..self.len().saturating_sub(from.len() - 1) {
                        if &self[i..i + from.len()] == from.as_slice() {
                            candidates.push((i, Endian::Little, rule.clone()));
                        }
                    }
                }
            }
        }

        candidates
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
            mutators::insert_from_dictionary,
            mutators::byte_insert,
        ]
    }

    /// Current expensive mutators available for mutation (typically those which allocate)
    fn expensive_mutators() -> &'static [Self::MutatorFunc] {
        &[expensive_mutators::splice_corpus_extend]
    }

    /// Generate a random `Vec<u8>` of `max_length` size
    fn generate(
        _corpus: &[Self],
        rng: &mut Rng,
        _dictionary: &Option<Vec<Vec<u8>>>,
        max_length: usize,
    ) -> Self {
        let mut result = vec![0u8; max_length];
        rng.fill_bytes(&mut result);
        result
    }

    /// Minimize a `Vec<u8>` with a variety of different techniques
    fn minimize(input: &mut Self, rng: &mut Rng) {
        // Cannot minimize an empty input
        if input.is_empty() {
            return;
        }

        // Randomly pick the type of minimization
        let state = match rng.next() % 12 {
            0..4 => MinimizeState::Slices,
            4..8 => MinimizeState::MultiBytes,
            8..10 => MinimizeState::SingleBytes,
            10..12 => MinimizeState::Replace(0xcd),
            _ => unreachable!(),
        };

        // Perform the minimization strategy for this state
        match state {
            MinimizeState::Slices => {
                let curr_input_len = input.len();

                let a = rng.gen::<usize>() % curr_input_len;
                let b = rng.gen::<usize>() % curr_input_len;
                let (first, second) = if a < b { (a, b) } else { (b, a) };

                let _slice_len = rng.gen::<usize>() % (curr_input_len - second);

                input.splice(first..second, []);
            }
            MinimizeState::MultiBytes => {
                for _ in 0..=(rng.gen::<usize>() % 32) {
                    if input.is_empty() {
                        return;
                    }

                    let curr_input_len = input.len();
                    input.remove(rng.gen::<usize>() % curr_input_len);
                }
            }
            MinimizeState::SingleBytes => {
                let curr_input_len = input.len();
                input.remove(rng.gen::<usize>() % curr_input_len);
            }
            MinimizeState::Replace(redqueen_byte) => {
                let curr_input_len = input.len();

                for _ in 0..rng.gen::<usize>() % 32 {
                    // Get the new offset to replace
                    let offset = rng.gen::<usize>() % curr_input_len;

                    // Found a newly replaced byte, replace it
                    input[offset] = redqueen_byte;
                }
            }
        }
    }
}

/// Stages of the minimization process
///
/// Stages:
/// Slice   - Attempt to delete slices of data to make the input smaller
/// Bytes   - Attempt to delele individual bytes to make the input smaller
/// Replace - Attempt to find unnecessary byte values by replacing bytes with `?`
#[derive(Debug)]
enum MinimizeState {
    /// This state tries to delete bytes of the input to make the input smaller
    Slices,

    /// This state tries to delete random bytes of the input to make the input smaller
    MultiBytes,

    /// This state tries to delete single bytes of the input to make the input smaller
    SingleBytes,

    /// This state tries to identify unnecessary bytes in the input with a `?` to signify
    /// the byte is not needed for the crash
    Replace(u8),
}

/// Endianness for the redqueen rules
#[derive(Debug)]
pub enum Endian {
    /// Little endian
    Little,
    /// Big endian
    Big,
}

/// Metadata about a crashing input or a new input that found new coverage.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct InputMetadata {
    /// Fuzz hash of the original file used for mutation
    #[serde(with = "SerHex::<CompactPfx>")]
    pub(crate) original_file: u64,

    /// Mutatation strategies used on this file
    pub(crate) mutation: Vec<String>,

    /// New coverage blocks hit by this input
    pub(crate) new_coverage: Vec<FeedbackLog>,
}

/// Custom serialize for Vec<u64>
fn serialize_vec_u64_as_hex<S>(values: &[u64], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // Convert the u64 to hex strings

    // Begin the sequence of elements
    let mut seq = serializer.serialize_seq(Some(values.len()))?;

    // Serialize each individual element
    for element in values.iter().map(|x| format!("{x:#x}")) {
        seq.serialize_element(&element)?;
    }

    // Finish the sequence
    seq.end()
}

/// Custom deserialize for Vec<u64>
fn deserialize_vec_u64_from_hex<'de, D>(deserializer: D) -> Result<Vec<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    // Get a Vec of hex strings from the deserializer
    let hex: Vec<String> = Deserialize::deserialize(deserializer)?;

    // Convert the hex strings back into u64
    let data = hex
        .iter()
        .map(|x| u64::from_str_radix(&x[2..], 16))
        .collect::<Result<Vec<u64>, _>>()
        .map_err(serde::de::Error::custom)?;

    // Return the result
    Ok(data)
}
