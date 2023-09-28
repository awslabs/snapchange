//! Implementation of the [`TextInput`], which represents a primarily ascii/text based input.
//! The trait [`FuzzInput`] is implemented for use with snapchange.

#![allow(missing_docs)]

use crate::fuzz_input::{FuzzInput, InputWithMetadata, MinimizeControlFlow, MinimizerState};
use crate::mutators;
use crate::rng::Rng;

use anyhow::Result;
#[cfg(feature = "redqueen")]
use rand::seq::SliceRandom;
use rand::{Rng as _, RngCore};
#[cfg(feature = "redqueen")]
use rustc_hash::FxHashSet;
use std::fmt::Debug;
use std::hash::Hash;
use std::sync::Arc;

#[cfg(feature = "redqueen")]
use crate::cmp_analysis::RedqueenRule;

#[derive(Hash, PartialEq, Eq, Debug, Default, Clone)]
pub struct TextInput {
    pub data: Vec<u8>,
    pub(crate) delimiters: Option<Vec<(u8, usize, Option<usize>)>>,
}

impl From<String> for TextInput {
    fn from(s: String) -> Self {
        Self {
            data: s.into_bytes(),
            ..Default::default()
        }
    }
}

impl From<Vec<u8>> for TextInput {
    fn from(b: Vec<u8>) -> Self {
        Self {
            data: b,
            ..Default::default()
        }
    }
}

impl From<&[u8]> for TextInput {
    fn from(b: &[u8]) -> Self {
        Self {
            data: b.to_vec(),
            ..Default::default()
        }
    }
}

impl<'a> TextInput {
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn data_mut(&'a mut self) -> &'a mut Vec<u8> {
        &mut self.data
    }

    pub fn data(&'a self) -> &'a [u8] {
        &self.data
    }
}

impl FuzzInput for TextInput {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(bytes.into())
    }

    fn to_bytes(&self, output: &mut Vec<u8>) -> Result<()> {
        output.clear();
        output.extend_from_slice(&self.data);
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
        assert!(max_length != 0);

        if input.is_empty() {
            *input = Self::generate(corpus, rng, dictionary, min_length, max_length).input;
            return vec!["Generate".to_string()];
        }

        // Get the number of changes to make to the input
        let num_change = (rng.next_u64() % max_mutations).max(1) as usize;

        // Mutations applied to this input
        let mut mutations: Vec<String> = Vec::with_capacity(num_change);

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

                    let curr_candidate = candidates.choose(rng).unwrap();

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
        input.data.truncate(max_length);

        // Return the mutation applied
        mutations
    }

    /// Current mutators available for mutation
    fn mutators() -> &'static [Self::MutatorFunc] {
        &[
            // basic mutators
            mutators::text::char_replace,
            mutators::text::replace_integer,
            mutators::text::replace_hex_integer,
            mutators::text::splice_within,
            mutators::text::havoc_as_bytes,
            // insert random strings, with the const param, being an upper bound to the number of
            // inserted bytes. This ensures that we will do small modification much more often.
            mutators::text::insert_repeated_chars::<4>,
            mutators::text::insert_repeated_chars::<1024>,
            mutators::text::insert_random_string::<4>,
            mutators::text::insert_random_string::<8>,
            mutators::text::insert_random_string::<1024>,
            // dictionary-based mutations
            mutators::text::splice_from_dictionary,
            mutators::text::insert_from_dictionary,
            // advanced text-focused insertion operators
            mutators::text::insert_from_dictionary_separated_by::<'\n'>,
            mutators::text::insert_from_dictionary_separated_by::<'\t'>,
            mutators::text::insert_from_dictionary_separated_by::<' '>,
            mutators::text::insert_from_dictionary_separated_by::<';'>,
            mutators::text::insert_from_corpus_separated_by::<'\n'>,
            mutators::text::insert_from_corpus_separated_by::<' '>,
            mutators::text::insert_from_corpus_separated_by::<'\t'>,
            mutators::text::insert_from_corpus_separated_by::<';'>,
            // text-focused mutation operations:
            // line-focused
            mutators::text::dup_between_separator::<'\n'>,
            mutators::text::delete_between_separator::<'\n'>,
            // word-focused
            mutators::text::dup_between_separator::<' '>,
            mutators::text::delete_between_separator::<' '>,
            mutators::text::dup_between_separator::<'\t'>,
            mutators::text::delete_between_separator::<'\t'>,
            // interesting for programming languages:
            mutators::text::dup_between_separator::<';'>,
            mutators::text::delete_between_separator::<';'>,
            mutators::text::dup_between_separator::<','>,
            mutators::text::delete_between_separator::<','>,
        ]
    }

    /// Current expensive mutators available for mutation (typically those which allocate)
    fn expensive_mutators() -> &'static [Self::MutatorFunc] {
        &[]
    }

    fn generate(
        _corpus: &[Arc<InputWithMetadata<Self>>],
        rng: &mut Rng,
        _dictionary: &Option<Vec<Vec<u8>>>,
        _min_length: usize,
        max_length: usize,
    ) -> InputWithMetadata<Self> {
        InputWithMetadata::from_input(
            mutators::text::helpers::random_ascii_string(rng, max_length).into(),
        )
    }

    /// return shannon byte entropy for the bytes slice
    fn entropy_metric(&self) -> Option<f64> {
        Some(crate::utils::byte_entropy(self.data()))
    }

    /// just return the length of the current byte buffer
    fn len(&self) -> Option<usize> {
        Some(self.data().len())
    }

    /// Redqueen implementation mostly wraps the bytes redqueen implementation.
    /// TODO: implement text transformations, i.e., itoa/atoi.

    #[cfg(feature = "redqueen")]
    type RuleCandidate = <Vec<u8> as FuzzInput>::RuleCandidate;

    /// Apply the given [`RedqueenRule`] to the current input using the given candidate
    /// returning the mutation done
    #[cfg(feature = "redqueen")]
    fn apply_redqueen_rule(
        &mut self,
        rule: &RedqueenRule,
        candidate: &Self::RuleCandidate,
    ) -> Option<String> {
        let bytes = self.data_mut();
        bytes.apply_redqueen_rule(rule, candidate)
    }

    /// Upper bound for the ranges produced during increasing entropy for redqueen
    fn entropy_limit(&self) -> usize {
        let bytes = &self.data;
        bytes.entropy_limit()
    }

    /// Increase entropy of the input between the given start and end values
    #[cfg(feature = "redqueen")]
    fn increase_entropy(&mut self, rng: &mut Rng, start: usize, end: usize) -> Result<()> {
        let bytes = self.data_mut();
        bytes.increase_entropy(rng, start, end)
    }

    /// Get a list of all of the `RuleCandidate`s that the given `rule` can be applied to. These
    /// candidates are then passed to `apply_redqueen_rule` to deterministically search the
    /// applicable redqueen search space for this input
    #[cfg(feature = "redqueen")]
    fn get_redqueen_rule_candidates(&self, rule: &RedqueenRule) -> Vec<Self::RuleCandidate> {
        self.data.get_redqueen_rule_candidates(rule)
    }

    /// Returns true if the given rule can be applied to this input. Used as a fast path instead of
    /// using get_redqueen_rule_candidates.
    #[cfg(feature = "redqueen")]
    fn has_redqueen_rule_candidates(&self, rule: &RedqueenRule) -> bool {
        self.data.has_redqueen_rule_candidates(rule)
    }

    /// TODO: create a proper minimizer for the text input type

    type MinState = crate::fuzz_input::NullMinimizerState;

    fn minimize(
        &mut self,
        _state: &mut Self::MinState,
        _current_iteration: u32,
        _last_successful_iteration: u32,
        _rng: &mut Rng,
    ) -> MinimizeControlFlow {
        MinimizeControlFlow::Stop
    }

    fn init_minimize(&mut self) -> (Self::MinState, MinimizeControlFlow) {
        crate::fuzz_input::NullMinimizerState::init()
    }
}
