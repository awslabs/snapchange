//! Various methods used to mutate inputs that are inherently expensive due to the
//! possibility of re-allocating the input
//!

use rand::Rng as _;
use std::sync::Arc;

use crate::fuzz_input::FuzzInput;
use crate::fuzz_input::InputWithMetadata;
use crate::rng::Rng;

/// Insert a random slice from the corpus into the `input`, expanding the `input`
pub(crate) fn splice_corpus_extend(
    input: &mut Vec<u8>,
    corpus: &[Arc<InputWithMetadata<Vec<u8>>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    if input.len() < 2 || corpus.is_empty() {
        return None;
    }

    // Pre-compute random numbers to avoid borrowing from the &mut fuzzer
    let rand_num1 = rng.gen::<usize>();
    let rand_num2 = rng.gen::<usize>();
    let rand_num3 = rng.gen::<usize>();
    let rand_num4 = rng.gen::<usize>();

    // Get the input which the comes will come from from the corpus
    let splice_from = &corpus[rand_num1 % corpus.len()].input;
    let splice_from_hash = splice_from.fuzz_hash();

    let max_splice_len = std::cmp::min(splice_from.len(), input.len());

    // Assume the length will be larger than 4 bytes
    if max_splice_len < 2 || input.len() < 2 || splice_from.len() < 2 {
        return None;
    }

    let splice_len = rand_num2 % max_splice_len;
    let splice_offset = rand_num3 % (splice_from.len() - splice_len);
    let input_offset = rand_num4 % (input.len() - splice_len);

    crate::utils::vec::splice_into(
        input,
        input_offset..(input_offset + splice_len),
        &splice_from[splice_offset..splice_offset + splice_len],
    );

    Some(format!(
        "SpliceCorpusExtend_offset_{input_offset:#x}_len_{splice_len:#x}_other_{splice_from_hash:#x}"
    ))
}

/// Insert a random dictionary entry into the `input`, potentially expanding the `input`.
pub(crate) fn splice_from_dictionary_extend(
    input: &mut Vec<u8>,
    _corpus: &[Arc<InputWithMetadata<Vec<u8>>>],
    rng: &mut Rng,
    dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    if dictionary.is_none() {
        return None;
    }
    let dictionary = dictionary.as_ref().unwrap();
    if dictionary.is_empty() {
        return None;
    }

    // select renadom dictionary entry
    let dict_idx = rng.gen_range(0..dictionary.len());
    let splice_from = &dictionary[dict_idx];
    // random offset into the input
    let input_offset = if input.is_empty() {
        0
    } else {
        rng.gen_range(0..input.len())
    };

    // we replace bytes up to the length of the dictionary entry. 0 will insert without overwriting.
    let splice_len = rng.gen_range(0..splice_from.len());
    crate::utils::vec::splice_into(
        input,
        input_offset..(input_offset + splice_len),
        &splice_from[..],
    );

    Some(format!(
        "DictionarySpliceExtend_offset_{input_offset:#x}_splicelen_{splice_len}_dictidx_{dict_idx}"
    ))
}
