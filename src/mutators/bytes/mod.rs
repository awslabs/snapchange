//! Various methods used to mutate inputs
#![allow(missing_docs)]
#![allow(clippy::ptr_arg)]

use rand::Rng as _;
use std::sync::Arc;

use crate::fuzz_input::InputWithMetadata;
use crate::rng::Rng;

pub mod helpers;
pub mod expensive;

/// Flip a random bit in the input
pub fn bit_flip(
    input: &mut Vec<u8>,
    _corpus: &[Arc<InputWithMetadata<Vec<u8>>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    match helpers::bit_flip(input, rng) {
        Some((byte_offset, bit_offset)) => {
            // Output mutation
            Some(format!(
                "BitFlip_offset_{byte_offset:#x}_bit_{bit_offset:#x}"
            ))
        }
        None => None,
    }
}

/// Replace a random byte in the input with a new byte
pub fn byte_flip(
    input: &mut Vec<u8>,
    _corpus: &[Arc<InputWithMetadata<Vec<u8>>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    match helpers::byte_flip(input, rng) {
        Some((offset, rand_byte)) => {
            Some(format!("ByteFlip_offset_{offset:#x}_byte_{rand_byte:#x}"))
        }
        None => None,
    }
}

/// Insert a random byte into the input with a new byte
pub fn byte_insert(
    input: &mut Vec<u8>,
    _corpus: &[Arc<InputWithMetadata<Vec<u8>>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    match helpers::byte_insert(input, rng) {
        Some((offset, rand_byte)) => {
            Some(format!("ByteInsert_offset_{offset:#x}_byte_{rand_byte:#x}"))
        }
        _ => None,
    }
}

/// Delete a random byte in the input
pub fn byte_delete(
    input: &mut Vec<u8>,
    _corpus: &[Arc<InputWithMetadata<Vec<u8>>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    match helpers::byte_delete(input, rng) {
        Some(offset) => Some(format!("ByteDelete_offset_{offset:#x}")),
        _ => None,
    }
}

/// Increment a random byte
pub fn byte_inc(
    input: &mut Vec<u8>,
    _corpus: &[Arc<InputWithMetadata<Vec<u8>>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    match helpers::inc(input, rng) {
        Some(offset) => Some(format!("ByteInc_offset_{offset:#x}")),
        _ => None,
    }
}

/// Decrement a random byte
pub fn byte_dec(
    input: &mut Vec<u8>,
    _corpus: &[Arc<InputWithMetadata<Vec<u8>>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    match helpers::dec(input, rng) {
        Some(offset) => Some(format!("ByteDec_offset_{offset:#x}")),
        _ => None,
    }
}

/// Impl functions to randomly set a given type
macro_rules! set_random {
    ($name:ident, $typ:ty) => {
        /// Replace a integer at random offset into the input with a new random word.
        pub fn $name(
            input: &mut Vec<u8>,
            _corpus: &[Arc<InputWithMetadata<Vec<u8>>>],
            rng: &mut Rng,
            _dictionary: &Option<Vec<Vec<u8>>>,
        ) -> Option<String> {
            match helpers::$name(input, rng) {
                Some((offset, rand_word)) =>
                // Output mutation
                {
                    Some(format!(
                        "{}_offset_{offset:#x}_data_{rand_word:#x}",
                        stringify!($name)
                    ))
                }
                _ => None,
            }
        }
    };
}

set_random!(set_random_u8, u8);
set_random!(set_random_u16, u16);
set_random!(set_random_u32, u32);
set_random!(set_random_u64, u64);

/// Copy a random slice from the corpus into the input
pub fn splice_corpus(
    input: &mut Vec<u8>,
    corpus: &[Arc<InputWithMetadata<Vec<u8>>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    if input.len() < 4 || corpus.is_empty() {
        return None;
    }

    // Pre-compute random numbers to avoid borrowing from the &mut fuzzer
    let rand_num1 = rng.gen::<usize>();
    let rand_num2 = rng.gen::<usize>();
    let rand_num3 = rng.gen::<usize>();
    let rand_num4 = rng.gen::<usize>();

    // Get the input which the comes will come from from the corpus
    let splice_from = &corpus[rand_num1 % corpus.len()];

    let max_splice_len = std::cmp::min(splice_from.input.len(), input.len());

    // Assume the length will be larger than 4 bytes
    if max_splice_len < 4 || input.len() < 4 || splice_from.input.len() < 4 {
        return None;
    }

    let splice_len = rand_num2 % max_splice_len;
    let splice_offset = rand_num3 % (splice_from.input.len() - splice_len);
    let input_offset = rand_num4 % (input.len() - splice_len);

    // Splice the found
    input[input_offset..input_offset + splice_len]
        .copy_from_slice(&splice_from.input[splice_offset..splice_offset + splice_len]);

    // Output mutation
    Some(format!("SpliceCorpus_offset_{input_offset:#x}"))
}

/// Copy a random slice from the current input into itself
pub fn splice_input(
    input: &mut Vec<u8>,
    _corpus: &[Arc<InputWithMetadata<Vec<u8>>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    if input.len() < 4 {
        return None;
    }

    let (src, dst, len) = helpers::splice_within(input, rng)?;

    // Output mutation
    Some(format!(
        "SpliceInput_srcoffset_{src:#x}_dstoffset_{dst:#x}_len_{len:#x}"
    ))
}

/// Replace bytes in the input with interesting values that trigger common bugs such as
/// off by one
pub fn replace_with_interesting(
    input: &mut Vec<u8>,
    _corpus: &[Arc<InputWithMetadata<Vec<u8>>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    match helpers::replace_with_interesting_integer(input, rng) {
        Some((offset, size, val)) => {
            let bits = size / 8;
            Some(format!("InterestingVal_{offset:#x}_u{bits}_val_{val:#x}"))
        }
        None => None,
    }
}

/// Sets a random slice in the input to a random byte (ala memset)
pub fn set_input_slice(
    input: &mut Vec<u8>,
    _corpus: &[Arc<InputWithMetadata<Vec<u8>>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    if input.len() < 4 {
        return None;
    }

    match helpers::set_slice(input, rng) {
        Some((dst, len, val)) => Some(format!(
            "SetInputSlice_offset_{dst:#x}_len_{len:#x}_val_{val:#x}"
        )),
        _ => None,
    }
}

/// Insert an element from the dictionary into the input
pub fn overwrite_from_dictionary(
    input: &mut Vec<u8>,
    _corpus: &[Arc<InputWithMetadata<Vec<u8>>>],
    rng: &mut Rng,
    dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    match dictionary {
        None => None,
        Some(dict) => {
            let (input_offset, element) = helpers::overwrite_from_dictionary(input, rng, dict)?;

            Some(format!(
                "OverwriteFromDictionary_offset_{input_offset:#x}_{element:x?}"
            ))
        }
    }
}
