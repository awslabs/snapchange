//! Various methods used to mutate inputs that are inherently expensive due to the
//! possibility of re-allocating the input
//!
use crate::fuzz_input::FuzzInput;
use crate::rng::Rng;
use crate::try_isize;

use rand::Rng as _;

use crate::fuzz_input::InputWithMetadata;
use std::sync::Arc;

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

    let orig_len = input.len();

    // Resize the input to fit the splice
    input.resize(input.len() + splice_len, 0);

    // Copy the bytes that will be overwritten by the splice
    unsafe {
        let src = try_isize!(input_offset);
        let dst = try_isize!(input_offset + splice_len);

        std::ptr::copy(
            input.as_mut_ptr().offset(src),
            input.as_mut_ptr().offset(dst),
            orig_len - input_offset,
        );
    }

    // Insert the splice
    input[input_offset..input_offset + splice_len]
        .copy_from_slice(&splice_from[splice_offset..splice_offset + splice_len]);

    Some(format!(
        "SpliceCorpusExtend_offset_{input_offset:#x}_len_{splice_len:#x}_other_{splice_from_hash:#x}"
    ))
}
