//! Various methods used to mutate inputs
#![allow(clippy::ptr_arg)]

use crate::rng::Rng;
use rand::Rng as _;

use crate::fuzz_input::InputWithMetadata;
use std::sync::Arc;

/// Flip a random bit in the input
pub fn bit_flip(
    input: &mut Vec<u8>,
    _corpus: &[Arc<InputWithMetadata<Vec<u8>>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    // Get the length of the input string
    let len = input.len();

    // If the input is empty, ignore
    if len == 0 {
        return None;
    }

    // Get the byte/bit offset to flip
    let byte_offset = rng.gen::<usize>() % len;
    let bit_offset = rng.gen::<u64>() & 7;

    // Flip the random bit
    // SAFETY: byte_offset is within the length of the input
    unsafe {
        *input.get_unchecked_mut(byte_offset) ^= 1 << bit_offset;
    }

    // Output mutation
    Some(format!(
        "BitFlip_offset_{byte_offset:#x}_bit_{bit_offset:#x}"
    ))
}

/// Replace a random byte in the input with a new byte
pub fn byte_flip(
    input: &mut Vec<u8>,
    _corpus: &[Arc<InputWithMetadata<Vec<u8>>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    if input.is_empty() {
        return None;
    }

    // Get the random offset and byte
    let offset = rng.gen::<usize>() % input.len();
    let rand_byte = rng.gen::<u8>();

    // Set the new byte
    input[offset] = rand_byte;

    // Output mutation
    Some(format!("ByteFlip_offset_{offset:#x}_byte_{rand_byte:#x}"))
}

/// Insert a random byte into the input with a new byte
pub fn byte_insert(
    input: &mut Vec<u8>,
    _corpus: &[Arc<InputWithMetadata<Vec<u8>>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    if input.is_empty() {
        return None;
    }

    // Get the random offset and byte
    let offset = rng.gen::<usize>() % input.len();
    let rand_byte = rng.gen::<u8>();

    // Insert the new byte
    input.insert(offset, rand_byte);

    // Output mutation
    Some(format!("ByteInsert_offset_{offset:#x}_byte_{rand_byte:#x}"))
}

/// Delete a random byte in the input
pub fn byte_delete(
    input: &mut Vec<u8>,
    _corpus: &[Arc<InputWithMetadata<Vec<u8>>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    if input.is_empty() {
        return None;
    }

    // Get the random offset and byte
    let offset = rng.gen::<usize>() % input.len();

    // Insert the new byte
    input.remove(offset);

    // Output mutation
    Some(format!("ByteDelete_offset_{offset:#x}"))
}

/// Impl functions to randomly set a given type
macro_rules! set_random {
    ($name:ident, $typ:ty) => {
        /// Replace a random u8 into the input with a new word
        pub fn $name(
            input: &mut Vec<u8>,
            _corpus: &[Arc<InputWithMetadata<Vec<u8>>>],
            rng: &mut Rng,
            _dictionary: &Option<Vec<Vec<u8>>>,
        ) -> Option<String> {
            const SIZE: usize = std::mem::size_of::<$typ>();

            if input.len() <= SIZE {
                return None;
            }

            // Get the random offset and byte ensuring there is room to fill
            let offset = rng.gen::<usize>() % (input.len() - SIZE);
            let rand_word = rng.gen::<$typ>();

            // Replace the new word
            #[allow(clippy::range_plus_one)]
            input[offset..offset + SIZE].copy_from_slice(&rand_word.to_le_bytes());

            // Output mutation
            Some(format!(
                "{}_offset_{offset:#x}_data_{rand_word:#x}",
                stringify!($name)
            ))
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

/// Increment a random byte
pub fn byte_inc(
    input: &mut Vec<u8>,
    _corpus: &[Arc<InputWithMetadata<Vec<u8>>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    if input.is_empty() {
        return None;
    }

    // Get the random offset and byte
    let offset = rng.gen::<usize>() % input.len();

    // Set the new byte
    input[offset] = input[offset].wrapping_add(1);

    // Output mutation
    Some(format!("ByteInc_offset_{offset:#x}"))
}

/// Decrement a random byte
pub fn byte_dec(
    input: &mut Vec<u8>,
    _corpus: &[Arc<InputWithMetadata<Vec<u8>>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    if input.is_empty() {
        return None;
    }

    // Get the random offset and byte
    let offset = rng.gen::<usize>() % input.len();

    // Set the new byte
    input[offset] = input[offset].wrapping_sub(1);

    // Output mutation
    Some(format!("ByteDec_offset_{offset:#x}"))
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

    // Pre-compute random numbers to avoid borrowing from the &mut fuzzer
    #[allow(clippy::cast_possible_wrap)]
    let src = (rng.gen::<usize>() % input.len()) as isize;

    #[allow(clippy::cast_possible_wrap)]
    let dst = (rng.gen::<usize>() % input.len()) as isize;

    // Get the larger of the two positions
    let largest = std::cmp::max(src, dst);

    // Get the maximum slice that is not out of bounds
    let max_len = input.len() - usize::try_from(largest).ok()?;

    // Randomly choose a length of slice to copy that is in bounds
    let len = rng.gen::<usize>() % max_len;

    // Copy the slice internally. These buffers could overlap
    // SAFETY: src and dst are within the bounds of input
    unsafe {
        std::ptr::copy(
            input.as_mut_ptr().offset(src),
            input.as_mut_ptr().offset(dst),
            len,
        );
    }

    // Output mutation
    Some(format!(
        "SpliceInput_srcoffset_{src:#x}_dstoffset_{dst:#x}_len_{len:#x}"
    ))
}

/// Interesting `u8` values to insert into a test input
const INTERESTING_U8: [u8; 10] = [
    u8::MAX,
    u8::MAX - 1,
    u8::MAX - 2,
    u8::MAX - 3,
    u8::MAX - 4,
    u8::MIN,
    u8::MIN + 1,
    u8::MIN + 2,
    u8::MIN + 3,
    u8::MIN + 4,
];

/// Interesting `u16` values to insert into a test input
const INTERESTING_U16: [u16; 20] = [
    (u8::MAX) as u16,
    (u8::MAX - 1) as u16,
    (u8::MAX - 2) as u16,
    (u8::MAX - 3) as u16,
    (u8::MAX - 4) as u16,
    (u8::MIN) as u16,
    (u8::MIN + 1) as u16,
    (u8::MIN + 2) as u16,
    (u8::MIN + 3) as u16,
    (u8::MIN + 4) as u16,
    u16::MAX,
    u16::MAX - 1,
    u16::MAX - 2,
    u16::MAX - 3,
    u16::MAX - 4,
    u16::MIN,
    u16::MIN + 1,
    u16::MIN + 2,
    u16::MIN + 3,
    u16::MIN + 4,
];

/// Interesting `u32` values to insert into a test input
const INTERESTING_U32: [u32; 30] = [
    (u8::MAX) as u32,
    (u8::MAX - 1) as u32,
    (u8::MAX - 2) as u32,
    (u8::MAX - 3) as u32,
    (u8::MAX - 4) as u32,
    (u8::MIN) as u32,
    (u8::MIN + 1) as u32,
    (u8::MIN + 2) as u32,
    (u8::MIN + 3) as u32,
    (u8::MIN + 4) as u32,
    (u16::MAX) as u32,
    (u16::MAX - 1) as u32,
    (u16::MAX - 2) as u32,
    (u16::MAX - 3) as u32,
    (u16::MAX - 4) as u32,
    (u16::MIN) as u32,
    (u16::MIN + 1) as u32,
    (u16::MIN + 2) as u32,
    (u16::MIN + 3) as u32,
    (u16::MIN + 4) as u32,
    u32::MAX,
    u32::MAX - 1,
    u32::MAX - 2,
    u32::MAX - 3,
    u32::MAX - 4,
    u32::MIN,
    u32::MIN + 1,
    u32::MIN + 2,
    u32::MIN + 3,
    u32::MIN + 4,
];

/// Interesting `u64` values to insert into a test input
const INTERESTING_U64: [u64; 40] = [
    (u8::MAX) as u64,
    (u8::MAX - 1) as u64,
    (u8::MAX - 2) as u64,
    (u8::MAX - 3) as u64,
    (u8::MAX - 4) as u64,
    (u8::MIN) as u64,
    (u8::MIN + 1) as u64,
    (u8::MIN + 2) as u64,
    (u8::MIN + 3) as u64,
    (u8::MIN + 4) as u64,
    (u16::MAX) as u64,
    (u16::MAX - 1) as u64,
    (u16::MAX - 2) as u64,
    (u16::MAX - 3) as u64,
    (u16::MAX - 4) as u64,
    (u16::MIN) as u64,
    (u16::MIN + 1) as u64,
    (u16::MIN + 2) as u64,
    (u16::MIN + 3) as u64,
    (u16::MIN + 4) as u64,
    (u32::MAX) as u64,
    (u32::MAX - 1) as u64,
    (u32::MAX - 2) as u64,
    (u32::MAX - 3) as u64,
    (u32::MAX - 4) as u64,
    (u32::MIN) as u64,
    (u32::MIN + 1) as u64,
    (u32::MIN + 2) as u64,
    (u32::MIN + 3) as u64,
    (u32::MIN + 4) as u64,
    u64::MAX,
    u64::MAX - 1,
    u64::MAX - 2,
    u64::MAX - 3,
    u64::MAX - 4,
    u64::MIN,
    u64::MIN + 1,
    u64::MIN + 2,
    u64::MIN + 3,
    u64::MIN + 4,
];

/// Replace bytes in the input with interesting values that trigger common bugs such as
/// off by one
pub fn replace_with_interesting(
    input: &mut Vec<u8>,
    _corpus: &[Arc<InputWithMetadata<Vec<u8>>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    if input.len() < 9 {
        return None;
    }

    // Randomly choose which size of number to create (u8, u16, u32, u64)
    let size = match rng.gen::<u64>() % 4 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };

    // Get the offset to replace with a random interesting value ensuring the random
    // number can fit in the input
    let offset = rng.gen::<usize>() % (input.len() - size);

    // Get the random value to replace in the input
    match size {
        1 => {
            let val = INTERESTING_U8[rng.gen::<usize>() % INTERESTING_U8.len()];
            input[offset..offset + size].copy_from_slice(&val.to_le_bytes());
            Some(format!("InterestingVal_{offset:#x}_val_{val:#x}"))
        }
        2 => {
            let val = INTERESTING_U16[rng.gen::<usize>() % INTERESTING_U16.len()];
            input[offset..offset + size].copy_from_slice(&val.to_le_bytes());
            Some(format!("InterestingVal_{offset:#x}_val_{val:#x}"))
        }
        4 => {
            let val = INTERESTING_U32[rng.gen::<usize>() % INTERESTING_U32.len()];
            input[offset..offset + size].copy_from_slice(&val.to_le_bytes());
            Some(format!("InterestingVal_{offset:#x}_val_{val:#x}"))
        }
        8 => {
            let val = INTERESTING_U64[rng.gen::<usize>() % INTERESTING_U64.len()];
            input[offset..offset + size].copy_from_slice(&val.to_le_bytes());
            Some(format!("InterestingVal_{offset:#x}_val_{val:#x}"))
        }
        _ => unreachable!(),
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

    // Pre-compute random numbers to avoid borrowing from the &mut fuzzer
    #[allow(clippy::cast_possible_wrap)]
    let dst = (rng.gen::<usize>() % input.len()) as isize;

    // Get the maximum slice that is not out of bounds
    let max_len = input.len() - usize::try_from(dst).ok()?;

    // Randomly choose a length of slice to copy that is in bounds
    let len = rng.gen::<usize>() % max_len;

    // Copy the slice internally
    // SAFETY: dst offset is within the bounds of input
    #[allow(clippy::cast_possible_truncation)]
    unsafe {
        let val = rng.gen::<u64>() as u8;
        std::ptr::write_bytes(input.as_mut_ptr().offset(dst), val, len);
        Some(format!(
            "SetInputSlice_offset_{dst:#x}_len_{len:#x}_val_{val:#x}"
        ))
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
            // Pre-compute random numbers to avoid borrowing from the &mut fuzzer
            let rand_num1 = rng.gen::<usize>();
            let rand_num2 = rng.gen::<usize>();

            // Get the dictionary element to insert
            let element = &dict[rand_num1 % dict.len()];

            let element_len = element.len();
            let input_offset = rand_num2 % (input.len().saturating_sub(element_len) + 1);
            let needed_len = input_offset + element_len;

            // The current input isn't large enough to hold the found element. Resize the input.
            if input.len() < needed_len {
                input.resize(needed_len + 1, 0);
            }

            // Splice the found
            input[input_offset..input_offset + element_len].copy_from_slice(element);

            Some(format!(
                "InsertFromDictionary_offset_{input_offset:#x}_{element:x?}"
            ))
        }
    }
}
