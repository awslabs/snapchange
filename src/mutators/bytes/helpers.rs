use rand::seq::SliceRandom;
use rand::Rng;

/// flip a random bit in the input
#[inline]
pub fn bit_flip<T: AsMut<[u8]>>(input: &mut T, rng: &mut impl rand::Rng) -> Option<(usize, u64)> {
    let input = input.as_mut();
    let len = input.len();
    // If the input is empty, ignore
    if len == 0 {
        return None;
    }

    // Get the byte/bit offset to flip
    let byte_offset = rng.gen_range(0..len);
    let bit_offset = rng.gen::<u64>() & 7;

    // Flip the random bit
    // SAFETY: byte_offset is within the length of the input
    unsafe {
        *input.get_unchecked_mut(byte_offset) ^= 1 << bit_offset;
    }

    Some((byte_offset, bit_offset))
}

/// replace a random byte in the input
#[inline]
pub fn byte_flip<T: AsMut<[u8]>>(input: &mut T, rng: &mut impl rand::Rng) -> Option<(usize, u8)> {
    let input = input.as_mut();
    if input.is_empty() {
        return None;
    }

    // Get the random offset and byte
    let len = input.len();
    let offset = rng.gen_range(0..len);
    let rand_byte = rng.gen::<u8>();

    // Set the new byte
    input[offset] = rand_byte;

    Some((offset, rand_byte))
}

/// Insert a random byte into the input with a new byte
#[inline]
pub fn byte_insert(input: &mut Vec<u8>, rng: &mut impl rand::Rng) -> Option<(usize, u8)> {
    if input.is_empty() {
        return None;
    }

    // Get the random offset and byte
    let len = input.len();
    let offset = rng.gen_range(0..len);
    let rand_byte = rng.gen::<u8>();

    // Insert the new byte
    input.insert(offset, rand_byte);

    // Output mutation
    Some((offset, rand_byte))
}

/// Delete a random byte in the input
#[inline]
pub fn byte_delete(input: &mut Vec<u8>, rng: &mut impl rand::Rng) -> Option<usize> {
    if input.is_empty() {
        return None;
    }

    // Get the random offset and byte
    let len = input.len();
    let offset = rng.gen_range(0..len);
    // Insert the new byte
    input.remove(offset);
    Some(offset)
}

/// Increment a random byte
pub fn inc<T: AsMut<[u8]>>(input: &mut T, rng: &mut impl rand::Rng) -> Option<usize> {
    let input = input.as_mut();
    if input.is_empty() {
        return None;
    }

    // Get the random offset and byte
    let offset = rng.gen_range(0..input.len());

    // Set the new byte
    input[offset] = input[offset].wrapping_add(1);

    Some(offset)
}

/// Decrement a random byte
pub fn dec<T: AsMut<[u8]>>(input: &mut T, rng: &mut impl rand::Rng) -> Option<usize> {
    let input = input.as_mut();
    if input.is_empty() {
        return None;
    }

    // Get the random offset and byte
    let offset = rng.gen_range(0..input.len());

    // Set the new byte
    input[offset] = input[offset].wrapping_sub(1);

    Some(offset)
}

/// Impl functions to randomly set a given type
macro_rules! set_random {
    ($name:ident, $typ:ty) => {
        /// Replace a random u8 into the input with a new word
        pub fn $name(input: &mut Vec<u8>, rng: &mut impl rand::Rng) -> Option<(usize, $typ)> {
            const SIZE: usize = std::mem::size_of::<$typ>();

            if input.len() <= SIZE {
                return None;
            }

            // Get the random offset and byte ensuring there is room to fill
            let last = input.len() - SIZE;
            let offset = rng.gen_range(0..last);
            let rand_word = rng.gen::<$typ>();

            // Replace the new word
            #[allow(clippy::range_plus_one)]
            input[offset..offset + SIZE].copy_from_slice(&rand_word.to_le_bytes());

            Some((offset, rand_word))
        }
    };
}

set_random!(set_random_u8, u8);
set_random!(set_random_u16, u16);
set_random!(set_random_u32, u32);
set_random!(set_random_u64, u64);

/// For an input with length `len` choose a random integer size: 1, 2, 4, 8
fn choose_integer_size(len: usize, rng: &mut impl Rng) -> usize {
    // the hot path will never loop, only for small inputs we do another loop iteration to identify
    // a smaller size.
    loop {
        let mut i = 4;
        let size = match rng.gen_range(0..i) {
            0 => 1,
            1 => 2,
            2 => 4,
            3 => 8,
            _ => unreachable!(),
        };
        if size <= len {
            return size;
        } else {
            i -= 1;
        }
        if i == 0 {
            return 0;
        }
    }
}

/// Replace bytes in the input with interesting values that trigger common bugs such as
/// off by one
pub fn set_random_word<T: AsMut<[u8]>>(
    input: &mut T,
    rng: &mut impl rand::Rng,
) -> Option<(usize, u8, u64)> {
    let input = input.as_mut();
    if input.is_empty() {
        return None;
    }

    // Randomly choose which size of number to create (u8, u16, u32, u64)
    let size = choose_integer_size(input.len(), rng);
    if size == 0 {
        return None;
    }

    // Get the offset to replace with a random interesting value ensuring the random
    // number can fit in the input
    let offset = rng.gen_range(0..=(input.len() - size));

    // Get the random value to replace in the input
    let val = match size {
        1 => {
            let val: u8 = rng.gen();
            input[offset] = val;
            val as u64
        }
        2 => {
            let val: u16 = rng.gen();
            input[offset..offset + size].copy_from_slice(&val.to_le_bytes());
            val as u64
        }
        4 => {
            let val: u32 = rng.gen();
            input[offset..offset + size].copy_from_slice(&val.to_le_bytes());
            val as u64
        }
        8 => {
            let val: u64 = rng.gen();
            input[offset..offset + size].copy_from_slice(&val.to_le_bytes());
            val as u64
        }
        _ => unreachable!(),
    };

    Some((offset, size as u8, val as u64))
}

/// Interesting `u8` values to insert into a test input
pub const INTERESTING_U8: [u8; 10] = [
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
pub const INTERESTING_U16: [u16; 20] = [
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
pub const INTERESTING_U32: [u32; 30] = [
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
pub const INTERESTING_U64: [u64; 40] = [
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
pub fn replace_with_interesting_integer<T: AsMut<[u8]>>(
    input: &mut T,
    rng: &mut impl rand::Rng,
) -> Option<(usize, u8, u64)> {
    let input = input.as_mut();
    if input.is_empty() {
        return None;
    }

    // Randomly choose which size of number to create (u8, u16, u32, u64)
    let size = choose_integer_size(input.len(), rng);
    if size == 0 {
        return None;
    }

    // select endianess at random
    let big_endian = rng.gen_bool(0.5);

    // Get the offset to replace with a random interesting value ensuring the random
    // number can fit in the input
    let offset = rng.gen_range(0..=(input.len() - size));

    // Get the random value to replace in the input
    let val = match size {
        1 => {
            let val = *INTERESTING_U8.as_slice().choose(rng).unwrap();
            input[offset] = val;
            val as u64
        }
        2 => {
            let val = *INTERESTING_U16.as_slice().choose(rng).unwrap();
            input[offset..offset + size].copy_from_slice(
                &(if big_endian {
                    val.to_be_bytes()
                } else {
                    val.to_le_bytes()
                }),
            );
            val as u64
        }
        4 => {
            let val = *INTERESTING_U32.as_slice().choose(rng).unwrap();
            input[offset..offset + size].copy_from_slice(
                &(if big_endian {
                    val.to_be_bytes()
                } else {
                    val.to_le_bytes()
                }),
            );
            val as u64
        }
        8 => {
            let val = *INTERESTING_U64.as_slice().choose(rng).unwrap();
            input[offset..offset + size].copy_from_slice(
                &(if big_endian {
                    val.to_be_bytes()
                } else {
                    val.to_le_bytes()
                }),
            );
            val as u64
        }
        _ => unreachable!(),
    };

    Some((offset, size as u8, val as u64))
}

/// Insert interesting values that trigger common bugs such as off by one. This always extends
/// an input's size.
pub fn insert_interesting_integer(
    input: &mut Vec<u8>,
    rng: &mut impl rand::Rng,
) -> Option<(usize, u8, u64)> {
    // Randomly choose which size of number to create (u8, u16, u32, u64)
    let size = choose_integer_size(usize::MAX, rng);
    if size == 0 {
        return None;
    }

    // select endianess at random
    let big_endian = rng.gen_bool(0.5);

    // Get the offset to replace with a random interesting value ensuring the random
    // number can fit in the input
    let offset = rng.gen_range(0..=input.len());

    // Get the random value to replace in the input
    let val = match size {
        1 => {
            let val = *INTERESTING_U8.as_slice().choose(rng).unwrap();
            input.insert(offset, val);
            val as u64
        }
        2 => {
            let val = *INTERESTING_U16.as_slice().choose(rng).unwrap();
            crate::utils::vec::fast_insert_at(
                input,
                offset,
                &(if big_endian {
                    val.to_be_bytes()
                } else {
                    val.to_le_bytes()
                }),
            );
            val as u64
        }
        4 => {
            let val = *INTERESTING_U32.as_slice().choose(rng).unwrap();
            crate::utils::vec::fast_insert_at(
                input,
                offset,
                &(if big_endian {
                    val.to_be_bytes()
                } else {
                    val.to_le_bytes()
                }),
            );
            val as u64
        }
        8 => {
            let val = *INTERESTING_U64.as_slice().choose(rng).unwrap();
            crate::utils::vec::fast_insert_at(
                input,
                offset,
                &(if big_endian {
                    val.to_be_bytes()
                } else {
                    val.to_le_bytes()
                }),
            );
            val as u64
        }
        _ => unreachable!(),
    };

    Some((offset, size as u8, val as u64))
}

/// Sets a random slice in the input to a random byte (ala memset)
pub fn set_slice<T: AsMut<[u8]>>(
    input: &mut T,
    rng: &mut impl rand::Rng,
) -> Option<(isize, usize, u8)> {
    let input = input.as_mut();
    if input.len() < 4 {
        return None;
    }

    // Pre-compute random numbers to avoid borrowing from the &mut fuzzer
    #[allow(clippy::cast_possible_wrap)]
    let dst = rng.gen_range(0isize..(input.len() as isize));

    // Get the maximum slice that is not out of bounds
    let max_len = input.len() - usize::try_from(dst).ok()?;

    // Randomly choose a length of slice to copy that is in bounds
    let len = rng.gen_range(0..max_len);
    let val: u8 = rng.gen();

    // Copy the slice internally
    // SAFETY: dst offset is within the bounds of input
    unsafe {
        std::ptr::write_bytes(input.as_mut_ptr().offset(dst), val, len);
    }

    Some((dst, len, val))
}

/// Overwrite data at random offset with a value from the dictionary.
pub fn overwrite_from_dictionary<T: AsMut<[u8]>>(
    input: &mut T,
    rng: &mut impl rand::Rng,
    dictionary: &[Vec<u8>],
) -> Option<(usize, usize)> {
    if dictionary.is_empty() {
        return None;
    }
    let input = input.as_mut();
    let dict_index = rng.gen_range(0..dictionary.len());
    // Get the dictionary element to insert
    let element = &dictionary[dict_index];
    let element_len = element.len();

    if element_len > input.len() {
        return None;
    }
    if element_len == input.len() {
        input.copy_from_slice(element);
        return Some((0, element_len));
    }

    let input_offset = rng.gen_range(0..(input.len() - element_len));
    // Splice the dictionary entry
    input[input_offset..input_offset + element_len].copy_from_slice(element);

    Some((input_offset, dict_index))
}

/// helper to splice data within a vector.
#[inline]
pub fn splice_within<T: AsMut<[u8]>>(
    input: &mut T,
    rng: &mut impl rand::Rng,
) -> Option<(isize, isize, usize)> {
    crate::mutators::helpers::splice_within(input, rng)
}

/// Copy a random sub-slice from `src` into a random subslice of `dst`.
/// This will potentially grow or shrink the destination vector.
#[inline]
pub fn splice_bytes_extend(
    dst: &mut Vec<u8>,
    src: &[u8],
    rng: &mut impl rand::Rng,
) -> Option<(std::ops::Range<usize>, std::ops::Range<usize>)> {
    crate::mutators::helpers::splice_extend(dst, src, rng)
}

/// Copy sub-slice from another byte slice into the current one.
#[inline]
pub fn splice_other_inplace<T: AsMut<[u8]>, S: AsRef<[u8]>>(
    input: &mut T,
    other: &S,
    rng: &mut impl rand::Rng,
) -> Option<(usize, usize, usize)> {
    crate::mutators::helpers::splice_other_inplace(input, other, rng)
}
