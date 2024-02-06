//! Several helper functions that can be utilized by custom mutators to mutate raw byte or text
//! strings using snapchange's default mutation operations.

use rand::seq::SliceRandom;

use crate::mutators::bytes;
use crate::mutators::helpers::{splice_extend, splice_other_inplace, splice_within};
use crate::mutators::numbers::{self, FuzzNum};
use crate::mutators::text;

/// Mutate a byte buffer using up to `max_mutations` mutation operators. The input is
/// potentially resized during mutation (leading to longer mutation time).
pub fn mutate_vec(
    input: &mut Vec<u8>,
    dictionary: Option<&Vec<Vec<u8>>>,
    mut splice_with: Option<&[u8]>,
    max_mutations: usize,
    rng: &mut impl rand::Rng,
) -> Option<Vec<String>> {
    if max_mutations == 0 {
        return None;
    }
    if input.is_empty() {
        return None;
    }
    let num_mutations = (rng.gen_range(1..=max_mutations)) as u32;
    let mut mutated = 0_u32;
    let mut tries = 0_u32;
    let mut mutation_log = vec![];
    while mutated < num_mutations {
        tries += 1;
        if tries >= (max_mutations as u32) * 3 {
            // input is probably not suitable for mutation (e.g., to small) - bail out.
            log::debug!(
                "attempted {} mutations, only {} succeeded, goal {}",
                tries,
                mutated,
                num_mutations
            );
            break;
        }
        let choice = rng.gen_range(0_u32..=10);
        let log_str = match choice {
            0 => {
                if mutated > 0 {
                    break;
                } else {
                    continue;
                }
            }
            1..=5 => {
                match mutate_inplace(
                    input,
                    dictionary,
                    splice_with,
                    max_mutations
                        .saturating_sub(mutated as usize)
                        .saturating_sub(1),
                    rng,
                ) {
                    Some(log) => {
                        mutated += log.len() as u32;
                        mutation_log.extend(log.into_iter());
                        continue;
                    }
                    None => continue,
                }
            }
            6 => {
                if let Some((offset, rand_byte)) = bytes::helpers::byte_insert(input, rng) {
                    format!("ByteInsert_offset_{offset:#x}_byte_{rand_byte:#x}")
                } else {
                    continue;
                }
            }
            7 => {
                if let Some(offset) = bytes::helpers::byte_delete(input, rng) {
                    format!("ByteDelete_offset_{offset:#x}")
                } else {
                    continue;
                }
            }
            8 => {
                if let Some((offset, size, _val)) =
                    bytes::helpers::insert_interesting_integer(input, rng)
                {
                    let bits = size / 8;
                    format!("InsertInteresting_u{bits}_offset_{offset}")
                } else {
                    continue;
                }
            }
            9 => match splice_with.take() {
                // we use take here to splice only once
                Some(other) => {
                    if other.is_empty() || input.is_empty() {
                        continue;
                    }
                    if let Some((dstr, srcr)) = splice_extend(input, other, rng) {
                        format!(
                            "SpliceBytesExtend_into_{}_{}_from_{}_{}",
                            dstr.start, dstr.end, srcr.start, srcr.end
                        )
                    } else {
                        continue;
                    }
                }
                _ => continue,
            },
            10 => match dictionary {
                Some(dictionary) => {
                    if dictionary.is_empty() {
                        continue;
                    }
                    let dict_idx = rng.gen_range(0..dictionary.len());
                    let other = &dictionary[dict_idx];
                    if other.is_empty() {
                        continue;
                    }
                    if input.is_empty() {
                        input.extend_from_slice(other);
                        format!(
                            "SpliceDictionaryExtend_into_{}_{}_from_{}_{}_{}",
                            0,
                            0,
                            dict_idx,
                            0,
                            other.len()
                        )
                    } else {
                        if let Some((dstr, srcr)) =
                            bytes::helpers::splice_bytes_extend(input, other, rng)
                        {
                            format!(
                                "SpliceDictionaryExtend_into_{}_{}_from_{}_{}_{}",
                                dstr.start, dstr.end, dict_idx, srcr.start, srcr.end
                            )
                        } else {
                            continue;
                        }
                    }
                }
                None => continue,
            },
            _ => unreachable!(),
        };

        mutation_log.push(log_str);
        mutated += 1;
    }

    if mutation_log.is_empty() {
        None
    } else {
        Some(mutation_log)
    }
}

/// Mutate a byte buffer using up to `max_mutations` mutation operators. The input is never
/// resized.
pub fn mutate_inplace<T: AsMut<[u8]>>(
    input: &mut T,
    dictionary: Option<&Vec<Vec<u8>>>,
    mut splice_with: Option<&[u8]>,
    max_mutations: usize,
    rng: &mut impl rand::Rng,
) -> Option<Vec<String>> {
    if max_mutations == 0 {
        return None;
    }
    let mut input = input.as_mut();
    if input.is_empty() {
        return None;
    }
    let num_mutations = (rng.gen_range(1..=max_mutations)) as u32;
    let mut mutated = 0_u32;
    let mut tries = 0_u32;
    let mut mutation_log = vec![];
    while mutated < num_mutations {
        tries += 1;
        if tries >= (max_mutations as u32) * 3 {
            // input is probably not suitable for mutation (e.g., to small) - bail out.
            log::debug!(
                "attempted {} mutations, only {} succeeded, goal {}",
                tries,
                mutated,
                num_mutations
            );
            break;
        }
        let choice = rng.gen_range(0_u32..=14);
        let log_str = match choice {
            0 => {
                if mutated > 0 {
                    break;
                } else {
                    continue;
                }
            }
            1 | 2 => match bytes::helpers::bit_flip(&mut input, rng) {
                Some((byte_offset, bit_offset)) => {
                    format!("BitFlip_offset_{byte_offset:#x}_bit_{bit_offset:#x}")
                }
                None => continue,
            },
            3 | 4 => match bytes::helpers::byte_flip(&mut input, rng) {
                Some((offset, rand_byte)) => {
                    format!("ByteFlip_offset_{offset:#x}_byte_{rand_byte:#x}")
                }
                None => continue,
            },
            5 => match bytes::helpers::inc(&mut input, rng) {
                Some(offset) => format!("ByteInc_offset_{offset:#x}"),
                _ => continue,
            },
            6 => match bytes::helpers::dec(&mut input, rng) {
                Some(offset) => format!("ByteDec_offset_{offset:#x}"),
                _ => continue,
            },
            7 => match bytes::helpers::set_random_word(&mut input, rng) {
                Some((offset, size, val)) => {
                    let bits = size / 8;
                    format!("SetRandom_u{bits}_{offset:#x}_val_{val:#x}")
                }
                _ => continue,
            },
            8 => match bytes::helpers::set_slice(&mut input, rng) {
                Some((offset, size, val)) => {
                    format!("SetSlice_{offset:#x}_len_{size}_val_{val:#x}")
                }
                _ => continue,
            },
            9 | 10 => match bytes::helpers::replace_with_interesting_integer(&mut input, rng) {
                Some((offset, size, val)) => {
                    let bits = size / 8;
                    format!("InterestingVal_{offset:#x}_u{bits}_val_{val:#x}")
                }
                None => continue,
            },
            11 | 12 => match dictionary {
                Some(dict) => {
                    match bytes::helpers::overwrite_from_dictionary(&mut input, rng, dict) {
                        Some((input_offset, element)) => {
                            format!("OverwriteFromDictionary_offset_{input_offset:#x}_{element:x?}")
                        }
                        None => continue,
                    }
                }
                None => continue,
            },
            13 => {
                if input.len() > 8 {
                    if let Some((src, dst, len)) = splice_within(&mut input, rng) {
                        format!("SpliceWithin_srcoffset_{src:#x}_dstoffset_{dst:#x}_len_{len:#x}")
                    } else {
                        continue;
                    }
                } else {
                    continue;
                }
            }
            14 => {
                match splice_with.take() {
                    // we use take here to splice only once
                    Some(other) => match splice_other_inplace(&mut input, &other, rng) {
                        Some((input_offset, other_offset, len)) => {
                            format!("SpliceOther_at_{input_offset}_from_{other_offset}_len_{len}")
                        }
                        None => continue,
                    },
                    _ => continue,
                }
            }
            _ => unreachable!(),
        };
        mutation_log.push(log_str);
        mutated += 1;
    }

    if mutation_log.is_empty() {
        None
    } else {
        Some(mutation_log)
    }
}

/// Mutate a string using up to `max_mutations` mutation operators. The input is never
/// resized.
pub fn mutate_text_vec(
    input: &mut Vec<u8>,
    dictionary: Option<&Vec<Vec<u8>>>,
    splice_with: Option<&[u8]>,
    max_mutations: usize,
    rng: &mut impl rand::Rng,
) -> Option<Vec<String>> {
    if max_mutations == 0 {
        return None;
    }
    if input.is_empty() {
        return None;
    }
    let num_mutations = (rng.gen_range(1..=max_mutations)) as u32;
    let mut mutated = 0_u32;
    let mut tries = 0_u32;
    let mut mutation_log = vec![];
    while mutated < num_mutations {
        tries += 1;
        if tries >= (max_mutations as u32) * 3 {
            // input is probably not suitable for mutation (e.g., to small) - bail out.
            log::debug!(
                "attempted {} mutations, only {} succeeded, goal {}",
                tries,
                mutated,
                num_mutations
            );
            break;
        }
        let choice = rng.gen_range(0_u32..=24);
        let log_str = match choice {
            0 => {
                if mutated > 0 {
                    break;
                } else {
                    continue;
                }
            }
            1..6 => {
                match mutate_inplace(
                    input,
                    dictionary,
                    splice_with,
                    max_mutations
                        .saturating_sub(mutated as usize)
                        .saturating_sub(2),
                    rng,
                ) {
                    Some(log) => {
                        mutated += log.len() as u32;
                        mutation_log.extend(log.into_iter());
                        continue;
                    }
                    None => continue,
                }
            }
            6..8 => {
                match mutate_vec(
                    input,
                    dictionary,
                    splice_with,
                    max_mutations
                        .saturating_sub(mutated as usize)
                        .saturating_sub(2),
                    rng,
                ) {
                    Some(log) => {
                        mutated += log.len() as u32;
                        mutation_log.extend(log.into_iter());
                        continue;
                    }
                    None => continue,
                }
            }
            8 => {
                if rng.gen_bool(0.8) {
                    match text::helpers::replace_integer_with_interesting(input, rng) {
                        Some(range) => {
                            let start = range.start;
                            let end = range.end;
                            format!("ReplaceIntegerWithInteresting_at_{start}_{end}")
                        }
                        None => continue,
                    }
                } else {
                    match text::helpers::replace_hex_integer_with_interesting(input, rng) {
                        Some(range) => {
                            let start = range.start;
                            let end = range.end;
                            format!("ReplaceHexIntegerWithInteresting_at_{start}_{end}")
                        }
                        None => continue,
                    }
                }
            }
            9 => {
                if rng.gen_bool(0.8) {
                    match text::helpers::replace_integer_with_rand(input, rng) {
                        Some(range) => {
                            let start = range.start;
                            let end = range.end;
                            format!("ReplaceIntegerWithRand_at_{start}_{end}")
                        }
                        None => continue,
                    }
                } else {
                    match text::helpers::replace_hex_integer_with_rand(input, rng) {
                        Some(range) => {
                            let start = range.start;
                            let end = range.end;
                            format!("ReplaceHexIntegerWithRand_at_{start}_{end}")
                        }
                        None => continue,
                    }
                }
            }
            10 | 11 | 12 => match text::helpers::char_replace(input, rng) {
                Some((offset, val)) => {
                    format!("CharReplace_at_{offset}_with_{val:x}")
                }
                None => continue,
            },
            13 => match text::helpers::insert_random_string::<4>(input, rng) {
                Some((offset, len)) => {
                    format!("InsertRandomString_offset_{offset}_len_{len}")
                }
                None => continue,
            },
            14 => match text::helpers::insert_random_string::<8>(input, rng) {
                Some((offset, len)) => {
                    format!("InsertRandomString_offset_{offset}_len_{len}")
                }
                None => continue,
            },
            15 => match text::helpers::insert_random_string::<128>(input, rng) {
                Some((offset, len)) => {
                    format!("InsertRandomString_offset_{offset}_len_{len}")
                }
                None => continue,
            },
            16 => match text::helpers::insert_repeated_chars::<4>(input, rng) {
                Some((offset, len, val)) => {
                    format!("InsertRepeatedChars_offset_{offset}_len_{len}_val_{val:x}")
                }
                None => continue,
            },
            17 => match text::helpers::insert_repeated_chars::<1024>(input, rng) {
                Some((offset, len, val)) => {
                    format!("InsertRepeatedChars_offset_{offset}_len_{len}_val_{val:x}")
                }

                None => continue,
            },
            18 | 19 | 20 | 21 => match dictionary {
                Some(dictionary) => {
                    if dictionary.is_empty() {
                        continue;
                    }
                    let dict_idx = rng.gen_range(0..dictionary.len());
                    let other = &dictionary[dict_idx];
                    // validity check
                    if other.is_empty() || other.as_ptr() == input.as_ptr() {
                        continue;
                    }
                    if input.is_empty() {
                        input.extend_from_slice(other);
                        format!(
                            "SpliceDictionaryExtend_into_{}_{}_from_{}_{}_{}",
                            0,
                            0,
                            dict_idx,
                            0,
                            other.len()
                        )
                    } else {
                        if let Some((dstr, srcr)) = splice_extend(input, other, rng) {
                            format!(
                                "SpliceDictionaryExtend_into_{}_{}_from_{}_{}_{}",
                                dstr.start, dstr.end, dict_idx, srcr.start, srcr.end
                            )
                        } else {
                            continue;
                        }
                    }
                }
                None => continue,
            },
            22 | 23 | 24 => {
                if let Some((src, dst, len)) = splice_within(input, rng) {
                    format!("SpliceWithin_srcoffset_{src:#x}_dstoffset_{dst:#x}_len_{len:#x}")
                } else {
                    continue;
                }
            }
            _ => unreachable!(),
        };

        mutation_log.push(log_str);
        mutated += 1;
    }

    if mutation_log.is_empty() {
        None
    } else {
        Some(mutation_log)
    }
}

/// Mutate a string using up to `max_mutations` mutation operators. The input is never
/// resized.
pub fn mutate_string(
    input: &mut String,
    dictionary: Option<&Vec<Vec<u8>>>,
    splice_with: Option<&str>,
    max_mutations: usize,
    rng: &mut impl rand::Rng,
) -> Option<Vec<String>> {
    if max_mutations == 0 {
        return None;
    }
    // SAFETY: this is safe, as we will not use the original string. instead we replace it with
    // the String returned by `from_utf8_lossy` below.
    let mut vec = unsafe { input.as_mut_vec() };
    let log = mutate_text_vec(
        &mut vec,
        dictionary,
        splice_with.map(|v| v.as_bytes()),
        max_mutations,
        rng,
    );
    *input = String::from_utf8_lossy(&vec).to_string();
    log
}

/// Mutate a primitive integer number
pub fn mutate_number<T: FuzzNum>(
    input: &mut T,
    dictionary: Option<&Vec<Vec<u8>>>,
    mut splice_with: Option<&T>,
    max_mutations: usize,
    rng: &mut impl rand::Rng,
) -> Option<Vec<String>>
where
    rand::distributions::Standard: rand::distributions::Distribution<T>,
{
    if max_mutations == 0 {
        return None;
    }
    let mut mutation_log: Vec<String> = vec![];

    let num_mutations = (rng.gen_range(1..=max_mutations)) as u32;
    let mut mutated = 0_u32;
    let mut tries = 0_u32;

    while mutated < num_mutations {
        tries += 1;
        if tries >= (max_mutations as u32) * 3 {
            // input is probably not suitable for mutation (e.g., to small) - bail out.
            log::debug!(
                "attempted {} mutations, only {} succeeded, goal {}",
                tries,
                mutated,
                num_mutations
            );
            break;
        }
        if let Some(log_str) =
            numbers::helpers::mutate_integer_once(input, dictionary, &mut splice_with, rng)
        {
            mutation_log.push(log_str);
            mutated += 1;
        }
    }

    if mutation_log.is_empty() {
        None
    } else {
        Some(mutation_log)
    }
}

/// mutate an array/slice of numbers
pub fn mutate_number_array<T: FuzzNum>(
    input: &mut [T],
    dictionary: Option<&Vec<Vec<u8>>>,
    splice_with: Option<&[T]>,
    max_mutations: usize,
    rng: &mut impl rand::Rng,
) -> Option<Vec<String>>
where
    rand::distributions::Standard: rand::distributions::Distribution<T>,
{
    if max_mutations == 0 {
        return None;
    }
    if input.is_empty() {
        return None;
    }
    let mut mutation_log: Vec<String> = vec![];

    let num_mutations = (rng.gen_range(1..=max_mutations)) as u32;
    let mut mutated = 0_u32;
    let mut tries = 0_u32;
    let mut splice_with = splice_with.map_or(None, |s| s.choose(rng));

    while mutated < num_mutations {
        tries += 1;
        if tries >= (max_mutations as u32) * 3 {
            // input is probably not suitable for mutation (e.g., to small) - bail out.
            log::debug!(
                "attempted {} mutations, only {} succeeded, goal {}",
                tries,
                mutated,
                num_mutations
            );
            break;
        }

        if let Some(target) = input.choose_mut(rng) {
            if let Some(log_str) =
                numbers::helpers::mutate_integer_once(target, dictionary, &mut splice_with, rng)
            {
                mutation_log.push(log_str);
                mutated += 1;
            }
        }
    }

    if mutation_log.is_empty() {
        None
    } else {
        Some(mutation_log)
    }
}

/// mutate a `Vec<T>` where `T` is a primitive integer number.
pub fn mutate_number_vec<T: FuzzNum>(
    input: &mut Vec<T>,
    dictionary: Option<&Vec<Vec<u8>>>,
    mut splice_with: Option<&[T]>,
    max_mutations: usize,
    rng: &mut impl rand::Rng,
) -> Option<Vec<String>>
where
    rand::distributions::Standard: rand::distributions::Distribution<T>,
{
    if max_mutations == 0 {
        return None;
    }
    if input.is_empty() {
        return None;
    }

    let num_mutations = (rng.gen_range(1..=max_mutations)) as u32;
    let mut mutated = 0_u32;
    let mut tries = 0_u32;
    let mut mutation_log = vec![];
    while mutated < num_mutations {
        tries += 1;
        if tries >= (max_mutations as u32) * 3 {
            // input is probably not suitable for mutation (e.g., to small) - bail out.
            log::debug!(
                "attempted {} mutations, only {} succeeded, goal {}",
                tries,
                mutated,
                num_mutations
            );
            break;
        }

        let choice = rng.gen_range(0_u32..10);
        let log_str = match choice {
            0 => match splice_with.take() {
                Some(other) => {
                    if let Some((dstr, srcr)) = splice_extend(input, other, rng) {
                        format!(
                            "SpliceBytesExtend_into_{}_{}_from_{}_{}",
                            dstr.start, dstr.end, srcr.start, srcr.end
                        )
                    } else {
                        continue;
                    }
                }
                None => continue,
            },
            1 => {
                match splice_with.take() {
                    Some(other) => {
                        if let Some((input_offset, other_offset, length)) =
                            splice_other_inplace(input, &other, rng)
                        {
                            format!("SpliceInplace_offset_{input_offset}_other_{other_offset}_len_{length}")
                        } else {
                            continue;
                        }
                    }
                    None => continue,
                }
            }
            2 => {
                if let Some((src, dst, len)) = splice_within(input, rng) {
                    format!("SpliceWithin_srcoffset_{src:#x}_dstoffset_{dst:#x}_len_{len:#x}")
                } else {
                    continue;
                }
            }
            _ => {
                if let Some(target) = input.choose_mut(rng) {
                    let mut splice_with = splice_with.map_or(None, |s| s.choose(rng));
                    if let Some(log_str) = numbers::helpers::mutate_integer_once(
                        target,
                        dictionary,
                        &mut splice_with,
                        rng,
                    ) {
                        log_str
                    } else {
                        continue;
                    }
                } else {
                    continue;
                }
            }
        };

        mutation_log.push(log_str);
        mutated += 1;
    }

    if mutation_log.is_empty() {
        None
    } else {
        Some(mutation_log)
    }
}
