//! Text mutators.

#![allow(missing_docs)]
#![allow(dead_code)]

use std::sync::Arc;

use rand::seq::SliceRandom;
use rand::Rng as _;

use crate::fuzz_input::InputWithMetadata;
use crate::input_types::TextInput;
use crate::rng::Rng;
use crate::utils;

pub mod helpers;

/// Replace a random byte in the input.
pub fn char_replace(
    input: &mut TextInput,
    _corpus: &[Arc<InputWithMetadata<TextInput>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    let (idx, r) = helpers::char_replace(&mut input.data, rng)?;
    Some(format!("ByteReplace_offset_{idx}_val_{r:x}"))
}

/// Insert a random string.
pub fn insert_random_string<const N: usize>(
    input: &mut TextInput,
    _corpus: &[Arc<InputWithMetadata<TextInput>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    let s = helpers::random_ascii_string(rng, N);
    if input.is_empty() {
        input.data_mut().extend_from_slice(s.as_bytes());
        Some(format!("InsertRandom_offset_0_len_{}", s.len()))
    } else {
        let idx = rng.gen_range(0..=input.len());
        utils::vec::fast_insert_at(input.data_mut(), idx, s.as_bytes());
        Some(format!("InsertRandom_offset_{}_len_{}", idx, s.len()))
    }
}

/// Insert repeated a randomly chosen repeated char (up to N times).
pub fn insert_repeated_chars<const N: usize>(
    input: &mut TextInput,
    _corpus: &[Arc<InputWithMetadata<TextInput>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    let (offset, c, len) = helpers::insert_repeated_chars::<N>(input.data_mut(), rng)?;
    Some(format!("InsertRepeated_{c:x}_len_{len}_offset_{offset}"))
}

/// Insert another corpus entry as a whole into the current input at a given separator.
pub fn insert_from_corpus_separated_by<const C: char>(
    input: &mut TextInput,
    corpus: &[Arc<InputWithMetadata<TextInput>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    if corpus.len() < 2 {
        return None;
    }
    // select another corpus item != the current one - we require that there are at least two corpus
    // entries so we know this doesn't loop endlessly.
    let other = loop {
        let other = corpus.choose(rng).unwrap();
        if other.data().as_ptr() != input.data().as_ptr() {
            break other;
        }
    };

    let index = helpers::insert_separated(input.data_mut(), C, &other.data(), rng)?;

    Some(format!("InsertFromCorpus_at_{index}"))
}

/// Insert from dictionary at a given separator.
pub fn insert_from_dictionary_separated_by<const C: char>(
    input: &mut TextInput,
    _corpus: &[Arc<InputWithMetadata<TextInput>>],
    rng: &mut Rng,
    dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    if let Some((dict_idx, offset)) = helpers::insert_from_dictionary_at_const_separator::<C>(
        input.data_mut(),
        rng,
        dictionary.as_ref(),
    ) {
        let sep: u8 = C.try_into().unwrap();
        return Some(format!(
            "InsertFromDictAtSep_{sep:x}_dict_{dict_idx}_offset_{offset}"
        ));
    }

    None
}

/// Insert random dictionary entry into the text input.
pub fn insert_from_dictionary(
    input: &mut TextInput,
    _corpus: &[Arc<InputWithMetadata<TextInput>>],
    rng: &mut Rng,
    dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    if let Some(dictionary) = dictionary {
        if !dictionary.is_empty() {
            let dict_idx = rng.gen_range(0..dictionary.len());
            let entry = &dictionary[dict_idx];
            let index = rng.gen_range(0..=input.len());
            utils::vec::fast_insert_at(input.data_mut(), index, &entry[..]);
            return Some(format!("InsertFromDict_{dict_idx}_offset_{index}"));
        }
    }
    None
}

/// Splice random dictionary entry into the text input.
pub fn splice_from_dictionary(
    input: &mut TextInput,
    _corpus: &[Arc<InputWithMetadata<TextInput>>],
    rng: &mut Rng,
    dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    if let Some(dictionary) = dictionary {
        if !dictionary.is_empty() {
            let dict_idx = rng.gen_range(0..dictionary.len());
            let entry = &dictionary[dict_idx];
            let (dstr, srcr) =
                crate::mutators::bytes::helpers::splice_bytes_extend(input.data_mut(), entry, rng)?;
            return Some(format!(
                "SpliceFromDictionaryExtend_into_{}_{}_from_{}_{}_{}",
                dstr.start, dstr.end, dict_idx, srcr.start, srcr.end
            ));
        }
    }
    None
}

/// Identify and replace a integer in the text input with an interesting or random integer.
pub fn replace_integer(
    input: &mut TextInput,
    _corpus: &[Arc<InputWithMetadata<TextInput>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    if rng.gen_bool(0.75) {
        helpers::replace_integer_with_interesting(input.data_mut(), rng);
        Some("ReplaceIntegerWithInteresting".to_string())
    } else {
        helpers::replace_integer_with_rand(input.data_mut(), rng);
        Some("ReplaceIntegerWithRand".to_string())
    }
}

/// Identify and replace a hex integer in the text input with an interesting or random integer.
pub fn replace_hex_integer(
    input: &mut TextInput,
    _corpus: &[Arc<InputWithMetadata<TextInput>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    if rng.gen_bool(0.75) {
        helpers::replace_hex_integer_with_interesting(input.data_mut(), rng);
        Some("ReplaceHexIntegerWithInteresting".to_string())
    } else {
        helpers::replace_hex_integer_with_rand(input.data_mut(), rng);
        Some("ReplaceHexIntegerWithRand".to_string())
    }
}

/// Copy random data inside of the input to another place in the input.
pub fn splice_within(
    input: &mut TextInput,
    _corpus: &[Arc<InputWithMetadata<TextInput>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    let (src, dst, len) = crate::mutators::bytes::helpers::splice_within(input.data_mut(), rng)?;
    Some(format!(
        "SpliceWithin_srcoffset_{src:#x}_dstoffset_{dst:#x}_len_{len:#x}"
    ))
}

/// duplicate content found between a separator
pub fn dup_between_separator<const C: char>(
    input: &mut TextInput,
    _corpus: &[Arc<InputWithMetadata<TextInput>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    let (start, end) = helpers::dup_between_separator(input.data_mut(), C, rng)?;
    let sep: u8 = C.try_into().unwrap();
    Some(format!("DupBetween_{sep:x}_{start}_{end}"))
}

/// remove content between a separator
pub fn delete_between_separator<const C: char>(
    input: &mut TextInput,
    _corpus: &[Arc<InputWithMetadata<TextInput>>],
    rng: &mut Rng,
    _dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    let (start, end) = helpers::dup_between_separator(input.data_mut(), C, rng)?;
    let sep: u8 = C.try_into().unwrap();
    Some(format!("DeleteBetween_{sep:x}_{start}_{end}"))
}

/// Treat text as bytes input and apply a bunch of mutations like it were a binary format.
pub fn havoc_as_bytes(
    input: &mut TextInput,
    corpus: &[Arc<InputWithMetadata<TextInput>>],
    rng: &mut Rng,
    dictionary: &Option<Vec<Vec<u8>>>,
) -> Option<String> {
    let max_mutations = 16;
    // find a second testcase except for the current one.
    let splice_with = if corpus.len() >= 2 {
        loop {
            let other = corpus.choose(rng).unwrap();
            if other.data().as_ptr() != input.data.as_ptr() {
                break Some(other.data());
            }
        }
    } else {
        None
    };
    let res = crate::mutators::havoc::mutate_vec(
        input.data_mut(),
        dictionary.as_ref(),
        splice_with,
        max_mutations,
        rng,
    )?;
    let mut log = "HavocAsBytes_".to_string();
    for mutation in res.into_iter() {
        log.push_str(mutation.as_str());
        log.push('_');
    }
    Some(log)
}

// pub fn mutate_delimited_data(
//     input: &mut String,
//     _corpus: &[String],
//     rng: &mut Rng,
//     _dictionary: &Option<Vec<Vec<u8>>>,
// ) -> Option<String> {
//     let params = input
//         .char_indices()
//         .filter_map(|(i, c)| {
//             if let Some((delim, direction)) = other_delimiter(c) {
//                 Some((i, c, delim, direction))
//             } else {
//                 None
//             }
//         })
//         .choose(rng);
//     if let Some((index, first, second, direction)) = params {
//         // let's find the second delimiter
//         let (start_idx, end_idx) = if direction == DelimiterDirection::Forward {
//             unimplemented!();
//         } else {
//             unimplemented!();
//         };
//
//         // TODO: add mutation log
//         None
//     } else {
//         None
//     }
// }
