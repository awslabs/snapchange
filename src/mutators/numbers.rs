//! mutation functions for numbers and arrays of numbers.

use num_traits::{
    FromPrimitive, Num, PrimInt, WrappingAdd, WrappingMul, WrappingNeg, WrappingShl, WrappingShr,
    WrappingSub,
};

/// Trait used to summarize needed supertraits for fuzzing primitive numbers
pub trait FuzzNum:
    Copy
    + Clone
    + Sized
    + Num
    + WrappingAdd
    + WrappingSub
    + WrappingNeg
    + WrappingMul
    + WrappingShl
    + WrappingShr
    + PrimInt
    + FromPrimitive
{
    /// create a number for a byteslice using little-endian byteorder
    ///
    /// ```rust
    /// # use snapchange::mutators::numbers::FuzzNum;
    ///
    /// assert_eq!(0x12345678u32, u32::from_le_byteslice(&[0x78, 0x56, 0x34, 0x12]));
    /// assert_eq!(0x12345678u32, u32::from_le_byteslice(&[0x78, 0x56, 0x34, 0x12, 0x00, 0x00]));
    /// assert_eq!(0x12345678u64, u64::from_le_byteslice(&[0x78, 0x56, 0x34, 0x12, 0x00, 0x00]));
    /// assert_eq!(0xff_u8, u8::from_le_byteslice(&[0xff, 0x00, 0x00]));
    /// assert_eq!(0_u8, u8::from_le_byteslice(&[]));
    /// assert_eq!(-1_i8, i8::from_le_byteslice(&[0xff, 0x00, 0x00]));
    /// assert_eq!(-1_i16, i16::from_le_byteslice(&[0xff, 0xff]));
    /// ```
    fn from_le_byteslice<B: AsRef<[u8]>>(bytes: B) -> Self {
        let mut res = Self::zero();
        let byte_count = res.count_zeros() / 8;
        for (byte, byte_index) in bytes.as_ref().iter().copied().zip(0..byte_count) {
            let shift_by = byte_index * 8;
            res = res | Self::from_u8(byte).unwrap().wrapping_shl(shift_by)
        }
        res
    }

    /// create a number for a byteslice using big-endian byteorder
    ///
    /// ```rust
    /// # use snapchange::mutators::numbers::FuzzNum;
    ///
    /// assert_eq!(0x12345678u32, u32::from_be_byteslice(&[0x12, 0x34, 0x56, 0x78]), "u32 basic");
    /// assert_eq!(0x12345678u32, u32::from_be_byteslice(&[0x12, 0x34, 0x56, 0x78, 0x00, 0x00]), "u32 excess bytes");
    /// assert_eq!(0x12345678u64, u64::from_be_byteslice(&[0x00, 0x00, 0x12, 0x34, 0x56, 0x78]), "u64 lacking bytes");
    /// assert_eq!(-1_i16, i16::from_be_byteslice(&[0xff, 0xff]), "i16");
    /// assert_eq!(-1_i32, i32::from_be_byteslice(&[0xff, 0xff, 0xff, 0xff, 0x00]), "i32 excess bytes");
    /// ```
    fn from_be_byteslice<B: AsRef<[u8]>>(bytes: B) -> Self {
        let mut res = Self::zero();
        let bytes = bytes.as_ref();
        let byte_count = res.count_zeros() / 8;
        let until = std::cmp::min(byte_count as usize, bytes.len());
        for (byte, byte_index) in bytes[0..until]
            .iter()
            .copied()
            .zip((0..until).into_iter().rev())
        {
            let shift_by = byte_index * 8;
            res = res | Self::from_u8(byte).unwrap().wrapping_shl(shift_by as u32)
        }
        res
    }
}

impl FuzzNum for u8 {
    fn from_le_byteslice<B: AsRef<[u8]>>(bytes: B) -> Self {
        let bytes = bytes.as_ref();
        if bytes.is_empty() {
            0u8
        } else {
            bytes[0]
        }
    }

    fn from_be_byteslice<B: AsRef<[u8]>>(bytes: B) -> Self {
        Self::from_le_byteslice(bytes)
    }
}
impl FuzzNum for u16 {}
impl FuzzNum for u32 {}
impl FuzzNum for u64 {}
impl FuzzNum for i8 {
    fn from_le_byteslice<B: AsRef<[u8]>>(bytes: B) -> Self {
        let bytes = bytes.as_ref();
        if bytes.is_empty() {
            0i8
        } else {
            bytes[0] as Self
        }
    }

    fn from_be_byteslice<B: AsRef<[u8]>>(bytes: B) -> Self {
        Self::from_le_byteslice(bytes)
    }
}
impl FuzzNum for i16 {}
impl FuzzNum for i32 {}
impl FuzzNum for i64 {}

/// helpers for the mutation functions
pub mod helpers {
    use super::*;
    use crate::mutators::bytes::helpers::{
        INTERESTING_U16, INTERESTING_U32, INTERESTING_U64, INTERESTING_U8,
    };
    use rand::seq::{IteratorRandom, SliceRandom};

    /// mutate a primitive integer number once
    pub fn mutate_integer_once<T: FuzzNum>(
        input: &mut T,
        dictionary: Option<&Vec<Vec<u8>>>,
        splice_with: &mut Option<&T>,
        rng: &mut impl rand::Rng,
    ) -> Option<String>
    where
        rand::distributions::Standard: rand::distributions::Distribution<T>,
    {
        let bytelen: usize = std::mem::size_of_val(input);
        let bitlen: usize = bytelen * 8;
        let choice = rng.gen_range(0..=15);
        match choice {
            0 => {
                let bit_offset = bitlen - 1;
                *input = *input ^ (T::one() << bit_offset);
                Some("NumBitFlip".to_string())
            }
            1 => {
                *input = input.wrapping_add(&T::one());
                Some("NumAddOne".to_string())
            }
            2 => {
                *input = input.wrapping_sub(&T::one());
                Some("NumSubOne".to_string())
            }
            3 => {
                *input = input.wrapping_neg();
                Some("NumNeg".to_string())
            }
            4 => {
                *input = input.wrapping_shl(1);
                Some("NumShlOne".to_string())
            }
            5 => {
                *input = input.wrapping_shr(1);
                Some("NumShrOne".to_string())
            }
            6 => {
                match bitlen {
                    8 => *input = T::from_u8(*INTERESTING_U8.choose(rng).unwrap())?,
                    16 => *input = T::from_u16(*INTERESTING_U16.choose(rng).unwrap())?,
                    32 => *input = T::from_u32(*INTERESTING_U32.choose(rng).unwrap())?,
                    64 => *input = T::from_u64(*INTERESTING_U64.choose(rng).unwrap())?,
                    _ => return None,
                };
                Some("NumReplaceWithInteresting".to_string())
            }
            7 => {
                match bitlen {
                    8 => *input = *input ^ T::from_u8(*INTERESTING_U8.choose(rng).unwrap())?,
                    16 => *input = *input ^ T::from_u16(*INTERESTING_U16.choose(rng).unwrap())?,
                    32 => *input = *input ^ T::from_u32(*INTERESTING_U32.choose(rng).unwrap())?,
                    64 => *input = *input ^ T::from_u64(*INTERESTING_U64.choose(rng).unwrap())?,
                    _ => return None,
                };
                Some("NumXorWithInteresting".to_string())
            }
            8 => {
                match bitlen {
                    8 => {
                        *input =
                            input.wrapping_add(&(T::from_u8(*INTERESTING_U8.choose(rng).unwrap())?))
                    }
                    16 => {
                        *input = input
                            .wrapping_add(&(T::from_u16(*INTERESTING_U16.choose(rng).unwrap())?))
                    }
                    32 => {
                        *input = input
                            .wrapping_add(&(T::from_u32(*INTERESTING_U32.choose(rng).unwrap())?))
                    }
                    64 => {
                        *input = input
                            .wrapping_add(&(T::from_u64(*INTERESTING_U64.choose(rng).unwrap())?))
                    }
                    _ => return None,
                };
                Some("NumAddInteresting".to_string())
            }
            9 => {
                let other: T = rng.gen();
                *input = input.wrapping_add(&other);
                Some("NumAddRand".to_string())
            }
            10 => {
                let other: T = rng.gen();
                *input = *input ^ other;
                Some("NumXorRand".to_string())
            }
            11 => match splice_with.take() {
                Some(&other) => {
                    *input = input.wrapping_add(&other);
                    Some("NumAddSplice".to_string())
                }
                None => None,
            },
            12 => match splice_with.take() {
                Some(&other) => {
                    *input = (*input) ^ other;
                    Some("NumXorSplice".to_string())
                }
                None => None,
            },
            13 | 14 | 15 => match dictionary {
                Some(dictionary) => {
                    if dictionary.is_empty() {
                        return None;
                    }
                    let other = dictionary
                        .iter()
                        .filter(|entry| entry.len() <= bytelen)
                        .choose(rng)?;
                    let mut other_bytes = vec![0u8; bytelen];
                    let other: T = if rng.gen_bool(0.5) {
                        let start = bytelen - other.len();
                        other_bytes[start..].copy_from_slice(&other);
                        T::from_be_byteslice(&other_bytes)
                    } else {
                        other_bytes[0..other.len()].copy_from_slice(&other);
                        T::from_le_byteslice(&other_bytes)
                    };
                    match choice {
                        13 => {
                            *input = other;
                            Some("NumReplDict".to_string())
                        }
                        14 => {
                            *input = input.wrapping_add(&other);
                            Some("NumAddDict".to_string())
                        }
                        15 => {
                            *input = *input ^ other;
                            Some("NumXorDict".to_string())
                        }
                        _ => unreachable!(),
                    }
                }
                None => None,
            },
            _ => unreachable!(),
        }
    }
}
