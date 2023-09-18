//! Provides structs and procedures for this Redqueen implementation

use std::ops::Add;

use anyhow::Result;
use iced_x86::Register as IcedRegister;
use serde::{Deserialize, Serialize};

use crate::addrs::VirtAddr;
use crate::fuzz_input::FuzzInput;
use crate::fuzzer::Fuzzer;
use crate::regs::x86;
use crate::Execution;
use crate::FuzzVm;

/// A replacement rule for cmp analysis
///
/// When applying a replacement rule during mutation, if the left value is
/// found in the input, replace it with the right. And also replace the
#[derive(Debug, Clone, Eq, Ord, PartialOrd, PartialEq)]
pub enum RedqueenRule {
    /// Replace one u8 with another
    SingleU8(u8, u8),
    /// Replace one u16 with another
    SingleU16(u16, u16),
    /// Replace one u32 with another
    SingleU32(u32, u32),
    /// Replace one u64 with another
    SingleU64(u64, u64),
    /// Replace one u128 with another
    SingleU128(u128, u128),
    /// Replace one f32 with another
    SingleF32(Vec<u8>, Vec<u8>),
    /// Replace one f64 with another
    SingleF64(Vec<u8>, Vec<u8>),
    /// Replace one set of bytes for another
    Bytes(Vec<u8>, Vec<u8>),
}

/// The arguments used to describe a redqueen breakpoint
#[derive(Debug, Copy, Clone)]
pub struct RedqueenArguments {
    /// Number of bytes compared in this rule
    pub size: Size,

    /// The comparison operation for this rule
    pub operation: Operation,

    /// Left operand
    pub left_op: Operand,

    /// Right operand
    pub right_op: Operand,
}

/// The size of the comparison for this rule
#[derive(Debug, Clone, Copy, Eq, Ord, PartialOrd, PartialEq)]
pub enum Size {
    /// Comparing 1 byte
    U8,
    /// Comparing 2 bytes
    U16,
    /// Comparing 4 bytes
    U32,
    /// Comparing 8 bytes
    U64,
    /// Comparing 16 bytes
    U128,
    /// Comparing 4 bytes as an f32
    F32,
    /// Comparing 8 bytes as an f64
    F64,
    /// Comparing a sequence of bytes
    Bytes,
}

/// Comparison operations
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialOrd, PartialEq)]
pub enum Operation {
    /// ==
    Equal,
    /// !=
    NotEqual,
    /// s<
    SignedLessThan,
    /// u<
    UnsignedLessThan,
    /// s<=
    SignedLessThanEqual,
    /// u<=
    UnsignedLessThanEqual,
    /// s>
    SignedGreaterThan,
    /// u>
    UnsignedGreaterThan,
    /// s>=
    SignedGreaterThanEqual,
    /// u>=
    UnsignedGreaterThanEqual,

    /// == for floats
    FloatingPointEqual,
    /// != for floats
    FloatingPointNotEqual,
    /// < for floats
    FloatingPointLessThan,
    /// <= for floats
    FloatingPointLessThanEqual,
    /// > for floats
    FloatingPointGreaterThan,
    /// >= for floats
    FloatingPointGreaterThanEqual,

    /// Special case for strcmp
    Strcmp,

    /// Special case for memcmp
    Memcmp,
}

impl From<&str> for Operation {
    fn from(val: &str) -> Operation {
        match val {
            "CMP_E" => Operation::Equal,
            "CMP_NE" => Operation::NotEqual,
            "CMP_SLT" => Operation::SignedLessThan,
            "CMP_ULT" => Operation::UnsignedLessThan,
            "CMP_SLE" => Operation::SignedLessThanEqual,
            "CMP_ULE" => Operation::UnsignedLessThanEqual,
            "CMP_SGT" => Operation::SignedGreaterThan,
            "CMP_UGT" => Operation::UnsignedGreaterThan,
            "CMP_SGE" => Operation::SignedGreaterThanEqual,
            "CMP_UGE" => Operation::UnsignedGreaterThanEqual,
            "FCMP_E" => Operation::FloatingPointEqual,
            "FCMP_NE" => Operation::FloatingPointNotEqual,
            "FCMP_LT" => Operation::FloatingPointLessThan,
            "FCMP_LE" => Operation::FloatingPointLessThanEqual,
            "FCMP_GT" => Operation::FloatingPointGreaterThan,
            "FCMP_GE" => Operation::FloatingPointGreaterThanEqual,
            "strcmp" => Operation::Strcmp,
            "memcmp" => Operation::Memcmp,
            _ => unimplemented!("Unknown operation: {val}"),
        }
    }
}

/// Information on how to retrieve the left operand comparison value
#[derive(Debug, Clone, Copy, Eq, Ord, PartialOrd, PartialEq)]
pub enum Operand {
    /// A single register operand
    Register(IcedRegister),

    /// A constant u8
    ConstU8(u8),
    /// A constant u16
    ConstU16(u16),
    /// A constant u32
    ConstU32(u32),
    // Memory,
}

macro_rules! impl_read_for_type {
    ($func:ident, $ty:ty) => {
        /// Retrieve this operand from the current state of the FuzzVm
        pub fn $func<FUZZER: Fuzzer>(&self, fuzzvm: &mut FuzzVm<FUZZER>) -> $ty {
            match self {
                Operand::Register(reg) => fuzzvm.get_iced_reg(*reg) as $ty,
                Operand::ConstU32(val) => *val as $ty,
                _ => unimplemented!(),
            }
        }
    };
}

impl Operand {
    impl_read_for_type!(read_u8, u8);
    impl_read_for_type!(read_u16, u16);
    impl_read_for_type!(read_u32, u32);
    impl_read_for_type!(read_u64, u64);
    impl_read_for_type!(read_u128, u128);
    impl_read_for_type!(read_f32, f32);
    impl_read_for_type!(read_f64, f64);
}

/// Add a RedqueenRule for the given RedqueenArguments.
///
/// This will read the values needed to compare against and add a RedqueenRule to the
/// FuzzVm for the found values.
pub fn gather_comparison<FUZZER: Fuzzer>(
    fuzzvm: &mut FuzzVm<FUZZER>,
    input: &<FUZZER as Fuzzer>::Input,
    args: &RedqueenArguments,
) -> Result<Execution> {
    // Get the arguments for this redqueen breakpoints
    let RedqueenArguments {
        size,
        operation,
        left_op,
        right_op,
    } = args;

    macro_rules! impl_primitive_sizes {
        ($($size:ident, $ty:ty, $func:ident, $rule:ident),*) => {
            match size {
                $(
                    Size::$size => {
                        let left_val = left_op.$func(fuzzvm);
                        let right_val = right_op.$func(fuzzvm);
                        log::info!("{size:?} Left {left_val:x?} Right {right_val:x?}");

                        if left_val != right_val {

                            // Generate the rule to satisfy this comparison
                            let rule =  RedqueenRule::$rule(left_val, right_val);

                            // Only add this rule to the redqueen rules if the left operand
                            // is actually in the input
                            if input.get_redqueen_rule_candidates(&rule).len() > 0 {
                                let input_hash = crate::utils::calculate_hash(input);
                                log::info!("Inserting rule 1! {input_hash:#x} {rule:x?}");
                                fuzzvm.redqueen_rules.entry(input_hash).or_default().insert(rule);
                            }

                            // Generate the rule to satisfy this comparison
                            let rule = RedqueenRule::$rule(right_val, left_val);

                            // Only add this rule to the redqueen rules if the left operand
                            // is actually in the input
                            if input.get_redqueen_rule_candidates(&rule).len() > 0 {
                                let input_hash = crate::utils::calculate_hash(input);
                                log::info!("Inserting rule 2! {input_hash:#x} {rule:x?}");
                                fuzzvm.redqueen_rules.entry(input_hash).or_default().insert(rule);
                            }
                        } else {
                            // Generate the rule to satisfy this comparison by forcing the values
                            // to be different
                            let rule = RedqueenRule::$rule(left_val, right_val.wrapping_add(1));

                            // Only add this rule to the redqueen rules if the left operand
                            // is actually in the input
                            if input.get_redqueen_rule_candidates(&rule).len() > 0 {
                                let input_hash = crate::utils::calculate_hash(input);
                                log::info!("Inserting rule 3! {input_hash:#x} {rule:x?}");
                                fuzzvm.redqueen_rules.entry(input_hash).or_default().insert(rule);
                            }

                            // Generate the rule to satisfy this comparison
                            let rule = RedqueenRule::$rule(left_val.wrapping_add(1), right_val);

                            // Only add this rule to the redqueen rules if the left operand
                            // is actually in the input
                            if input.get_redqueen_rule_candidates(&rule).len() > 0 {
                                let input_hash = crate::utils::calculate_hash(input);
                                log::info!("Inserting rule 4! {input_hash:#x} {rule:x?}");
                                fuzzvm.redqueen_rules.entry(input_hash).or_default().insert(rule);
                            }
                       }
                    }
                )*
                Size::Bytes => {
                    let left_addr = left_op.read_u64(fuzzvm);
                    let right_addr = right_op.read_u64(fuzzvm);
                    let left_val = fuzzvm.read_bytes_until(VirtAddr(left_addr), fuzzvm.cr3(), 0, 0x4000)?;
                    let right_val = fuzzvm.read_bytes_until(VirtAddr(right_addr), fuzzvm.cr3(), 0, 0x4000)?;
                    if left_val != right_val {
                        panic!("Here");
                    }
                }
                _ => {
                    // Pass down to the float impls
                }
            }
        };
    }

    macro_rules! impl_float_sizes {
        ($($size:ident, $ty:ty, $func:ident, $rule:ident),*) => {
            match size {
                $(
                    Size::$size => {
                        let left_val = left_op.$func(fuzzvm);
                        let right_val = right_op.$func(fuzzvm);
                        log::info!("{size:?} Left {left_val:x?} Right {right_val:x?}");

                        if left_val != right_val {
                            // Generate the rule to satisfy this comparison
                            let rule =  RedqueenRule::$rule(left_val.to_le_bytes().to_vec(), right_val.to_le_bytes().to_vec());

                            // Only add this rule to the redqueen rules if the left operand
                            // is actually in the input
                            if input.get_redqueen_rule_candidates(&rule).len() > 0 {
                                let input_hash = crate::utils::calculate_hash(input);
                                log::info!("Inserting rule! {input_hash:#x} {rule:x?}");
                                fuzzvm.redqueen_rules.entry(input_hash).or_default().insert(rule);
                            }

                            // Generate the rule to satisfy this comparison
                            let rule = RedqueenRule::$rule(right_val.to_le_bytes().to_vec(), left_val.to_le_bytes().to_vec());

                            // Only add this rule to the redqueen rules if the left operand
                            // is actually in the input
                            if input.get_redqueen_rule_candidates(&rule).len() > 0 {
                                let input_hash = crate::utils::calculate_hash(input);
                                log::info!("Inserting rule! {input_hash:#x} {rule:x?}");
                                fuzzvm.redqueen_rules.entry(input_hash).or_default().insert(rule);
                            }
                        } else {
                            // Generate the rule to satisfy this comparison by forcing the values
                            // to be different
                            let rule = RedqueenRule::$rule(left_val.to_le_bytes().to_vec(), right_val.add(1.0).to_le_bytes().to_vec());

                            // Only add this rule to the redqueen rules if the left operand
                            // is actually in the input
                            if input.get_redqueen_rule_candidates(&rule).len() > 0 {
                                let input_hash = crate::utils::calculate_hash(input);
                                log::info!("Inserting rule! {input_hash:#x} {rule:x?}");
                                fuzzvm.redqueen_rules.entry(input_hash).or_default().insert(rule);
                            }

                            // Generate the rule to satisfy this comparison
                            let rule = RedqueenRule::$rule(
                                left_val.add(1.0).to_le_bytes().to_vec(),
                                right_val.to_le_bytes().to_vec()
                            );

                            // Only add this rule to the redqueen rules if the left operand
                            // is actually in the input
                            if input.get_redqueen_rule_candidates(&rule).len() > 0 {
                                let input_hash = crate::utils::calculate_hash(input);
                                log::info!("Inserting rule! {input_hash:#x} {rule:x?}");
                                fuzzvm.redqueen_rules.entry(input_hash).or_default().insert(rule);
                            }
                       }
                    }
                )*
                _ => {}
            }
        };
    }

    #[rustfmt::skip]
    impl_primitive_sizes!(
        U8,   u8,   read_u8,   SingleU8,
        U16,  u16,  read_u16,  SingleU16,
        U32,  u32,  read_u32,  SingleU32,
        U64,  u64,  read_u64,  SingleU64,
        U128, u128, read_u128, SingleU128
    );

    #[rustfmt::skip]
    impl_float_sizes!(
        F32,  f32,  read_f32,  SingleF32,
        F64,  f64,  read_f64,  SingleF64
    );

    Ok(Execution::Continue)
}
