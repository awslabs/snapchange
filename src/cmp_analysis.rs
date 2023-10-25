//! Provides structs and procedures for this Redqueen implementation

use std::ops::Add;
use std::ops::Sub;

use ahash::HashSetExt;
use anyhow::Result;
use iced_x86::Register as IcedRegister;
use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize};

use crate::addrs::VirtAddr;
use crate::fuzz_input::FuzzInput;
use crate::fuzzer::Fuzzer;
use crate::regs::x86;
use crate::stats::PerfMark;
use crate::Execution;
use crate::FuzzVm;

/// Coverage found during redqueen
#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RedqueenCoverage {
    /// Virtual address for this coverage
    pub virt_addr: VirtAddr,

    /// CR3 of this coverage
    pub rflags: u64,

    /// The nth time coverage has been hit
    pub hit_count: u32,
}

/// A constant used by redqueen as a byte slice
#[derive(Debug, Clone, Eq, Ord, PartialOrd, PartialEq, Hash)]
pub enum RedqueenConst {
    /// A u8 byte slice
    U8([u8; 1]),
    /// A u16 byte slice
    U16([u8; 2]),
    /// A u24 byte slice
    U24([u8; 3]),
    /// A u32 byte slice
    U32([u8; 4]),
    /// A u40 byte slice
    U40([u8; 5]),
    /// A u48 byte slice
    U48([u8; 6]),
    /// A u56 byte slice
    U56([u8; 7]),
    /// A u64 byte slice
    U64([u8; 8]),
    /// A u128 byte slice
    U128([u8; 16]),
}

impl RedqueenConst {
    /// Get the underlying byte slice for this RedqueenConst
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            RedqueenConst::U8(bytes) => bytes,
            RedqueenConst::U16(bytes) => bytes,
            RedqueenConst::U24(bytes) => bytes,
            RedqueenConst::U32(bytes) => bytes,
            RedqueenConst::U40(bytes) => bytes,
            RedqueenConst::U48(bytes) => bytes,
            RedqueenConst::U56(bytes) => bytes,
            RedqueenConst::U64(bytes) => bytes,
            RedqueenConst::U128(bytes) => bytes,
        }
    }

    /// Get the length of this RedqueenConst
    pub const fn len(&self) -> usize {
        match self {
            RedqueenConst::U8(bytes) => bytes.len(),
            RedqueenConst::U16(bytes) => bytes.len(),
            RedqueenConst::U24(bytes) => bytes.len(),
            RedqueenConst::U32(bytes) => bytes.len(),
            RedqueenConst::U40(bytes) => bytes.len(),
            RedqueenConst::U48(bytes) => bytes.len(),
            RedqueenConst::U56(bytes) => bytes.len(),
            RedqueenConst::U64(bytes) => bytes.len(),
            RedqueenConst::U128(bytes) => bytes.len(),
        }
    }

    /// Get the minimum number of bytes needed to represent the given value
    ///
    /// Example:
    /// RedqueenConst::U32([0x12, 0x34, 0x00, 0x00]) -> 2
    /// RedqueenConst::U64([0x12, 0x34, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00]) -> 3
    pub fn minimum_bytes(&self) -> usize {
        let bytes = self.as_bytes();
        let mut min = bytes.len();
        while min > 1 {
            if bytes[min - 1] != 0 {
                return min;
            }

            min -= 1;
        }

        min
    }
}

impl From<u8> for RedqueenConst {
    fn from(val: u8) -> Self {
        RedqueenConst::U8([val])
    }
}
impl From<u16> for RedqueenConst {
    fn from(val: u16) -> Self {
        RedqueenConst::U16(val.to_le_bytes())
    }
}
impl From<u32> for RedqueenConst {
    fn from(val: u32) -> Self {
        RedqueenConst::U32(val.to_le_bytes())
    }
}
impl From<u64> for RedqueenConst {
    fn from(val: u64) -> Self {
        RedqueenConst::U64(val.to_le_bytes())
    }
}
impl From<u128> for RedqueenConst {
    fn from(val: u128) -> Self {
        RedqueenConst::U128(val.to_le_bytes())
    }
}
impl From<[u8; 3]> for RedqueenConst {
    fn from(val: [u8; 3]) -> Self {
        RedqueenConst::U24(val)
    }
}
impl From<[u8; 5]> for RedqueenConst {
    fn from(val: [u8; 5]) -> Self {
        RedqueenConst::U40(val)
    }
}
impl From<[u8; 6]> for RedqueenConst {
    fn from(val: [u8; 6]) -> Self {
        RedqueenConst::U48(val)
    }
}
impl From<[u8; 7]> for RedqueenConst {
    fn from(val: [u8; 7]) -> Self {
        RedqueenConst::U56(val)
    }
}

/// A replacement rule for cmp analysis
///
/// When applying a replacement rule during mutation, if the left value is
/// found in the input, replace it with the right. And also replace the
#[derive(Debug, Clone, Eq, Ord, PartialOrd, PartialEq, Hash)]
pub enum RedqueenRule {
    /// Replace one RQ const with another
    Primitive(RedqueenConst, RedqueenConst),

    /// Replace one f32 with another
    SingleF32([u8; 4], [u8; 4]),

    /// Replace one f64 with another
    SingleF64([u8; 8], [u8; 8]),

    /// Replace one set of bytes for another
    Bytes(Vec<u8>, Vec<u8>),
}

/// The arguments used to describe a redqueen breakpoint
#[derive(Debug, Clone)]
pub struct RedqueenArguments {
    /// Number of bytes compared in this rule
    pub size: Size,

    /// The comparison operation for this rule
    pub operation: Conditional,

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

    /// Comparing byts as an X87 register
    X87,

    /// Comparing a sequence of bytes
    Bytes(usize),

    /// Comparing a sequence of bytes with length in the given register
    Register(iced_x86::Register),
}

/// Comparison operations
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Eq, Ord, PartialOrd, PartialEq)]
pub enum Conditional {
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

impl From<&str> for Conditional {
    fn from(val: &str) -> Conditional {
        match val {
            "CMP_E" => Conditional::Equal,
            "CMP_NE" => Conditional::NotEqual,
            "CMP_SLT" => Conditional::SignedLessThan,
            "CMP_ULT" => Conditional::UnsignedLessThan,
            "CMP_SLE" => Conditional::SignedLessThanEqual,
            "CMP_ULE" => Conditional::UnsignedLessThanEqual,
            "CMP_SGT" => Conditional::SignedGreaterThan,
            "CMP_UGT" => Conditional::UnsignedGreaterThan,
            "CMP_SGE" => Conditional::SignedGreaterThanEqual,
            "CMP_UGE" => Conditional::UnsignedGreaterThanEqual,
            "FCMP_E" => Conditional::FloatingPointEqual,
            "FCMP_NE" => Conditional::FloatingPointNotEqual,
            "FCMP_LT" => Conditional::FloatingPointLessThan,
            "FCMP_LE" => Conditional::FloatingPointLessThanEqual,
            "FCMP_GT" => Conditional::FloatingPointGreaterThan,
            "FCMP_GE" => Conditional::FloatingPointGreaterThanEqual,
            "strcmp" => Conditional::Strcmp,
            "memcmp" => Conditional::Memcmp,
            _ => unimplemented!("Unknown operation: {val}"),
        }
    }
}

/// Information on how to retrieve the left operand comparison value
#[derive(Debug, Clone, PartialOrd, PartialEq)]
pub enum Operand {
    /// A single register operand
    Register(IcedRegister),

    /// A constant u8
    ConstU8(u8),

    /// A constant u16
    ConstU16(u16),

    /// A constant u32
    ConstU32(u32),

    /// A constant u64
    ConstU64(u64),

    /// A constant u128
    ConstU128(u64),

    /// A constant f64
    ConstF64(f64),

    /// A memory location to read the operand
    Load {
        /// The operand to get the address to read from memory
        address: Box<Operand>,
    },

    /// Bitwise inversion of the operand
    Not {
        /// The operand to get the address to read from memory
        src: Box<Operand>,
    },

    /// Sign inversion of the operand
    Neg {
        /// The operand to get the address to read from memory
        src: Box<Operand>,
    },

    /// Sign inversion of the operand
    SignExtend {
        /// The operand to get the address to read from memory
        src: Box<Operand>,
    },

    /// Arithmetic shift right
    ArithmeticShiftRight {
        /// Left operand
        left: Box<Operand>,

        /// Left operand
        right: Box<Operand>,
    },

    /// Bitwise AND
    And {
        /// Left operand
        left: Box<Operand>,

        /// Left operand
        right: Box<Operand>,
    },

    /// Bitwise OR
    Or {
        /// Left operand
        left: Box<Operand>,

        /// Left operand
        right: Box<Operand>,
    },

    /// Add the two operands
    Add {
        /// Left operand
        left: Box<Operand>,

        /// Left operand
        right: Box<Operand>,
    },

    /// Subtract the two operands
    Sub {
        /// Left operand
        left: Box<Operand>,

        /// Left operand
        right: Box<Operand>,
    },

    /// Multiply the two operands
    Mul {
        /// Left operand
        left: Box<Operand>,

        /// Left operand
        right: Box<Operand>,
    },

    /// Shift the left operand by right bits
    LogicalShiftLeft {
        /// Left operand
        left: Box<Operand>,

        /// Left operand
        right: Box<Operand>,
    },
}

macro_rules! impl_read_for_type {
    ($func:ident, $ty:ty, $mark:ident) => {
        /// Retrieve this operand from the current state of the FuzzVm
        pub fn $func<FUZZER: Fuzzer>(&self, fuzzvm: &mut FuzzVm<FUZZER>) -> Result<$ty> {
            let _timer = fuzzvm.scoped_timer(crate::stats::PerfMark::$mark);

            match self {
                Operand::Register(IcedRegister::XMM0) => Ok(fuzzvm.xmm0_i128() as $ty),
                Operand::Register(IcedRegister::XMM1) => Ok(fuzzvm.xmm1_i128() as $ty),
                Operand::Register(IcedRegister::XMM2) => Ok(fuzzvm.xmm2_i128() as $ty),
                Operand::Register(IcedRegister::XMM3) => Ok(fuzzvm.xmm3_i128() as $ty),
                Operand::Register(IcedRegister::XMM4) => Ok(fuzzvm.xmm4_i128() as $ty),
                Operand::Register(IcedRegister::XMM5) => Ok(fuzzvm.xmm5_i128() as $ty),
                Operand::Register(IcedRegister::XMM6) => Ok(fuzzvm.xmm6_i128() as $ty),
                Operand::Register(IcedRegister::XMM7) => Ok(fuzzvm.xmm7_i128() as $ty),
                Operand::Register(IcedRegister::XMM8) => Ok(fuzzvm.xmm8_i128() as $ty),
                Operand::Register(IcedRegister::XMM9) => Ok(fuzzvm.xmm9_i128() as $ty),
                Operand::Register(IcedRegister::XMM10) => Ok(fuzzvm.xmm10_i128() as $ty),
                Operand::Register(IcedRegister::XMM11) => Ok(fuzzvm.xmm11_i128() as $ty),
                Operand::Register(IcedRegister::XMM12) => Ok(fuzzvm.xmm12_i128() as $ty),
                Operand::Register(IcedRegister::XMM13) => Ok(fuzzvm.xmm13_i128() as $ty),
                Operand::Register(IcedRegister::XMM14) => Ok(fuzzvm.xmm14_i128() as $ty),
                Operand::Register(IcedRegister::XMM15) => Ok(fuzzvm.xmm15_i128() as $ty),
                Operand::Register(IcedRegister::ST0) => Ok(fuzzvm.st0_i128() as $ty),
                Operand::Register(IcedRegister::ST1) => Ok(fuzzvm.st1_i128() as $ty),
                Operand::Register(IcedRegister::ST2) => Ok(fuzzvm.st2_i128() as $ty),
                Operand::Register(IcedRegister::ST3) => Ok(fuzzvm.st3_i128() as $ty),
                Operand::Register(IcedRegister::ST4) => Ok(fuzzvm.st4_i128() as $ty),
                Operand::Register(IcedRegister::ST5) => Ok(fuzzvm.st5_i128() as $ty),
                Operand::Register(IcedRegister::ST6) => Ok(fuzzvm.st6_i128() as $ty),
                Operand::Register(IcedRegister::ST7) => Ok(fuzzvm.st7_i128() as $ty),
                Operand::Register(reg) => Ok(fuzzvm.get_iced_reg(*reg) as $ty),
                Operand::ConstU8(val) => Ok(*val as $ty),
                Operand::ConstU16(val) => Ok(*val as $ty),
                Operand::ConstU32(val) => Ok(*val as $ty),
                Operand::ConstU64(val) => Ok(*val as $ty),
                Operand::ConstU128(val) => Ok(*val as $ty),
                Operand::ConstF64(val) => Ok(*val as $ty),
                Operand::Load { address } => {
                    let addr = address.read_u64(fuzzvm)?;
                    let addr = VirtAddr(addr);
                    fuzzvm.read::<$ty>(addr, fuzzvm.cr3())
                }
                Operand::And { left, right } => Ok(left.$func(fuzzvm)? & right.$func(fuzzvm)?),
                Operand::Add { left, right } => {
                    Ok(left.$func(fuzzvm)?.wrapping_add(right.$func(fuzzvm)?))
                }
                Operand::Sub { left, right } => Ok(left.$func(fuzzvm)? - right.$func(fuzzvm)?),
                Operand::Mul { left, right } => Ok(left.$func(fuzzvm)? * right.$func(fuzzvm)?),
                Operand::Or { left, right } => Ok(left.$func(fuzzvm)? | right.$func(fuzzvm)?),
                Operand::Not { src } => Ok(!src.$func(fuzzvm)?),
                Operand::Neg { src } => Ok(src.$func(fuzzvm)?.wrapping_neg()),
                Operand::LogicalShiftLeft { left, right } => {
                    Ok(left.$func(fuzzvm)? << right.$func(fuzzvm)?)
                }
                Operand::ArithmeticShiftRight { left, right } => {
                    Ok(left.$func(fuzzvm)? >> right.$func(fuzzvm)?)
                }
                Operand::SignExtend { src } => Ok(src.$func(fuzzvm)? as i64 as $ty),
            }
        }
    };
}

impl Operand {
    impl_read_for_type!(read_u8, u8, RQReadU8);
    impl_read_for_type!(read_u16, u16, RQReadU16);
    impl_read_for_type!(read_u32, u32, RQReadU32);
    impl_read_for_type!(read_u64, u64, RQReadU64);
    impl_read_for_type!(read_u128, u128, RQReadU128);

    /// Retrieve the f32 from the current state of the FuzzVm
    pub fn read_f32<FUZZER: Fuzzer>(&self, fuzzvm: &mut FuzzVm<FUZZER>) -> Result<f32> {
        let _timer = fuzzvm.scoped_timer(crate::stats::PerfMark::RQReadF32);

        match self {
            Operand::Register(IcedRegister::XMM0) => Ok(fuzzvm.xmm0_f32()),
            Operand::Register(IcedRegister::XMM1) => Ok(fuzzvm.xmm1_f32()),
            Operand::Register(IcedRegister::XMM2) => Ok(fuzzvm.xmm2_f32()),
            Operand::Register(IcedRegister::XMM3) => Ok(fuzzvm.xmm3_f32()),
            Operand::Register(IcedRegister::XMM4) => Ok(fuzzvm.xmm4_f32()),
            Operand::Register(IcedRegister::XMM5) => Ok(fuzzvm.xmm5_f32()),
            Operand::Register(IcedRegister::XMM6) => Ok(fuzzvm.xmm6_f32()),
            Operand::Register(IcedRegister::XMM7) => Ok(fuzzvm.xmm7_f32()),
            Operand::Register(IcedRegister::XMM8) => Ok(fuzzvm.xmm8_f32()),
            Operand::Register(IcedRegister::XMM9) => Ok(fuzzvm.xmm9_f32()),
            Operand::Register(IcedRegister::XMM10) => Ok(fuzzvm.xmm10_f32()),
            Operand::Register(IcedRegister::XMM11) => Ok(fuzzvm.xmm11_f32()),
            Operand::Register(IcedRegister::XMM12) => Ok(fuzzvm.xmm12_f32()),
            Operand::Register(IcedRegister::XMM13) => Ok(fuzzvm.xmm13_f32()),
            Operand::Register(IcedRegister::XMM14) => Ok(fuzzvm.xmm14_f32()),
            Operand::Register(IcedRegister::XMM15) => Ok(fuzzvm.xmm15_f32()),
            Operand::Register(reg) => {
                panic!("Unknown regsiter for read_f32: {reg:?}");
            }
            Operand::ConstU8(val) => Ok(*val as f32),
            Operand::ConstU16(val) => Ok(*val as f32),
            Operand::ConstU32(val) => Ok(*val as f32),
            Operand::ConstU64(val) => Ok(*val as f32),
            Operand::ConstU128(val) => Ok(*val as f32),
            Operand::ConstF64(val) => Ok(*val as f32),
            Operand::Load { address } => {
                let addr = address.read_u64(fuzzvm)?;
                let addr = VirtAddr(addr);
                Ok(f32::from_le_bytes(
                    fuzzvm.read::<[u8; 4]>(addr, fuzzvm.cr3())?,
                ))
            }
            Operand::Add { left, right } => Ok(left.read_f32(fuzzvm)? + right.read_f32(fuzzvm)?),
            Operand::Sub { left, right } => Ok(left.read_f32(fuzzvm)? - right.read_f32(fuzzvm)?),
            Operand::Mul { left, right } => Ok(left.read_f32(fuzzvm)? * right.read_f32(fuzzvm)?),
            Operand::Neg { src } => Ok(-src.read_f32(fuzzvm)?),
            Operand::LogicalShiftLeft { left, right } => {
                unimplemented!("Cannot LSL f32 values")
            }
            Operand::And { left, right } => {
                unimplemented!("Cannot AND f32 values")
            }
            Operand::Or { left, right } => {
                unimplemented!("Cannot OR f32 values")
            }
            Operand::Not { src } => {
                unimplemented!("Cannot NOT f32 values")
            }
            Operand::ArithmeticShiftRight { left, right } => {
                unimplemented!("Cannot ASR f32 values")
            }
            Operand::SignExtend { src } => {
                unimplemented!("Cannot sign extend f32 values")
            }
        }
    }

    /// Retrieve an f64 from the current state of the FuzzVm
    pub fn read_f64<FUZZER: Fuzzer>(&self, fuzzvm: &mut FuzzVm<FUZZER>) -> Result<f64> {
        let _timer = fuzzvm.scoped_timer(crate::stats::PerfMark::RQReadF64);

        match self {
            Operand::Register(IcedRegister::XMM0) => Ok(fuzzvm.xmm0_f64()),
            Operand::Register(IcedRegister::XMM1) => Ok(fuzzvm.xmm1_f64()),
            Operand::Register(IcedRegister::XMM2) => Ok(fuzzvm.xmm2_f64()),
            Operand::Register(IcedRegister::XMM3) => Ok(fuzzvm.xmm3_f64()),
            Operand::Register(IcedRegister::XMM4) => Ok(fuzzvm.xmm4_f64()),
            Operand::Register(IcedRegister::XMM5) => Ok(fuzzvm.xmm5_f64()),
            Operand::Register(IcedRegister::XMM6) => Ok(fuzzvm.xmm6_f64()),
            Operand::Register(IcedRegister::XMM7) => Ok(fuzzvm.xmm7_f64()),
            Operand::Register(IcedRegister::XMM8) => Ok(fuzzvm.xmm8_f64()),
            Operand::Register(IcedRegister::XMM9) => Ok(fuzzvm.xmm9_f64()),
            Operand::Register(IcedRegister::XMM10) => Ok(fuzzvm.xmm10_f64()),
            Operand::Register(IcedRegister::XMM11) => Ok(fuzzvm.xmm11_f64()),
            Operand::Register(IcedRegister::XMM12) => Ok(fuzzvm.xmm12_f64()),
            Operand::Register(IcedRegister::XMM13) => Ok(fuzzvm.xmm13_f64()),
            Operand::Register(IcedRegister::XMM14) => Ok(fuzzvm.xmm14_f64()),
            Operand::Register(IcedRegister::XMM15) => Ok(fuzzvm.xmm15_f64()),
            Operand::Register(reg) => {
                panic!("Unknown regsiter for read_f64: {reg:?}");
                // Ok(fuzzvm.get_iced_reg(*reg) as $ty),
            }
            Operand::ConstU8(val) => Ok(*val as f64),
            Operand::ConstU16(val) => Ok(*val as f64),
            Operand::ConstU32(val) => Ok(*val as f64),
            Operand::ConstU64(val) => Ok(*val as f64),
            Operand::ConstU128(val) => Ok(*val as f64),
            Operand::ConstF64(val) => Ok(*val as f64),
            Operand::Load { address } => {
                let addr = address.read_u64(fuzzvm)?;
                let addr = VirtAddr(addr);
                Ok(f64::from_le_bytes(
                    fuzzvm.read::<[u8; 8]>(addr, fuzzvm.cr3())?,
                ))
            }
            Operand::Add { left, right } => Ok(left.read_f64(fuzzvm)? + right.read_f64(fuzzvm)?),
            Operand::Sub { left, right } => Ok(left.read_f64(fuzzvm)? - right.read_f64(fuzzvm)?),
            Operand::Mul { left, right } => Ok(left.read_f64(fuzzvm)? * right.read_f64(fuzzvm)?),
            Operand::Neg { src } => Ok(-src.read_f64(fuzzvm)?),
            Operand::LogicalShiftLeft { left, right } => {
                unimplemented!("Cannot LSL f64 values")
            }
            Operand::And { left, right } => {
                unimplemented!("Cannot AND f64 values")
            }
            Operand::Or { left, right } => {
                unimplemented!("Cannot OR f64 values")
            }
            Operand::Not { src } => {
                unimplemented!("Cannot NOT f64 values")
            }
            Operand::ArithmeticShiftRight { left, right } => {
                unimplemented!("Cannot ASR f32 values")
            }
            Operand::SignExtend { src } => {
                unimplemented!("Cannot sign extend f32 values")
            }
        }
    }

    /// Read the given x87 register
    pub fn read_x87<FUZZER: Fuzzer>(&self, fuzzvm: &mut FuzzVm<FUZZER>) -> Result<Vec<u8>> {
        let _timer = fuzzvm.scoped_timer(crate::stats::PerfMark::RQReadX87);

        match self {
            Operand::Register(IcedRegister::ST0) => Ok(fuzzvm.fpu()?.fpr[0][..10].to_vec()),
            Operand::Register(IcedRegister::ST1) => Ok(fuzzvm.fpu()?.fpr[1][..10].to_vec()),
            Operand::Register(IcedRegister::ST2) => Ok(fuzzvm.fpu()?.fpr[2][..10].to_vec()),
            Operand::Register(IcedRegister::ST3) => Ok(fuzzvm.fpu()?.fpr[3][..10].to_vec()),
            Operand::Register(IcedRegister::ST4) => Ok(fuzzvm.fpu()?.fpr[4][..10].to_vec()),
            Operand::Register(IcedRegister::ST5) => Ok(fuzzvm.fpu()?.fpr[5][..10].to_vec()),
            Operand::Register(IcedRegister::ST6) => Ok(fuzzvm.fpu()?.fpr[6][..10].to_vec()),
            Operand::Register(IcedRegister::ST7) => Ok(fuzzvm.fpu()?.fpr[7][..10].to_vec()),
            _ => unimplemented!("Cannot read bytes for {self:?}"),
        }
    }
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
    let _timer = fuzzvm.scoped_timer(PerfMark::GatherComparison);

    // Get the arguments for this redqueen breakpoints
    let RedqueenArguments {
        size,
        operation,
        left_op,
        right_op,
    } = args;

    // Ignore U8 rules for now since we have the byte flipper as a normal mutator
    if *size == Size::U8 {
        return Ok(Execution::Continue);
    }

    let input_hash = input.fuzz_hash();

    macro_rules! impl_primitive_sizes {
        ($($size:ident, $ty:ty, $func:ident),*) => {
            match size {
                $(
                    Size::$size => {
                        let left_val: $ty = left_op.$func(fuzzvm)?.into();
                        let right_val: $ty = right_op.$func(fuzzvm)?.into();
                        match operation {
                            Conditional::Equal | Conditional::NotEqual => {
                                let condition = left_val.eq(&right_val);

                                if condition {
                                    // OP - ax == bx (true)
                                    // AX - 3
                                    // BX - 3
                                    // Wanted !=
                                    // Replace 3 -> 4

                                    // Generate the rule to satisfy this comparison
                                    let new_val = right_val.wrapping_add(1);
                                    let rule = RedqueenRule::Primitive(left_val.into(), new_val.into());
                                    fuzzvm.set_redqueen_rule_candidates(&input, rule);
                                } else {
                                    // OP - ax == bx (false)
                                    // AX - 3
                                    // BX - 5
                                    // Wanted ==
                                    // Replace 3 -> 5
                                    // Replace 5 -> 3

                                    // Generate the rule to satisfy this comparison
                                    let rule =  RedqueenRule::Primitive(left_val.into(), right_val.into());
                                    fuzzvm.set_redqueen_rule_candidates(&input, rule);

                                    // Generate the rule to satisfy this comparison
                                    let rule = RedqueenRule::Primitive(right_val.into(), left_val.into());
                                    fuzzvm.set_redqueen_rule_candidates(&input, rule);
                                }
                            }
                            Conditional::SignedLessThan
                            | Conditional::SignedGreaterThanEqual
                            | Conditional::UnsignedLessThan
                            | Conditional::UnsignedGreaterThanEqual  => {
                                let condition = left_val.lt(&right_val);

                                if condition {
                                    // OP - ax < bx (true)
                                    // AX - 0
                                    // BX - 128_u8
                                    // Wanted >=
                                    // Replace 0 -> (128 + 1)
                                    // Replace 4 -> (0 - 1 = -1)

                                    // Generate the rule to satisfy this comparison
                                    if let Some(new_val) = right_val.checked_add(1) {
                                        let rule =  RedqueenRule::Primitive(left_val.into(), new_val.into());

                                        // Only add this rule to the redqueen rules if the left operand
                                        // is actually in the input
                                        fuzzvm.set_redqueen_rule_candidates(&input, rule);
                                    }

                                    if let Some(new_val) = left_val.checked_sub(1) {
                                        // Generate the rule to satisfy this comparison
                                        let rule = RedqueenRule::Primitive(right_val.into(), new_val.into());
                                        fuzzvm.set_redqueen_rule_candidates(&input, rule);
                                    }
                                } else {
                                    // OP - ax < bx (false)
                                    // AX - 4
                                    // BX - 3
                                    // Wanted <
                                    // Replace 4 -> 2
                                    // Replace 3 -> 5

                                    // Generate the rule to satisfy this comparison
                                    if let Some(new_val) = right_val.checked_sub(1) {
                                        let rule =  RedqueenRule::Primitive(left_val.into(), new_val.into());
                                        fuzzvm.set_redqueen_rule_candidates(&input, rule);
                                    }

                                    // Generate the rule to satisfy this comparison
                                    if let Some(new_val) = left_val.checked_add(1) {
                                        let rule =  RedqueenRule::Primitive(right_val.into(), new_val.into());
                                        fuzzvm.set_redqueen_rule_candidates(&input, rule);
                                    }
                                }
                            }
                            Conditional::SignedLessThanEqual
                            | Conditional::UnsignedLessThanEqual
                            | Conditional::SignedGreaterThan
                            | Conditional::UnsignedGreaterThan => {
                                let condition = left_val.le(&right_val);

                                if condition {
                                    // OP - ax <= bx (true)
                                    // AX - 127_u8
                                    // BX - 128_u8
                                    // Wanted >
                                    // Replace 127 -> (128 + 1)
                                    // Replace 128 -> (127 - 1 = 126)

                                    // Generate the rule to satisfy this comparison
                                    if let Some(new_val) = right_val.checked_add(1) {
                                        let rule =  RedqueenRule::Primitive(left_val.into(), new_val.into());
                                        fuzzvm.set_redqueen_rule_candidates(&input, rule);
                                    }

                                    if let Some(new_val) = left_val.checked_sub(1) {
                                        // Generate the rule to satisfy this comparison
                                        let rule = RedqueenRule::Primitive(right_val.into(), new_val.into());
                                        fuzzvm.set_redqueen_rule_candidates(&input, rule);
                                    }
                                } else {
                                    // OP - ax <= bx (false)
                                    // AX - 4
                                    // BX - 3
                                    // Wanted >
                                    // Replace 4 -> 2
                                    // Replace 3 -> 5

                                    // Generate the rule to satisfy this comparison
                                    if let Some(new_val) = right_val.checked_sub(1) {
                                        let rule =  RedqueenRule::Primitive(left_val.into(), new_val.into());
                                        fuzzvm.set_redqueen_rule_candidates(&input, rule);
                                    }

                                    if let Some(new_val) = left_val.checked_add(1) {
                                        // Generate the rule to satisfy this comparison
                                        let rule = RedqueenRule::Primitive(right_val.into(), new_val.into());
                                        fuzzvm.set_redqueen_rule_candidates(&input, rule);
                                    }
                                }
                            }
                            _ => panic!("Unknown operation for primatives: {operation:?} {size:?} {args:x?}"),
                        }
                    }
                    Size::Bytes(_) | Size::Register(_) => {
                        let len = match size {
                            Size::Bytes(len) => *len,
                            Size::Register(reg) => fuzzvm.get_iced_reg(*reg) as usize,
                            _ => { unreachable!() }
                        };

                        // Read the address from each of the operands
                        let left_val = left_op.read_u64(fuzzvm)?;
                        let right_val = right_op.read_u64(fuzzvm)?;

                        match operation {
                            Conditional::Strcmp => {
                                let mut left_bytes = fuzzvm.read_bytes_until(VirtAddr(left_val as u64), fuzzvm.cr3(), 0, 64 * 1024);
                                let mut right_bytes = fuzzvm.read_bytes_until(VirtAddr(right_val as u64), fuzzvm.cr3(), 0, 64 * 1024);

                                let mut left_bytes = left_bytes?;
                                let mut right_bytes = right_bytes?;

                                if left_bytes != right_bytes {
                                    // Strings are not equal. Force them to be equal

                                    // Only add this rule to the redqueen rules if the left operand
                                    // is actually in the input
                                    let rule =  RedqueenRule::Bytes(left_bytes.clone(), right_bytes.clone());
                                    fuzzvm.set_redqueen_rule_candidates(&input, rule);

                                    // Only add this rule to the redqueen rules if the left operand
                                    // is actually in the input
                                    let rule =  RedqueenRule::Bytes(right_bytes.clone(), left_bytes.clone());
                                    fuzzvm.set_redqueen_rule_candidates(&input, rule);

                                    // Also add a rule specifically changing just the bytes for the smaller string
                                    let min_size = left_bytes.len().min(right_bytes.len());
                                    left_bytes.truncate(min_size);
                                    right_bytes.truncate(min_size);

                                    // Only add this rule to the redqueen rules if the left operand
                                    // is actually in the input
                                    let rule =  RedqueenRule::Bytes(left_bytes.clone(), right_bytes.clone());
                                    fuzzvm.set_redqueen_rule_candidates(&input, rule);

                                    // Only add this rule to the redqueen rules if the left operand
                                    // is actually in the input
                                    let rule =  RedqueenRule::Bytes(right_bytes.clone(), left_bytes.clone());
                                    fuzzvm.set_redqueen_rule_candidates(&input, rule);
                                } else {
                                    // Strings are equal. Force them to not be equal.

                                    // Only add this rule to the redqueen rules if the left operand
                                    // is actually in the input
                                    left_bytes[0] = left_bytes[0].wrapping_add(1);
                                    let rule =  RedqueenRule::Bytes(left_bytes, right_bytes);
                                    fuzzvm.set_redqueen_rule_candidates(&input, rule);
                                }

                            }
                            Conditional::Memcmp => {
                                let mut left_bytes = vec![0_u8; len];
                                let mut right_bytes = vec![0_u8; len];

                                fuzzvm.read_bytes(VirtAddr(left_val as u64), fuzzvm.cr3(), &mut left_bytes)?;
                                fuzzvm.read_bytes(VirtAddr(right_val as u64), fuzzvm.cr3(), &mut right_bytes)?;
                                if left_bytes != right_bytes {
                                    // bytes are not equal, force them to be equal
                                    let rule =  RedqueenRule::Bytes(left_bytes.clone(), right_bytes.clone());
                                    fuzzvm.set_redqueen_rule_candidates(&input, rule);

                                    let rule =  RedqueenRule::Bytes(right_bytes.clone(), left_bytes.clone());
                                    fuzzvm.set_redqueen_rule_candidates(&input, rule);
                                } else {
                                    // bytes are equal. Force them to not be equal.

                                    // Only add this rule to the redqueen rules if the left operand
                                    // is actually in the input
                                    left_bytes[0] = left_bytes[0].wrapping_add(1);
                                    let rule =  RedqueenRule::Bytes(left_bytes, right_bytes);
                                    fuzzvm.set_redqueen_rule_candidates(&input, rule);
                                }
                            }
                            _ => panic!("Unknown BYTES operation: {operation:?}")
                        }
                    }
                    Size::X87 => {
                        let mut left_bytes = left_op.read_x87(fuzzvm)?;
                        let right_bytes = right_op.read_x87(fuzzvm)?;

                        if left_bytes != right_bytes {
                            // bytes are not equal, force them to be equal
                            let rule =  RedqueenRule::Bytes(left_bytes.clone(), right_bytes.clone());
                            fuzzvm.set_redqueen_rule_candidates(&input, rule);

                            let rule =  RedqueenRule::Bytes(right_bytes.clone(), left_bytes.clone());
                            fuzzvm.set_redqueen_rule_candidates(&input, rule);
                        } else {
                            // bytes are equal. Force them to not be equal.

                            left_bytes[0] = left_bytes[0].wrapping_add(1);
                            let rule =  RedqueenRule::Bytes(left_bytes, right_bytes);
                            fuzzvm.set_redqueen_rule_candidates(&input, rule);
                        }

                    }
                )*
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
                        let left_val = left_op.$func(fuzzvm)?;
                        let right_val = right_op.$func(fuzzvm)?;
                        // log::info!("FLOAT {size:?} {operation:?} Left {left_val:x?} Right {right_val:x?}");
                        match operation {
                            Conditional::FloatingPointEqual | Conditional::FloatingPointNotEqual => {
                                let condition = left_val.eq(&right_val);
                                if condition {
                                    // OP - ax == bx (true)
                                    // AX - 3
                                    // BX - 3
                                    // Wanted !=
                                    // Replace 3 -> 4

                                    // Generate the rule to satisfy this comparison
                                    let new_val = right_val.add(1.0);
                                    let rule =  RedqueenRule::$rule(left_val.to_le_bytes(), new_val.to_le_bytes());
                                    fuzzvm.set_redqueen_rule_candidates(&input, rule);
                                } else {
                                    // OP - ax == bx (false)
                                    // AX - 3
                                    // BX - 5
                                    // Wanted ==
                                    // Replace 3 -> 5
                                    // Replace 5 -> 3

                                    // Generate the rule to satisfy this comparison
                                    let rule =  RedqueenRule::$rule(left_val.to_le_bytes(), right_val.to_le_bytes());
                                    fuzzvm.set_redqueen_rule_candidates(&input, rule);

                                    // Generate the rule to satisfy this comparison
                                    let rule = RedqueenRule::$rule(right_val.to_le_bytes(), left_val.to_le_bytes());
                                    fuzzvm.set_redqueen_rule_candidates(&input, rule);
                                }
                            }
                            Conditional::FloatingPointLessThan | Conditional::FloatingPointGreaterThanEqual => {
                                let condition = match operation {
                                    Conditional::FloatingPointLessThan => {
                                        left_val.lt(&right_val)
                                    }
                                    Conditional::FloatingPointGreaterThanEqual => {
                                        !left_val.ge(&right_val)
                                    }
                                    _ => unreachable!()
                                };

                                if condition {
                                    // OP - ax < bx (true)
                                    // AX - 0
                                    // BX - 128_u8
                                    // Wanted >=
                                    // Replace 0 -> (128 + 1)
                                    // Replace 4 -> (0 - 1 = -1)

                                    // Generate the rule to satisfy this comparison
                                    let new_val = right_val.add(1.0);
                                    let rule =  RedqueenRule::$rule(left_val.to_le_bytes(), new_val.to_le_bytes());
                                    fuzzvm.set_redqueen_rule_candidates(&input, rule);

                                    // Generate the rule to satisfy this comparison
                                    let new_val = left_val.sub(1.0);
                                    let rule = RedqueenRule::$rule(right_val.to_le_bytes(), new_val.to_le_bytes());
                                    fuzzvm.set_redqueen_rule_candidates(&input, rule);
                                    /*
                                    if input.get_redqueen_rule_candidates(&rule).len() > 0 {
                                        fuzzvm.redqueen_rules.entry(input_hash).or_default().insert(rule);
                                    }
                                    */
                                } else {
                                    // OP - ax < bx (false)
                                    // AX - 4
                                    // BX - 3
                                    // Wanted <
                                    // Replace 4 -> 2
                                    // Replace 3 -> 5

                                    // Generate the rule to satisfy this comparison
                                    let new_val = right_val.sub(1.0);
                                    let rule =  RedqueenRule::$rule(left_val.to_le_bytes(), new_val.to_le_bytes());
                                    fuzzvm.set_redqueen_rule_candidates(&input, rule);

                                    // Generate the rule to satisfy this comparison
                                    let new_val = left_val.add(1.0);
                                    let rule =  RedqueenRule::$rule(right_val.to_le_bytes(), new_val.to_le_bytes());
                                    fuzzvm.set_redqueen_rule_candidates(&input, rule);
                                }
                            }
                            Conditional::FloatingPointLessThanEqual | Conditional::FloatingPointGreaterThan => {
                                let condition = match operation {
                                    Conditional::FloatingPointLessThanEqual => {
                                        left_val.le(&right_val)
                                    }
                                    Conditional::FloatingPointGreaterThan => {
                                        !left_val.gt(&right_val)
                                    }
                                    _ => unreachable!()
                                };

                                if condition {
                                    // OP - ax <= bx (true)
                                    // AX - 127_u8
                                    // BX - 128_u8
                                    // Wanted >
                                    // Replace 127 -> (128 + 1)
                                    // Replace 128 -> (127 - 1 = 126)

                                    // Generate the rule to satisfy this comparison
                                    let new_val = right_val.add(1.0);
                                    let rule =  RedqueenRule::$rule(left_val.to_le_bytes(), new_val.to_le_bytes());
                                    fuzzvm.set_redqueen_rule_candidates(&input, rule);

                                    let new_val = left_val.sub(1.0);
                                    let rule = RedqueenRule::$rule(right_val.to_le_bytes(), new_val.to_le_bytes());
                                    fuzzvm.set_redqueen_rule_candidates(&input, rule);
                                } else {
                                    // OP - ax <= bx (false)
                                    // AX - 4
                                    // BX - 3
                                    // Wanted >
                                    // Replace 4 -> 2
                                    // Replace 3 -> 5

                                    // Generate the rule to satisfy this comparison
                                    let new_val = right_val.sub(1.0);

                                    let rule =  RedqueenRule::$rule(left_val.to_le_bytes(), new_val.to_le_bytes());
                                    fuzzvm.set_redqueen_rule_candidates(&input, rule);

                                    let new_val = left_val.add(1.0);

                                    // Generate the rule to satisfy this comparison
                                    let rule = RedqueenRule::$rule(right_val.to_le_bytes(), new_val.to_le_bytes());
                                    fuzzvm.set_redqueen_rule_candidates(&input, rule);
                                }
                            }
                            _ => panic!("Unknown operation for primatives: {operation:?} {size:?} {args:x?}"),
                        }
                    }
                )*
                _ => {}
            }
        };
    }

    #[rustfmt::skip]
    impl_primitive_sizes!(
        U8,   u8,   read_u8,   
        U16,  u16,  read_u16,
        U32,  u32,  read_u32,  
        U64,  u64,  read_u64,  
        U128, u128, read_u128
    );

    #[rustfmt::skip]
    impl_float_sizes!(
        F32,  f32,  read_f32, SingleF32,
        F64,  f64,  read_f64, SingleF64
    );

    Ok(Execution::Continue)
}
