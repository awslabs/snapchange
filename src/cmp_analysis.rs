//! Provides structs and procedures for this Redqueen implementation

use serde::{Deserialize, Serialize};

/// A replacement rule for cmp analysis
///
/// When applying a replacement rule during mutation, if the left value is
/// found in the input, replace it with the right. And also replace the
#[derive(Debug, Clone, Eq, Ord, PartialOrd, PartialEq, Serialize, Deserialize)]
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
