//! Implementations of the [`FuzzInput`] trait for input types:
//!
//! * [`Vec<u8>`] - classic bytes only mutators.
//! * [`TextInput`] - Wrapper around `Vec<u8>` to provide mutations for text-based formats.
//!

pub mod bytes;
pub mod text;

pub use bytes::*;
pub use text::*;
