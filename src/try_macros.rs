//! Various try macros for common unit conversions

/// Shortened macro for `u8::try_from(val).unwrap()`
#[macro_export]
macro_rules! try_u8 {
    ($val:expr) => {
        u8::try_from($val).unwrap()
    };
}

/// Shortened macro for `u16::try_from(val).unwrap()`
#[macro_export]
macro_rules! try_u16 {
    ($val:expr) => {
        u16::try_from($val).unwrap()
    };
}

/// Shortened macro for `u32::try_from(val).unwrap()`
#[macro_export]
macro_rules! try_u32 {
    ($val:expr) => {
        u32::try_from($val).unwrap()
    };
}

/// Shortened macro for `u64::try_from(val).unwrap()`
#[macro_export]
macro_rules! try_u64 {
    ($val:expr) => {
        u64::try_from($val).unwrap()
    };
}

/// Shortened macro for `usize::try_from(val).unwrap()`
#[macro_export]
macro_rules! try_usize {
    ($val:expr) => {
        usize::try_from($val).unwrap()
    };
}

/// Shortened macro for `isize::try_from(val).unwrap()`
#[macro_export]
macro_rules! try_isize {
    ($val:expr) => {
        isize::try_from($val).unwrap()
    };
}
