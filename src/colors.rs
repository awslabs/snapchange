//! Implements ANSI foreground colors for printable types

use core::marker::PhantomData;

/// Wrapper struct for generically selecting a color over something to be printed
pub struct Styled<'a, T: Sized, C> {
    /// Original data to stylize
    original: &'a T,

    /// Color of the text
    color: PhantomData<C>,
}

/// Trait which provides the ANSI color string
pub trait Color {
    /// The ANSI color string for this color
    const ANSI: &'static str;
}

/// Creates structs for each ANSI color and implemented the [`Color`] trait for them
macro_rules! create_color {
    ($color:ident, $num:expr) => {
        pub struct $color;

        impl Color for $color {
            const ANSI: &'static str = concat!("\x1b[", stringify!($num), "m");
        }
    };
}

create_color!(Black, 30);
create_color!(Red, 31);
create_color!(Green, 32);
create_color!(Yellow, 33);
create_color!(Blue, 34);
create_color!(Magenta, 35);
create_color!(Cyan, 36);
create_color!(White, 37);
create_color!(Normal, 39);
create_color!(BrightBlack, 90);
create_color!(BrightRed, 91);
create_color!(BrightGreen, 92);
create_color!(BrightYellow, 93);
create_color!(BrightBlue, 94);
create_color!(BrightMagenta, 95);
create_color!(BrightCyan, 96);
create_color!(BrightWhite, 97);

/// Implements the various `core::fmt` traits
macro_rules! impl_formats {
    ($ty:path) => {
        impl<'a, T: $ty, C: Color> $ty for Styled<'a, T, C> {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let _ = f.write_str(C::ANSI);
                let _ = <T as $ty>::fmt(&self.original, f);
                f.write_str(Normal::ANSI)
            }
        }
    };
}

/// Implements each function that is available for adding color
macro_rules! trait_func {
    ($color:ident, $ty:ident) => {
        fn $color(&self) -> Styled<Self, $ty>
        where
            Self: Sized,
        {
            Styled {
                original: self,
                color: PhantomData,
            }
        }
    };
}

/// Provides wrapper functions to apply foreground colors
pub trait Colorized {
    trait_func!(black, Black);
    trait_func!(red, Red);
    trait_func!(green, Green);
    trait_func!(yellow, Yellow);
    trait_func!(blue, Blue);
    trait_func!(magenta, Magenta);
    trait_func!(cyan, Cyan);
    trait_func!(white, White);
    trait_func!(normal, Normal);
    trait_func!(default, Normal);
    trait_func!(bright_black, BrightBlack);
    trait_func!(bright_red, BrightRed);
    trait_func!(bright_green, BrightGreen);
    trait_func!(bright_yellow, BrightYellow);
    trait_func!(bright_blue, BrightBlue);
    trait_func!(bright_magenta, BrightMagenta);
    trait_func!(bright_cyan, BrightCyan);
    trait_func!(bright_white, BrightWhite);
    trait_func!(light_black, BrightBlack);
    trait_func!(light_red, BrightRed);
    trait_func!(light_green, BrightGreen);
    trait_func!(light_yellow, BrightYellow);
    trait_func!(light_blue, BrightBlue);
    trait_func!(light_magenta, BrightMagenta);
    trait_func!(light_cyan, BrightCyan);
    trait_func!(light_white, BrightWhite);
}

impl_formats!(core::fmt::Debug);
impl_formats!(core::fmt::Display);
impl_formats!(core::fmt::LowerHex);

// Magic impl which gives any trait that implements Display color functions
impl<T: core::fmt::Display> Colorized for T {}
