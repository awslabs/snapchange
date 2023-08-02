#![feature(variant_count)]

use snapchange::snapchange_main;

mod constants;
mod fuzzer;

fn main() {
    snapchange_main::<fuzzer::Example03Fuzzer>().unwrap();
}
