#![feature(const_mut_refs)]

mod fuzzer;

fn main() {
    if let Err(e) = snapchange::snapchange_main::<fuzzer::Example04Fuzzer>() {
        panic!("{e:?}");
    }
}
