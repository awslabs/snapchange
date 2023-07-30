use snapchange::snapchange_main;

mod fuzzer;
mod constants;

fn main() {
    snapchange_main::<fuzzer::Example1Fuzzer>().unwrap();
}
