use snapchange::snapchange_main;

mod fuzzer;

fn main() {
    snapchange_main::<fuzzer::Example1Fuzzer>().unwrap();
}
