use snapchange::snapchange_main;

mod constants;
mod fuzzer;

fn main() {
    snapchange_main::<fuzzer::Example7Fuzzer>().unwrap();
}
