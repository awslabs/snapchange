use snapchange::snapchange_main;

mod fuzzer;
mod redqueen;

fn main() {
    snapchange_main::<fuzzer::Example05Fuzzer>().unwrap();
}
