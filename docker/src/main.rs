use snapchange::snapchange_main;

mod fuzzer;

fn main() {
    snapchange_main::<fuzzer::TemplateFuzzer>().unwrap();
}
