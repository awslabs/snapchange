use snapchange::snapchange_main;

pub mod fuzzer;
pub mod constants;

fn main() {
    snapchange_main::<fuzzer::TemplateFuzzer>().unwrap();
}
