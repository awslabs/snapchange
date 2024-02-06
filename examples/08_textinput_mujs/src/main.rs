use snapchange::prelude::*;

mod fuzzer;
mod constants;

fn main() -> anyhow::Result<()> {
    snapchange_main::<fuzzer::JSTextFuzzer>()
}
