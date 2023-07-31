use anyhow::Result;
use snapchange::snapchange_main;

mod constants;
mod fuzzer;

fn main() -> Result<()> {
    snapchange_main::<fuzzer::Example02Fuzzer>()
}
