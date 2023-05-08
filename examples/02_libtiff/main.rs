use anyhow::Result;
use snapchange::snapchange_main;

mod fuzzer;

fn main() -> Result<()> {
    snapchange_main::<fuzzer::Example02Fuzzer>()
}
