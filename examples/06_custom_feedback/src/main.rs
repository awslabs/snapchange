use snapchange::snapchange_main;

mod fuzzer;
mod constants;

fn main() -> anyhow::Result<()> {
    snapchange_main::<fuzzer::MazeFuzzer>()
}
