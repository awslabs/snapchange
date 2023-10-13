use regex::Regex;
use std::fs;
use std::fs::File;
use std::io::Write;

fn main() {
    println!("cargo:rerun-if-env-changed=MAZE_TARGET");
    let target = std::env::var("MAZE_TARGET").unwrap_or("maze.small.nobt".to_string());

    println!("cargo:rerun-if-changed=snapshot/*/fuzzvm.qemuregs");
    println!("cargo:rerun-if-changed=snapshot/*/vm.log");

    let qemuregs = fs::read_to_string(format!("./snapshot/{target}/fuzzvm.qemuregs")).unwrap();
    let mut w = File::create("src/constants.rs").unwrap();

    writeln!(w, "#![allow(unused)]").unwrap();

    let re = Regex::new(r"CR3=([0-9A-Fa-f]+)").unwrap();
    let captures = re.captures(&qemuregs).unwrap();
    let cr3 = &captures.get(1).unwrap().as_str();
    writeln!(w, "pub const CR3: u64 = 0x{};", cr3).unwrap();

    let re = Regex::new(r"RIP=([0-9A-Fa-f]+)").unwrap();
    let captures = re.captures(&qemuregs).unwrap();
    let rip = &captures.get(1).unwrap().as_str();
    writeln!(w, "pub const RIP: u64 = 0x{};", rip).unwrap();

    let vmlog = fs::read_to_string(format!("./snapshot/{target}/vm.log")).unwrap();
    let re = Regex::new(r"SNAPSHOT Data buffer: (0x[0-9A-Fa-f]+)").unwrap();
    let captures = re.captures(&vmlog).unwrap();
    let input_addr = &captures.get(1).unwrap().as_str();
    writeln!(w, "pub const INPUT: u64 = {};", input_addr).unwrap();

    writeln!(w, "pub const TARGET: &'static str = {:?};", target).unwrap();
    writeln!(
        w,
        "pub const TARGET_LOG_POS: &'static str = {:?};",
        format!("{target}!log_pos")
    )
    .unwrap();
    writeln!(
        w,
        "pub const TARGET_LOSE: &'static str = {:?};",
        format!("{target}!lose")
    )
    .unwrap();
    writeln!(
        w,
        "pub const TARGET_WIN: &'static str = {:?};",
        format!("{target}!win")
    )
    .unwrap();
    writeln!(
        w,
        "pub const TARGET_BYE: &'static str = {:?};",
        format!("{target}!bye")
    )
    .unwrap();
    writeln!(
        w,
        "pub const TARGET_EQ16: &'static str = {:?};",
        format!("{target}!eq16")
    )
    .unwrap();
}
