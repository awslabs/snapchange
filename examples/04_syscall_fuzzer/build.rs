use regex::Regex;
use std::fs;
use std::fs::File;
use std::io::Write;

fn main() {
    println!("cargo:rerun-if-changed=snapshot/fuzzvm.qemuregs");
    println!("cargo:rerun-if-changed=snapshot/vm.log");

    let qemuregs = fs::read_to_string("./snapshot/fuzzvm.qemuregs").unwrap();
    let mut w = File::create("src/constants.rs").unwrap();

    let re = Regex::new(r"CR3=([0-9A-Fa-f]+)").unwrap();
    let captures = re.captures(&qemuregs).unwrap();
    let cr3 = &captures.get(1).unwrap().as_str();
    writeln!(w, "pub const CR3: u64 = 0x{cr3};").unwrap();

    let re = Regex::new(r"RIP=([0-9A-Fa-f]+)").unwrap();
    let captures = re.captures(&qemuregs).unwrap();
    let rip = &captures.get(1).unwrap().as_str();
    writeln!(w, "pub const RIP: u64 = 0x{rip};").unwrap();

    // 355:SNAPSHOT: Scratch memory: 0x7ffff758d000 Length: 0xa00000
    // 356:SNAPSHOT: Shellcode: 0x7ffff748d000 Length: 0x100000
    let vm_log = fs::read_to_string("./snapshot/vm.log").unwrap();

    let re = Regex::new(r"Scratch memory: (0x[0-9A-Fa-f]+)").unwrap();
    let captures = re.captures(&vm_log).unwrap();
    let scratch = &captures.get(1).unwrap().as_str();
    writeln!(w, "pub const SCRATCH: u64 = {scratch};").unwrap();

    let re = Regex::new(r"Shellcode: (0x[0-9A-Fa-f]+)").unwrap();
    let captures = re.captures(&vm_log).unwrap();
    let shellcode = &captures.get(1).unwrap().as_str();
    writeln!(w, "pub const SHELLCODE: u64 = {shellcode};").unwrap();
}
