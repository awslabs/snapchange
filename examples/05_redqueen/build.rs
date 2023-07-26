#![feature(iter_array_chunks)]
#![allow(unused_macros)]

/// Debug print macro
macro_rules! p {
    ($($tokens: tt)*) => {
        println!("cargo:warning={}", format!($($tokens)*))
    }
}

/// Comparison operations
#[allow(dead_code)]
#[derive(Debug)]
pub enum CmpOperation {
    Equal,
    NotEqual,
    SignedLessThan,
    UnsignedLessThan,
    SignedLessThanEqual,
    UnsignedLessThanEqual,
    SignedGreaterThan,
    UnsignedGreaterThan,
    SignedGreaterThanEqual,
    UnsignedGreaterThanEqual,

    FloatingPointEqual,
    FloatingPointNotEqual,
    FloatingPointLessThan,
    FloatingPointLessThanEqual,
    FloatingPointGreaterThan,
    FloatingPointGreaterThanEqual,

    Strcmp,
    Memcmp,
}

#[rustfmt::skip]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = std::env::var_os("OUT_DIR").unwrap();

    // Get all of the snapshot/*cmps files
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR").unwrap();
    let snapshot_dir = std::path::Path::new(&manifest_dir).join("snapshot");
    let cmp_files = snapshot_dir
        .read_dir()
        .expect("No snapshot directory found")
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .path()
                .as_path()
                .extension()
                .and_then(|x| x.to_str())
                == Some("cmps")
        })
        .map(|entry| entry.unwrap())
        .collect::<Vec<_>>();

    let mut output = String::from("");
    let mut breakpoint_addresses = Vec::new();
    
    // Get the CR3 from the snapshot
    let project_state = snapchange::cmdline::get_project_state(&snapshot_dir, None).unwrap();
    let cr3 = project_state.vbcpu.cr3;

    // Output path for the redqueen module
    let path = std::path::Path::new(&manifest_dir).join("src").join("redqueen.rs");

    output.push_str("use snapchange::addrs::VirtAddr;\n");
    output.push_str("use snapchange::fuzzvm::FuzzVm;\n");
    output.push_str("use snapchange::cmp_analysis::RedqueenRule;\n");
    output.push_str("use snapchange::fuzzer::{Breakpoint, AddressLookup, BreakpointType};\n");
    output.push_str("use snapchange::{Cr3, Execution, Fuzzer, FuzzInput};\n");
    output.push_str("use std::ops::*;\n");
    output.push_str(&format!("const CR3: Cr3 = Cr3({cr3:#x});\n"));
    output.push_str("#[allow(unused_mut)]\n");
    output.push_str("#[allow(unused_parens)]\n");
    output.push_str("pub fn redqueen_breakpoints<FUZZER: Fuzzer>() -> Option<&'static [Breakpoint<FUZZER>]> {\n");
    output.push_str("    Some(&[\n");
    // Init writing breakpoints
    // Read the .cmps files to gather the cmp rules for this target
    for file in cmp_files {
        let data = std::fs::read_to_string(file.path()).unwrap();

        let lines: Vec<_> = data.lines().collect();

        let mut index = 0;
        loop {
            // If this is the last line, we're done!
            if index >= lines.len() {
                break;
            }

            let mut line = lines[index].to_string();
            index += 1;

            // Look ahead to see if the next line also has the same address. It's possible currently for the
            // same address to have different comparisons (like checking doubles)
            // Example:
            // 5555555558a0 zmm0 < zmm1 
            // 5555555558a0 zmm0 == zmm1 
            for _ in 0..4 {
                // If this is the last line, no need to check for another line
                if index >= lines.len() {
                    break;
                }

                let next_line = lines[index];

                let Some([line_addr, _line_cmp_size, line_left, line_op, line_right]) = line.split(',').array_chunks().next() else {
                    panic!("Invalid cmp analysis rule found: {line:?}");
                };
                let line_addr = u64::from_str_radix(&line_addr.replace("0x", ""), 16).unwrap();

                let Some([next_line_addr, _next_line_cmp_size, next_line_left, next_line_op, next_line_right]) 
                        = next_line.split(',').array_chunks().next() else {
                    panic!("Invalid cmp analysis rule found: {next_line:?}");
                };
                let next_line_addr = u64::from_str_radix(&next_line_addr.replace("0x", ""), 16).unwrap();

                // If these two lines don't have the same address, there is no worry of clashing rules. 
                if line_addr != next_line_addr {
                    break;
                }

                // If these two lines have the same address, but different operands with different 
                // comparisons, we can't handle this case currently
                if line_left != next_line_left {
                    panic!("Address {line_addr:#x} has multiple redqueen breakpoints with different comparisons");
                }

                if line_right != next_line_right {
                    panic!("Address {next_line_addr:#x} has multiple redqueen breakpoints with different comparisons");
                }

                
                // Two lines with matching operands but different comparisons. Fix
                match (line_op, next_line_op) {
                    ("FCMP_LT", "FCMP_E") => line = line.replace("FCMP_LT", "FCMP_LE"),
                    ("FCMP_E",  "FCMP_LT") => line = line.replace("FCMP_E", "FCMP_LE"),
                    ("FCMP_GE", "FCMP_NE") => line = line.replace("FCMP_GE", "FCMP_GT"),
                    ("FCMP_NE", "FCMP_GE") => line = line.replace("FCMP_NE", "FCMP_GT"),
                    (a, b) => {
                        panic!("Unknown: {a} {b}");
                    }
                }

                // Skip over the line that we combined together
                index += 1;
            }

            
            // Expected rule format: 0x555555555246,4,load_from add rbp -0x10,NE,0x11111111
            let Some([addr, cmp_size, left_op, operation, right_op]) = line.split(',').array_chunks().next() else {
                panic!("Invalid cmp analysis rule found: {line}");
            };

            let addr = u64::from_str_radix(&addr.replace("0x", ""), 16)
                .expect("Failed to parse cmp analysis address");

            breakpoint_addresses.push(addr);


            let operation = match operation {
                "CMP_E" => CmpOperation::Equal,
                "CMP_NE" => CmpOperation::NotEqual,
                "CMP_SLT" => CmpOperation::SignedLessThan,
                "CMP_ULT" => CmpOperation::UnsignedLessThan,
                "CMP_SLE" => CmpOperation::SignedLessThanEqual,
                "CMP_ULE" => CmpOperation::UnsignedLessThanEqual,
                "CMP_SGT" => CmpOperation::SignedGreaterThan,
                "CMP_UGT" => CmpOperation::UnsignedGreaterThan,
                "CMP_SGE" => CmpOperation::SignedGreaterThanEqual,
                "CMP_UGE" => CmpOperation::UnsignedGreaterThanEqual,
                "FCMP_E"   => CmpOperation::FloatingPointEqual,
                "FCMP_NE"  => CmpOperation::FloatingPointNotEqual,
                "FCMP_LT"  => CmpOperation::FloatingPointLessThan,
                "FCMP_LE"  => CmpOperation::FloatingPointLessThanEqual,
                "FCMP_GT"  => CmpOperation::FloatingPointGreaterThan,
                "FCMP_GE"  => CmpOperation::FloatingPointGreaterThanEqual,
                "strcmp" => CmpOperation::Strcmp,
                "memcmp" => CmpOperation::Memcmp,
                _ => unimplemented!("Unknown operation: {operation}"),
            };

            let (mut left_op, _remainder, left_op_name) = parse_cmp_operand(left_op, String::new(), 0);
            let (mut right_op, _remainder, right_op_name) = parse_cmp_operand(right_op, String::new(), 0);

            if left_op.contains("xmm") {
                if cmp_size == "f0x4" {
                    left_op = left_op
                        .replace("xmm0", "xmm0_f32")
                        .replace("xmm1", "xmm1_f32")
                        .replace("xmm2", "xmm2_f32")
                        .replace("xmm3", "xmm3_f32")
                        .replace("xmm4", "xmm4_f32")
                        .replace("xmm5", "xmm5_f32")
                        .replace("xmm6", "xmm6_f32")
                        .replace("xmm7", "xmm7_f32")
                        .replace("xmm8", "xmm8_f32")
                        .replace("xmm9", "xmm9_f32")
                        .replace("xmm10", "xmm10_f32")
                        .replace("xmm11", "xmm11_f32")
                        .replace("xmm12", "xmm12_f32")
                        .replace("xmm13", "xmm13_f32")
                        .replace("xmm14", "xmm14_f32")
                        .replace("xmm15", "xmm15_f32");
                } else {
                    left_op = left_op
                        .replace("xmm0", "xmm0_f64")
                        .replace("xmm1", "xmm1_f64")
                        .replace("xmm2", "xmm2_f64")
                        .replace("xmm3", "xmm3_f64")
                        .replace("xmm4", "xmm4_f64")
                        .replace("xmm5", "xmm5_f64")
                        .replace("xmm6", "xmm6_f64")
                        .replace("xmm7", "xmm7_f64")
                        .replace("xmm8", "xmm8_f64")
                        .replace("xmm9", "xmm9_f64")
                        .replace("xmm10", "xmm10_f64")
                        .replace("xmm11", "xmm11_f64")
                        .replace("xmm12", "xmm12_f64")
                        .replace("xmm13", "xmm13_f64")
                        .replace("xmm14", "xmm14_f64")
                        .replace("xmm15", "xmm15_f64");
                }
            }

            if right_op.contains("xmm") {
                if cmp_size == "f0x4" {
                    right_op = right_op
                        .replace("xmm0", "xmm0_f32")
                        .replace("xmm1", "xmm1_f32")
                        .replace("xmm2", "xmm2_f32")
                        .replace("xmm3", "xmm3_f32")
                        .replace("xmm4", "xmm4_f32")
                        .replace("xmm5", "xmm5_f32")
                        .replace("xmm6", "xmm6_f32")
                        .replace("xmm7", "xmm7_f32")
                        .replace("xmm8", "xmm8_f32")
                        .replace("xmm9", "xmm9_f32")
                        .replace("xmm10", "xmm10_f32")
                        .replace("xmm11", "xmm11_f32")
                        .replace("xmm12", "xmm12_f32")
                        .replace("xmm13", "xmm13_f32")
                        .replace("xmm14", "xmm14_f32")
                        .replace("xmm15", "xmm15_f32");
                } else {
                    right_op = right_op
                        .replace("xmm0", "xmm0_f64")
                        .replace("xmm1", "xmm1_f64")
                        .replace("xmm2", "xmm2_f64")
                        .replace("xmm3", "xmm3_f64")
                        .replace("xmm4", "xmm4_f64")
                        .replace("xmm5", "xmm5_f64")
                        .replace("xmm6", "xmm6_f64")
                        .replace("xmm7", "xmm7_f64")
                        .replace("xmm8", "xmm8_f64")
                        .replace("xmm9", "xmm9_f64")
                        .replace("xmm10", "xmm10_f64")
                        .replace("xmm11", "xmm11_f64")
                        .replace("xmm12", "xmm12_f64")
                        .replace("xmm13", "xmm13_f64")
                        .replace("xmm14", "xmm14_f64")
                        .replace("xmm15", "xmm15_f64");
                }
            }

            let left_literal = left_op.starts_with("0x");
            let right_literal = right_op.starts_with("0x");

            let value_type = match cmp_size {
                "0x1" => "u8",
                "0x2" => "u16",
                "0x4" => "u32",
                "0x8" => "u64",
                "0x10" => "u128",
                "f0x4" => "f32",
                "f0x8" => "f64",
                _ => "u64"
            };

            let unsigned_type = value_type;

            let signed_type = match cmp_size {
                "0x1" => "i8",
                "0x2" => "i16",
                "0x4" => "i32",
                "0x8" => "i64",
                "0x10" => "i128",
                "f0x4" => "f32",
                "f0x8" => "f64",
                _ => "i64"
            };

            let cmp_size = u32::from_str_radix(&cmp_size.replace("0x", "").replace("f", ""), 16)
                .expect("Failed to parse cmp analysis cmp_size");

            // let (cmp_size, _remainder) = parse_cmp_operand(cmp_size);

            output.push_str(&format!(" // ORIGINAL LINE:{line}\n"));
            output.push_str(&format!(" // {addr:#x} {cmp_size:#x} {operation:?}\n"));

            output.push_str(&format!("Breakpoint {{\n"));
            output.push_str(&format!("    lookup: AddressLookup::Virtual(VirtAddr({addr:#x}), CR3),\n" ));
            output.push_str(&format!("    bp_type: BreakpointType::Repeated,\n"));
            output.push_str(&format!("    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {{\n" ));
            // output.push_str(&format!("        fuzzvm.print_context();\n"));
            output.push_str(&format!("        // Get the hash of the input to use as a key into the redqueen rules map\n"));
            output.push_str(&format!("        let input_hash = snapchange::utils::calculate_hash(input);\n" ));
            // output.push_str(&format!("        let rip = VirtAddr(fuzzvm.rip());\n"));
            // output.push_str(&format!("        println!(\"{addr:#x} {operation:?} {{left_op:#x}} {{right_op:#x}}\");\n"));

            // Ease of use macro to add the rule to the redqueen rules map
            macro_rules! add_rule {
                () => {{
                    // output.push_str(&format!("        println!(\"Hash {{input_hash:#x}} Addr {addr:#x} Rule: {{:x?}}\", &rule);\n"));
                    output.push_str(&format!("        // Only add this rule to the redqueen rules if the left operand\n"));
                    output.push_str(&format!("        // is actually in the input\n"));
                    output.push_str(&format!("        if input.get_redqueen_rule_candidates(&rule).len() > 0 {{\n"));
                    // output.push_str(&format!("            println!(\"{{:#x}} THIS RULE {{rule:x?}}\", fuzzvm.rip());\n"));
                    output.push_str(&format!("            fuzzvm\n"));
                    output.push_str(&format!("                .redqueen_rules\n"));
                    output.push_str(&format!("                .entry(input_hash)\n"));
                    output.push_str(&format!("                .or_default()\n"));
                    // output.push_str(&format!("                .insert((rip, rule));\n"));
                    output.push_str(&format!("                .insert(rule);\n"));
                    output.push_str(&format!("        }}\n"));
                }}
            }

            macro_rules! impl_condition {
                 (float, $op:literal, $adjustment_func:literal, true add $iftrue_add:expr, false add $iffalse_add:expr) => {
                    // output.push_str(&format!("        println!(\"{{:#x}} Left {{left_op}} Right {{right_op}}\", fuzzvm.rip());\n"));
                    // output.push_str(&format!("        println!(\"{{:#x}} Left {{:02x?}} Right {{:02x?}}\", fuzzvm.rip(), left_op.to_le_bytes(), right_op.to_le_bytes());\n"));
                    // output.push_str(&format!("        println!(\"{{:#x}} XMM {{:02x?}}\", fuzzvm.rip(), fuzzvm.xmm0());\n"));
                    // output.push_str(&format!("        fuzzvm.hexdump(VirtAddr(fuzzvm.rax()), CR3, 0x20);\n"));
                    let float_type = format!("f{}", cmp_size * 8);
                    output.push_str(&left_op);
                    output.push_str(&format!("        let mut left_op = {left_op_name} as {float_type};\n"));
                    output.push_str(&right_op);
                    output.push_str(&format!("        let mut right_op = {right_op_name} as {float_type};\n"));
                    output.push_str(&format!("        if left_op {} right_op {{\n", $op));
                    // If the left operand is not literal, attempt to replace the left operand with the right
                    if !left_literal {
                        output.push_str(&format!("                let rule = RedqueenRule::SingleF{}(left_op.to_le_bytes().to_vec(), right_op.{}({}).to_le_bytes().to_vec());\n", 
                            cmp_size * 8, $adjustment_func, $iftrue_add));
                        add_rule!();
                    }
                    if !right_literal {
                        output.push_str(&format!("                let rule = RedqueenRule::SingleF{}(right_op.to_le_bytes().to_vec(), left_op.{}({}).to_le_bytes().to_vec());\n", 
                                    cmp_size * 8, $adjustment_func, $iftrue_add));
                        add_rule!();
                    }
                    output.push_str(&format!("        }} else {{\n"));
                    // If the left operand is not literal, attempt to replace the left operand with the right
                    if !left_literal {
                        output.push_str(&format!("                let rule = RedqueenRule::SingleF{}(left_op.to_le_bytes().to_vec(), right_op.{}({}).to_le_bytes().to_vec());\n", 
                                    cmp_size * 8, $adjustment_func, $iffalse_add));
                        add_rule!();
                    }
                    if !right_literal {
                        output.push_str(&format!("                let rule = RedqueenRule::SingleF{}(right_op.to_le_bytes().to_vec(), left_op.{}({}).to_le_bytes().to_vec());\n", 
                                    cmp_size * 8, $adjustment_func, $iffalse_add));
                        add_rule!();
                    }
                    output.push_str(&format!("        }}\n"));
                };
                ($ty:expr, $op:literal, $adjustment_func:literal, true add $iftrue_add:expr, false add $iffalse_add:expr) => {
                    output.push_str(&left_op);
                    output.push_str(&format!("        let mut left_op = {left_op_name} as {};\n" , $ty));
                    output.push_str(&right_op);
                    output.push_str(&format!("        let mut right_op = {right_op_name} as {};\n" , $ty));

                    // output.push_str(&format!("        let mut left_op = {left_op} as {value_type};\n" ));
                    // output.push_str(&format!("        let mut right_op = {right_op} as {value_type};\n" ));
                    output.push_str(&format!("        if (left_op as {}) {} (right_op as {}) {{\n", $ty, $op, $ty));
                    // If the left operand is not literal, attempt to replace the left operand with the right
                    if !left_literal {
                        output.push_str(&format!("                let rule = RedqueenRule::SingleU{}((left_op as u{}), (right_op as u{}).{}({}));\n", 
                            cmp_size * 8, cmp_size * 8, cmp_size * 8,$adjustment_func, $iftrue_add));
                        add_rule!();
                    }
                    if !right_literal {
                        output.push_str(&format!("                let rule = RedqueenRule::SingleU{}((right_op as u{}), (left_op as u{}).{}({}));\n", 
                                    cmp_size * 8, cmp_size * 8, cmp_size * 8, $adjustment_func, $iftrue_add));
                        add_rule!();
                    }
                    output.push_str(&format!("        }} else {{\n"));
                    // If the left operand is not literal, attempt to replace the left operand with the right
                    if !left_literal {
                        output.push_str(&format!("                let rule = RedqueenRule::SingleU{}((left_op as u{}), (right_op as u{}).{}({}));\n", 
                                    cmp_size * 8, cmp_size * 8, cmp_size * 8, $adjustment_func, $iffalse_add));
                        add_rule!();
                    }
                    if !right_literal {
                        output.push_str(&format!("                let rule = RedqueenRule::SingleU{}((right_op as u{}), (left_op as u{}).{}({}));\n", 
                                    cmp_size * 8, cmp_size * 8, cmp_size * 8, $adjustment_func, $iffalse_add));
                        add_rule!();
                    }
                    output.push_str(&format!("        }}\n"));
                };
            }

            match operation {
                CmpOperation::Equal => {
                    impl_condition!(unsigned_type, "==", "wrapping_add", true add "1", false add "0");
                }
                CmpOperation::NotEqual => {
                    impl_condition!(unsigned_type, "!=", "wrapping_add", true add "0", false add "1");
                }
                CmpOperation::SignedGreaterThanEqual => {
                    impl_condition!(signed_type, ">=", "wrapping_add_signed", true add "-1", false add "0");
                }
                CmpOperation::SignedGreaterThan => {
                    impl_condition!(signed_type, ">", "wrapping_add_signed", true add "-1", false add "1");
                }
                CmpOperation::SignedLessThanEqual => {
                    impl_condition!(signed_type, "<=", "wrapping_add_signed", true add "1", false add "-1");
                }
                CmpOperation::SignedLessThan => {
                    impl_condition!(signed_type, "<", "wrapping_add_signed", true add "0", false add "1");
                }
                CmpOperation::UnsignedGreaterThanEqual => {
                    impl_condition!(unsigned_type, ">=", "wrapping_add_signed", true add "-1", false add "0");
                }
                CmpOperation::UnsignedGreaterThan => {
                    impl_condition!(unsigned_type, ">", "wrapping_add_signed", true add "-1", false add "1");
                }
                CmpOperation::UnsignedLessThanEqual => {
                    impl_condition!(unsigned_type, "<=", "wrapping_add_signed", true add "1", false add "-1");
                }
                CmpOperation::UnsignedLessThan => {
                    impl_condition!(unsigned_type, "<", "wrapping_add_signed", true add "0", false add "1");
                }
                CmpOperation::FloatingPointEqual => {
                    impl_condition!(float, "==", "add", true add "1.0", false add "0.0");
                }
                CmpOperation::FloatingPointNotEqual => {
                    impl_condition!(float, "!=", "add", true add "0.0", false add "1.0");
                }
                CmpOperation::FloatingPointLessThan => {
                    impl_condition!(float, "<", "add", true add "0.0", false add "1.0");
                }
                CmpOperation::FloatingPointLessThanEqual => {
                    impl_condition!(float, "<=", "add", true add "1.0", false add "1.0");
                }
                CmpOperation::FloatingPointGreaterThan => {
                    impl_condition!(float, ">", "add", true add "-1.0", false add "1.0");
                }
                CmpOperation::FloatingPointGreaterThanEqual => {
                    impl_condition!(float, ">=", "add", true add "-1.0", false add "0.0");
                }
                CmpOperation::Strcmp => {
                    output.push_str(&left_op);
                    output.push_str(&format!("        let mut left_op: {value_type} = {left_op_name}.try_into().unwrap();\n"));
                    output.push_str(&right_op);
                    output.push_str(&format!("        let mut right_op: {value_type} = {right_op_name}.try_into().unwrap();\n"));

                    // output.push_str(&format!("        let mut left_op = {left_op} as {value_type};\n" ));
                    // output.push_str(&format!("        let mut right_op = {right_op} as {value_type};\n" ));
                    output.push_str(&format!("        let mut left_bytes = fuzzvm.read_bytes_until(VirtAddr(left_op), CR3, 0, 0x4000)?;\n"));
                    output.push_str(&format!("        let mut right_bytes = fuzzvm.read_bytes_until(VirtAddr(right_op), CR3, 0, 0x4000)?;\n"));
                    output.push_str(&format!("        if left_bytes != right_bytes {{\n"));
                    output.push_str(&format!("                let min_size = left_bytes.len().min(right_bytes.len());\n" ));
                    output.push_str(&format!("                let rule = RedqueenRule::Bytes(left_bytes.clone(), right_bytes.clone());\n"));
                    add_rule!();
                    output.push_str(&format!("                let rule = RedqueenRule::Bytes(right_bytes.clone(), left_bytes.clone());\n"));
                    add_rule!();
                    output.push_str(&format!("                left_bytes.truncate(min_size);\n"));
                    output.push_str(&format!("                right_bytes.truncate(min_size);\n" ));
                    output.push_str(&format!("                let rule = RedqueenRule::Bytes(left_bytes.clone(), right_bytes.clone());\n"));
                    add_rule!();
                    output.push_str(&format!("                let rule = RedqueenRule::Bytes(right_bytes.clone(), left_bytes.clone());\n"));
                    add_rule!();
                    output.push_str(&format!("        }} else {{\n"));
                    output.push_str(&format!("            // Strings are equal, force them to not be equal\n" ));
                    output.push_str(&format!("            let mut new_left = left_bytes.clone();\n" ));
                    output.push_str(&format!("            new_left[0] = new_left[0].wrapping_add(1);\n" ));
                    output.push_str(&format!("            let rule = RedqueenRule::Bytes(right_bytes, new_left);\n" ));
                    add_rule!();
                    output.push_str(&format!("        }}\n"));
                }
                CmpOperation::Memcmp => {
                    // output.push_str(&format!("        let mut left_op = {left_op} as {value_type};\n" ));
                    // output.push_str(&format!("        let mut right_op = {right_op} as {value_type};\n" ));
                    output.push_str(&left_op);
                    output.push_str(&format!("        let mut left_op: {value_type} = {left_op_name}.try_into().unwrap();\n"));
                    output.push_str(&right_op);
                    output.push_str(&format!("        let mut right_op: {value_type} = {right_op_name}.try_into().unwrap();\n"));
                    output.push_str(&format!("        let mut left_bytes = vec![0u8; {cmp_size}];\n" ));
                    output.push_str(&format!("        fuzzvm.read_bytes(VirtAddr(left_op), CR3, &mut left_bytes).unwrap();\n"));
                    output.push_str(&format!("        let mut right_bytes = vec![0u8; {cmp_size}];\n" ));
                    output.push_str(&format!("        fuzzvm.read_bytes(VirtAddr(right_op), CR3, &mut right_bytes).unwrap();\n"));
                    output.push_str(&format!("        if left_bytes != right_bytes {{\n"));
                    output.push_str(&format!("                let rule = RedqueenRule::Bytes(left_bytes.clone(), right_bytes.clone());\n"));
                    add_rule!();
                    output.push_str(&format!("            let rule = RedqueenRule::Bytes(right_bytes.clone(), left_bytes.clone());\n"));
                    add_rule!();
                    output.push_str(&format!("        }} else {{\n"));
                    output.push_str(&format!("            // Strings are equal, force them to not be equal\n" ));
                    output.push_str(&format!("            let mut new_left = left_bytes.clone();\n" ));
                    output.push_str(&format!("            new_left[0] = new_left[0].wrapping_add(1);\n" ));
                    output.push_str(&format!("            let rule = RedqueenRule::Bytes(right_bytes, new_left);\n" ));
                    add_rule!();
                    output.push_str(&format!("        }}\n"));
                }
            }
            output.push_str(&format!(
                "        // Insert the rule in the total redqueen rules\n"
            ));
            output.push_str(&format!("        Ok(Execution::Continue)\n"));
            output.push_str(&format!("    }}\n"));
            output.push_str(&format!("}},\n"));
        }
    }

    // End writing breakpoints
    output.push_str("    ])\n");
    output.push_str("}\n");

    output.push_str("pub fn redqueen_breakpoint_addresses() -> &'static [u64] {\n");
    output.push_str("    &[\n");
    for addr in breakpoint_addresses {
        output.push_str(&format!("{addr:#x},\n"));
    }
    output.push_str("]}\n");

    std::fs::write(&path, output).unwrap();

}

/// Parse the cmp line given by the binja plugin and return how to retrieve
/// the information from a `fuzzvm`.
///
/// Example:
///
/// BP Address,Size,Operand 1,Operation,Operand 2
///
/// 0x555555555514,0x4,reg eax,E,0x912f2593
/// 0x55555555557e,0x4,load_from add reg rax 0x4,SLT,0x41414141
///
/// Operand examples:
///
/// reg eax -> eax
/// load_from add reg rax 0x4 -> [rax + 0x4]
///
/// Function calls:
///
/// 0x55555555582c,0x30,reg rdi,memcmp,reg rsi -> memcmp(rdi, rsi)
fn parse_cmp_operand(input: &str, mut res: String, index: usize) -> (String, &str, String) {
    let var_name = format!("arg{index}");

    if let Some(input) = input.strip_prefix("load_from ") {
        // load_from cmd: Need to deref a memory address
        let (mut res, input, name) = parse_cmp_operand(input, res, index + 1);
        res.push_str(&format!(
            "let {var_name} = fuzzvm.read::<u64>(VirtAddr({name}), CR3).unwrap();\n"
        ));
        (res, input, var_name)
    } else if input.starts_with("0x") {
        // Literal number

        // Get the first element before a space in the input
        // or the entire string if this is the last element
        let (num, input) = if let Some(elem) = input.split_once(' ') {
            elem
        } else {
            (input, "")
        };

        res.push_str(&format!("let {var_name} = {num} as u64;\n"));

        // Return the number and the remainder
        (res, input, var_name)
    } else if input.starts_with("-0x") {
        // Literal negative hex number

        // Get the first element before a space in the input
        // or the entire string if this is the last element
        let (num, input) = if let Some(elem) = input.split_once(' ') {
            elem
        } else {
            (input, "")
        };

        res.push_str(&format!("let {var_name} = ({num}_i64) as u64;\n"));
        (res, input, var_name)
    } else if let Some(input) = input.strip_prefix("reg ") {
        // Get the first element before a space in the input
        // or the entire string if this is the last element
        let (reg, input) = if let Some(elem) = input.split_once(' ') {
            elem
        } else {
            (input, "")
        };

        let as_u64 = if !reg.contains("xmm") { "as u64" } else { "" };

        res.push_str(&format!("let {var_name} = fuzzvm.{reg}() {as_u64};\n"));
        (res, input, var_name)
    } else if input.contains(".") {
        let (num, input) = if let Some(elem) = input.split_once(' ') {
            elem
        } else {
            (input, "")
        };

        res.push_str(&format!("let {var_name} = {num};\n"));
        (res, input, var_name)
    } else {
        for (cmd, func) in &[
            ("add ", "wrapping_add"),
            ("and ", "bitand"),
            ("sub ", "wrapping_sub"),
            ("logical_shift_left ", "shl"),
            ("left_shift_left ", "shl"),
        ] {
            if let Some(input) = input.strip_prefix(cmd) {
                // Found a command. Get the left and right operands for this command
                let (res, input, left_var) = parse_cmp_operand(input, res, index + 1);
                let (mut res, input, right_var) = parse_cmp_operand(input, res, index + 2);

                res.push_str(&format!(
                    "let {var_name} = {left_var}.{func}({right_var});\n"
                ));

                // Return the result
                return (res, input, var_name);
            }
        }

        // No command was found. Return Unknown
        (format!("UNKNOWN: {input}"), input, "unknown".to_string())
    }
}
