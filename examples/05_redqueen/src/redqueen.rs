use snapchange::addrs::VirtAddr;
use snapchange::fuzzvm::FuzzVm;
use snapchange::cmp_analysis::RedqueenRule;
use snapchange::fuzzer::{Breakpoint, AddressLookup, BreakpointType};
use snapchange::{Cr3, Execution, Fuzzer, FuzzInput};
use std::ops::*;
const CR3: Cr3 = Cr3(0x100994000);
#[allow(unused_mut)]
#[allow(unused_parens)]
pub fn redqueen_breakpoints<FUZZER: Fuzzer>() -> Option<&'static [Breakpoint<FUZZER>]> {
    Some(&[
 // ORIGINAL LINE:0x5555555551eb,0x1,load_from 0x555555558018,CMP_NE,0x0
 // 0x5555555551eb 0x1 NotEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x5555555551eb), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg1 = 0x555555558018 as u64;
let arg0 = fuzzvm.read::<u64>(VirtAddr(arg1), CR3).unwrap();
        let mut left_op = arg0 as u8;
let arg0 = 0x0 as u64;
        let mut right_op = arg0 as u8;
        if (left_op as u8) != (right_op as u8) {
                let rule = RedqueenRule::SingleU8((left_op as u8), (right_op as u8).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU8((right_op as u8), (left_op as u8).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU8((left_op as u8), (right_op as u8).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU8((right_op as u8), (left_op as u8).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555268,0x4,reg eax,CMP_SLT,load_from add reg rbp -0x1c
 // 0x555555555268 0x4 SignedLessThan
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555268), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.eax() as u64;
        let mut left_op = arg0 as i32;
let arg2 = fuzzvm.rbp() as u64;
let arg3 = (-0x1c_i64) as u64;
let arg1 = arg2.wrapping_add(arg3);
let arg0 = fuzzvm.read::<u64>(VirtAddr(arg1), CR3).unwrap();
        let mut right_op = arg0 as i32;
        if (left_op as i32) < (right_op as i32) {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add_signed(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add_signed(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x5555555552f2,0x4,reg eax,CMP_E,0xd39a8f32
 // 0x5555555552f2 0x4 Equal
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x5555555552f2), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.eax() as u64;
        let mut left_op = arg0 as u32;
let arg0 = 0xd39a8f32 as u64;
        let mut right_op = arg0 as u32;
        if (left_op as u32) == (right_op as u32) {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x55555555535c,0x4,reg eax,CMP_NE,0x0
 // 0x55555555535c 0x4 NotEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x55555555535c), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.eax() as u64;
        let mut left_op = arg0 as u32;
let arg0 = 0x0 as u64;
        let mut right_op = arg0 as u32;
        if (left_op as u32) != (right_op as u32) {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x55555555537a,0x4,reg eax,CMP_E,0xa51c1874
 // 0x55555555537a 0x4 Equal
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x55555555537a), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.eax() as u64;
        let mut left_op = arg0 as u32;
let arg0 = 0xa51c1874 as u64;
        let mut right_op = arg0 as u32;
        if (left_op as u32) == (right_op as u32) {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x5555555553e4,0x4,reg eax,CMP_NE,0x0
 // 0x5555555553e4 0x4 NotEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x5555555553e4), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.eax() as u64;
        let mut left_op = arg0 as u32;
let arg0 = 0x0 as u64;
        let mut right_op = arg0 as u32;
        if (left_op as u32) != (right_op as u32) {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555402,0x4,reg eax,CMP_E,0x29bcacf9
 // 0x555555555402 0x4 Equal
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555402), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.eax() as u64;
        let mut left_op = arg0 as u32;
let arg0 = 0x29bcacf9 as u64;
        let mut right_op = arg0 as u32;
        if (left_op as u32) == (right_op as u32) {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x55555555546c,0x4,reg eax,CMP_NE,0x0
 // 0x55555555546c 0x4 NotEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x55555555546c), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.eax() as u64;
        let mut left_op = arg0 as u32;
let arg0 = 0x0 as u64;
        let mut right_op = arg0 as u32;
        if (left_op as u32) != (right_op as u32) {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x55555555548a,0x4,reg eax,CMP_E,0x7736a87f
 // 0x55555555548a 0x4 Equal
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x55555555548a), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.eax() as u64;
        let mut left_op = arg0 as u32;
let arg0 = 0x7736a87f as u64;
        let mut right_op = arg0 as u32;
        if (left_op as u32) == (right_op as u32) {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x5555555554f4,0x4,reg eax,CMP_NE,0x0
 // 0x5555555554f4 0x4 NotEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x5555555554f4), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.eax() as u64;
        let mut left_op = arg0 as u32;
let arg0 = 0x0 as u64;
        let mut right_op = arg0 as u32;
        if (left_op as u32) != (right_op as u32) {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555523,0x4,reg eax,CMP_NE,0x41414141
 // 0x555555555523 0x4 NotEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555523), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.eax() as u64;
        let mut left_op = arg0 as u32;
let arg0 = 0x41414141 as u64;
        let mut right_op = arg0 as u32;
        if (left_op as u32) != (right_op as u32) {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555538,0x4,reg eax,CMP_SLE,0x41414140
 // 0x555555555538 0x4 SignedLessThanEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555538), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.eax() as u64;
        let mut left_op = arg0 as i32;
let arg0 = 0x41414140 as u64;
        let mut right_op = arg0 as i32;
        if (left_op as i32) <= (right_op as i32) {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x55555555554d,0x4,reg eax,CMP_SGT,0x41414141
 // 0x55555555554d 0x4 SignedGreaterThan
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x55555555554d), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.eax() as u64;
        let mut left_op = arg0 as i32;
let arg0 = 0x41414141 as u64;
        let mut right_op = arg0 as i32;
        if (left_op as i32) > (right_op as i32) {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555562,0x4,reg eax,CMP_SLE,0x41414141
 // 0x555555555562 0x4 SignedLessThanEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555562), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.eax() as u64;
        let mut left_op = arg0 as i32;
let arg0 = 0x41414141 as u64;
        let mut right_op = arg0 as i32;
        if (left_op as i32) <= (right_op as i32) {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555577,0x4,reg eax,CMP_SGT,0x41414140
 // 0x555555555577 0x4 SignedGreaterThan
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555577), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.eax() as u64;
        let mut left_op = arg0 as i32;
let arg0 = 0x41414140 as u64;
        let mut right_op = arg0 as i32;
        if (left_op as i32) > (right_op as i32) {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x55555555558c,0x4,reg eax,CMP_NE,0x42424242
 // 0x55555555558c 0x4 NotEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x55555555558c), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.eax() as u64;
        let mut left_op = arg0 as u32;
let arg0 = 0x42424242 as u64;
        let mut right_op = arg0 as u32;
        if (left_op as u32) != (right_op as u32) {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x5555555555a1,0x4,reg eax,CMP_ULE,0x42424241
 // 0x5555555555a1 0x4 UnsignedLessThanEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x5555555555a1), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.eax() as u64;
        let mut left_op = arg0 as u32;
let arg0 = 0x42424241 as u64;
        let mut right_op = arg0 as u32;
        if (left_op as u32) <= (right_op as u32) {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x5555555555b6,0x4,reg eax,CMP_UGT,0x42424242
 // 0x5555555555b6 0x4 UnsignedGreaterThan
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x5555555555b6), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.eax() as u64;
        let mut left_op = arg0 as u32;
let arg0 = 0x42424242 as u64;
        let mut right_op = arg0 as u32;
        if (left_op as u32) > (right_op as u32) {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x5555555555cb,0x4,reg eax,CMP_ULE,0x42424242
 // 0x5555555555cb 0x4 UnsignedLessThanEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x5555555555cb), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.eax() as u64;
        let mut left_op = arg0 as u32;
let arg0 = 0x42424242 as u64;
        let mut right_op = arg0 as u32;
        if (left_op as u32) <= (right_op as u32) {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x5555555555e0,0x4,reg eax,CMP_UGT,0x42424241
 // 0x5555555555e0 0x4 UnsignedGreaterThan
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x5555555555e0), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.eax() as u64;
        let mut left_op = arg0 as u32;
let arg0 = 0x42424241 as u64;
        let mut right_op = arg0 as u32;
        if (left_op as u32) > (right_op as u32) {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x5555555555f5,0x2,reg ax,CMP_NE,0x4343
 // 0x5555555555f5 0x2 NotEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x5555555555f5), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.ax() as u64;
        let mut left_op = arg0 as u16;
let arg0 = 0x4343 as u64;
        let mut right_op = arg0 as u16;
        if (left_op as u16) != (right_op as u16) {
                let rule = RedqueenRule::SingleU16((left_op as u16), (right_op as u16).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU16((right_op as u16), (left_op as u16).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU16((left_op as u16), (right_op as u16).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU16((right_op as u16), (left_op as u16).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x55555555560a,0x2,reg ax,CMP_SLE,0x4342
 // 0x55555555560a 0x2 SignedLessThanEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x55555555560a), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.ax() as u64;
        let mut left_op = arg0 as i16;
let arg0 = 0x4342 as u64;
        let mut right_op = arg0 as i16;
        if (left_op as i16) <= (right_op as i16) {
                let rule = RedqueenRule::SingleU16((left_op as u16), (right_op as u16).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU16((right_op as u16), (left_op as u16).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU16((left_op as u16), (right_op as u16).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU16((right_op as u16), (left_op as u16).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x55555555561f,0x2,reg ax,CMP_SGT,0x4343
 // 0x55555555561f 0x2 SignedGreaterThan
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x55555555561f), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.ax() as u64;
        let mut left_op = arg0 as i16;
let arg0 = 0x4343 as u64;
        let mut right_op = arg0 as i16;
        if (left_op as i16) > (right_op as i16) {
                let rule = RedqueenRule::SingleU16((left_op as u16), (right_op as u16).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU16((right_op as u16), (left_op as u16).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU16((left_op as u16), (right_op as u16).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU16((right_op as u16), (left_op as u16).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555634,0x2,reg ax,CMP_SLE,0x4343
 // 0x555555555634 0x2 SignedLessThanEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555634), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.ax() as u64;
        let mut left_op = arg0 as i16;
let arg0 = 0x4343 as u64;
        let mut right_op = arg0 as i16;
        if (left_op as i16) <= (right_op as i16) {
                let rule = RedqueenRule::SingleU16((left_op as u16), (right_op as u16).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU16((right_op as u16), (left_op as u16).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU16((left_op as u16), (right_op as u16).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU16((right_op as u16), (left_op as u16).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555649,0x2,reg ax,CMP_SGT,0x4342
 // 0x555555555649 0x2 SignedGreaterThan
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555649), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.ax() as u64;
        let mut left_op = arg0 as i16;
let arg0 = 0x4342 as u64;
        let mut right_op = arg0 as i16;
        if (left_op as i16) > (right_op as i16) {
                let rule = RedqueenRule::SingleU16((left_op as u16), (right_op as u16).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU16((right_op as u16), (left_op as u16).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU16((left_op as u16), (right_op as u16).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU16((right_op as u16), (left_op as u16).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x55555555565e,0x2,reg ax,CMP_NE,0x4444
 // 0x55555555565e 0x2 NotEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x55555555565e), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.ax() as u64;
        let mut left_op = arg0 as u16;
let arg0 = 0x4444 as u64;
        let mut right_op = arg0 as u16;
        if (left_op as u16) != (right_op as u16) {
                let rule = RedqueenRule::SingleU16((left_op as u16), (right_op as u16).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU16((right_op as u16), (left_op as u16).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU16((left_op as u16), (right_op as u16).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU16((right_op as u16), (left_op as u16).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555673,0x2,reg ax,CMP_ULE,0x4443
 // 0x555555555673 0x2 UnsignedLessThanEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555673), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.ax() as u64;
        let mut left_op = arg0 as u16;
let arg0 = 0x4443 as u64;
        let mut right_op = arg0 as u16;
        if (left_op as u16) <= (right_op as u16) {
                let rule = RedqueenRule::SingleU16((left_op as u16), (right_op as u16).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU16((right_op as u16), (left_op as u16).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU16((left_op as u16), (right_op as u16).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU16((right_op as u16), (left_op as u16).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555688,0x2,reg ax,CMP_UGT,0x4444
 // 0x555555555688 0x2 UnsignedGreaterThan
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555688), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.ax() as u64;
        let mut left_op = arg0 as u16;
let arg0 = 0x4444 as u64;
        let mut right_op = arg0 as u16;
        if (left_op as u16) > (right_op as u16) {
                let rule = RedqueenRule::SingleU16((left_op as u16), (right_op as u16).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU16((right_op as u16), (left_op as u16).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU16((left_op as u16), (right_op as u16).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU16((right_op as u16), (left_op as u16).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x55555555569d,0x2,reg ax,CMP_ULE,0x4444
 // 0x55555555569d 0x2 UnsignedLessThanEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x55555555569d), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.ax() as u64;
        let mut left_op = arg0 as u16;
let arg0 = 0x4444 as u64;
        let mut right_op = arg0 as u16;
        if (left_op as u16) <= (right_op as u16) {
                let rule = RedqueenRule::SingleU16((left_op as u16), (right_op as u16).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU16((right_op as u16), (left_op as u16).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU16((left_op as u16), (right_op as u16).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU16((right_op as u16), (left_op as u16).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x5555555556b2,0x2,reg ax,CMP_UGT,0x4443
 // 0x5555555556b2 0x2 UnsignedGreaterThan
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x5555555556b2), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.ax() as u64;
        let mut left_op = arg0 as u16;
let arg0 = 0x4443 as u64;
        let mut right_op = arg0 as u16;
        if (left_op as u16) > (right_op as u16) {
                let rule = RedqueenRule::SingleU16((left_op as u16), (right_op as u16).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU16((right_op as u16), (left_op as u16).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU16((left_op as u16), (right_op as u16).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU16((right_op as u16), (left_op as u16).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x5555555556d0,0x8,reg rax,CMP_NE,0x4545454545454545
 // 0x5555555556d0 0x8 NotEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x5555555556d0), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.rax() as u64;
        let mut left_op = arg0 as u64;
let arg0 = 0x4545454545454545 as u64;
        let mut right_op = arg0 as u64;
        if (left_op as u64) != (right_op as u64) {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x5555555556f0,0x8,reg rax,CMP_ULE,0x4545454545454544
 // 0x5555555556f0 0x8 UnsignedLessThanEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x5555555556f0), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.rax() as u64;
        let mut left_op = arg0 as u64;
let arg0 = 0x4545454545454544 as u64;
        let mut right_op = arg0 as u64;
        if (left_op as u64) <= (right_op as u64) {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555710,0x8,reg rax,CMP_UGT,0x4545454545454545
 // 0x555555555710 0x8 UnsignedGreaterThan
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555710), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.rax() as u64;
        let mut left_op = arg0 as u64;
let arg0 = 0x4545454545454545 as u64;
        let mut right_op = arg0 as u64;
        if (left_op as u64) > (right_op as u64) {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555730,0x8,reg rax,CMP_ULE,0x4545454545454545
 // 0x555555555730 0x8 UnsignedLessThanEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555730), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.rax() as u64;
        let mut left_op = arg0 as u64;
let arg0 = 0x4545454545454545 as u64;
        let mut right_op = arg0 as u64;
        if (left_op as u64) <= (right_op as u64) {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555750,0x8,reg rax,CMP_UGT,0x4545454545454544
 // 0x555555555750 0x8 UnsignedGreaterThan
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555750), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.rax() as u64;
        let mut left_op = arg0 as u64;
let arg0 = 0x4545454545454544 as u64;
        let mut right_op = arg0 as u64;
        if (left_op as u64) > (right_op as u64) {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555770,0x8,reg rax,CMP_NE,0x524448434947414d
 // 0x555555555770 0x8 NotEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555770), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.rax() as u64;
        let mut left_op = arg0 as u64;
let arg0 = 0x524448434947414d as u64;
        let mut right_op = arg0 as u64;
        if (left_op as u64) != (right_op as u64) {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555790,0x8,reg rax,CMP_SLE,0x524448434947414c
 // 0x555555555790 0x8 SignedLessThanEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555790), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.rax() as u64;
        let mut left_op = arg0 as i64;
let arg0 = 0x524448434947414c as u64;
        let mut right_op = arg0 as i64;
        if (left_op as i64) <= (right_op as i64) {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x5555555557b0,0x8,reg rax,CMP_SGT,0x524448434947414d
 // 0x5555555557b0 0x8 SignedGreaterThan
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x5555555557b0), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.rax() as u64;
        let mut left_op = arg0 as i64;
let arg0 = 0x524448434947414d as u64;
        let mut right_op = arg0 as i64;
        if (left_op as i64) > (right_op as i64) {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x5555555557d0,0x8,reg rax,CMP_SLE,0x524448434947414d
 // 0x5555555557d0 0x8 SignedLessThanEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x5555555557d0), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.rax() as u64;
        let mut left_op = arg0 as i64;
let arg0 = 0x524448434947414d as u64;
        let mut right_op = arg0 as i64;
        if (left_op as i64) <= (right_op as i64) {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x5555555557f0,0x8,reg rax,CMP_SGT,0x524448434947414c
 // 0x5555555557f0 0x8 SignedGreaterThan
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x5555555557f0), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.rax() as u64;
        let mut left_op = arg0 as i64;
let arg0 = 0x524448434947414c as u64;
        let mut right_op = arg0 as i64;
        if (left_op as i64) > (right_op as i64) {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add_signed(-1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add_signed(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x55555555580a,0x4,reg eax,CMP_E,0x0
 // 0x55555555580a 0x4 Equal
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x55555555580a), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.eax() as u64;
        let mut left_op = arg0 as u32;
let arg0 = 0x0 as u64;
        let mut right_op = arg0 as u32;
        if (left_op as u32) == (right_op as u32) {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555824,0x8,reg rdi,strcmp,0x555555556008
 // 0x555555555824 0x8 Strcmp
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555824), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.rdi() as u64;
        let mut left_op: u64 = arg0.try_into().unwrap();
let arg0 = 0x555555556008 as u64;
        let mut right_op: u64 = arg0.try_into().unwrap();
        let mut left_bytes = fuzzvm.read_bytes_until(VirtAddr(left_op), CR3, 0, 0x4000)?;
        let mut right_bytes = fuzzvm.read_bytes_until(VirtAddr(right_op), CR3, 0, 0x4000)?;
        if left_bytes != right_bytes {
                let min_size = left_bytes.len().min(right_bytes.len());
                let rule = RedqueenRule::Bytes(left_bytes.clone(), right_bytes.clone());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::Bytes(right_bytes.clone(), left_bytes.clone());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                left_bytes.truncate(min_size);
                right_bytes.truncate(min_size);
                let rule = RedqueenRule::Bytes(left_bytes.clone(), right_bytes.clone());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::Bytes(right_bytes.clone(), left_bytes.clone());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
            // Strings are equal, force them to not be equal
            let mut new_left = left_bytes.clone();
            new_left[0] = new_left[0].wrapping_add(1);
            let rule = RedqueenRule::Bytes(right_bytes, new_left);
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555851,0x30,reg rdi,memcmp,reg rsi
 // 0x555555555851 0x30 Memcmp
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555851), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.rdi() as u64;
        let mut left_op: u64 = arg0.try_into().unwrap();
let arg0 = fuzzvm.rsi() as u64;
        let mut right_op: u64 = arg0.try_into().unwrap();
        let mut left_bytes = vec![0u8; 48];
        fuzzvm.read_bytes(VirtAddr(left_op), CR3, &mut left_bytes).unwrap();
        let mut right_bytes = vec![0u8; 48];
        fuzzvm.read_bytes(VirtAddr(right_op), CR3, &mut right_bytes).unwrap();
        if left_bytes != right_bytes {
                let rule = RedqueenRule::Bytes(left_bytes.clone(), right_bytes.clone());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
            let rule = RedqueenRule::Bytes(right_bytes.clone(), left_bytes.clone());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
            // Strings are equal, force them to not be equal
            let mut new_left = left_bytes.clone();
            new_left[0] = new_left[0].wrapping_add(1);
            let rule = RedqueenRule::Bytes(right_bytes, new_left);
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555887,0x8,reg rbx,CMP_NE,reg rax
 // 0x555555555887 0x8 NotEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555887), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.rbx() as u64;
        let mut left_op = arg0 as u64;
let arg0 = fuzzvm.rax() as u64;
        let mut right_op = arg0 as u64;
        if (left_op as u64) != (right_op as u64) {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555a7a,0x1,reg al,CMP_NE,0x21
 // 0x555555555a7a 0x1 NotEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555a7a), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.al() as u64;
        let mut left_op = arg0 as u8;
let arg0 = 0x21 as u64;
        let mut right_op = arg0 as u8;
        if (left_op as u8) != (right_op as u8) {
                let rule = RedqueenRule::SingleU8((left_op as u8), (right_op as u8).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU8((right_op as u8), (left_op as u8).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU8((left_op as u8), (right_op as u8).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU8((right_op as u8), (left_op as u8).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555a8b,0x1,reg al,CMP_NE,0x21
 // 0x555555555a8b 0x1 NotEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555a8b), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.al() as u64;
        let mut left_op = arg0 as u8;
let arg0 = 0x21 as u64;
        let mut right_op = arg0 as u8;
        if (left_op as u8) != (right_op as u8) {
                let rule = RedqueenRule::SingleU8((left_op as u8), (right_op as u8).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU8((right_op as u8), (left_op as u8).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU8((left_op as u8), (right_op as u8).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU8((right_op as u8), (left_op as u8).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555a9c,0x4,load_from add reg rbp -0x14,CMP_NE,0xdeadbeef
 // 0x555555555a9c 0x4 NotEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555a9c), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg2 = fuzzvm.rbp() as u64;
let arg3 = (-0x14_i64) as u64;
let arg1 = arg2.wrapping_add(arg3);
let arg0 = fuzzvm.read::<u64>(VirtAddr(arg1), CR3).unwrap();
        let mut left_op = arg0 as u32;
let arg0 = 0xdeadbeef as u64;
        let mut right_op = arg0 as u32;
        if (left_op as u32) != (right_op as u32) {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x55555555582b,0x4,reg eax,CMP_NE,0x0
 // 0x55555555582b 0x4 NotEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x55555555582b), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.eax() as u64;
        let mut left_op = arg0 as u32;
let arg0 = 0x0 as u64;
        let mut right_op = arg0 as u32;
        if (left_op as u32) != (right_op as u32) {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555858,0x4,reg eax,CMP_NE,0x0
 // 0x555555555858 0x4 NotEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555858), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.eax() as u64;
        let mut left_op = arg0 as u32;
let arg0 = 0x0 as u64;
        let mut right_op = arg0 as u32;
        if (left_op as u32) != (right_op as u32) {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU32((left_op as u32), (right_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU32((right_op as u32), (left_op as u32).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x5555555558b1,f0x8,reg xmm0,FCMP_E,111.01
 // 0x5555555558b1 0x8 FloatingPointEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x5555555558b1), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.xmm0_f64() ;
        let mut left_op = arg0 as f64;
let arg0 = 111.01;
        let mut right_op = arg0 as f64;
        if left_op == right_op {
                let rule = RedqueenRule::SingleF64(left_op.to_le_bytes().to_vec(), right_op.add(1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF64(right_op.to_le_bytes().to_vec(), left_op.add(1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleF64(left_op.to_le_bytes().to_vec(), right_op.add(0.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF64(right_op.to_le_bytes().to_vec(), left_op.add(0.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x5555555558ce,f0x8,reg xmm0,FCMP_GE,123.01
 // 0x5555555558ce 0x8 FloatingPointGreaterThanEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x5555555558ce), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.xmm0_f64() ;
        let mut left_op = arg0 as f64;
let arg0 = 123.01;
        let mut right_op = arg0 as f64;
        if left_op >= right_op {
                let rule = RedqueenRule::SingleF64(left_op.to_le_bytes().to_vec(), right_op.add(-1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF64(right_op.to_le_bytes().to_vec(), left_op.add(-1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleF64(left_op.to_le_bytes().to_vec(), right_op.add(0.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF64(right_op.to_le_bytes().to_vec(), left_op.add(0.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x5555555558ef,f0x8,reg xmm0,FCMP_GE,reg xmm1
 // 0x5555555558ef 0x8 FloatingPointGreaterThanEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x5555555558ef), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.xmm0_f64() ;
        let mut left_op = arg0 as f64;
let arg0 = fuzzvm.xmm1_f64() ;
        let mut right_op = arg0 as f64;
        if left_op >= right_op {
                let rule = RedqueenRule::SingleF64(left_op.to_le_bytes().to_vec(), right_op.add(-1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF64(right_op.to_le_bytes().to_vec(), left_op.add(-1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleF64(left_op.to_le_bytes().to_vec(), right_op.add(0.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF64(right_op.to_le_bytes().to_vec(), left_op.add(0.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x55555555590c,f0x8,reg xmm0,FCMP_GT,111.01
 // 0x55555555590c 0x8 FloatingPointGreaterThan
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x55555555590c), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.xmm0_f64() ;
        let mut left_op = arg0 as f64;
let arg0 = 111.01;
        let mut right_op = arg0 as f64;
        if left_op > right_op {
                let rule = RedqueenRule::SingleF64(left_op.to_le_bytes().to_vec(), right_op.add(-1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF64(right_op.to_le_bytes().to_vec(), left_op.add(-1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleF64(left_op.to_le_bytes().to_vec(), right_op.add(1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF64(right_op.to_le_bytes().to_vec(), left_op.add(1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x55555555592d,f0x8,reg xmm0,FCMP_GT,reg xmm1
 // 0x55555555592d 0x8 FloatingPointGreaterThan
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x55555555592d), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.xmm0_f64() ;
        let mut left_op = arg0 as f64;
let arg0 = fuzzvm.xmm1_f64() ;
        let mut right_op = arg0 as f64;
        if left_op > right_op {
                let rule = RedqueenRule::SingleF64(left_op.to_le_bytes().to_vec(), right_op.add(-1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF64(right_op.to_le_bytes().to_vec(), left_op.add(-1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleF64(left_op.to_le_bytes().to_vec(), right_op.add(1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF64(right_op.to_le_bytes().to_vec(), left_op.add(1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555958,f0x8,reg xmm0,FCMP_E,3.14
 // 0x555555555958 0x8 FloatingPointEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555958), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.xmm0_f64() ;
        let mut left_op = arg0 as f64;
let arg0 = 3.14;
        let mut right_op = arg0 as f64;
        if left_op == right_op {
                let rule = RedqueenRule::SingleF64(left_op.to_le_bytes().to_vec(), right_op.add(1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF64(right_op.to_le_bytes().to_vec(), left_op.add(1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleF64(left_op.to_le_bytes().to_vec(), right_op.add(0.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF64(right_op.to_le_bytes().to_vec(), left_op.add(0.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x55555555597f,f0x8,reg xmm0,FCMP_NE,3.14
 // 0x55555555597f 0x8 FloatingPointNotEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x55555555597f), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.xmm0_f64() ;
        let mut left_op = arg0 as f64;
let arg0 = 3.14;
        let mut right_op = arg0 as f64;
        if left_op != right_op {
                let rule = RedqueenRule::SingleF64(left_op.to_le_bytes().to_vec(), right_op.add(0.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF64(right_op.to_le_bytes().to_vec(), left_op.add(0.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleF64(left_op.to_le_bytes().to_vec(), right_op.add(1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF64(right_op.to_le_bytes().to_vec(), left_op.add(1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x5555555559a8,f0x4,reg xmm0,FCMP_E,1230000.0
 // 0x5555555559a8 0x4 FloatingPointEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x5555555559a8), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.xmm0_f32() ;
        let mut left_op = arg0 as f32;
let arg0 = 1230000.0;
        let mut right_op = arg0 as f32;
        if left_op == right_op {
                let rule = RedqueenRule::SingleF32(left_op.to_le_bytes().to_vec(), right_op.add(1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF32(right_op.to_le_bytes().to_vec(), left_op.add(1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleF32(left_op.to_le_bytes().to_vec(), right_op.add(0.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF32(right_op.to_le_bytes().to_vec(), left_op.add(0.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x5555555559c4,f0x4,reg xmm0,FCMP_GE,123.01000213623047
 // 0x5555555559c4 0x4 FloatingPointGreaterThanEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x5555555559c4), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.xmm0_f32() ;
        let mut left_op = arg0 as f32;
let arg0 = 123.01000213623047;
        let mut right_op = arg0 as f32;
        if left_op >= right_op {
                let rule = RedqueenRule::SingleF32(left_op.to_le_bytes().to_vec(), right_op.add(-1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF32(right_op.to_le_bytes().to_vec(), left_op.add(-1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleF32(left_op.to_le_bytes().to_vec(), right_op.add(0.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF32(right_op.to_le_bytes().to_vec(), left_op.add(0.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x5555555559e4,f0x4,10.010000228881836,FCMP_GE,reg xmm1
 // 0x5555555559e4 0x4 FloatingPointGreaterThanEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x5555555559e4), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = 10.010000228881836;
        let mut left_op = arg0 as f32;
let arg0 = fuzzvm.xmm1_f32() ;
        let mut right_op = arg0 as f32;
        if left_op >= right_op {
                let rule = RedqueenRule::SingleF32(left_op.to_le_bytes().to_vec(), right_op.add(-1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF32(right_op.to_le_bytes().to_vec(), left_op.add(-1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleF32(left_op.to_le_bytes().to_vec(), right_op.add(0.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF32(right_op.to_le_bytes().to_vec(), left_op.add(0.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555a00,f0x4,reg xmm0,FCMP_GT,1230000.0
 // 0x555555555a00 0x4 FloatingPointGreaterThan
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555a00), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.xmm0_f32() ;
        let mut left_op = arg0 as f32;
let arg0 = 1230000.0;
        let mut right_op = arg0 as f32;
        if left_op > right_op {
                let rule = RedqueenRule::SingleF32(left_op.to_le_bytes().to_vec(), right_op.add(-1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF32(right_op.to_le_bytes().to_vec(), left_op.add(-1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleF32(left_op.to_le_bytes().to_vec(), right_op.add(1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF32(right_op.to_le_bytes().to_vec(), left_op.add(1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555a20,f0x4,1230000.0,FCMP_GT,reg xmm1
 // 0x555555555a20 0x4 FloatingPointGreaterThan
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555a20), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = 1230000.0;
        let mut left_op = arg0 as f32;
let arg0 = fuzzvm.xmm1_f32() ;
        let mut right_op = arg0 as f32;
        if left_op > right_op {
                let rule = RedqueenRule::SingleF32(left_op.to_le_bytes().to_vec(), right_op.add(-1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF32(right_op.to_le_bytes().to_vec(), left_op.add(-1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleF32(left_op.to_le_bytes().to_vec(), right_op.add(1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF32(right_op.to_le_bytes().to_vec(), left_op.add(1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555a45,f0x4,reg xmm0,FCMP_E,3.1415927410125732
 // 0x555555555a45 0x4 FloatingPointEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555a45), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.xmm0_f32() ;
        let mut left_op = arg0 as f32;
let arg0 = 3.1415927410125732;
        let mut right_op = arg0 as f32;
        if left_op == right_op {
                let rule = RedqueenRule::SingleF32(left_op.to_le_bytes().to_vec(), right_op.add(1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF32(right_op.to_le_bytes().to_vec(), left_op.add(1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleF32(left_op.to_le_bytes().to_vec(), right_op.add(0.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF32(right_op.to_le_bytes().to_vec(), left_op.add(0.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555a67,f0x4,reg xmm0,FCMP_NE,3.1415927410125732
 // 0x555555555a67 0x4 FloatingPointNotEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555a67), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.xmm0_f32() ;
        let mut left_op = arg0 as f32;
let arg0 = 3.1415927410125732;
        let mut right_op = arg0 as f32;
        if left_op != right_op {
                let rule = RedqueenRule::SingleF32(left_op.to_le_bytes().to_vec(), right_op.add(0.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF32(right_op.to_le_bytes().to_vec(), left_op.add(0.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleF32(left_op.to_le_bytes().to_vec(), right_op.add(1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleF32(right_op.to_le_bytes().to_vec(), left_op.add(1.0).to_le_bytes().to_vec());
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555af1,0x8,reg rax,CMP_E,0x0
 // 0x555555555af1 0x8 Equal
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555af1), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = fuzzvm.rax() as u64;
        let mut left_op = arg0 as u64;
let arg0 = 0x0 as u64;
        let mut right_op = arg0 as u64;
        if (left_op as u64) == (right_op as u64) {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
 // ORIGINAL LINE:0x555555555b94,0x8,0x1,CMP_NE,reg rbx
 // 0x555555555b94 0x8 NotEqual
Breakpoint {
    lookup: AddressLookup::Virtual(VirtAddr(0x555555555b94), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);
let arg0 = 0x1 as u64;
        let mut left_op = arg0 as u64;
let arg0 = fuzzvm.rbx() as u64;
        let mut right_op = arg0 as u64;
        if (left_op as u64) != (right_op as u64) {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add(0));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        } else {
                let rule = RedqueenRule::SingleU64((left_op as u64), (right_op as u64).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
                let rule = RedqueenRule::SingleU64((right_op as u64), (left_op as u64).wrapping_add(1));
        // Only add this rule to the redqueen rules if the left operand
        // is actually in the input
        if input.get_redqueen_rule_candidates(&rule).len() > 0 {
            fuzzvm
                .redqueen_rules
                .entry(input_hash)
                .or_default()
                .insert(rule);
        }
        }
        // Insert the rule in the total redqueen rules
        Ok(Execution::Continue)
    }
},
    ])
}
pub fn redqueen_breakpoint_addresses() -> &'static [u64] {
    &[
0x5555555551eb,
0x555555555268,
0x5555555552f2,
0x55555555535c,
0x55555555537a,
0x5555555553e4,
0x555555555402,
0x55555555546c,
0x55555555548a,
0x5555555554f4,
0x555555555523,
0x555555555538,
0x55555555554d,
0x555555555562,
0x555555555577,
0x55555555558c,
0x5555555555a1,
0x5555555555b6,
0x5555555555cb,
0x5555555555e0,
0x5555555555f5,
0x55555555560a,
0x55555555561f,
0x555555555634,
0x555555555649,
0x55555555565e,
0x555555555673,
0x555555555688,
0x55555555569d,
0x5555555556b2,
0x5555555556d0,
0x5555555556f0,
0x555555555710,
0x555555555730,
0x555555555750,
0x555555555770,
0x555555555790,
0x5555555557b0,
0x5555555557d0,
0x5555555557f0,
0x55555555580a,
0x555555555824,
0x555555555851,
0x555555555887,
0x555555555a7a,
0x555555555a8b,
0x555555555a9c,
0x55555555582b,
0x555555555858,
0x5555555558b1,
0x5555555558ce,
0x5555555558ef,
0x55555555590c,
0x55555555592d,
0x555555555958,
0x55555555597f,
0x5555555559a8,
0x5555555559c4,
0x5555555559e4,
0x555555555a00,
0x555555555a20,
0x555555555a45,
0x555555555a67,
0x555555555af1,
0x555555555b94,
]}
