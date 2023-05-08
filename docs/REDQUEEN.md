# Redqueen

Snapchange has a [Redqueen](https://www.ndss-symposium.org/ndss-paper/redqueen-fuzzing-with-input-to-state-correspondence) 
implementation. Redqueen provides a mechanism to overcome common fuzzing roadblocks. These 
roadblocks are overcome by looking at the state of the guest at each known comparison and attempts
to invert the result of the comparison. Using the state of the guest at the comparison, rules are
created to replace bytes found in the input with bytes that would invert the comparison.

## High Level Example

The fuzzer has reached a point where redqueen is enabled. The fuzzer will take an input from
the corpus and attempt to pinpoint mutations that will force comparisons to be inverted.

Let's use the following pseudo example:

```
input[0..4]  == 'abcd'
input[4..8]  >  3.14
memcmp(input[8..16], 'magic!!!')
```

The input for this example is `aaaa0000notmagic`

The first step is to gather the current comparison states.
This is done using a series of comparision breakpoints (more on that later). The breakpoints are
set specifically after the comparison. This is because along with the comparison operands, we also 
want to the result of the `rflags` register. 

We can think of redqueen as a stateful coverage pass. The coverage for redqueen is not just if
an instruction has been hit, but also if the `rflags` register (specifically the zero and carry
flags).

The input is run through the example and the following redqueen coverage is found:

```
# Instr:    input[0..4] == 'abcd'
# Coverage: aaaa != abcd (needed ==)

# Instr:    input[4..8] > 3.14
# Coverage: 0000 < 3.14 (needed >)

# Instr:    memcmp(input[8..16], 'magic!!!')
# Coverage: notmagic != magic!!! (needed ==)
```

After gathering the dynamic comparison information, redqueen will go through each comparison
to add rules to force the inverted case. Each rule takes the form "find these bytes" and 
"replace with these bytes".

For this example:

```
aaaa != abcd (needed ==)
0000 < 3.14  (needed >)
notmagic != magic!!!
```

We will generate the following rules:

* If `aaaa` is found in the input, replace `aaaa` with `abcd` since we want these to be equal
* If `0000` is found in the input, replace `0000` with `3.15` since we need a value greater than `3.15`
* If `notmagic` is found in the input, replace `notmagic` with `magic!!!`

These rules are then applied, one at a time, to the starting input to see if there is any new
redqueen coverage. For example:

New Input:

```
abcd0000notmagic
```

New Input Redqueen Coverage:

```
# Instr:    input[0..4] == 'abcd'
# Coverage: abcd == abcd (NEW)

# Instr:    input[4..8] > 3.14
# Covearge: 0000 < 3.14 (needed >)
```

This new input found a new redqueen coverage, so this input is added to the corpus. This will
continue for all rules looking for new redqueen coverage.

## Redqueen breakpoints

Breakpoints are used to gather the dynamic comparison information. These breakpoints are generated
using [Binary Ninja](https://binary.ninja) using the included [script](../../coverage_scripts/bn_snapchange.py).

The result of this script are single lines redqueen breakpoints:

```
0x55555555548a,0x4,reg eax,CMP_E,0x7736a87f
```

This breakpoint describes the following:

* `0x55555555548a` - Address to break
* `0x4` - Size of the comparison
* `reg eax` - (left operand) Register to read 
* `CMP_E` - The expected comparison
* `0x7736a87f` - (right operand) Literal number

Currently, the breakpoints in Snapchange must be `'static`, which means they must be known at
compile time. In order to enable this for a fuzzer, a `build.rs` is included for redqueen which 
parses these comparison breakpoints and generate a (massive) `redqueen.rs` file which creates a 
`Breakpoint` for each line.

The `Breakpoint` generated from the above during `build.rs`:

```rust
// ORIGINAL LINE:0x55555555548a,0x4,reg eax,CMP_E,0x7736a87f
// 0x55555555548a 0x4 Equal
Breakpoint {
    lookup: BreakpointLookup::Address(VirtAddr(0x55555555548a), CR3),
    bp_type: BreakpointType::Repeated,
    bp_hook: |fuzzvm: &mut FuzzVm<FUZZER>, input, _fuzzer| {
        // Get the hash of the input to use as a key into the redqueen rules map
        let input_hash = snapchange::utils::calculate_hash(input);

        let arg0 = fuzzvm.eax() as u64;
        let mut left_op = arg0 as u32;
        let arg0 = 0x7736a87f as u64;

        let mut right_op = arg0 as u32;
        if (left_op as u32) == (right_op as u32) {
            let rule = RedqueenRule::SingleU32(
                (left_op as u32),
                (right_op as u32).wrapping_add(1),
            );

            // Only add this rule to the redqueen rules if the left operand
            // is actually in the input
            if input.get_redqueen_rule_candidates(&rule).len() > 0 {
                fuzzvm
                    .redqueen_rules
                    .entry(input_hash)
                    .or_default()
                    .insert(rule);
            }
            let rule = RedqueenRule::SingleU32(
                (right_op as u32),
                (left_op as u32).wrapping_add(1),
            );
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
            let rule = RedqueenRule::SingleU32(
                (left_op as u32),
                (right_op as u32).wrapping_add(0),
            );
            // Only add this rule to the redqueen rules if the left operand
            // is actually in the input
            if input.get_redqueen_rule_candidates(&rule).len() > 0 {
                fuzzvm
                    .redqueen_rules
                    .entry(input_hash)
                    .or_default()
                    .insert(rule);
            }
            let rule = RedqueenRule::SingleU32(
                (right_op as u32),
                (left_op as u32).wrapping_add(0),
            );
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
    },
},
```
These breakpoints are then included in the fuzzer via the `redqueen_breakpoints` 
trait function:

```
examples/05_redqueen/fuzzer.rs

    fn redqueen_breakpoints(&self) -> Option<&[Breakpoint<Self>]> {
        crate::redqueen::redqueen_breakpoints::<Self>()
    }

    fn redqueen_breakpoint_addresses() -> &'static [u64] {
        crate::redqueen::redqueen_breakpoint_addresses()
    }
```

When these breakpoints are hit, the new generated rules are added to a `BTreeMap` in the
`FuzzVm` keyed by the input hash. This is used so that each input is only needed to 
gather redqueen rules once. Currently, these rules are not shared between cores as it 
seems to have a larger performance loss to share the redqueen rules than to have each
redqueen core generate their own rules on the fly.

## Application of Redqueen Rules

During fuzzing, redqueen will be triggered when a fuzzer sees an input from the corpus
that hasn't been fuzzed yet by calling the `fuzzvm::gather_redqueen` function. 

For any `FuzzInput` to be used with redqueen, it must implement the redqueen functions
in the `FuzzInput` trait:

*  get_redqueen_rule_candidates
*  apply_redqueen_rule
*  increase_redqueen_entropy


#### Get Redqueen Rule Candidates

This enables a custom input type to be used for fuzzing and still gain access to redqueen.

`gather_redqueen` will begin by iterating over all the found redqueen rules (generated
from the redqueen breakpoints above). It begins by getting the number of candidate locations
in the input that the current rule could be applied. If this number is above the configurable
threshold, then an attempt to increase the entropy of the input is done.

Example: 

Input: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa12345678`
aaaa != abcd (needed ==)
0000 < 3.14  (needed >)
notmagic != magic!!!
Rule: `Replace aaaa -> abcd`
Threshold: 10
Candidates: 54 possible locations to apply the rule

Since there more than 10 locations that could replace `aaaa` with `abcd`, the increase entropy step 
(called "colorization" in the Redqueen paper) would be triggered. If there were less than 
10 candidates, the increase entropy step is skipped and redqueen would go straight to applying the 
rules. Since we are over the threshold, the increase entropy step is next.

#### Increase Redqueen Entropy

With too many rule candidates found, we need to modify the current input in such a way that keeps
the same rules, but reduces the number of possible candidates. This is done by randomly changing 
each rule candidate location's bytes and checking if the coverage is still the same. If the 
coverage is the same, then we keep the increased entropy input. If the coverage changed, then
we discard the change and revert back to the last input.

Example:

Input: `aaaaaaaaaaaaa`
Original Coverage: (0x1234, Rflags(0x4)) | (0x4000, Rflags(0x0))
Rule Candidates: 12

Rule Candidate: aaaa -> abcd at offset 0
Test Input: `1936aaaaaaaaa`
Test Coverage: (0x1234, Rflags(0x4)) | (0x4000, Rflags(0x0))
Coverage is the same, we keep the new input!

Rule Candidate: aaaa -> abcd at offset 4
Test Input: `1936pqiuaaaaa`
Test Coverage: (0x1234, Rflags(0x4)) | (0x4000, Rflags(0x2))
Coverage changed! Discard the mutation

Rule Candidate: aaaa -> bb at offset 5
Test Input: `1936aqweraaaa`
Test Coverage: (0x1234, Rflags(0x4)) | (0x4000, Rflags(0x0))
Coverage is the same, we keep the new input!

This new input will potentially have drastically fewer rule candidates than before:

New Input: `1936aqweraaaa`
Rules: Replace `1936` -> `abcd`

#### Apply Redqueen Rules

With the redqueen rules found, it is now time to apply the rules to see if any new coverage
is found. Redqueen will iterate through the redqueen rule candidates and apply them to the
current input. After executing the new input, if there are any new redqueen coverage points,
the mutated input is then ran through redqueen again recursively.


```
Rule Candidate: `1936` -> `abcd`
Input: `1936aqweraaaa`
Current Coverage: (0x1234, Rflags(0x4)) | (0x4000, Rflags(0x0))

New Input: `abcdaqweraaaa`
Current Coverage: (0x1234, Rflags(0x2)) <- NEW COVERAGE
```

The applied rule has new coverage, so the input is stored in the corpus for future mutation
and it then sent to redqueen for further analysis.
