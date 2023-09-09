//! Fuzzer template

#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]

use anyhow::Result;

use snapchange::addrs::{Cr3, VirtAddr};
use snapchange::fuzzer::{AddressLookup, Breakpoint, BreakpointType, Fuzzer};
use snapchange::fuzzvm::FuzzVm;
use snapchange::rng::Rng;
use snapchange::Execution;

use crate::constants;

const CR3: Cr3 = Cr3(constants::CR3);

// Custom input which will generate bytes between [0x40, 0x7f] as
// per the challenge
#[derive(Debug, Default, Clone, Hash, Eq, PartialEq)]
pub struct RestrictedInput {
    data: Vec<u8>,
}

impl snapchange::FuzzInput for RestrictedInput {
    // Only mutate up to 4 bytes in the input, keeping to the wanted byte range
    fn mutate(
        input: &mut Self,
        corpus: &[Self],
        rng: &mut Rng,
        dictionary: &Option<Vec<Vec<u8>>>,
        max_length: usize,
        max_mutations: u64,
    ) -> Vec<String> {
        for _ in 0..rng.next() % 4 + 1 {
            let offset = rng.next() as usize % input.data.len();
            input.data[offset] = (rng.next() as u8 % (0x80 - 0x40)) + 0x40;
        }

        // Do not generate the mutation strategy strings for now
        vec![]
    }

    // Generate an input where all the bytes are [0x40, 0x7f]
    fn generate(
        corpus: &[Self],
        rng: &mut Rng,
        dictionary: &Option<Vec<Vec<u8>>>,
        max_length: usize,
    ) -> Self {
        let mut data = Vec::new();
        for _ in 0..=0x16 {
            let byte = (rng.next() as u8 % (0x7d - 0x40)) + 0x40;
            data.push(byte);
        }
        Self { data }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            data: bytes.to_vec(),
        })
    }

    fn to_bytes(&self, output: &mut Vec<u8>) -> Result<()> {
        output.clear();
        output.extend(&self.data);
        Ok(())
    }
}

#[derive(Default)]
pub struct Example1Fuzzer;

impl Fuzzer for Example1Fuzzer {
    // NOTE: Using the custom input type here
    type Input = RestrictedInput;
    const START_ADDRESS: u64 = constants::RIP;
    const MAX_INPUT_LENGTH: usize = 0x17;
    const MAX_MUTATIONS: u64 = 4;

    // Since we took the snapshot using a patched binary, we need to revert the original
    // RIP before the `int3 ; vmcall` (4 bytes) that we patched over `main`
    fn set_input(&mut self, input: &Self::Input, fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        fuzzvm.set_rip(fuzzvm.rip() - 4);

        Ok(())
    }

    fn breakpoints(&self) -> Option<&[Breakpoint<Self>]> {
        Some(&[
            // For perf, ignore the first call to printf("Key: ")
            Breakpoint {
                lookup: AddressLookup::SymbolOffset("ld-musl-x86_64.so.1!printf", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, _input, _fuzzer, _feedback| {
                    fuzzvm.fake_immediate_return()?;

                    // Continue execution
                    Ok(Execution::Continue)
                },
            },
            // Scanf is where we inject our mutated string. The destination buffer is stored
            // in RDI, so we write the current input bytes into the buffer at RDI.
            Breakpoint {
                lookup: AddressLookup::SymbolOffset("ld-musl-x86_64.so.1!__isoc99_scanf", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, _fuzzer, _feedback| {
                    let input_addr = fuzzvm.rsi();
                    fuzzvm.write_bytes_dirty(VirtAddr(input_addr), fuzzvm.cr3(), &input.data);

                    fuzzvm.fake_immediate_return()?;

                    // Continue execution
                    Ok(Execution::Continue)
                },
            },
            Breakpoint {
                lookup: AddressLookup::Virtual(VirtAddr(0x7ffff7f51000 + 0x1396), CR3),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, _fuzzer, feedback| {
                    // Stateful coverage is done here.
                    // At offset 0x1396, there is a byte for byte comparison check that
                    // we want to keep track of. The included feedback mechanism allows
                    // a fuzzer to insert a new value (u64) into the coverage. In this,
                    // case we OR the current counter value to the RIP to create a
                    // "stateful" coverage point.
                    //
                    // Example:
                    // RIP - 0xdeadbeefcafe    Counter - 1
                    // Value: 0x01deadbeefcafe
                    // RIP - 0xdeadbeefcafe    Counter - 2
                    // Value: 0x02deadbeefcafe
                    // RIP - 0xdeadbeefcafe    Counter - 3
                    // Value: 0x03deadbeefcafe
                    //
                    // Then the fuzzer knows that any unique value here is a new coverage
                    // point that we need to store the current input into the corpus
                    let counter = fuzzvm.rax();

                    if let Some(feedback) = feedback {
                        let state = (counter << 56) | fuzzvm.rip();

                        if feedback.record(state) {
                            log::info!("New byte found! at {counter}: {input:?}");
                        }
                    }

                    // Continue execution
                    Ok(Execution::Continue)
                },
            },
            Breakpoint {
                lookup: AddressLookup::Virtual(VirtAddr(0x7ffff7f51000 + 0x1504), CR3),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, _fuzzer, feedback| {
                    // Crash reset on the put("Optimal") call
                    Ok(Execution::CrashReset {
                        path: "FOUND".to_string(),
                    })
                },
            },
        ])
    }
}
