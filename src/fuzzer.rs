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

#[derive(Debug, Default, Clone, Hash, Eq, PartialEq)]
pub struct RestrictedInput {
    data: Vec<u8>,
}

impl snapchange::FuzzInput for RestrictedInput {
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
}

#[derive(Default)]
pub struct Example1Fuzzer {
    // Fuzzer specific data could go in here
}

impl Fuzzer for Example1Fuzzer {
    type Input = RestrictedInput;
    const START_ADDRESS: u64 = constants::RIP;
    const MAX_INPUT_LENGTH: usize = 0x17;
    const MAX_MUTATIONS: u64 = 4;

    fn set_input(&mut self, input: &Self::Input, fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        fuzzvm.set_rip(fuzzvm.rip() - 4);

        Ok(())
    }

    fn breakpoints(&self) -> Option<&[Breakpoint<Self>]> {
        Some(&[
            Breakpoint {
                lookup: AddressLookup::SymbolOffset("ld-musl-x86_64.so.1!printf", 0x0),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, _input, _fuzzer, _feedback| {
                    fuzzvm.fake_immediate_return()?;

                    // Continue execution
                    Ok(Execution::Continue)
                },
            },
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
            /*
            Breakpoint {
                lookup: AddressLookup::Virtual(VirtAddr(0x7ffff7f51000 + 0x14cc), CR3),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, _fuzzer, feedback| {
                    let counter =
                        fuzzvm.read::<u32>(VirtAddr(fuzzvm.rbp() - 0x28), fuzzvm.cr3())? as u64;

                    if let Some(feedback) = feedback {
                        let state = (counter << 56) | fuzzvm.rip();

                        if feedback.record(state) {
                            log::info!("New value! at {counter}: {input:?}");
                        }
                    }

                    // Continue execution
                    Ok(Execution::Continue)
                },
            },
            */
            Breakpoint {
                lookup: AddressLookup::Virtual(VirtAddr(0x7ffff7f51000 + 0x1396), CR3),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm: &mut FuzzVm<Self>, input, _fuzzer, feedback| {
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
                    // Crash reset
                    Ok(Execution::CrashReset {
                        path: "FOUND".to_string(),
                    })
                },
            },
        ])
    }
}
