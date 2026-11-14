// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Independent crate oracles for actual captured HIA codec calls.
use base64::alphabet::STANDARD;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{self, BufRead};

const INVALID: u64 = 0xffff_ffff;
const BOUND: u64 = 0xffff_fffd;
const CHUNK: usize = 1 << 20;

fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value.as_bytes().chunks_exact(2).map(|part| {
        u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap()
    }).collect()
}

fn hex(raw: &[u8]) -> String {
    raw.iter().map(|value| format!("{value:02x}")).collect()
}

fn call(op: u64, input: &[u8]) -> (u64, Vec<u8>) {
    if input.len() > 1_398_104 || ((op == 1 || op == 2 || op == 7) && input.len() > CHUNK) {
        return (BOUND, Vec::new());
    }
    let output = match op {
        1 => Sha256::digest(input).to_vec(),
        2 => hex(&Sha256::digest(input)).into_bytes(),
        7 => base64::engine::general_purpose::STANDARD.encode(input).into_bytes(),
        8 | 9 | 10 => {
            let relaxed_bits = GeneralPurpose::new(&STANDARD, GeneralPurposeConfig::new()
                .with_decode_allow_trailing_bits(true)
                .with_decode_padding_mode(DecodePaddingMode::RequireCanonical));
            let mut source = input;
            if op == 8 {
                let end = input.iter().rposition(|value| *value != b'=').map_or(0, |at| at + 1);
                if end != 0 && end % 4 == 0 && end < input.len() { source = &input[..end]; }
            }
            let result = if op == 10 {
                base64::engine::general_purpose::STANDARD.decode(source)
            } else { relaxed_bits.decode(source) };
            match result { Ok(value) => value, Err(_) => return (INVALID, Vec::new()) }
        }
        _ => panic!("unrecognized independent-oracle operation"),
    };
    if op >= 8 && output.len() > CHUNK { return (BOUND, Vec::new()); }
    (output.len() as u64, output)
}

fn main() {
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut total = 0u64;
    for line in io::stdin().lock().lines() {
        let value: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let expected = unhex(value["output_hex"].as_str().unwrap());
        if value["kind"] == "call" {
            let input = unhex(value["input_hex"].as_str().unwrap());
            let op = value["op"].as_u64().unwrap();
            let actual = call(op, &input);
            assert_eq!(actual, (value["code"].as_u64().unwrap(), expected), "case {total}, op {op}");
            *counts.entry(format!("operation_{op}")).or_default() += 1;
        } else {
            assert_eq!(value["kind"], "stream_digest");
            let message = unhex(value["message_hex"].as_str().unwrap());
            let state = unhex(value["input_state_hex"].as_str().unwrap());
            assert_eq!(state.len(), 128);
            assert_eq!(&state[..8], b"HSHA2561");
            assert_eq!(u64::from_le_bytes(state[8..16].try_into().unwrap()), message.len() as u64);
            let used = message.len() % 64;
            assert_eq!(u64::from_le_bytes(state[16..24].try_into().unwrap()), used as u64);
            assert_eq!(&state[56..56 + used], &message[message.len() - used..]);
            assert!(state[56 + used..].iter().all(|byte| *byte == 0));
            let mut digest = Sha256::new();
            for chunk in message.chunks(97) { digest.update(chunk); }
            let raw = digest.finalize();
            let actual = if value["hexadecimal"].as_bool().unwrap() { hex(&raw).into_bytes() } else { raw.to_vec() };
            assert_eq!(actual, expected, "stream case {total}");
            *counts.entry("stream_digest".to_owned()).or_default() += 1;
        }
        total += 1;
    }
    assert!(total > 0);
    println!("{}", json!({"status":"PASS","rust_oracle_cases":total,"counts":counts}));
}
