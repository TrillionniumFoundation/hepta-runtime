// Copyright 2026 Muvon Un Limited
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

// Additional oracle adapter Copyright 2026 TrillionniumFoundation.
// This qualification oracle invokes the unmodified retained Rust owner. Build
// in a temporary Cargo package with serde_json = "=1.0.151" (float_roundtrip,
// raw_value) and serde = "=1.0.229"; HIA_REFERENCE_RUNTIME selects its checkout.
// Default mode compares captured native calls from JSONL on stdin. With
// --export-vectors, JSON values arrive one per line and produce fixed vectors.
// No HIA parser is reproduced here.
use std::io::{self, BufRead};

#[allow(dead_code)]
mod original {
    include!(concat!(env!("HIA_REFERENCE_RUNTIME"), "/src/utils/line_hash.rs"));
}

fn hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(value, "{byte:02x}").unwrap();
    }
    value
}

fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value.as_bytes().chunks_exact(2).map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
    }).collect()
}

fn native_result(tag: u64, value: u64, auxiliary: u64, payload: &[u8]) -> Vec<u8> {
    let mut result = b"HIAEPR01".to_vec();
    result.extend_from_slice(&tag.to_le_bytes());
    result.extend_from_slice(&value.to_le_bytes());
    result.extend_from_slice(&auxiliary.to_le_bytes());
    result.extend_from_slice(payload);
    result
}

fn reason(message: &str) -> u64 {
    if message == "line number must be an integer" { return 1; }
    if message == "line value is empty" { return 2; }
    if message.starts_with("invalid line id '") {
        if message.ends_with("': expected \"N:hh\" as shown in view output (e.g. \"12:a3\")") { return 3; }
        if message.ends_with("': lines are 1-indexed") { return 4; }
        if message.ends_with("': the hash part must be 2 hex chars (e.g. \"12:a3\")") { return 5; }
    }
    if message.starts_with("invalid line value '") { return 6; }
    if message.starts_with("line value must be a line id like \"12:a3\" or an integer line number, got ") { return 7; }
    panic!("original Rust produced an unrecognized diagnostic");
}

fn main() {
    assert_eq!(std::mem::size_of::<usize>(), 8, "oracle is the LP64 profile");
    let export = std::env::args().any(|arg| arg == "--export-vectors");
    let mut count = 0u64;
    for line in io::stdin().lock().lines() {
        let line = line.expect("JSON source line");
        let captured: serde_json::Value = if export { serde_json::Value::Null }
            else { serde_json::from_str(&line).expect("captured native call") };
        let source = if export { line } else { captured["json"].as_str().expect("JSON literal").to_owned() };
        let value: serde_json::Value = serde_json::from_str(&source).expect("JSON value");
        let (kind, payload, scalar) = match &value {
            serde_json::Value::Number(number) => match number.as_i64() {
                Some(number) => (0u64, Vec::new(), number as u64),
                None => (1u64, Vec::new(), 0u64),
            },
            serde_json::Value::String(value) => (2u64, value.as_bytes().to_vec(), 0u64),
            _ => (3u64, value.to_string().into_bytes(), 0u64),
        };
        let mut input = b"HIAEP001".to_vec();
        input.extend_from_slice(&kind.to_le_bytes());
        input.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        input.extend_from_slice(&scalar.to_le_bytes());
        input.extend_from_slice(&payload);
        let (result, expected) = match original::parse_endpoint(&value) {
            Ok(original::Endpoint::Number(number)) => (
                serde_json::json!({"kind":"number", "number":number}), native_result(1, number as u64, 0, &[])),
            Ok(original::Endpoint::Id { line, hash }) => {
                let auxiliary = u64::from(hash.as_bytes()[0]) | (u64::from(hash.as_bytes()[1]) << 8);
                (serde_json::json!({"kind":"id", "line":line, "hash":hash}), native_result(2, line as u64, auxiliary, &[]))
            },
            Err(message) => (
                serde_json::json!({"kind":"error", "message":message}),
                native_result(0, reason(&message), message.len() as u64, message.as_bytes())),
        };
        if export {
            println!("{}", serde_json::json!({"json":source, "input_hex":hex(&input), "result":result}));
        } else {
            assert_eq!(unhex(captured["input_hex"].as_str().expect("input hex")), input, "Value boundary case {}", count);
            assert_eq!(unhex(captured["native_output_hex"].as_str().expect("output hex")), expected, "native endpoint case {}", count);
        }
        count += 1;
    }
    if !export {
        assert!(count > 0, "original Rust comparison requires actual native cases");
        println!("{}", serde_json::json!({"status":"PASS", "rust_oracle_cases":count}));
    }
}
