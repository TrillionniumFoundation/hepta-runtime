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

//! Test-owned observer of unchanged current target type declarations.
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::io::{self, BufRead, Write};
include!("original.rs");

fn word(out: &mut [u8], at: usize, value: u64) {
	out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn hex(raw: &[u8]) -> String {
	const DIGITS: &[u8] = b"0123456789abcdef";
	let mut result = String::with_capacity(raw.len() * 2);
	for byte in raw {
		result.push(DIGITS[(byte >> 4) as usize] as char);
		result.push(DIGITS[(byte & 15) as usize] as char);
	}
	result
}
fn result_frame(params: &TextFileWriteParams) -> Vec<u8> {
	let mut out = vec![0; 128];
	out[..8].copy_from_slice(b"HTPPRR01");
	let mode = match params.mode {
		TextFileWriteMode::Create => 1,
		TextFileWriteMode::Replace => 2,
		TextFileWriteMode::Append => 3,
	};
	word(&mut out, 16, mode);
	word(&mut out, 24, params.path.len() as u64);
	word(&mut out, 32, params.content.len() as u64);
	word(&mut out, 40, params.expected_sha256.len() as u64);
	out.extend_from_slice(params.path.as_bytes());
	out.extend_from_slice(params.content.as_bytes());
	out.extend_from_slice(params.expected_sha256.as_bytes());
	out
}
fn error_frame(message: &str) -> Vec<u8> {
	let mut out = vec![0; 128];
	out[..8].copy_from_slice(b"HTPPRR01");
	word(&mut out, 8, 1);
	word(&mut out, 72, message.len() as u64);
	out.extend_from_slice(message.as_bytes());
	out
}
fn main() {
	let input = io::stdin().lock();
	let mut output = io::BufWriter::new(io::stdout().lock());
	for line in input.lines() {
		let row: Value = serde_json::from_str(&line.unwrap()).unwrap();
		let raw = row["raw_json"].as_str().unwrap();
		let result = match serde_json::from_str::<Map<String, Value>>(raw) {
			Err(error) => json!({"value_admitted":false,"value_error":error.to_string()}),
			Ok(map) => {
				let value = Value::Object(map);
				let canonical = serde_json::to_string(&value).unwrap();
				match serde_json::from_value::<TextFileWriteParams>(value) {
					Ok(params) => json!({"value_admitted":true,"canonical":canonical,"ok":true,
						"normalized":serde_json::to_value(&params).unwrap(),"frame_hex":hex(&result_frame(&params))}),
					Err(error) => json!({"value_admitted":true,"canonical":canonical,"ok":false,
						"error":error.to_string(),"frame_hex":hex(&error_frame(&error.to_string()))}),
				}
			}
		};
		serde_json::to_writer(&mut output,
			&json!({"case_id":row["case_id"],"name":row["name"],"result":result})).unwrap();
		output.write_all(b"\n").unwrap();
	}
	output.flush().unwrap();
}
