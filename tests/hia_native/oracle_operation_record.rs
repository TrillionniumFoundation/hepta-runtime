// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Test adapter around the complete unchanged original result-record owners.
use ring::digest;
use serde_json::{json, Value};
use std::io::{self, BufRead};
include!(concat!(env!("OUT_DIR"), "/original_operation_reference.rs"));

const INVALID: u32 = 0xffffffff;
const PAYLOAD: u32 = 0xfffffffd;
const BINDING: u32 = 0xfffffffc;
const INTEGRITY: u32 = 0xfffffffb;
type RefResult<T> = Result<T, u32>;

#[derive(Default)]
struct Counts {
	constructor: usize,
	aad: usize,
	seal: usize,
	open: usize,
	preflight: usize,
	verified_scope: usize,
	preflight_entropy_reached: usize,
}

struct Frame<'a> {
	op: u64,
	kind: u64,
	timestamp: u128,
	fields: [&'a str; 6],
	tail: &'a [u8],
}

fn word(raw: &[u8], at: usize) -> RefResult<u64> {
	Ok(u64::from_le_bytes(
		raw.get(at..at + 8)
			.ok_or(INVALID)?
			.try_into()
			.map_err(|_| INVALID)?,
	))
}

fn parse(raw: &[u8]) -> RefResult<Frame<'_>> {
	if raw.len() < 96 || raw.get(..8) != Some(b"HRREC001") || word(raw, 16)? != 0 {
		return Err(INVALID);
	}
	let op = word(raw, 8)?;
	let kind = word(raw, 24)?;
	if !(1..=4).contains(&op) || !(1..=2).contains(&kind) {
		return Err(INVALID);
	}
	let mut at = 96usize;
	let mut spans = [&[][..]; 6];
	for (index, span) in spans.iter_mut().enumerate() {
		let size = word(raw, 48 + index * 8)?;
		if size > (raw.len() - at) as u64 {
			return Err(INVALID);
		}
		*span = &raw[at..at + size as usize];
		at += size as usize;
	}
	let tail = &raw[at..];
	if (op == 1 && !tail.is_empty()) || (op == 2 && tail.len() < 44) || (op == 3 && tail.len() < 32)
	{
		return Err(INVALID);
	}
	let mut fields = [""; 6];
	for (field, span) in fields.iter_mut().zip(spans) {
		*field = std::str::from_utf8(span).map_err(|_| BINDING)?;
	}
	Ok(Frame {
		op,
		kind,
		timestamp: u128::from(word(raw, 32)?) | (u128::from(word(raw, 40)?) << 64),
		fields,
		tail,
	})
}

fn decode(text: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
	if text.len() % 2 != 0 {
		return Err("odd fixture hex length".into());
	}
	text.as_bytes()
		.chunks_exact(2)
		.map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
		.collect()
}

fn hex(raw: &[u8]) -> String {
	raw.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let mut cases = 0usize;
	let mut refused = 0usize;
	let mut counts = Counts::default();
	let mut output_hash = digest::Context::new(&digest::SHA256);
	for line in io::stdin().lock().lines() {
		let row: Value = serde_json::from_str(&line?)?;
		let raw = decode(row["input_hex"].as_str().ok_or("missing input")?)?;
		let expected = decode(row["output_hex"].as_str().ok_or("missing output")?)?;
		let expected_code = row["code"].as_u64().ok_or("missing code")?;
		let token = row
			.get("verified_token_hex")
			.map(|value| decode(value.as_str().ok_or("invalid token fixture")?))
			.transpose()?;
		let result = match parse(&raw) {
			Ok(frame) => original::reference(&frame, token.as_deref(), &mut counts),
			Err(code) => Err(code),
		};
		let (code, value) = match result {
			Ok(value) => (value.len() as u64, value),
			Err(code) => {
				refused += 1;
				(u64::from(code), Vec::new())
			}
		};
		if (code, &value) != (expected_code, &expected) {
			return Err(format!(
				"original record owner disagrees at fixture {cases}: code {code}/{expected_code}"
			)
			.into());
		}
		output_hash.update(format!("{code}:{}\n", hex(&value)).as_bytes());
		cases += 1;
	}
	println!(
		"{}",
		json!({"status":"PASS", "rust_oracle_cases":cases, "refusal_cases":refused,
		"original_binding_constructor_calls":counts.constructor, "original_binding_aad_calls":counts.aad,
		"original_seal_calls":counts.seal, "original_open_calls":counts.open,
		"original_preflight_seal_calls":counts.preflight,
		"original_preflight_entropy_reached":counts.preflight_entropy_reached,
		"original_verified_scope_constructor_calls":counts.verified_scope,
		"original_owner_calls":counts.constructor + counts.aad + counts.seal + counts.open + counts.preflight + counts.verified_scope,
		"output_sha256":hex(output_hash.finish().as_ref()), "native_cases_added_by_replay":0})
	);
	Ok(())
}
