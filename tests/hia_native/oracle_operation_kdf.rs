// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Independent ring primitives and complete unchanged original operation owners.
use ring::{digest, hkdf, hmac};
use serde_json::{json, Value};
use std::io::{self, BufRead};
include!(concat!(env!("OUT_DIR"), "/original_operation_reference.rs"));

const INVALID: u32 = 0xffffffff;
const BOUND: u32 = 0xfffffffd;
type RefResult<T> = Result<T, u32>;

fn word(raw: &[u8], at: usize) -> RefResult<u64> {
	Ok(u64::from_le_bytes(
		raw.get(at..at + 8)
			.ok_or(INVALID)?
			.try_into()
			.map_err(|_| INVALID)?,
	))
}

struct OutputLength(usize);
impl hkdf::KeyType for OutputLength {
	fn len(&self) -> usize {
		self.0
	}
}

fn expanded(prk: &hkdf::Prk, info: &[u8], size: usize) -> RefResult<Vec<u8>> {
	let info = [info];
	let key = prk.expand(&info, OutputLength(size)).map_err(|_| BOUND)?;
	let mut out = vec![0; size];
	key.fill(&mut out).map_err(|_| BOUND)?;
	Ok(out)
}

fn reference(
	raw: &[u8],
	original_calls: &mut usize,
	record_calls: &mut usize,
) -> RefResult<Vec<u8>> {
	if raw.len() < 56 || raw.get(..8) != Some(b"HRKDF001") || word(raw, 16)? != 0 {
		return Err(INVALID);
	}
	let op = word(raw, 8)?;
	if !(1..=9).contains(&op) {
		return Err(INVALID);
	}
	let an = word(raw, 24)?;
	let bn = word(raw, 32)?;
	let cn = word(raw, 40)?;
	let size = word(raw, 48)?;
	if an > 1 << 20 || bn > 1 << 20 || cn > 1 << 20 || size > 8160 {
		return Err(BOUND);
	}
	if raw.len() as u64 != 56 + an + bn + cn {
		return Err(INVALID);
	}
	let (an, bn, cn, size) = (an as usize, bn as usize, cn as usize, size as usize);
	let a = &raw[56..56 + an];
	let b = &raw[56 + an..56 + an + bn];
	let c = &raw[56 + an + bn..];
	match op {
		1 | 2 => {
			if cn != 0 || size != 32 {
				return Err(INVALID);
			}
			Ok(hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, a), b)
				.as_ref()
				.to_vec())
		}
		3 => {
			if an != 32 || cn != 0 {
				return Err(INVALID);
			}
			expanded(&hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, a), b, size)
		}
		4 => expanded(&hkdf::Salt::new(hkdf::HKDF_SHA256, a).extract(b), c, size),
		5 => {
			if bn != 0 || cn != 0 || size != 128 {
				return Err(INVALID);
			}
			*original_calls += 1;
			original::token_keys(a).map_err(|_| INVALID)
		}
		6..=8 => {
			if an != 32 || cn != 0 || size != 64 {
				return Err(INVALID);
			}
			*original_calls += 1;
			original::binding(op, a, b).map_err(|_| INVALID)
		}
		9 => {
			if an != 32 || bn != 64 || cn != 64 || size != 32 {
				return Err(INVALID);
			}
			*original_calls += 1;
			let value = original::record_key_bytes(a, b, c).map_err(|_| INVALID)?;
			*record_calls += 1;
			Ok(value)
		}
		_ => Err(INVALID),
	}
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
	let mut original_calls = 0usize;
	let mut record_calls = 0usize;
	let mut output_hash = digest::Context::new(&digest::SHA256);
	for line in io::stdin().lock().lines() {
		let row: Value = serde_json::from_str(&line?)?;
		let raw = decode(row["input_hex"].as_str().ok_or("missing input")?)?;
		let expected = decode(row["output_hex"].as_str().ok_or("missing output")?)?;
		let expected_code = row["code"].as_u64().ok_or("missing code")?;
		let (code, value) = match reference(&raw, &mut original_calls, &mut record_calls) {
			Ok(value) => (value.len() as u64, value),
			Err(code) => (u64::from(code), Vec::new()),
		};
		if (code, &value) != (expected_code, &expected) {
			return Err(format!(
				"reference disagrees at fixture {cases}: code {code}/{expected_code}"
			)
			.into());
		}
		output_hash.update(format!("{code}:{}\n", hex(&value)).as_bytes());
		cases += 1;
	}
	println!(
		"{}",
		json!({"status":"PASS","rust_oracle_cases":cases,
		"original_owner_calls":original_calls,"original_record_key_cipher_comparisons":record_calls,
		"output_sha256":hex(output_hash.finish().as_ref()),"native_cases_added_by_replay":0})
	);
	Ok(())
}
