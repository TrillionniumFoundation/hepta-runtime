// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Independent ring AEAD reference for source-bound native fixtures.
use ring::{aead, digest};
use serde_json::{json, Value};
use std::io::{self, BufRead};
include!(concat!(env!("OUT_DIR"), "/original_operation_reference.rs"));

const INVALID: u32 = 0xffffffff;
const BOUND: u32 = 0xfffffffd;
const AUTHENTICATION: u32 = 0xfffffffc;
type RefResult<T> = Result<T, u32>;

fn word(raw: &[u8], at: usize) -> RefResult<u64> {
	Ok(u64::from_le_bytes(
		raw.get(at..at + 8)
			.ok_or(INVALID)?
			.try_into()
			.map_err(|_| INVALID)?,
	))
}

fn reference(raw: &[u8]) -> RefResult<Vec<u8>> {
	if raw.len() < 88
		|| raw.get(..8) != Some(b"HRAEAD01")
		|| word(raw, 16)? != 0
		|| raw.get(84..88) != Some(&[0, 0, 0, 0])
	{
		return Err(INVALID);
	}
	let op = word(raw, 8)?;
	if op != 1 && op != 2 {
		return Err(INVALID);
	}
	let aad_size = word(raw, 24)?;
	let size = word(raw, 32)?;
	if aad_size > 1048576 || size > 1048624 {
		return Err(BOUND);
	}
	if raw.len() as u64 != 88 + aad_size + size + if op == 2 { 16 } else { 0 } {
		return Err(INVALID);
	}
	let key = aead::LessSafeKey::new(
		aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &raw[40..72]).map_err(|_| INVALID)?,
	);
	let nonce = aead::Nonce::assume_unique_for_key(raw[72..84].try_into().map_err(|_| INVALID)?);
	let aad = aead::Aad::from(&raw[88..88 + aad_size as usize]);
	let mut value = raw[88 + aad_size as usize..].to_vec();
	if op == 1 {
		key.seal_in_place_append_tag(nonce, aad, &mut value)
			.map_err(|_| AUTHENTICATION)?;
		Ok(value)
	} else {
		let plain = key
			.open_in_place(nonce, aad, &mut value)
			.map_err(|_| AUTHENTICATION)?;
		Ok(plain.to_vec())
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
	let mut encrypted = 0usize;
	let mut decrypted = 0usize;
	let mut refused = 0usize;
	let mut original_seals = 0usize;
	let mut original_opens = 0usize;
	let mut original_authentication_refusals = 0usize;
	let mut output_hash = digest::Context::new(&digest::SHA256);
	for line in io::stdin().lock().lines() {
		let row: Value = serde_json::from_str(&line?)?;
		let raw = decode(row["input_hex"].as_str().ok_or("missing input")?)?;
		let expected = decode(row["output_hex"].as_str().ok_or("missing output")?)?;
		let expected_code = row["code"].as_u64().ok_or("missing code")?;
		let (code, value) = match reference(&raw) {
			Ok(value) => {
				if raw[8] == 1 {
					encrypted += 1;
				} else {
					decrypted += 1;
				}
				(value.len() as u64, value)
			}
			Err(code) => {
				refused += 1;
				(u64::from(code), Vec::new())
			}
		};
		if (code, &value) != (expected_code, &expected) {
			return Err(format!(
				"reference disagrees at fixture {cases}: code {code}/{expected_code}"
			)
			.into());
		}
		if let Some(original) = row.get("original_record") {
			let (seals, opens, authentication_refusals) =
				original::verify_native_fixture(original, &raw, &value, code)?;
			original_seals += seals;
			original_opens += opens;
			original_authentication_refusals += authentication_refusals;
		}
		output_hash.update(format!("{code}:{}\n", hex(&value)).as_bytes());
		cases += 1;
	}
	println!(
		"{}",
		json!({"status":"PASS","rust_oracle_cases":cases,
		"encryption_cases":encrypted,"decryption_cases":decrypted,"refusal_cases":refused,
		"original_seal_calls":original_seals,"original_open_calls":original_opens,
		"original_authentication_refusals":original_authentication_refusals,
		"output_sha256":hex(output_hash.finish().as_ref()),"native_cases_added_by_replay":0})
	);
	Ok(())
}
