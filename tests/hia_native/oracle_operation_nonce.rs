// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Serial corpus replay through the complete unchanged original nonce-set owner.
use ring::digest;
use serde_json::{json, Value};
use std::{
	collections::BTreeMap,
	io::{self, BufRead},
};
include!(concat!(env!("OUT_DIR"), "/original_operation_reference.rs"));

const INVALID: u32 = 0xffffffff;
const BINDING: u32 = 0xfffffffd;
const NONCE: u32 = 0xfffffffc;
const STATE: u32 = 0xfffffffb;

fn word(raw: &[u8], at: usize) -> Result<u64, u32> {
	Ok(u64::from_le_bytes(
		raw.get(at..at + 8)
			.ok_or(INVALID)?
			.try_into()
			.map_err(|_| INVALID)?,
	))
}

fn reference(
	raw: &[u8],
	state: &mut Option<original::ReferenceLedger>,
	binding_calls: &mut usize,
	reservation_calls: &mut usize,
) -> Result<(), u32> {
	if raw.len() < 24 || raw.get(..8) != Some(b"HRNONC01") || word(raw, 16)? != 0 {
		return Err(INVALID);
	}
	let op = word(raw, 8)?;
	if !(1..=3).contains(&op) || raw.len() != if op == 2 { 164 } else { 24 } {
		return Err(INVALID);
	}
	match op {
		1 => {
			if state.is_some() {
				return Err(STATE);
			}
			*state = Some(original::ReferenceLedger::new());
			Ok(())
		}
		2 => {
			*binding_calls += 1;
			let binding =
				original::validated_binding(&raw[24..88], &raw[88..152]).map_err(|_| BINDING)?;
			let state = state.as_mut().ok_or(STATE)?;
			let nonce: [u8; 12] = raw[152..164].try_into().map_err(|_| INVALID)?;
			*reservation_calls += 1;
			state.reserve(&binding, nonce).map_err(|_| NONCE)
		}
		3 => {
			*state = None;
			Ok(())
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
	let mut sessions = BTreeMap::<String, Option<original::ReferenceLedger>>::new();
	let mut cases = 0usize;
	let mut binding_calls = 0usize;
	let mut reservation_calls = 0usize;
	let mut accepted = 0usize;
	let mut nonce_refusals = 0usize;
	let mut output_hash = digest::Context::new(&digest::SHA256);
	for line in io::stdin().lock().lines() {
		let row: Value = serde_json::from_str(&line?)?;
		let session = row["session"].as_str().ok_or("missing session")?;
		let raw = decode(row["input_hex"].as_str().ok_or("missing input")?)?;
		let expected_code = row["code"].as_u64().ok_or("missing code")?;
		let expected_count = row["count"].as_u64().ok_or("missing count")?;
		let state = sessions.entry(session.to_owned()).or_default();
		let code = match reference(&raw, state, &mut binding_calls, &mut reservation_calls) {
			Ok(()) => 0,
			Err(code) => code,
		};
		let count = state.as_ref().map(|ledger| ledger.count()).unwrap_or(0);
		if (u64::from(code), count as u64) != (expected_code, expected_count) {
			return Err(format!(
				"reference disagrees at fixture {cases}: code {code}/{expected_code}, count {count}/{expected_count}"
			)
			.into());
		}
		if code == 0 && word(&raw, 8) == Ok(2) {
			accepted += 1;
		}
		if code == NONCE {
			nonce_refusals += 1;
		}
		output_hash.update(format!("{session}:{code}:{count}\n").as_bytes());
		cases += 1;
	}
	println!(
		"{}",
		json!({"status":"PASS","rust_oracle_cases":cases,
		"original_binding_calls":binding_calls,"original_nonce_reservations":reservation_calls,
		"accepted_reservations":accepted,"nonce_refusals":nonce_refusals,
		"sessions":sessions.len(),"output_sha256":hex(output_hash.finish().as_ref()),
		"native_cases_added_by_replay":0})
	);
	Ok(())
}
