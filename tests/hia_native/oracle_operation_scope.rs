// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Persistent test adapter around the complete unchanged original crypto scope.
use ring::digest;
use serde_json::{json, Value};
use std::io::{self, BufRead};
include!(concat!(env!("OUT_DIR"), "/original_operation_reference.rs"));

const INVALID: u32 = 0xffffffff;
const INPUT: u32 = 0xfffffffd;
const PAYLOAD: u32 = 0xfffffffc;
const BINDING: u32 = 0xfffffffb;
const ENTROPY: u32 = 0xfffffffa;
const NONCE: u32 = 0xfffffff9;
const INTEGRITY: u32 = 0xfffffff8;
const KEY: u32 = 0xfffffff7;
const STATE: u32 = 0xfffffff6;
type RefResult<T> = Result<T, u32>;

#[derive(Default)]
struct Counts {
	verified_constructor: usize,
	stdio_constructor: usize,
	request_binding: usize,
	idempotency_binding: usize,
	policy_binding: usize,
	seal: usize,
	open: usize,
	clone: usize,
	release: usize,
	last_release: usize,
	nonce_setup: usize,
	binding_constructor: usize,
	entropy_fills: usize,
	entropy_bytes_requested: usize,
	fixture_controls: usize,
}

struct Frame<'a> {
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

fn parse_record(raw: &[u8], expected: u64) -> RefResult<Frame<'_>> {
	if raw.len() < 96
		|| raw.get(..8) != Some(b"HRREC001")
		|| word(raw, 16)? != 0
		|| word(raw, 8)? != expected
		|| !(1..=2).contains(&word(raw, 24)?)
	{
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
	let mut fields = [""; 6];
	for (field, span) in fields.iter_mut().zip(spans) {
		*field = std::str::from_utf8(span).map_err(|_| BINDING)?;
	}
	Ok(Frame {
		kind: word(raw, 24)?,
		timestamp: u128::from(word(raw, 32)?) | (u128::from(word(raw, 40)?) << 64),
		fields,
		tail: &raw[at..],
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
	assert_eq!(std::mem::size_of::<usize>(), 8);
	let mut counts = Counts::default();
	let mut reference = original::ScopeReference::new();
	let mut session = 0u64;
	let mut sessions = 0usize;
	let mut cases = 0usize;
	let mut refusals = 0usize;
	let mut original_domain_rows = 0usize;
	let mut output_hash = digest::Context::new(&digest::SHA256);
	for line in io::stdin().lock().lines() {
		let row: Value = serde_json::from_str(&line?)?;
		let next_session = row["session"].as_u64().ok_or("missing session")?;
		if next_session != session {
			assert!(next_session > session);
			reference = original::ScopeReference::new();
			session = next_session;
			sessions += 1;
		}
		let raw = decode(row["input_hex"].as_str().ok_or("missing input")?)?;
		let expected = decode(row["output_hex"].as_str().ok_or("missing output")?)?;
		let target = row["target"].as_u64().ok_or("missing target")?;
		let before = reference.owner_calls(&counts);
		let result = reference.dispatch(target, &raw, &mut counts);
		if reference.owner_calls(&counts) != before {
			original_domain_rows += 1;
		}
		let (code, value) = match result {
			Ok(value) => (value.len() as u64, value),
			Err(code) => {
				refusals += 1;
				(u64::from(code), Vec::new())
			}
		};
		assert_eq!(
			code,
			row["code"].as_u64().ok_or("missing code")?,
			"status mismatch at row {cases}"
		);
		assert_eq!(value, expected, "bytes mismatch at row {cases}");
		let (state, refs, entropy, nonces) = reference.state();
		assert_eq!(
			row["scope_state"].as_u64(),
			Some(state),
			"scope state at row {cases}"
		);
		assert_eq!(
			row["scope_references"].as_u64(),
			Some(refs),
			"scope refs at row {cases}"
		);
		assert_eq!(
			row["entropy_calls"].as_u64(),
			Some(entropy),
			"entropy count at row {cases}"
		);
		assert_eq!(
			row["nonce_count"].as_u64(),
			Some(nonces),
			"nonce count at row {cases}"
		);
		output_hash.update(format!("{code}:{}\n", hex(&value)).as_bytes());
		cases += 1;
	}
	println!(
		"{}",
		json!({"status":"PASS", "rust_oracle_cases":cases, "sessions":sessions,
		"refusal_cases":refusals, "original_domain_rows":original_domain_rows,
		"adapter_only_rows":cases-original_domain_rows,
		"original_verified_constructors":counts.verified_constructor,
		"original_stdio_constructors":counts.stdio_constructor,
		"original_request_bindings":counts.request_binding,
		"original_idempotency_bindings":counts.idempotency_binding,
		"original_policy_bindings":counts.policy_binding,
		"original_seals":counts.seal, "original_opens":counts.open,
		"original_clones":counts.clone, "original_releases":counts.release,
		"original_last_releases":counts.last_release, "original_nonce_setup_reservations":counts.nonce_setup,
		"original_binding_constructors":counts.binding_constructor,
		"original_entropy_fixture_fills":counts.entropy_fills,
		"original_entropy_fixture_requested_bytes":counts.entropy_bytes_requested,
		"fixture_control_rows":counts.fixture_controls, "original_owner_calls":reference.owner_calls(&counts),
		"output_sha256":hex(output_hash.finish().as_ref()), "native_cases_added_by_replay":0})
	);
	Ok(())
}
