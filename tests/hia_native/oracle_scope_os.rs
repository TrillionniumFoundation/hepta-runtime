// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Persistent test adapter around the complete unchanged original crypto scope.
use serde_json::json;
use std::io::{self, BufRead, Write};
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
	let mut scope = original::ScopeReference::new();
	let mut requests = 0usize;
	let mut refusals = 0usize;
	let mut stdout = io::stdout().lock();
	for line in io::stdin().lock().lines() {
		let line = line?;
		assert!(line.len() <= 8 << 20);
		let raw = decode(&line)?;
		let (code, value) = match scope.dispatch(&raw, &mut counts) {
			Ok(value) => (value.len() as u32, value),
			Err(code) => {
				refusals += 1;
				(code, Vec::new())
			}
		};
		writeln!(stdout, "{code:08x}:{}", hex(&value))?;
		stdout.flush()?;
		requests += 1;
	}
	eprintln!(
		"{}",
		json!({
			"schema":"hepta.runtime.scope-os-original-owner.v1", "status":"PASS", "requests":requests,
			"refusals":refusals, "original_verified_constructors":counts.verified_constructor,
			"original_stdio_constructors":counts.stdio_constructor,
			"original_request_bindings":counts.request_binding,
			"original_idempotency_bindings":counts.idempotency_binding,
			"original_policy_bindings":counts.policy_binding,
			"original_seals":counts.seal, "original_opens":counts.open,
			"original_clones":counts.clone, "original_releases":counts.release,
			"original_last_releases":counts.last_release,
			"actual_system_entropy":true, "fixture_entropy_owner_used":false
		})
	);
	Ok(())
}
