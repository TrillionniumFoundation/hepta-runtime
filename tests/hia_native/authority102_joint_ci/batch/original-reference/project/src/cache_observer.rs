// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Fixture-only setup and complete observations of the original cache instance.

pub(crate) fn fixture_apply(cache: &ViewCache, raw: &[u8]) -> std::io::Result<Vec<u8>> {
	use std::io::{Error, ErrorKind};
	let invalid = || Error::new(ErrorKind::InvalidInput, "non-admitted cache fixture frame");
	if raw.len() < 48 || &raw[..8] != b"HVCACH01" || crate::word(raw, 16) != 0 {
		return Err(invalid());
	}
	let operation = crate::word(raw, 8);
	let key_len = usize::try_from(crate::word(raw, 24)).map_err(|_| invalid())?;
	let content_len = usize::try_from(crate::word(raw, 32)).map_err(|_| invalid())?;
	if key_len > raw.len() - 48
		|| content_len != raw.len() - 48 - key_len
		|| crate::word(raw, 40) != 0
	{
		return Err(invalid());
	}
	let key = std::str::from_utf8(&raw[48..48 + key_len]).map_err(|_| invalid())?;
	let value = std::str::from_utf8(&raw[48 + key_len..]).map_err(|_| invalid())?;
	let result = match operation {
		1 if value.is_empty() => cache.get(key),
		2 => {
			cache.set(key.to_owned(), value.to_owned());
			None
		}
		9 if key.is_empty() && value.is_empty() => {
			let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
				let _guard = cache.entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
				panic!("test-only original Mutex poisoning event");
			}));
			assert!(result.is_err() && cache.entries.is_poisoned());
			None
		}
		_ => return Err(invalid()),
	};
	let mut output = b"HVCAR001".to_vec();
	output.extend_from_slice(&u64::from(result.is_some()).to_le_bytes());
	output.extend_from_slice(&(result.as_ref().map_or(0, String::len) as u64).to_le_bytes());
	output.extend_from_slice(&0u64.to_le_bytes());
	if let Some(value) = result {
		output.extend_from_slice(value.as_bytes());
	}
	Ok(output)
}

pub(crate) fn fixture_snapshot(cache: &ViewCache, phase: u64) -> Vec<u8> {
	let poisoned = cache.entries.is_poisoned();
	let guard = cache.entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
	let mut entries: Vec<_> = guard.iter().collect();
	entries.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
	let mut body = Vec::new();
	for (key, value) in &entries {
		body.extend_from_slice(&(key.len() as u64).to_le_bytes());
		body.extend_from_slice(&(value.len() as u64).to_le_bytes());
		body.extend_from_slice(key.as_bytes());
		body.extend_from_slice(value.as_bytes());
	}
	let mut output = b"HLCSCS01".to_vec();
	for word in [48 + body.len() as u64, phase, u64::from(poisoned), entries.len() as u64, body.len() as u64] {
		output.extend_from_slice(&word.to_le_bytes());
	}
	output.extend_from_slice(&body);
	output
}
