// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Fixture-only access to the real original history instance and its full state.

pub(crate) fn fixture_history_apply(raw: &[u8]) -> std::io::Result<Vec<u8>> {
	use std::io::{Error, ErrorKind};
	let invalid = || Error::new(ErrorKind::InvalidInput, "non-admitted history fixture frame");
	if raw.len() < 64 || &raw[..8] != b"HHISTQ01" || raw[40..64] != [0u8; 24] {
		return Err(invalid());
	}
	let operation = crate::word(raw, 8);
	let cap = usize::try_from(crate::word(raw, 16)).map_err(|_| invalid())?;
	let kn = usize::try_from(crate::word(raw, 24)).map_err(|_| invalid())?;
	let vn = usize::try_from(crate::word(raw, 32)).map_err(|_| invalid())?;
	if kn > raw.len() - 64 || vn != raw.len() - 64 - kn {
		return Err(invalid());
	}
	let key = std::str::from_utf8(&raw[64..64 + kn]).map_err(|_| invalid())?;
	let value = std::str::from_utf8(&raw[64 + kn..]).map_err(|_| invalid())?;
	if (operation != 1 && (cap != 0 || vn != 0))
		|| (operation != 1 && operation != 2 && kn != 0)
		|| !matches!(operation, 0..=3)
	{
		return Err(invalid());
	}
	let mut kind = 0u64;
	let mut body = None;
	if operation == 3 {
		let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
			let _guard = file_history().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
			panic!("test-only original history Mutex poisoning");
		}));
		assert!(outcome.is_err() && file_history().is_poisoned());
	} else if operation == 1 || operation == 2 {
		match file_history().lock() {
			Ok(mut history) => {
				if operation == 1 {
					history.push(key.to_owned(), value.to_owned(), cap);
				} else {
					body = history.pop(key);
					kind = if body.is_some() { 1 } else { 2 };
				}
			}
			Err(_) => kind = 3,
		}
	}
	let poisoned = file_history().is_poisoned();
	let history = file_history().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
	let mut answer = b"HHISTR01".to_vec();
	for value in [kind, body.as_ref().map_or(0, String::len) as u64, history.total_bytes as u64,
		history.files.values().map(Vec::len).sum::<usize>() as u64,
		history.order.len() as u64, u64::from(poisoned), 0] {
		answer.extend_from_slice(&value.to_le_bytes());
	}
	if let Some(value) = body { answer.extend_from_slice(value.as_bytes()); }
	Ok(answer)
}

pub(crate) fn fixture_history_snapshot(phase: u64, generation: u64) -> Vec<u8> {
	let poisoned = file_history().is_poisoned();
	let history = file_history().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
	let mut keys: Vec<_> = history.files.iter().collect();
	keys.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
	let mut body = Vec::new();
	for (key, snapshots) in &keys {
		body.extend_from_slice(&(key.len() as u64).to_le_bytes());
		body.extend_from_slice(&(snapshots.len() as u64).to_le_bytes());
		body.extend_from_slice(key.as_bytes());
		for snapshot in *snapshots {
			body.extend_from_slice(&(snapshot.len() as u64).to_le_bytes());
			body.extend_from_slice(snapshot.as_bytes());
		}
	}
	for key in &history.order {
		body.extend_from_slice(&(key.len() as u64).to_le_bytes());
		body.extend_from_slice(key.as_bytes());
	}
	let mut answer = b"HLTBHS01".to_vec();
	for value in [80 + body.len() as u64, phase, generation, u64::from(poisoned), keys.len() as u64,
		history.files.values().map(Vec::len).sum::<usize>() as u64, history.total_bytes as u64,
		history.order.len() as u64, body.len() as u64] {
		answer.extend_from_slice(&value.to_le_bytes());
	}
	answer.extend_from_slice(&body);
	answer
}
