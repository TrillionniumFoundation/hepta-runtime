// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Read-only fixture observation: do not acquire an async per-file lock here.

pub(crate) fn fixture_lock_snapshot(phase: u64, generation: u64) -> Vec<u8> {
	let poisoned = get_file_locks().is_poisoned();
	let locks = get_file_locks().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
	let mut entries: Vec<_> = locks.iter().collect();
	entries.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
	let mut body = Vec::new();
	for (key, lease) in &entries {
		body.extend_from_slice(&(key.len() as u64).to_le_bytes());
		body.extend_from_slice(&(Arc::strong_count(lease) as u64).to_le_bytes());
		body.extend_from_slice(key.as_bytes());
	}
	let mut answer = b"HLTBLK01".to_vec();
	for value in [56 + body.len() as u64, phase, generation, u64::from(poisoned), entries.len() as u64,
		body.len() as u64] {
		answer.extend_from_slice(&value.to_le_bytes());
	}
	answer.extend_from_slice(&body);
	answer
}
