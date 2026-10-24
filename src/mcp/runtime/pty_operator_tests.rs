// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Capacity is reserved for active work, not all historical PTY sessions.
use super::*;

#[test]
fn pty_slots_are_bounded_and_released_on_every_drop_path() {
	let mut permits = (0..MAX_ACTIVE_SESSIONS)
		.map(|_| reserve_pty_slot().unwrap())
		.collect::<Vec<_>>();
	assert!(reserve_pty_slot().is_err());
	permits.pop();
	let recovered = reserve_pty_slot().unwrap();
	assert!(reserve_pty_slot().is_err());
	drop(recovered);
	drop(permits);
	let all = (0..MAX_ACTIVE_SESSIONS)
		.map(|_| reserve_pty_slot().unwrap())
		.collect::<Vec<_>>();
	assert_eq!(all.len(), MAX_ACTIVE_SESSIONS);
}
