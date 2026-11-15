// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! The diagnostic clock preserves expired budgets and nested thread ownership.
use super::*;
use std::time::Duration;

#[test]
fn diagnostic_remaining_budget_is_signed_without_reset() {
	let now = Instant::now();
	assert_eq!(remaining(now + Duration::from_micros(41), now), 41);
	assert_eq!(remaining(now, now + Duration::from_micros(53)), -53);
}

#[test]
fn diagnostic_thread_context_restores_after_unwind() {
	let now = Instant::now();
	let context = Context {
		id: 17,
		tool: "test",
		entered: now,
		deadline: now + Duration::from_secs(3),
		limit: 32,
		cursor: false,
	};
	CURRENT.with(|current| current.set(Some(context)));
	let result = std::panic::catch_unwind(|| {
		let _guard = QueryTrace(None).enter();
		assert!(CURRENT.with(Cell::get).is_none());
		panic!("controlled context unwind");
	});
	assert!(result.is_err());
	assert_eq!(CURRENT.with(Cell::get).unwrap().id, 17);
	CURRENT.with(|current| current.set(None));
}
