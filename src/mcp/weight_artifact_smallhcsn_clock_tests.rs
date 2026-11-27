// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Deterministic same-boot boundaries without sleeping or executing a model.

use super::*;

#[test]
fn original_boottime_window_cannot_be_reopened_by_in_range_wall_time() {
	let start = Stamp {
		boot_id: "12345678-1234-1234-1234-123456789abc".into(),
		boottime_nanoseconds: 9_000_000_000,
	};
	let inside = Stamp {
		boottime_nanoseconds: 68_999_999_999,
		..start.clone()
	};
	assert_eq!(
		start.remaining_at(&inside, 60).unwrap(),
		Duration::from_nanos(1)
	);
	let expired = Stamp {
		boottime_nanoseconds: 69_000_000_000,
		..start.clone()
	};
	assert!(start.remaining_at(&expired, 60).is_err());
	let later = Stamp {
		boottime_nanoseconds: 129_000_000_000,
		..start.clone()
	};
	assert!(start.remaining_at(&later, 60).is_err());
}

#[test]
fn changed_boot_backwards_counter_and_overflow_refuse_new_work() {
	let start = Stamp {
		boot_id: "12345678-1234-1234-1234-123456789abc".into(),
		boottime_nanoseconds: 9_000_000_000,
	};
	let reboot = Stamp {
		boot_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into(),
		..start.clone()
	};
	assert!(start.remaining_at(&reboot, 60).is_err());
	let backwards = Stamp {
		boottime_nanoseconds: 8_999_999_999,
		..start.clone()
	};
	assert!(start.remaining_at(&backwards, 60).is_err());
	assert!(start.remaining_at(&start, u64::MAX).is_err());
	let bad = Stamp {
		boot_id: "a".repeat(36),
		..start.clone()
	};
	assert!(bad.validate().is_err());
}
