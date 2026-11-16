// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Exact target lock concurrency tests, retained only as the independent reference.
// Exact target owner and all five original shared gate tests, unchanged.
#![allow(dead_code)]
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Instant;
include!("audit_store_lock.rs.txt");
include!("audit_store_tests.rs.txt");
include!("controller_extra_tests.rs.txt");

fn extra_observation(kind: &str, fields: &str) {
	use std::io::Write;
	static JOURNAL: std::sync::OnceLock<Mutex<std::fs::File>> = std::sync::OnceLock::new();
	let journal = JOURNAL.get_or_init(|| {
		Mutex::new(
			std::fs::OpenOptions::new()
				.write(true)
				.create_new(true)
				.open(std::env::var("HIA_AUDIT_ORIGINAL_OBSERVATIONS").unwrap())
				.unwrap(),
		)
	});
	let case = std::thread::current().name().unwrap().to_owned();
	writeln!(
		journal.lock().unwrap(),
		"{{\"case\":\"{case}\",\"kind\":\"{kind}\",{fields}}}"
	)
	.unwrap();
}
