// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! One wall-clock deadline bounds admission, synchronous math and asynchronous I/O.
use anyhow::{Context, Result};
use std::time::{Duration, Instant};

pub(super) struct Deadline {
	end: Instant,
}
impl Deadline {
	pub fn new(duration: Duration) -> Self {
		Self {
			end: Instant::now() + duration,
		}
	}
	pub fn remaining(&self) -> Result<Duration> {
		self.end
			.checked_duration_since(Instant::now())
			.context("complete-model wall deadline exceeded")
	}
	pub fn check(&self) -> Result<()> {
		self.remaining().map(|_| ())
	}
}
