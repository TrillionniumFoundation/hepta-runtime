// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! One wall-clock deadline bounds admission, synchronous math and asynchronous I/O.
use anyhow::{Context, Result};
use std::time::{Duration, Instant};

pub struct Deadline {
	end: Instant,
}
impl Deadline {
	pub fn new(duration: Duration) -> Self {
		Self {
			end: Instant::now() + duration,
		}
	}
	/// A phase cap cannot extend the existing whole-attempt cutoff.
	pub fn capped(&self, duration: Duration) -> Self {
		Self {
			end: self.end.min(Instant::now() + duration),
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
