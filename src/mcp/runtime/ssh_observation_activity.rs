// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Lifetime accounting for original observation work, without admission limits.

use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;

#[derive(Default)]
pub(super) struct Activity {
	active: AtomicUsize,
	idle: Notify,
}

pub(super) struct Lease(Arc<Activity>);

impl Activity {
	pub(super) fn lease(self: &Arc<Self>) -> Result<Lease> {
		self.active
			.fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
				count.checked_add(1)
			})
			.map_err(|_| anyhow!("observation activity counter overflow"))?;
		Ok(Lease(self.clone()))
	}

	pub(super) fn active(&self) -> usize {
		self.active.load(Ordering::Acquire)
	}

	pub(super) async fn drain(&self) {
		loop {
			let notified = self.idle.notified();
			tokio::pin!(notified);
			notified.as_mut().enable();
			if self.active() == 0 {
				return;
			}
			notified.await;
		}
	}
}

impl Drop for Lease {
	fn drop(&mut self) {
		if self.0.active.fetch_sub(1, Ordering::AcqRel) == 1 {
			self.0.idle.notify_waiters();
		}
	}
}
