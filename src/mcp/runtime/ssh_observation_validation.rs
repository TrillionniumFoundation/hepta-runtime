// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bounded complete-file validation that never owns an SSH child or credential lease.

use anyhow::{anyhow, bail, Context, Result};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout_at, Instant};
use tokio_util::sync::CancellationToken;

const WORKERS: usize = 2;

pub(super) struct Workers {
	permits: Arc<Semaphore>,
}

// The closure owns this guard, including when its caller times out or drops
// the JoinHandle. Failure freezes admission before releasing worker capacity.
struct Completion {
	_permit: OwnedSemaphorePermit,
	stop: CancellationToken,
	completed: bool,
}

impl Completion {
	fn finish(mut self) {
		// Consuming the whole guard forces the blocking closure to own its
		// permit and Drop state together, rather than capturing copied fields.
		self.completed = true;
	}
}

impl Drop for Completion {
	fn drop(&mut self) {
		if !self.completed {
			self.stop.cancel();
		}
	}
}

impl Workers {
	pub(super) fn new() -> Self {
		Self {
			permits: Arc::new(Semaphore::new(WORKERS)),
		}
	}

	pub(super) async fn run<F>(
		&self,
		stop: &CancellationToken,
		deadline: Instant,
		check: F,
	) -> Result<()>
	where
		F: FnOnce() -> Result<()> + Send + 'static,
	{
		let permit = tokio::select! {
			biased;
			_ = stop.cancelled() => bail!("observation validation stopped before admission"),
			value = timeout_at(deadline, self.permits.clone().acquire_owned()) => value
				.context("observation validation capacity deadline")?
				.context("observation validation capacity closed")?,
		};
		if stop.is_cancelled() || Instant::now() >= deadline {
			bail!("observation validation cancelled or expired before submission");
		}
		// Construct before spawn so even a discarded unstarted closure freezes
		// admission. At most WORKERS closures are submitted; Tokio's otherwise
		// unbounded blocking queue cannot accumulate validation work.
		let completion = Completion {
			_permit: permit,
			stop: stop.clone(),
			completed: false,
		};
		let mut work = tokio::task::spawn_blocking(move || {
			// Admission can precede execution in Tokio's blocking queue. Keep
			// the original deadline and refuse stale work before opening files.
			if completion.stop.is_cancelled() || Instant::now() >= deadline {
				completion.stop.cancel();
				completion.finish();
				bail!("observation validation cancelled or expired before worker execution");
			}
			let result = check();
			if result.is_err() {
				completion.stop.cancel();
			}
			completion.finish();
			result
		});
		let result = tokio::select! {
			biased;
			value = &mut work => value.map_err(|error| {
				stop.cancel();
				anyhow!("observation validation worker unavailable: {error}")
			})?,
			_ = stop.cancelled() => bail!("observation validation stopped before authority acceptance"),
			_ = tokio::time::sleep_until(deadline) => {
				stop.cancel();
				bail!("observation validation deadline; no result accepted");
			},
		};
		result?;
		// Completion and a timer/cancellation can become ready together. A
		// successfully hashed earlier snapshot grants no late authority.
		if stop.is_cancelled() || Instant::now() >= deadline {
			bail!("observation validation cancelled or expired before authority acceptance");
		}
		Ok(())
	}

	pub(super) async fn finish_shutdown(&self, cleanup: Result<()>) -> Result<()> {
		// The owner calls this even when child/supervisor cleanup returned early.
		// Await real closure completion before propagating the original error.
		let drained = self.drain().await;
		cleanup.and(drained)
	}

	pub(super) async fn drain(&self) -> Result<()> {
		// Admission is stopped first. Normal cleanup also joins supervisors;
		// the owner's final barrier still runs if that cleanup returned early.
		// Detached checks own permits until their actual closures return, so
		// filesystem cleanup or dropping the owner cannot overtake their work.
		let _all = self
			.permits
			.clone()
			.acquire_many_owned(WORKERS as u32)
			.await
			.context("observation validation drain unavailable")?;
		Ok(())
	}
}

#[cfg(test)]
#[path = "ssh_observation_validation_tests.rs"]
mod tests;
