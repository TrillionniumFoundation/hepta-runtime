// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Complete-file validation with original-work custody and no worker count cap.

use super::activity::{Activity, Lease};
use anyhow::{anyhow, bail, Result};
use std::sync::Arc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub(super) struct Workers {
	activity: Arc<Activity>,
}

// The same guard follows queued/running work, its returned result, and the
// final owner check. Failure freezes admission before releasing custody.
struct Completion {
	_activity: Lease,
	stop: CancellationToken,
	completed: bool,
}

impl Completion {
	fn finish(mut self) {
		// Consuming the whole guard forces the blocking closure to own its
		// activity and Drop state together, rather than capturing copied fields.
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

// Send is required for the blocking task's result. Core separately enforces
// its lifetime owner thread before using this ticket; it is not a file lease.
pub(super) struct OwnerTicket {
	completion: Completion,
	deadline: Instant,
}

impl OwnerTicket {
	pub(super) fn check_current(&self) -> Result<()> {
		if self.completion.stop.is_cancelled() || Instant::now() >= self.deadline {
			bail!("observation validation cancelled or expired before authority acceptance");
		}
		Ok(())
	}

	pub(super) fn finish<F>(self, check: F) -> Result<()>
	where
		F: FnOnce(&Self) -> Result<()>,
	{
		self.check_current()?;
		check(&self)?;
		self.check_current()?;
		// No early activity release separates the complete
		// worker read from this owner result. Errors/unwind retain failure Drop.
		self.completion.finish();
		Ok(())
	}
}

impl Workers {
	pub(super) fn new() -> Self {
		Self {
			activity: Arc::new(Activity::default()),
		}
	}

	// Existing worker-lifecycle tests retain the no-owner-work wrapper. The
	// production owner must explicitly consume its ticket with a full recheck.
	#[cfg(test)]
	pub(super) async fn run<F>(
		&self,
		stop: &CancellationToken,
		deadline: Instant,
		check: F,
	) -> Result<()>
	where
		F: FnOnce() -> Result<()> + Send + 'static,
	{
		self.run_retained(stop, deadline, move |_| check())
			.await?
			.finish(|_| Ok(()))
	}

	pub(super) async fn run_retained<F>(
		&self,
		stop: &CancellationToken,
		deadline: Instant,
		check: F,
	) -> Result<OwnerTicket>
	where
		F: FnOnce(&OwnerTicket) -> Result<()> + Send + 'static,
	{
		// Construct before spawn so even a discarded unstarted closure freezes
		// admission. The lease only tracks work for shutdown; it never queues or
		// rejects an independent validation because another one is active.
		let ticket = OwnerTicket {
			completion: Completion {
				_activity: self.activity.lease()?,
				stop: stop.clone(),
				completed: false,
			},
			deadline,
		};
		ticket.check_current()?;
		let mut work = tokio::task::spawn_blocking(move || {
			// Admission can precede execution in Tokio's blocking queue. Keep
			// the original deadline and refuse stale work before opening files.
			ticket.check_current()?;
			check(&ticket)?;
			ticket.check_current()?;
			Ok::<_, anyhow::Error>(ticket)
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
		let ticket = result?;
		// Completion and a timer/cancellation can become ready together. A
		// successfully hashed earlier snapshot grants no late authority.
		ticket.check_current()?;
		Ok(ticket)
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
		// Detached checks and unconsumed/active owner tickets retain the same
		// activity leases, so cleanup cannot overtake either phase of validation.
		self.activity.drain().await;
		Ok(())
	}
}

#[cfg(test)]
#[path = "ssh_observation_validation_tests.rs"]
mod tests;
