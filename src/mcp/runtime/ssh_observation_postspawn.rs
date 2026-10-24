// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Resolve only an owned live child with verified UID/inode and empty argv.
use super::{process_identity, OwnedChild, ProcessIdentity};
use anyhow::{bail, Context, Result};
use std::time::Duration;
use tokio::time::{sleep_until, timeout_at, Instant};
use tokio_util::sync::CancellationToken;

pub(super) struct Ready {
	pub identity: Option<ProcessIdentity>,
	pub terminal: bool,
}

pub(super) async fn wait_empty_argv(
	owned: &OwnedChild,
	anchor: &ProcessIdentity,
	expected: &[u8],
	ssh_inode: (u64, u64),
	deadline: Instant,
	cancel: &CancellationToken,
	stop: &CancellationToken,
) -> Result<Ready> {
	Waiting {
		owned,
		anchor,
		expected,
		ssh_inode,
		deadline,
		cancel,
		stop,
	}
	.run_with(process_identity)
	.await
}

struct Waiting<'a> {
	owned: &'a OwnedChild,
	anchor: &'a ProcessIdentity,
	expected: &'a [u8],
	ssh_inode: (u64, u64),
	deadline: Instant,
	cancel: &'a CancellationToken,
	stop: &'a CancellationToken,
}

impl Waiting<'_> {
	fn active(&self) -> Result<()> {
		if self.cancel.is_cancelled() || self.stop.is_cancelled() || Instant::now() >= self.deadline
		{
			bail!("observation empty argv readiness cancelled or expired");
		}
		Ok(())
	}

	async fn run_with(
		&self,
		mut observe: impl FnMut(u32) -> Result<ProcessIdentity>,
	) -> Result<Ready> {
		self.active()?;
		if self.owned.pid == 0
			|| self.owned.pidfd.is_none()
			|| self.expected.is_empty()
			|| !self.anchor.argv.is_empty()
			|| self.anchor.uid != unsafe { libc::geteuid() }
			|| (self.anchor.dev, self.anchor.ino) != self.ssh_inode
		{
			bail!("observation empty argv readiness precondition refused");
		}
		let mut pause = Duration::from_millis(1);
		loop {
			// Waiting grants no authority and never refreshes the caller's deadline.
			tokio::select! {
				biased;
				_ = self.cancel.cancelled() => bail!("observation empty argv readiness cancelled"),
				_ = self.stop.cancelled() => bail!("observation empty argv readiness stopped"),
				_ = sleep_until(self.deadline.min(Instant::now() + pause)) => {},
			}
			self.active()?;
			let mut child = tokio::select! {
				biased;
				_ = self.cancel.cancelled() => bail!("observation empty argv readiness cancelled"),
				_ = self.stop.cancelled() => bail!("observation empty argv readiness stopped"),
				value = timeout_at(self.deadline, self.owned.child.lock()) =>
					value.context("observation empty argv child ownership deadline")?,
			};
			self.active()?;
			// All owner wait/reap paths share this lock. A pidfd alone does not
			// protect numeric /proc lookups from reuse after another reaper runs.
			if child.try_wait()?.is_some() {
				self.active()?;
				return Ok(Ready {
					identity: None,
					terminal: true,
				});
			}
			// No errno allowlist: a read failure immediately leaves readiness.
			let identity = observe(self.owned.pid)?;
			if identity.birth != self.anchor.birth
				|| identity.uid != self.anchor.uid
				|| (identity.dev, identity.ino) != self.ssh_inode
				|| (!identity.argv.is_empty() && identity.argv != self.expected)
			{
				bail!("observation empty argv child identity changed");
			}
			let terminal = child.try_wait()?.is_some();
			self.active()?;
			if identity.argv == self.expected {
				return Ok(Ready {
					identity: Some(identity),
					terminal,
				});
			}
			if terminal {
				return Ok(Ready {
					identity: None,
					terminal: true,
				});
			}
			drop(child);
			pause = (pause * 2).min(Duration::from_millis(20));
		}
	}
}

#[cfg(test)]
#[path = "ssh_observation_postspawn_tests.rs"]
mod tests;
