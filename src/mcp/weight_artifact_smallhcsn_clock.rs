// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Original same-boot model windows independent of wall-clock corrections.
//! Missing or changed clocks deny new model work, never the saved exact inverse.

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;
#[cfg(target_os = "linux")]
use tokio::io::AsyncReadExt;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Stamp {
	pub boot_id: String,
	pub boottime_nanoseconds: u64,
}

impl Stamp {
	pub(super) fn validate(&self) -> Result<()> {
		let bytes = self.boot_id.as_bytes();
		ensure!(
			bytes.len() == 36
				&& bytes.iter().enumerate().all(|(index, byte)| {
					if matches!(index, 8 | 13 | 18 | 23) {
						*byte == b'-'
					} else {
						byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
					}
				}),
			"native Linux boot identity is malformed"
		);
		Ok(())
	}

	pub(super) fn remaining_at(&self, now: &Self, seconds: u64) -> Result<Duration> {
		self.validate()?;
		now.validate()?;
		ensure!(
			self.boot_id == now.boot_id,
			"original attempt belongs to a different kernel boot; inverse only"
		);
		let elapsed = now
			.boottime_nanoseconds
			.checked_sub(self.boottime_nanoseconds)
			.context("native boottime moved backward; inverse only")?;
		let limit = seconds
			.checked_mul(1_000_000_000)
			.context("native model window overflow")?;
		ensure!(
			elapsed < limit,
			"original monotonic model window expired; inverse only"
		);
		Ok(Duration::from_nanos(limit - elapsed))
	}
}

#[cfg(target_os = "linux")]
fn boottime() -> Result<u64> {
	let mut value = libc::timespec {
		tv_sec: 0,
		tv_nsec: 0,
	};
	// CLOCK_BOOTTIME is a kernel counter shared across processes and includes suspend.
	// The initialized timespec is exclusively borrowed for this nonblocking syscall.
	let status = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) };
	if status != 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	ensure!(
		value.tv_sec >= 0 && (0..1_000_000_000).contains(&value.tv_nsec),
		"native boottime value invalid"
	);
	u64::try_from(value.tv_sec)?
		.checked_mul(1_000_000_000)
		.and_then(|seconds| seconds.checked_add(value.tv_nsec as u64))
		.context("native boottime counter overflow")
}

async fn capture(earliest: bool) -> Result<Stamp> {
	#[cfg(target_os = "linux")]
	{
		let read = async {
			let started = boottime()?;
			let file = tokio::fs::File::open("/proc/sys/kernel/random/boot_id").await?;
			let mut bytes = Vec::with_capacity(37);
			file.take(65).read_to_end(&mut bytes).await?;
			ensure!(
				bytes.len() <= 64,
				"bounded native boot identity read exceeded"
			);
			let stamp = Stamp {
				boot_id: std::str::from_utf8(&bytes)?.trim_end().to_owned(),
				boottime_nanoseconds: if earliest { started } else { boottime()? },
			};
			stamp.validate()?;
			Ok::<_, anyhow::Error>(stamp)
		};
		tokio::time::timeout(Duration::from_secs(1), read)
			.await
			.context("native boot identity sampling deadline; inverse remains allowed")?
	}
	#[cfg(not(target_os = "linux"))]
	{
		let _ = earliest;
		anyhow::bail!("fixed model work requires the original Linux boot clock; inverse remains separately owned");
	}
}

pub(super) async fn begin() -> Result<Stamp> {
	capture(true).await
}

pub(super) async fn sample() -> Result<Stamp> {
	#[cfg(all(test, target_os = "linux"))]
	if let Some(stamp) = TEST_OBSERVATION.get() {
		stamp.validate()?;
		return Ok(stamp.clone());
	}
	capture(false).await
}

#[cfg(all(test, target_os = "linux"))]
static TEST_OBSERVATION: std::sync::OnceLock<Stamp> = std::sync::OnceLock::new();

#[cfg(all(test, target_os = "linux"))]
pub(super) fn observe_for_test(stamp: Stamp) -> Result<()> {
	stamp.validate()?;
	TEST_OBSERVATION
		.set(stamp)
		.map_err(|_| anyhow::anyhow!("one synthetic clock observation per isolated test"))
}

#[cfg(test)]
#[path = "weight_artifact_smallhcsn_clock_tests.rs"]
mod tests;
