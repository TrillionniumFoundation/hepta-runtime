// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Process CPU and monotonic elapsed measurements; no monetary conversion is assumed.

use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::time::Instant;

pub fn cpu_seconds() -> Result<f64> {
	let mut value = libc::timespec {
		tv_sec: 0,
		tv_nsec: 0,
	};
	if unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut value) } != 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	let seconds = value.tv_sec as f64 + value.tv_nsec as f64 * 1e-9;
	if !seconds.is_finite() || seconds < 0.0 {
		bail!("process CPU clock invalid");
	}
	Ok(seconds)
}

pub struct Stamp {
	wall: Instant,
	cpu: f64,
}
impl Stamp {
	pub fn start() -> Result<Self> {
		Ok(Self {
			wall: Instant::now(),
			cpu: cpu_seconds()?,
		})
	}
	pub fn finish(self, phase: &str) -> Result<Value> {
		Ok(
			json!({"phase":phase,"wall_seconds":self.wall.elapsed().as_secs_f64(),
			"process_cpu_seconds":cpu_seconds()?-self.cpu,"cpu_clock":"CLOCK_PROCESS_CPUTIME_ID",
			"cost_unit":"seconds; real deployment utility conversion remains an explicit parameter"}),
		)
	}
}
