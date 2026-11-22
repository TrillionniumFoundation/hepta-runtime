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

pub fn reaped_child_cpu_seconds() -> Result<f64> {
	let mut value = std::mem::MaybeUninit::<libc::rusage>::uninit();
	if unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, value.as_mut_ptr()) } != 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	let value = unsafe { value.assume_init() };
	let seconds = value.ru_utime.tv_sec as f64
		+ value.ru_stime.tv_sec as f64
		+ (value.ru_utime.tv_usec + value.ru_stime.tv_usec) as f64 * 1e-6;
	if !seconds.is_finite() || seconds < 0.0 {
		bail!("reaped child CPU measurement invalid");
	}
	Ok(seconds)
}

pub struct Stamp {
	wall: Instant,
	cpu: f64,
	children: f64,
}
impl Stamp {
	pub fn start() -> Result<Self> {
		Ok(Self {
			wall: Instant::now(),
			cpu: cpu_seconds()?,
			children: reaped_child_cpu_seconds()?,
		})
	}
	pub fn finish(self, phase: &str) -> Result<Value> {
		let process = cpu_seconds()? - self.cpu;
		let children = reaped_child_cpu_seconds()? - self.children;
		Ok(
			json!({"phase":phase,"wall_seconds":self.wall.elapsed().as_secs_f64(),
			"process_cpu_seconds":process,"cpu_clock":"CLOCK_PROCESS_CPUTIME_ID",
			"reaped_child_cpu_seconds":children,"child_cpu_clock":"RUSAGE_CHILDREN",
			"process_and_reaped_descendants_cpu_seconds":process+children,
			"cost_unit":"seconds; real deployment utility conversion remains an explicit parameter"}),
		)
	}
}
