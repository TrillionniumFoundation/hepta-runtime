// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//! Actual unchanged target Deserialize followed by the complete async plan handler.

use anyhow::{anyhow, bail, Result};
use std::io::{Read, Write};
#[path = "../weight_bellman.rs"]
mod original;

fn clock_ns() -> Result<u64> {
	let mut value = libc::timespec { tv_sec: 0, tv_nsec: 0 };
	let code = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) };
	if code != 0 || value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
		bail!("invalid actual monotonic clock");
	}
	u64::try_from(value.tv_sec)?
		.checked_mul(1_000_000_000)
		.and_then(|v| v.checked_add(value.tv_nsec as u64))
		.ok_or_else(|| anyhow!("monotonic clock overflow"))
}

fn main() -> Result<()> {
	let mut input = Vec::new();
	std::io::stdin().read_to_end(&mut input)?;
	let mut output = std::io::BufWriter::new(std::io::stdout().lock());
	let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
	let mut at = 0;
	let mut index = 0_u64;
	while at < input.len() {
		if input.len() - at < 8 { bail!("partial owned input header"); }
		let size = usize::try_from(u64::from_le_bytes(input[at..at + 8].try_into()?))?;
		at += 8;
		if size > input.len() - at { bail!("partial owned input body"); }
		let value: serde_json::Value = serde_json::from_slice(&input[at..at + size])?;
		at += size;
		let canonical = serde_json::to_vec(&value)?;
		let before = clock_ns()?;
		let (status, text) = match serde_json::from_value::<original::BellmanPlanParams>(value) {
			Ok(params) => match runtime.block_on(original::plan(params)) {
				Ok(result) => (0_u64, result),
				Err(error) => (2_u64, error.to_string()),
			},
			Err(error) => (1_u64, format!("failed to deserialize parameters: {error}")),
		};
		let after = clock_ns()?;
		let mut result = b"HBCOR001".to_vec();
		for word in [status, canonical.len() as u64, text.len() as u64, before, after, index, 0] {
			result.extend_from_slice(&word.to_le_bytes());
		}
		result.extend_from_slice(&canonical);
		result.extend_from_slice(text.as_bytes());
		output.write_all(&(result.len() as u64).to_le_bytes())?;
		output.write_all(&result)?;
		index += 1;
	}
	output.flush()?;
	Ok(())
}
