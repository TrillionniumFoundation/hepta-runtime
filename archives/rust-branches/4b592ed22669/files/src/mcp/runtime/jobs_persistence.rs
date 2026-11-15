// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Single-pass receipt encoding with a payload-sized allocation hint.

use super::{JobRecord, MAX_JOB_RECORD_BYTES};
use anyhow::{bail, Context, Result};

fn capacity_hint(record: &JobRecord) -> usize {
	// This is only a reservation hint, not validation or an encoded-size pass.
	// Fixed keys, formatting and numeric fields fit in the initial allowance;
	// string lengths need no scan of their contents. After encoding, the
	// original encoded-byte check still rejects receipts that exceed the read limit.
	let array_items = record.args.len().saturating_add(record.env_keys.len());
	let fixed = 768usize.saturating_add(array_items.saturating_mul(8));
	[
		record.id.as_str(),
		record.host.as_str(),
		record.ssh_target.as_str(),
		record.unit.as_str(),
		record.remote_job_dir.as_str(),
		record.executable.as_str(),
		record.launch_state.as_str(),
	]
	.into_iter()
	.chain(record.args.iter().map(String::as_str))
	.chain(record.env_keys.iter().map(String::as_str))
	.chain(record.cwd.as_deref())
	.chain(record.idempotency_key.as_deref())
	.chain(record.request_digest.as_deref())
	.chain(record.launch_error.as_deref())
	.fold(fixed, |bytes, value| bytes.saturating_add(value.len()))
	.min(MAX_JOB_RECORD_BYTES as usize)
}

pub(super) fn encode_record(record: &JobRecord) -> Result<Vec<u8>> {
	let hint = capacity_hint(record);
	// Keep the original small-record starting capacity. Larger plain payloads
	// can avoid geometric growth without adding work to every JSON fragment.
	let mut bytes = Vec::new();
	bytes
		.try_reserve_exact(if hint > 4096 { hint } else { 128 })
		.context("cannot reserve durable job encoding buffer")?;
	serde_json::to_writer_pretty(&mut bytes, record)?;
	// This preserves the existing post-encoding rejection. Reservation is a
	// hint, not an allocation bound: JSON escaping may still grow the Vec.
	if bytes.len() as u64 > MAX_JOB_RECORD_BYTES {
		bail!("durable job record exceeds {} bytes", MAX_JOB_RECORD_BYTES);
	}
	Ok(bytes)
}

#[cfg(test)]
#[path = "jobs_persistence_tests.rs"]
mod tests;
