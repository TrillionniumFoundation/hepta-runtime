// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Single-pass receipt encoding with bounded byte lengths and reservation requests.

use super::{JobRecord, MAX_JOB_RECORD_BYTES};
use anyhow::{bail, Context, Result};
use std::io::{self, Write};

struct RecordBuffer {
	bytes: Vec<u8>,
	writable_capacity: usize,
	limit_exceeded: bool,
}

impl RecordBuffer {
	fn new(capacity_hint: usize) -> Result<Self> {
		let mut bytes = Vec::new();
		bytes
			.try_reserve_exact(capacity_hint.min(MAX_JOB_RECORD_BYTES as usize))
			.context("cannot allocate bounded durable job write buffer")?;
		let writable_capacity = bytes.capacity().min(MAX_JOB_RECORD_BYTES as usize);
		Ok(Self {
			bytes,
			writable_capacity,
			limit_exceeded: false,
		})
	}

	#[inline]
	fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
		// Logical capacity stays within the encoded-byte limit even if an
		// allocator grants more space than requested. Most serde fragments
		// already fit, so they need only one available-capacity comparison.
		if bytes.len() > self.writable_capacity - self.bytes.len() {
			self.reserve(bytes.len())?;
		}
		self.bytes.extend_from_slice(bytes);
		Ok(())
	}

	#[cold]
	#[inline(never)]
	fn reserve(&mut self, additional: usize) -> io::Result<()> {
		let limit = MAX_JOB_RECORD_BYTES as usize;
		if additional > limit - self.bytes.len() {
			self.limit_exceeded = true;
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				"durable job write buffer limit exceeded",
			));
		}
		let required = self.bytes.len() + additional;
		// Clamp growth before requesting memory, including JSON escapes whose
		// encoded size is larger than the source String length.
		let capacity = required
			.max(self.writable_capacity.saturating_mul(2))
			.min(limit);
		self.bytes
			.try_reserve_exact(capacity - self.bytes.len())
			.map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
		self.writable_capacity = self.bytes.capacity().min(limit);
		Ok(())
	}
}

impl Write for RecordBuffer {
	#[inline]
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		self.append(bytes)?;
		Ok(bytes.len())
	}

	#[inline]
	fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
		// serde uses write_all for every token/escape. This buffer either appends
		// the complete fragment or returns an error, without the generic partial
		// write retry loop used by the trait's default implementation.
		self.append(bytes)
	}

	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

fn capacity_hint(record: &JobRecord) -> usize {
	// This is only a reservation hint, not validation or an encoded-size pass.
	// Fixed keys, formatting and numeric fields fit in the initial allowance;
	// string lengths need no scan of their contents. The writer enforces the
	// actual encoded-byte limit even if escaping makes this estimate too small.
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
	// Retain serde_json's small-record starting capacity. Reserving an estimate
	// only pays when the payload would otherwise require a large reallocation.
	let mut writer = RecordBuffer::new(if hint > 4096 { hint } else { 128 })?;
	if let Err(error) = serde_json::to_writer_pretty(&mut writer, record) {
		if writer.limit_exceeded {
			bail!("durable job record exceeds {} bytes", MAX_JOB_RECORD_BYTES);
		}
		return Err(error).context("cannot encode durable job record");
	}
	Ok(writer.bytes)
}

#[cfg(test)]
#[path = "jobs_persistence_tests.rs"]
mod tests;
