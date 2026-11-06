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

//! Bounded, session-owned canonical bundle snapshots for complete byte readback.
//! This is a native extension; frozen REA tools and their schemas are unchanged.

use super::rea_contract::{self, Failure};
use super::rea_evidence_session::{EvidenceSession, EvidenceSnapshot};
use rmcp::{model::CallToolResult, schemars};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

const OP: &str = "read_evidence_bundle";
const PROFILE: &str = "hepta.evidence-bundle-readback.v1";
const MAX_PAGE_BYTES: usize = 256 * 1024;

fn default_length() -> usize {
	64 * 1024
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ReadParams {
	/// Returned snapshot_id. Required for every continuation or replay of an existing snapshot.
	pub snapshot_id: Option<String>,
	/// Byte offset into canonical UTF-8 JSON, not a record index or character offset.
	#[serde(default)]
	pub offset: usize,
	/// 1..=262144 bytes. Hex encoding preserves arbitrary UTF-8 split boundaries exactly.
	#[serde(default = "default_length")]
	pub length: usize,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct CloseParams {
	/// Exact snapshot_id returned by rea_read_evidence_bundle in this MCP session.
	pub snapshot_id: String,
}

#[derive(Debug, Clone, Copy)]
struct Limits {
	snapshot_bytes: usize,
	total_bytes: usize,
	snapshots: usize,
}

impl Default for Limits {
	fn default() -> Self {
		Self {
			snapshot_bytes: 64 * 1024 * 1024,
			total_bytes: 128 * 1024 * 1024,
			snapshots: 4,
		}
	}
}

#[derive(Debug)]
struct Snapshot {
	id: String,
	sha256: String,
	bytes: Vec<u8>,
	records: usize,
	unknowns: usize,
}

#[derive(Debug, Default)]
struct State {
	snapshots: BTreeMap<String, Arc<Snapshot>>,
	bytes: usize,
}

/// No eviction: an accepted cursor remains usable until explicit release or
/// session shutdown. One encoder owns the allocation budget even if its caller
/// drops the future. Limits count encoded payload bytes, not total process RSS.
#[derive(Debug)]
pub(super) struct ReadbackRegistry {
	state: Mutex<State>,
	encoder: Arc<Semaphore>,
	limits: Limits,
}

impl Default for ReadbackRegistry {
	fn default() -> Self {
		Self {
			state: Mutex::new(State::default()),
			encoder: Arc::new(Semaphore::new(1)),
			limits: Limits::default(),
		}
	}
}

fn hexadecimal(bytes: &[u8]) -> String {
	const HEX: &[u8; 16] = b"0123456789abcdef";
	let mut out = String::with_capacity(bytes.len() * 2);
	for byte in bytes {
		out.push(HEX[(byte >> 4) as usize] as char);
		out.push(HEX[(byte & 15) as usize] as char);
	}
	out
}

fn valid_id(id: &str) -> bool {
	id.strip_prefix("ebs1_").is_some_and(|digest| {
		digest.len() == 64
			&& digest
				.bytes()
				.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
	})
}

fn invalid(message: &str) -> Failure {
	Failure::input(
		OP,
		vec![json!({"reason":"invalid_value","message":message})],
	)
}

fn active(cancellation: &CancellationToken) -> Result<(), Failure> {
	if cancellation.is_cancelled() {
		Err(Failure::cancelled(OP))
	} else {
		Ok(())
	}
}

impl ReadbackRegistry {
	fn unavailable() -> Failure {
		Failure::integrity("Evidence readback registry is unavailable")
	}

	fn budget(&self, reason: &str) -> Failure {
		Failure::resource(
			OP,
			"evidence-snapshot-cache",
			reason,
			json!({"max_snapshot_bytes":self.limits.snapshot_bytes,
				"max_retained_bytes":self.limits.total_bytes,
				"max_snapshots":self.limits.snapshots}),
			false,
			"Release an existing snapshot with rea_close_evidence_snapshot, or export the complete retained bundle to an authorized file. Existing snapshots and Evidence are unchanged.",
		)
	}

	async fn select(
		&self,
		params: &ReadParams,
		session: &EvidenceSession,
		cancellation: &CancellationToken,
	) -> Result<Arc<Snapshot>, Failure> {
		active(cancellation)?;
		if !(1..=MAX_PAGE_BYTES).contains(&params.length) {
			return Err(invalid("length must be between 1 and 262144 bytes"));
		}
		if let Some(id) = &params.snapshot_id {
			if !valid_id(id) {
				return Err(invalid(
					"snapshot_id must be ebs1_ followed by 64 lowercase hex digits",
				));
			}
			return self
				.state
				.lock()
				.map_err(|_| Self::unavailable())?
				.snapshots
				.get(id)
				.cloned()
				.ok_or_else(|| Failure::integrity("Snapshot is not retained in this session; it may have been released. Explicitly request a new snapshot at offset zero."));
		}
		if params.offset != 0 {
			return Err(invalid(
				"continuation requires snapshot_id; a new snapshot starts at offset zero",
			));
		}
		let permit = Arc::clone(&self.encoder)
			.try_acquire_owned()
			.map_err(|_| self.budget("A snapshot encoder is already active in this session."))?;
		let available = {
			let state = self.state.lock().map_err(|_| Self::unavailable())?;
			if state.snapshots.len() >= self.limits.snapshots {
				return Err(self.budget("The retained snapshot count limit was reached."));
			}
			self.limits
				.snapshot_bytes
				.min(self.limits.total_bytes.saturating_sub(state.bytes))
		};
		if available == 0 {
			return Err(self.budget("The retained snapshot byte limit was reached."));
		}
		let selected = session.snapshot()?;
		let child = cancellation.child_token();
		// Dropping a cancelled request cancels its bounded encoder as well. The
		// semaphore stays with the worker until it has actually stopped writing.
		let _cancel_on_drop = child.clone().drop_guard();
		let (candidate, _permit) = tokio::task::spawn_blocking(move || {
			let candidate = encode(selected, available, child);
			(candidate, permit)
		})
		.await
		.map_err(|error| Failure::output(OP, format!("Snapshot encoder failed: {error}")))?;
		active(cancellation)?;
		let candidate = candidate.map_err(|error| match error {
			EncodeError::Cancelled => Failure::cancelled(OP),
			EncodeError::Limit => {
				self.budget("Canonical bundle exceeds the available snapshot byte budget.")
			}
			EncodeError::Other(message) => Failure::output(OP, message),
		})?;
		let mut state = self.state.lock().map_err(|_| Self::unavailable())?;
		active(cancellation)?;
		if let Some(existing) = state.snapshots.get(&candidate.id) {
			return Ok(Arc::clone(existing));
		}
		if state.snapshots.len() >= self.limits.snapshots
			|| candidate.bytes.len() > self.limits.total_bytes.saturating_sub(state.bytes)
		{
			return Err(self.budget("The retained snapshot budget was reached before publication."));
		}
		let candidate = Arc::new(candidate);
		state.bytes += candidate.bytes.len();
		state
			.snapshots
			.insert(candidate.id.clone(), Arc::clone(&candidate));
		Ok(candidate)
	}

	pub(super) async fn read(
		&self,
		params: ReadParams,
		session: &EvidenceSession,
		cancellation: CancellationToken,
	) -> CallToolResult {
		let snapshot = match self.select(&params, session, &cancellation).await {
			Ok(snapshot) => snapshot,
			Err(error) => return error.wire(),
		};
		if params.offset > snapshot.bytes.len() {
			return invalid("offset exceeds the immutable snapshot length").wire();
		}
		if let Err(error) = active(&cancellation) {
			return error.wire();
		}
		let end = snapshot
			.bytes
			.len()
			.min(params.offset.saturating_add(params.length));
		let bytes = &snapshot.bytes[params.offset..end];
		let result = json!({"profile":PROFILE,"snapshot_id":snapshot.id,
			"sha256":snapshot.sha256,"total_bytes":snapshot.bytes.len(),
			"records":snapshot.records,"unknowns":snapshot.unknowns,
			"encoding":"hex","offset":params.offset,"length":bytes.len(),
			"bytes_hex":hexadecimal(bytes),"chunk_sha256":hexadecimal(&Sha256::digest(bytes)),
			"next_offset":if end < snapshot.bytes.len() {Some(end)} else {None},
			"eof":end == snapshot.bytes.len(),"persistence":"session-only"});
		rea_contract::success(OP, json!({"result":result}), None)
	}

	pub(super) fn close(&self, params: CloseParams) -> CallToolResult {
		if !valid_id(&params.snapshot_id) {
			return Failure::input(
				"close_evidence_snapshot",
				vec![json!({"reason":"invalid_value",
					"message":"snapshot_id must be ebs1_ followed by 64 lowercase hex digits"})],
			)
			.wire();
		}
		let mut state = match self.state.lock() {
			Ok(state) => state,
			Err(_) => return Self::unavailable().wire(),
		};
		let released = state.snapshots.remove(&params.snapshot_id);
		let released_bytes = released.as_ref().map_or(0, |snapshot| snapshot.bytes.len());
		state.bytes -= released_bytes;
		let result = json!({"profile":PROFILE,"snapshot_id":params.snapshot_id,
			"released":released.is_some(),"released_bytes":released_bytes,
			"retained_snapshots":state.snapshots.len(),"retained_bytes":state.bytes});
		drop(state);
		rea_contract::success("close_evidence_snapshot", json!({"result":result}), None)
	}
}

#[derive(Debug)]
enum EncodeError {
	Cancelled,
	Limit,
	Other(String),
}

struct BoundedWriter {
	bytes: Vec<u8>,
	hash: Sha256,
	limit: usize,
	cancellation: CancellationToken,
	limit_exceeded: bool,
}

impl Write for BoundedWriter {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
			self.limit_exceeded = true;
			return Err(io::Error::other("snapshot encoding budget exceeded"));
		}
		for chunk in bytes.chunks(64 * 1024) {
			if self.cancellation.is_cancelled() {
				return Err(io::Error::other("snapshot encoding cancelled"));
			}
			self.bytes
				.try_reserve(chunk.len())
				.map_err(io::Error::other)?;
			self.bytes.extend_from_slice(chunk);
			self.hash.update(chunk);
		}
		Ok(bytes.len())
	}
	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

fn encode(
	selected: EvidenceSnapshot,
	limit: usize,
	cancellation: CancellationToken,
) -> Result<Snapshot, EncodeError> {
	let mut output = BoundedWriter {
		bytes: Vec::new(),
		hash: Sha256::new(),
		limit,
		cancellation,
		limit_exceeded: false,
	};
	if let Err(error) = selected.write_canonical(&mut output) {
		return Err(if output.cancellation.is_cancelled() {
			EncodeError::Cancelled
		} else if output.limit_exceeded {
			EncodeError::Limit
		} else {
			EncodeError::Other(format!("Complete snapshot encoding failed: {error:#}"))
		});
	}
	if output.cancellation.is_cancelled() {
		return Err(EncodeError::Cancelled);
	}
	let sha256 = hexadecimal(&output.hash.finalize());
	Ok(Snapshot {
		id: format!("ebs1_{sha256}"),
		sha256,
		bytes: output.bytes,
		records: selected.record_count(),
		unknowns: selected.unknown_count(),
	})
}

#[cfg(test)]
#[path = "rea_evidence_readback_tests.rs"]
mod tests;
