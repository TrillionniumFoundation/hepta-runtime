// Copyright 2026 Muvon Un Limited
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

//! Read-only MCP interop for the canonical codex-execution-core v1 intent.
//!
//! This port only validates and hashes a shadow intent. It is intentionally
//! incapable of issuing a reservation, Start, FinalUse or an EffectReceipt.
//! Wire equality is tested against the independent execution-core golden vector.

use anyhow::{bail, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::config::runtime_config;

const MAX_RECORD_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShadowExecutionIntentParams {
	pub record: CanonicalExecutionRecordV1,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(
	tag = "kind",
	content = "record",
	rename_all = "snake_case",
	deny_unknown_fields
)]
pub enum CanonicalExecutionRecordV1 {
	ExecutionIntent(CanonicalExecutionIntentV1),
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CanonicalExecutionIntentV1 {
	pub binding: CanonicalExecutionBindingV1,
	pub class: CanonicalExecutionClassV1,
	pub payload_digest: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalExecutionClassV1 {
	ReadOnlyInspection,
	FileRead,
	NonDestructiveBuild,
	RestrictedFileWrite,
	DurableProcess,
	PrivilegedAction,
	CrossHostDevice,
}

impl CanonicalExecutionClassV1 {
	fn is_effectful(self) -> bool {
		!matches!(self, Self::ReadOnlyInspection | Self::FileRead)
	}
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalCurrentnessV1 {
	Current,
	Stale,
	Unknown,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ShadowFinalUseV1 {
	NotGranted,
}

// Internally tagged unit variants may discard extra map members before the
// enum-level deny_unknown_fields check. A strict map-shaped envelope keeps
// forged authorization fields out without changing canonical wire bytes.
impl<'de> Deserialize<'de> for ShadowFinalUseV1 {
	fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		#[derive(Deserialize)]
		#[serde(rename_all = "snake_case")]
		enum State {
			NotGranted,
		}
		#[derive(Deserialize)]
		#[serde(deny_unknown_fields)]
		struct Envelope {
			state: State,
		}
		match Envelope::deserialize(deserializer)?.state {
			State::NotGranted => Ok(Self::NotGranted),
		}
	}
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CanonicalExecutionBindingV1 {
	pub schema_version: u32,
	pub run_id: String,
	pub turn_id: String,
	pub cell_id: Option<String>,
	pub organ_id: Option<String>,
	pub operation_id: String,
	pub principal: String,
	pub objective_digest: String,
	pub policy_digest: String,
	pub candidate_digest: String,
	pub host: String,
	pub generation: u64,
	pub idempotency_key: String,
	pub predecessor: Option<String>,
	pub currentness: CanonicalCurrentnessV1,
	pub final_use: ShadowFinalUseV1,
	pub rollback_reference: Option<String>,
}

fn valid_text(s: &str) -> bool {
	!s.is_empty() && s.len() <= 256 && s.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_digest(s: &str) -> bool {
	s.len() == 64
		&& s.bytes().any(|byte| byte != b'0')
		&& s.bytes()
			.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate(record: &CanonicalExecutionRecordV1) -> Result<()> {
	let CanonicalExecutionRecordV1::ExecutionIntent(intent) = record;
	let b = &intent.binding;
	if b.schema_version != 1 || b.generation == 0 {
		bail!("execution v1 schema or generation invalid");
	}
	if b.predecessor.is_some() || !matches!(b.currentness, CanonicalCurrentnessV1::Current) {
		bail!("shadow protocol requires a current first intent with no predecessor");
	}
	for value in [
		&b.run_id,
		&b.turn_id,
		&b.operation_id,
		&b.principal,
		&b.host,
		&b.idempotency_key,
	] {
		if !valid_text(value) {
			bail!("invalid execution identity");
		}
	}
	match (&b.cell_id, &b.organ_id) {
		(Some(value), None) | (None, Some(value)) if valid_text(value) => {}
		_ => bail!("shadow execution must bind exactly one cell or organ"),
	}
	for value in [
		&b.objective_digest,
		&b.policy_digest,
		&b.candidate_digest,
		&intent.payload_digest,
	] {
		if !valid_digest(value) {
			bail!("invalid canonical execution digest");
		}
	}
	if let Some(value) = &b.rollback_reference {
		if !valid_text(value) {
			bail!("invalid rollback reference");
		}
	}
	if intent.class.is_effectful() && b.rollback_reference.is_none() {
		bail!("effectful proposal requires explicit rollback reference");
	}
	Ok(())
}

fn validate_and_digest(record: &CanonicalExecutionRecordV1) -> Result<String> {
	validate(record)?;
	let bytes = serde_json::to_vec(record)?;
	if bytes.len() > MAX_RECORD_BYTES {
		bail!("execution record exceeds canonical byte budget");
	}
	let mut hash = Sha256::new();
	hash.update(b"codex.execution-record.v1\0");
	hash.update(bytes);
	let mut hex = String::with_capacity(64);
	const HEX: &[u8; 16] = b"0123456789abcdef";
	for byte in hash.finalize() {
		hex.push(HEX[(byte >> 4) as usize] as char);
		hex.push(HEX[(byte & 15) as usize] as char);
	}
	Ok(hex)
}

/// Non-executing inspection, explicitly bound to a configured host.
/// No ledger write, token issuance, SSH, PTY or shell calls occur.
pub fn admit_shadow_intent(params: ShadowExecutionIntentParams) -> Result<String> {
	let CanonicalExecutionRecordV1::ExecutionIntent(intent) = &params.record;
	runtime_config()?.host(&intent.binding.host)?;
	let record_digest = validate_and_digest(&params.record)?;
	Ok(serde_json::json!({
		"schema_version": 1,
		"status": "shadow_only",
		"executable": false,
		"record_digest": record_digest,
		"operation_id": intent.binding.operation_id,
	})
	.to_string())
}

#[cfg(test)]
#[path = "execution_tests.rs"]
mod tests;
