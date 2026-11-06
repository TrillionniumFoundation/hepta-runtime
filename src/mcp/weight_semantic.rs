// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
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

//! Read-only MCP boundary for one explicit, content-bound endpoint replay core.
//!
//! The worker owns its permit across parsing, replay and bounded serialization.
//! Cancelling an asynchronous waiter cannot admit a second CPU worker. The core
//! reconstructs its own features and teacher; identities bind supplied bytes,
//! not external provenance, hardware arithmetic or successful model editing.

use anyhow::{ensure, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::sync::{Arc, OnceLock};
use tokio::sync::Semaphore;

#[path = "weight_semantic/lib.rs"]
pub(super) mod core;

const MAX_RESULT_BYTES: usize = 1024 * 1024;
const TARGET_CONTRACT: &[u8] = include_bytes!("weight_semantic/target_contract.json");
static WORKERS: OnceLock<Arc<Semaphore>> = OnceLock::new();

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SemanticReplayParams {
	/// Exact UTF-8 JSON of the endpoint replay request, at most 2 MiB. Contains
	/// profile="hepta.joint-renewal.endpoint-replay.v1", checkpoint_json and its
	/// expected_checkpoint_sha256, public_json and its expected_public_sha256,
	/// and traces=[{source_row,steps:[{action,completion}]}]. Completion is null
	/// except at the actual due boundary; then provide observation_tick, failure
	/// and observation (0/1 on success, null on failure). All layers reject
	/// unknown fields. No hidden features, labels or teacher tables are accepted.
	#[schemars(length(min = 1, max = 2097152))]
	pub request_json: String,
	/// Lowercase SHA-256 of request_json's exact bytes, including any whitespace.
	#[schemars(length(min = 64, max = 64))]
	pub expected_request_sha256: String,
	/// Lowercase SHA-256 of the compiled weight_semantic/lib.rs source bytes.
	/// This is not a compiler, binary or external-source authentication claim.
	#[schemars(length(min = 64, max = 64))]
	pub expected_core_source_sha256: String,
	/// Lowercase SHA-256 of the exact compiled target_contract.json bytes.
	/// The endpoint, current-at-due, repair and additive-utility contract is fixed.
	#[schemars(length(min = 64, max = 64))]
	pub expected_target_contract_sha256: String,
}

#[derive(Serialize)]
struct SemanticReplayResult {
	#[serde(flatten)]
	replay: core::ReplayResult,
	adapter_schema: &'static str,
	request_sha256: String,
	request_bytes: usize,
	core_source_sha256: String,
	adapter_source_sha256: String,
	target_contract_sha256: String,
	maximum_concurrent_workers: usize,
	weights_modified: bool,
	independent_holdout_verified: bool,
	task_value_improvement_qualified: bool,
	production_eligible: bool,
}

fn sha(bytes: &[u8]) -> String {
	Sha256::digest(bytes)
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}

fn digest(value: &str) -> Result<()> {
	ensure!(
		value.len() == 64
			&& value
				.bytes()
				.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
		"semantic replay digests must be 64 lowercase hexadecimal characters"
	);
	Ok(())
}

struct BoundedResult {
	bytes: Vec<u8>,
	limit: usize,
}

impl Write for BoundedResult {
	fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
		if data.len() > self.limit.saturating_sub(self.bytes.len()) {
			return Err(std::io::Error::other(
				"semantic replay result byte budget exceeded; request fewer traces",
			));
		}
		self.bytes.extend_from_slice(data);
		Ok(data.len())
	}

	fn flush(&mut self) -> std::io::Result<()> {
		Ok(())
	}
}

pub(super) fn encode_result(value: &impl Serialize) -> Result<String> {
	let mut output = BoundedResult {
		bytes: Vec::new(),
		limit: MAX_RESULT_BYTES.min(crate::utils::truncation::MAX_RESULT_BYTES),
	};
	serde_json::to_writer(&mut output, value)
		.context("serializing bounded semantic replay result")?;
	String::from_utf8(output.bytes).context("semantic replay JSON result is not UTF-8")
}

pub(super) fn admit_request(params: &SemanticReplayParams) -> Result<core::ReplayParams> {
	ensure!(
		!params.request_json.is_empty() && params.request_json.len() <= core::MAX_REQUEST_BYTES,
		"semantic replay request_json must contain 1..2097152 UTF-8 bytes"
	);
	for value in [
		&params.expected_request_sha256,
		&params.expected_core_source_sha256,
		&params.expected_target_contract_sha256,
	] {
		digest(value)?;
	}
	let request_sha256 = sha(params.request_json.as_bytes());
	ensure!(
		request_sha256 == params.expected_request_sha256,
		"semantic replay request SHA256 mismatch"
	);
	let core_source_sha256 = sha(include_bytes!("weight_semantic/lib.rs"));
	ensure!(
		core_source_sha256 == params.expected_core_source_sha256,
		"semantic replay core source SHA256 mismatch"
	);
	let target_contract_sha256 = sha(TARGET_CONTRACT);
	ensure!(
		target_contract_sha256 == params.expected_target_contract_sha256,
		"semantic replay target contract SHA256 mismatch"
	);
	// Hash and size admission precede the second, structured parsing allocation.
	serde_json::from_str(&params.request_json).context("semantic replay request JSON is invalid")
}

fn execute(params: &SemanticReplayParams) -> Result<String> {
	let request = admit_request(params)?;
	let replay = core::replay(&request).context("native semantic core rejected the request")?;
	let core_source_sha256 = sha(include_bytes!("weight_semantic/lib.rs"));
	ensure!(
		replay.implementation_sha256 == core_source_sha256,
		"semantic replay core implementation identity differs"
	);
	encode_result(&SemanticReplayResult {
		replay,
		adapter_schema: "hepta.weight-semantic-replay.mcp.v1",
		request_sha256: params.expected_request_sha256.clone(),
		request_bytes: params.request_json.len(),
		core_source_sha256,
		adapter_source_sha256: sha(include_bytes!("weight_semantic.rs")),
		target_contract_sha256: params.expected_target_contract_sha256.clone(),
		maximum_concurrent_workers: 1,
		weights_modified: false,
		independent_holdout_verified: false,
		task_value_improvement_qualified: false,
		production_eligible: false,
	})
}

async fn run_worker<F>(workers: Arc<Semaphore>, work: F) -> Result<String>
where
	F: FnOnce() -> Result<String> + Send + 'static,
{
	let permit = workers
		.try_acquire_owned()
		.context("native semantic replay busy; no work admitted or queued")?;
	tokio::task::spawn_blocking(move || {
		// A dropped JoinHandle does not cancel a running blocking task. Its permit
		// must therefore live in the closure, including serialization and errors.
		let _permit = permit;
		work()
	})
	.await
	.context("native semantic replay worker failed")?
}

pub(super) async fn run_shared_worker<F>(work: F) -> Result<String>
where
	F: FnOnce() -> Result<String> + Send + 'static,
{
	let workers = WORKERS.get_or_init(|| Arc::new(Semaphore::new(1))).clone();
	run_worker(workers, work).await
}

pub async fn replay(params: SemanticReplayParams) -> Result<String> {
	run_shared_worker(move || execute(&params)).await
}

#[cfg(test)]
#[path = "weight_semantic/lib_tests.rs"]
mod core_tests;

#[cfg(test)]
#[path = "weight_semantic_tests.rs"]
pub(crate) mod weight_semantic_tests;
