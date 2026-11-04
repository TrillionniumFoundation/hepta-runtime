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

//! Explicit, bounded source-map decoding. Source names and URLs are declarations;
//! the runtime admits only the selected map file and never follows its sources.

use anyhow::{bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use tokio_util::sync::CancellationToken;

#[path = "rea_source_map_parser.rs"]
mod parser;
#[path = "rea_source_map_worker.rs"]
mod worker;

pub(super) const MAX_MAP_BYTES: usize = 8 * 1024 * 1024;
pub(super) const MAX_REQUEST_BYTES: usize = 64 * 1024 * 1024;
pub(super) const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub(super) const MAX_MAPPINGS: usize = 200_000;
pub(super) const PROFILE: &str = "hepta.source-map-declarations.v1";

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceMapCollection {
	#[default]
	Summary,
	Sources,
	Names,
	Mappings,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GeneratedPosition {
	/// One-based generated line. JavaScript/CSS columns count UTF-16 code units.
	pub line: u32,
	/// Zero-based column; never a UTF-8 byte offset for JavaScript/CSS.
	pub column: u32,
}

fn default_limit() -> usize {
	64
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InspectSourceMapParams {
	/// Absolute regular UTF-8 JSON source-map file inside controller workspace roots, <=8 MiB.
	pub path: String,
	/// Optional complete-file lowercase SHA-256 precondition.
	pub expected_sha256: Option<String>,
	/// Returned analysis_sha256, mandatory on continuation pages; binds bytes and decoder profile.
	pub expected_analysis_sha256: Option<String>,
	#[serde(default)]
	pub collection: SourceMapCollection,
	#[serde(default)]
	pub offset: usize,
	/// 1..=256 rows. A summary returns counts, without all sources or content.
	#[serde(default = "default_limit")]
	pub limit: usize,
	/// Greatest recorded generated position <=query across lines. All coincident mappings survive.
	pub generated_position: Option<GeneratedPosition>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkerRequest {
	pub text: String,
	pub expected_analysis_sha256: Option<String>,
	pub collection: SourceMapCollection,
	pub offset: usize,
	pub limit: usize,
	pub generated_position: Option<GeneratedPosition>,
}

pub(super) fn sha256(bytes: &[u8]) -> String {
	let mut value = String::with_capacity(64);
	for byte in Sha256::digest(bytes) {
		let _ = write!(&mut value, "{byte:02x}");
	}
	value
}

fn valid_digest(value: &str) -> bool {
	value.len() == 64
		&& value
			.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) fn analysis_identity(map_sha256: &str) -> String {
	sha256(format!("{PROFILE}\0{map_sha256}").as_bytes())
}

pub(super) fn validate_request(request: &WorkerRequest) -> Result<()> {
	if request.text.len() > MAX_MAP_BYTES {
		bail!("source map exceeds 8 MiB");
	}
	if !(1..=256).contains(&request.limit) || request.offset > MAX_MAPPINGS {
		bail!("source-map page requires limit 1..=256 and offset <=200000");
	}
	if request.offset > 0 && request.expected_analysis_sha256.is_none() {
		bail!("source-map continuation requires expected_analysis_sha256");
	}
	if matches!(request.collection, SourceMapCollection::Summary) && request.offset != 0 {
		bail!("source-map summary has no continuation rows");
	}
	if request
		.expected_analysis_sha256
		.as_deref()
		.is_some_and(|v| !valid_digest(v))
	{
		bail!("source-map analysis identity must be a complete lowercase SHA-256");
	}
	if request
		.generated_position
		.as_ref()
		.is_some_and(|p| p.line == 0)
	{
		bail!("source-map query line must be one-based");
	}
	Ok(())
}

fn ensure_not_cancelled(cancellation: &CancellationToken) -> Result<()> {
	if cancellation.is_cancelled() {
		bail!("source-map inspection cancelled");
	}
	Ok(())
}

async fn inspect_with_roots(
	params: InspectSourceMapParams,
	roots: &[PathBuf],
	cancellation: &CancellationToken,
) -> Result<String> {
	ensure_not_cancelled(cancellation)?;
	if params
		.expected_sha256
		.as_deref()
		.is_some_and(|v| !valid_digest(v))
	{
		bail!("source-map source identity must be a complete lowercase SHA-256");
	}
	let mut request = WorkerRequest {
		text: String::new(),
		expected_analysis_sha256: params.expected_analysis_sha256,
		collection: params.collection,
		offset: params.offset,
		limit: params.limit,
		generated_position: params.generated_position,
	};
	validate_request(&request)?;
	static SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
	let permit = Arc::clone(SLOTS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(2))))
		.try_acquire_owned()
		.context("source-map parser is busy; retry after another inspection finishes")?;
	ensure_not_cancelled(cancellation)?;
	// The descriptor-bound file read retains admission until it actually finishes.
	let bytes =
		super::rea_files::read_bounded(Path::new(&params.path), roots, MAX_MAP_BYTES as u64).await;
	ensure_not_cancelled(cancellation)?;
	let bytes = bytes?;
	let source_sha256 = sha256(&bytes);
	let analysis_sha256 = analysis_identity(&source_sha256);
	if params
		.expected_sha256
		.as_ref()
		.is_some_and(|v| v != &source_sha256)
		|| request
			.expected_analysis_sha256
			.as_ref()
			.is_some_and(|v| v != &analysis_sha256)
	{
		bail!("source-map input or decoder identity changed");
	}
	let byte_length = bytes.len();
	request.text = String::from_utf8(bytes).context("source map must be valid UTF-8 JSON")?;
	ensure_not_cancelled(cancellation)?;
	#[cfg(not(test))]
	let report = worker::inspect_isolated(&request, cancellation).await?;
	#[cfg(test)]
	let report = parser::report(&request)?;
	ensure_not_cancelled(cancellation)?;
	if report["map_sha256"] != source_sha256
		|| report["analysis_sha256"] != analysis_sha256
		|| report["map_bytes"].as_u64() != Some(byte_length as u64)
	{
		bail!("source-map worker result does not bind the admitted bytes and profile");
	}
	let output = serde_json::to_string(&report)?;
	if output.len() > MAX_RESPONSE_BYTES {
		bail!("source-map response exceeds 1 MiB; reduce the selected page");
	}
	drop(permit);
	Ok(output)
}

pub async fn inspect(
	params: InspectSourceMapParams,
	cancellation: CancellationToken,
) -> Result<String> {
	ensure_not_cancelled(&cancellation)?;
	let roots = &super::runtime::runtime_config()?.controller_workspace_roots;
	inspect_with_roots(params, roots, &cancellation).await
}

/// Internal one-shot worker; it receives bytes, never paths or runtime credentials.
pub fn serve_once() -> Result<()> {
	worker::serve_once()
}

#[cfg(test)]
#[path = "rea_source_map_tests.rs"]
mod tests;
