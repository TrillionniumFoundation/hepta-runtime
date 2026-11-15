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

//! Read-only inspection and comparison of saved HAR observations. Recorded
//! response delivery never opens a socket or infers application transitions.

use anyhow::{bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

#[path = "rea_web_parser.rs"]
mod parser;

const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

fn default_limit() -> usize {
	64
}

fn default_body_length() -> usize {
	4096
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebCaptureSource {
	/// Absolute saved HAR path within configured controller workspace roots.
	pub path: String,
	/// Full SHA-256 of the exact saved capture, returned by inspection.
	pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InspectWebCaptureParams {
	/// Absolute saved HAR 1.2 file; never a URL or a live browser target.
	pub path: String,
	/// Pin the complete source; required for continuation pages.
	pub expected_sha256: Option<String>,
	/// Offset among entries matching all supplied filters, not the original entry index.
	#[serde(default)]
	pub offset: usize,
	/// Entries per page, 1..=256. Original capture indices are preserved.
	#[serde(default = "default_limit")]
	pub limit: usize,
	/// Exact case-sensitive recorded HTTP method; no normalization.
	pub method: Option<String>,
	/// Exact recorded URL, including its query string. It is never fetched.
	pub url: Option<String>,
	/// Exact recorded response status, 0..=599; zero can represent a failed request.
	pub status: Option<u16>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompareWebCapturesParams {
	pub before: WebCaptureSource,
	pub after: WebCaptureSource,
	/// Offset in deterministic request-identity and occurrence order.
	#[serde(default)]
	pub offset: usize,
	#[serde(default = "default_limit")]
	pub limit: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReplayWebEntryParams {
	pub source: WebCaptureSource,
	/// Original zero-based entry index returned by inspection.
	pub entry_index: usize,
	/// Byte offset in the UTF-8 representation of recorded HAR content.text.
	#[serde(default)]
	pub body_offset: usize,
	/// At most 65,536 bytes of that representation. Base64 is not decoded.
	#[serde(default = "default_body_length")]
	pub body_length: usize,
}

fn validate_digest(value: &str) -> Result<()> {
	if value.len() != 64
		|| !value
			.bytes()
			.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
	{
		bail!("saved web capture identity must be 64 lowercase SHA-256 characters");
	}
	Ok(())
}

fn validate_page(offset: usize, limit: usize) -> Result<()> {
	if !(1..=256).contains(&limit) || offset > parser::MAX_ENTRIES.saturating_mul(2) {
		bail!("saved web page requires limit 1..=256 and a bounded offset");
	}
	Ok(())
}

fn validate_inspect(params: &InspectWebCaptureParams) -> Result<()> {
	validate_page(params.offset, params.limit)?;
	if params.offset > 0 && params.expected_sha256.is_none() {
		bail!("saved web continuation requires expected_sha256 from the first page");
	}
	if let Some(digest) = &params.expected_sha256 {
		validate_digest(digest)?;
	}
	if let Some(method) = &params.method {
		parser::validate_method(method)?;
	}
	if params.url.as_ref().is_some_and(|url| {
		url.is_empty() || url.len() > parser::MAX_URL_BYTES || url.chars().any(char::is_control)
	}) {
		bail!("saved web URL filter is empty, oversized or contains control characters");
	}
	if params.status.is_some_and(|status| status > 599) {
		bail!("saved web status filter must be between 0 and 599");
	}
	Ok(())
}

fn validate_replay(params: &ReplayWebEntryParams) -> Result<()> {
	validate_digest(&params.source.sha256)?;
	if params.entry_index >= parser::MAX_ENTRIES
		|| params.body_offset > MAX_FILE_BYTES as usize
		|| !(1..=65_536).contains(&params.body_length)
	{
		bail!("saved web replay requires a bounded entry index and 1..=65536 body bytes");
	}
	Ok(())
}

fn admission() -> Arc<tokio::sync::Semaphore> {
	static SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
	Arc::clone(SLOTS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(2))))
}

async fn load_capture(
	path: &str,
	expected: Option<&str>,
	roots: &[PathBuf],
) -> Result<parser::Capture> {
	let permit = admission()
		.try_acquire_owned()
		.context("saved web parser is busy; retry this read after another inspection finishes")?;
	let bytes = super::rea_files::read_bounded(Path::new(path), roots, MAX_FILE_BYTES).await?;
	let expected = expected.map(str::to_owned);
	// The blocking task retains the permit after caller cancellation, so detached
	// parsing cannot silently exceed the shared concurrency bound.
	tokio::task::spawn_blocking(move || {
		let _permit = permit;
		parser::parse_capture(&bytes, expected.as_deref())
	})
	.await
	.context("saved web parse task failed")?
}

fn encode(report: Value) -> Result<String> {
	let encoded = serde_json::to_string(&report)?;
	if encoded.len() > MAX_RESPONSE_BYTES {
		bail!("saved web result exceeds 1 MiB; reduce the selected page or body range");
	}
	Ok(encoded)
}

async fn inspect_with_roots(params: InspectWebCaptureParams, roots: &[PathBuf]) -> Result<String> {
	validate_inspect(&params)?;
	let capture = load_capture(&params.path, params.expected_sha256.as_deref(), roots).await?;
	encode(parser::inspect(&capture, &params)?)
}

async fn compare_with_roots(params: CompareWebCapturesParams, roots: &[PathBuf]) -> Result<String> {
	validate_page(params.offset, params.limit)?;
	validate_digest(&params.before.sha256)?;
	validate_digest(&params.after.sha256)?;
	let before = load_capture(&params.before.path, Some(&params.before.sha256), roots).await?;
	let after = load_capture(&params.after.path, Some(&params.after.sha256), roots).await?;
	encode(parser::compare(
		&before,
		&after,
		params.offset,
		params.limit,
	)?)
}

async fn replay_with_roots(params: ReplayWebEntryParams, roots: &[PathBuf]) -> Result<String> {
	validate_replay(&params)?;
	let capture = load_capture(&params.source.path, Some(&params.source.sha256), roots).await?;
	encode(parser::replay(&capture, &params)?)
}

pub async fn inspect_capture(params: InspectWebCaptureParams) -> Result<String> {
	validate_inspect(&params)?;
	let roots = &super::runtime::runtime_config()?.controller_workspace_roots;
	inspect_with_roots(params, roots).await
}

pub async fn compare_captures(params: CompareWebCapturesParams) -> Result<String> {
	validate_page(params.offset, params.limit)?;
	validate_digest(&params.before.sha256)?;
	validate_digest(&params.after.sha256)?;
	let roots = &super::runtime::runtime_config()?.controller_workspace_roots;
	compare_with_roots(params, roots).await
}

pub async fn replay_entry(params: ReplayWebEntryParams) -> Result<String> {
	validate_replay(&params)?;
	let roots = &super::runtime::runtime_config()?.controller_workspace_roots;
	replay_with_roots(params, roots).await
}

#[cfg(test)]
#[path = "rea_web_tests.rs"]
mod rea_web_tests;
