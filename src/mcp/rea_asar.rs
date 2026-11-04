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

//! Controller-confined ASAR indexing and selected-member acquisition. A
//! header/descriptor observation is distinct from a selected payload digest.

use anyhow::{anyhow, bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::sync::CancellationToken;

#[path = "rea_asar_parser.rs"]
mod parser;
#[path = "rea_asar_worker.rs"]
mod worker;

const MAX_HEADER_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_WORKER_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_SOURCE_BYTES: usize = 1024 * 1024;
const MAX_READ_BYTES: usize = 64 * 1024;

fn page_limit() -> usize {
	64
}
fn read_limit() -> usize {
	16 * 1024
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InspectAsarParams {
	/// Absolute ASAR file inside configured controller workspace roots.
	pub path: String,
	/// Zero-based offset in the complete lexicographically sorted entry inventory.
	#[serde(default)]
	pub offset: usize,
	/// 1..=256 declarations per page; default 64.
	#[serde(default = "page_limit")]
	pub limit: usize,
	/// Descriptor observation from a prior page; paired with expected_header_sha256.
	pub expected_version: Option<String>,
	/// Native SHA-256 of archive bytes [0, payload_offset), including both Pickles and padding.
	/// Required on continuation. This is not Electron's JSON-header fuse digest.
	pub expected_header_sha256: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadAsarMemberParams {
	/// Absolute archive file inside configured controller workspace roots.
	pub path: String,
	/// Exact inventoried packed regular member path. Links and unpacked members are refused.
	pub member: String,
	/// Required descriptor observation returned by rea_inspect_asar.
	pub expected_version: String,
	/// Required native complete-Pickle header SHA-256 returned by rea_inspect_asar;
	/// an Electron JSON-header fuse digest is a different byte scope.
	pub expected_header_sha256: String,
	/// Zero-based byte offset within the selected member.
	#[serde(default)]
	pub offset: u64,
	/// Requested bytes, 1..=65536; default 16384. The entire selected member (<=64 MiB)
	/// is hashed and any declared SHA256/block integrity must match before delivery.
	#[serde(default = "read_limit")]
	pub length: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AsarSource {
	/// Exact inventoried packed member. The graph's path field selects the archive.
	pub member: String,
	/// Descriptor observation returned by rea_inspect_asar; required on every acquisition.
	pub expected_version: String,
	/// Native complete-Pickle digest returned by rea_inspect_asar, not the JSON-header fuse digest.
	pub expected_header_sha256: String,
}

pub(super) fn hex(bytes: &[u8]) -> String {
	let mut output = String::with_capacity(bytes.len().saturating_mul(2));
	for byte in bytes {
		let _ = write!(output, "{byte:02x}");
	}
	output
}

fn unhex(text: &str) -> Result<Vec<u8>> {
	if text.len() > MAX_SOURCE_BYTES * 2 || !text.len().is_multiple_of(2) {
		bail!("invalid ASAR worker byte representation length");
	}
	text.as_bytes()
		.chunks_exact(2)
		.map(|pair| {
			let mut value = 0u8;
			for byte in pair {
				value = value * 16
					+ match byte {
						b'0'..=b'9' => byte - b'0',
						b'a'..=b'f' => byte - b'a' + 10,
						_ => bail!("invalid ASAR worker hex byte"),
					};
			}
			Ok(value)
		})
		.collect()
}

pub(super) fn valid_digest(digest: &str) -> bool {
	digest.len() == 64
		&& digest
			.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validate_identity(version: Option<&str>, header: Option<&str>, required: bool) -> Result<()> {
	if version.is_some() != header.is_some() || (required && version.is_none()) {
		bail!("ASAR acquisition or continuation requires both expected_version and expected_header_sha256");
	}
	if version.is_some_and(|v| !v.strip_prefix("asv1_").is_some_and(valid_digest))
		|| header.is_some_and(|v| !valid_digest(v))
	{
		bail!("invalid ASAR descriptor/header identity");
	}
	Ok(())
}

impl AsarSource {
	pub(super) fn validate(&self) -> Result<()> {
		parser::validate_path(&self.member)?;
		validate_identity(
			Some(&self.expected_version),
			Some(&self.expected_header_sha256),
			true,
		)
	}
}

fn observed_version(meta: &std::fs::Metadata) -> Result<String> {
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		let fields = format!(
			"hepta-asar-observation-v1:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
			meta.dev(),
			meta.ino(),
			meta.len(),
			meta.mode(),
			meta.uid(),
			meta.gid(),
			meta.nlink(),
			meta.mtime(),
			meta.mtime_nsec(),
			meta.ctime(),
			meta.ctime_nsec()
		);
		Ok(format!("asv1_{}", hex(&Sha256::digest(fields.as_bytes()))))
	}
	#[cfg(not(unix))]
	{
		let _ = meta;
		bail!("ASAR observation requires qualified Unix descriptor metadata")
	}
}

fn ensure_not_cancelled(cancellation: &CancellationToken) -> Result<()> {
	if cancellation.is_cancelled() {
		bail!("ASAR inspection cancelled");
	}
	Ok(())
}

async fn hash_range(
	file: &mut tokio::fs::File,
	offset: u64,
	length: u64,
	cancellation: &CancellationToken,
) -> Result<String> {
	ensure_not_cancelled(cancellation)?;
	file.seek(std::io::SeekFrom::Start(offset)).await?;
	let mut hash = Sha256::new();
	let mut buffer = [0u8; 64 * 1024];
	let mut remaining = length;
	while remaining > 0 {
		ensure_not_cancelled(cancellation)?;
		let size = usize::try_from(remaining.min(buffer.len() as u64))?;
		file.read_exact(&mut buffer[..size])
			.await
			.context("ASAR source changed or ended during commitment check")?;
		hash.update(&buffer[..size]);
		remaining -= size as u64;
	}
	ensure_not_cancelled(cancellation)?;
	Ok(hex(&hash.finalize()))
}

fn number(value: &Value, field: &str) -> Result<u64> {
	value
		.get(field)
		.and_then(Value::as_u64)
		.ok_or_else(|| anyhow!("ASAR worker omitted {field}"))
}

async fn checked_report(
	file: &mut tokio::fs::File,
	before: &std::fs::Metadata,
	request: &parser::Request,
	report: &Value,
	expected_header: Option<&str>,
	cancellation: &CancellationToken,
) -> Result<()> {
	if report["record_format"] != "hepta.rea-asar.v1"
		|| report["request"] != serde_json::to_value(request)?
		|| report["source"]["observed_version"].as_str() != Some(observed_version(before)?.as_str())
		|| report["source"]["size_bytes"].as_u64() != Some(before.len())
	{
		bail!("ASAR worker report differs from the admitted descriptor or request");
	}
	let header_length = number(&report["source"], "header_bytes")?;
	if !(16..=MAX_HEADER_BYTES + 8).contains(&header_length)
		|| header_length > before.len()
		|| report["source"]["payload_offset"].as_u64() != Some(header_length)
	{
		bail!("ASAR worker returned invalid header extent");
	}
	let actual = hash_range(file, 0, header_length, cancellation).await?;
	if report["source"]["header_sha256"].as_str() != Some(actual.as_str())
		|| expected_header.is_some_and(|expected| expected != actual)
	{
		bail!("ASAR header commitment changed or differs from the admitted bytes");
	}
	if let parser::Request::Read {
		member,
		offset,
		length,
		require_complete,
	} = request
	{
		let result = &report["result"];
		let entry = &result["entry"];
		let size = number(entry, "size_bytes")?;
		let start = number(entry, "payload_offset")?;
		let returned = number(result, "length")?;
		if entry["kind"] != "packed_file"
			|| entry["path"].as_str() != Some(member.as_str())
			|| size > parser::MAX_VERIFY_BYTES
			|| start < header_length
			|| start > before.len()
			|| size > before.len() - start
			|| *offset > size
			|| returned != (size - *offset).min(*length as u64)
			|| result["offset"].as_u64() != Some(*offset)
			|| result["member_bytes_verified"].as_u64() != Some(size)
			|| (*require_complete && (*offset != 0 || returned != size))
		{
			bail!("ASAR worker returned an invalid selected-member extent");
		}
		let bytes = unhex(
			result["bytes_hex"]
				.as_str()
				.ok_or_else(|| anyhow!("ASAR worker omitted selected bytes"))?,
		)?;
		if bytes.len() as u64 != returned {
			bail!("ASAR worker selected byte length differs");
		}
		let range = hash_range(file, start + offset, returned, cancellation).await?;
		if range != hex(&Sha256::digest(&bytes))
			|| result["range_sha256"].as_str() != Some(range.as_str())
		{
			bail!("ASAR worker bytes differ from the admitted descriptor range");
		}
		let member_hash = hash_range(file, start, size, cancellation).await?;
		if result["member_sha256"].as_str() != Some(member_hash.as_str()) {
			bail!("ASAR selected whole-member digest differs from the admitted descriptor");
		}
	}
	let after = file.metadata().await?;
	#[cfg(unix)]
	super::rea_files::ensure_unchanged(before, &after)?;
	if observed_version(&after)? != observed_version(before)? {
		bail!("ASAR descriptor changed during inspection");
	}
	ensure_not_cancelled(cancellation)
}

async fn inspect_with_roots(
	path: &str,
	request: parser::Request,
	expected_version: Option<&str>,
	expected_header: Option<&str>,
	roots: &[PathBuf],
	cancellation: &CancellationToken,
) -> Result<Value> {
	ensure_not_cancelled(cancellation)?;
	request.validate()?;
	let required = match &request {
		parser::Request::Index { offset, .. } => *offset > 0,
		parser::Request::Read { .. } => true,
	};
	validate_identity(expected_version, expected_header, required)?;
	static SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
	let _permit = Arc::clone(SLOTS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(2))))
		.try_acquire_owned()
		.context("ASAR parser is busy; retry after another inspection finishes")?;
	let (mut file, before) = super::rea_files::open_confined(Path::new(path), roots).await?;
	ensure_not_cancelled(cancellation)?;
	let version = observed_version(&before)?;
	if expected_version.is_some_and(|expected| expected != version) {
		bail!("ASAR descriptor changed; obtain a fresh index identity");
	}
	let worker_file = file.try_clone().await?.into_std().await;
	ensure_not_cancelled(cancellation)?;
	#[cfg(not(test))]
	let mut report = worker::inspect_isolated(worker_file, &request, cancellation).await?;
	#[cfg(test)]
	let mut report = {
		let request = request.clone();
		tokio::task::spawn_blocking(move || {
			let mut worker_file = worker_file;
			parser::inspect_file(&mut worker_file, &request)
		})
		.await
		.context("ASAR parser test task failed")??
	};
	ensure_not_cancelled(cancellation)?;
	tokio::time::timeout(
		std::time::Duration::from_secs(20),
		checked_report(
			&mut file,
			&before,
			&request,
			&report,
			expected_header,
			cancellation,
		),
	)
	.await
	.context("ASAR commitment check exceeded 20 second deadline")??;
	report["source"]["local_path"] = json!(path);
	report["source"]["header_pinned"] = json!(expected_header.is_some());
	report["source"]["header_pin_authenticated"] = json!(false);
	Ok(report)
}

fn render(report: &Value) -> Result<String> {
	let encoded = serde_json::to_string(report)?;
	if encoded.len() > MAX_RESPONSE_BYTES {
		bail!("ASAR response exceeds 1 MiB; reduce page size");
	}
	Ok(encoded)
}

pub async fn inspect_asar(
	params: InspectAsarParams,
	cancellation: CancellationToken,
) -> Result<String> {
	ensure_not_cancelled(&cancellation)?;
	let roots = &super::runtime::runtime_config()?.controller_workspace_roots;
	render(
		&inspect_with_roots(
			&params.path,
			parser::Request::Index {
				offset: params.offset,
				limit: params.limit,
			},
			params.expected_version.as_deref(),
			params.expected_header_sha256.as_deref(),
			roots,
			&cancellation,
		)
		.await?,
	)
}

pub async fn read_member(
	params: ReadAsarMemberParams,
	cancellation: CancellationToken,
) -> Result<String> {
	ensure_not_cancelled(&cancellation)?;
	if !(1..=MAX_READ_BYTES).contains(&params.length) {
		bail!("ASAR member read length must be 1..=65536 bytes");
	}
	let roots = &super::runtime::runtime_config()?.controller_workspace_roots;
	render(
		&inspect_with_roots(
			&params.path,
			parser::Request::Read {
				member: params.member,
				offset: params.offset,
				length: params.length,
				require_complete: false,
			},
			Some(&params.expected_version),
			Some(&params.expected_header_sha256),
			roots,
			&cancellation,
		)
		.await?,
	)
}

/// The graph receives only copied, bounded source bytes. These observations are
/// acquisition provenance; the graph identity continues to bind source bytes and grammar.
pub(super) async fn read_javascript_source(
	path: &str,
	selection: &AsarSource,
	roots: &[PathBuf],
	cancellation: &CancellationToken,
) -> Result<(Vec<u8>, Value)> {
	selection.validate()?;
	let report = inspect_with_roots(
		path,
		parser::Request::Read {
			member: selection.member.clone(),
			offset: 0,
			length: MAX_SOURCE_BYTES,
			require_complete: true,
		},
		Some(&selection.expected_version),
		Some(&selection.expected_header_sha256),
		roots,
		cancellation,
	)
	.await?;
	let result = &report["result"];
	let bytes = unhex(
		result["bytes_hex"]
			.as_str()
			.ok_or_else(|| anyhow!("ASAR worker omitted source bytes"))?,
	)?;
	let provenance = json!({"archive":report["source"],"member":result["entry"],
		"member_sha256":result["member_sha256"],"integrity_status":result["integrity_status"],
		"publisher_authenticated":false,"graph_identity_includes_archive_metadata":false});
	Ok((bytes, provenance))
}

/// Internal CLI: receives a read-only archive fd on stdin, never a pathname.
pub fn serve_once(request_json: &str) -> Result<()> {
	worker::serve_once(request_json)
}

#[cfg(test)]
#[path = "rea_asar_tests.rs"]
mod tests;
