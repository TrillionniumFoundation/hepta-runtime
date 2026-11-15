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

//! Native model-artifact inspection and bounded byte reads. Admission,
//! header commitments, optional streaming full-content commitments and final
//! descriptor checks share one open file. These tools do not execute models.

use anyhow::{anyhow, bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

#[path = "rea_model_parser.rs"]
mod parser;
#[path = "rea_model_session.rs"]
pub mod session;
#[path = "rea_model_worker.rs"]
mod worker;

pub(super) const MAX_HEADER_BYTES: u64 = 16 * 1024 * 1024;
pub(super) const MAX_READ_BYTES: usize = 64 * 1024;
pub(super) const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub(super) const MAX_INDEX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const HASH_BUFFER_BYTES: usize = 64 * 1024;
const HASH_DEADLINE: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Collection {
	#[default]
	Tensors,
	Metadata,
	Summary,
}

#[derive(
	Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum HashMode {
	#[default]
	Header,
	Full,
}

fn default_page_limit() -> usize {
	64
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InspectModelArtifactParams {
	/// Absolute regular-file path inside configured controller workspace roots.
	pub path: String,
	/// Tensor directory (default), metadata rows, or summary without rows.
	#[serde(default)]
	pub collection: Collection,
	/// Zero-based row offset. Nonzero offsets require both expected identity fields.
	#[serde(default)]
	pub offset: usize,
	/// Rows per page, 1..=256 (default 64). Smaller pages bound response size.
	#[serde(default = "default_page_limit")]
	pub limit: usize,
	/// Header-only is default. Full streams every file byte with a 64 KiB buffer.
	#[serde(default)]
	pub hash: HashMode,
	/// Descriptor observation token from a previous page; not a content digest.
	pub expected_version: Option<String>,
	/// Header SHA-256 from the same previous observation. Does not bind payload bytes.
	pub expected_header_sha256: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadModelArtifactParams {
	/// Absolute regular-file path inside configured controller workspace roots.
	pub path: String,
	/// Exact descriptor observation token returned by model inspection.
	pub expected_version: String,
	/// Exact header digest returned with that token. A header digest is not a full-file digest.
	pub expected_header_sha256: String,
	/// If supplied, stream and verify the complete file before returning the selected bytes.
	pub expected_full_sha256: Option<String>,
	/// Exact tensor name, or omit for an explicitly selected absolute file-byte range.
	pub tensor_name: Option<String>,
	/// Offset relative to the tensor when named, otherwise absolute file offset.
	#[serde(default)]
	pub offset: u64,
	/// Exact bytes to read, 1..=65536. A read crossing its selected boundary is rejected.
	pub length: usize,
}

pub(super) fn digest_hex(bytes: &[u8]) -> String {
	let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
	for byte in bytes {
		let _ = write!(encoded, "{byte:02x}");
	}
	encoded
}

pub(super) fn observed_version(metadata: &std::fs::Metadata) -> Result<String> {
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		let observation = format!(
			"hepta-model-file-observation-v1:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
			metadata.dev(),
			metadata.ino(),
			metadata.len(),
			metadata.mode(),
			metadata.uid(),
			metadata.gid(),
			metadata.nlink(),
			metadata.mtime(),
			metadata.mtime_nsec(),
			metadata.ctime(),
			metadata.ctime_nsec(),
			metadata.is_file()
		);
		Ok(format!(
			"mfv1_{}",
			digest_hex(&Sha256::digest(observation.as_bytes()))
		))
	}
	#[cfg(not(unix))]
	{
		let _ = metadata;
		bail!("model artifact identity requires Unix descriptor metadata on this build")
	}
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
	if value.len() != 64
		|| !value
			.bytes()
			.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
	{
		bail!("{label} must be 64 lowercase hexadecimal characters");
	}
	Ok(())
}

fn validate_version(value: &str) -> Result<()> {
	let digest = value
		.strip_prefix("mfv1_")
		.ok_or_else(|| anyhow!("expected_version is not a model descriptor observation token"))?;
	validate_digest(digest, "expected_version digest")
}

/// Reading is limited to the admitted length even if another process appends.
/// A final metadata check rejects ordinary mutation; the digest binds the bytes
/// actually captured and is not a filesystem snapshot against privileged races.
async fn hash_prefix(file: &mut tokio::fs::File, length: u64) -> Result<String> {
	file.seek(std::io::SeekFrom::Start(0)).await?;
	let mut remaining = length;
	let mut buffer = [0_u8; HASH_BUFFER_BYTES];
	let mut hash = Sha256::new();
	while remaining > 0 {
		let size = usize::try_from(remaining.min(HASH_BUFFER_BYTES as u64))?;
		file.read_exact(&mut buffer[..size])
			.await
			.context("model ended before its admitted extent during hashing")?;
		hash.update(&buffer[..size]);
		remaining -= size as u64;
	}
	Ok(digest_hex(&hash.finalize()))
}

struct ExpectedIdentity<'a> {
	version: Option<&'a str>,
	header: Option<&'a str>,
	full: Option<&'a str>,
}

async fn execute_with_roots(
	path: &Path,
	roots: &[PathBuf],
	request: parser::WorkerRequest,
	expected: ExpectedIdentity<'_>,
	hash_mode: HashMode,
) -> Result<Value> {
	if let Some(version) = expected.version {
		validate_version(version)?;
	}
	if let Some(digest) = expected.header {
		validate_digest(digest, "expected_header_sha256")?;
	}
	if let Some(digest) = expected.full {
		validate_digest(digest, "expected_full_sha256")?;
	}
	let (mut file, before) = super::rea_files::open_confined(path, roots).await?;
	let version = observed_version(&before)?;
	if expected.version.is_some_and(|expected| expected != version) {
		bail!("model descriptor observation changed; inspect the new artifact before reading");
	}
	// Duplicated descriptors share an open-file position. The parser finishes
	// before controller hashing starts; no concurrent seek occurs on this owner.
	let worker_file = file.try_clone().await?.into_std().await;
	#[cfg(not(test))]
	let mut report = worker::inspect_isolated(worker_file, &request).await?;
	#[cfg(test)]
	let mut report = tokio::task::spawn_blocking(move || {
		let mut worker_file = worker_file;
		parser::inspect_file(&mut worker_file, &request)
	})
	.await
	.context("model parser test task failed")??;
	let source = report
		.get("source")
		.and_then(Value::as_object)
		.ok_or_else(|| anyhow!("model worker omitted source identity"))?;
	if source.get("observed_version").and_then(Value::as_str) != Some(version.as_str())
		|| source.get("size_bytes").and_then(Value::as_u64) != Some(before.len())
	{
		bail!("model worker source differs from controller-admitted descriptor");
	}
	let header_bytes = source
		.get("header_bytes")
		.and_then(Value::as_u64)
		.filter(|length| *length <= MAX_HEADER_BYTES && *length <= before.len())
		.ok_or_else(|| anyhow!("model worker returned an invalid header extent"))?;
	let declared_header = source
		.get("header_sha256")
		.and_then(Value::as_str)
		.ok_or_else(|| anyhow!("model worker omitted header digest"))?
		.to_string();
	let actual_header = hash_prefix(&mut file, header_bytes).await?;
	if actual_header != declared_header {
		bail!("model worker header digest differs from admitted source bytes");
	}
	if expected
		.header
		.is_some_and(|expected| expected != actual_header)
	{
		bail!("model header digest changed; requested page or byte range is stale");
	}
	// Independently bind a returned byte range to the same admitted descriptor.
	if report["operation"] == "read_model_artifact" {
		let range = &report["result"];
		let start = range["file_offset"]
			.as_u64()
			.ok_or_else(|| anyhow!("model worker omitted range offset"))?;
		let length = range["length"]
			.as_u64()
			.filter(|length| *length > 0 && *length <= MAX_READ_BYTES as u64)
			.ok_or_else(|| anyhow!("model worker returned invalid range length"))?;
		if start > before.len() || length > before.len() - start {
			bail!("model worker range is outside admitted descriptor");
		}
		file.seek(std::io::SeekFrom::Start(start)).await?;
		let mut bytes = vec![0_u8; length as usize];
		file.read_exact(&mut bytes).await?;
		if range["sha256"].as_str() != Some(digest_hex(&Sha256::digest(&bytes)).as_str())
			|| range["bytes_hex"].as_str() != Some(digest_hex(&bytes).as_str())
		{
			bail!("model worker range differs from admitted source bytes");
		}
	}
	let full_hash = if hash_mode == HashMode::Full || expected.full.is_some() {
		Some(
			tokio::time::timeout(HASH_DEADLINE, hash_prefix(&mut file, before.len()))
				.await
				.context("streaming model hash exceeded 300 second deadline")??,
		)
	} else {
		None
	};
	if let Some(expected) = expected.full {
		if full_hash.as_deref() != Some(expected) {
			bail!("model full-file digest does not match requested content identity");
		}
	}
	let after = file.metadata().await?;
	#[cfg(unix)]
	super::rea_files::ensure_unchanged(&before, &after)?;
	if observed_version(&after)? != version {
		bail!("model descriptor changed during inspection or read");
	}
	let source = report["source"]
		.as_object_mut()
		.ok_or_else(|| anyhow!("model worker source is invalid"))?;
	source.insert("local_path".to_string(), json!(path.to_string_lossy()));
	source.insert("full_sha256".to_string(), json!(full_hash));
	source.insert(
		"identity_scope".to_string(),
		json!(if full_hash.is_some() {
			"full_file"
		} else {
			"header_and_descriptor_observation"
		}),
	);
	let limitations = report["limitations"]
		.as_array_mut()
		.ok_or_else(|| anyhow!("model worker limitations are invalid"))?;
	limitations.push(json!("Header SHA-256 does not commit to tensor payloads. Descriptor observation detects ordinary writes and replacement, not privileged same-UID mutation that defeats metadata observations."));
	limitations.push(json!("Pagination narrows delivery only. Tensor payload values, inference compatibility and model behavior are not validated; no model is executed or modified."));
	limitations.push(json!("This is a Hepta native model record, not an upstream REA Evidence record or a claim of complete format/provider parity."));
	Ok(report)
}

fn encode_report(report: &Value) -> Result<String> {
	let encoded = serde_json::to_string(report)?;
	if encoded.len() > MAX_RESPONSE_BYTES {
		bail!("model artifact response exceeds 1 MiB; reduce page limit or selected byte length");
	}
	Ok(encoded)
}

pub async fn inspect_model_artifact(params: InspectModelArtifactParams) -> Result<String> {
	if !(1..=256).contains(&params.limit) {
		bail!("model page limit must be between 1 and 256");
	}
	if params.expected_version.is_some() != params.expected_header_sha256.is_some() {
		bail!("expected_version and expected_header_sha256 must be supplied together");
	}
	if params.offset > 0 && params.expected_version.is_none() {
		bail!("continuation pages require expected_version and expected_header_sha256");
	}
	let roots = &super::runtime::runtime_config()?.controller_workspace_roots;
	let report = execute_with_roots(
		Path::new(&params.path),
		roots,
		parser::WorkerRequest::Inspect {
			collection: params.collection,
			offset: params.offset,
			limit: params.limit,
		},
		ExpectedIdentity {
			version: params.expected_version.as_deref(),
			header: params.expected_header_sha256.as_deref(),
			full: None,
		},
		params.hash,
	)
	.await?;
	encode_report(&report)
}

pub async fn read_model_artifact(params: ReadModelArtifactParams) -> Result<String> {
	if !(1..=MAX_READ_BYTES).contains(&params.length) {
		bail!("model read length must be between 1 and {MAX_READ_BYTES}");
	}
	let roots = &super::runtime::runtime_config()?.controller_workspace_roots;
	let report = execute_with_roots(
		Path::new(&params.path),
		roots,
		parser::WorkerRequest::Read {
			tensor_name: params.tensor_name,
			offset: params.offset,
			length: params.length,
		},
		ExpectedIdentity {
			version: Some(&params.expected_version),
			header: Some(&params.expected_header_sha256),
			full: params.expected_full_sha256.as_deref(),
		},
		HashMode::Header,
	)
	.await?;
	encode_report(&report)
}

/// Inspect a nonempty editable tensor through the caller's already-admitted
/// descriptor. Returns the complete record; its `result.tensor` is the tensor
/// descriptor and `source` carries the independently checked header identity.
/// The caller retains responsibility for its own full-content commitment and
/// final metadata check while writing a separate candidate artifact.
pub(super) async fn inspect_tensor_descriptor(
	file: &mut tokio::fs::File,
	tensor_name: &str,
) -> Result<Value> {
	let before = file.metadata().await?;
	let version = observed_version(&before)?;
	let worker_file = file.try_clone().await?.into_std().await;
	let request = parser::WorkerRequest::Read {
		tensor_name: Some(tensor_name.to_string()),
		offset: 0,
		length: 1,
	};
	#[cfg(not(test))]
	let report = worker::inspect_isolated(worker_file, &request).await?;
	#[cfg(test)]
	let report = tokio::task::spawn_blocking(move || {
		let mut worker_file = worker_file;
		parser::inspect_file(&mut worker_file, &request)
	})
	.await
	.context("model tensor parser test task failed")??;
	let source = &report["source"];
	let tensor = &report["result"]["tensor"];
	if report["record_format"] != "hepta.rea-model-artifact.v1"
		|| report["operation"] != "read_model_artifact"
		|| report["format"] != "safetensors"
		|| source["observed_version"].as_str() != Some(version.as_str())
		|| source["size_bytes"].as_u64() != Some(before.len())
		|| tensor["name"].as_str() != Some(tensor_name)
		|| tensor["storage_length_verified"] != true
		|| !matches!(tensor["dtype"].as_str(), Some("F32" | "F16" | "BF16"))
	{
		bail!("tensor edit requires a bound safetensors F32/F16/BF16 descriptor");
	}
	let header_length = source["header_bytes"]
		.as_u64()
		.filter(|length| *length <= MAX_HEADER_BYTES && *length <= before.len())
		.ok_or_else(|| anyhow!("model worker returned invalid header extent"))?;
	let header = hash_prefix(file, header_length).await?;
	if source["header_sha256"].as_str() != Some(header.as_str()) {
		bail!("tensor descriptor header differs from admitted source bytes");
	}
	let start = tensor["file_offset"]
		.as_u64()
		.ok_or_else(|| anyhow!("tensor descriptor has no file offset"))?;
	let length = tensor["byte_length"]
		.as_u64()
		.filter(|length| *length > 0)
		.ok_or_else(|| anyhow!("empty or unknown tensor extent cannot be patched"))?;
	if start < header_length
		|| start > before.len()
		|| length > before.len() - start
		|| report["result"]["file_offset"].as_u64() != Some(start)
		|| report["result"]["offset"] != 0
		|| report["result"]["length"] != 1
	{
		bail!("tensor descriptor range is outside the admitted file");
	}
	file.seek(std::io::SeekFrom::Start(start)).await?;
	let mut byte = [0_u8; 1];
	file.read_exact(&mut byte).await?;
	if report["result"]["bytes_hex"].as_str() != Some(digest_hex(&byte).as_str())
		|| report["result"]["sha256"].as_str() != Some(digest_hex(&Sha256::digest(byte)).as_str())
	{
		bail!("tensor descriptor probe differs from admitted source bytes");
	}
	let after = file.metadata().await?;
	#[cfg(unix)]
	super::rea_files::ensure_unchanged(&before, &after)?;
	if observed_version(&after)? != version {
		bail!("model changed during tensor descriptor inspection");
	}
	Ok(report)
}

/// Capture a complete directory once for an explicitly retained snapshot.
/// The controller validates structure bytes on the same admitted descriptor;
/// subsequent session operations use committed pages instead of this parser.
pub(super) async fn inspect_snapshot_directory(file: &mut tokio::fs::File) -> Result<Value> {
	let before = file.metadata().await?;
	let version = observed_version(&before)?;
	let worker_file = file.try_clone().await?.into_std().await;
	let request = parser::WorkerRequest::Directory;
	#[cfg(not(test))]
	let report = worker::inspect_isolated(worker_file, &request).await?;
	#[cfg(test)]
	let report = tokio::task::spawn_blocking(move || {
		let mut worker_file = worker_file;
		parser::inspect_file(&mut worker_file, &request)
	})
	.await
	.context("snapshot directory parser task failed")??;
	if report["record_format"] != "hepta.rea-model-artifact.v1"
		|| report["operation"] != "index_model_artifact"
		|| report["rea_evidence_compatible"] != false
		|| report["source"]["observed_version"].as_str() != Some(version.as_str())
		|| report["source"]["size_bytes"].as_u64() != Some(before.len())
		|| !report["result"]["tensors"].is_array()
		|| !report["result"]["metadata"].is_array()
	{
		bail!("model index worker returned an unbound directory");
	}
	let header_length = report["source"]["header_bytes"]
		.as_u64()
		.filter(|length| *length <= MAX_HEADER_BYTES && *length <= before.len())
		.ok_or_else(|| anyhow!("model index worker returned an invalid header extent"))?;
	let header = hash_prefix(file, header_length).await?;
	if report["source"]["header_sha256"].as_str() != Some(header.as_str()) {
		bail!("snapshot directory does not match its admitted header bytes");
	}
	#[cfg(unix)]
	super::rea_files::ensure_unchanged(&before, &file.metadata().await?)?;
	Ok(report)
}

/// CLI entrypoint for the private single-shot inherited-descriptor worker.
pub fn serve_once(request_json: &str) -> Result<()> {
	worker::serve_once(request_json)
}

#[cfg(test)]
#[path = "rea_model_tests.rs"]
mod rea_model_tests;
