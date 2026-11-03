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

//! Root-confined, inherited-descriptor ZIP/APK/JAR index delivery. Directory
//! commitments and optional whole-file hashes have distinct scopes.

use anyhow::{anyhow, bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

#[path = "rea_artifact_zip_parser.rs"]
mod parser;
#[path = "rea_artifact_zip_worker.rs"]
mod worker;

const MAX_DIRECTORY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveFilter {
	#[default]
	All,
	Manifest,
	Dex,
	NativeLibrary,
	Resource,
	JavaClass,
	SignatureMarker,
}

impl ArchiveFilter {
	fn matches(self, role: &str) -> bool {
		match self {
			Self::All => true,
			Self::Manifest => role == "manifest",
			Self::Dex => role == "dex",
			Self::NativeLibrary => role == "native_library",
			Self::Resource => role == "resource",
			Self::JavaClass => role == "java_class",
			Self::SignatureMarker => role == "signature_marker",
		}
	}
}

#[derive(
	Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveHashMode {
	#[default]
	Index,
	Full,
}

fn default_limit() -> usize {
	64
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InspectArchiveParams {
	/// Absolute regular-file path inside configured controller workspace roots.
	pub path: String,
	/// Filter by filename-derived role; no decompression or content validation occurs.
	#[serde(default)]
	pub filter: ArchiveFilter,
	/// Zero-based page offset. Continuations require both expected identity fields.
	#[serde(default)]
	pub offset: usize,
	/// Number of entries, 1..=256; default 64.
	#[serde(default = "default_limit")]
	pub limit: usize,
	/// Index hashes only directory/EOCD bytes; full additionally streams the entire archive.
	#[serde(default)]
	pub hash: ArchiveHashMode,
	/// Exact observed descriptor token from an earlier page, not a content digest.
	pub expected_version: Option<String>,
	/// Central-directory SHA-256 paired with that earlier descriptor token.
	pub expected_directory_sha256: Option<String>,
}

fn hex(bytes: &[u8]) -> String {
	let mut value = String::with_capacity(bytes.len().saturating_mul(2));
	for byte in bytes {
		let _ = write!(value, "{byte:02x}");
	}
	value
}

fn observed_version(meta: &std::fs::Metadata) -> Result<String> {
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		let values = format!(
			"hepta-archive-observation-v1:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
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
		Ok(format!("afv1_{}", hex(&Sha256::digest(values.as_bytes()))))
	}
	#[cfg(not(unix))]
	{
		let _ = meta;
		bail!("archive observation requires Unix descriptor metadata")
	}
}

async fn hash_range(file: &mut tokio::fs::File, offset: u64, length: u64) -> Result<String> {
	file.seek(std::io::SeekFrom::Start(offset)).await?;
	let mut remaining = length;
	let mut buffer = [0_u8; 64 * 1024];
	let mut hash = Sha256::new();
	while remaining > 0 {
		let size = usize::try_from(remaining.min(buffer.len() as u64))?;
		file.read_exact(&mut buffer[..size])
			.await
			.context("archive changed or ended during hashing")?;
		hash.update(&buffer[..size]);
		remaining -= size as u64;
	}
	Ok(hex(&hash.finalize()))
}

fn validate_params(params: &InspectArchiveParams) -> Result<()> {
	if !(1..=256).contains(&params.limit) {
		bail!("archive page limit must be between 1 and 256");
	}
	if params.expected_version.is_some() != params.expected_directory_sha256.is_some()
		|| (params.offset > 0 && params.expected_version.is_none())
	{
		bail!("archive continuation requires both expected_version and expected_directory_sha256");
	}
	for (label, value) in [
		(
			"expected_version",
			params
				.expected_version
				.as_deref()
				.map(|value| value.strip_prefix("afv1_").unwrap_or("")),
		),
		(
			"expected_directory_sha256",
			params.expected_directory_sha256.as_deref(),
		),
	] {
		if value.is_some_and(|value| {
			value.len() != 64
				|| !value
					.bytes()
					.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
		}) {
			bail!("invalid archive {label} identity");
		}
	}
	Ok(())
}

async fn inspect_with_roots(params: InspectArchiveParams, roots: &[PathBuf]) -> Result<Value> {
	validate_params(&params)?;
	static SLOTS: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
	let _slot = SLOTS
		.get_or_init(|| tokio::sync::Semaphore::new(2))
		.acquire()
		.await
		.context("archive parser admission closed")?;
	let (mut file, before) =
		super::rea_files::open_confined(Path::new(&params.path), roots).await?;
	let version = observed_version(&before)?;
	if params
		.expected_version
		.as_deref()
		.is_some_and(|expected| expected != version)
	{
		bail!("archive descriptor changed; obtain a fresh first page");
	}
	let request = parser::Request {
		filter: params.filter,
		offset: params.offset,
		limit: params.limit,
	};
	let worker_file = file.try_clone().await?.into_std().await;
	#[cfg(not(test))]
	let mut report = worker::inspect_isolated(worker_file, &request).await?;
	#[cfg(test)]
	let mut report = tokio::task::spawn_blocking(move || {
		let mut worker_file = worker_file;
		parser::inspect_file(&mut worker_file, &request)
	})
	.await
	.context("archive parser test task failed")??;
	let source = &report["source"];
	if report["record_format"] != "hepta.rea-archive-index.v1"
		|| report["operation"] != "inspect_archive"
		|| source["observed_version"].as_str() != Some(version.as_str())
		|| source["size_bytes"].as_u64() != Some(before.len())
		|| report["result"]["offset"].as_u64() != Some(params.offset as u64)
		|| report["result"]["limit"].as_u64() != Some(params.limit as u64)
		|| report["result"]["filter"] != serde_json::to_value(params.filter)?
	{
		bail!("archive worker result differs from admitted source or requested page");
	}
	let mut directory_digest = String::new();
	for (offset_key, size_key, digest_key, max_size) in [
		(
			"central_directory_offset",
			"central_directory_bytes",
			"central_directory_sha256",
			MAX_DIRECTORY_BYTES,
		),
		("eocd_offset", "eocd_bytes", "eocd_sha256", 22 + 65_535),
	] {
		let offset = source[offset_key]
			.as_u64()
			.ok_or_else(|| anyhow!("archive worker omitted {offset_key}"))?;
		let length = source[size_key]
			.as_u64()
			.ok_or_else(|| anyhow!("archive worker omitted {size_key}"))?;
		if length > max_size || offset > before.len() || length > before.len() - offset {
			bail!("archive worker returned invalid structural extent");
		}
		let actual = hash_range(&mut file, offset, length).await?;
		if source[digest_key].as_str() != Some(actual.as_str()) {
			bail!("archive index commitment differs from admitted source bytes");
		}
		if digest_key == "central_directory_sha256" {
			directory_digest = actual;
		}
	}
	if params
		.expected_directory_sha256
		.as_deref()
		.is_some_and(|expected| expected != directory_digest)
	{
		bail!("archive directory digest changed; requested page is stale");
	}
	let full_hash = if params.hash == ArchiveHashMode::Full {
		Some(
			tokio::time::timeout(
				std::time::Duration::from_secs(300),
				hash_range(&mut file, 0, before.len()),
			)
			.await
			.context("archive full-file hash exceeded 300 second deadline")??,
		)
	} else {
		None
	};
	let after = file.metadata().await?;
	#[cfg(unix)]
	super::rea_files::ensure_unchanged(&before, &after)?;
	if observed_version(&after)? != version {
		bail!("archive descriptor changed during inspection");
	}
	let source = report["source"]
		.as_object_mut()
		.ok_or_else(|| anyhow!("invalid archive source"))?;
	source.insert("local_path".to_string(), json!(params.path));
	source.insert("full_sha256".to_string(), json!(full_hash));
	source.insert(
		"identity_scope".to_string(),
		json!(if full_hash.is_some() {
			"full_file"
		} else {
			"directory_and_descriptor_observation"
		}),
	);
	report["limitations"].as_array_mut().ok_or_else(|| anyhow!("invalid archive limitations"))?
		.push(json!("Directory SHA-256 does not bind payload contents. Descriptor metadata detects ordinary modification, not privileged races that defeat those observations. Full-file hashing still does not verify decompressed member CRCs or signatures."));
	Ok(report)
}

pub async fn inspect_archive(params: InspectArchiveParams) -> Result<String> {
	validate_params(&params)?;
	let roots = &super::runtime::runtime_config()?.controller_workspace_roots;
	let report = inspect_with_roots(params, roots).await?;
	let encoded = serde_json::to_string(&report)?;
	if encoded.len() > MAX_RESPONSE_BYTES {
		bail!("archive response exceeds 1 MiB; reduce page size");
	}
	Ok(encoded)
}

pub fn serve_once(request_json: &str) -> Result<()> {
	worker::serve_once(request_json)
}

#[cfg(test)]
#[path = "rea_artifact_zip_tests.rs"]
mod rea_artifact_zip_tests;

/// Reuse the checked ZIP directory on the already admitted application descriptor.
pub(crate) fn inspect_application_directory(
	file: &mut std::fs::File,
) -> anyhow::Result<serde_json::Value> {
	parser::inspect_file(
		file,
		&parser::Request {
			filter: ArchiveFilter::Manifest,
			offset: 0,
			limit: 256,
		},
	)
}
