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

//! Durable, immutable-by-protocol native preview records.
//!
//! Records are NOT REA Evidence. This store requires a trusted controller
//! state directory, supports an atomic exclusive publication via hard link,
//! checks full-record SHA-256 and the native preview semantic identifier,
//! and rejects damaged/conflicting records across controller restarts.
//!
//! It does not protect against an attacker controlling the server UID or
//! writing the configured state directory: there is no secret MAC or remote
//! attestation. Filesystem space and disk/IO quotas remain production gates.

use anyhow::{anyhow, bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::rea;
use super::rea_files;
use super::runtime::runtime_config;

const STORE_SCHEMA: &str = "hepta.rea.preview-store.v1";
const RECORD_VERSION: &str = "hepta.rea.preview.v1";
const ID_PREFIX: &str = "hepta_rea_preview_v1_";
const MAX_RECORD_BYTES: usize = 512 * 1024;
const MAX_ENVELOPE_BYTES: u64 = 1024 * 1024;
const MAX_STORED_RECORDS: usize = 2048;
const MAX_STORED_BYTES: u64 = 256 * 1024 * 1024;
static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct RetainPreviewParams {
	/// Absolute local artifact path contained in a configured controller workspace.
	pub path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ReadPreviewParams {
	/// Exact hepta_rea_preview_v1_ content identifier previously returned by retain.
	pub native_evidence_id: String,
}

fn sha256_hex(data: &[u8]) -> String {
	let digest = Sha256::digest(data);
	let mut result = String::with_capacity(64);
	for byte in digest {
		let _ = write!(result, "{byte:02x}");
	}
	result
}

fn id_suffix(id: &str) -> Result<&str> {
	let suffix = id
		.strip_prefix(ID_PREFIX)
		.ok_or_else(|| anyhow!("invalid native preview ID prefix"))?;
	if suffix.len() != 64
		|| !suffix
			.bytes()
			.all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
	{
		bail!("native preview ID must contain exactly 64 lowercase hex digits");
	}
	Ok(suffix)
}

pub(super) fn report_identity(record: &Value) -> Result<String> {
	if record["record_format"] != RECORD_VERSION
		|| record["rea_evidence_compatible"] != false
		|| record["operation"] != "rea_inspect_artifact"
		|| record["coverage"]["scope"] != "selected-file-header"
		|| record["coverage"]["status"] != "partial"
		|| !record["analysis_profile"].is_null()
	{
		bail!("unexpected native preview identity or coverage");
	}
	if record["upstream_reference"]["source_commit"] != rea::REA_SOURCE_COMMIT
		|| record["upstream_reference"]["version"] != rea::REA_VERSION
	{
		bail!("unrecognized native preview source identity");
	}
	let digest = record["subject"]["sha256"]
		.as_str()
		.ok_or_else(|| anyhow!("missing captured source digest"))?;
	if digest.len() != 64
		|| !digest
			.bytes()
			.all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
	{
		bail!("invalid captured source digest");
	}
	if record["subject"]["size_bytes"].as_u64().is_none()
		|| record["subject"]["local_path"].as_str().is_none()
		|| !record["normalized_result"].is_object()
	{
		bail!("incomplete native preview source facts");
	}
	let limitations = record["limitations"]
		.as_array()
		.ok_or_else(|| anyhow!("native preview limitations must be an array"))?;
	if limitations.iter().any(|limitation| !limitation.is_string()) {
		bail!("native preview limitations must contain strings");
	}
	let mut material = format!("{RECORD_VERSION}\0{digest}\0").into_bytes();
	material.extend(serde_json::to_vec(&record["normalized_result"])?);
	let expected = format!("{ID_PREFIX}{}", sha256_hex(&material));
	let provided = record["native_evidence_id"]
		.as_str()
		.ok_or_else(|| anyhow!("missing native preview identifier"))?;
	id_suffix(provided)?;
	if expected != provided {
		bail!("native preview semantic digest mismatch");
	}
	Ok(expected)
}

fn store_dir(state_dir: &Path) -> Result<PathBuf> {
	if !state_dir.is_absolute() {
		bail!("REA preview state_dir must be an absolute trusted controller path");
	}
	Ok(state_dir.join("rea-preview-v1"))
}

/// The controlling state directory is an administrator-owned trust assumption.
/// Reject an existing symlink/loose-permission store root, including after
/// startup. The handler does not accept caller-selected output directories.
fn prepare_root(state_dir: &Path) -> Result<PathBuf> {
	let root = store_dir(state_dir)?;
	std::fs::create_dir_all(state_dir).context("cannot create controller state directory")?;
	// Establish private permissions in the create syscall itself. A separate
	// chmod exposes a transient 0755 directory to simultaneous readers.
	let mut builder = std::fs::DirBuilder::new();
	#[cfg(unix)]
	{
		use std::os::unix::fs::DirBuilderExt;
		builder.mode(0o700);
	}
	match builder.create(&root) {
		Ok(()) => {}
		Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
		Err(error) => return Err(error).context("cannot create REA preview store"),
	}
	validate_root(&root)?;
	Ok(root)
}

fn validate_root(root: &Path) -> Result<()> {
	let metadata = std::fs::symlink_metadata(root).context("REA preview store unavailable")?;
	if !metadata.is_dir() || metadata.file_type().is_symlink() {
		bail!("REA preview store must be a real directory, not a symlink");
	}
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		if metadata.permissions().mode() & 0o077 != 0 {
			bail!("REA preview store must not be accessible to group or others");
		}
	}
	Ok(())
}

/// Retained records are private single-link files. A hard-linked inode can
/// be modified outside the store and defeats file-ownership/quota assumptions.
fn reject_external_hardlinks(metadata: &std::fs::Metadata) -> Result<()> {
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		if metadata.nlink() != 1 {
			bail!("REA preview store refuses externally hard-linked files");
		}
	}
	Ok(())
}

fn filename(root: &Path, id: &str) -> Result<PathBuf> {
	id_suffix(id)?;
	Ok(root.join(format!("{id}.json")))
}

fn make_envelope(record: &Value) -> Result<Vec<u8>> {
	report_identity(record)?;
	let record_bytes = serde_json::to_vec(record)?;
	if record_bytes.len() > MAX_RECORD_BYTES {
		bail!("native preview record exceeds durable record size budget");
	}
	let envelope = json!({
		"store_format": STORE_SCHEMA,
		"record_sha256": sha256_hex(&record_bytes),
		"record": record
	});
	let encoded = serde_json::to_vec(&envelope)?;
	if encoded.len() as u64 > MAX_ENVELOPE_BYTES {
		bail!("native preview durable envelope exceeds 1 MiB");
	}
	Ok(encoded)
}

fn verify_envelope(data: &[u8], requested_id: &str) -> Result<Value> {
	let parsed: Value =
		super::rea_evidence::parse_unique_json(data).context("corrupt native preview envelope")?;
	let map = parsed
		.as_object()
		.ok_or_else(|| anyhow!("native preview envelope must be an object"))?;
	if map.len() != 3
		|| !map.contains_key("store_format")
		|| !map.contains_key("record_sha256")
		|| !map.contains_key("record")
	{
		bail!("unexpected native preview durable envelope members");
	}
	if parsed["store_format"] != STORE_SCHEMA {
		bail!("unsupported native preview store version");
	}
	let record = parsed
		.get("record")
		.ok_or_else(|| anyhow!("native preview store has no record"))?;
	let hash = parsed["record_sha256"]
		.as_str()
		.ok_or_else(|| anyhow!("native preview store has no record digest"))?;
	if hash != sha256_hex(&serde_json::to_vec(record)?) {
		bail!("native preview persisted record is altered");
	}
	let id = report_identity(record)?;
	if requested_id != id {
		bail!("native preview persisted identity differs from the lookup key");
	}
	Ok(record.clone())
}

fn semantic_record_matches(first: &Value, second: &Value) -> Result<bool> {
	let mut left = first.clone();
	let mut right = second.clone();
	if report_identity(&left)? != report_identity(&right)? {
		return Ok(false);
	}
	// The selected source path is display metadata and excluded from the
	// versioned native identifier. Retain the original capture pathname.
	left["subject"]["local_path"] = Value::Null;
	right["subject"]["local_path"] = Value::Null;
	Ok(left == right)
}

struct StagingFile(PathBuf);

impl Drop for StagingFile {
	fn drop(&mut self) {
		let _ = std::fs::remove_file(&self.0);
	}
}

fn publish_exclusive(root: &Path, id: &str, encoded: &[u8]) -> Result<bool> {
	let dest = filename(root, id)?;
	let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
	let nanos = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.context("system clock predates epoch")?
		.as_nanos();
	let tmp = root.join(format!(
		".{:x}-{:x}-{:x}.tmp",
		std::process::id(),
		nanos,
		sequence
	));
	let mut opts = OpenOptions::new();
	opts.write(true).create_new(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		opts.mode(0o600);
	}
	let mut file = opts
		.open(&tmp)
		.context("cannot reserve REA durable staging file")?;
	let cleanup = StagingFile(tmp);
	file.write_all(encoded)
		.context("cannot stage REA preview")?;
	file.sync_all()
		.context("cannot sync REA preview staging file")?;
	drop(file);
	match std::fs::hard_link(&cleanup.0, &dest) {
		Ok(()) => {
			let directory = std::fs::File::open(root)?;
			directory
				.sync_all()
				.context("cannot sync REA preview directory")?;
			Ok(false)
		}
		Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(true),
		Err(error) => Err(error).context("cannot publish immutable REA preview"),
	}
}

/// Count both published records and abandoned temporary bytes. The upper bound
/// is local protection against unbounded *cooperating* MCP retention calls;
/// an external process with the same UID can bypass this policy. Requires the
/// caller to hold the cross-process store directory flock.
fn enforce_quota(
	root: &Path,
	candidate_bytes: u64,
	max_records: usize,
	max_total_bytes: u64,
) -> Result<()> {
	let mut records = 0usize;
	let mut occupied = 0u64;
	for entry in std::fs::read_dir(root).context("cannot enumerate REA preview store")? {
		let entry = entry?;
		let metadata = std::fs::symlink_metadata(entry.path())
			.context("cannot inspect REA preview store member")?;
		if !metadata.is_file() || metadata.file_type().is_symlink() {
			bail!("REA preview store contains an unsafe non-file or symbolic link");
		}
		reject_external_hardlinks(&metadata)?;
		occupied = occupied
			.checked_add(metadata.len())
			.ok_or_else(|| anyhow!("REA preview stored-byte accounting overflow"))?;
		if entry.path().extension().is_some_and(|ext| ext == "json") {
			records += 1;
		}
		if occupied > max_total_bytes {
			bail!("REA preview store exceeds total durable byte budget");
		}
	}
	if records >= max_records {
		bail!("REA preview store exceeds retained record count budget");
	}
	if occupied
		.checked_add(candidate_bytes)
		.is_none_or(|size| size > max_total_bytes)
	{
		bail!("REA preview store exceeds total durable byte budget");
	}
	Ok(())
}

/// Serialize all cooperating writers, including concurrent controller
/// processes sharing one trusted local store, before quota accounting and
/// immutable publication. A preexisting identity can be reused at capacity.
fn publish_budgeted(root: &Path, id: &str, encoded: &[u8]) -> Result<bool> {
	#[cfg(not(unix))]
	{
		let _ = (root, id, encoded);
		bail!("REA preview durable quota locking requires Unix flock");
	}
	#[cfg(unix)]
	{
		use std::os::fd::AsRawFd;
		let dir = std::fs::File::open(root).context("cannot lock REA preview store")?;
		if unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX) } != 0 {
			return Err(std::io::Error::last_os_error())
				.context("cannot acquire exclusive REA preview store quota lock");
		}
		let path = filename(root, id)?;
		match std::fs::symlink_metadata(path) {
			Ok(metadata) => {
				if metadata.is_file() && !metadata.file_type().is_symlink() {
					reject_external_hardlinks(&metadata)?;
					return Ok(true);
				}
				bail!("REA preview store identity resolves to unsafe file type");
			}
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
			Err(error) => return Err(error).context("cannot inspect existing preview identity"),
		}
		enforce_quota(
			root,
			encoded.len() as u64,
			MAX_STORED_RECORDS,
			MAX_STORED_BYTES,
		)?;
		publish_exclusive(root, id, encoded)
	}
}

/// Publish a worker-created partial preview by content identity, or return a
/// verified prior record. Never overwrite an existing ID on conflict.
pub async fn retain_record(record: &Value, state_dir: &Path) -> Result<Value> {
	let id = report_identity(record)?;
	let bytes = make_envelope(record)?;
	let target_state = state_dir.to_path_buf();
	let target_id = id.clone();
	let reused = tokio::task::spawn_blocking(move || {
		let root = prepare_root(&target_state)?;
		publish_budgeted(&root, &target_id, &bytes)
	})
	.await
	.context("REA preview durable publish task failed")??;

	// Every receipt follows a fresh readback, even the original writer.
	// This detects a corrupted existing object instead of silently reusing it.
	let prior = read_record(&id, state_dir).await?;
	if !semantic_record_matches(&prior, record)? {
		bail!("native preview ID collision with different retained provenance");
	}
	Ok(json!({
		"status": "retained",
		"native_evidence_id": id,
		"reused": reused,
		"record_format": RECORD_VERSION,
		"rea_evidence_compatible": false
	}))
}

pub async fn read_record(id: &str, state_dir: &Path) -> Result<Value> {
	let root = store_dir(state_dir)?;
	let path = filename(&root, id)?;
	let root_clone = root.clone();
	tokio::task::spawn_blocking(move || validate_root(&root_clone))
		.await
		.context("REA preview directory validation task failed")??;
	let check = path.clone();
	tokio::task::spawn_blocking(move || {
		let metadata =
			std::fs::symlink_metadata(&check).context("REA preview record unavailable")?;
		if !metadata.is_file() || metadata.file_type().is_symlink() {
			bail!("REA preview record is not a regular file");
		}
		reject_external_hardlinks(&metadata)
	})
	.await
	.context("REA preview hardlink validation task failed")??;
	let bytes = rea_files::read_bounded(&path, &[root], MAX_ENVELOPE_BYTES).await?;
	verify_envelope(&bytes, id)
}

pub async fn retain_preview(params: RetainPreviewParams) -> Result<String> {
	let report = rea::inspect_artifact(rea::InspectArtifactParams { path: params.path }).await?;
	let parsed: Value = serde_json::from_str(&report)?;
	let receipt = retain_record(&parsed, &runtime_config()?.state_dir).await?;
	Ok(serde_json::to_string(&receipt)?)
}

pub async fn read_preview(params: ReadPreviewParams) -> Result<String> {
	let id = params.native_evidence_id;
	let record = read_record(&id, &runtime_config()?.state_dir).await?;
	Ok(serde_json::to_string(&json!({
		"status":"retained",
		"native_evidence_id":id,
		"record":record
	}))?)
}

#[cfg(test)]
#[path = "rea_store_tests.rs"]
mod rea_store_tests;
