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

//! Durable model snapshot sessions. Initial capture verifies the full source;
//! later pages use committed indexes and ranges verify only touched chunks.
//! Authorization is supplied by the server's authenticated owner, never an MCP
//! argument. No process-local cache or original pathname is needed for recovery.

use anyhow::{anyhow, bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use super::{Collection, MAX_READ_BYTES};
use crate::mcp::{rea_evidence, rea_files, runtime};

#[path = "rea_model_session_index.rs"]
mod index;
#[path = "rea_model_session_store.rs"]
mod store;

const SCHEMA: &str = "hepta.rea.model-session.v1";
const PARSER_SCHEMA: &str = "hepta.rea.model-directory-index.v1";
const ID_PREFIX: &str = "rms1_";
const CHUNK_BYTES: usize = 1024 * 1024;
const PAGE_ROWS: usize = 64;
const MAX_SNAPSHOT_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const MAX_STORE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_SESSION_COUNT: usize = 32;
const MAX_INDEX_BYTES: usize = 128 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenModelSessionParams {
	/// Absolute source beneath admitted controller roots; runtime state paths are refused.
	pub path: String,
	/// Complete lowercase SHA-256 of the exact source to capture, not a header digest.
	pub expected_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryModelSessionParams {
	/// Session ID returned by open under this authenticated owner and runtime policy.
	pub session_id: String,
	/// Tensors, metadata, or summary including retained snapshot capabilities.
	#[serde(default)]
	pub collection: Collection,
	#[serde(default)]
	pub offset: usize,
	/// Rows to return, 1..=256. Pages are restored without reparsing the model.
	#[serde(default = "super::default_page_limit")]
	pub limit: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadModelSessionParams {
	/// Session ID returned by open under this authenticated owner and runtime policy.
	pub session_id: String,
	/// Exact tensor name, or omit for an absolute range in the retained snapshot.
	pub tensor_name: Option<String>,
	#[serde(default)]
	pub offset: u64,
	/// 1..=65536 bytes. Only touched 1 MiB chunks are reverified on this read.
	pub length: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PagePin {
	sha256: String,
	byte_length: usize,
	rows: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
	schema: String,
	parser_schema: String,
	owner_sha256: String,
	policy_sha256: String,
	source_path: String,
	source_sha256: String,
	byte_length: u64,
	chunk_bytes: usize,
	chunk_sha256: Vec<String>,
	summary: Value,
	tensor_count: usize,
	metadata_count: usize,
	tensor_pages: Vec<PagePin>,
	metadata_pages: Vec<PagePin>,
	tensor_names: Vec<Option<PagePin>>,
}

struct Scope {
	state: PathBuf,
	roots: Vec<PathBuf>,
	owner_sha256: String,
	policy_sha256: String,
}

impl Scope {
	fn current(owner: &str) -> Result<Self> {
		if owner.is_empty() || owner.len() > 4096 {
			bail!("authenticated runtime owner is unavailable");
		}
		let config = runtime::runtime_config()?;
		Ok(Self {
			state: config.state_dir.clone(),
			roots: config.controller_workspace_roots.clone(),
			owner_sha256: hash(format!("{SCHEMA}\0owner\0{owner}").as_bytes()),
			policy_sha256: runtime::request_results::policy_binding()?,
		})
	}

	fn source_allowed(&self, path: &Path) -> Result<()> {
		if !path.is_absolute()
			|| path
				.components()
				.any(|part| matches!(part, Component::ParentDir))
			|| path.starts_with(&self.state)
			|| !self
				.roots
				.iter()
				.any(|root| path.starts_with(root) && path != root)
		{
			bail!("model snapshot source is outside current roots or belongs to runtime state");
		}
		Ok(())
	}
}

fn hash(bytes: &[u8]) -> String {
	super::digest_hex(&Sha256::digest(bytes))
}

fn validate_id(id: &str) -> Result<()> {
	let suffix = id
		.strip_prefix(ID_PREFIX)
		.ok_or_else(|| anyhow!("invalid model session ID"))?;
	super::validate_digest(suffix, "model session ID")
}

fn identity(manifest: &Manifest) -> Result<String> {
	Ok(format!(
		"{ID_PREFIX}{}",
		hash(&serde_json::to_vec(manifest)?)
	))
}

fn validate_manifest(manifest: &Manifest, id: &str, scope: &Scope) -> Result<()> {
	if manifest.schema != SCHEMA
		|| manifest.parser_schema != PARSER_SCHEMA
		|| manifest.owner_sha256 != scope.owner_sha256
		|| manifest.policy_sha256 != scope.policy_sha256
		|| identity(manifest)? != id
	{
		bail!("model session does not match its owner, current policy, schema or identity");
	}
	scope.source_allowed(Path::new(&manifest.source_path))?;
	super::validate_digest(&manifest.source_sha256, "snapshot SHA-256")?;
	if manifest.byte_length == 0
		|| manifest.byte_length > MAX_SNAPSHOT_BYTES
		|| manifest.chunk_bytes != CHUNK_BYTES
		|| manifest.chunk_sha256.len() != manifest.byte_length.div_ceil(CHUNK_BYTES as u64) as usize
		|| manifest.tensor_count > 100_000
		|| manifest.metadata_count > 100_000
		|| manifest.tensor_names.len() != 256
	{
		bail!("model session manifest exceeds its structural budgets");
	}
	for digest in &manifest.chunk_sha256 {
		super::validate_digest(digest, "snapshot chunk SHA-256")?;
	}
	for (count, pages) in [
		(manifest.tensor_count, &manifest.tensor_pages),
		(manifest.metadata_count, &manifest.metadata_pages),
	] {
		if pages.len() != count.div_ceil(PAGE_ROWS) {
			bail!("model session index page count is inconsistent");
		}
		for (number, pin) in pages.iter().enumerate() {
			if pin.rows != (count - number * PAGE_ROWS).min(PAGE_ROWS)
				|| pin.byte_length > 2 * 1024 * 1024
			{
				bail!("model session index page is outside its budget");
			}
			super::validate_digest(&pin.sha256, "index page SHA-256")?;
		}
	}
	for pin in manifest.tensor_names.iter().flatten() {
		if pin.rows == 0 || pin.rows > manifest.tensor_count || pin.byte_length > 8 * 1024 * 1024 {
			bail!("model session name index is outside its budget");
		}
		super::validate_digest(&pin.sha256, "name index SHA-256")?;
	}
	if manifest.summary["source"]["full_sha256"].as_str() != Some(manifest.source_sha256.as_str())
		|| manifest.summary["source"]["size_bytes"].as_u64() != Some(manifest.byte_length)
		|| manifest.summary["tensor_count"].as_u64() != Some(manifest.tensor_count as u64)
		|| manifest.summary["metadata_count"].as_u64() != Some(manifest.metadata_count as u64)
		|| manifest.summary["rea_evidence_compatible"] != false
	{
		bail!("model session summary does not match its retained content");
	}
	Ok(())
}

async fn load(scope: &Scope, id: &str) -> Result<(PathBuf, Manifest)> {
	validate_id(id)?;
	let root = store::root(&scope.state, false).await?;
	let directory = root.join(id);
	store::require_directory(&directory).await?;
	let bytes = store::read_private(
		&directory.join("manifest.json"),
		&directory,
		MAX_MANIFEST_BYTES as u64,
	)
	.await?;
	let value = rea_evidence::parse_unique_json(&bytes)?;
	let manifest: Manifest =
		serde_json::from_value(value).context("invalid model session manifest")?;
	validate_manifest(&manifest, id, scope)?;
	Ok((directory, manifest))
}

async fn capture(
	source: &mut tokio::fs::File,
	before: &std::fs::Metadata,
	target: &Path,
	expected: &str,
) -> Result<Vec<String>> {
	let mut output = store::create_private(target).await?;
	let mut buffer = vec![0_u8; CHUNK_BYTES];
	let mut complete = Sha256::new();
	let mut chunks = Vec::new();
	let mut remaining = before.len();
	while remaining > 0 {
		let length = usize::try_from(remaining.min(CHUNK_BYTES as u64))?;
		source
			.read_exact(&mut buffer[..length])
			.await
			.context("model source truncated during capture")?;
		complete.update(&buffer[..length]);
		chunks.push(hash(&buffer[..length]));
		output.write_all(&buffer[..length]).await?;
		remaining -= length as u64;
	}
	if super::digest_hex(&complete.finalize()) != expected {
		bail!("model source does not match its required complete SHA-256");
	}
	#[cfg(unix)]
	rea_files::ensure_unchanged(before, &source.metadata().await?)?;
	output.sync_all().await?;
	Ok(chunks)
}

async fn snapshot_file(directory: &Path, manifest: &Manifest) -> Result<tokio::fs::File> {
	let (file, metadata) =
		rea_files::open_confined(&directory.join("snapshot.bin"), &[directory.to_owned()]).await?;
	store::require_file(&metadata)?;
	if metadata.len() != manifest.byte_length {
		bail!("retained model snapshot size differs from its manifest");
	}
	Ok(file)
}

async fn chunk(
	file: &mut tokio::fs::File,
	manifest: &Manifest,
	number: usize,
	buffer: &mut [u8],
) -> Result<usize> {
	let offset = (number as u64)
		.checked_mul(CHUNK_BYTES as u64)
		.filter(|offset| *offset < manifest.byte_length)
		.ok_or_else(|| anyhow!("snapshot chunk number is outside the file"))?;
	let length = usize::try_from((manifest.byte_length - offset).min(CHUNK_BYTES as u64))?;
	file.seek(std::io::SeekFrom::Start(offset)).await?;
	file.read_exact(&mut buffer[..length]).await?;
	let expected = manifest
		.chunk_sha256
		.get(number)
		.ok_or_else(|| anyhow!("snapshot chunk has no commitment"))?;
	if hash(&buffer[..length]) != *expected {
		bail!("retained model snapshot chunk differs from its committed content");
	}
	Ok(length)
}

async fn verify_snapshot(directory: &Path, manifest: &Manifest) -> Result<()> {
	let mut file = snapshot_file(directory, manifest).await?;
	let before = file.metadata().await?;
	let mut buffer = vec![0_u8; CHUNK_BYTES];
	for number in 0..manifest.chunk_sha256.len() {
		chunk(&mut file, manifest, number, &mut buffer).await?;
	}
	#[cfg(unix)]
	rea_files::ensure_unchanged(&before, &file.metadata().await?)?;
	Ok(())
}

async fn build<G: Send + 'static>(
	scope: &Scope,
	params: &OpenModelSessionParams,
	source: &mut tokio::fs::File,
	before: &std::fs::Metadata,
	stage: &Path,
	root: &Path,
	guards: store::PublishGuards<G>,
) -> Result<Value> {
	let chunks = capture(
		source,
		before,
		&stage.join("snapshot.bin"),
		&params.expected_sha256,
	)
	.await?;
	let (mut snapshot, snapshot_metadata) =
		rea_files::open_confined(&stage.join("snapshot.bin"), &[stage.to_owned()]).await?;
	store::require_file(&snapshot_metadata)?;
	let report = super::inspect_snapshot_directory(&mut snapshot).await?;
	let index = index::build(stage, report, &params.expected_sha256).await?;
	let manifest = Manifest {
		schema: SCHEMA.into(),
		parser_schema: PARSER_SCHEMA.into(),
		owner_sha256: scope.owner_sha256.clone(),
		policy_sha256: scope.policy_sha256.clone(),
		source_path: params.path.clone(),
		source_sha256: params.expected_sha256.clone(),
		byte_length: before.len(),
		chunk_bytes: CHUNK_BYTES,
		chunk_sha256: chunks,
		summary: index.summary,
		tensor_count: index.tensor_count,
		metadata_count: index.metadata_count,
		tensor_pages: index.tensor_pages,
		metadata_pages: index.metadata_pages,
		tensor_names: index.tensor_names,
	};
	let bytes = serde_json::to_vec(&manifest)?;
	if bytes.len() > MAX_MANIFEST_BYTES
		|| bytes
			.len()
			.checked_add(index.stored_bytes)
			.is_none_or(|size| size > MAX_INDEX_BYTES)
	{
		bail!("model session manifest or retained index exceeds its byte budget");
	}
	let id = identity(&manifest)?;
	validate_manifest(&manifest, &id, scope)?;
	store::write_private(&stage.join("manifest.json"), &bytes).await?;
	tokio::fs::File::open(stage).await?.sync_all().await?;
	let reused = store::publish(stage, &root.join(&id), guards).await?;
	let (saved_directory, saved) = load(scope, &id).await?;
	if reused {
		index::verify_all(&saved_directory, &saved).await?;
		verify_snapshot(&saved_directory, &saved).await?;
	}
	Ok(open_receipt(&saved, &id, reused, 1))
}

fn open_receipt(manifest: &Manifest, id: &str, reused: bool, parses: usize) -> Value {
	json!({
		"record_format":"hepta.rea.model-session-open.v1","session_id":id,"reused":reused,
		"source_path":manifest.source_path,"snapshot_sha256":manifest.source_sha256,
		"byte_length":manifest.byte_length,"tensor_count":manifest.tensor_count,"metadata_count":manifest.metadata_count,
		"snapshot":true,"source_modified":false,"rea_evidence_compatible":false,
		"recovery":"retained snapshot and index; original source not required",
		"authorization":"same authenticated runtime owner and exact current policy",
		"directory_parses_this_open":parses,"full_source_hash_passes_this_open":1,
		"queries_reparse_model":false,"ranges_verify":"touched chunks against retained manifest",
		"capabilities":capabilities()
	})
}

// Reconciliation is bounded by the session count and happens only on open.
// It allows a repeated request to recover its ID even when no new reservation
// fits. Neither the caller's current source nor retained data are trusted by
// metadata: both are verified before a successful reuse receipt.
async fn reusable(
	scope: &Scope,
	root: &Path,
	params: &OpenModelSessionParams,
) -> Result<Option<(String, PathBuf, Manifest)>> {
	let mut entries = tokio::fs::read_dir(root).await?;
	let mut count = 0usize;
	while let Some(entry) = entries.next_entry().await? {
		count += 1;
		if count > MAX_SESSION_COUNT {
			bail!("model session store has exceeded its directory budget");
		}
		let name = entry.file_name();
		let name = name
			.to_str()
			.ok_or_else(|| anyhow!("model session store name is not UTF-8"))?;
		if name.starts_with(".stage-") {
			continue;
		}
		validate_id(name)?;
		let directory = entry.path();
		store::require_directory(&directory).await?;
		let bytes = store::read_private(
			&directory.join("manifest.json"),
			&directory,
			MAX_MANIFEST_BYTES as u64,
		)
		.await?;
		let manifest: Manifest = serde_json::from_value(rea_evidence::parse_unique_json(&bytes)?)?;
		if identity(&manifest)? != name {
			bail!("model session store contains a damaged manifest identity");
		}
		if manifest.schema == SCHEMA
			&& manifest.parser_schema == PARSER_SCHEMA
			&& manifest.owner_sha256 == scope.owner_sha256
			&& manifest.policy_sha256 == scope.policy_sha256
			&& manifest.source_path == params.path
			&& manifest.source_sha256 == params.expected_sha256
		{
			validate_manifest(&manifest, name, scope)?;
			return Ok(Some((name.to_owned(), directory, manifest)));
		}
	}
	Ok(None)
}

async fn open_with_admission<G: Send + 'static>(
	scope: &Scope,
	params: &OpenModelSessionParams,
	owner_admission: G,
) -> Result<Value> {
	if !cfg!(target_os = "linux") {
		bail!("atomic retained model snapshots are currently qualified on Linux only");
	}
	super::validate_digest(&params.expected_sha256, "expected_sha256")?;
	scope.source_allowed(Path::new(&params.path))?;
	let (mut source, before) =
		rea_files::open_confined(Path::new(&params.path), &scope.roots).await?;
	if before.len() == 0 || before.len() > MAX_SNAPSHOT_BYTES {
		bail!("model snapshot must contain 1 byte through 32 GiB");
	}
	let root = store::root(&scope.state, true).await?;
	let store_lock = store::lock(&root).await?;
	if let Some((id, directory, manifest)) = reusable(scope, &root, params).await? {
		if before.len() != manifest.byte_length
			|| super::hash_prefix(&mut source, before.len()).await? != params.expected_sha256
		{
			bail!("current model source does not match the reusable snapshot SHA-256");
		}
		#[cfg(unix)]
		rea_files::ensure_unchanged(&before, &source.metadata().await?)?;
		index::verify_all(&directory, &manifest).await?;
		verify_snapshot(&directory, &manifest).await?;
		store::confirm_existing(store::PublishGuards::new(store_lock, owner_admission)).await?;
		return Ok(open_receipt(&manifest, &id, true, 0));
	}
	store::admit_quota(&root, before.len() + MAX_INDEX_BYTES as u64).await?;
	let stage = store::staging(&root).await?;
	let guards = store::PublishGuards::new(store_lock, owner_admission);
	let result = build(scope, params, &mut source, &before, &stage, &root, guards).await;
	let cleanup = store::remove_staging(&stage).await;
	match (result, cleanup) {
		(Ok(value), Ok(())) => Ok(value),
		(Err(error), _) | (Ok(_), Err(error)) => Err(error),
	}
}

fn capabilities() -> Value {
	json!({
		"snapshot_max_bytes":MAX_SNAPSHOT_BYTES,"store_max_bytes":MAX_STORE_BYTES,
		"store_max_sessions":MAX_SESSION_COUNT,"chunk_bytes":CHUNK_BYTES,
		"page_rows":PAGE_ROWS,"query_max_rows":256,"read_max_bytes":MAX_READ_BYTES,
		"snapshot_source_is_live":false,"model_execution":false,"automatic_eviction":false,
		"retained_index_format":PARSER_SCHEMA,
		"trust_scope":"administrator-owned private state; hashes are not remote attestation",
		"snapshot_publication_platform":"linux"
	})
}

fn encode(mut value: Value) -> Result<String> {
	let commitment = hash(&serde_json::to_vec(&value)?);
	value["result_sha256"] = json!(commitment);
	super::encode_report(&value)
}

// Enumerate only retained manifests belonging to the current authenticated
// owner and exact policy. Payload contents are verified by page/range access;
// discovery neither reparses the source nor reads or hashes snapshot payloads.
async fn list_at(scope: &Scope) -> Result<String> {
	let root = match store::root(&scope.state, false).await {
		Ok(root) => Some(root),
		Err(error)
			if error
				.downcast_ref::<std::io::Error>()
				.is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
		{
			None
		}
		Err(error) => return Err(error.context("model session store is unavailable")),
	};
	let mut sessions = Vec::new();
	if let Some(root) = root {
		let mut entries = tokio::fs::read_dir(root).await?;
		let mut count = 0usize;
		while let Some(entry) = entries.next_entry().await? {
			count += 1;
			if count > MAX_SESSION_COUNT {
				bail!("model session store has exceeded its directory budget");
			}
			let name = entry.file_name();
			let name = name
				.to_str()
				.ok_or_else(|| anyhow!("model session store contains an unrecognized entry"))?;
			if name.starts_with(".stage-") {
				continue;
			}
			validate_id(name)
				.map_err(|_| anyhow!("model session store contains an unrecognized entry"))?;
			let directory = entry.path();
			store::require_directory(&directory).await.map_err(|_| {
				anyhow!("model session store contains an unavailable or non-private directory")
			})?;
			let bytes = store::read_private(
				&directory.join("manifest.json"),
				&directory,
				MAX_MANIFEST_BYTES as u64,
			)
			.await
			.map_err(|_| {
				anyhow!("model session store contains an unavailable or invalid private manifest")
			})?;
			let value = rea_evidence::parse_unique_json(&bytes)
				.map_err(|_| anyhow!("model session store contains a damaged manifest"))?;
			let manifest: Manifest = serde_json::from_value(value)
				.map_err(|_| anyhow!("model session store contains a damaged manifest"))?;
			if identity(&manifest)? != name {
				bail!("model session store contains a damaged manifest identity");
			}
			if manifest.schema != SCHEMA || manifest.parser_schema != PARSER_SCHEMA {
				bail!("model session store contains a manifest with an unsupported schema");
			}
			// Do not disclose IDs, paths, hashes, sizes, or even an excluded
			// session count for another owner or a former policy.
			if manifest.owner_sha256 != scope.owner_sha256
				|| manifest.policy_sha256 != scope.policy_sha256
			{
				continue;
			}
			validate_manifest(&manifest, name, scope)?;
			let _snapshot = snapshot_file(&directory, &manifest).await.context(
				"a listed model session snapshot is unavailable or structurally invalid",
			)?;
			sessions.push(json!({
				"session_id":name,
				"source_path":manifest.source_path,
				"snapshot_sha256":manifest.source_sha256,
				"format":manifest.summary["format"],
				"format_version":manifest.summary["format_version"],
				"byte_length":manifest.byte_length,
				"tensor_count":manifest.tensor_count,
				"metadata_count":manifest.metadata_count,
				"retention":"captured_snapshot_and_directory",
				"source_required":false,
				"manifest_verified":true,
				"snapshot_structure_verified":true,
				"index_pages_and_payload_chunks":"verified_on_access"
			}));
		}
	}
	sessions.sort_by(|left, right| {
		left["session_id"]
			.as_str()
			.cmp(&right["session_id"].as_str())
	});
	encode(json!({
		"record_format":"hepta.rea.model-session-list.v1",
		"sessions":sessions,
		"authorization":"same authenticated runtime owner and exact current policy",
		"snapshot_payload_bytes_read":0,
		"source_bytes_read":0,
		"directory_parse_count":0,
		"retention":"published private snapshots; incomplete staging is not a recoverable session",
		"verification":"manifest identity and snapshot structure; index pages and payload chunks checked on access"
	}))
}

async fn query_at(scope: &Scope, params: QueryModelSessionParams) -> Result<String> {
	if !(1..=256).contains(&params.limit) {
		bail!("model session query limit must be between 1 and 256");
	}
	let (directory, manifest) = load(scope, &params.session_id).await?;
	let (result, pages) = index::query(
		&directory,
		&manifest,
		params.collection,
		params.offset,
		params.limit,
	)
	.await?;
	encode(json!({
		"record_format":"hepta.rea.model-session-query.v1","session_id":params.session_id,
		"snapshot_sha256":manifest.source_sha256,"source_path":manifest.source_path,
		"snapshot":true,"result":result,"index_pages_read":pages,
		"snapshot_payload_bytes_read":0,"directory_parse_count":0,
		"verification":"manifest identity and selected index page hashes",
		"rea_evidence_compatible":false,"capabilities":capabilities()
	}))
}

async fn read_at(scope: &Scope, params: ReadModelSessionParams) -> Result<String> {
	if !(1..=MAX_READ_BYTES).contains(&params.length) {
		bail!("model session read length must be between 1 and 65536");
	}
	let (directory, manifest) = load(scope, &params.session_id).await?;
	let tensor = if let Some(name) = params.tensor_name.as_deref() {
		index::tensor(&directory, &manifest, name).await?
	} else {
		Value::Null
	};
	let (base, extent) = if tensor.is_null() {
		(0, manifest.byte_length)
	} else {
		if tensor["storage_length_verified"] != true {
			bail!("tensor-scoped reads require a verified storage layout");
		}
		let base = tensor["file_offset"]
			.as_u64()
			.ok_or_else(|| anyhow!("tensor has no offset"))?;
		let extent = tensor["byte_length"]
			.as_u64()
			.ok_or_else(|| anyhow!("tensor storage layout is unknown"))?;
		if base > manifest.byte_length || extent > manifest.byte_length - base {
			bail!("cached tensor extent exceeds its snapshot");
		}
		(base, extent)
	};
	if params.offset > extent || params.length as u64 > extent - params.offset {
		bail!("model session range crosses its file or tensor boundary");
	}
	let start = base
		.checked_add(params.offset)
		.ok_or_else(|| anyhow!("snapshot range overflow"))?;
	let end = start
		.checked_add(params.length as u64)
		.ok_or_else(|| anyhow!("snapshot range overflow"))?;
	let first = (start / CHUNK_BYTES as u64) as usize;
	let last = ((end - 1) / CHUNK_BYTES as u64) as usize;
	let mut file = snapshot_file(&directory, &manifest).await?;
	let before = file.metadata().await?;
	let mut buffer = vec![0_u8; CHUNK_BYTES];
	let mut bytes = Vec::with_capacity(params.length);
	let mut verified_bytes = 0usize;
	for number in first..=last {
		let length = chunk(&mut file, &manifest, number, &mut buffer).await?;
		verified_bytes += length;
		let chunk_start = number as u64 * CHUNK_BYTES as u64;
		let low = start.saturating_sub(chunk_start) as usize;
		let high = usize::try_from((end - chunk_start).min(length as u64))?;
		bytes.extend_from_slice(&buffer[low..high]);
	}
	#[cfg(unix)]
	rea_files::ensure_unchanged(&before, &file.metadata().await?)?;
	if bytes.len() != params.length {
		bail!("verified snapshot chunks did not cover the requested range");
	}
	encode(json!({
		"record_format":"hepta.rea.model-session-read.v1","session_id":params.session_id,
		"snapshot_sha256":manifest.source_sha256,"snapshot":true,"tensor":tensor,
		"file_offset":start,"offset":params.offset,"length":params.length,
		"encoding":"hex","bytes_hex":super::digest_hex(&bytes),"sha256":hash(&bytes),
		"verified_chunk_indices":(first..=last).collect::<Vec<_>>(),
		"snapshot_payload_bytes_read":verified_bytes,"directory_parse_count":0,
		"verification":"only touched chunks, against their manifest-bound hashes",
		"complete_snapshot_rehashed_this_read":false,"rea_evidence_compatible":false
	}))
}

/// The server resolves owner from authenticated request context. Its actual
/// admission permit is retained by the blocking final commit through parent
/// fsync, even if this future is cancelled. Timeout is an unconfirmed outcome;
/// repeating the identical path/hash request reconciles any committed session.
pub async fn open(
	params: OpenModelSessionParams,
	owner: &str,
	admission: std::sync::Arc<crate::mcp::runtime::effect_owner_fence::AdmissionPermit>,
) -> Result<String> {
	let scope = Scope::current(owner)?;
	let value = tokio::time::timeout(
		Duration::from_secs(300),
		open_with_admission(&scope, &params, admission),
	)
	.await
	.context("model snapshot capture exceeded 300 seconds; commit outcome is unconfirmed; retry the identical path and SHA-256 to reconcile")??;
	encode(value)
}

/// Discover retained session IDs after restart without requiring the original
/// source. Only the resolved owner and exact current policy are visible.
pub async fn list(owner: &str) -> Result<String> {
	let scope = Scope::current(owner)?;
	tokio::time::timeout(Duration::from_secs(60), list_at(&scope))
		.await
		.context("model session listing exceeded 60 seconds; store contents are unconfirmed")?
}

/// Query the retained directory. Summary returns capabilities and provenance.
pub async fn query(params: QueryModelSessionParams, owner: &str) -> Result<String> {
	let scope = Scope::current(owner)?;
	tokio::time::timeout(Duration::from_secs(60), query_at(&scope, params))
		.await
		.context("model session query exceeded 60 seconds")?
}

/// Read a verified range of the captured snapshot, independent of source edits.
pub async fn read(params: ReadModelSessionParams, owner: &str) -> Result<String> {
	let scope = Scope::current(owner)?;
	tokio::time::timeout(Duration::from_secs(60), read_at(&scope, params))
		.await
		.context("model session read exceeded 60 seconds")?
}

#[cfg(all(test, target_os = "linux"))]
#[path = "rea_model_session_tests.rs"]
mod rea_model_session_tests;
