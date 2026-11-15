// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Immutable native weight artifacts beneath the existing controller state root.
//! A model and its exact reverse patch are published as one directory transition.

use anyhow::{anyhow, bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use super::weight_tensor::{self, ExactElementEdit, PatchTensorParams, TensorPatch};

const MAX_MODEL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_STORE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 512 * 1024;
const MAX_ARTIFACTS: usize = 128;
static STAGE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RestoreParams {
	/// Exact native artifact ID. Restore creates a new artifact; it overwrites nothing.
	pub artifact_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
	schema: String,
	artifact_id: String,
	kind: String,
	source_path: String,
	source_sha256: String,
	target_sha256: String,
	patch: TensorPatch,
	parent_artifact_id: Option<String>,
	changed_bytes: u64,
	no_op: bool,
}

fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unchanged(before: &std::fs::Metadata, after: &std::fs::Metadata) -> Result<()> {
	#[cfg(unix)]
	{
		super::rea_files::ensure_unchanged(before, after)
	}
	#[cfg(not(unix))]
	{
		let _ = (before, after);
		bail!("native artifact identity checks require Unix")
	}
}

fn id_for(manifest: &Manifest) -> Result<String> {
	let mut identity = serde_json::to_value(manifest)?;
	identity
		.as_object_mut()
		.ok_or_else(|| anyhow!("manifest must be an object"))?
		.remove("artifact_id");
	Ok(format!(
		"wa1_{}",
		hex(&Sha256::digest(serde_json::to_vec(&identity)?))
	))
}

fn check_id(id: &str) -> Result<()> {
	if !id
		.strip_prefix("wa1_")
		.is_some_and(super::weight_config::valid_sha256)
	{
		bail!("invalid native weight artifact identity");
	}
	Ok(())
}

async fn store_root(state: &Path) -> Result<PathBuf> {
	if !state.is_absolute() {
		bail!("weight artifact state root must be administrator-configured and absolute");
	}
	tokio::fs::create_dir_all(state).await?;
	let root = state.join("weight-artifacts-v1");
	private_directory(&root).await?;
	tokio::fs::File::open(state).await?.sync_all().await?;
	Ok(root)
}

async fn private_directory(path: &Path) -> Result<()> {
	let mut builder = tokio::fs::DirBuilder::new();
	#[cfg(unix)]
	builder.mode(0o700);
	match builder.create(path).await {
		Ok(()) => {}
		Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
		Err(error) => return Err(error.into()),
	}
	verify_private_directory(path).await
}

async fn verify_private_directory(path: &Path) -> Result<()> {
	let metadata = tokio::fs::symlink_metadata(path).await?;
	if !metadata.is_dir() || metadata.file_type().is_symlink() {
		bail!("native weight store directory must not be a symlink");
	}
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		if metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
			bail!("native weight store directory must be private and owned");
		}
	}
	Ok(())
}

async fn lock_store(root: &Path) -> Result<std::fs::File> {
	let mut options = tokio::fs::OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
	let file = options.open(root).await?.into_std().await;
	#[cfg(unix)]
	{
		use std::os::fd::AsRawFd;
		let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
		loop {
			if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
				break;
			}
			let error = std::io::Error::last_os_error();
			if error.kind() != std::io::ErrorKind::WouldBlock {
				return Err(error.into());
			}
			if tokio::time::Instant::now() >= deadline {
				bail!("native weight artifact publisher is busy; retry the identical request");
			}
			tokio::time::sleep(Duration::from_millis(20)).await;
		}
	}
	Ok(file)
}

async fn quota(root: &Path, incoming: u64) -> Result<()> {
	let mut entries = tokio::fs::read_dir(root).await?;
	let mut count = 0usize;
	let mut bytes = 0u64;
	while let Some(entry) = entries.next_entry().await? {
		let meta = tokio::fs::symlink_metadata(entry.path()).await?;
		if !meta.is_dir() || meta.file_type().is_symlink() {
			bail!("unexpected entry in the native weight artifact store");
		}
		count += 1;
		if count >= MAX_ARTIFACTS {
			bail!("native weight artifact count budget exhausted");
		}
		let mut contents = tokio::fs::read_dir(entry.path()).await?;
		let mut members = 0usize;
		while let Some(member) = contents.next_entry().await? {
			members += 1;
			let meta = tokio::fs::symlink_metadata(member.path()).await?;
			if !meta.is_file() || meta.file_type().is_symlink() || members > 2 {
				bail!("unexpected member in a native weight artifact");
			}
			bytes = bytes
				.checked_add(meta.len())
				.ok_or_else(|| anyhow!("artifact quota overflow"))?;
		}
	}
	if bytes
		.checked_add(incoming)
		.is_none_or(|size| size > MAX_STORE_BYTES)
	{
		bail!("native weight artifact store exceeds its 8 GiB budget");
	}
	Ok(())
}

async fn create_private(path: &Path) -> Result<tokio::fs::File> {
	let mut options = tokio::fs::OpenOptions::new();
	options.write(true).create_new(true);
	#[cfg(unix)]
	options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
	Ok(options.open(path).await?)
}

async fn copy_bytes(
	input: &mut tokio::fs::File,
	output: &mut Option<&mut tokio::fs::File>,
	count: u64,
	source: &mut Sha256,
	target: &mut Sha256,
) -> Result<()> {
	if count == 0 {
		return Ok(());
	}
	let mut remaining = count;
	let mut buffer = vec![0u8; count.min(1024 * 1024) as usize];
	while remaining > 0 {
		let length = remaining.min(buffer.len() as u64) as usize;
		input.read_exact(&mut buffer[..length]).await?;
		source.update(&buffer[..length]);
		target.update(&buffer[..length]);
		if let Some(output) = output.as_deref_mut() {
			output.write_all(&buffer[..length]).await?;
		}
		remaining -= length as u64;
	}
	Ok(())
}

async fn transform(
	input: &mut tokio::fs::File,
	mut output: Option<&mut tokio::fs::File>,
	patch: &TensorPatch,
) -> Result<(String, String, u64)> {
	input.seek(std::io::SeekFrom::Start(0)).await?;
	let mut source = Sha256::new();
	let mut target = Sha256::new();
	let mut position = 0u64;
	let mut changed = 0u64;
	for change in &patch.changes {
		let before = weight_tensor::unhex(&change.expected_hex)?;
		let after = weight_tensor::unhex(&change.replacement_hex)?;
		let gap = change
			.file_offset
			.checked_sub(position)
			.ok_or_else(|| anyhow!("patch ranges overlap"))?;
		copy_bytes(input, &mut output, gap, &mut source, &mut target).await?;
		let mut actual = vec![0u8; before.len()];
		input.read_exact(&mut actual).await?;
		if actual != before {
			bail!(
				"tensor element {} does not match its exact expected bytes",
				change.index
			);
		}
		source.update(&actual);
		target.update(&after);
		changed += actual
			.iter()
			.zip(&after)
			.filter(|(left, right)| left != right)
			.count() as u64;
		if let Some(output) = output.as_deref_mut() {
			output.write_all(&after).await?;
		}
		position = change.file_offset + before.len() as u64;
	}
	copy_bytes(
		input,
		&mut output,
		patch
			.source_size_bytes
			.checked_sub(position)
			.ok_or_else(|| anyhow!("patch exceeds admitted source"))?,
		&mut source,
		&mut target,
	)
	.await?;
	Ok((hex(&source.finalize()), hex(&target.finalize()), changed))
}

async fn file_hash(file: &mut tokio::fs::File, size: u64) -> Result<String> {
	file.seek(std::io::SeekFrom::Start(0)).await?;
	let mut hash = Sha256::new();
	let mut remaining = size;
	let mut buffer = vec![0u8; 1024 * 1024];
	while remaining > 0 {
		let length = remaining.min(buffer.len() as u64) as usize;
		file.read_exact(&mut buffer[..length]).await?;
		hash.update(&buffer[..length]);
		remaining -= length as u64;
	}
	Ok(hex(&hash.finalize()))
}

async fn read_manifest_metadata(root: &Path, id: &str) -> Result<Manifest> {
	check_id(id)?;
	let path = root.join(id).join("manifest.json");
	let bytes =
		super::rea_files::read_private_bounded(&path, &[root.to_owned()], MAX_MANIFEST_BYTES)
			.await?;
	let value = super::rea_evidence::parse_unique_json(&bytes)?;
	let manifest: Manifest = serde_json::from_value(value)?;
	if manifest.schema != "hepta.weight.native-artifact.v1"
		|| manifest.artifact_id != id
		|| !matches!(manifest.kind.as_str(), "patch" | "restore")
		|| !super::weight_config::valid_sha256(&manifest.source_sha256)
		|| !super::weight_config::valid_sha256(&manifest.target_sha256)
		|| manifest.no_op != (manifest.source_sha256 == manifest.target_sha256)
		|| id_for(&manifest)? != id
	{
		bail!("native weight manifest identity is inconsistent");
	}
	Ok(manifest)
}

async fn open_manifest_model(
	root: &Path,
	id: &str,
	manifest: &Manifest,
) -> Result<(tokio::fs::File, std::fs::Metadata)> {
	let model = root.join(id).join("model.safetensors");
	let (file, before) = super::rea_files::open_confined(&model, &[root.to_owned()]).await?;
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		if before.nlink() != 1
			|| before.mode() & 0o777 != 0o600
			|| before.uid() != unsafe { libc::geteuid() }
		{
			bail!("retained native weight file must be private, owned and singly linked");
		}
	}
	if before.len() != manifest.patch.source_size_bytes || before.len() > MAX_MODEL_BYTES {
		bail!("retained native weight artifact length differs from its manifest");
	}
	Ok((file, before))
}

/// Admit only a fixed private artifact ID. The caller must verify the returned
/// full-content commitment on this descriptor and recheck its metadata.
pub(super) async fn open_pinned_artifact(
	id: &str,
	state: &Path,
) -> Result<(tokio::fs::File, std::fs::Metadata, String)> {
	let root = state.join("weight-artifacts-v1");
	verify_private_directory(&root).await?;
	let manifest = read_manifest_metadata(&root, id).await?;
	let (file, before) = open_manifest_model(&root, id, &manifest).await?;
	Ok((file, before, manifest.target_sha256))
}

async fn read_manifest(root: &Path, id: &str) -> Result<Manifest> {
	let manifest = read_manifest_metadata(root, id).await?;
	let (mut file, before) = open_manifest_model(root, id, &manifest).await?;
	if file_hash(&mut file, before.len()).await? != manifest.target_sha256 {
		bail!("retained native weight artifact bytes differ from their manifest");
	}
	unchanged(&before, &file.metadata().await?)?;
	Ok(manifest)
}

async fn find_reusable(
	root: &Path,
	params: &PatchTensorParams,
	plan: &TensorPatch,
	parent: Option<&str>,
	kind: &str,
) -> Result<Option<Manifest>> {
	let mut entries = tokio::fs::read_dir(root).await?;
	let mut count = 0usize;
	while let Some(entry) = entries.next_entry().await? {
		count += 1;
		if count > MAX_ARTIFACTS {
			bail!("native artifact lookup exceeds its bounded entry count");
		}
		let name = entry
			.file_name()
			.into_string()
			.map_err(|_| anyhow!("invalid artifact filename"))?;
		if name.starts_with(".pending-") {
			continue;
		}
		let saved = read_manifest_metadata(root, &name).await?;
		if saved.source_path == params.path
			&& saved.source_sha256 == params.expected_sha256
			&& saved.patch == *plan
			&& saved.kind == kind
			&& saved.parent_artifact_id.as_deref() == parent
		{
			return Ok(Some(read_manifest(root, &name).await?));
		}
	}
	Ok(None)
}

async fn rename_exclusive(from: &Path, to: &Path) -> Result<()> {
	#[cfg(target_os = "linux")]
	{
		use std::os::unix::ffi::OsStrExt;
		let from = std::ffi::CString::new(from.as_os_str().as_bytes())?;
		let to = std::ffi::CString::new(to.as_os_str().as_bytes())?;
		tokio::task::spawn_blocking(move || {
			let result = unsafe {
				libc::renameat2(
					libc::AT_FDCWD,
					from.as_ptr(),
					libc::AT_FDCWD,
					to.as_ptr(),
					libc::RENAME_NOREPLACE,
				)
			};
			if result != 0 {
				return Err(std::io::Error::last_os_error());
			}
			Ok(())
		})
		.await??;
		Ok(())
	}
	#[cfg(not(target_os = "linux"))]
	{
		let _ = (from, to);
		bail!("native weight artifact publication currently requires Linux renameat2");
	}
}

fn receipt(root: &Path, manifest: &Manifest, reused: bool) -> Value {
	json!({"schema":"hepta.weight.native-artifact-receipt.v1","artifact_id":manifest.artifact_id,"kind":manifest.kind,"artifact_path":root.join(&manifest.artifact_id).join("model.safetensors"),"manifest_path":root.join(&manifest.artifact_id).join("manifest.json"),"source_sha256":manifest.source_sha256,"sha256":manifest.target_sha256,"byte_length":manifest.patch.source_size_bytes,"changed_bytes":manifest.changed_bytes,"exact_no_op":manifest.no_op,"reused":reused,"source_modified":false,"production_eligible":false,"behavior_evaluated":false})
}

async fn apply_with_roots(
	params: PatchTensorParams,
	roots: &[PathBuf],
	state: &Path,
	parent: Option<String>,
	restored_sha: Option<String>,
) -> Result<Value> {
	if !cfg!(target_os = "linux") {
		bail!("native weight artifact publication is qualified only on Linux");
	}
	if !super::weight_config::valid_sha256(&params.expected_sha256)
		|| params.edits.is_empty()
		|| params.edits.len() > 1024
		|| params.tensor_name.is_empty()
		|| params.tensor_name.len() > 4096
		|| params
			.edits
			.iter()
			.any(|edit| edit.expected_hex.len() > 8 || edit.replacement_hex.len() > 8)
	{
		bail!("invalid source digest or bounded edit count");
	}
	let (mut source, before) =
		super::rea_files::open_confined(Path::new(&params.path), roots).await?;
	if before.len() > MAX_MODEL_BYTES {
		bail!("native weight input exceeds 2 GiB; no output was published");
	}
	let report =
		super::rea_model::inspect_tensor_descriptor(&mut source, &params.tensor_name).await?;
	let plan = weight_tensor::prepare(&params, &report)?;
	let kind = if parent.is_some() { "restore" } else { "patch" };
	let root = store_root(state).await?;
	let _lock = lock_store(&root).await?;
	if let Some(saved) = find_reusable(&root, &params, &plan, parent.as_deref(), kind).await? {
		let (source_hash, target_hash, changed) = transform(&mut source, None, &plan).await?;
		unchanged(&before, &source.metadata().await?)?;
		if source_hash != params.expected_sha256
			|| target_hash != saved.target_sha256
			|| changed != saved.changed_bytes
			|| restored_sha
				.as_ref()
				.is_some_and(|expected| *expected != target_hash)
		{
			bail!("retained artifact no longer matches the admitted source and exact patch");
		}
		tokio::fs::File::open(&root).await?.sync_all().await?;
		return Ok(receipt(&root, &saved, true));
	}
	quota(&root, before.len() + MAX_MANIFEST_BYTES).await?;
	let sequence = STAGE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
	let nanos = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)?
		.as_nanos();
	let stage = root.join(format!(
		".pending-{}-{nanos}-{sequence}",
		std::process::id()
	));
	private_directory(&stage).await?;
	let result = async {
		let mut output = create_private(&stage.join("model.safetensors")).await?;
		let (source_hash, target_hash, changed_bytes) =
			transform(&mut source, Some(&mut output), &plan).await?;
		unchanged(&before, &source.metadata().await?)?;
		if source_hash != params.expected_sha256 {
			bail!("complete source hash differs; native weight output was not published");
		}
		if restored_sha
			.as_ref()
			.is_some_and(|expected| *expected != target_hash)
		{
			bail!("inverse patch did not reconstruct the original parent bytes");
		}
		output.sync_all().await?;
		drop(output);
		let mut manifest = Manifest {
			schema: "hepta.weight.native-artifact.v1".into(),
			artifact_id: String::new(),
			kind: kind.into(),
			source_path: params.path,
			source_sha256: source_hash.clone(),
			target_sha256: target_hash.clone(),
			patch: plan,
			parent_artifact_id: parent,
			changed_bytes,
			no_op: source_hash == target_hash,
		};
		manifest.artifact_id = id_for(&manifest)?;
		let destination = root.join(&manifest.artifact_id);
		if tokio::fs::try_exists(&destination).await? {
			let saved = read_manifest(&root, &manifest.artifact_id).await?;
			if serde_json::to_value(&saved)? != serde_json::to_value(&manifest)? {
				bail!("native artifact identity collision or conflicting manifest");
			}
			tokio::fs::File::open(&root).await?.sync_all().await?;
			return Ok(receipt(&root, &saved, true));
		}
		let encoded = serde_json::to_vec(&manifest)?;
		if encoded.len() as u64 > MAX_MANIFEST_BYTES {
			bail!("native weight manifest exceeds its byte budget");
		}
		let mut manifest_file = create_private(&stage.join("manifest.json")).await?;
		manifest_file.write_all(&encoded).await?;
		manifest_file.sync_all().await?;
		drop(manifest_file);
		tokio::fs::File::open(&stage).await?.sync_all().await?;
		rename_exclusive(&stage, &destination).await?;
		tokio::fs::File::open(&root).await?.sync_all().await?;
		let saved = read_manifest(&root, &manifest.artifact_id).await?;
		Ok::<_, anyhow::Error>(receipt(&root, &saved, false))
	}
	.await;
	if tokio::fs::try_exists(&stage).await? {
		tokio::fs::remove_dir_all(&stage)
			.await
			.context("cleanup failed native artifact staging")?;
	}
	result
}

pub async fn patch(params: PatchTensorParams) -> Result<String> {
	let config = super::runtime::runtime_config()?;
	let result = tokio::time::timeout(
		Duration::from_secs(300),
		apply_with_roots(
			params,
			&config.controller_workspace_roots,
			&config.state_dir,
			None,
			None,
		),
	)
	.await
	.context(
		"native artifact deadline exceeded; retry identical input to reconcile publication",
	)??;
	Ok(serde_json::to_string(&result)?)
}

async fn restore_with_state(id: &str, state: &Path) -> Result<Value> {
	let root = store_root(state).await?;
	let saved = read_manifest(&root, id).await?;
	if saved.kind != "patch" {
		bail!("restore expects an original native patch artifact");
	}
	let params = PatchTensorParams {
		path: root
			.join(id)
			.join("model.safetensors")
			.to_string_lossy()
			.into_owned(),
		expected_sha256: saved.target_sha256,
		tensor_name: saved.patch.tensor_name,
		edits: saved
			.patch
			.changes
			.into_iter()
			.map(|change| ExactElementEdit {
				index: change.index,
				expected_hex: change.replacement_hex,
				replacement_hex: change.expected_hex,
			})
			.collect(),
	};
	apply_with_roots(
		params,
		&[root],
		state,
		Some(id.into()),
		Some(saved.source_sha256),
	)
	.await
}

pub async fn restore(params: RestoreParams) -> Result<String> {
	let config = super::runtime::runtime_config()?;
	let result = tokio::time::timeout(
		Duration::from_secs(300),
		restore_with_state(&params.artifact_id, &config.state_dir),
	)
	.await
	.context("native restore deadline exceeded; retry the identical artifact ID")??;
	Ok(serde_json::to_string(&result)?)
}

#[cfg(all(test, target_os = "linux"))]
#[path = "weight_artifact_tests.rs"]
mod tests;
