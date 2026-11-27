// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bind the existing F32 guarded head's explicit bias to its actual checkpoint tensor.
//! Reuses the original forward, artifact owner and durable guard journal without a new lifecycle.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::super::{
	rea_files, rea_model, runtime, weight_artifact, weight_config, weight_forward,
	weight_guard_journal,
};
use super::{digest, GuardedPatchParams};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BiasBinding {
	pub tensor_name: String,
	pub payload_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBoundParams {
	pub guard: GuardedPatchParams,
	pub bias_binding: BiasBinding,
}

#[derive(Debug, Serialize)]
pub struct BiasEvidence {
	schema: &'static str,
	source_sha256: String,
	bias_tensor_name: String,
	bias_dtype: &'static str,
	bias_shape: Vec<usize>,
	bias_payload_sha256: String,
	bias_exact_bytes_hex: String,
	source_size_bytes: u64,
	complete_source_hash_passes: u8,
	caller_bias_matches_stored_bits: bool,
	full_model_executed: bool,
}

/// This serializable evidence has no deserialization constructor and grants no owner permission.
#[derive(Serialize)]
pub struct BoundGuard {
	guard: GuardedPatchParams,
	bias_evidence: BiasEvidence,
}

impl BoundGuard {
	pub fn guarded_params(&self) -> &GuardedPatchParams {
		&self.guard
	}

	pub fn bias_evidence(&self) -> &BiasEvidence {
		&self.bias_evidence
	}
}

async fn authenticate_inner(
	params: &SourceBoundParams,
	file: &mut tokio::fs::File,
) -> Result<BoundGuard> {
	let guard = &params.guard;
	let binding = &params.bias_binding;
	let bias = guard
		.bias
		.as_ref()
		.ok_or_else(|| anyhow!("source-bound F32 guard requires its explicit stored bias"))?;
	if !weight_config::valid_sha256(&guard.patch.expected_sha256)
		|| !weight_config::valid_sha256(&binding.payload_sha256)
		|| binding.tensor_name.is_empty()
		|| binding.tensor_name.len() > 1024
		|| binding.tensor_name == guard.patch.tensor_name
		|| !(1..=4096).contains(&bias.len())
		|| bias.iter().any(|value| !value.is_finite())
	{
		bail!("source-bound F32 guard requires distinct tensors, complete hashes and finite bias");
	}
	let before = file.metadata().await?;
	if !before.is_file() || !(9..=2 * 1024 * 1024 * 1024).contains(&before.len()) {
		bail!("source-bound F32 guard requires a regular checkpoint within 2 GiB");
	}
	let report = rea_model::inspect_tensor_descriptor(file, &binding.tensor_name).await?;
	let tensor = &report["result"]["tensor"];
	let byte_length = bias.len() * 4;
	let offset = tensor["file_offset"]
		.as_u64()
		.ok_or_else(|| anyhow!("stored F32 bias offset is missing"))?;
	if report["format"] != "safetensors"
		|| tensor["name"] != binding.tensor_name
		|| tensor["dtype"] != "F32"
		|| tensor["shape"] != json!([bias.len().to_string()])
		|| tensor["storage_length_verified"] != true
		|| tensor["byte_length"].as_u64() != Some(byte_length as u64)
		|| offset > before.len()
		|| byte_length as u64 > before.len() - offset
	{
		bail!("stored bias is not the exact named F32 vector required by this head");
	}
	// Read the exact bias during the same complete-file hash pass used by the native forward.
	let (source_sha, bytes) =
		weight_forward::capture(file, before.len(), offset, byte_length).await?;
	#[cfg(unix)]
	rea_files::ensure_unchanged(&before, &file.metadata().await?)?;
	let expected: Vec<_> = bias.iter().flat_map(|value| value.to_le_bytes()).collect();
	if source_sha != guard.patch.expected_sha256
		|| digest(&bytes) != binding.payload_sha256
		|| bytes != expected
	{
		bail!("explicit F32 bias or checkpoint differs from the actual stored parameter bytes");
	}
	Ok(BoundGuard {
		guard: guard.clone(),
		bias_evidence: BiasEvidence {
			schema: "hepta.weight.source-bound-f32-bias.v1",
			source_sha256: source_sha,
			bias_tensor_name: binding.tensor_name.clone(),
			bias_dtype: "F32",
			bias_shape: vec![bias.len()],
			bias_payload_sha256: digest(&bytes),
			bias_exact_bytes_hex: rea_model::digest_hex(&bytes),
			source_size_bytes: before.len(),
			complete_source_hash_passes: 1,
			caller_bias_matches_stored_bits: true,
			full_model_executed: false,
		},
	})
}

/// Authenticate bytes from a descriptor already admitted by the caller's existing file policy.
/// No feature augmentation, parameter conversion or model execution happens here.
pub async fn authenticate_from_admitted(
	params: &SourceBoundParams,
	file: &mut tokio::fs::File,
) -> Result<BoundGuard> {
	tokio::time::timeout(Duration::from_secs(60), authenticate_inner(params, file))
		.await
		.context("stored F32 bias authentication exceeded 60 seconds")?
}

async fn evaluate_with_roots(
	params: SourceBoundParams,
	roots: &[PathBuf],
	state: &Path,
) -> Result<Value> {
	if Path::new(&params.guard.patch.path).starts_with(state) {
		bail!("source-bound F32 guard requires a workspace source, not an artifact path");
	}
	let (mut source, _) =
		rea_files::open_confined(Path::new(&params.guard.patch.path), roots).await?;
	let bound = authenticate_from_admitted(&params, &mut source).await?;
	drop(source);
	let guard = weight_guard_journal::evaluate_with_roots(bound.guard, roots, state).await?;
	Ok(json!({
		"schema":"hepta.weight.source-bound-f32-guard.v1",
		"bias_evidence":bound.bias_evidence,
		"guard":guard,
		"full_model_executed":false,
		"feature_provenance_verified":false,
		"production_eligible":false,
		"lifecycle":"unchanged durable F32 guard; passing artifacts are retained for review, failing artifacts are restored"
	}))
}

/// Delegate exact publication, candidate forward and failed-candidate restoration to the
/// existing durable F32 guard. Passing artifacts remain isolated and are never activated.
pub async fn evaluate(params: SourceBoundParams) -> Result<Value> {
	let config = runtime::runtime_config()?;
	evaluate_with_roots(
		params,
		&config.controller_workspace_roots,
		&config.state_dir,
	)
	.await
}

pub(in crate::mcp) async fn next_request_with_state(
	params: &SourceBoundParams,
	artifact_id: &str,
	state: &Path,
) -> Result<Value> {
	let (mut file, _, source_sha) =
		weight_artifact::open_pinned_artifact(artifact_id, state).await?;
	if source_sha != params.guard.patch.expected_sha256 {
		bail!("new F32 request requires a restored artifact with the original checkpoint hash");
	}
	let bound = authenticate_from_admitted(params, &mut file).await?;
	drop(file);
	let forward = weight_forward::forward_with_roots(
		weight_forward::ForwardLinearParams {
			source: weight_forward::LinearSource::Artifact {
				artifact_id: artifact_id.into(),
				tensor_name: bound.guard.patch.tensor_name,
			},
			inputs: bound.guard.inputs,
			bias: bound.guard.bias,
		},
		&[],
		state,
	)
	.await?;
	if forward["source_sha256"] != source_sha {
		bail!("restored F32 artifact changed between bias authentication and new forward");
	}
	Ok(json!({
		"schema":"hepta.weight.source-bound-f32-next-request.v1",
		"artifact_id":artifact_id,
		"bias_evidence":bound.bias_evidence,
		"forward":forward,
		"full_model_executed":false,
		"feature_provenance_verified":false,
		"production_eligible":false
	}))
}

/// A fresh request reopens the actual restored artifact and authenticates its stored bias again.
pub async fn next_request(params: &SourceBoundParams, artifact_id: &str) -> Result<Value> {
	let state = runtime::runtime_config()?.state_dir.clone();
	next_request_with_state(params, artifact_id, &state).await
}

#[cfg(all(test, target_os = "linux"))]
#[path = "weight_guard_f32_source_tests.rs"]
mod tests;
