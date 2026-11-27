// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Session-scoped preflight and roundtrip through the unchanged artifact owner.

use super::{F32GuardInput, SessionAuthority};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::mcp::{
	rea_files, rea_model, runtime, weight_artifact,
	weight_guard::{source_bound_f32, GuardedPatchParams},
	weight_guard_journal, weight_norm,
	weight_tensor::{self, PatchTensorParams, TensorPatch},
};

pub(super) fn request(
	input: F32GuardInput,
	authority: &SessionAuthority,
) -> Result<source_bound_f32::SourceBoundParams> {
	let params = source_bound_f32::SourceBoundParams {
		guard: GuardedPatchParams {
			patch: PatchTensorParams {
				path: authority.source_path.clone(),
				expected_sha256: authority.parent_sha256.clone(),
				tensor_name: authority.allowed_readout.weight_tensor.clone(),
				edits: input.edits,
			},
			inputs: input.inputs,
			bias: Some(input.bias),
			objective: input.objective,
			minimum_gain: input.minimum_gain,
			constraints: input.constraints,
			max_update_l2_norm: Some(input.maximum_update_l2_norm),
		},
		bias_binding: source_bound_f32::BiasBinding {
			tensor_name: authority.allowed_readout.bias_tensor.clone(),
			payload_sha256: authority.allowed_readout.bias_payload_sha256.clone(),
		},
	};
	authority.authorize_guard(&params.guard)?;
	let budget = weight_norm::check_edits(&params.guard.patch.edits, input.maximum_update_l2_norm)?;
	if !budget.within_budget {
		bail!("session candidate exceeds its exact represented-F32 update radius");
	}
	Ok(params)
}

/// Hash the complete proposed bytes without publishing or allocating a checkpoint-sized copy.
/// Byte-level overlap also handles an edited F32 element crossing a stream-chunk boundary.
pub(super) async fn proposed_hash(
	file: &mut tokio::fs::File,
	patch: &TensorPatch,
) -> Result<(String, String, String)> {
	file.seek(std::io::SeekFrom::Start(0)).await?;
	let changes = patch
		.changes
		.iter()
		.map(|change| {
			Ok((
				change.file_offset,
				weight_tensor::unhex(&change.expected_hex)?,
				weight_tensor::unhex(&change.replacement_hex)?,
			))
		})
		.collect::<Result<Vec<_>>>()?;
	let mut source_hash = Sha256::new();
	let mut candidate_hash = Sha256::new();
	let mut tensor_hash = Sha256::new();
	let mut buffer = vec![0_u8; 1024 * 1024];
	let mut position = 0_u64;
	let mut changed_bytes = 0_usize;
	while position < patch.source_size_bytes {
		let length = (patch.source_size_bytes - position).min(buffer.len() as u64) as usize;
		file.read_exact(&mut buffer[..length]).await?;
		source_hash.update(&buffer[..length]);
		let left = position.max(patch.tensor_file_offset);
		let right =
			(position + length as u64).min(patch.tensor_file_offset + patch.tensor_byte_length);
		if left < right {
			tensor_hash.update(&buffer[(left - position) as usize..(right - position) as usize]);
		}
		for (offset, expected, replacement) in &changes {
			let left = position.max(*offset);
			let right = (position + length as u64).min(*offset + expected.len() as u64);
			for at in left..right {
				let index = (at - position) as usize;
				let within = (at - *offset) as usize;
				if buffer[index] != expected[within] {
					bail!("session preflight old edit bytes differ from the admitted source");
				}
				buffer[index] = replacement[within];
				changed_bytes += 1;
			}
		}
		candidate_hash.update(&buffer[..length]);
		position += length as u64;
	}
	if changed_bytes != patch.changes.len() * 4 {
		bail!("session proposal did not cover every admitted F32 edit byte");
	}
	Ok((
		rea_model::digest_hex(&source_hash.finalize()),
		rea_model::digest_hex(&candidate_hash.finalize()),
		rea_model::digest_hex(&tensor_hash.finalize()),
	))
}

async fn authenticate(
	params: &source_bound_f32::SourceBoundParams,
	authority: &SessionAuthority,
	roots: &[PathBuf],
) -> Result<(Value, String)> {
	authority.revalidate().await?;
	let (mut file, before) =
		rea_files::open_confined(Path::new(&authority.source_path), roots).await?;
	let report =
		rea_model::inspect_tensor_descriptor(&mut file, &authority.allowed_readout.weight_tensor)
			.await?;
	let tensor = &report["result"]["tensor"];
	let shape = vec![
		authority.allowed_readout.outputs.to_string(),
		authority.allowed_readout.columns.to_string(),
	];
	if tensor["dtype"] != "F32" || tensor["shape"] != json!(shape) {
		bail!("actual source head differs from the session F32 tensor scope");
	}
	let patch = weight_tensor::prepare(&params.guard.patch, &report)?;
	if patch.source_size_bytes != before.len() || before.len() > 2 * 1024 * 1024 * 1024 {
		bail!("actual session source exceeds or differs from its descriptor budget");
	}
	let (source_sha, candidate_sha, tensor_sha) = proposed_hash(&mut file, &patch).await?;
	if source_sha != authority.parent_sha256
		|| tensor_sha != authority.allowed_readout.weight_payload_sha256
	{
		bail!("actual source or selected weight payload differs from the admitted session");
	}
	let bound = source_bound_f32::authenticate_from_admitted(params, &mut file).await?;
	#[cfg(unix)]
	rea_files::ensure_unchanged(&before, &file.metadata().await?)?;
	authority.revalidate().await?;
	Ok((serde_json::to_value(bound.bias_evidence())?, candidate_sha))
}

async fn preflight(
	params: &source_bound_f32::SourceBoundParams,
	authority: &SessionAuthority,
	roots: &[PathBuf],
) -> Result<(Value, String)> {
	tokio::time::timeout(
		Duration::from_secs(60),
		authenticate(params, authority, roots),
	)
	.await
	.context("session F32 preflight exceeded 60 seconds; no candidate requested")?
}

pub(super) async fn prepare(input: F32GuardInput, authority: SessionAuthority) -> Result<Value> {
	let config = runtime::runtime_config()?;
	let params = request(input, &authority)?;
	let (bias, candidate_sha) =
		preflight(&params, &authority, &config.controller_workspace_roots).await?;
	let journal_id = weight_guard_journal::session_identity_with_roots(
		&params.guard,
		&config.controller_workspace_roots,
		&config.state_dir,
		&authority,
	)
	.await?;
	Ok(json!({
		"schema":"hepta.rea.session-f32-preparation.v1","journal_id":journal_id,
		"parent_sha256":authority.parent_sha256,"expected_candidate_sha256":candidate_sha,
		"weight_tensor":authority.allowed_readout.weight_tensor,"bias_evidence":bias,
		"source_payload_hash_passes":2,"forward_calls":0,"candidate_published":false,
		"journal_written":false,"accepted_for_activation":false,
		"binding_is_authorization_token":false,"production_eligible":false
	}))
}

async fn execute(
	params: source_bound_f32::SourceBoundParams,
	expected_journal_id: String,
	authority: SessionAuthority,
	roots: Vec<PathBuf>,
	state: PathBuf,
) -> Result<Value> {
	let current_id = weight_guard_journal::session_identity_with_roots(
		&params.guard,
		&roots,
		&state,
		&authority,
	)
	.await?;
	if current_id != expected_journal_id {
		bail!("session request differs from its prepared original journal identity; no effect requested");
	}
	let (bias, candidate_sha) = preflight(&params, &authority, &roots).await?;
	authority.revalidate().await?;
	let guard = weight_guard_journal::evaluate_session_with_roots(
		params.guard.clone(),
		&roots,
		&state,
		&authority,
	)
	.await?;
	#[cfg(all(test, target_os = "linux"))]
	super::tests::after_guard(&guard).await;
	let candidate = guard["candidate"].clone();
	let authority_before_inverse = authority
		.revalidate()
		.await
		.err()
		.map(|error| error.to_string());
	// Compensation remains in the original admitted task even if its session metadata is revoked
	// after publication. It cannot promote the candidate or create a different edit.
	let inverse = async {
		if guard["journal_id"] != expected_journal_id || candidate["sha256"] != candidate_sha {
			bail!("published guard identity differs from the prepared session candidate");
		}
		let id = candidate["artifact_id"].as_str().ok_or_else(|| {
			anyhow!("session candidate identity unavailable; reconcile the original journal")
		})?;
		let restored = if guard["restoration"].is_object() {
			guard["restoration"].clone()
		} else {
			weight_artifact::restore_with_state(id, &state).await?
		};
		if restored["source_sha256"] != candidate_sha
			|| restored["sha256"] != authority.parent_sha256
			|| restored["source_modified"] != false
			|| restored["production_eligible"] != false
		{
			bail!("session inverse receipt differs from its exact prepared parent");
		}
		Ok::<_, anyhow::Error>(restored)
	}
	.await;
	let (restoration, inverse_error) = match inverse {
		Ok(receipt) => (receipt, None),
		Err(error) => (Value::Null, Some(error.to_string())),
	};
	let fresh = async {
		let id = restoration["artifact_id"]
			.as_str()
			.ok_or_else(|| anyhow!("session inverse is not verified"))?;
		tokio::time::timeout(
			Duration::from_secs(60),
			source_bound_f32::next_request_with_state(&params, id, &state),
		)
		.await
		.context("session restored artifact fresh-request deadline expired")?
	}
	.await;
	let (new_request, fresh_error) = match fresh {
		Ok(report) => (report, None),
		Err(error) => (Value::Null, Some(error.to_string())),
	};
	let authority_after = authority
		.revalidate()
		.await
		.err()
		.map(|error| error.to_string());
	let authority_valid = authority_before_inverse.is_none() && authority_after.is_none();
	let report = json!({
		"schema":"hepta.rea.session-f32-roundtrip.v1","journal_id":expected_journal_id,
		"candidate":candidate,"guard":guard,"bias_evidence":bias,
		"restoration":restoration,"new_request":new_request,
		"restoration_verified":inverse_error.is_none() && fresh_error.is_none(),
		"inverse_error":inverse_error,"fresh_request_error":fresh_error,
		"session_authority_valid_after_effect":authority_valid,
		"authority_before_inverse_error":authority_before_inverse,"authority_after_error":authority_after,
		"research_roundtrip_verified":inverse_error.is_none() && fresh_error.is_none() && authority_valid,
		"accepted_for_activation":false,"live_activation":false,"production_eligible":false,
		"full_model_executed":false,"feature_provenance_verified":false,
		"original_owner_task_retained":true,"process_crash_recovery_verified":false,
		"automatic_retry":false,"background_recovery":false
	});
	#[cfg(all(test, target_os = "linux"))]
	super::tests::completed(&report);
	Ok(report)
}

pub(super) async fn roundtrip(
	input: F32GuardInput,
	expected_journal_id: String,
	authority: SessionAuthority,
) -> Result<Value> {
	let params = request(input, &authority)?;
	let config = runtime::runtime_config()?;
	let roots = config.controller_workspace_roots.clone();
	let state = config.state_dir.clone();
	let guards = weight_artifact::cohort::owner_guards().await?;
	tokio::time::timeout(Duration::from_secs(420), weight_artifact::cohort::retained_transaction(guards, execute(params, expected_journal_id, authority, roots, state)))
		.await.context("session F32 response deadline exceeded; the original owner task may finish; recover only the prepared journal identity")?
}
