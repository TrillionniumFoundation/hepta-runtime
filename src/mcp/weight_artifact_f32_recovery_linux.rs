// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Lock the original intent, find one exact published candidate, then call the canonical inverse.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::super::super::{
	check_id, lock_store, open_pinned_artifact, read_manifest, read_manifest_metadata,
	restore_with_state, verify_private_directory, Manifest, MAX_ARTIFACTS,
};
use super::RecoveryParams;
use crate::mcp::{
	rea_files, rea_model, weight_config, weight_forward,
	weight_guard::{source_bound_f32, GuardedPatchParams},
	weight_guard_journal::recovery::{self, LockedIntent},
	weight_norm,
};

struct Prepared {
	intent: LockedIntent,
	source_bound: source_bound_f32::SourceBoundParams,
	candidate: Manifest,
	bias_evidence: Value,
	update_budget: Value,
	discovered_without_candidate_record: bool,
}

fn patch_matches(manifest: &Manifest, request: &GuardedPatchParams) -> bool {
	let patch = &request.patch;
	if manifest.kind != "patch"
		|| manifest.source_path != patch.path
		|| manifest.source_sha256 != patch.expected_sha256
		|| manifest.parent_artifact_id.is_some()
		|| manifest.patch.tensor_name != patch.tensor_name
		|| manifest.patch.dtype != "F32"
		|| manifest.patch.changes.len() != patch.edits.len()
	{
		return false;
	}
	let edits: BTreeMap<_, _> = patch.edits.iter().map(|edit| (edit.index, edit)).collect();
	if edits.len() != patch.edits.len() {
		return false;
	}
	let indices: BTreeSet<_> = manifest
		.patch
		.changes
		.iter()
		.map(|change| change.index)
		.collect();
	if indices.len() != edits.len() {
		return false;
	}
	manifest.patch.changes.iter().all(|change| {
		edits.get(&change.index).is_some_and(|edit| {
			change.expected_hex == edit.expected_hex
				&& change.replacement_hex == edit.replacement_hex
				&& change
					.index
					.checked_mul(4)
					.and_then(|offset| manifest.patch.tensor_file_offset.checked_add(offset))
					== Some(change.file_offset)
		})
	})
}

async fn locate(
	params: &RecoveryParams,
	intent: &LockedIntent,
	state: &Path,
) -> Result<(Manifest, bool)> {
	let root = state.join("weight-artifacts-v1");
	verify_private_directory(&root).await?;
	let _owner = lock_store(&root).await?;
	let hinted = match (&params.candidate_artifact_id, &intent.candidate_artifact_id) {
		(Some(requested), Some(recorded)) if requested != recorded => {
			bail!("requested recovery candidate differs from the original guard candidate record");
		}
		(Some(id), _) | (_, Some(id)) => Some(id.as_str()),
		(None, None) => None,
	};
	let matches = |manifest: &Manifest| {
		patch_matches(manifest, &intent.request)
			&& manifest.target_sha256 == params.expected_candidate_sha256
	};
	if let Some(id) = hinted {
		check_id(id)?;
		let candidate = read_manifest(&root, id).await?;
		if !matches(&candidate) {
			bail!(
				"published recovery candidate differs from the original intent and complete hashes"
			);
		}
		return Ok((candidate, false));
	}
	let mut entries = tokio::fs::read_dir(&root).await?;
	let mut count = 0;
	let mut found = None;
	while let Some(entry) = entries.next_entry().await? {
		count += 1;
		if count > MAX_ARTIFACTS {
			bail!("source-bound recovery exceeds the original artifact count budget");
		}
		let name = entry
			.file_name()
			.into_string()
			.map_err(|_| anyhow!("source-bound recovery artifact name is invalid"))?;
		if name.starts_with(".pending-") || super::super::valid_id(&name) {
			// A private pending stage is not a published candidate. The original owner
			// retains it; this recovery operation cannot promote it or create a candidate.
			continue;
		}
		check_id(&name)?;
		let manifest = read_manifest_metadata(&root, &name).await?;
		if matches(&manifest) {
			if found.is_some() {
				bail!("source-bound recovery has multiple matching published artifacts");
			}
			found = Some(read_manifest(&root, &name).await?);
		}
	}
	let candidate = found.ok_or_else(|| {
		anyhow!(
		"no exact published candidate exists; recovery remains unverified and no candidate was created"
	)
	})?;
	Ok((candidate, true))
}

async fn prepare(
	params: &RecoveryParams,
	roots: &[PathBuf],
	state: &Path,
	authority: Option<&crate::mcp::rea_model::session::weight::SessionAuthority>,
) -> Result<Prepared> {
	if !weight_config::valid_sha256(&params.original_source_sha256)
		|| !weight_config::valid_sha256(&params.expected_candidate_sha256)
	{
		bail!("source-bound recovery requires complete original and candidate SHA-256 values");
	}
	let intent = match authority {
		Some(authority) => {
			authority.check_bias_binding(&params.bias_binding)?;
			recovery::lock_existing_for_session(&params.journal_id, roots, state, authority).await?
		}
		None => recovery::lock_existing(&params.journal_id, roots, state).await?,
	};
	if intent
		.recorded_candidate_sha256
		.as_ref()
		.is_some_and(|sha| *sha != params.expected_candidate_sha256)
	{
		bail!("requested complete candidate hash differs from the original guard record");
	}
	let request = &intent.request;
	let bias = request.bias.as_deref().ok_or_else(|| {
		anyhow!("source-bound recovery requires the original explicit stored bias")
	})?;
	let columns = request.inputs.first().map_or(0, Vec::len);
	weight_forward::check_inputs(&request.inputs, Some(bias), bias.len(), columns)?;
	if request.patch.expected_sha256 != params.original_source_sha256
		|| !Path::new(&request.patch.path).is_absolute()
		|| Path::new(&request.patch.path).starts_with(state)
		|| !roots
			.iter()
			.any(|root| Path::new(&request.patch.path).starts_with(root))
		|| request.patch.edits.is_empty()
		|| request.patch.edits.len() > 1024
		|| request
			.patch
			.edits
			.iter()
			.any(|edit| edit.expected_hex.len() != 8 || edit.replacement_hex.len() != 8)
	{
		bail!("original recovery intent is not the exact bounded F32 workspace request");
	}
	let update_budget = request
		.max_update_l2_norm
		.map(|radius| weight_norm::check_edits(&request.patch.edits, radius))
		.transpose()?;
	if update_budget
		.as_ref()
		.is_some_and(|budget| !budget.within_budget)
	{
		bail!("original recovery request exceeds its exact F32 update radius");
	}
	let (candidate, discovered_without_candidate_record) = locate(params, &intent, state).await?;
	if candidate.patch.tensor_byte_length != (bias.len() * columns * 4) as u64 {
		bail!("original F32 recovery tensor extent differs from its recorded head dimensions");
	}
	let source_bound = source_bound_f32::SourceBoundParams {
		guard: intent.request.clone(),
		bias_binding: params.bias_binding.clone(),
	};
	let mut candidate_params = source_bound.clone();
	candidate_params.guard.patch.expected_sha256 = candidate.target_sha256.clone();
	let (mut file, _, committed) = open_pinned_artifact(&candidate.artifact_id, state).await?;
	if committed != params.expected_candidate_sha256 {
		bail!("candidate owner identity changed after exact recovery lookup");
	}
	let before = file.metadata().await?;
	let descriptor =
		rea_model::inspect_tensor_descriptor(&mut file, &intent.request.patch.tensor_name).await?;
	let tensor = &descriptor["result"]["tensor"];
	if tensor["dtype"] != "F32"
		|| tensor["shape"] != json!([bias.len().to_string(), columns.to_string()])
		|| tensor["file_offset"].as_u64() != Some(candidate.patch.tensor_file_offset)
		|| tensor["byte_length"].as_u64() != Some(candidate.patch.tensor_byte_length)
	{
		bail!("actual recovery candidate head differs from the original recorded dimensions");
	}
	let bound = source_bound_f32::authenticate_from_admitted(&candidate_params, &mut file).await?;
	rea_files::ensure_unchanged(&before, &file.metadata().await?)?;
	let bias_evidence = serde_json::to_value(bound.bias_evidence())?;
	drop(file);
	intent.revalidate().await?;
	Ok(Prepared {
		intent,
		source_bound,
		candidate,
		bias_evidence,
		update_budget: serde_json::to_value(update_budget)?,
		discovered_without_candidate_record,
	})
}

pub(super) async fn run_with_roots(
	params: RecoveryParams,
	roots: &[PathBuf],
	state: &Path,
) -> Result<Value> {
	run_scoped(params, roots, state, None).await
}

pub(super) async fn run_for_session(
	params: RecoveryParams,
	roots: &[PathBuf],
	state: &Path,
	authority: crate::mcp::rea_model::session::weight::SessionAuthority,
) -> Result<Value> {
	run_scoped(params, roots, state, Some(authority)).await
}

async fn run_scoped(
	params: RecoveryParams,
	roots: &[PathBuf],
	state: &Path,
	authority: Option<crate::mcp::rea_model::session::weight::SessionAuthority>,
) -> Result<Value> {
	let started = Instant::now();
	// This timeout is read-only. The admitted write phase below is retained to completion
	// by the existing owner task, even if the caller's response deadline expires.
	let prepared = tokio::time::timeout(
		Duration::from_secs(60),
		prepare(&params, roots, state, authority.as_ref()),
	)
	.await
	.context("source-bound recovery preflight exceeded 60 seconds; no inverse was requested")??;
	let intent_sha = prepared.intent.intent_sha256.clone();
	let candidate_id = prepared.candidate.artifact_id.clone();
	let request_sha =
		crate::mcp::rea_model::digest_hex(&Sha256::digest(serde_json::to_vec(&params)?));
	if let Some(authority) = &authority {
		authority.revalidate().await?;
	}
	let restoration = restore_with_state(&candidate_id, state).await?;
	let checked = async {
		if restoration["source_sha256"] != params.expected_candidate_sha256
			|| restoration["sha256"] != params.original_source_sha256
			|| restoration["source_modified"] != false
			|| restoration["production_eligible"] != false
		{
			bail!("canonical inverse receipt differs from the original recovery intent");
		}
		prepared.intent.revalidate().await?;
		let restored_id = restoration["artifact_id"]
			.as_str()
			.ok_or_else(|| anyhow!("canonical inverse has no artifact identity"))?;
		let fresh = tokio::time::timeout(
			Duration::from_secs(60),
			source_bound_f32::next_request_with_state(&prepared.source_bound, restored_id, state),
		)
		.await
		.context("restored artifact fresh-request deadline expired")??;
		prepared.intent.revalidate().await?;
		if let Some(authority) = &authority {
			authority.revalidate().await?;
		}
		Ok::<_, anyhow::Error>(fresh)
	}
	.await;
	let (verified, fresh, error) = match checked {
		Ok(fresh) => (true, fresh, None),
		Err(error) => (
			false,
			Value::Null,
			Some(error.to_string().chars().take(1024).collect::<String>()),
		),
	};
	Ok(json!({
		"schema":"hepta.weight.original-intent-f32-recovery.v1",
		"outcome":if verified {"restored_and_fresh_request_verified"} else {"restoration_or_fresh_request_unverified"},
		"accepted":false,"restoration_verified":verified,"recovery_error":error,
		"journal_id":params.journal_id,"original_intent_sha256":intent_sha,
		"original_completion_present":prepared.intent.original_completion_present,
		"original_candidate_record_present":prepared.intent.candidate_artifact_id.is_some(),
		"candidate_artifact_id":candidate_id,"candidate_sha256":params.expected_candidate_sha256,
		"original_source_sha256":params.original_source_sha256,
		"candidate_discovered_without_record":prepared.discovered_without_candidate_record,
		"candidate_bias_evidence":prepared.bias_evidence,"original_f32_update_budget":prepared.update_budget,
		"restoration":restoration,"new_request":fresh,"request_sha256":request_sha,
		"original_source_path_opened":false,"parent_forward_replayed":false,
		"candidate_forward_replayed":false,"new_candidate_published":false,
		"original_guard_records_modified":false,"original_journal_owner_lock_retained":true,
		"restored_head_forward_allowance":1,"prior_interrupted_call_cost_known":false,
		"response_deadline_seconds":420,"read_only_preflight_deadline_seconds":60,
		"fresh_restored_request_deadline_seconds":60,
		"native_operation_wall_seconds":started.elapsed().as_secs_f64(),
		"process_crash_observed_by_this_operation":false,"background_recovery":false,
		"full_model_executed":false,"feature_provenance_verified":false,
		"live_activation":false,"production_eligible":false,
		"scope":"explicit restore-first re-entry of an exact published F32 candidate using the original native intent; no original-path forward or new candidate"
	}))
}
