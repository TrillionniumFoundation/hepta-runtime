// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Source-bound F16 supplied-row research through the existing cohort owner.
//! Both passing and failing candidates are reverse-published; no active model pointer is owned.

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

use super::super::super::{rea_files, runtime, weight_guard::f16};
use f16::reopen::{self, ReopenedHead, Version};
use f16::{CoupledF16Evaluation, CoupledF16EvaluationParams};

#[derive(Serialize)]
pub struct ResearchReport {
	schema: &'static str,
	request_sha256: String,
	bridge_selected_source_sha256: String,
	outcome: &'static str,
	preflight: CoupledF16Evaluation,
	publication: Option<Value>,
	candidate_readback: Option<ReopenedHead>,
	candidate_error: Option<String>,
	restoration: Option<Value>,
	restored_readback: Option<ReopenedHead>,
	restoration_error: Option<String>,
	supplied_row_condition_satisfied: bool,
	canonical_owner_invoked: bool,
	restore_attempted: bool,
	restored_bytes_and_predictions_verified: bool,
	crash_recovery_verified: bool,
	full_model_executed: bool,
	feature_provenance_verified: bool,
	live_activation: bool,
	production_eligible: bool,
}

fn implementation_sha256() -> String {
	super::digest(
		&[
			b"hepta.weight.f16-research-selected-source.v1\0".as_slice(),
			include_bytes!("weight_artifact_f16_research.rs").as_slice(),
			include_bytes!("weight_artifact_cohort.rs").as_slice(),
			include_bytes!("weight_guard_f16.rs").as_slice(),
			include_bytes!("weight_guard_f16_reopen.rs").as_slice(),
		]
		.concat(),
	)
}

fn error_text(error: anyhow::Error) -> String {
	format!("{error:#}").chars().take(2048).collect()
}

fn artifact_id(receipt: &Value) -> Result<&str> {
	receipt["artifact_id"]
		.as_str()
		.filter(|id| super::valid_id(id))
		.ok_or_else(|| {
			anyhow!("cohort response lacks a valid identity; reconcile the same request")
		})
}

fn check_receipt(receipt: &Value, source: &str, target: &str) -> Result<()> {
	if receipt["schema"] != "hepta.weight.native-cohort-receipt.v1"
		|| receipt["source_sha256"] != source
		|| receipt["sha256"] != target
		|| receipt["all_members_verified"] != true
		|| receipt["source_modified"] != false
		|| receipt["incumbent_pointer_modified"] != false
		|| receipt["production_eligible"] != false
	{
		bail!("canonical cohort receipt differs from the typed research commitment");
	}
	Ok(())
}

async fn verify_artifact(
	plan: &CoupledF16Evaluation,
	params: &CoupledF16EvaluationParams,
	id: &str,
	state: &Path,
	version: Version,
) -> Result<ReopenedHead> {
	let expected = match version {
		Version::Original => params.proposal.source_sha256.as_str(),
		Version::Candidate => plan.candidate_sha256(),
	};
	let (mut file, _, actual_sha) = super::open_pinned(id, state).await?;
	if actual_sha != expected {
		bail!("reopened cohort manifest does not match the typed source/candidate hash");
	}
	reopen::verify_from_admitted(plan, params, &mut file, version).await
}

fn bind_owner_request(
	plan: &CoupledF16Evaluation,
	implementation: &str,
) -> Result<Option<super::PatchParams>> {
	let Some(mut request) = plan.cohort_proposal().cloned() else {
		return Ok(None);
	};
	// Bind the inline rows, objective, constraints and thresholds to the existing owner's
	// original request key. A changed objective cannot reuse an earlier publication silently.
	request.identity.dependency_manifest_sha256 = super::digest(&serde_json::to_vec(&json!({
		"schema":"hepta.weight.f16-research-owner-binding.v1",
		"proposal_dependency_sha256":request.identity.dependency_manifest_sha256,
		"evaluation_request_sha256":plan.request_sha256(),
		"bridge_selected_source_sha256":implementation
	}))?);
	Ok(Some(request))
}

async fn run_with_roots(
	params: CoupledF16EvaluationParams,
	roots: &[PathBuf],
	state: &Path,
) -> Result<ResearchReport> {
	if !cfg!(target_os = "linux") {
		bail!("F16 cohort research publication requires Linux");
	}
	let (mut source, _) = rea_files::open_confined(Path::new(&params.proposal.path), roots).await?;
	let preflight = f16::evaluate_from_admitted(&params, &mut source).await?;
	drop(source);
	let implementation = implementation_sha256();
	let request_sha256 = preflight.request_sha256().to_owned();
	let owner_request = bind_owner_request(&preflight, &implementation)?;
	let mut report = ResearchReport {
		schema: "hepta.weight.f16-cohort-research.v1",
		request_sha256,
		bridge_selected_source_sha256: implementation,
		outcome: "keep_without_publication",
		preflight,
		publication: None,
		candidate_readback: None,
		candidate_error: None,
		restoration: None,
		restored_readback: None,
		restoration_error: None,
		supplied_row_condition_satisfied: false,
		canonical_owner_invoked: false,
		restore_attempted: false,
		restored_bytes_and_predictions_verified: false,
		crash_recovery_verified: false,
		full_model_executed: false,
		feature_provenance_verified: false,
		live_activation: false,
		production_eligible: false,
	};
	let Some(owner_request) = owner_request else {
		return Ok(report);
	};
	// The enclosing retained task owns the original cohort semaphore and effect fence.
	// Do not cancel this future at a deadline while an atomic publication may still finish.
	let publication = super::apply_with_roots(
		owner_request,
		roots,
		state,
		None,
		None,
		super::Boundary::None,
	)
	.await
	.context("F16 publication did not return; reconcile only the identical owner request")?;
	let candidate_id = artifact_id(&publication)?.to_owned();
	report.canonical_owner_invoked = true;
	report.publication = Some(publication.clone());
	let checked = async {
		check_receipt(
			&publication,
			&params.proposal.source_sha256,
			report.preflight.candidate_sha256(),
		)?;
		verify_artifact(
			&report.preflight,
			&params,
			&candidate_id,
			state,
			Version::Candidate,
		)
		.await
	}
	.await;
	match checked {
		Ok(readback) => {
			report.supplied_row_condition_satisfied = readback.supplied_row_condition_satisfied();
			report.candidate_readback = Some(readback);
		}
		Err(error) => report.candidate_error = Some(error_text(error)),
	}
	// No candidate remains selected, including a passing one. Reverse publication uses the
	// original cohort journal and inverse bytes; this layer creates no journal or live pointer.
	report.restore_attempted = true;
	let restore_request = super::RestoreCohortParams {
		request_id: super::digest(&serde_json::to_vec(&json!({
			"schema":"hepta.weight.f16-research-restore-key.v1",
			"request_sha256":report.request_sha256,
			"candidate_artifact_id":candidate_id
		}))?),
		artifact_id: candidate_id,
	};
	let recovered = super::restore_with_state(restore_request, state).await;
	match recovered {
		Ok(restoration) => {
			let checked = async {
				check_receipt(
					&restoration,
					report.preflight.candidate_sha256(),
					&params.proposal.source_sha256,
				)?;
				verify_artifact(
					&report.preflight,
					&params,
					artifact_id(&restoration)?,
					state,
					Version::Original,
				)
				.await
			}
			.await;
			report.restoration = Some(restoration);
			match checked {
				Ok(readback) => {
					report.restored_bytes_and_predictions_verified = true;
					report.restored_readback = Some(readback);
				}
				Err(error) => report.restoration_error = Some(error_text(error)),
			}
		}
		Err(error) => report.restoration_error = Some(error_text(error)),
	}
	report.outcome = if !report.restored_bytes_and_predictions_verified {
		"recovery_unverified"
	} else if report.supplied_row_condition_satisfied && report.candidate_error.is_none() {
		"supplied_row_pass_and_restored"
	} else {
		"supplied_row_reject_and_restored"
	};
	Ok(report)
}

/// One isolated research request; both passing and failing candidates are restored.
/// The existing owner retains task custody after caller cancellation. A process crash still
/// requires explicit same-request reconciliation; this API does not supply a new crash journal.
pub async fn run(params: CoupledF16EvaluationParams) -> Result<ResearchReport> {
	let config = runtime::runtime_config()?;
	let roots = config.controller_workspace_roots.clone();
	let state = config.state_dir.clone();
	let guards = super::owner_guards().await?;
	super::retained_transaction(guards, async move {
		run_with_roots(params, &roots, &state).await
	})
	.await
}

async fn next_request_with_state(
	params: &CoupledF16EvaluationParams,
	artifact_id: &str,
	state: &Path,
) -> Result<ReopenedHead> {
	let (mut file, _, source_sha) = super::open_pinned(artifact_id, state).await?;
	if source_sha != params.proposal.source_sha256 {
		bail!("new request requires the original complete checkpoint hash after restoration");
	}
	reopen::read_original_from_admitted(params, &mut file).await
}

/// Fresh owner admission and forward on an actual restored artifact; no prior report is trusted.
pub async fn next_request(
	params: &CoupledF16EvaluationParams,
	artifact_id: &str,
) -> Result<ReopenedHead> {
	let state = runtime::runtime_config()?.state_dir.clone();
	next_request_with_state(params, artifact_id, &state).await
}

#[cfg(all(test, target_os = "linux"))]
#[path = "weight_artifact_f16_research_tests.rs"]
mod tests;
