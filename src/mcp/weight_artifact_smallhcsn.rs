// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! One fixed-profile full-model attempt inside the original cohort owner and journal.
//! No public paths, alternate store, lifecycle registry or planner is introduced.

use super::*;
use crate::mcp::{
	rea_files,
	rea_model::session::weight::smallhcsn::{Authority, CompileInput, Input},
	runtime, weight_hidden_scope as hidden, weight_smallhcsn as model,
};
use anyhow::ensure;

use super::model_clock as clock;
#[cfg(all(test, target_os = "linux"))]
#[path = "weight_artifact_smallhcsn_compile_tests.rs"]
mod compile_tests;
#[path = "weight_artifact_smallhcsn_compile.rs"]
mod compiler;
#[path = "weight_artifact_smallhcsn_evaluation.rs"]
mod evaluation;
#[path = "weight_artifact_smallhcsn_execution.rs"]
mod execution;
#[path = "weight_artifact_smallhcsn_inverse.rs"]
mod inverse;
#[path = "weight_artifact_smallhcsn_journal.rs"]
mod journal;
#[path = "weight_artifact_smallhcsn_ndu.rs"]
mod ndu;
#[cfg(all(test, target_os = "linux"))]
#[path = "weight_artifact_smallhcsn_ndu_tests.rs"]
mod ndu_tests;
#[cfg(all(test, target_os = "linux"))]
#[path = "weight_artifact_smallhcsn_tests.rs"]
mod tests;

const ATTEMPT_SECONDS: u64 = 60;
const PHASE_SECONDS: u64 = 20;
const MAX_PROFILE_BYTES: usize = 49152;
const MAX_RAW_BYTES: usize = 65536;
const MAX_FIXED_ARTIFACT_BYTES: u64 = 131072;

fn budget() -> Value {
	json!({
		"schema":"hepta.smallhcsn.attempt-budget.v1",
		"normal_attempt_seconds":ATTEMPT_SECONDS,
		"phase_seconds":PHASE_SECONDS,"phases":["parent","candidate","restored"],
		"maximum_phase_reservations":3,"crash_refunds":false,"charged_phase_replay":false,
		"artifact_bytes":MAX_FIXED_ARTIFACT_BYTES,"profile_bytes":MAX_PROFILE_BYTES,
		"raw_input_bytes":MAX_RAW_BYTES,"queries":80,"choices":2,"ticks":6,
		"maximum_model_output_bytes":14800,"maximum_original_intent_bytes":MAX_MANIFEST_BYTES,
		"maximum_research_phase_record_bytes":4096,"maximum_research_records":10,
		"maximum_final_result_records":2,"maximum_final_result_record_bytes":48*1024,
		"response_bytes":60*1024,
		"original_native_clock_window_persisted":true,"recovery_restarts_window":false,
		"phase_deadline_is_cooperative":true,"os_hard_realtime_guarantee":false
	})
}

fn implementation() -> String {
	digest(
		&[
			include_bytes!("weight_artifact_smallhcsn.rs").as_slice(),
			include_bytes!("weight_artifact_smallhcsn_journal.rs").as_slice(),
			include_bytes!("weight_artifact_smallhcsn_evaluation.rs").as_slice(),
			include_bytes!("weight_artifact_smallhcsn_execution.rs").as_slice(),
			include_bytes!("weight_artifact_smallhcsn_inverse.rs").as_slice(),
			include_bytes!("weight_artifact_smallhcsn_compile.rs").as_slice(),
			include_bytes!("weight_artifact_smallhcsn_ndu.rs").as_slice(),
			include_bytes!("weight_artifact_smallhcsn_clock.rs").as_slice(),
			include_bytes!("weight_smallhcsn_ndu.rs").as_slice(),
			include_bytes!("../../qualification/weight_program_runtime_20261122/src/planner.rs")
				.as_slice(),
			include_bytes!("weight_smallhcsn_proposal.rs").as_slice(),
			include_bytes!("weight_smallhcsn_proposal_math.rs").as_slice(),
			include_bytes!("rea_model_session_smallhcsn.rs").as_slice(),
			include_bytes!("weight_hidden_scope.rs").as_slice(),
			include_bytes!("weight_hidden_scope_layout.rs").as_slice(),
			include_bytes!("weight_artifact_cohort.rs").as_slice(),
			include_bytes!("weight_artifact.rs").as_slice(),
			include_bytes!("weight_tensor.rs").as_slice(),
			include_bytes!("weight_norm.rs").as_slice(),
		]
		.concat(),
	)
}

fn request_id(
	input: &Input,
	authority: &Authority,
	roots: &[PathBuf],
	state: &Path,
) -> Result<String> {
	Ok(digest(&serde_json::to_vec(&json!({
		"schema":"hepta.smallhcsn.original-request.v1",
		"authority":authority.binding()?,"request":input,"roots":roots,"state":state,
		"evaluator":model::evaluator_identity(),"implementation":implementation(),"budget":budget()
	}))?))
}

fn binding(input: &Input, authority: &Authority, id: &str) -> Result<Value> {
	let mut value = json!({
		"schema":"hepta.smallhcsn.cohort-binding.v1","original_request_id":id,
		"authority":authority.binding()?,"parent_sha256":authority.parent_sha256(),
		"profile_sha256":digest(input.profile_json.as_bytes()),
		"raw_input_sha256":input.plan.input_sha256,
		"plan_sha256":digest(&serde_json::to_vec(&input.plan)?),
		"candidate_sha256":input.plan.candidate_sha256,
		"evaluator_sha256":model::evaluator_identity(),"implementation_sha256":implementation(),
		"budget_sha256":digest(&serde_json::to_vec(&budget())?),
		"fixed_scope":"smallhcsn_centered_sender_drive_and_bias40_v1"
	});
	if let Some(proposal) = &input.proposal {
		let program = compiler::program(
			proposal,
			&digest(input.profile_json.as_bytes()),
			&compiler::compiler_identity(),
			&model::evaluator_identity(),
		)?;
		value["native_proposal_program_sha256"] = program["program_sha256"].clone();
	}
	if let Some(program) = ndu::bound_program(input)? {
		value["finite_policy_program_sha256"] = program["program_sha256"].clone();
	}
	Ok(value)
}

fn decode_raw(text: &str) -> Result<Vec<u8>> {
	ensure!(
		text.len() <= MAX_RAW_BYTES * 2 && text.len().is_multiple_of(2) && text.is_ascii(),
		"bounded raw-input hex required"
	);
	let mut bytes = Vec::with_capacity(text.len() / 2);
	for word in text.as_bytes().chunks(16) {
		bytes.extend(weight_tensor::unhex(std::str::from_utf8(word)?)?);
	}
	Ok(bytes)
}

async fn capture(
	file: &mut tokio::fs::File,
	before: &std::fs::Metadata,
	expected: &str,
	deadline: &model::Deadline,
) -> Result<Vec<u8>> {
	ensure!(
		(10..=MAX_FIXED_ARTIFACT_BYTES).contains(&before.len()),
		"fixed artifact byte budget"
	);
	deadline.check()?;
	file.seek(std::io::SeekFrom::Start(0)).await?;
	let mut bytes = vec![0u8; before.len() as usize];
	file.read_exact(&mut bytes).await?;
	unchanged(before, &file.metadata().await?)?;
	ensure!(
		digest(&bytes) == expected,
		"complete admitted SmallHCSN bytes differ"
	);
	deadline.check()?;
	Ok(bytes)
}

struct Prepared {
	id: String,
	input: Input,
	parent: Vec<u8>,
	raw: Vec<u8>,
	plan: hidden::PreparedPlan,
	cohort: PreparedCohort,
	semantic: Value,
	proposal_evidence: Value,
	ndu_evidence: Value,
	preparation_computation: Value,
}

async fn preflight(
	input: Input,
	authority: &Authority,
	roots: &[PathBuf],
	state: &Path,
	deadline: &model::Deadline,
) -> Result<Prepared> {
	preflight_for_policy(input, authority, roots, state, deadline, true).await
}

async fn preflight_for_policy(
	input: Input,
	authority: &Authority,
	roots: &[PathBuf],
	state: &Path,
	deadline: &model::Deadline,
	require_execution: bool,
) -> Result<Prepared> {
	let started = std::time::Instant::now();
	authority.authorize(&input)?;
	authority.revalidate().await?;
	let id = request_id(&input, authority, roots, state)?;
	let raw = decode_raw(&input.raw_input_hex)?;
	ensure!(
		raw.len() <= MAX_RAW_BYTES && digest(&raw) == input.plan.input_sha256,
		"fixed raw-input bytes differ from the admitted plan"
	);
	let normalized = model::inputs(&raw)?;
	ensure!(
		(1..=80).contains(&normalized.queries()),
		"fixed model query budget"
	);
	let (mut file, before) =
		rea_files::open_confined(Path::new(authority.source_path()), roots).await?;
	let parent = capture(&mut file, &before, authority.parent_sha256(), deadline).await?;
	let bound = model::bind(input.profile_json.as_bytes(), &parent, &raw)?;
	ensure!(
		bound.canonical_sha256() == authority.parent_sha256(),
		"fixed full-model profile is not the canonical session parent"
	);
	let semantic = model::sender_semantic_map(&bound)?;
	let proposal_evidence = if let Some(proposal) = &input.proposal {
		let (compiled, evidence) = compiler::from_bound(
			proposal,
			input.profile_json.as_bytes(),
			&bound,
			&parent,
			&raw,
			std::time::Instant::now() + deadline.remaining()?.min(Duration::from_secs(5)),
		)?;
		ensure!(serde_json::to_vec(&compiled)? == serde_json::to_vec(&input.plan)?,
			"caller plan differs from the native shared proposal recompiled from actual parent/raw bytes");
		evidence
	} else {
		Value::Null
	};
	let ndu_evidence = ndu::select(
		&input,
		&proposal_evidence,
		std::time::Instant::now() + deadline.remaining()?.min(Duration::from_secs(5)),
	)?;
	if require_execution && input.ndu.is_some() {
		ensure!(
			ndu_evidence["execution_selected"] == true,
			"conditional finite policy selected STOP; no model or effect intent is permitted"
		);
	}
	let plan = hidden::prepare_with_deadline(
		&input.plan,
		&parent,
		std::time::Instant::now() + deadline.remaining()?.min(Duration::from_secs(5)),
	)?;
	let params = plan.cohort_request(authority.source_path().to_owned(), id.clone())?;
	let cohort = prepare_with_roots(
		params,
		roots,
		None,
		None,
		Some(binding(&input, authority, &id)?),
	)
	.await?;
	ensure!(
		cohort.manifest.target_sha256 == input.plan.candidate_sha256
			&& cohort.manifest.source_size_bytes == parent.len() as u64,
		"native cohort compiler differs from the exact hidden candidate"
	);
	// All preparation is read-only. A second complete source identity is authenticated by
	// the original cohort compiler; its descriptor-owned FD is kept for publication.
	authority.revalidate().await?;
	deadline.check()?;
	let preparation_computation = json!({
		"pure_compiler_invocations":u64::from(input.proposal.is_some()),
		"pure_compile_wall_seconds":proposal_evidence["pure_math_wall_seconds"],
		"math_and_materialization_wall_seconds":proposal_evidence["math_and_materialization_wall_seconds"],
		"source_admission_and_preparation_wall_seconds":started.elapsed().as_secs_f64(),
		"proposal_radius_checks":proposal_evidence["radius_checks"],
		"additional_radius_checks":{"prepared_plan_global":1,"canonical_cohort_members":2,"canonical_cohort_global":1},
		"finite_planner_invocations":u64::from(input.ndu.is_some()),
		"finite_planner_wall_seconds":ndu_evidence["planner_wall_seconds"],
		"finite_planner_work_admission":ndu_evidence["program"]["work_admission"],
		"model_forward_calls":0,"zero_forward_does_not_mean_zero_compute_cost":true
	});
	Ok(Prepared {
		id,
		input,
		parent,
		raw,
		plan,
		cohort,
		semantic,
		proposal_evidence,
		ndu_evidence,
		preparation_computation,
	})
}

pub(in crate::mcp) async fn compile(input: CompileInput, authority: Authority) -> Result<Value> {
	compiler::run(input, authority).await
}

pub(in crate::mcp) async fn prepare(input: Input, authority: Authority) -> Result<Value> {
	prepare_or_plan(input, authority, false).await
}

pub(in crate::mcp) async fn plan(input: Input, authority: Authority) -> Result<Value> {
	ensure!(
		input.ndu.is_some(),
		"fixed policy inspection requires an explicit declared finite law"
	);
	prepare_or_plan(input, authority, true).await
}

async fn prepare_or_plan(input: Input, authority: Authority, policy_only: bool) -> Result<Value> {
	let config = runtime::runtime_config()?;
	let deadline = model::Deadline::new(Duration::from_secs(ATTEMPT_SECONDS));
	let prepared = tokio::time::timeout(
		deadline.remaining()?,
		preflight_for_policy(
			input,
			&authority,
			&config.controller_workspace_roots,
			&config.state_dir,
			&deadline,
			!policy_only,
		),
	)
	.await
	.context("fixed SmallHCSN preparation exceeded its bounded read-only deadline")??;
	Ok(json!({
		"schema":"hepta.rea.smallhcsn-preparation.v1","journal_id":prepared.id,
		"conditional_policy_inspection_only":policy_only,
		"finite_policy":prepared.ndu_evidence,"whole_roundtrip_reservation_charged":false,
		"ndu_execution_binding":if prepared.input.proposal.is_some() {
			serde_json::to_value(ndu::execution_binding(&prepared.input,&compiler::compiler_identity(),&model::evaluator_identity(),&budget())?)?
		} else {Value::Null},
		"parent_sha256":authority.parent_sha256(),
		"candidate_sha256":prepared.cohort.manifest.target_sha256,
		"candidate_artifact_id":prepared.cohort.manifest.artifact_id,
		"bound_identity":prepared.cohort.manifest.research_binding,
		"semantic_map":prepared.semantic,"plan_evidence":prepared.plan.evidence(),"budget":budget(),
		"proposal_compilation":prepared.proposal_evidence,"preparation_computation":prepared.preparation_computation,
		"model_calls":0,"forward_calls":0,"candidate_published":false,
		"journal_written":false,"weight_artifact_store_written":false,
		"full_model_executed":false,"accepted_for_activation":false,"production_eligible":false
	}))
}

pub(in crate::mcp) async fn roundtrip(
	input: Input,
	expected_journal_id: String,
	authority: Authority,
	admission: runtime::effect_owner_fence::AdmissionPermit,
) -> Result<Value> {
	authority.authorize(&input)?;
	let config = runtime::runtime_config()?;
	let roots = config.controller_workspace_roots.clone();
	let state = config.state_dir.clone();
	ensure!(
		request_id(&input, &authority, &roots, &state)? == expected_journal_id,
		"fixed SmallHCSN request differs from its prepared original ID"
	);
	let guards = owner_guards_from_admission(admission).await?;
	retained_transaction(
		guards,
		execution::roundtrip(input, expected_journal_id, authority, roots, state),
	)
	.await
}

pub(in crate::mcp) async fn recover(
	id: String,
	expected_candidate_sha256: String,
	authority: Authority,
	admission: runtime::effect_owner_fence::AdmissionPermit,
) -> Result<Value> {
	ensure!(
		crate::mcp::weight_config::valid_sha256(&id)
			&& crate::mcp::weight_config::valid_sha256(&expected_candidate_sha256),
		"explicit recovery requires the original journal and candidate digests"
	);
	let config = runtime::runtime_config()?;
	let roots = config.controller_workspace_roots.clone();
	let state = config.state_dir.clone();
	let guards = owner_guards_from_admission(admission).await?;
	retained_transaction(
		guards,
		execution::recover(id, expected_candidate_sha256, authority, roots, state),
	)
	.await
}
