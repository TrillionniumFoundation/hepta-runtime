// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Source-admitted shared sender proposals with explicit row identities and measured cost.
//! This adapter performs pure bounded fitting, never a model forward or publication.

use super::*;
use crate::mcp::{
	rea_model::session::weight::smallhcsn::{CompileInput, ProposalInput},
	weight_smallhcsn_proposal as proposal,
};

pub(super) fn compiler_identity() -> String {
	digest(
		&[
			include_bytes!("weight_artifact_smallhcsn_compile.rs").as_slice(),
			include_bytes!("weight_smallhcsn_proposal.rs").as_slice(),
			include_bytes!("weight_smallhcsn_proposal_math.rs").as_slice(),
			include_bytes!("weight_hidden_scope.rs").as_slice(),
			include_bytes!("weight_hidden_scope_layout.rs").as_slice(),
			include_bytes!("weight_norm.rs").as_slice(),
		]
		.concat(),
	)
}

pub(super) fn canonical_parameters(input: &ProposalInput) -> Result<proposal::CompileParams> {
	ensure!(
		input.row_identities.len() == 480 && input.parameters.target_delta_z.len() == 480,
		"shared proposal requires exactly 480 explicitly identified target rows"
	);
	let mut seen = [false; 480];
	let mut parameters = input.parameters.clone();
	for (row, target) in input
		.row_identities
		.iter()
		.zip(&input.parameters.target_delta_z)
	{
		ensure!(
			row.query < 80 && row.choice < 2 && matches!(row.tick, 0 | 2 | 4),
			"shared proposal target row lies outside the fixed slow-tick profile"
		);
		let index = (row.tick / 2) * 160 + row.query * 2 + row.choice;
		ensure!(
			!seen[index],
			"duplicate shared proposal target row identity"
		);
		seen[index] = true;
		parameters.target_delta_z[index] = *target;
	}
	ensure!(
		seen.into_iter().all(|value| value),
		"incomplete shared target row identity set"
	);
	Ok(parameters)
}

pub(super) fn program(
	input: &ProposalInput,
	profile_sha256: &str,
	compiler_sha256: &str,
	evaluator_sha256: &str,
) -> Result<Value> {
	let parameters = canonical_parameters(input)?;
	let mut value = json!({
		"schema":"hepta.smallhcsn.shared-native-program.v1",
		"parent_sha256":parameters.parent_sha256,"raw_input_sha256":parameters.input_sha256,
		"profile_sha256":profile_sha256,"compiler_source_sha256":compiler_sha256,
		"evaluator_source_sha256":evaluator_sha256,
		"transport_proposal_sha256":digest(&serde_json::to_vec(input)?),
		"canonical_compiler_request_sha256":digest(&serde_json::to_vec(&parameters)?),
		"target_rows_sha256":digest(&serde_json::to_vec(&input.row_identities)?),
		"native_row_layout":"slow_tick_0_2_4_then_query_0_79_then_choice_0_1",
		"shared_parameters":40,"maximum_pure_compile_seconds":5,
		"target_trace_and_parent_correctness_verified":false,"full_model_forward_calls":0
	});
	value["program_sha256"] = json!(digest(&serde_json::to_vec(&value)?));
	Ok(value)
}

pub(super) fn from_bound(
	input: &ProposalInput,
	profile: &[u8],
	bound: &model::BoundModel,
	parent: &[u8],
	raw: &[u8],
	deadline: std::time::Instant,
) -> Result<(hidden::PlanParams, Value)> {
	let started = std::time::Instant::now();
	ensure!(
		started < deadline,
		"source-bound shared compile deadline exhausted"
	);
	let parameters = canonical_parameters(input)?;
	let semantic = model::sender_semantic_map(bound)?;
	let program = program(
		input,
		&digest(profile),
		&compiler_identity(),
		&model::evaluator_identity(),
	)?;
	let proposed = proposal::compile_with_deadline(&parameters, bound, raw, deadline)?;
	let (edits, math) = proposed.into_parts();
	ensure!(
		edits.len() == 40,
		"native shared compiler must account for all forty original F32 words"
	);
	let identity = Identity {
		code_sha256: compiler_identity(),
		tensor_map_sha256: semantic["semantic_map_sha256"]
			.as_str()
			.context("native tensor map identity")?
			.into(),
		data_manifest_sha256: parameters.input_sha256.clone(),
		objective_sha256: digest(&serde_json::to_vec(&parameters.target_source)?),
		dependency_manifest_sha256: program["program_sha256"]
			.as_str()
			.context("native program identity")?
			.into(),
	};
	let plan = hidden::plan_from_edits(
		parent,
		parameters.input_sha256.clone(),
		edits,
		parameters.maximum_update_l2_norm,
		parameters.target_source.clone(),
		identity,
		deadline,
	)?;
	let checks = math["additional_inward_corrections"]
		.as_u64()
		.context("native rounding correction count")?
		+ 1;
	let evidence = json!({
		"schema":"hepta.smallhcsn.shared-compilation.v1","program":program,
		"native_compiler_report":math,"plan_sha256":digest(&serde_json::to_vec(&plan)?),
		"candidate_sha256":plan.candidate_sha256,
		"compiler_invocations":1,"compiler_model_forward_calls":0,
		"pure_math_wall_seconds":math["wall_seconds"],
		"math_and_materialization_wall_seconds":started.elapsed().as_secs_f64(),
		"radius_checks":{"proposal_f32_realizations":checks,"materialized_plan_global":1},
		"row_identity_reordering_verified":true,"actual_parent_words_and_raw_keys_verified":true,
		"target_trace_and_parent_correctness_verified":false,"target_is_proved_ndu_objective":false,
		"zero_forward_does_not_mean_zero_compute_cost":true,
		"artifact_published":false,"journal_written":false,"production_eligible":false
	});
	Ok((plan, evidence))
}

pub(super) async fn run(input: CompileInput, authority: Authority) -> Result<Value> {
	authority.authorize_data(&input.profile_json, &input.raw_input_hex)?;
	ensure!(
		input.proposal.parameters.parent_sha256 == authority.parent_sha256(),
		"shared compiler cannot substitute a different session parent"
	);
	let config = runtime::runtime_config()?;
	let deadline = model::Deadline::new(Duration::from_secs(5));
	let started = std::time::Instant::now();
	let operation = async {
		authority.revalidate().await?;
		let raw = decode_raw(&input.raw_input_hex)?;
		let (mut file, before) = rea_files::open_confined(
			Path::new(authority.source_path()),
			&config.controller_workspace_roots,
		)
		.await?;
		let parent = capture(&mut file, &before, authority.parent_sha256(), &deadline).await?;
		let bound = model::bind(input.profile_json.as_bytes(), &parent, &raw)?;
		let (plan, evidence) = from_bound(
			&input.proposal,
			input.profile_json.as_bytes(),
			&bound,
			&parent,
			&raw,
			std::time::Instant::now() + deadline.remaining()?,
		)?;
		authority.revalidate().await?;
		deadline.check()?;
		Ok::<_, anyhow::Error>(json!({
			"schema":"hepta.rea.smallhcsn-native-compile.v1","plan":plan,
			"compilation":evidence,"semantic_map":model::sender_semantic_map(&bound)?,
			"pure_compiler_invocations_this_request":1,
			"source_admission_and_compile_wall_seconds":started.elapsed().as_secs_f64(),
			"model_calls":0,"forward_calls":0,"candidate_published":false,
			"journal_written":false,"weight_artifact_store_written":false,
			"accepted_for_activation":false,"production_eligible":false,
			"next_step":"submit this plan with the identical proposal/profile/raw input for zero-forward preparation; preparation and roundtrip each recompile and report their own cost"
		}))
	};
	tokio::time::timeout(deadline.remaining()?, operation)
		.await
		.context(
			"fixed source-bound shared compilation exceeded five seconds; no effect requested",
		)?
}
