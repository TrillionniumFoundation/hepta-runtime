// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Explicit target-row identity, real source admission and zero-forward compilation controls.

use super::*;
use crate::mcp::{
	rea_model::session::{self, weight::smallhcsn as scope},
	weight_smallhcsn_proposal as proposal,
};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tokio::fs;

pub(super) fn table(parent: String, input: String) -> scope::ProposalInput {
	let digest = model::sha(b"synthetic target declaration; correctness is not measured");
	let mut rows = Vec::new();
	let mut values = Vec::new();
	// Deliberately use a noncanonical choice/tick/query transport order with explicit identities.
	for choice in 0..2 {
		for tick in [0, 2, 4] {
			for query in 0..80 {
				rows.push(scope::TargetRow {
					query,
					choice,
					tick,
				});
				values.push(if query % 2 == 0 {
					[0.0; 4]
				} else {
					[0.05, -0.05, 0.025, -0.025]
				});
			}
		}
	}
	scope::ProposalInput {
		parameters: proposal::CompileParams {
			parent_sha256: parent,
			input_sha256: input,
			trace_sha256: digest.clone(),
			target_source: hidden::TargetDeclaration {
				kind: hidden::TargetSourceKind::CallerSpecified,
				source_sha256: digest,
				description: "synthetic declared target".into(),
			},
			parent_correct: (0..80).map(|q| q % 2 == 0).collect(),
			target_delta_z: values,
			maximum_update_l2_norm: 0.1,
			dose: proposal::Dose::Full,
		},
		row_identities: rows,
	}
}

pub(super) fn fence_only_proposal(parent: String, input: String) -> scope::ProposalInput {
	table(parent, input)
}

#[test]
fn explicit_choice_major_rows_are_reordered_by_identity_and_never_implicitly_flattened() {
	let mut input = table("0".repeat(64), "1".repeat(64));
	for (row, value) in input
		.row_identities
		.iter()
		.zip(&mut input.parameters.target_delta_z)
	{
		*value = [((row.tick / 2) * 160 + row.query * 2 + row.choice) as f64; 4];
	}
	let canonical = compiler::canonical_parameters(&input).unwrap();
	for (index, value) in canonical.target_delta_z.iter().enumerate() {
		assert_eq!(*value, [index as f64; 4]);
	}
	let mut duplicate = input.clone();
	duplicate.row_identities[1] = duplicate.row_identities[0];
	assert!(compiler::canonical_parameters(&duplicate).is_err());
	let mut odd = input.clone();
	odd.row_identities[0].tick = 1;
	assert!(compiler::canonical_parameters(&odd).is_err());
	let mut short = input.clone();
	short.row_identities.pop();
	assert!(compiler::canonical_parameters(&short).is_err());
	let mut long = input;
	long.parameters.target_delta_z.push([0.0; 4]);
	assert!(compiler::canonical_parameters(&long).is_err());
}

#[test]
fn native_program_binds_rows_targets_source_profile_evaluator_and_pure_budget() {
	let input = table("0".repeat(64), "1".repeat(64));
	let p = compiler::program(&input, &"2".repeat(64), &"3".repeat(64), &"4".repeat(64)).unwrap();
	assert_eq!(p["maximum_pure_compile_seconds"], 5);
	assert_eq!(p["full_model_forward_calls"], 0);
	assert_eq!(p["target_trace_and_parent_correctness_verified"], false);
	let mut changed = input.clone();
	changed.parameters.target_delta_z[1][0] += 0.01;
	let q = compiler::program(&changed, &"2".repeat(64), &"3".repeat(64), &"4".repeat(64)).unwrap();
	assert_ne!(p["program_sha256"], q["program_sha256"]);
	let q = compiler::program(&input, &"5".repeat(64), &"3".repeat(64), &"4".repeat(64)).unwrap();
	assert_ne!(p["program_sha256"], q["program_sha256"]);
	let q = compiler::program(&input, &"2".repeat(64), &"3".repeat(64), &"6".repeat(64)).unwrap();
	assert_ne!(p["program_sha256"], q["program_sha256"]);
}

pub(super) fn raw_eighty() -> Vec<u8> {
	let mut bytes = b"HCSNIN1\0".to_vec();
	for value in [80u32, 6, 2, 9] {
		bytes.extend_from_slice(&value.to_le_bytes());
	}
	for value in std::iter::repeat_n(0.0f32, 9)
		.chain(std::iter::repeat_n(1.0f32, 10))
		.chain(std::iter::repeat_n(0.0f32, 80 * 108 + 160))
	{
		bytes.extend_from_slice(&value.to_le_bytes());
	}
	for _ in 0..80 {
		bytes.extend_from_slice(&0i64.to_le_bytes());
	}
	bytes
}

#[tokio::test]
async fn actual_snapshot_compile_and_prepare_recompute_the_plan_without_publication_or_forward() {
	let f = model::semantic_tests::fixture(false);
	let raw = raw_eighty();
	let mut profile: Value = serde_json::from_slice(&f.profile).unwrap();
	profile["input_sha256"] = json!(digest(&raw));
	profile["input_bytes"] = json!(raw.len());
	let profile_json = serde_json::to_string(&profile).unwrap();
	let parent_sha256 = digest(&f.artifact);
	let proposal = table(parent_sha256.clone(), digest(&raw));
	let temp = tempfile::tempdir().unwrap();
	fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
		.await
		.unwrap();
	let workspace = temp.path().join("workspace");
	fs::create_dir(&workspace).await.unwrap();
	let state = temp.path().join("state");
	runtime::init_runtime(
		serde_json::from_value(json!({
			"state_dir":state,"controller_workspace_roots":[workspace],
			"hosts":{"denied":{"ssh_target":"never-connect-native-compile-tests",
				"remote_state_dir":temp.path().join("unused"),"allow_execute":false,
				"allow_pty":false,"allow_write":false,"allow_job_network":false}}
		}))
		.unwrap(),
	)
	.unwrap();
	let path = workspace.join("canonical.safetensors");
	fs::write(&path, &f.artifact).await.unwrap();
	let opened = session::open(
		session::OpenModelSessionParams {
			path: path.to_string_lossy().into(),
			expected_sha256: parent_sha256.clone(),
		},
		"native-compile-owner",
		Arc::new(
			runtime::effect_owner_fence::admit_new_effect()
				.await
				.unwrap(),
		),
	)
	.await
	.unwrap();
	let opened: Value = serde_json::from_str(&opened).unwrap();
	let compile_input = scope::CompileInput {
		profile_json: profile_json.clone(),
		raw_input_hex: hex(&raw),
		proposal: proposal.clone(),
	};
	let params = scope::Params {
		session_id: opened["session_id"].as_str().unwrap().into(),
		parent_sha256,
		profile: scope::FixedProfile::SmallhcsnCenteredSenderDriveAndBias40V1,
		operation: scope::Operation::Compile {
			request: Box::new(compile_input.clone()),
		},
	};
	let authority = scope::admit_for_test(&params, "native-compile-owner")
		.await
		.unwrap();
	let compiled = compile(compile_input, authority.clone()).await.unwrap();
	assert_eq!(compiled["forward_calls"], 0);
	assert_eq!(compiled["pure_compiler_invocations_this_request"], 1);
	assert_eq!(
		compiled["compilation"]["actual_parent_words_and_raw_keys_verified"],
		true
	);
	assert_eq!(
		compiled["compilation"]["target_trace_and_parent_correctness_verified"],
		false
	);
	assert_eq!(
		compiled["compilation"]["native_compiler_report"]["actual_f32_budget"]["within_budget"],
		true
	);
	let plan: hidden::PlanParams = serde_json::from_value(compiled["plan"].clone()).unwrap();
	assert_eq!(plan.edits.len(), 40);
	let input = Input {
		profile_json,
		raw_input_hex: hex(&raw),
		plan,
		minimum_mse_gain: 0.0,
		proposal: Some(proposal),
		ndu: None,
	};
	let prepared = prepare(input.clone(), authority.clone()).await.unwrap();
	assert_eq!(prepared["forward_calls"], 0);
	assert_eq!(
		prepared["preparation_computation"]["pure_compiler_invocations"],
		1
	);
	assert_eq!(
		prepared["proposal_compilation"]["program"],
		compiled["compilation"]["program"]
	);
	assert_eq!(
		prepared["bound_identity"]["native_proposal_program_sha256"],
		compiled["compilation"]["program"]["program_sha256"]
	);
	let mut altered = input;
	altered.plan.identity.code_sha256 = "0".repeat(64);
	assert!(prepare(altered, authority)
		.await
		.unwrap_err()
		.to_string()
		.contains("caller plan differs"));
	for name in ["weight-artifacts-v1", "weight-cohort-journal-v1"] {
		assert!(!fs::try_exists(state.join(name)).await.unwrap());
	}
	assert_eq!(fs::read(path).await.unwrap(), f.artifact);
	// This control intentionally invokes three pure compilers: compile, prepare, rejected prepare.
	// All three consume numerical work; none invokes the six-tick model.
}
