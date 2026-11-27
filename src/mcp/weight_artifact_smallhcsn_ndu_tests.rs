// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Actual source admission, fixed-policy reservation and original inverse controls.
//! Synthetic publication controls do not execute a model or calibrate the law.

use super::*;
use crate::mcp::{
	rea_model::session::{self, weight::smallhcsn as scope},
	weight_smallhcsn_ndu as finite,
};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tokio::fs;

struct Case {
	_temp: tempfile::TempDir,
	path: PathBuf,
	parent: Vec<u8>,
	roots: Vec<PathBuf>,
	state: PathBuf,
	input: Input,
	authority: Authority,
}

async fn fixture() -> Case {
	let f = model::semantic_tests::fixture(false);
	let raw = compile_tests::raw_eighty();
	let mut profile: Value = serde_json::from_slice(&f.profile).unwrap();
	profile["input_sha256"] = json!(digest(&raw));
	profile["input_bytes"] = json!(raw.len());
	let profile_json = serde_json::to_string(&profile).unwrap();
	let parent_sha256 = digest(&f.artifact);
	let proposal = compile_tests::table(parent_sha256.clone(), digest(&raw));
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
			"hosts":{"denied":{"ssh_target":"never-connect-finite-policy-tests",
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
		"finite-policy-owner",
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
	let authority = scope::admit_for_test(&params, "finite-policy-owner")
		.await
		.unwrap();
	let compiled = compile(compile_input, authority.clone()).await.unwrap();
	let mut input = Input {
		profile_json,
		raw_input_hex: hex(&raw),
		plan: serde_json::from_value(compiled["plan"].clone()).unwrap(),
		minimum_mse_gain: 0.0,
		proposal: Some(proposal),
		ndu: None,
	};
	let prepared = prepare(input.clone(), authority.clone()).await.unwrap();
	input.ndu = Some(finite::Request {
		law: finite::DeclaredLaw {
			information_scope: "synthetic uncalibrated law".into(),
			utility_unit: "synthetic utility".into(),
			calibration_sha256: digest(b"declared calibration; not evidence"),
			verification_pass_probability: 0.8,
			use_gain_if_verified: 2.0,
			analytic_edit_utility_cost: 0.1,
			complete_verification_utility_cost: 0.2,
		},
		budget: finite::Budget {
			compute: 3,
			feedback: 3,
		},
		expected_execution: serde_json::from_value(prepared["ndu_execution_binding"].clone())
			.unwrap(),
	});
	// Exactly two pure compilers have run in fixture preparation. There are no model calls.
	Case {
		_temp: temp,
		path,
		parent: f.artifact,
		roots: vec![workspace],
		state,
		input,
		authority,
	}
}

#[tokio::test]
async fn actual_native_policy_binds_the_plan_and_upfront_intent_without_a_forward_or_write() {
	let case = fixture().await;
	let planned = plan(case.input.clone(), case.authority.clone())
		.await
		.unwrap();
	assert_eq!(planned["finite_policy"]["execution_selected"], true);
	assert_eq!(planned["conditional_policy_inspection_only"], true);
	assert_eq!(planned["whole_roundtrip_reservation_charged"], false);
	assert_eq!(planned["forward_calls"], 0);
	assert_eq!(
		planned["preparation_computation"]["finite_planner_invocations"],
		1
	);
	let deadline = model::Deadline::new(Duration::from_secs(60));
	let prepared = preflight(
		case.input.clone(),
		&case.authority,
		&case.roots,
		&case.state,
		&deadline,
	)
	.await
	.unwrap();
	let saved = journal::Saved::new(
		&prepared,
		&case.authority,
		&case.roots,
		&case.state,
		journal::wall_clock_milliseconds().unwrap(),
		clock::begin().await.unwrap(),
	)
	.unwrap();
	assert_eq!(saved.id(), planned["journal_id"].as_str().unwrap());
	assert_eq!(
		saved.ndu_evidence["program"],
		planned["finite_policy"]["program"]
	);
	assert_eq!(
		saved.ndu_evidence["upfront_reservation"]["compute_units"],
		3
	);
	assert_eq!(
		saved.ndu_evidence["upfront_reservation"]["feedback_units"],
		3
	);
	assert_eq!(
		saved.ndu_evidence["upfront_reservation"]["refund_on_failure_or_crash"],
		false
	);
	saved
		.validate(&case.authority, &case.roots, &case.state)
		.unwrap();
	let mut tampered = saved.clone();
	tampered.ndu_evidence["program"]["execution_binding"]["candidate_sha256"] =
		json!("0".repeat(64));
	assert!(tampered
		.validate(&case.authority, &case.roots, &case.state)
		.is_err());
	let mut underfunded = saved.clone();
	underfunded.ndu_evidence["upfront_reservation"]["compute_units"] = json!(1);
	assert!(underfunded
		.validate(&case.authority, &case.roots, &case.state)
		.is_err());
	for name in ["weight-artifacts-v1", "weight-cohort-journal-v1"] {
		assert!(!fs::try_exists(case.state.join(name)).await.unwrap());
	}
	assert_eq!(fs::read(&case.path).await.unwrap(), case.parent);
	// Four pure compilers and two finite solves; none is free or a six-tick evaluation.
}

#[tokio::test]
async fn original_bound_reservation_is_not_refunded_when_inverse_recovery_has_no_model_clock() {
	let case = fixture().await;
	let deadline = model::Deadline::new(Duration::from_secs(60));
	let prepared = preflight(
		case.input.clone(),
		&case.authority,
		&case.roots,
		&case.state,
		&deadline,
	)
	.await
	.unwrap();
	let mut saved = journal::Saved::new(
		&prepared,
		&case.authority,
		&case.roots,
		&case.state,
		journal::wall_clock_milliseconds().unwrap(),
		clock::begin().await.unwrap(),
	)
	.unwrap();
	// A legacy missing-clock intent is valid for exact compensation, never a fresh forward.
	saved.native_boot_clock = None;
	let root = store_root(&case.state).await.unwrap();
	let lock = lock_store(&root).await.unwrap();
	let directory = journal_directory(&case.state, saved.id()).await.unwrap();
	let intent = original_intent(
		&saved.manifest,
		&prepared.cohort.manifest_bytes,
		&case.roots,
		&case.state,
		Some(serde_json::to_value(&saved).unwrap()),
	)
	.unwrap();
	journal::write(
		&directory,
		"intent.json",
		&serde_json::to_value(&intent).unwrap(),
		MAX_MANIFEST_BYTES,
	)
	.await
	.unwrap();
	journal::charge(&directory, &saved, journal::Phase::Parent)
		.await
		.unwrap();
	publish_prepared(prepared.cohort, &root, &directory, intent, Boundary::None)
		.await
		.unwrap();
	journal::charge(&directory, &saved, journal::Phase::Candidate)
		.await
		.unwrap();
	drop(lock);
	fs::remove_file(&case.path).await.unwrap();
	let before = fs::read(directory.join("intent.json")).await.unwrap();
	let result = recover(
		saved.id().into(),
		case.input.plan.candidate_sha256.clone(),
		case.authority,
		runtime::effect_owner_fence::admit_new_effect()
			.await
			.unwrap(),
	)
	.await
	.unwrap();
	assert_eq!(result["restored_bytes_verified"], true, "{result}");
	assert_eq!(result["attempt_ledger"]["reserved_phase_count"], 2);
	assert_eq!(result["attempt_ledger"]["completed_model_evaluations"], 0);
	assert_eq!(
		result["original_finite_policy"]["upfront_reservation"]["compute_units"],
		3
	);
	assert_eq!(
		result["finite_policy_observation"]["unused_reservation_refunded"],
		false
	);
	assert_eq!(
		result["finite_policy_observation"]["actual_utility_gain_verified"],
		false
	);
	assert_eq!(result["finite_planner_invocations_this_request"], 0);
	assert_eq!(result["pure_compiler_invocations_this_request"], 0);
	assert!(result["observed_fixed_data_change"]["observed_mse_gain"].is_null());
	assert_eq!(
		fs::read(directory.join("intent.json")).await.unwrap(),
		before
	);
	assert!(!fs::try_exists(&case.path).await.unwrap());
	// Three pure compilers and one finite solve occurred before the original intent.
	// The synthetic interruption and actual inverse use zero model evaluations.
}

#[test]
fn a_passing_zero_threshold_noop_is_not_reported_as_strict_gain_or_verified_ndu_utility() {
	let parent = json!({"model_completed":true,"metrics":{"queries":1,"mse":1.0,"correct":1,"physical_valid":true}});
	assert!(evaluation::quality(&parent, &parent, 0.0).unwrap());
	let unchanged = evaluation::observed_gain(&parent, &parent);
	assert_eq!(unchanged["observed_mse_gain"], 0.0);
	assert_eq!(unchanged["delta_correct"], 0);
	assert_eq!(unchanged["strict_improvement"], false);
	let mut better = parent.clone();
	better["metrics"]["mse"] = json!(0.5);
	assert_eq!(
		evaluation::observed_gain(&parent, &better)["strict_improvement"],
		true
	);
	assert_eq!(
		evaluation::observed_gain(&parent, &better)["declared_ndu_use_gain_verified"],
		false
	);
	let policy =
		json!({"program":{"program_sha256":"a".repeat(64)},"expected_declared_net_gain":1000.0});
	let observation = ndu::observed(&policy, true, true);
	assert_eq!(observation["actual_utility_gain_verified"], false);
	assert_eq!(observation["candidate_remains_active"], false);
}
