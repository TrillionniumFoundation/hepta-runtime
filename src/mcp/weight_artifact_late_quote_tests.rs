// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Synthetic full-kernel transaction controls, each run in an isolated test process.
//! These are engineering regressions, not new checkpoint or trading-quality evidence.

use super::*;
use crate::mcp::rea_model::session::{
	self,
	weight::{late_quote as scope, SessionWeightRequest},
};
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::fs;

pub(super) const OWNER_A: &str = "synthetic-late-quote-owner-a";
const OWNER_B: &str = "synthetic-late-quote-owner-b";

#[derive(Default)]
struct Hook {
	publication: Mutex<Option<Value>>,
	finished: Mutex<Option<Value>>,
	reached: tokio::sync::Notify,
	resume: tokio::sync::Notify,
	done: tokio::sync::Notify,
}
static HOOK: OnceLock<Arc<Hook>> = OnceLock::new();

pub(super) async fn after_publication(_directory: &Path, receipt: &Value) {
	if let Some(hook) = HOOK.get() {
		*hook.publication.lock().unwrap() = Some(receipt.clone());
		hook.reached.notify_one();
		hook.resume.notified().await;
	}
}

pub(super) fn completed(report: &Value) {
	if let Some(hook) = HOOK.get() {
		*hook.finished.lock().unwrap() = Some(report.clone());
		hook.done.notify_one();
	}
}

pub(super) struct Case {
	pub(super) _temp: tempfile::TempDir,
	pub(super) roots: Vec<PathBuf>,
	pub(super) state: PathBuf,
	pub(super) path: PathBuf,
	pub(super) parent: Vec<u8>,
	pub(super) params: scope::Params,
	pub(super) input: Input,
	pub(super) config: Value,
}

fn repin(profile: &mut Value, parent: &[u8], raw: &[u8]) {
	profile["input_sha256"] = json!(digest(raw));
	profile["input_bytes"] = json!(raw.len());
	let pin = &mut profile["profiles"][0];
	pin["canonical_sha256"] = json!(digest(parent));
	let start = 8 + pin["header_length"].as_u64().unwrap() as usize;
	for tensor in pin["tensors"].as_array_mut().unwrap() {
		let lo = start + tensor["data_offsets"][0].as_u64().unwrap() as usize;
		let hi = start + tensor["data_offsets"][1].as_u64().unwrap() as usize;
		tensor["sha256"] = json!(digest(&parent[lo..hi]));
	}
}

pub(super) async fn fixture(ready: bool, radius: f64) -> Case {
	let f = model::semantic_tests::fixture(false);
	let mut parent = f.artifact;
	let mut profile: Value = serde_json::from_slice(&f.profile).unwrap();
	let start = 8 + profile["profiles"][0]["header_length"].as_u64().unwrap() as usize;
	let offset = |name: &str| {
		start
			+ profile["profiles"][0]["tensors"]
				.as_array()
				.unwrap()
				.iter()
				.find(|v| v["name"] == name)
				.unwrap()["data_offsets"][0]
				.as_u64()
				.unwrap() as usize
	};
	let mark = offset("body.input_mark.weight");
	let readout = offset("body.readout.weight");
	for channel in 0..4 {
		// The zero-radius ready fixture already ranks correctly despite one wrong
		// coordinate. Its nonzero SIGN proposal must not prevent KEEP admission.
		let value: f32 = if ready && !(radius == 0.0 && channel == 0) {
			-0.25
		} else {
			0.25
		};
		let index = mark + (channel * 9 + 7) * 4;
		parent[index..index + 4].copy_from_slice(&value.to_le_bytes());
		let index = readout + (20 + channel * 5 + 2) * 4;
		parent[index..index + 4].copy_from_slice(&0.5f32.to_le_bytes());
	}
	let mut late_raw = f.raw;
	for (index, value) in [(97, 0.25f32), (106, -0.25f32)] {
		let offset = 100 + index * 4;
		late_raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
	}
	let label = late_raw.len() - 8;
	late_raw[label..].copy_from_slice(&1i64.to_le_bytes());
	let mut normal_raw = late_raw.clone();
	// A distinct normal-task target makes unconditional bridge routing fail.
	// Normal-route evaluation is not declared to be the lower-quote task.
	normal_raw[label..].copy_from_slice(&0i64.to_le_bytes());
	repin(&mut profile, &parent, &late_raw);
	let mut normal_profile = profile.clone();
	repin(&mut normal_profile, &parent, &normal_raw);
	let temp = tempfile::tempdir().unwrap();
	fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
		.await
		.unwrap();
	let workspace = temp.path().join("workspace");
	fs::create_dir(&workspace).await.unwrap();
	let state = temp.path().join("state");
	let config = json!({"state_dir":state,"controller_workspace_roots":[workspace],
		"hosts":{"denied":{"ssh_target":"never-connect-late-quote-tests",
			"remote_state_dir":temp.path().join("unused"),"allow_execute":false,
			"allow_pty":false,"allow_write":false,"allow_job_network":false}}});
	runtime::init_runtime(serde_json::from_value(config.clone()).unwrap()).unwrap();
	let path = workspace.join("canonical.safetensors");
	fs::write(&path, &parent).await.unwrap();
	let input = Input {
		profile_json: serde_json::to_string(&profile).unwrap(),
		raw_input_hex: hex(&late_raw),
		retention_profile_json: serde_json::to_string(&normal_profile).unwrap(),
		retention_raw_input_hex: hex(&normal_raw),
		minimum_accuracy_percent: 95,
		maximum_update_l2_norm: radius,
	};
	let permit = Arc::new(
		runtime::effect_owner_fence::admit_new_effect()
			.await
			.unwrap(),
	);
	let opened = session::open(
		session::OpenModelSessionParams {
			path: path.to_string_lossy().into(),
			expected_sha256: digest(&parent),
		},
		OWNER_A,
		permit,
	)
	.await
	.unwrap();
	let opened: Value = serde_json::from_str(&opened).unwrap();
	let params = scope::Params {
		session_id: opened["session_id"].as_str().unwrap().into(),
		parent_sha256: digest(&parent),
		profile: scope::FixedProfile::SmallhcsnLateQuoteMinMark4TaskRouteV1,
		operation: scope::Operation::Prepare {
			request: Box::new(input.clone()),
		},
	};
	Case {
		_temp: temp,
		roots: vec![workspace],
		state,
		path,
		parent,
		params,
		input,
		config,
	}
}

pub(super) async fn authority(case: &Case) -> Authority {
	scope::admit_for_test(&case.params, OWNER_A).await.unwrap()
}

pub(super) async fn planned(case: &Case) -> Value {
	prepare(case.input.clone(), authority(case).await)
		.await
		.unwrap()
}

pub(super) async fn execute(case: &Case, id: &str) -> Value {
	roundtrip(
		case.input.clone(),
		id.into(),
		authority(case).await,
		runtime::effect_owner_fence::admit_new_effect()
			.await
			.unwrap(),
	)
	.await
	.unwrap()
}

async fn try_recover(case: &Case, id: &str, plan: &str) -> Result<Value> {
	recover(
		id.into(),
		plan.into(),
		authority(case).await,
		runtime::effect_owner_fence::admit_new_effect()
			.await
			.unwrap(),
	)
	.await
}

pub(super) async fn recover_case(case: &Case, id: &str, plan: &str) -> Value {
	try_recover(case, id, plan).await.unwrap()
}

fn directory(case: &Case, id: &str) -> PathBuf {
	case.state.join("weight-cohort-journal-v1").join(id)
}

async fn bytes(case: &Case, id: &str, name: &str) -> Vec<u8> {
	fs::read(directory(case, id).join(name)).await.unwrap()
}

fn observation<'a>(phase: &'a Value, name: &str) -> &'a Value {
	phase["observations"]
		.as_array()
		.unwrap()
		.iter()
		.find(|row| row["name"] == name)
		.unwrap()
}

fn assert_inverse(report: &Value) {
	assert_eq!(
		report["weights_graph_route_initial_state_and_evaluator_restored"], true,
		"{report}"
	);
	let capsule = &report["restoration"]["function_capsule"];
	assert_eq!(capsule["function"]["graph"], "original");
	assert_eq!(
		capsule["function"]["request_route"],
		"original_fixed_profile"
	);
	assert_eq!(
		capsule["function"]["initial_state_contract"],
		"fixed_reset_step0_six_tick_v1"
	);
	assert_eq!(
		capsule["route_contract"]["late_request_requires_checked_task"],
		false
	);
	assert_eq!(report["source_modified"], false);
	assert_eq!(report["production_eligible"], false);
	assert_eq!(report["global_ndu_optimality_verified"], false);
}

#[tokio::test]
async fn prepare_binds_two_functions_without_forward_or_publication() {
	let case = fixture(false, 2.0).await;
	let plan = planned(&case).await;
	assert_eq!(plan["model_forward_calls"], 0);
	assert_eq!(plan["compilation_label_reads"], 0);
	assert_eq!(plan["journal_written"], false);
	assert_eq!(plan["candidate_published"], false);
	assert_eq!(plan["program"]["changed_f32_words"], 4);
	assert_eq!(
		plan["keep_function"]["artifact_sha256"],
		digest(&case.parent)
	);
	assert_ne!(plan["keep_function"], plan["parent_function"]);
	assert!(scope::admit_for_test(&case.params, OWNER_B).await.is_err());
	for name in ["weight-artifacts-v1", "weight-cohort-journal-v1"] {
		assert!(!fs::try_exists(case.state.join(name)).await.unwrap());
	}
	assert_eq!(fs::read(&case.path).await.unwrap(), case.parent);
}

#[tokio::test]
async fn same_sha_keep_restores_graph_and_reuses_without_source_or_model_replay() {
	let case = fixture(true, 2.0).await;
	let plan = planned(&case).await;
	let id = plan["journal_id"].as_str().unwrap();
	let plan_sha = plan["plan_sha256"].as_str().unwrap();
	assert_eq!(
		plan["parent_function"]["artifact_sha256"],
		plan["sign_function"]["artifact_sha256"]
	);
	let report = execute(&case, id).await;
	assert_eq!(report["selected_action"], "keep");
	assert_eq!(report["research_roundtrip_verified"], true, "{report}");
	assert_eq!(report["unconditional_graph_retention_passed"], false);
	assert_eq!(
		report["attempt_ledger"]["completed_forward_calls_with_durable_results"],
		7
	);
	assert_eq!(report["attempt_ledger"]["reserved_phase_count"], 3);
	assert_eq!(report["fresh_restored_complete_outputs_equal"], true);
	assert_eq!(
		report["candidate"]["sha256"],
		report["restoration"]["sha256"]
	);
	assert_ne!(
		report["candidate"]["artifact_id"],
		report["restoration"]["artifact_id"]
	);
	assert_ne!(
		report["candidate"]["function_capsule"],
		report["restoration"]["function_capsule"]
	);
	assert_inverse(&report);
	let original = bytes(&case, id, "late-intent.json").await;
	fs::remove_file(&case.path).await.unwrap();
	let recovered = recover_case(&case, id, plan_sha).await;
	assert_inverse(&recovered);
	assert_eq!(recovered["original_source_path_opened"], false);
	assert_eq!(recovered["new_complete_forward_results_this_request"], 0);
	assert_eq!(
		recovered["restoration"]["artifact_id"],
		report["restoration"]["artifact_id"]
	);
	assert_eq!(bytes(&case, id, "late-intent.json").await, original);
	assert!(!fs::try_exists(&case.path).await.unwrap());
}

#[tokio::test]
async fn sign_candidate_runs_actual_scoped_retention_and_complete_inverse() {
	let case = fixture(false, 2.0).await;
	let plan = planned(&case).await;
	let report = execute(&case, plan["journal_id"].as_str().unwrap()).await;
	assert_eq!(report["selected_action"], "sign");
	assert_eq!(report["research_roundtrip_verified"], true, "{report}");
	assert_eq!(
		report["attempt_ledger"]["completed_forward_calls_with_durable_results"],
		8
	);
	assert_eq!(report["unconditional_graph_accepted"], false);
	let scoped = observation(&report["candidate_evaluation"], "scoped_normal");
	assert_eq!(
		scoped["function"]["artifact_sha256"],
		report["candidate"]["sha256"]
	);
	assert_ne!(scoped["function"]["artifact_sha256"], digest(&case.parent));
	assert_eq!(scoped["function"]["graph"], "original");
	assert_inverse(&report);
	assert_eq!(
		fs::read(report["restoration"]["artifact_path"].as_str().unwrap())
			.await
			.unwrap(),
		case.parent
	);
}

#[tokio::test]
async fn zero_radius_keeps_a_ready_model_even_when_sign_is_inadmissible() {
	let case = fixture(true, 0.0).await;
	let plan = planned(&case).await;
	assert_eq!(plan["sign_admissible"], false);
	assert!(plan["sign_artifact_id"].is_null());
	let report = execute(&case, plan["journal_id"].as_str().unwrap()).await;
	assert_eq!(report["selected_action"], "keep");
	assert_eq!(report["candidate_goal_met"], true);
	assert_inverse(&report);
}

#[tokio::test]
async fn zero_radius_abstains_without_publishing_or_changing_the_budget() {
	let case = fixture(false, 0.0).await;
	let plan = planned(&case).await;
	assert_eq!(plan["sign_admissible"], false);
	let report = execute(&case, plan["journal_id"].as_str().unwrap()).await;
	assert_eq!(report["status"], "ABSTAIN_NO_ADMISSIBLE_EDIT");
	assert_eq!(report["selected_action"], "abstain");
	assert_eq!(report["candidate_publication_absent_verified"], true);
	assert_eq!(report["attempt_ledger"]["reserved_phase_count"], 1);
	assert_eq!(
		report["attempt_ledger"]["completed_forward_calls_with_durable_results"],
		3
	);
	assert!(report["candidate"].is_null());
	assert_eq!(fs::read(&case.path).await.unwrap(), case.parent);
}

#[tokio::test]
async fn compiler_ignores_labels_but_execution_rejects_false_task_targets() {
	let mut case = fixture(true, 2.0).await;
	let correct_plan = planned(&case).await;
	let mut raw = decode_raw(&case.input.raw_input_hex).unwrap();
	let at = raw.len() - 8;
	raw[at..].copy_from_slice(&0i64.to_le_bytes());
	let mut profile: Value = serde_json::from_str(&case.input.profile_json).unwrap();
	repin(&mut profile, &case.parent, &raw);
	case.input.profile_json = serde_json::to_string(&profile).unwrap();
	case.input.raw_input_hex = hex(&raw);
	let false_plan = planned(&case).await;
	assert_eq!(false_plan["program"], correct_plan["program"]);
	let report = execute(&case, false_plan["journal_id"].as_str().unwrap()).await;
	assert_eq!(report["candidate_publication_absent_verified"], true);
	assert_eq!(report["candidate_goal_met"], false);
	assert_eq!(
		report["attempt_ledger"]["completed_forward_calls_with_durable_results"],
		0
	);
	assert!(report["candidate"].is_null());
}

#[tokio::test]
async fn immutable_attempt_seal_and_decision_reject_clock_route_task_and_same_sha_tamper() {
	let case = fixture(true, 2.0).await;
	let plan = planned(&case).await;
	let id = plan["journal_id"].as_str().unwrap();
	let expected = plan["plan_sha256"].as_str().unwrap();
	execute(&case, id).await;
	let path = directory(&case, id).join("late-intent.json");
	let original = fs::read(&path).await.unwrap();
	let saved: Value = serde_json::from_slice(&original).unwrap();
	for kind in ["clock", "route", "task"] {
		let mut altered = saved.clone();
		match kind {
			"clock" => {
				altered["created_unix_ms"] = json!(saved["created_unix_ms"].as_u64().unwrap() + 1);
				altered["expires_unix_ms"] = json!(saved["expires_unix_ms"].as_u64().unwrap() + 1);
			}
			"route" => {
				altered["plan"]["keep_function"]["request_route"] = json!("original_fixed_profile")
			}
			_ => altered["plan"]["semantic_task"]["semantic_input_sha256"] = json!("a".repeat(64)),
		}
		fs::write(&path, serde_json::to_vec(&altered).unwrap())
			.await
			.unwrap();
		assert!(try_recover(&case, id, expected).await.is_err(), "{kind}");
		fs::write(&path, &original).await.unwrap();
	}
	let decision_path = directory(&case, id).join("late-decision.json");
	let original_decision = fs::read(&decision_path).await.unwrap();
	let mut decision: Value = serde_json::from_slice(&original_decision).unwrap();
	decision["action"] = json!("sign");
	decision["selected_artifact_id"] = plan["sign_artifact_id"].clone();
	decision["selected_function"] = plan["sign_function"].clone();
	fs::write(&decision_path, serde_json::to_vec(&decision).unwrap())
		.await
		.unwrap();
	assert!(try_recover(&case, id, expected).await.is_err());
	fs::write(&decision_path, original_decision).await.unwrap();
	assert!(try_recover(&case, id, &"b".repeat(64)).await.is_err());
	assert_eq!(
		recover_case(&case, id, expected).await["new_complete_forward_results_this_request"],
		0
	);
}

async fn saved_only(case: &Case, seal: bool) -> (Prepared, journal::Saved, PathBuf) {
	let prepared = compiler::preflight(
		case.input.clone(),
		&authority(case).await,
		&case.roots,
		&case.state,
	)
	.await
	.unwrap()
	.unwrap();
	let saved = journal::Saved::new(
		&prepared,
		journal::now_ms().unwrap(),
		clock::begin().await.unwrap(),
	)
	.unwrap();
	store_root(&case.state).await.unwrap();
	let directory = journal_directory(&case.state, &saved.journal_id)
		.await
		.unwrap();
	journal::write(
		&directory,
		"late-intent.json",
		&serde_json::to_value(&saved).unwrap(),
		MAX_MANIFEST_BYTES,
	)
	.await
	.unwrap();
	if seal {
		journal::write(
			&directory,
			"late-intent-seal.json",
			&saved.seal().unwrap(),
			4096,
		)
		.await
		.unwrap();
	}
	(prepared, saved, directory)
}

// An interrupted durable record fixture, not a claim that a process was killed.
// Real hard-kill/fresh-process qualification reuses the public fixture separately.
async fn interrupted(case: &Case, charge_restored: bool) -> journal::Saved {
	let (prepared, saved, directory) = saved_only(case, true).await;
	let deadline = model::Deadline::new(Duration::from_secs(60));
	let parent = evaluation::run(
		&directory,
		&saved,
		journal::Phase::Parent,
		None,
		prepared.parent.clone(),
		prepared.parent,
		&deadline,
	)
	.await
	.unwrap();
	let decision = journal::Decision::from_original_observation(&saved, &parent).unwrap();
	assert_eq!(decision.action, Action::Keep);
	journal::write(
		&directory,
		"late-decision.json",
		&serde_json::to_value(&decision).unwrap(),
		4096,
	)
	.await
	.unwrap();
	let root = store_root(&case.state).await.unwrap();
	let child = journal_directory(&case.state, &prepared.keep.manifest.request.request_id)
		.await
		.unwrap();
	publish_prepared(
		prepared.keep,
		&root,
		&child,
		inverse::candidate_intent(&saved, &decision).unwrap(),
		Boundary::None,
	)
	.await
	.unwrap();
	journal::charge(&directory, &saved, journal::Phase::Candidate)
		.await
		.unwrap();
	if charge_restored {
		journal::charge(&directory, &saved, journal::Phase::Restored)
			.await
			.unwrap();
	}
	saved
}

#[tokio::test]
async fn saved_without_seal_or_spent_parent_phase_never_replays_selection() {
	let case = fixture(true, 2.0).await;
	let (_, saved, directory) = saved_only(&case, false).await;
	assert!(try_recover(&case, &saved.journal_id, &saved.plan_sha256)
		.await
		.is_err());
	assert!(!journal::charged(&directory, journal::Phase::Parent)
		.await
		.unwrap());
	journal::write(
		&directory,
		"late-intent-seal.json",
		&saved.seal().unwrap(),
		4096,
	)
	.await
	.unwrap();
	journal::charge(&directory, &saved, journal::Phase::Parent)
		.await
		.unwrap();
	let charged = fs::read(directory.join("late-parent-charge.json"))
		.await
		.unwrap();
	fs::remove_file(&case.path).await.unwrap();
	let report = recover_case(&case, &saved.journal_id, &saved.plan_sha256).await;
	assert_eq!(report["candidate_publication_absent_verified"], true);
	assert_eq!(report["new_complete_forward_results_this_request"], 0);
	assert_eq!(report["attempt_ledger"]["reserved_phase_count"], 1);
	assert_eq!(
		report["attempt_ledger"]["unobserved_partial_work_possible"],
		true
	);
	assert_eq!(
		fs::read(directory.join("late-parent-charge.json"))
			.await
			.unwrap(),
		charged
	);
	assert!(!journal::charged(&directory, journal::Phase::Candidate)
		.await
		.unwrap());
}

#[tokio::test]
async fn source_missing_candidate_charge_restores_without_replaying_missing_suffix() {
	let case = fixture(true, 2.0).await;
	let saved = interrupted(&case, false).await;
	let id = &saved.journal_id;
	let charged = bytes(&case, id, "late-candidate-charge.json").await;
	fs::remove_file(&case.path).await.unwrap();
	let report = recover_case(&case, id, &saved.plan_sha256).await;
	assert_inverse(&report);
	assert_eq!(report["original_source_path_opened"], false);
	assert_eq!(report["new_complete_forward_results_this_request"], 2);
	assert_eq!(
		report["attempt_ledger"]["completed_forward_calls_with_durable_results"],
		5
	);
	assert!(report["candidate_evaluation"].is_null());
	assert_eq!(report["research_roundtrip_verified"], false);
	assert_eq!(
		bytes(&case, id, "late-candidate-charge.json").await,
		charged
	);
	assert_eq!(
		recover_case(&case, id, &saved.plan_sha256).await
			["new_complete_forward_results_this_request"],
		0
	);
}

async fn clock_inverse(reboot: bool) {
	let case = fixture(true, 2.0).await;
	let saved = interrupted(&case, false).await;
	let mut observed = saved.native_boot_clock.clone();
	if reboot {
		let changed = if observed.boot_id.starts_with('a') {
			"b"
		} else {
			"a"
		};
		observed.boot_id.replace_range(0..1, changed);
	} else {
		observed.boottime_nanoseconds += 60_000_000_000;
	}
	clock::observe_for_test(observed).unwrap();
	fs::remove_file(&case.path).await.unwrap();
	let report = recover_case(&case, &saved.journal_id, &saved.plan_sha256).await;
	assert_inverse(&report);
	assert_eq!(report["new_complete_forward_results_this_request"], 0);
	assert_eq!(report["attempt_ledger"]["reserved_phase_count"], 2);
	assert!(report["restored_evaluation"].is_null());
	assert_eq!(report["research_roundtrip_verified"], false);
}

#[tokio::test]
async fn changed_kernel_boot_keeps_exact_inverse_but_denies_new_forward() {
	clock_inverse(true).await;
}

#[tokio::test]
async fn expired_monotonic_window_keeps_exact_inverse_but_denies_new_forward() {
	clock_inverse(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_caller_and_revoked_session_cannot_drop_already_owned_inverse() {
	let case = fixture(true, 2.0).await;
	let plan = planned(&case).await;
	let id = plan["journal_id"].as_str().unwrap().to_owned();
	let admitted = authority(&case).await;
	let input = case.input.clone();
	let permit = runtime::effect_owner_fence::admit_new_effect()
		.await
		.unwrap();
	let hook = Arc::new(Hook::default());
	assert!(HOOK.set(Arc::clone(&hook)).is_ok());
	let task = tokio::spawn(async move { roundtrip(input, id, admitted, permit).await });
	tokio::time::timeout(Duration::from_secs(20), hook.reached.notified())
		.await
		.unwrap();
	let manifest = case
		.state
		.join("rea-model-sessions-v1")
		.join(&case.params.session_id)
		.join("manifest.json");
	fs::write(&manifest, b"{}").await.unwrap();
	task.abort();
	let _ = task.await;
	hook.resume.notify_one();
	tokio::time::timeout(Duration::from_secs(20), hook.done.notified())
		.await
		.unwrap();
	let report = hook.finished.lock().unwrap().clone().unwrap();
	assert_inverse(&report);
	assert_eq!(report["session_authority_valid_after_effect"], false);
	assert_eq!(report["research_roundtrip_verified"], false);
	assert_eq!(report["attempt_ledger"]["reserved_phase_count"], 1);
	assert_eq!(fs::read(&case.path).await.unwrap(), case.parent);
}

#[test]
fn closed_wire_refuses_graph_paths_scope_expansion_and_legacy_cross_profile() {
	let input = json!({"profile_json":"{}","raw_input_hex":"00",
		"retention_profile_json":"{}","retention_raw_input_hex":"00",
		"minimum_accuracy_percent":95,"maximum_update_l2_norm":0.0});
	let base = json!({"session_id":"a".repeat(64),"parent_sha256":"b".repeat(64),
		"profile":"smallhcsn_late_quote_min_mark4_task_route_v1",
		"operation":{"kind":"late_quote_prepare","request":input}});
	assert!(serde_json::from_value::<SessionWeightRequest>(base.clone()).is_ok());
	for key in ["path", "graph", "editable_indices", "owner"] {
		let mut altered = base.clone();
		altered["operation"]["request"][key] = json!("caller override");
		assert!(serde_json::from_value::<SessionWeightRequest>(altered).is_err());
	}
	let mut old_profile = base.clone();
	old_profile["profile"] = json!("smallhcsn_centered_sender_drive_and_bias40_v1");
	assert!(serde_json::from_value::<SessionWeightRequest>(old_profile).is_err());
	let mut recovery = base;
	recovery["operation"] = json!({"kind":"late_quote_recover","journal_id":"c".repeat(64),
		"expected_plan_sha256":"d".repeat(64),"candidate_sha256":"e".repeat(64)});
	assert!(serde_json::from_value::<SessionWeightRequest>(recovery).is_err());
}
