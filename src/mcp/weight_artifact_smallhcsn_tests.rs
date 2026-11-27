// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Synthetic native admission, original-journal, non-replay and retained-inverse controls.
//! Authoring these controls does not execute any real checkpoint or consume research budgets.

use super::*;
use crate::mcp::rea_model::session::{
	self,
	weight::{smallhcsn as scope, SessionWeightRequest},
};
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::fs;

const OWNER_A: &str = "synthetic-smallhcsn-owner-a";
const OWNER_B: &str = "synthetic-smallhcsn-owner-b";

#[derive(Default)]
struct Hook {
	after_publication: bool,
	publication: Mutex<Option<Value>>,
	finished: Mutex<Option<Value>>,
	reached: tokio::sync::Notify,
	resume: tokio::sync::Notify,
	done: tokio::sync::Notify,
}
static HOOK: OnceLock<Arc<Hook>> = OnceLock::new();

pub(super) async fn after_publication(_directory: &Path, receipt: &Value) {
	if let Some(hook) = HOOK.get().filter(|hook| hook.after_publication) {
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

struct Case {
	_temp: tempfile::TempDir,
	roots: Vec<PathBuf>,
	state: PathBuf,
	path: PathBuf,
	parent: Vec<u8>,
	params: scope::Params,
	input: Input,
}

async fn open(path: &Path, parent: &str, owner: &str) -> String {
	let permit = Arc::new(
		runtime::effect_owner_fence::admit_new_effect()
			.await
			.unwrap(),
	);
	let text = session::open(
		session::OpenModelSessionParams {
			path: path.to_string_lossy().into(),
			expected_sha256: parent.into(),
		},
		owner,
		permit,
	)
	.await
	.unwrap();
	serde_json::from_str::<Value>(&text).unwrap()["session_id"]
		.as_str()
		.unwrap()
		.into()
}

async fn fixture(noop: bool) -> Case {
	let f = model::semantic_tests::fixture(false);
	let temp = tempfile::tempdir().unwrap();
	fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
		.await
		.unwrap();
	let workspace = temp.path().join("workspace");
	fs::create_dir(&workspace).await.unwrap();
	let state = temp.path().join("state");
	let config = serde_json::from_value(json!({
		"state_dir":state,"controller_workspace_roots":[workspace],
		"hosts":{"denied":{"ssh_target":"never-connect-smallhcsn-tests",
			"remote_state_dir":temp.path().join("unused"),"allow_execute":false,
			"allow_pty":false,"allow_write":false,"allow_job_network":false}}
	}))
	.unwrap();
	runtime::init_runtime(config).unwrap();
	let path = workspace.join("canonical.safetensors");
	fs::write(&path, &f.artifact).await.unwrap();
	let parent_sha = digest(&f.artifact);
	let mut candidate = f.artifact.clone();
	let replacement = if noop { 0.0f32 } else { 0.125f32 };
	candidate[f.drive_offset..f.drive_offset + 4].copy_from_slice(&replacement.to_le_bytes());
	let declared = digest(b"synthetic declared objective; not task truth");
	let input = Input {
		profile_json: String::from_utf8(f.profile).unwrap(),
		raw_input_hex: hex(&f.raw),
		minimum_mse_gain: 0.0,
		proposal: None,
		ndu: None,
		plan: hidden::PlanParams {
			scope: hidden::EditScope::SenderDriveAndBias,
			parent_sha256: parent_sha.clone(),
			candidate_sha256: digest(&candidate),
			header_sha256: f.header_sha256,
			input_sha256: digest(&f.raw),
			allowed_coordinates: vec![
				hidden::Coordinate::Weight { row: 0, column: 0 },
				hidden::Coordinate::Bias { row: 0 },
			],
			edits: vec![
				hidden::Edit {
					coordinate: hidden::Coordinate::Weight { row: 0, column: 0 },
					expected_hex: "00000000".into(),
					replacement_hex: hex(&replacement.to_le_bytes()),
				},
				hidden::Edit {
					coordinate: hidden::Coordinate::Bias { row: 0 },
					expected_hex: "00000000".into(),
					replacement_hex: "00000000".into(),
				},
			],
			maximum_update_l2_norm: 1.0,
			target_source: hidden::TargetDeclaration {
				kind: hidden::TargetSourceKind::CallerSpecified,
				source_sha256: declared.clone(),
				description: "synthetic native control".into(),
			},
			identity: Identity {
				code_sha256: declared.clone(),
				tensor_map_sha256: declared.clone(),
				data_manifest_sha256: declared.clone(),
				objective_sha256: declared.clone(),
				dependency_manifest_sha256: declared,
			},
		},
	};
	let id = open(&path, &parent_sha, OWNER_A).await;
	let params = scope::Params {
		session_id: id,
		parent_sha256: parent_sha,
		profile: scope::FixedProfile::SmallhcsnCenteredSenderDriveAndBias40V1,
		operation: scope::Operation::Prepare {
			request: Box::new(input.clone()),
		},
	};
	Case {
		_temp: temp,
		roots: vec![workspace],
		state,
		path,
		parent: f.artifact,
		params,
		input,
	}
}

async fn authority(case: &Case) -> Authority {
	scope::admit_for_test(&case.params, OWNER_A).await.unwrap()
}

async fn planned(case: &Case) -> Value {
	prepare(case.input.clone(), authority(case).await)
		.await
		.unwrap()
}

async fn execute(case: &Case, id: &str) -> Value {
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

async fn recover_case(case: &Case, id: &str) -> Value {
	recover(
		id.into(),
		case.input.plan.candidate_sha256.clone(),
		authority(case).await,
		runtime::effect_owner_fence::admit_new_effect()
			.await
			.unwrap(),
	)
	.await
	.unwrap()
}

async fn record_bytes(case: &Case, id: &str, name: &str) -> Vec<u8> {
	fs::read(
		case.state
			.join("weight-cohort-journal-v1")
			.join(id)
			.join(name),
	)
	.await
	.unwrap()
}

#[tokio::test]
async fn typed_initial_intent_matches_owner_bytes_and_rejects_conflicting_rewrites() {
	for research in [None, Some(json!({"owner":"original-owner","cost":0.25}))] {
		let directory = tempfile::tempdir().unwrap();
		fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
			.await
			.unwrap();
		let intent = Intent {
			schema: "hepta.weight.cohort-intent.v1".into(),
			request_digest: "1".repeat(64),
			artifact_id: "cohort-test-original".into(),
			manifest_sha256: "2".repeat(64),
			research,
		};
		let typed = serde_json::to_vec(&intent).unwrap();
		let via_value = serde_json::to_vec(&serde_json::to_value(&intent).unwrap()).unwrap();
		assert_ne!(
			typed, via_value,
			"the old intermediate Value reordered the record"
		);
		assert_eq!(
			serde_json::from_slice::<Intent>(&via_value).unwrap(),
			intent
		);
		journal::write_intent(directory.path(), &intent)
			.await
			.unwrap();
		assert_eq!(
			fs::read(directory.path().join("intent.json"))
				.await
				.unwrap(),
			typed
		);
		// The original publication path rechecks these exact typed bytes.
		write_record(directory.path(), "intent.json", &typed)
			.await
			.unwrap();
		journal::write_intent(directory.path(), &intent)
			.await
			.unwrap();
		let mut changed = intent;
		changed.request_digest = "3".repeat(64);
		assert!(journal::write_intent(directory.path(), &changed)
			.await
			.is_err());
		assert!(write_record(directory.path(), "intent.json", &via_value)
			.await
			.is_err());
		assert_eq!(
			fs::read(directory.path().join("intent.json"))
				.await
				.unwrap(),
			typed
		);
	}
}

#[tokio::test]
async fn legacy_value_encoded_unpublished_intent_keeps_bytes_and_spent_phase() {
	let case = fixture(false).await;
	let authority = authority(&case).await;
	let deadline = model::Deadline::new(Duration::from_secs(60));
	let prepared = preflight(
		case.input.clone(),
		&authority,
		&case.roots,
		&case.state,
		&deadline,
	)
	.await
	.unwrap();
	let saved = journal::Saved::new(
		&prepared,
		&authority,
		&case.roots,
		&case.state,
		journal::wall_clock_milliseconds().unwrap(),
		clock::begin().await.unwrap(),
	)
	.unwrap();
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
	// Preserve the old encoder deliberately. Recovery must consume this original
	// record, not repair/rewrite it or replay publication under a replacement key.
	journal::write(
		&directory,
		"intent.json",
		&serde_json::to_value(&intent).unwrap(),
		MAX_MANIFEST_BYTES,
	)
	.await
	.unwrap();
	let original = record_bytes(&case, saved.id(), "intent.json").await;
	assert_ne!(original, serde_json::to_vec(&intent).unwrap());
	journal::charge(&directory, &saved, journal::Phase::Parent)
		.await
		.unwrap();
	let charge = record_bytes(&case, saved.id(), "model-parent-charge.json").await;
	drop(lock);
	drop(prepared);
	fs::remove_file(&case.path).await.unwrap();
	let result = recover_case(&case, saved.id()).await;
	assert_eq!(result["candidate_publication_absent_verified"], true);
	assert_eq!(result["restored_bytes_verified"], false);
	assert_eq!(result["full_model_executed"], false);
	assert_eq!(result["original_source_path_opened"], false);
	assert_eq!(result["attempt_ledger"]["reserved_phase_count"], 1);
	assert_eq!(result["attempt_ledger"]["reserved_seconds"], 20);
	assert_eq!(result["attempt_ledger"]["completed_model_evaluations"], 0);
	assert_eq!(
		result["attempt_ledger"]["phases"][0]["interrupted_cost_unknown"],
		true
	);
	assert_eq!(
		record_bytes(&case, saved.id(), "intent.json").await,
		original
	);
	assert_eq!(
		record_bytes(&case, saved.id(), "model-parent-charge.json").await,
		charge
	);
	assert!(!journal::charged(&directory, journal::Phase::Candidate)
		.await
		.unwrap());
	assert!(!journal::charged(&directory, journal::Phase::Restored)
		.await
		.unwrap());
	assert!(!fs::try_exists(&case.path).await.unwrap());
}

#[tokio::test]
async fn fixed_prepare_authenticates_semantics_without_artifact_journal_or_model() {
	let case = fixture(false).await;
	for name in ["weight-artifacts-v1", "weight-cohort-journal-v1"] {
		assert!(!fs::try_exists(case.state.join(name)).await.unwrap());
	}
	let report = planned(&case).await;
	assert_eq!(report["forward_calls"], 0);
	assert_eq!(report["journal_written"], false);
	assert_eq!(report["candidate_sha256"], case.input.plan.candidate_sha256);
	assert_eq!(
		report["semantic_map"]["recurrent"]["potentially_active_elements"],
		48
	);
	assert_eq!(report["semantic_map"]["recurrent"]["inert_elements"], 144);
	assert_eq!(
		report["semantic_map"]["allowed_parameters"]["maximum_coordinates"],
		40
	);
	for name in ["weight-artifacts-v1", "weight-cohort-journal-v1"] {
		assert!(!fs::try_exists(case.state.join(name)).await.unwrap());
	}
	let mut tampered = case.input.clone();
	tampered.plan.candidate_sha256 = "0".repeat(64);
	assert!(prepare(tampered, authority(&case).await).await.is_err());
	assert!(scope::admit_for_test(&case.params, OWNER_B).await.is_err());
	assert_eq!(fs::read(&case.path).await.unwrap(), case.parent);
}

#[tokio::test]
async fn real_six_tick_noop_roundtrip_and_source_missing_same_id_reuse() {
	let case = fixture(true).await;
	let plan = planned(&case).await;
	let id = plan["journal_id"].as_str().unwrap();
	let result = execute(&case, id).await;
	assert_eq!(result["research_roundtrip_verified"], true, "{result}");
	assert_eq!(result["restored_bytes_verified"], true);
	assert_eq!(result["fresh_restored_model_matches_parent"], true);
	assert_eq!(result["attempt_ledger"]["reserved_phase_count"], 3);
	assert_eq!(result["attempt_ledger"]["completed_model_evaluations"], 3);
	assert_eq!(result["attempt_ledger"]["reserved_seconds"], 60);
	assert_eq!(
		result["parent_evaluation"]["metrics"]["output_sha256"],
		result["restored_evaluation"]["metrics"]["output_sha256"]
	);
	let intent = record_bytes(&case, id, "intent.json").await;
	let again = execute(&case, id).await;
	assert_eq!(again["reused_original_result"], true);
	assert_eq!(again["new_model_evaluations"], 0);
	assert_eq!(fs::read(&case.path).await.unwrap(), case.parent);
	fs::remove_file(&case.path).await.unwrap();
	let recovered = recover_case(&case, id).await;
	assert_eq!(recovered["restored_bytes_verified"], true);
	assert_eq!(recovered["new_model_evaluations"], 0);
	assert_eq!(
		recovered["restoration"]["artifact_id"],
		result["restoration"]["artifact_id"]
	);
	assert_eq!(record_bytes(&case, id, "intent.json").await, intent);
	assert!(!fs::try_exists(&case.path).await.unwrap());
}

#[tokio::test]
async fn rejected_quality_still_restores_actual_candidate_before_fresh_full_model() {
	let mut case = fixture(false).await;
	case.input.minimum_mse_gain = 1000.0;
	let plan = planned(&case).await;
	let result = execute(&case, plan["journal_id"].as_str().unwrap()).await;
	assert_eq!(result["candidate_quality_passed"], false);
	assert_eq!(result["research_roundtrip_verified"], false);
	assert_eq!(result["restored_bytes_verified"], true);
	assert_eq!(result["fresh_restored_model_matches_parent"], true);
	assert_eq!(result["attempt_ledger"]["completed_model_evaluations"], 3);
	assert_eq!(
		fs::read(result["restoration"]["artifact_path"].as_str().unwrap())
			.await
			.unwrap(),
		case.parent
	);
	assert_eq!(fs::read(&case.path).await.unwrap(), case.parent);
}

#[tokio::test]
async fn foreign_session_and_legacy_restore_cannot_cross_native_bound_intent() {
	let case = fixture(true).await;
	let plan = planned(&case).await;
	let id = plan["journal_id"].as_str().unwrap();
	let mut foreign = case.params.clone();
	foreign.session_id = open(&case.path, &case.params.parent_sha256, OWNER_B).await;
	let foreign_authority = scope::admit_for_test(&foreign, OWNER_B).await.unwrap();
	let foreign_plan = prepare(case.input.clone(), foreign_authority.clone())
		.await
		.unwrap();
	assert_ne!(foreign_plan["journal_id"], id);
	let result = execute(&case, id).await;
	assert!(recover(
		id.into(),
		case.input.plan.candidate_sha256.clone(),
		foreign_authority,
		runtime::effect_owner_fence::admit_new_effect()
			.await
			.unwrap()
	)
	.await
	.is_err());
	assert!(restore_with_state(
		RestoreCohortParams {
			request_id: "a".repeat(64),
			artifact_id: result["candidate"]["artifact_id"].as_str().unwrap().into(),
		},
		&case.state
	)
	.await
	.unwrap_err()
	.to_string()
	.contains("session-bound cohort"));
	let intent: Value =
		serde_json::from_slice(&record_bytes(&case, id, "intent.json").await).unwrap();
	assert_eq!(
		intent["research"]["authority"]["schema"],
		"hepta.rea.smallhcsn-sender-authority.v1"
	);
	assert!(intent["research"]["authority"]
		.get("allowed_readout")
		.is_none());
	assert_eq!(fs::read(&case.path).await.unwrap(), case.parent);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caller_cancellation_and_revocation_after_publication_keep_the_inverse() {
	let case = fixture(false).await;
	let plan = planned(&case).await;
	let id = plan["journal_id"].as_str().unwrap().to_owned();
	let hook = Arc::new(Hook {
		after_publication: true,
		..Hook::default()
	});
	assert!(HOOK.set(Arc::clone(&hook)).is_ok());
	let admitted = authority(&case).await;
	let input = case.input.clone();
	let permit = runtime::effect_owner_fence::admit_new_effect()
		.await
		.unwrap();
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
	let result = hook.finished.lock().unwrap().clone().unwrap();
	assert_eq!(result["restored_bytes_verified"], true, "{result}");
	assert_eq!(result["research_roundtrip_verified"], false);
	assert_eq!(result["session_authority_valid_after_effect"], false);
	assert_eq!(result["attempt_ledger"]["reserved_phase_count"], 1);
	assert_eq!(
		fs::read(result["restoration"]["artifact_path"].as_str().unwrap())
			.await
			.unwrap(),
		case.parent
	);
	assert_eq!(fs::read(&case.path).await.unwrap(), case.parent);
}

// Build an actual canonical publication with durable unknown charges, without pretending that a
// killed process finished a model. This tests the exact recovery owner and non-replay boundary.
async fn interrupted(case: &Case, created: u64, charge_restored: bool) -> (String, journal::Saved) {
	interrupted_clock(case, created, charge_restored, true).await
}

async fn interrupted_clock(
	case: &Case,
	created: u64,
	charge_restored: bool,
	has_boot_clock: bool,
) -> (String, journal::Saved) {
	let authority = authority(case).await;
	let deadline = model::Deadline::new(Duration::from_secs(60));
	let prepared = preflight(
		case.input.clone(),
		&authority,
		&case.roots,
		&case.state,
		&deadline,
	)
	.await
	.unwrap();
	let mut saved = journal::Saved::new(
		&prepared,
		&authority,
		&case.roots,
		&case.state,
		created,
		clock::begin().await.unwrap(),
	)
	.unwrap();
	if !has_boot_clock {
		saved.native_boot_clock = None;
	}
	let root = store_root(&case.state).await.unwrap();
	let _lock = lock_store(&root).await.unwrap();
	let directory = journal_directory(&case.state, saved.id()).await.unwrap();
	let intent = original_intent(
		&saved.manifest,
		&prepared.cohort.manifest_bytes,
		&case.roots,
		&case.state,
		Some(serde_json::to_value(&saved).unwrap()),
	)
	.unwrap();
	journal::write_intent(&directory, &intent).await.unwrap();
	journal::charge(&directory, &saved, journal::Phase::Parent)
		.await
		.unwrap();
	publish_prepared(prepared.cohort, &root, &directory, intent, Boundary::None)
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
	(saved.id().to_owned(), saved)
}

#[tokio::test]
async fn source_missing_recovery_never_replays_unknown_parent_or_candidate_charges() {
	let case = fixture(false).await;
	let (id, _) = interrupted(&case, journal::wall_clock_milliseconds().unwrap(), false).await;
	let intent = record_bytes(&case, &id, "intent.json").await;
	fs::remove_file(&case.path).await.unwrap();
	let result = recover_case(&case, &id).await;
	assert_eq!(result["original_source_path_opened"], false);
	assert_eq!(result["restored_bytes_verified"], true, "{result}");
	assert_eq!(result["research_roundtrip_verified"], false);
	assert_eq!(result["attempt_ledger"]["reserved_phase_count"], 3);
	assert_eq!(result["attempt_ledger"]["completed_model_evaluations"], 1);
	assert!(result["parent_evaluation"].is_null());
	assert!(result["candidate_evaluation"].is_null());
	assert_eq!(record_bytes(&case, &id, "intent.json").await, intent);
	assert!(!fs::try_exists(&case.path).await.unwrap());
}

#[tokio::test]
async fn all_charged_expired_and_backward_clock_attempts_restore_without_new_forward() {
	let mut case = fixture(false).await;
	let now = journal::wall_clock_milliseconds().unwrap();
	for (index, created, all_charged) in [
		(0, now, true),
		(1, now - 60001, false),
		(2, now + 60000, false),
	] {
		case.input.minimum_mse_gain = index as f64;
		let (id, _) = interrupted(&case, created, all_charged).await;
		let result = recover_case(&case, &id).await;
		assert_eq!(result["restored_bytes_verified"], true, "{result}");
		assert_eq!(result["research_roundtrip_verified"], false);
		assert_eq!(result["attempt_ledger"]["completed_model_evaluations"], 0);
		assert!(result["restored_evaluation"].is_null());
		assert_eq!(
			result["attempt_ledger"]["reserved_phase_count"],
			if all_charged { 3 } else { 2 }
		);
	}
}

async fn clock_denied_inverse(kind: &str) {
	let case = fixture(false).await;
	let (id, saved) = interrupted_clock(
		&case,
		journal::wall_clock_milliseconds().unwrap(),
		false,
		kind != "legacy",
	)
	.await;
	if let Some(mut observed) = saved.native_boot_clock.clone() {
		if kind == "reboot" {
			let changed = if observed.boot_id.starts_with('a') {
				"b"
			} else {
				"a"
			};
			observed.boot_id.replace_range(0..1, changed);
		} else {
			observed.boottime_nanoseconds = observed
				.boottime_nanoseconds
				.checked_add(60_000_000_000)
				.unwrap();
		}
		clock::observe_for_test(observed).unwrap();
	}
	// Inject a kernel observation while the wall interval is current, then exercise
	// the actual original inverse owner; this control never waits for real expiry.
	assert!(journal::wall_clock_milliseconds().unwrap() < saved.expires_unix_milliseconds);
	let intent = record_bytes(&case, &id, "intent.json").await;
	fs::remove_file(&case.path).await.unwrap();
	let result = recover_case(&case, &id).await;
	assert_eq!(result["restored_bytes_verified"], true, "{result}");
	assert_eq!(result["attempt_ledger"]["completed_model_evaluations"], 0);
	assert_eq!(result["attempt_ledger"]["reserved_phase_count"], 2);
	assert!(result["restored_evaluation"].is_null());
	assert_eq!(result["research_roundtrip_verified"], false);
	assert_eq!(record_bytes(&case, &id, "intent.json").await, intent);
	assert!(!fs::try_exists(&case.path).await.unwrap());
}

#[tokio::test]
async fn elapsed_boottime_with_in_range_wall_clock_restores_without_a_new_forward() {
	clock_denied_inverse("elapsed").await;
}

#[tokio::test]
async fn changed_kernel_boot_restores_without_a_new_forward() {
	clock_denied_inverse("reboot").await;
}

#[tokio::test]
async fn legacy_missing_original_boot_clock_restores_without_a_new_forward() {
	clock_denied_inverse("legacy").await;
}

#[tokio::test]
async fn changed_saved_input_and_candidate_identity_fail_before_new_model_or_inverse() {
	let case = fixture(false).await;
	let (id, _) = interrupted(&case, journal::wall_clock_milliseconds().unwrap(), true).await;
	let path = case
		.state
		.join("weight-cohort-journal-v1")
		.join(&id)
		.join("intent.json");
	let original = fs::read(&path).await.unwrap();
	let mut altered: Value = serde_json::from_slice(&original).unwrap();
	altered["research"]["input"]["minimum_mse_gain"] = json!(17.0);
	fs::write(&path, serde_json::to_vec(&altered).unwrap())
		.await
		.unwrap();
	assert!(recover(
		id.clone(),
		case.input.plan.candidate_sha256.clone(),
		authority(&case).await,
		runtime::effect_owner_fence::admit_new_effect()
			.await
			.unwrap()
	)
	.await
	.is_err());
	fs::write(&path, &original).await.unwrap();
	assert!(recover(
		id.clone(),
		"0".repeat(64),
		authority(&case).await,
		runtime::effect_owner_fence::admit_new_effect()
			.await
			.unwrap()
	)
	.await
	.is_err());
	assert!(!fs::try_exists(
		case.state
			.join("weight-cohort-journal-v1")
			.join(&id)
			.join("smallhcsn-recovery.json")
	)
	.await
	.unwrap());
	assert_eq!(record_bytes(&case, &id, "intent.json").await, original);
	let result = recover_case(&case, &id).await;
	assert_eq!(result["restored_bytes_verified"], true);
	assert_eq!(result["attempt_ledger"]["completed_model_evaluations"], 0);
}

#[test]
fn closed_hidden_wire_preserves_f32_json_and_rejects_readout_authority_and_paths() {
	let old = json!({"session_id":"rms1_test","parent_sha256":"0".repeat(64),
		"readout":{"weight_tensor":"w","weight_payload_sha256":"0".repeat(64),
			"bias_tensor":"b","bias_payload_sha256":"1".repeat(64),"outputs":2,"columns":2},
		"operation":{"kind":"f32_recover","journal_id":"wgj1_test","expected_candidate_sha256":"2".repeat(64),"candidate_artifact_id":null}});
	let old_typed: SessionWeightRequest = serde_json::from_value(old.clone()).unwrap();
	assert_eq!(serde_json::to_value(old_typed).unwrap(), old);
	let hidden = json!({"session_id":"rms1_test","parent_sha256":"0".repeat(64),
		"profile":"smallhcsn_centered_sender_drive_and_bias40_v1",
		"operation":{"kind":"smallhcsn_recover","journal_id":"1".repeat(64),"expected_candidate_sha256":"2".repeat(64)}});
	assert!(serde_json::from_value::<SessionWeightRequest>(hidden.clone()).is_ok());
	for field in [
		"readout",
		"owner",
		"path",
		"state_dir",
		"authority",
		"executable",
		"raw_input_hex",
	] {
		let mut forged = hidden.clone();
		forged[field] = json!("forged");
		assert!(
			serde_json::from_value::<SessionWeightRequest>(forged).is_err(),
			"{field}"
		);
	}
	let mut cross = old;
	cross["operation"] = hidden["operation"].clone();
	assert!(serde_json::from_value::<SessionWeightRequest>(cross).is_err());
}
struct FenceEnvironment(Vec<(&'static str, Option<std::ffi::OsString>)>);
impl Drop for FenceEnvironment {
	fn drop(&mut self) {
		for (key, value) in &self.0 {
			match value {
				Some(value) => std::env::set_var(key, value),
				None => std::env::remove_var(key),
			}
		}
	}
}

#[derive(Debug)]
struct NativeClient;
impl rmcp::ClientHandler for NativeClient {
	fn get_info(&self) -> rmcp::model::ClientConfig {
		rmcp::model::ClientConfig::new(
			rmcp::model::ClientCapabilities::default(),
			rmcp::model::Implementation::new("fixed-smallhcsn-fence-control", "0.0.0"),
		)
		.with_protocol_version(rmcp::model::ProtocolVersion::V_2025_11_25)
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_mcp_entry_rejects_all_hidden_variants_under_the_original_fence() {
	use rmcp::{
		service::{ClientLifecycleMode, ClientServiceExt},
		ServiceExt,
	};
	let case = fixture(false).await;
	let fence = case._temp.path().join("effect-owner");
	fs::create_dir(&fence).await.unwrap();
	fs::set_permissions(&fence, std::fs::Permissions::from_mode(0o700))
		.await
		.unwrap();
	for (name, bytes) in [
		(".owner.lock", Vec::new()),
		(
			".owner.json",
			serde_json::to_vec(&json!({
				"schema":"hepta-effect-owner-fence-v1","owner":"v4","epoch":7,"phase":"frozen",
				"state_root":case.state,"predecessor_state_root":null
			}))
			.unwrap(),
		),
	] {
		let path = fence.join(name);
		fs::write(&path, bytes).await.unwrap();
		fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
			.await
			.unwrap();
	}
	let keys = [
		"HEPTA_EFFECT_OWNER_FENCE_DIR",
		"HEPTA_EFFECT_OWNER_SELF",
		"HEPTA_EFFECT_OWNER_FENCE_REQUIRED",
	];
	let _environment = FenceEnvironment(
		keys.into_iter()
			.map(|key| (key, std::env::var_os(key)))
			.collect(),
	);
	std::env::set_var(keys[0], &fence);
	std::env::set_var(keys[1], "v4");
	std::env::set_var(keys[2], "1");
	let (client_io, server_io) = tokio::io::duplex(65536);
	let root = case.roots[0].clone();
	let task = tokio::spawn(async move {
		let server = crate::mcp::server::OctofsServer::with_root(root)
			.serve(server_io)
			.await
			.unwrap();
		let _ = server.waiting().await;
	});
	let client = tokio::time::timeout(
		Duration::from_secs(5),
		NativeClient.serve_with_lifecycle(client_io, ClientLifecycleMode::Initialize),
	)
	.await
	.unwrap()
	.unwrap();
	for operation in [
		scope::Operation::Plan {
			request: Box::new(case.input.clone()),
		},
		scope::Operation::Compile {
			request: Box::new(scope::CompileInput {
				profile_json: case.input.profile_json.clone(),
				raw_input_hex: case.input.raw_input_hex.clone(),
				proposal: super::compile_tests::fence_only_proposal(
					case.params.parent_sha256.clone(),
					case.input.plan.input_sha256.clone(),
				),
			}),
		},
		scope::Operation::Prepare {
			request: Box::new(case.input.clone()),
		},
		scope::Operation::Roundtrip {
			request: Box::new(case.input.clone()),
			expected_journal_id: "0".repeat(64),
		},
		scope::Operation::Recover {
			journal_id: "0".repeat(64),
			expected_candidate_sha256: case.input.plan.candidate_sha256.clone(),
		},
	] {
		let mut params = case.params.clone();
		params.operation = operation;
		let args = serde_json::to_value(params).unwrap();
		let reply = tokio::time::timeout(
			Duration::from_secs(10),
			client.call_tool(
				rmcp::model::CallToolRequestParams::new("rea_model_session_weight".to_owned())
					.with_arguments(args.as_object().unwrap().clone()),
			),
		)
		.await
		.unwrap()
		.unwrap();
		assert_eq!(reply.is_error, Some(true));
		let text = reply
			.content
			.iter()
			.find_map(|block| match block {
				rmcp::model::ContentBlock::Text(text) => Some(text.text.as_str()),
				_ => None,
			})
			.unwrap();
		assert!(text.contains("effect owner admission frozen"), "{text}");
	}
	for name in ["weight-artifacts-v1", "weight-cohort-journal-v1"] {
		assert!(!fs::try_exists(case.state.join(name)).await.unwrap());
	}
	assert_eq!(fs::read(&case.path).await.unwrap(), case.parent);
	drop(client);
	task.abort();
	let _ = task.await;
}
