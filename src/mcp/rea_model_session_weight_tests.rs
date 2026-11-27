// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Real session admission, scoped original intents, exact inverse and denial controls.

use super::*;
use crate::mcp::{runtime, weight_artifact::cohort::f32_recovery, weight_guard::source_bound_f32};
use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

const OWNER_A: &str = "credential-owner-a";
const OWNER_B: &str = "credential-owner-b";

#[derive(Default)]
struct Boundary {
	observed: Mutex<Option<Value>>,
	finished: Mutex<Option<Value>>,
	reached: tokio::sync::Notify,
	resume: tokio::sync::Notify,
	done: tokio::sync::Notify,
}
static BOUNDARY: OnceLock<Arc<Boundary>> = OnceLock::new();

// A single nextest-isolated control installs this gate. No hook exists in production builds.
pub(super) async fn after_guard(guard: &Value) {
	if let Some(boundary) = BOUNDARY.get() {
		*boundary.observed.lock().unwrap() = Some(guard.clone());
		boundary.reached.notify_one();
		boundary.resume.notified().await;
	}
}

pub(super) fn completed(report: &Value) {
	if let Some(boundary) = BOUNDARY.get() {
		*boundary.finished.lock().unwrap() = Some(report.clone());
		boundary.done.notify_one();
	}
}

struct Case {
	_temp: tempfile::TempDir,
	state: PathBuf,
	path: PathBuf,
	source: Vec<u8>,
	candidate_sha: String,
	params: SessionWeightParams,
	input: F32GuardInput,
}

async fn fixture() -> Case {
	let temp = tempfile::tempdir().unwrap();
	fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
	let workspace = temp.path().join("workspace");
	fs::create_dir(&workspace).unwrap();
	let state = temp.path().join("state");
	let config = serde_json::from_value(json!({
		"state_dir":state,"controller_workspace_roots":[workspace],"hosts":{}
	}))
	.unwrap();
	runtime::init_runtime(config).unwrap();
	let mut header = serde_json::to_vec(&json!({
		"readout.weight":{"dtype":"F32","shape":[2,2],"data_offsets":[0,16]},
		"readout.bias":{"dtype":"F32","shape":[2],"data_offsets":[16,24]},
		"physics":{"dtype":"F64","shape":[1],"data_offsets":[24,32]}
	}))
	.unwrap();
	while !header.len().is_multiple_of(8) {
		header.push(b' ');
	}
	let offset = 8 + header.len();
	let mut source = (header.len() as u64).to_le_bytes().to_vec();
	source.extend(header);
	let weights: Vec<u8> = [1_f32, 0.0, 0.0, 1.0]
		.iter()
		.flat_map(|value| value.to_le_bytes())
		.collect();
	let bias: Vec<u8> = [0.5_f32, -0.5]
		.iter()
		.flat_map(|value| value.to_le_bytes())
		.collect();
	source.extend(&weights);
	source.extend(&bias);
	source.extend(0.25_f64.to_le_bytes());
	let mut candidate = source.clone();
	candidate[offset..offset + 4].copy_from_slice(&2_f32.to_le_bytes());
	let path = workspace.join("original.safetensors");
	fs::write(&path, &source).unwrap();
	let opened = super::super::open_with_admission(
		&super::super::Scope::current(OWNER_A).unwrap(),
		&super::super::OpenModelSessionParams {
			path: path.to_string_lossy().into(),
			expected_sha256: super::super::hash(&source),
		},
		(),
	)
	.await
	.unwrap();
	let input = F32GuardInput {
		edits: vec![ExactElementEdit {
			index: 0,
			expected_hex: "0000803f".into(),
			replacement_hex: "00000040".into(),
		}],
		inputs: vec![vec![1.0, 2.0]],
		bias: vec![0.5, -0.5],
		objective: Objective::SquaredError {
			targets: vec![vec![2.5, 1.5]],
		},
		minimum_gain: 0.0,
		constraints: Vec::new(),
		maximum_update_l2_norm: 1.0,
	};
	let params = SessionWeightParams {
		session_id: opened["session_id"].as_str().unwrap().into(),
		parent_sha256: super::super::hash(&source),
		readout: ReadoutScope {
			weight_tensor: "readout.weight".into(),
			weight_payload_sha256: super::super::hash(&weights),
			bias_tensor: "readout.bias".into(),
			bias_payload_sha256: super::super::hash(&bias),
			outputs: 2,
			columns: 2,
		},
		operation: SessionWeightOperation::Prepare {
			request: Box::new(input.clone()),
		},
	};
	Case {
		_temp: temp,
		state,
		path,
		source,
		candidate_sha: super::super::hash(&candidate),
		params,
		input,
	}
}

async fn call(params: SessionWeightParams, owner: &str) -> Result<Value> {
	Ok(serde_json::from_str(
		&run_for_owner(params, owner, true).await?,
	)?)
}

async fn plan(case: &Case) -> Value {
	let result = call(case.params.clone(), OWNER_A).await.unwrap();
	assert_eq!(
		result["result"]["expected_candidate_sha256"],
		case.candidate_sha
	);
	assert_eq!(result["result"]["forward_calls"], 0);
	assert_eq!(result["result"]["journal_written"], false);
	assert!(!case.state.join("weight-guard-journal-v1").exists());
	result
}

fn roundtrip_params(case: &Case, id: &str) -> SessionWeightParams {
	let mut params = case.params.clone();
	params.operation = SessionWeightOperation::Roundtrip {
		request: Box::new(case.input.clone()),
		expected_journal_id: id.into(),
	};
	params
}

fn recovery_params(case: &Case, id: &str, candidate: &Value) -> SessionWeightParams {
	let mut params = case.params.clone();
	params.operation = SessionWeightOperation::Recover {
		journal_id: id.into(),
		expected_candidate_sha256: case.candidate_sha.clone(),
		candidate_artifact_id: candidate["artifact_id"].as_str().map(str::to_owned),
	};
	params
}

fn private_manifest(case: &Case) -> PathBuf {
	case.state
		.join("rea-model-sessions-v1")
		.join(&case.params.session_id)
		.join("manifest.json")
}

fn journals(case: &Case) -> Vec<PathBuf> {
	let root = case.state.join("weight-guard-journal-v1");
	if !root.exists() {
		return Vec::new();
	}
	fs::read_dir(root)
		.unwrap()
		.map(|entry| entry.unwrap().path())
		.filter(|path| {
			path.file_name()
				.unwrap()
				.to_string_lossy()
				.starts_with("wgj1_")
		})
		.collect()
}

#[tokio::test]
async fn session_roundtrip_and_source_missing_original_intent_recovery() {
	let case = fixture().await;
	let prepared = plan(&case).await;
	let id = prepared["result"]["journal_id"].as_str().unwrap();
	let report = call(roundtrip_params(&case, id), OWNER_A).await.unwrap();
	let result = &report["result"];
	assert_eq!(result["journal_id"], id);
	assert_eq!(result["guard"]["accepted"], true);
	assert_eq!(result["research_roundtrip_verified"], true);
	assert_eq!(result["restoration"]["sha256"], case.params.parent_sha256);
	assert_eq!(
		result["new_request"]["forward"]["outputs"],
		json!([[1.5, 1.5]])
	);
	assert_eq!(fs::read(&case.path).unwrap(), case.source);
	let repeated = call(roundtrip_params(&case, id), OWNER_A)
		.await
		.unwrap_err();
	assert!(repeated.to_string().contains("already exists"));
	let intent_path = case
		.state
		.join("weight-guard-journal-v1")
		.join(id)
		.join("intent.json");
	let original_intent = fs::read(&intent_path).unwrap();
	let intent: Value = serde_json::from_slice(&original_intent).unwrap();
	assert_eq!(
		intent["session_authority"]["session_id"],
		case.params.session_id
	);
	assert_eq!(
		intent["session_authority"]["allowed_readout"]["weight_tensor"],
		"readout.weight"
	);
	fs::remove_file(&case.path).unwrap();
	let recovered = call(recovery_params(&case, id, &result["candidate"]), OWNER_A)
		.await
		.unwrap();
	assert_eq!(recovered["result"]["restoration_verified"], true);
	assert_eq!(recovered["result"]["parent_forward_replayed"], false);
	assert_eq!(recovered["result"]["original_source_path_opened"], false);
	assert_eq!(
		recovered["result"]["restoration"]["artifact_id"],
		result["restoration"]["artifact_id"]
	);
	assert_eq!(fs::read(intent_path).unwrap(), original_intent);
	assert!(!case.path.exists());
}

#[tokio::test]
async fn owner_session_and_legacy_recovery_cannot_cross_bound_intent() {
	let case = fixture().await;
	assert!(call(case.params.clone(), OWNER_B).await.is_err());
	let prepared = plan(&case).await;
	let id = prepared["result"]["journal_id"].as_str().unwrap();
	let mut other = case.params.clone();
	let opened = super::super::open_with_admission(
		&super::super::Scope::current(OWNER_B).unwrap(),
		&super::super::OpenModelSessionParams {
			path: case.path.to_string_lossy().into(),
			expected_sha256: case.params.parent_sha256.clone(),
		},
		(),
	)
	.await
	.unwrap();
	other.session_id = opened["session_id"].as_str().unwrap().into();
	let other_plan = call(other.clone(), OWNER_B).await.unwrap();
	assert_ne!(other_plan["result"]["journal_id"], id);
	other.operation = SessionWeightOperation::Roundtrip {
		request: Box::new(case.input.clone()),
		expected_journal_id: id.into(),
	};
	assert!(call(other.clone(), OWNER_B).await.is_err());
	assert!(journals(&case).is_empty());
	let report = call(roundtrip_params(&case, id), OWNER_A).await.unwrap();
	let candidate = &report["result"]["candidate"];
	other.operation = recovery_params(&case, id, candidate).operation;
	assert!(call(other, OWNER_B).await.is_err());
	assert!(f32_recovery::run(f32_recovery::RecoveryParams {
		journal_id: id.into(),
		original_source_sha256: case.params.parent_sha256.clone(),
		expected_candidate_sha256: case.candidate_sha.clone(),
		candidate_artifact_id: candidate["artifact_id"].as_str().map(str::to_owned),
		bias_binding: source_bound_f32::BiasBinding {
			tensor_name: case.params.readout.bias_tensor.clone(),
			payload_sha256: case.params.readout.bias_payload_sha256.clone()
		},
	})
	.await
	.is_err());
	assert_eq!(journals(&case).len(), 1);
}

#[tokio::test]
async fn failing_candidate_uses_the_original_guard_inverse_before_fresh_request() {
	let mut case = fixture().await;
	case.input.objective = Objective::SquaredError {
		targets: vec![vec![1.5, 1.5]],
	};
	case.params.operation = SessionWeightOperation::Prepare {
		request: Box::new(case.input.clone()),
	};
	let prepared = plan(&case).await;
	let id = prepared["result"]["journal_id"].as_str().unwrap();
	let report = call(roundtrip_params(&case, id), OWNER_A).await.unwrap();
	let result = &report["result"];
	assert_eq!(result["guard"]["accepted"], false);
	assert_eq!(result["guard"]["outcome"], "rejected_and_restored");
	assert_eq!(result["research_roundtrip_verified"], true);
	assert_eq!(
		result["restoration"]["artifact_id"],
		result["guard"]["restoration"]["artifact_id"]
	);
	assert_eq!(
		result["new_request"]["forward"]["outputs"],
		json!([[1.5, 1.5]])
	);
	assert_eq!(
		fs::read(result["restoration"]["artifact_path"].as_str().unwrap()).unwrap(),
		case.source
	);
}

#[tokio::test]
async fn exact_noop_at_zero_radius_is_a_control_and_cannot_claim_gain() {
	let mut case = fixture().await;
	case.input.edits[0].replacement_hex = case.input.edits[0].expected_hex.clone();
	case.input.maximum_update_l2_norm = 0.0;
	case.candidate_sha = case.params.parent_sha256.clone();
	case.params.operation = SessionWeightOperation::Prepare {
		request: Box::new(case.input.clone()),
	};
	let prepared = plan(&case).await;
	let id = prepared["result"]["journal_id"].as_str().unwrap();
	let report = call(roundtrip_params(&case, id), OWNER_A).await.unwrap();
	let result = &report["result"];
	assert_eq!(result["candidate"]["sha256"], case.params.parent_sha256);
	assert_eq!(result["guard"]["accepted"], false);
	assert_eq!(result["guard"]["gain"], 0.0);
	assert_eq!(result["research_roundtrip_verified"], true);
	assert_eq!(result["accepted_for_activation"], false);
}

#[tokio::test]
async fn source_tensor_bias_budget_and_prepared_request_tampering_fail_before_journal() {
	let case = fixture().await;
	let prepared = plan(&case).await;
	let id = prepared["result"]["journal_id"].as_str().unwrap();
	let mut wrong = case.params.clone();
	wrong.parent_sha256 = "0".repeat(64);
	assert!(call(wrong, OWNER_A).await.is_err());
	let mut wrong = case.params.clone();
	wrong.readout.weight_payload_sha256 = "0".repeat(64);
	assert!(call(wrong, OWNER_A).await.is_err());
	let mut wrong = case.params.clone();
	wrong.readout.bias_payload_sha256 = "0".repeat(64);
	assert!(call(wrong, OWNER_A).await.is_err());
	let mut wrong = case.params.clone();
	wrong.readout.weight_tensor = "physics".into();
	assert!(call(wrong, OWNER_A).await.is_err());
	let mut wrong = case.params.clone();
	wrong.readout.columns = 3;
	assert!(call(wrong, OWNER_A).await.is_err());
	let mut input = case.input.clone();
	input.maximum_update_l2_norm = 0.5;
	let mut wrong = case.params.clone();
	wrong.operation = SessionWeightOperation::Prepare {
		request: Box::new(input),
	};
	assert!(call(wrong, OWNER_A).await.is_err());
	let mut input = case.input.clone();
	input.bias[0] = -0.0;
	let mut wrong = case.params.clone();
	wrong.operation = SessionWeightOperation::Prepare {
		request: Box::new(input),
	};
	assert!(call(wrong, OWNER_A).await.is_err());
	let mut input = case.input.clone();
	input.minimum_gain = 0.25;
	let mut wrong = case.params.clone();
	wrong.operation = SessionWeightOperation::Roundtrip {
		request: Box::new(input),
		expected_journal_id: id.into(),
	};
	assert!(call(wrong, OWNER_A).await.is_err());
	assert!(journals(&case).is_empty());
}

#[tokio::test]
async fn changed_or_deleted_original_after_prepare_never_publishes_a_candidate() {
	let case = fixture().await;
	let prepared = plan(&case).await;
	let id = prepared["result"]["journal_id"].as_str().unwrap();
	let mut changed = case.source.clone();
	let last = changed.len() - 1;
	changed[last] ^= 1;
	fs::write(&case.path, changed).unwrap();
	assert!(call(roundtrip_params(&case, id), OWNER_A).await.is_err());
	fs::remove_file(&case.path).unwrap();
	assert!(call(roundtrip_params(&case, id), OWNER_A).await.is_err());
	assert!(journals(&case).is_empty());
}

#[tokio::test]
async fn revoked_session_metadata_invalidates_the_opaque_lease() {
	let case = fixture().await;
	let authority = admit(&case.params, OWNER_A, true).await.unwrap();
	let mut manifest: Value =
		serde_json::from_slice(&fs::read(private_manifest(&case)).unwrap()).unwrap();
	manifest["policy_sha256"] = json!("0".repeat(64));
	fs::write(
		private_manifest(&case),
		serde_json::to_vec(&manifest).unwrap(),
	)
	.unwrap();
	assert!(authority.revalidate().await.is_err());
	assert!(call(case.params.clone(), OWNER_A).await.is_err());
	assert!(journals(&case).is_empty());
}

#[tokio::test]
async fn admitted_inverse_survives_caller_cancellation_after_session_revocation() {
	let case = fixture().await;
	let prepared = plan(&case).await;
	let id = prepared["result"]["journal_id"].as_str().unwrap();
	let boundary = Arc::new(Boundary::default());
	assert!(BOUNDARY.set(Arc::clone(&boundary)).is_ok());
	let params = roundtrip_params(&case, id);
	let caller = tokio::spawn(async move { call(params, OWNER_A).await });
	tokio::time::timeout(Duration::from_secs(30), boundary.reached.notified())
		.await
		.unwrap();
	let published = boundary.observed.lock().unwrap().clone().unwrap();
	assert_eq!(published["accepted"], true);
	assert_eq!(published["candidate"]["sha256"], case.candidate_sha);
	assert!(published["restoration"].is_null());
	fs::remove_file(private_manifest(&case)).unwrap();
	caller.abort();
	assert!(caller.await.unwrap_err().is_cancelled());
	boundary.resume.notify_one();
	tokio::time::timeout(Duration::from_secs(30), boundary.done.notified())
		.await
		.unwrap();
	let finished = boundary.finished.lock().unwrap().clone().unwrap();
	assert_eq!(finished["restoration_verified"], true);
	assert_eq!(finished["session_authority_valid_after_effect"], false);
	assert_eq!(finished["research_roundtrip_verified"], false);
	assert_eq!(finished["restoration"]["sha256"], case.params.parent_sha256);
	assert_eq!(
		finished["new_request"]["forward"]["outputs"],
		json!([[1.5, 1.5]])
	);
	assert_eq!(
		fs::read(finished["restoration"]["artifact_path"].as_str().unwrap()).unwrap(),
		case.source
	);
	assert!(!private_manifest(&case).exists());
}

#[tokio::test]
async fn legacy_unbound_intent_remains_unbound_and_requires_legacy_recovery() {
	let case = fixture().await;
	let authority = admit(&case.params, OWNER_A, true).await.unwrap();
	let params = transaction::request(case.input.clone(), &authority).unwrap();
	let report = source_bound_f32::evaluate(params.clone()).await.unwrap();
	let guard = &report["guard"];
	let id = guard["journal_id"].as_str().unwrap();
	let intent: Value = serde_json::from_slice(
		&fs::read(
			case.state
				.join("weight-guard-journal-v1")
				.join(id)
				.join("intent.json"),
		)
		.unwrap(),
	)
	.unwrap();
	assert!(intent.get("session_authority").is_none());
	assert!(intent.get("session_adapter_source_sha256").is_none());
	assert_eq!(
		intent["request"],
		serde_json::to_value(&params.guard).unwrap()
	);
	assert!(
		call(recovery_params(&case, id, &guard["candidate"]), OWNER_A)
			.await
			.is_err()
	);
	fs::remove_file(&case.path).unwrap();
	let recovered = f32_recovery::run(f32_recovery::RecoveryParams {
		journal_id: id.into(),
		original_source_sha256: case.params.parent_sha256.clone(),
		expected_candidate_sha256: case.candidate_sha,
		candidate_artifact_id: guard["candidate"]["artifact_id"]
			.as_str()
			.map(str::to_owned),
		bias_binding: params.bias_binding,
	})
	.await
	.unwrap();
	assert_eq!(recovered["restoration_verified"], true);
	assert_eq!(recovered["original_source_path_opened"], false);
}

#[test]
fn typed_session_wire_has_no_caller_authority_or_paths() {
	let base = json!({"session_id":"rms1_test","parent_sha256":"0".repeat(64),
		"readout":{"weight_tensor":"w","weight_payload_sha256":"0".repeat(64),"bias_tensor":"b","bias_payload_sha256":"1".repeat(64),"outputs":2,"columns":2},
		"operation":{"kind":"f32_recover","journal_id":"wgj1_test","expected_candidate_sha256":"2".repeat(64),"candidate_artifact_id":null}});
	assert!(serde_json::from_value::<SessionWeightParams>(base.clone()).is_ok());
	for field in [
		"owner",
		"path",
		"state_dir",
		"session_authority",
		"executable",
	] {
		let mut changed = base.clone();
		changed[field] = json!("forged");
		assert!(serde_json::from_value::<SessionWeightParams>(changed).is_err());
	}
	let schema = schemars::schema_for!(SessionWeightParams);
	assert!(serde_json::to_string(&schema)
		.unwrap()
		.contains("f32_prepare"));
}

#[tokio::test]
async fn exact_source_planning_handles_f32_element_across_stream_boundary() {
	let temp = tempfile::tempdir().unwrap();
	let path = temp.path().join("bytes.bin");
	let mut bytes = vec![0_u8; 1024 * 1024 + 9];
	let offset = 1024 * 1024 - 2;
	bytes[offset..offset + 4].copy_from_slice(&1_f32.to_le_bytes());
	fs::write(&path, &bytes).unwrap();
	let mut expected = bytes.clone();
	expected[offset..offset + 4].copy_from_slice(&2_f32.to_le_bytes());
	let patch = crate::mcp::weight_tensor::TensorPatch {
		tensor_name: "w".into(),
		dtype: "F32".into(),
		tensor_file_offset: offset as u64,
		tensor_byte_length: 4,
		source_size_bytes: bytes.len() as u64,
		changes: vec![crate::mcp::weight_tensor::ByteChange {
			index: 0,
			file_offset: offset as u64,
			expected_hex: "0000803f".into(),
			replacement_hex: "00000040".into(),
		}],
	};
	let mut file = tokio::fs::File::open(&path).await.unwrap();
	let (source, candidate, tensor) = transaction::proposed_hash(&mut file, &patch).await.unwrap();
	assert_eq!(source, super::super::hash(&bytes));
	assert_eq!(candidate, super::super::hash(&expected));
	assert_eq!(tensor, super::super::hash(&1_f32.to_le_bytes()));
	assert_eq!(fs::read(path).unwrap(), bytes);
}
