// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Real session admission, scoped original intents, exact inverse and denial controls.

use super::*;
use crate::mcp::{runtime, weight_artifact::cohort::f32_recovery, weight_guard::source_bound_f32};
use rmcp::model::{
	CallToolRequestParams, ClientCapabilities, ClientConfig, ContentBlock, Implementation,
	ProtocolVersion,
};
use rmcp::service::{ClientLifecycleMode, ClientServiceExt, RunningService};
use rmcp::{ClientHandler, RoleClient, ServiceExt};
use serde_json::Value;
use std::ffi::OsString;
use std::fs::Permissions;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::fs;

const OWNER_A: &str = "credential-owner-a";
const OWNER_B: &str = "credential-owner-b";

#[derive(Default)]
struct Boundary {
	observed: Mutex<Option<Value>>,
	finished: Mutex<Option<Value>>,
	reached: tokio::sync::Notify,
	resume: tokio::sync::Notify,
	done: tokio::sync::Notify,
	capacity_reached: tokio::sync::Notify,
}
static BOUNDARY: OnceLock<Arc<Boundary>> = OnceLock::new();

pub(super) fn waiting_for_owner_capacity() {
	if let Some(boundary) = BOUNDARY.get() {
		boundary.capacity_reached.notify_one();
	}
}

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
	fs::set_permissions(temp.path(), Permissions::from_mode(0o700))
		.await
		.unwrap();
	let workspace = temp.path().join("workspace");
	fs::create_dir(&workspace).await.unwrap();
	let state = temp.path().join("state");
	let config = serde_json::from_value(json!({
		"state_dir":state,"controller_workspace_roots":[workspace],
		"hosts":{"denied":{
			"ssh_target":"never-connect-session-weight-tests",
			"remote_state_dir":temp.path().join("no-remote"),
			"allow_execute":false,"allow_pty":false,"allow_write":false,"allow_job_network":false
		}}
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
	fs::write(&path, &source).await.unwrap();
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
	let deadline = tokio::time::Instant::now() + Duration::from_secs(420);
	let admission = runtime::effect_owner_fence::admit_new_effect().await?;
	Ok(serde_json::from_str(
		&run_for_owner(params, owner, true, admission, deadline).await?,
	)?)
}

struct EffectFence {
	root: PathBuf,
	state: PathBuf,
	saved: Vec<(&'static str, Option<OsString>)>,
}

impl EffectFence {
	async fn new(case: &Case) -> Self {
		let root = case._temp.path().join("effect-authority");
		fs::create_dir(&root).await.unwrap();
		fs::set_permissions(&root, Permissions::from_mode(0o700))
			.await
			.unwrap();
		let lock = root.join(".owner.lock");
		fs::write(&lock, b"").await.unwrap();
		fs::set_permissions(&lock, Permissions::from_mode(0o600))
			.await
			.unwrap();
		let saved = [
			"HEPTA_EFFECT_OWNER_FENCE_DIR",
			"HEPTA_EFFECT_OWNER_SELF",
			"HEPTA_EFFECT_OWNER_FENCE_REQUIRED",
		]
		.into_iter()
		.map(|key| (key, std::env::var_os(key)))
		.collect();
		let fence = Self {
			root,
			state: case.state.clone(),
			saved,
		};
		fence.set_phase("admitting").await;
		std::env::set_var("HEPTA_EFFECT_OWNER_FENCE_DIR", &fence.root);
		std::env::set_var("HEPTA_EFFECT_OWNER_SELF", "v4");
		std::env::set_var("HEPTA_EFFECT_OWNER_FENCE_REQUIRED", "1");
		fence
	}

	async fn lock(&self) -> fs::File {
		fs::OpenOptions::new()
			.read(true)
			.write(true)
			.open(self.root.join(".owner.lock"))
			.await
			.unwrap()
	}

	async fn set_phase(&self, phase: &str) {
		let lock = self.lock().await;
		assert_eq!(
			unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
			0
		);
		let record = json!({"schema":"hepta-effect-owner-fence-v1", "owner":"v4",
			"epoch":7, "phase":phase, "state_root":self.state, "predecessor_state_root":null});
		let path = self.root.join(".owner.json");
		fs::write(&path, serde_json::to_vec(&record).unwrap())
			.await
			.unwrap();
		fs::set_permissions(&path, Permissions::from_mode(0o600))
			.await
			.unwrap();
	}

	async fn exclusive_available(&self) -> bool {
		let lock = self.lock().await;
		if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
			true
		} else {
			assert_eq!(
				std::io::Error::last_os_error().kind(),
				std::io::ErrorKind::WouldBlock
			);
			false
		}
	}

	async fn released(&self) {
		tokio::time::timeout(Duration::from_secs(5), async {
			while !self.exclusive_available().await {
				tokio::task::yield_now().await;
			}
		})
		.await
		.unwrap();
	}
}

impl Drop for EffectFence {
	fn drop(&mut self) {
		for (key, previous) in &self.saved {
			match previous {
				Some(value) => std::env::set_var(key, value),
				None => std::env::remove_var(key),
			}
		}
	}
}

#[derive(Debug)]
struct FenceClient;
impl ClientHandler for FenceClient {
	fn get_info(&self) -> ClientConfig {
		ClientConfig::new(
			ClientCapabilities::default(),
			Implementation::new("session-weight-fence-test", "0.0.0"),
		)
		.with_protocol_version(ProtocolVersion::V_2025_11_25)
	}
}

async fn mcp_connection(
	case: &Case,
) -> (
	RunningService<RoleClient, FenceClient>,
	tokio::task::JoinHandle<()>,
) {
	let (client_io, server_io) = tokio::io::duplex(4096);
	let root = case.path.parent().unwrap().to_path_buf();
	let task = tokio::spawn(async move {
		let server = crate::mcp::server::OctofsServer::with_root(root)
			.serve(server_io)
			.await
			.unwrap();
		let _ = server.waiting().await;
	});
	let client = tokio::time::timeout(
		Duration::from_secs(5),
		FenceClient.serve_with_lifecycle(client_io, ClientLifecycleMode::Initialize),
	)
	.await
	.unwrap()
	.unwrap();
	(client, task)
}

async fn mcp_call(
	client: &RunningService<RoleClient, FenceClient>,
	name: &str,
	arguments: Value,
) -> (bool, String) {
	let result = tokio::time::timeout(
		Duration::from_secs(10),
		client.call_tool(
			CallToolRequestParams::new(name.to_owned())
				.with_arguments(arguments.as_object().unwrap().clone()),
		),
	)
	.await
	.unwrap()
	.unwrap();
	let text = result
		.content
		.iter()
		.find_map(|block| match block {
			ContentBlock::Text(text) => Some(text.text.clone()),
			_ => None,
		})
		.unwrap();
	(result.is_error == Some(true), text)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_mcp_entry_fences_prepare_roundtrip_and_recovery_before_weight_effects() {
	let mut case = fixture().await;
	let fence = EffectFence::new(&case).await;
	let (client, server_task) = mcp_connection(&case).await;
	let (failed, opened) = mcp_call(
		&client,
		"rea_model_session_open",
		json!({
			"path":case.path, "expected_sha256":case.params.parent_sha256
		}),
	)
	.await;
	assert!(!failed, "{opened}");
	let opened: Value = serde_json::from_str(&opened).unwrap();
	case.params.session_id = opened["session_id"].as_str().unwrap().into();
	let (failed, prepared) = mcp_call(
		&client,
		"rea_model_session_weight",
		serde_json::to_value(&case.params).unwrap(),
	)
	.await;
	assert!(!failed, "{prepared}");
	let prepared: Value = serde_json::from_str(&prepared).unwrap();
	assert_eq!(prepared["result"]["forward_calls"], 0);
	assert_eq!(prepared["result"]["journal_written"], false);
	let id = prepared["result"]["journal_id"].as_str().unwrap();
	fence.set_phase("frozen").await;
	for params in [
		case.params.clone(),
		roundtrip_params(&case, id),
		recovery_params(&case, id, &Value::Null),
	] {
		let (failed, text) = mcp_call(
			&client,
			"rea_model_session_weight",
			serde_json::to_value(params).unwrap(),
		)
		.await;
		assert!(
			failed && text.contains("effect owner admission frozen"),
			"{text}"
		);
	}
	fence.set_phase("admitting").await;
	std::env::set_var("HEPTA_EFFECT_OWNER_SELF", "v11");
	let (failed, text) = mcp_call(
		&client,
		"rea_model_session_weight",
		serde_json::to_value(&case.params).unwrap(),
	)
	.await;
	assert!(failed && text.contains("effect owner mismatch"), "{text}");
	assert!(!fs::try_exists(case.state.join("weight-artifacts-v1"))
		.await
		.unwrap());
	assert!(!fs::try_exists(case.state.join("weight-guard-journal-v1"))
		.await
		.unwrap());
	assert_eq!(fs::read(&case.path).await.unwrap(), case.source);
	fence.released().await;
	drop(client);
	server_task.abort();
	let _ = server_task.await;
}

#[tokio::test]
async fn admitted_capacity_wait_uses_the_original_deadline_without_publication_or_permit_leak() {
	let case = fixture().await;
	let fence = EffectFence::new(&case).await;
	let prepared = plan(&case).await;
	let params = roundtrip_params(&case, prepared["result"]["journal_id"].as_str().unwrap());
	let mut occupied = Vec::new();
	for _ in 0..4 {
		occupied.push(
			crate::mcp::weight_artifact::cohort::owner_guards()
				.await
				.unwrap(),
		);
	}
	let boundary = Arc::new(Boundary::default());
	assert!(BOUNDARY.set(Arc::clone(&boundary)).is_ok());
	let admission = runtime::effect_owner_fence::admit_new_effect()
		.await
		.unwrap();
	let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
	let caller =
		tokio::spawn(
			async move { run_for_owner(params, OWNER_A, true, admission, deadline).await },
		);
	tokio::time::timeout(Duration::from_secs(2), boundary.capacity_reached.notified())
		.await
		.unwrap();
	let error = tokio::time::timeout(Duration::from_secs(5), caller)
		.await
		.unwrap()
		.unwrap()
		.unwrap_err();
	assert!(error
		.to_string()
		.contains("session weight response deadline exceeded"));
	assert!(!fs::try_exists(case.state.join("weight-artifacts-v1"))
		.await
		.unwrap());
	assert!(journals(&case).await.is_empty());
	assert_eq!(fs::read(&case.path).await.unwrap(), case.source);
	drop(occupied);
	fence.released().await;
}

async fn plan(case: &Case) -> Value {
	let result = call(case.params.clone(), OWNER_A).await.unwrap();
	assert_eq!(
		result["result"]["expected_candidate_sha256"],
		case.candidate_sha
	);
	assert_eq!(result["result"]["forward_calls"], 0);
	assert_eq!(result["result"]["journal_written"], false);
	assert!(!fs::try_exists(case.state.join("weight-guard-journal-v1"))
		.await
		.unwrap());
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

async fn journals(case: &Case) -> Vec<PathBuf> {
	let root = case.state.join("weight-guard-journal-v1");
	if !fs::try_exists(&root).await.unwrap() {
		return Vec::new();
	}
	let mut entries = fs::read_dir(root).await.unwrap();
	let mut result = Vec::new();
	while let Some(entry) = entries.next_entry().await.unwrap() {
		let path = entry.path();
		if path
			.file_name()
			.unwrap()
			.to_string_lossy()
			.starts_with("wgj1_")
		{
			result.push(path);
		}
	}
	result
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
	assert_eq!(fs::read(&case.path).await.unwrap(), case.source);
	let repeated = call(roundtrip_params(&case, id), OWNER_A)
		.await
		.unwrap_err();
	assert!(repeated.to_string().contains("already exists"));
	let intent_path = case
		.state
		.join("weight-guard-journal-v1")
		.join(id)
		.join("intent.json");
	let original_intent = fs::read(&intent_path).await.unwrap();
	let intent: Value = serde_json::from_slice(&original_intent).unwrap();
	assert_eq!(
		intent["session_authority"]["session_id"],
		case.params.session_id
	);
	assert_eq!(
		intent["session_authority"]["allowed_readout"]["weight_tensor"],
		"readout.weight"
	);
	fs::remove_file(&case.path).await.unwrap();
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
	assert_eq!(fs::read(intent_path).await.unwrap(), original_intent);
	assert!(!fs::try_exists(&case.path).await.unwrap());
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
	assert!(journals(&case).await.is_empty());
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
	assert_eq!(journals(&case).await.len(), 1);
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
		fs::read(result["restoration"]["artifact_path"].as_str().unwrap())
			.await
			.unwrap(),
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
	assert!(journals(&case).await.is_empty());
}

#[tokio::test]
async fn changed_or_deleted_original_after_prepare_never_publishes_a_candidate() {
	let case = fixture().await;
	let prepared = plan(&case).await;
	let id = prepared["result"]["journal_id"].as_str().unwrap();
	let mut changed = case.source.clone();
	let last = changed.len() - 1;
	changed[last] ^= 1;
	fs::write(&case.path, changed).await.unwrap();
	assert!(call(roundtrip_params(&case, id), OWNER_A).await.is_err());
	fs::remove_file(&case.path).await.unwrap();
	assert!(call(roundtrip_params(&case, id), OWNER_A).await.is_err());
	assert!(journals(&case).await.is_empty());
}

#[tokio::test]
async fn revoked_session_metadata_invalidates_the_opaque_lease() {
	let case = fixture().await;
	let authority = admit(&case.params, OWNER_A, true).await.unwrap();
	let mut manifest: Value =
		serde_json::from_slice(&fs::read(private_manifest(&case)).await.unwrap()).unwrap();
	manifest["policy_sha256"] = json!("0".repeat(64));
	fs::write(
		private_manifest(&case),
		serde_json::to_vec(&manifest).unwrap(),
	)
	.await
	.unwrap();
	assert!(authority.revalidate().await.is_err());
	assert!(call(case.params.clone(), OWNER_A).await.is_err());
	assert!(journals(&case).await.is_empty());
}

#[tokio::test]
async fn admitted_inverse_survives_caller_cancellation_after_session_revocation() {
	let case = fixture().await;
	let fence = EffectFence::new(&case).await;
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
	assert!(!fence.exclusive_available().await);
	fs::remove_file(private_manifest(&case)).await.unwrap();
	// A new entry would now be refused, but the original retained inverse owns its permit.
	std::env::set_var("HEPTA_EFFECT_OWNER_SELF", "v11");
	caller.abort();
	assert!(caller.await.unwrap_err().is_cancelled());
	assert!(!fence.exclusive_available().await);
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
		fs::read(finished["restoration"]["artifact_path"].as_str().unwrap())
			.await
			.unwrap(),
		case.source
	);
	assert!(!fs::try_exists(private_manifest(&case)).await.unwrap());
	fence.released().await;
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
		.await
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
	fs::remove_file(&case.path).await.unwrap();
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

#[test]
fn session_request_schema_preserves_all_three_closed_object_branches() {
	let schema = serde_json::to_value(schemars::schema_for!(SessionWeightRequest)).unwrap();
	assert_eq!(schema["type"], "object");
	let branches = schema["anyOf"].as_array().expect("untagged alternatives");
	assert_eq!(branches.len(), 3);
	for (branch, required) in branches.iter().zip([
		["operation", "parent_sha256", "readout", "session_id"],
		["operation", "parent_sha256", "profile", "session_id"],
		["operation", "parent_sha256", "profile", "session_id"],
	]) {
		let reference = branch["$ref"].as_str().expect("typed object reference");
		let payload = schema
			.pointer(reference.strip_prefix('#').expect("local schema reference"))
			.expect("referenced branch remains in schema");
		assert_eq!(payload["type"], "object");
		assert_eq!(payload["additionalProperties"], false);
		let mut actual: Vec<_> = payload["required"]
			.as_array()
			.unwrap()
			.iter()
			.map(|name| name.as_str().unwrap())
			.collect();
		actual.sort_unstable();
		assert_eq!(actual, required);
	}
	for (branch, expected) in branches.iter().skip(1).zip([
		"smallhcsn_centered_sender_drive_and_bias40_v1",
		"smallhcsn_late_quote_min_mark4_task_route_v1",
	]) {
		let reference = branch["$ref"].as_str().unwrap();
		let payload = schema
			.pointer(reference.strip_prefix('#').unwrap())
			.unwrap();
		let profile_ref = payload["properties"]["profile"]["$ref"].as_str().unwrap();
		let profile = schema
			.pointer(profile_ref.strip_prefix('#').unwrap())
			.unwrap();
		assert_eq!(profile["enum"], json!([expected]));
	}
	let encoded = serde_json::to_string(&schema).unwrap();
	for operation in [
		"f32_prepare",
		"f32_roundtrip",
		"f32_recover",
		"smallhcsn_compile",
		"smallhcsn_plan",
		"smallhcsn_prepare",
		"smallhcsn_roundtrip",
		"smallhcsn_recover",
		"late_quote_compile",
		"late_quote_prepare",
		"late_quote_roundtrip",
		"late_quote_recover",
	] {
		assert!(encoded.contains(operation), "missing {operation}");
	}
}

#[test]
fn session_request_wire_keeps_f32_and_both_fixed_profiles_disjoint() {
	let f32 = json!({"session_id":"rms1_test","parent_sha256":"0".repeat(64),
		"readout":{"weight_tensor":"w","weight_payload_sha256":"0".repeat(64),"bias_tensor":"b","bias_payload_sha256":"1".repeat(64),"outputs":2,"columns":2},
		"operation":{"kind":"f32_recover","journal_id":"wgj1_test","expected_candidate_sha256":"2".repeat(64),"candidate_artifact_id":null}});
	let hidden = json!({"session_id":"rms1_test","parent_sha256":"0".repeat(64),
		"profile":"smallhcsn_centered_sender_drive_and_bias40_v1",
		"operation":{"kind":"smallhcsn_recover","journal_id":"3".repeat(64),"expected_candidate_sha256":"2".repeat(64)}});
	let late = json!({"session_id":"rms1_test","parent_sha256":"0".repeat(64),
		"profile":"smallhcsn_late_quote_min_mark4_task_route_v1",
		"operation":{"kind":"late_quote_recover","journal_id":"3".repeat(64),"expected_plan_sha256":"4".repeat(64)}});
	let wires = [(&f32, "f32"), (&hidden, "smallhcsn"), (&late, "late_quote")];
	for (wire, expected) in wires {
		let decoded: SessionWeightRequest = serde_json::from_value(wire.clone()).unwrap();
		assert_eq!(
			match &decoded {
				SessionWeightRequest::F32(_) => "f32",
				SessionWeightRequest::SmallHcsn(_) => "smallhcsn",
				SessionWeightRequest::LateQuote(_) => "late_quote",
			},
			expected
		);
		assert_eq!(serde_json::to_value(decoded).unwrap(), *wire);
		for field in [
			"owner",
			"path",
			"state_dir",
			"session_authority",
			"executable",
		] {
			let mut forged = wire.clone();
			forged[field] = json!("forged");
			assert!(serde_json::from_value::<SessionWeightRequest>(forged).is_err());
		}
		let mut unknown_operation_field = wire.clone();
		unknown_operation_field["operation"]["path"] = json!("forged");
		assert!(serde_json::from_value::<SessionWeightRequest>(unknown_operation_field).is_err());
		for (other, other_kind) in wires {
			if expected == other_kind {
				continue;
			}
			let mut swapped = wire.clone();
			swapped["operation"] = other["operation"].clone();
			assert!(serde_json::from_value::<SessionWeightRequest>(swapped).is_err());
			if wire.get("profile").is_some() && other.get("profile").is_some() {
				let mut swapped_profile = wire.clone();
				swapped_profile["profile"] = other["profile"].clone();
				assert!(serde_json::from_value::<SessionWeightRequest>(swapped_profile).is_err());
			}
		}
	}
	for profiled in [&hidden, &late] {
		let mut hybrid = f32.clone();
		hybrid["profile"] = profiled["profile"].clone();
		assert!(serde_json::from_value::<SessionWeightRequest>(hybrid).is_err());
	}
	let request = json!({"profile_json":"{}","raw_input_hex":"00",
		"retention_profile_json":"{}","retention_raw_input_hex":"00",
		"minimum_accuracy_percent":95,"maximum_update_l2_norm":1.0});
	for operation in [
		json!({"kind":"late_quote_compile","request":request}),
		json!({"kind":"late_quote_prepare","request":request}),
		json!({"kind":"late_quote_roundtrip","request":request,"expected_journal_id":"3".repeat(64)}),
	] {
		let mut wire = late.clone();
		wire["operation"] = operation;
		let decoded: SessionWeightRequest = serde_json::from_value(wire.clone()).unwrap();
		assert!(matches!(&decoded, SessionWeightRequest::LateQuote(_)));
		assert_eq!(serde_json::to_value(decoded).unwrap(), wire);
		wire["operation"]["request"]["owner"] = json!("forged");
		assert!(serde_json::from_value::<SessionWeightRequest>(wire).is_err());
	}
	for non_object in [Value::Null, json!([]), json!("rms1_test")] {
		assert!(serde_json::from_value::<SessionWeightRequest>(non_object).is_err());
	}
}

#[tokio::test]
async fn exact_source_planning_handles_f32_element_across_stream_boundary() {
	let temp = tempfile::tempdir().unwrap();
	let path = temp.path().join("bytes.bin");
	let mut bytes = vec![0_u8; 1024 * 1024 + 9];
	let offset = 1024 * 1024 - 2;
	bytes[offset..offset + 4].copy_from_slice(&1_f32.to_le_bytes());
	fs::write(&path, &bytes).await.unwrap();
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
	assert_eq!(fs::read(path).await.unwrap(), bytes);
}
