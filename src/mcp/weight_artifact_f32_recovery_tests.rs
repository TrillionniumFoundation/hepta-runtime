// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Real original intents, immutable artifacts and SIGKILL/restart with an unavailable source.

use super::*;
use crate::mcp::{
	rea_model,
	weight_guard::{source_bound_f32, GuardedPatchParams, Objective},
	weight_guard_journal,
	weight_tensor::{ExactElementEdit, PatchTensorParams},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Deserialize, Serialize)]
struct Case {
	source_bound: source_bound_f32::SourceBoundParams,
	roots: Vec<PathBuf>,
	state: PathBuf,
	expected_candidate_sha256: String,
}

fn digest(bytes: &[u8]) -> String {
	rea_model::digest_hex(&Sha256::digest(bytes))
}

fn private_write(path: &Path, bytes: &[u8]) {
	let mut file = fs::OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.custom_flags(libc::O_NOFOLLOW)
		.open(path)
		.unwrap();
	file.write_all(bytes).unwrap();
	file.sync_all().unwrap();
}

fn fixture() -> (tempfile::TempDir, Case, Vec<u8>) {
	let temp = tempfile::tempdir().unwrap();
	fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
	let state = temp.path().join("state");
	fs::DirBuilder::new().mode(0o700).create(&state).unwrap();
	let path = temp.path().join("original.safetensors");
	let mut header = serde_json::to_vec(&json!({
		"body.readout.weight":{"dtype":"F32","shape":[2,2],"data_offsets":[0,16]},
		"body.readout.bias":{"dtype":"F32","shape":[2],"data_offsets":[16,24]},
		"physics":{"dtype":"F64","shape":[1],"data_offsets":[24,32]}
	}))
	.unwrap();
	while !header.len().is_multiple_of(8) {
		header.push(b' ');
	}
	let offset = 8 + header.len();
	let mut original = (header.len() as u64).to_le_bytes().to_vec();
	original.extend(header);
	for value in [1_f32, 0.0, 0.0, 1.0, 0.5, -0.5] {
		original.extend(value.to_le_bytes());
	}
	original.extend(0.25_f64.to_le_bytes());
	let mut candidate = original.clone();
	candidate[offset..offset + 4].copy_from_slice(&2_f32.to_le_bytes());
	private_write(&path, &original);
	let bias_bytes: Vec<_> = [0.5_f32, -0.5]
		.iter()
		.flat_map(|value| value.to_le_bytes())
		.collect();
	let source_bound = source_bound_f32::SourceBoundParams {
		guard: GuardedPatchParams {
			patch: PatchTensorParams {
				path: path.to_string_lossy().into(),
				expected_sha256: digest(&original),
				tensor_name: "body.readout.weight".into(),
				edits: vec![ExactElementEdit {
					index: 0,
					expected_hex: rea_model::digest_hex(&1_f32.to_le_bytes()),
					replacement_hex: rea_model::digest_hex(&2_f32.to_le_bytes()),
				}],
			},
			inputs: vec![vec![1.0, 2.0]],
			bias: Some(vec![0.5, -0.5]),
			objective: Objective::SquaredError {
				targets: vec![vec![2.5, 1.5]],
			},
			minimum_gain: 0.0,
			constraints: Vec::new(),
			max_update_l2_norm: Some(1.0),
		},
		bias_binding: source_bound_f32::BiasBinding {
			tensor_name: "body.readout.bias".into(),
			payload_sha256: digest(&bias_bytes),
		},
	};
	let case = Case {
		source_bound,
		roots: vec![temp.path().into()],
		state,
		expected_candidate_sha256: digest(&candidate),
	};
	private_write(
		&temp.path().join("case.json"),
		&serde_json::to_vec(&case).unwrap(),
	);
	(temp, case, original)
}

async fn initial(case: &Case) -> Result<Value> {
	let mut file = tokio::fs::File::open(&case.source_bound.guard.patch.path).await?;
	source_bound_f32::authenticate_from_admitted(&case.source_bound, &mut file).await?;
	drop(file);
	weight_guard_journal::evaluate_with_roots(
		case.source_bound.guard.clone(),
		&case.roots,
		&case.state,
	)
	.await
}

fn journal_id(case: &Case) -> String {
	let entries: Vec<_> = fs::read_dir(case.state.join("weight-guard-journal-v1"))
		.unwrap()
		.map(|entry| entry.unwrap().file_name().into_string().unwrap())
		.filter(|name| name.starts_with("wgj1_"))
		.collect();
	assert_eq!(entries.len(), 1);
	entries[0].clone()
}

fn params(case: &Case) -> RecoveryParams {
	RecoveryParams {
		journal_id: journal_id(case),
		original_source_sha256: case.source_bound.guard.patch.expected_sha256.clone(),
		expected_candidate_sha256: case.expected_candidate_sha256.clone(),
		candidate_artifact_id: None,
		bias_binding: case.source_bound.bias_binding.clone(),
	}
}

fn artifact_count(case: &Case) -> usize {
	let root = case.state.join("weight-artifacts-v1");
	if !root.exists() {
		return 0;
	}
	fs::read_dir(root)
		.unwrap()
		.filter(|entry| {
			entry
				.as_ref()
				.unwrap()
				.file_name()
				.to_string_lossy()
				.starts_with("wa1_")
		})
		.count()
}

#[tokio::test]
async fn restore_first_does_not_open_missing_or_changed_original_path() {
	for remove in [true, false] {
		let (_temp, case, original) = fixture();
		let accepted = initial(&case).await.unwrap();
		assert_eq!(accepted["accepted"], true);
		let before_records: Vec<_> = ["intent.json", "candidate.json", "completion.json"]
			.iter()
			.map(|name| {
				fs::read(
					case.state
						.join("weight-guard-journal-v1")
						.join(journal_id(&case))
						.join(name),
				)
				.unwrap()
			})
			.collect();
		let mut changed = original.clone();
		let last = changed.len() - 1;
		changed[last] ^= 1;
		if remove {
			fs::remove_file(&case.source_bound.guard.patch.path).unwrap();
		} else {
			fs::write(&case.source_bound.guard.patch.path, &changed).unwrap();
		}
		let report = linux::run_with_roots(params(&case), &case.roots, &case.state)
			.await
			.unwrap();
		assert_eq!(report["restoration_verified"], true);
		assert_eq!(report["accepted"], false);
		assert_eq!(report["original_source_path_opened"], false);
		assert_eq!(report["parent_forward_replayed"], false);
		assert_eq!(report["candidate_forward_replayed"], false);
		assert_eq!(report["new_candidate_published"], false);
		assert_eq!(
			report["new_request"]["forward"]["outputs"],
			json!([[1.5, 1.5]])
		);
		assert_eq!(
			fs::read(report["restoration"]["artifact_path"].as_str().unwrap()).unwrap(),
			original
		);
		assert_eq!(artifact_count(&case), 2);
		if remove {
			assert!(!Path::new(&case.source_bound.guard.patch.path).exists());
		} else {
			assert_eq!(
				fs::read(&case.source_bound.guard.patch.path).unwrap(),
				changed
			);
		}
		let after_records: Vec<_> = ["intent.json", "candidate.json", "completion.json"]
			.iter()
			.map(|name| {
				fs::read(
					case.state
						.join("weight-guard-journal-v1")
						.join(journal_id(&case))
						.join(name),
				)
				.unwrap()
			})
			.collect();
		assert_eq!(before_records, after_records);
		let repeat = linux::run_with_roots(params(&case), &case.roots, &case.state)
			.await
			.unwrap();
		assert_eq!(
			repeat["restoration"]["artifact_id"],
			report["restoration"]["artifact_id"]
		);
		assert_eq!(repeat["restoration"]["reused"], true);
		assert_eq!(artifact_count(&case), 2);
	}
}

#[tokio::test]
async fn wrong_source_candidate_bias_hint_or_intent_never_requests_inverse() {
	let (_temp, case, _) = fixture();
	initial(&case).await.unwrap();
	for kind in 0..5 {
		let mut params = params(&case);
		match kind {
			0 => params.original_source_sha256 = "1".repeat(64),
			1 => params.expected_candidate_sha256 = "2".repeat(64),
			2 => params.bias_binding.payload_sha256 = "3".repeat(64),
			3 => params.candidate_artifact_id = Some(format!("wa1_{}", "4".repeat(64))),
			_ => params.journal_id = format!("wgj1_{}", "5".repeat(64)),
		}
		assert!(linux::run_with_roots(params, &case.roots, &case.state)
			.await
			.is_err());
		assert_eq!(artifact_count(&case), 1);
	}
}

#[tokio::test]
async fn tampered_candidate_or_original_intent_is_not_recovered() {
	for change_intent in [true, false] {
		let (_temp, case, _) = fixture();
		let accepted = initial(&case).await.unwrap();
		let path = if change_intent {
			case.state
				.join("weight-guard-journal-v1")
				.join(journal_id(&case))
				.join("intent.json")
		} else {
			PathBuf::from(accepted["candidate"]["artifact_path"].as_str().unwrap())
		};
		let mut bytes = fs::read(&path).unwrap();
		let last = bytes.len() - 1;
		bytes[last] ^= 1;
		fs::write(&path, bytes).unwrap();
		assert!(
			linux::run_with_roots(params(&case), &case.roots, &case.state)
				.await
				.is_err()
		);
		assert_eq!(artifact_count(&case), 1);
	}
}

#[tokio::test]
async fn absent_existing_journal_is_not_created_by_recovery() {
	let (_temp, case, _) = fixture();
	let params = RecoveryParams {
		journal_id: format!("wgj1_{}", "1".repeat(64)),
		original_source_sha256: case.source_bound.guard.patch.expected_sha256.clone(),
		expected_candidate_sha256: case.expected_candidate_sha256.clone(),
		candidate_artifact_id: None,
		bias_binding: case.source_bound.bias_binding.clone(),
	};
	assert!(linux::run_with_roots(params, &case.roots, &case.state)
		.await
		.is_err());
	assert!(!case.state.join("weight-guard-journal-v1").exists());
	assert!(!case.state.join("weight-artifacts-v1").exists());
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
	fn drop(&mut self) {
		if self.0.try_wait().ok().flatten().is_none() {
			let _ = self.0.kill();
			let _ = self.0.wait();
		}
	}
}

fn child(
	temp: &Path,
	mode: &str,
	phase: Option<&str>,
	tag: &str,
) -> (OwnedChild, PathBuf, PathBuf) {
	let marker = temp.join(format!("marker-{tag}"));
	let output = temp.join(format!("output-{tag}.json"));
	let mut command = Command::new(std::env::current_exe().unwrap());
	command
		.args([
			"--ignored",
			"--exact",
			"mcp::weight_artifact::cohort::f32_recovery::tests::recovery_crash_worker",
			"--nocapture",
		])
		.env("HEPTA_TEST_SOURCE_RECOVERY_CASE", temp.join("case.json"))
		.env("HEPTA_TEST_SOURCE_RECOVERY_MODE", mode)
		.env("HEPTA_TEST_SOURCE_RECOVERY_OUTPUT", &output)
		.env("HEPTA_TEST_JOURNAL_MARKER", &marker)
		.env_remove("HEPTA_TEST_JOURNAL_PHASE")
		.stdin(Stdio::null())
		.stdout(Stdio::null())
		.stderr(Stdio::null());
	if let Some(phase) = phase {
		command.env("HEPTA_TEST_JOURNAL_PHASE", phase);
	}
	(OwnedChild(command.spawn().unwrap()), marker, output)
}

fn wait_marker(child: &mut OwnedChild, marker: &Path) {
	let deadline = Instant::now() + Duration::from_secs(25);
	while !marker.exists() {
		assert!(
			child.0.try_wait().unwrap().is_none(),
			"child stopped before failpoint"
		);
		assert!(
			Instant::now() < deadline,
			"child failpoint deadline exceeded"
		);
		std::thread::sleep(Duration::from_millis(5));
	}
}

fn finish(child: &mut OwnedChild, output: &Path) -> Value {
	let deadline = Instant::now() + Duration::from_secs(30);
	loop {
		if let Some(status) = child.0.try_wait().unwrap() {
			assert!(status.success());
			break;
		}
		assert!(
			Instant::now() < deadline,
			"recovery child deadline exceeded"
		);
		std::thread::sleep(Duration::from_millis(5));
	}
	serde_json::from_slice(&fs::read(output).unwrap()).unwrap()
}

#[test]
#[ignore = "subprocess worker; invoked only by the owned source-bound crash controls"]
fn recovery_crash_worker() {
	let path = PathBuf::from(std::env::var("HEPTA_TEST_SOURCE_RECOVERY_CASE").unwrap());
	let case: Case = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.unwrap();
	let result = if std::env::var("HEPTA_TEST_SOURCE_RECOVERY_MODE").unwrap() == "initial" {
		runtime.block_on(initial(&case))
	} else {
		runtime.block_on(linux::run_with_roots(
			params(&case),
			&case.roots,
			&case.state,
		))
	};
	let response = match result {
		Ok(report) => json!({"ok":true,"report":report}),
		Err(error) => json!({"ok":false,"error":error.to_string()}),
	};
	private_write(
		&PathBuf::from(std::env::var("HEPTA_TEST_SOURCE_RECOVERY_OUTPUT").unwrap()),
		&serde_json::to_vec(&response).unwrap(),
	);
}

#[test]
fn real_sigkill_then_missing_source_restarts_without_original_forward_or_new_candidate() {
	for phase in ["after_intent", "after_guard_before_candidate"] {
		let (temp, case, original) = fixture();
		let (mut running, marker, _) = child(temp.path(), "initial", Some(phase), "initial");
		wait_marker(&mut running, &marker);
		let directory = case
			.state
			.join("weight-guard-journal-v1")
			.join(journal_id(&case));
		assert!(!directory.join("candidate.json").exists());
		assert!(!directory.join("completion.json").exists());
		let before = artifact_count(&case);
		running.0.kill().unwrap();
		assert_eq!(running.0.wait().unwrap().signal(), Some(libc::SIGKILL));
		fs::remove_file(&case.source_bound.guard.patch.path).unwrap();
		let (mut restarted, _, output) = child(temp.path(), "recover", None, "recovery");
		let response = finish(&mut restarted, &output);
		if phase == "after_intent" {
			assert_eq!(response["ok"], false);
			assert_eq!(before, 0);
			assert_eq!(artifact_count(&case), 0);
		} else {
			assert_eq!(response["ok"], true, "{response}");
			let report = &response["report"];
			assert_eq!(report["restoration_verified"], true);
			assert_eq!(report["candidate_discovered_without_record"], true);
			assert_eq!(report["original_candidate_record_present"], false);
			assert_eq!(report["original_source_path_opened"], false);
			assert_eq!(report["parent_forward_replayed"], false);
			assert_eq!(report["candidate_forward_replayed"], false);
			assert_eq!(report["new_candidate_published"], false);
			assert_eq!(
				report["new_request"]["forward"]["outputs"],
				json!([[1.5, 1.5]])
			);
			assert_eq!(
				fs::read(report["restoration"]["artifact_path"].as_str().unwrap()).unwrap(),
				original
			);
			assert_eq!(before, 1);
			assert_eq!(artifact_count(&case), 2);
		}
		assert!(!Path::new(&case.source_bound.guard.patch.path).exists());
		assert!(!directory.join("candidate.json").exists());
		assert!(!directory.join("completion.json").exists());
		println!(
			"SOURCE_BOUND_RECOVERY_CRASH_RECEIPT={}",
			json!({"phase":phase,"signal":libc::SIGKILL,"fresh_process":true,"original_source_removed":true,"published_before_kill":before,"published_after_recovery":artifact_count(&case),"response":response,"prior_process_cpu_cost_known":false})
		);
	}
}

#[test]
fn live_original_guard_lock_refuses_restore_first_recovery() {
	let (temp, case, _) = fixture();
	let (mut original, marker, _) = child(
		temp.path(),
		"initial",
		Some("after_guard_before_candidate"),
		"holder",
	);
	wait_marker(&mut original, &marker);
	let (mut contender, _, output) = child(temp.path(), "recover", None, "contender");
	let response = finish(&mut contender, &output);
	assert_eq!(response["ok"], false);
	assert!(response["error"].as_str().unwrap().contains("live process"));
	assert_eq!(artifact_count(&case), 1);
	assert!(original.0.try_wait().unwrap().is_none());
}
