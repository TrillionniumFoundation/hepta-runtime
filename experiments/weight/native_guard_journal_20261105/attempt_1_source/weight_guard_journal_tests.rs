// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Real isolated files and actual SIGKILL/restart qualification. No mock artifact engine.

use super::super::weight_guard::{Constraint, Objective};
use super::super::weight_tensor::{ExactElementEdit, PatchTensorParams};
use super::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{symlink, DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Deserialize, Serialize)]
struct Case {
	params: GuardedPatchParams,
	roots: Vec<PathBuf>,
	state: PathBuf,
}

fn mkdir(path: &Path) {
	fs::DirBuilder::new().mode(0o700).create(path).unwrap();
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

fn hex(value: f32) -> String {
	value
		.to_le_bytes()
		.iter()
		.map(|b| format!("{b:02x}"))
		.collect()
}

fn fixture() -> (tempfile::TempDir, Case, Vec<u8>) {
	let temp = tempfile::tempdir().unwrap();
	fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
	let state = temp.path().join("state");
	mkdir(&state);
	let source = temp.path().join("parent.safetensors");
	let mut header =
		serde_json::to_vec(&json!({"weight":{"dtype":"F32","shape":[1,2],"data_offsets":[0,8]}}))
			.unwrap();
	while !header.len().is_multiple_of(8) {
		header.push(b' ');
	}
	let mut original = (header.len() as u64).to_le_bytes().to_vec();
	original.extend(header);
	original.extend(1.0f32.to_le_bytes());
	original.extend((-3.0f32).to_le_bytes());
	private_write(&source, &original);
	let params = GuardedPatchParams {
		patch: PatchTensorParams {
			path: source.to_string_lossy().into_owned(),
			expected_sha256: linux::digest(&original),
			tensor_name: "weight".into(),
			edits: vec![ExactElementEdit {
				index: 0,
				expected_hex: hex(1.0),
				replacement_hex: hex(2.0),
			}],
		},
		inputs: vec![vec![-2., 1.], vec![0.5, 2.], vec![3., -1.]],
		bias: None,
		objective: Objective::SquaredError {
			targets: vec![vec![-7.], vec![-5.], vec![9.]],
		},
		minimum_gain: 0.0,
		constraints: vec![],
		max_update_l2_norm: Some(1.0),
	};
	let case = Case {
		params,
		roots: vec![temp.path().to_owned()],
		state,
	};
	private_write(
		&temp.path().join("case.json"),
		&serde_json::to_vec(&case).unwrap(),
	);
	(temp, case, original)
}

async fn run(case: &Case) -> Value {
	evaluate_with_roots(case.params.clone(), &case.roots, &case.state)
		.await
		.unwrap()
}

fn entries(case: &Case) -> Vec<PathBuf> {
	let root = case.state.join(linux::ROOT_NAME);
	if !root.exists() {
		return Vec::new();
	}
	fs::read_dir(root)
		.unwrap()
		.map(|e| e.unwrap().path())
		.filter(|p| {
			p.file_name()
				.unwrap()
				.to_string_lossy()
				.starts_with("wgj1_")
		})
		.collect()
}

fn artifact_count(case: &Case) -> usize {
	let root = case.state.join("weight-artifacts-v1");
	if !root.exists() {
		return 0;
	}
	fs::read_dir(root)
		.unwrap()
		.filter(|e| {
			e.as_ref()
				.unwrap()
				.file_name()
				.to_string_lossy()
				.starts_with("wa1_")
		})
		.count()
}

#[tokio::test]
async fn ordinary_acceptance_is_durable_and_completed_retry_reruns_authentication() {
	let (_temp, case, original) = fixture();
	let first = run(&case).await;
	assert_eq!(first["accepted"], true);
	assert_eq!(first["current_durable_completion"], true);
	assert_eq!(first["f32_update_budget_source_bytes_authenticated"], true);
	assert_eq!(artifact_count(&case), 1);
	let dir = entries(&case).pop().unwrap();
	for name in ["intent.json", "candidate.json", "completion.json"] {
		assert_eq!(
			fs::metadata(dir.join(name)).unwrap().permissions().mode() & 0o777,
			0o600
		);
	}
	let saved = fs::read(dir.join("completion.json")).unwrap();
	let repeat = run(&case).await;
	assert_eq!(repeat["accepted"], true);
	assert_eq!(
		repeat["completed_receipt_reauthenticated_by_full_guard_replay"],
		true
	);
	assert_eq!(
		repeat["candidate"]["artifact_id"],
		first["candidate"]["artifact_id"]
	);
	assert_eq!(fs::read(dir.join("completion.json")).unwrap(), saved);
	assert_eq!(artifact_count(&case), 1);
	assert_eq!(fs::read(&case.params.patch.path).unwrap(), original);
}

#[test]
fn canonical_identity_binds_full_request_roots_state_and_named_semantics() {
	let (_temp, case, _) = fixture();
	let hash =
		|c: &Case| linux::digest(&linux::canonical_request(&c.params, &c.roots, &c.state).unwrap());
	let baseline = hash(&case);
	let mut mutations = Vec::new();
	let mut c = case.clone();
	c.params.inputs[0][0] += 0.1;
	mutations.push(c);
	let mut c = case.clone();
	c.params.bias = Some(vec![0.0]);
	mutations.push(c);
	let mut c = case.clone();
	c.params.minimum_gain = 0.1;
	mutations.push(c);
	let mut c = case.clone();
	c.params.max_update_l2_norm = Some(2.0);
	mutations.push(c);
	let mut c = case.clone();
	c.params.constraints = vec![Constraint::Preserve {
		column: 0,
		max_absolute_change: 1.0,
	}];
	mutations.push(c);
	let mut c = case.clone();
	c.params.objective = Objective::SquaredError {
		targets: vec![vec![0.], vec![0.], vec![0.]],
	};
	mutations.push(c);
	let mut c = case.clone();
	c.params.patch.edits[0].replacement_hex = hex(1.5);
	mutations.push(c);
	let mut c = case.clone();
	c.params.patch.expected_sha256 = "f".repeat(64);
	mutations.push(c);
	let mut c = case.clone();
	c.params.patch.path.push_str(".other");
	mutations.push(c);
	let mut c = case.clone();
	c.roots.push(c.roots[0].join("different"));
	mutations.push(c);
	let mut c = case.clone();
	c.state = c.state.join("different");
	mutations.push(c);
	assert!(mutations.iter().all(|c| hash(c) != baseline));
	let v: Value = serde_json::from_slice(
		&linux::canonical_request(&case.params, &case.roots, &case.state).unwrap(),
	)
	.unwrap();
	for name in [
		"guard",
		"norm",
		"forward",
		"tensor",
		"artifact",
		"journal",
		"cargo_lock",
	] {
		assert_eq!(v["named_source_sha256"][name].as_str().unwrap().len(), 64);
	}
	assert_eq!(v["source_fingerprint_is_complete_execution_closure"], false);
	assert!(v["guard_semantics"].as_str().unwrap().contains("exact-l2"));
}

#[tokio::test]
async fn oversized_and_nonfinite_requests_fail_before_intent_or_artifact() {
	let (_temp, mut case, _) = fixture();
	case.params.inputs = vec![vec![1.0; 4096]; 64];
	assert!(
		evaluate_with_roots(case.params.clone(), &case.roots, &case.state)
			.await
			.is_err()
	);
	assert!(entries(&case).is_empty());
	assert_eq!(artifact_count(&case), 0);
	case.params.inputs = vec![vec![f32::NAN, 1.0]];
	assert!(
		evaluate_with_roots(case.params.clone(), &case.roots, &case.state)
			.await
			.is_err()
	);
	case.params.inputs = vec![vec![0., 1.0]];
	case.params.max_update_l2_norm = Some(f64::INFINITY);
	assert!(
		evaluate_with_roots(case.params.clone(), &case.roots, &case.state)
			.await
			.is_err()
	);
	assert!(entries(&case).is_empty());
	assert_eq!(artifact_count(&case), 0);
}

#[tokio::test]
async fn private_root_symlink_hardlink_and_changed_intent_are_denied() {
	let (temp, case, _) = fixture();
	fs::set_permissions(&case.state, fs::Permissions::from_mode(0o755)).unwrap();
	assert!(
		evaluate_with_roots(case.params.clone(), &case.roots, &case.state)
			.await
			.is_err()
	);
	fs::set_permissions(&case.state, fs::Permissions::from_mode(0o700)).unwrap();
	let outside = temp.path().join("elsewhere");
	mkdir(&outside);
	symlink(&outside, case.state.join(linux::ROOT_NAME)).unwrap();
	assert!(
		evaluate_with_roots(case.params.clone(), &case.roots, &case.state)
			.await
			.is_err()
	);
	fs::remove_file(case.state.join(linux::ROOT_NAME)).unwrap();
	let passed = run(&case).await;
	assert_eq!(passed["accepted"], true);
	let dir = entries(&case).pop().unwrap();
	let link = temp.path().join("external-link");
	fs::hard_link(dir.join("completion.json"), &link).unwrap();
	assert!(
		evaluate_with_roots(case.params.clone(), &case.roots, &case.state)
			.await
			.is_err()
	);
	fs::remove_file(link).unwrap();
	fs::write(dir.join("intent.json"), b"{}").unwrap();
	assert!(
		evaluate_with_roots(case.params.clone(), &case.roots, &case.state)
			.await
			.is_err()
	);
	assert_eq!(artifact_count(&case), 1);
}

#[tokio::test]
async fn completed_candidate_tampering_and_source_change_never_reuse_acceptance() {
	for tamper_source in [false, true] {
		let (_temp, case, original) = fixture();
		let passed = run(&case).await;
		assert_eq!(passed["accepted"], true);
		let target = if tamper_source {
			PathBuf::from(&case.params.patch.path)
		} else {
			PathBuf::from(passed["candidate"]["artifact_path"].as_str().unwrap())
		};
		let mut changed = fs::read(&target).unwrap();
		let last = changed.len() - 1;
		changed[last] ^= 1;
		fs::write(&target, changed).unwrap();
		let refused = run(&case).await;
		assert_eq!(refused["accepted"], false);
		assert_eq!(refused["current_durable_completion"], false);
		assert_eq!(refused["interruption_recovery_verified"], false);
		assert!(
			refused["error"].as_str().unwrap().contains("hash")
				|| refused["error"].as_str().unwrap().contains("SHA")
				|| refused["error"].as_str().unwrap().contains("manifest")
		);
		if !tamper_source {
			assert_eq!(fs::read(&case.params.patch.path).unwrap(), original);
		}
	}
}

#[tokio::test]
async fn altered_completed_metrics_are_detected_and_force_restore() {
	let (_temp, case, original) = fixture();
	let passed = run(&case).await;
	assert_eq!(passed["accepted"], true);
	let path = entries(&case).pop().unwrap().join("completion.json");
	let mut saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
	saved["semantic_result"]["guard"]["primary_after"] = json!(999);
	// Even a self-consistent unkeyed envelope cannot replace current evaluation.
	saved["semantic_sha256"] = json!(linux::digest(
		&serde_json::to_vec(&saved["semantic_result"]).unwrap()
	));
	fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
	let rejected = run(&case).await;
	assert_eq!(rejected["accepted"], false);
	assert_eq!(
		rejected["outcome"],
		"rejected_and_restored_journal_incomplete"
	);
	assert_eq!(
		fs::read(rejected["restoration"]["artifact_path"].as_str().unwrap()).unwrap(),
		original
	);
}

#[tokio::test]
async fn count_quota_and_abandoned_bytes_are_bounded() {
	let (_temp, case, _) = fixture();
	let root = case.state.join(linux::ROOT_NAME);
	mkdir(&root);
	for i in 0..linux::MAX_ENTRIES {
		mkdir(&root.join(format!(".pending-entry-{i}")));
	}
	let error = evaluate_with_roots(case.params.clone(), &case.roots, &case.state)
		.await
		.unwrap_err();
	assert!(error.to_string().contains("quota"));
	assert_eq!(artifact_count(&case), 0);
	let (_temp, case, _) = fixture();
	let root = case.state.join(linux::ROOT_NAME);
	mkdir(&root);
	for i in 0..64 {
		let stage = root.join(format!(".pending-entry-{i}"));
		mkdir(&stage);
		let file = fs::OpenOptions::new()
			.write(true)
			.create_new(true)
			.mode(0o600)
			.open(stage.join("intent.json"))
			.unwrap();
		file.set_len(1024 * 1024).unwrap();
	}
	let error = evaluate_with_roots(case.params.clone(), &case.roots, &case.state)
		.await
		.unwrap_err();
	assert!(error.to_string().contains("quota"));
	assert_eq!(artifact_count(&case), 0);
}

#[tokio::test]
async fn interrupted_prepublication_budget_or_label_refusal_does_not_apply_any_candidate() {
	for labels in [false, true] {
		let (_temp, mut case, _) = fixture();
		if labels {
			case.params.objective = Objective::SquaredError { targets: vec![] };
		} else {
			case.params.max_update_l2_norm = Some(0.5);
		}
		let first = run(&case).await;
		assert_eq!(first["accepted"], false);
		assert_eq!(artifact_count(&case), 0);
		let replay = run(&case).await;
		assert_eq!(replay["accepted"], false);
		assert_eq!(replay["outcome"], "rejected_recovery_unverified");
		assert_eq!(artifact_count(&case), 0);
	}
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

fn child(temp: &Path, phase: Option<&str>, tag: &str) -> (OwnedChild, PathBuf, PathBuf) {
	let marker = temp.join(format!("marker-{tag}"));
	let output = temp.join(format!("output-{tag}.json"));
	let mut command = Command::new(std::env::current_exe().unwrap());
	command
		.args([
			"--ignored",
			"--exact",
			"mcp::weight_guard_journal::tests::journal_crash_worker",
			"--nocapture",
		])
		.env("HEPTA_TEST_JOURNAL_CASE", temp.join("case.json"))
		.env("HEPTA_TEST_JOURNAL_OUTPUT", &output)
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
			"child terminated before the requested failpoint"
		);
		assert!(
			Instant::now() < deadline,
			"child failpoint deadline exceeded"
		);
		std::thread::sleep(Duration::from_millis(5));
	}
}

fn kill(child: &mut OwnedChild) {
	child.0.kill().unwrap();
	assert_eq!(child.0.wait().unwrap().signal(), Some(libc::SIGKILL));
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
			"child completion deadline exceeded"
		);
		std::thread::sleep(Duration::from_millis(5));
	}
	serde_json::from_slice(&fs::read(output).unwrap()).unwrap()
}

#[test]
#[ignore = "subprocess worker; invoked by owned crash-qualification parent only"]
fn journal_crash_worker() {
	let path = PathBuf::from(std::env::var("HEPTA_TEST_JOURNAL_CASE").unwrap());
	let case: Case = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.unwrap();
	let result = runtime.block_on(evaluate_with_roots(case.params, &case.roots, &case.state));
	let value = match result {
		Ok(report) => json!({"ok":true,"report":report}),
		Err(error) => json!({"ok":false,"accepted":false,"error":error.to_string()}),
	};
	private_write(
		&PathBuf::from(std::env::var("HEPTA_TEST_JOURNAL_OUTPUT").unwrap()),
		&serde_json::to_vec(&value).unwrap(),
	);
}

#[test]
fn real_sigkill_and_fresh_process_reconcile_cover_four_durable_boundaries() {
	for phase in [
		"after_intent",
		"after_guard_before_candidate",
		"after_candidate_before_completion",
		"after_completion",
	] {
		let (temp, case, original) = fixture();
		let started = Instant::now();
		let (mut running, marker, _) = child(temp.path(), Some(phase), "interrupted");
		wait_marker(&mut running, &marker);
		let directory = entries(&case).pop().unwrap();
		let had_candidate_record = directory.join("candidate.json").exists();
		let had_completion = directory.join("completion.json").exists();
		let artifacts_before = artifact_count(&case);
		kill(&mut running);
		let killed_wall = started.elapsed().as_secs_f64();
		let replay_start = Instant::now();
		let (mut restarted, _, output) = child(temp.path(), None, "reconcile");
		let response = finish(&mut restarted, &output);
		assert_eq!(response["ok"], true);
		let report = &response["report"];
		assert_eq!(fs::read(&case.params.patch.path).unwrap(), original);
		if phase == "after_completion" {
			assert_eq!(report["accepted"], true);
			assert_eq!(
				report["completed_receipt_reauthenticated_by_full_guard_replay"],
				true
			);
			assert_eq!(artifact_count(&case), 1);
		} else {
			assert_eq!(report["accepted"], false);
			assert_eq!(report["outcome"], "interrupted_rejected_and_restored");
			assert_eq!(report["replay_guard_internal_accepted"], true);
			assert_eq!(report["interruption_recovery_verified"], true);
			assert_eq!(
				report["restoration"]["sha256"],
				case.params.patch.expected_sha256
			);
			assert_eq!(
				fs::read(report["restoration"]["artifact_path"].as_str().unwrap()).unwrap(),
				original
			);
			assert_eq!(artifact_count(&case), 2);
			let (mut again, _, again_output) = child(temp.path(), None, "again");
			let again = finish(&mut again, &again_output);
			assert_eq!(again["report"]["accepted"], false);
			assert_eq!(
				again["report"]["completed_receipt_reauthenticated_by_full_guard_replay"],
				true
			);
			assert_eq!(artifact_count(&case), 2);
		}
		println!(
			"JOURNAL_CRASH_RECEIPT={}",
			json!({"phase":phase,"signal":libc::SIGKILL,
            "child_restarted":true,"had_candidate_record_at_kill":had_candidate_record,
            "had_completion_at_kill":had_completion,"artifacts_at_kill":artifacts_before,
            "artifacts_after_reconcile":artifact_count(&case),"accepted":report["accepted"],
            "outcome":report["outcome"],"parent_sha256":case.params.patch.expected_sha256,
            "forced_restoration_sha256":report["restoration"]["sha256"],
            "interrupted_child_observed_wall_seconds":killed_wall,
            "reconcile_and_optional_repeat_wall_seconds":replay_start.elapsed().as_secs_f64(),
            "prior_interrupted_child_cpu_known":false,"source_bytes_unchanged":true})
		);
	}
}

#[test]
fn killed_request_with_missing_changed_source_or_artifact_quota_stays_unverified() {
	for failure in ["missing_source", "changed_source", "artifact_quota"] {
		let (temp, case, _) = fixture();
		let (mut running, marker, _) = child(temp.path(), Some("after_intent"), "interrupted");
		wait_marker(&mut running, &marker);
		kill(&mut running);
		match failure {
			"missing_source" => fs::remove_file(&case.params.patch.path).unwrap(),
			"changed_source" => {
				let mut bytes = fs::read(&case.params.patch.path).unwrap();
				let last = bytes.len() - 1;
				bytes[last] ^= 1;
				fs::write(&case.params.patch.path, bytes).unwrap();
			}
			"artifact_quota" => {
				let root = case.state.join("weight-artifacts-v1");
				mkdir(&root);
				for i in 0..128 {
					mkdir(&root.join(format!(".pending-test-{i}")));
				}
			}
			_ => unreachable!(),
		}
		let (mut restarted, _, output) = child(temp.path(), None, "reconcile");
		let response = finish(&mut restarted, &output);
		assert_eq!(response["ok"], true);
		let report = &response["report"];
		assert_eq!(report["accepted"], false);
		assert_eq!(report["outcome"], "rejected_recovery_unverified");
		assert_eq!(report["interruption_recovery_verified"], false);
		assert_eq!(artifact_count(&case), 0);
		println!(
			"JOURNAL_CRASH_FAILURE_RECEIPT={}",
			json!({"case":failure,"signal":libc::SIGKILL,
            "child_restarted":true,"accepted":false,"outcome":report["outcome"],
            "recovery_verified":false,"artifacts_published":0,"failure_durably_retained":report["this_failure_durably_retained"]})
		);
	}
}

#[test]
fn live_cross_process_lock_prevents_concurrent_duplicate_evaluation() {
	let (temp, case, original) = fixture();
	let (mut first, marker, _) = child(temp.path(), Some("after_intent"), "holder");
	wait_marker(&mut first, &marker);
	let (mut second, _, output) = child(temp.path(), None, "contender");
	let denied = finish(&mut second, &output);
	assert_eq!(denied["ok"], false);
	assert!(denied["error"].as_str().unwrap().contains("busy"));
	assert_eq!(entries(&case).len(), 1);
	assert_eq!(artifact_count(&case), 0);
	kill(&mut first);
	let (mut restarted, _, output) = child(temp.path(), None, "reconcile");
	let response = finish(&mut restarted, &output);
	assert_eq!(response["report"]["accepted"], false);
	assert_eq!(response["report"]["interruption_recovery_verified"], true);
	assert_eq!(fs::read(&case.params.patch.path).unwrap(), original);
	println!(
		"JOURNAL_CONCURRENCY_RECEIPT={}",
		json!({"live_cross_process_flock":true,
        "second_process_rejected_busy":true,"model_artifacts_while_locked":0,
        "owner_killed_signal":libc::SIGKILL,"fresh_process_recovery_verified":true})
	);
}
