// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Actual independent-process SIGKILL and cold recovery at both atomic publication boundaries.
//! Fixtures are synthetic owner controls, not independent model-quality experiments.

use super::*;
use crate::mcp::rea_model::session::weight::late_quote as scope;
use std::os::unix::{fs::PermissionsExt, process::ExitStatusExt};
use std::process::{Command, Output, Stdio};
use std::time::Instant;

const CHILD: &str =
	"mcp::weight_artifact::cohort::late_quote::crash_tests::late_quote_crash_worker";

#[test]
fn late_quote_crash_worker() {
	let Ok(mode) = std::env::var("HEPTA_LATE_QUOTE_CHILD_MODE") else {
		return;
	};
	let ipc = PathBuf::from(std::env::var("HEPTA_LATE_QUOTE_CHILD_IPC").unwrap());
	let runtime = tokio::runtime::Builder::new_multi_thread()
		.worker_threads(2)
		.enable_all()
		.build()
		.unwrap();
	runtime.block_on(async {
		if mode=="run" {
			let case=tests::fixture(true,1.0).await;
			let plan=tests::planned(&case).await;
			let descriptor=json!({"schema":"hepta.late-quote.synthetic-process-case.v1","config":case.config,"params":case.params,"input":case.input,
				"plan":plan,"source":case.path,"parent_sha256":digest(&case.parent),"owned_root":case._temp.path()});
			write_record(&ipc,"case.json",&serde_json::to_vec(&descriptor).unwrap()).await.unwrap();
			let result=tests::execute(&case,plan["journal_id"].as_str().unwrap()).await;
			write_record(&ipc,"unexpected-completion.json",&serde_json::to_vec(&result).unwrap()).await.unwrap();
			panic!("real crash boundary was not reached");
		}
		assert_eq!(mode,"recover");
		let descriptor:Value=serde_json::from_slice(&tokio::fs::read(ipc.join("case.json")).await.unwrap()).unwrap();
		runtime::init_runtime(serde_json::from_value(descriptor["config"].clone()).unwrap()).unwrap();
		let params:scope::Params=serde_json::from_value(descriptor["params"].clone()).unwrap();
		let authority=scope::admit_for_test(&params,tests::OWNER_A).await.unwrap();
		let plan=&descriptor["plan"];
		let result=recover(plan["journal_id"].as_str().unwrap().into(),plan["plan_sha256"].as_str().unwrap().into(),authority,
			runtime::effect_owner_fence::admit_new_effect().await.unwrap()).await.unwrap();
		let file=std::env::var("HEPTA_LATE_QUOTE_CHILD_RESULT").unwrap();
		write_record(&ipc,&file,&serde_json::to_vec(&result).unwrap()).await.unwrap();
	});
}

fn child(ipc: &Path, mode: &str, result: &str) -> Command {
	let mut command = Command::new(std::env::current_exe().unwrap());
	command
		.args(["--exact", CHILD, "--nocapture"])
		.env("HEPTA_LATE_QUOTE_CHILD_MODE", mode)
		.env("HEPTA_LATE_QUOTE_CHILD_IPC", ipc)
		.env("HEPTA_LATE_QUOTE_CHILD_RESULT", result)
		.stdout(Stdio::null())
		.stderr(Stdio::piped());
	command
}

fn bounded_recovery(ipc: &Path, result: &str) -> Output {
	let mut process = child(ipc, "recover", result).spawn().unwrap();
	let started = Instant::now();
	loop {
		if process.try_wait().unwrap().is_some() {
			return process.wait_with_output().unwrap();
		}
		if started.elapsed() > Duration::from_secs(45) {
			process.kill().unwrap();
			let output = process.wait_with_output().unwrap();
			panic!(
				"cold recovery watchdog: {}",
				String::from_utf8_lossy(&output.stderr)
			);
		}
		std::thread::sleep(Duration::from_millis(10));
	}
}

fn snapshot_tree(root: &Path) -> Vec<(String, String)> {
	fn visit(root: &Path, path: &Path, out: &mut Vec<(String, String)>) {
		let mut entries = std::fs::read_dir(path)
			.unwrap()
			.map(|e| e.unwrap().path())
			.collect::<Vec<_>>();
		entries.sort();
		for p in entries {
			if p.is_dir() {
				visit(root, &p, out);
			} else {
				out.push((
					p.strip_prefix(root).unwrap().to_string_lossy().into_owned(),
					digest(&std::fs::read(p).unwrap()),
				));
			}
		}
	}
	let mut result = Vec::new();
	visit(root, root, &mut result);
	result
}

fn real_crash(occurrence: usize) {
	let ipc = tempfile::tempdir().unwrap();
	std::fs::set_permissions(ipc.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
	let marker = ipc.path().join("published.marker");
	let mut writer = child(ipc.path(), "run", "unused.json")
		.env("HEPTA_TEST_COHORT_PHASE", "published")
		.env("HEPTA_TEST_COHORT_OCCURRENCE", occurrence.to_string())
		.env("HEPTA_TEST_COHORT_MARKER", &marker)
		.spawn()
		.unwrap();
	let started = Instant::now();
	while !marker.is_file() {
		if let Some(status) = writer.try_wait().unwrap() {
			let output = writer.wait_with_output().unwrap();
			panic!(
				"child stopped before publication {status}: {}",
				String::from_utf8_lossy(&output.stderr)
			);
		}
		if started.elapsed() > Duration::from_secs(45) {
			writer.kill().unwrap();
			let output = writer.wait_with_output().unwrap();
			panic!(
				"crash marker deadline: {}",
				String::from_utf8_lossy(&output.stderr)
			);
		}
		std::thread::sleep(Duration::from_millis(10));
	}
	writer.kill().unwrap();
	let status = writer.wait().unwrap();
	assert_eq!(status.signal(), Some(libc::SIGKILL));
	let descriptor: Value =
		serde_json::from_slice(&std::fs::read(ipc.path().join("case.json")).unwrap()).unwrap();
	let state = PathBuf::from(descriptor["config"]["state_dir"].as_str().unwrap());
	let id = descriptor["plan"]["journal_id"].as_str().unwrap();
	let directory = state.join("weight-cohort-journal-v1").join(id);
	let saved: journal::Saved =
		serde_json::from_slice(&std::fs::read(directory.join("late-intent.json")).unwrap())
			.unwrap();
	let decision: journal::Decision =
		serde_json::from_slice(&std::fs::read(directory.join("late-decision.json")).unwrap())
			.unwrap();
	assert_eq!(decision.action, Action::Keep);
	let candidate = saved.manifest(Action::Keep).unwrap();
	assert_eq!(
		candidate.target_sha256,
		saved.plan.parent_function.artifact_sha256
	);
	let store = state.join("weight-artifacts-v1");
	let inverse = inverse::inverse_manifest(&saved, &decision, &store).unwrap();
	let interrupted = if occurrence == 1 { candidate } else { &inverse };
	assert!(store
		.join(&interrupted.artifact_id)
		.join("model.safetensors")
		.is_file());
	assert!(!state
		.join("weight-cohort-journal-v1")
		.join(&interrupted.request.request_id)
		.join("outcome.json")
		.exists());
	std::fs::remove_file(descriptor["source"].as_str().unwrap()).unwrap();
	let result = bounded_recovery(ipc.path(), "recovery-one.json");
	assert!(
		result.status.success(),
		"{}",
		String::from_utf8_lossy(&result.stderr)
	);
	let first: Value =
		serde_json::from_slice(&std::fs::read(ipc.path().join("recovery-one.json")).unwrap())
			.unwrap();
	assert_eq!(
		first["weights_graph_route_initial_state_and_evaluator_restored"], true,
		"{first}"
	);
	assert_eq!(first["original_source_path_opened"], false);
	assert_eq!(first["pure_compiler_invocations_this_request"], 0);
	assert_eq!(first["selection_replayed_on_recovery"], false);
	assert_eq!(first["parent_or_candidate_forward_replayed"], false);
	assert_eq!(first["new_complete_forward_results_this_request"], 2);
	assert_eq!(first["restoration"]["artifact_id"], inverse.artifact_id);
	assert_eq!(
		first["restoration"]["function_capsule"]["function"]["graph"],
		"original"
	);
	assert_eq!(
		first["restoration"]["function_capsule"]["function"]["request_route"],
		"original_fixed_profile"
	);
	assert_eq!(
		first["restoration"]["function_capsule"]["function"]["initial_state_contract"],
		"fixed_reset_step0_six_tick_v1"
	);
	assert_eq!(
		first["restoration"]["function_capsule"]["route_contract"]["late_request_graph"],
		"original"
	);
	assert_eq!(
		first["attempt_ledger"]["completed_forward_calls_with_durable_results"],
		if occurrence == 1 { 5 } else { 7 }
	);
	let before = snapshot_tree(&state);
	let result = bounded_recovery(ipc.path(), "recovery-two.json");
	assert!(
		result.status.success(),
		"{}",
		String::from_utf8_lossy(&result.stderr)
	);
	let second: Value =
		serde_json::from_slice(&std::fs::read(ipc.path().join("recovery-two.json")).unwrap())
			.unwrap();
	assert_eq!(second["new_complete_forward_results_this_request"], 0);
	assert_eq!(
		second["restoration"]["artifact_id"],
		first["restoration"]["artifact_id"]
	);
	assert_eq!(second["reused_original_result"], true);
	assert_eq!(
		snapshot_tree(&state),
		before,
		"cold recovery must not republish or rewrite the original durable effects"
	);
	assert!(!Path::new(descriptor["source"].as_str().unwrap()).exists());
	std::fs::remove_dir_all(descriptor["owned_root"].as_str().unwrap()).unwrap();
}

#[test]
fn graph_only_same_sha_hard_kill_before_publication_receipt_recovers_original_function() {
	real_crash(1);
}

#[test]
fn inverse_hard_kill_before_receipt_is_reconciled_once_in_fresh_processes() {
	real_crash(2);
}
