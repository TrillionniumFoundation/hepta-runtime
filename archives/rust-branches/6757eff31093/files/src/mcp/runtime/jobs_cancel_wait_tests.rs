// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Cancellation wait boundaries execute the complete bound helper and retain its outcome.
use super::*;
use std::io::{Seek, Write};
use std::process::{Child, Command};
use std::time::Instant;

struct Reap(Child);

impl Drop for Reap {
	fn drop(&mut self) {
		if !matches!(self.0.try_wait(), Ok(Some(_))) {
			let _ = self.0.kill();
			let _ = self.0.wait();
		}
	}
}

fn exercise(options: Value) -> Value {
	let mut input = tempfile::NamedTempFile::new().unwrap();
	let stdout = tempfile::NamedTempFile::new().unwrap();
	let stderr = tempfile::NamedTempFile::new().unwrap();
	serde_json::to_writer(
		&mut input,
		&json!({"helper":bound_remote_code(CANCEL_CODE).unwrap(),"options":options}),
	)
	.unwrap();
	input.flush().unwrap();
	input.rewind().unwrap();
	// Regular files avoid pipe backpressure while the bounded parent reaps the helper.
	let mut child = Reap(
		Command::new("python3")
			.args([
				"-I",
				"-S",
				"-c",
				include_str!("jobs_cancel_wait_fixture.py"),
			])
			.stdin(input.reopen().unwrap())
			.stdout(stdout.reopen().unwrap())
			.stderr(stderr.reopen().unwrap())
			.spawn()
			.unwrap(),
	);
	let deadline = Instant::now() + Duration::from_secs(10);
	let status = loop {
		if let Some(status) = child.0.try_wait().unwrap() {
			break status;
		}
		assert!(
			Instant::now() < deadline,
			"cancel wait fixture did not finish"
		);
		std::thread::sleep(Duration::from_millis(10));
	};
	assert!(
		status.success(),
		"{}",
		std::fs::read_to_string(stderr.path()).unwrap()
	);
	serde_json::from_slice(&std::fs::read(stdout.path()).unwrap()).unwrap()
}

fn acknowledged(trace: &Value, atomic: bool) {
	assert!(trace["error"].is_null(), "{trace:#}");
	let ack: Value = serde_json::from_str(trace["stdout"].as_str().unwrap()).unwrap();
	assert_eq!(ack["result"], "term_sent");
	assert_eq!(ack["atomic_identity"], atomic);
	assert_eq!(ack["supervisor_pid"], 424242);
	assert_eq!(ack["termination_confirmed"], false);
	assert_eq!(ack["reconcile_via"], "process_status");
	assert_eq!(
		trace["signals"],
		json!([if atomic { "pidfd" } else { "posix" }])
	);
	assert_eq!(trace["pidfd_leaked"], false);
	assert_eq!(trace["pidfd_closes"], usize::from(atomic));
	assert_eq!(trace["cancel_receipt"]["job_id"], "wait-fixture");
	assert_eq!(trace["cancel_receipt"]["launch_nonce"], "b".repeat(32));
	let retained = retain_cancel_outcome("wait-fixture", Ok(ack));
	assert_eq!(retained["result"], "term_sent");
	assert_eq!(retained["termination_confirmed"], false);
	assert_eq!(retained["automatic_retry"], false);
}

fn unknown_after_signal(trace: &Value, kind: &str, message: &str) {
	assert_eq!(trace["error"]["type"], kind, "{trace:#}");
	assert!(trace["error"]["message"]
		.as_str()
		.unwrap()
		.contains(message));
	assert_eq!(trace["stdout"], "");
	assert_eq!(trace["signals"], json!(["pidfd"]));
	assert_eq!(trace["pidfd_closes"], 1);
	assert_eq!(trace["pidfd_leaked"], false);
	assert_eq!(trace["sleeps"], json!([]));
	assert_eq!(trace["cancel_receipt"]["job_id"], "wait-fixture");
	let retained = retain_cancel_outcome(
		"wait-fixture",
		Err(anyhow::anyhow!("{}", trace["error"]["message"])),
	);
	assert_eq!(retained["result"], "cancel_unknown");
	assert_eq!(retained["outcome"], "unknown");
	assert_eq!(retained["automatic_retry"], false);
	assert_eq!(retained["termination_confirmed"], false);
	assert!(retained.get("signal_sent").is_none());
}

#[test]
fn pidfd_readiness_wakes_without_a_terminal_receipt_or_completion_claim() {
	for mask in [1, 16, 17] {
		let trace = exercise(json!({"poll_steps":[{"elapsed_ms":17,"mask":mask}]}));
		acknowledged(&trace, true);
		assert_eq!(trace["exit_exists"], false);
		assert_eq!(trace["elapsed_ns"], 17_000_000);
		assert_eq!(trace["polls"].as_array().unwrap().len(), 1);
		assert_eq!(trace["sleeps"], json!([]));
	}
}

#[test]
fn pidfd_readiness_rechecks_real_metadata_even_at_or_after_the_grace_deadline() {
	for (grace, elapsed) in [(0.1, 17.0), (0.02, 20.0), (0.02, 20.5)] {
		let trace = exercise(json!({"grace":grace,"poll_steps":[
			{"elapsed_ms":elapsed,"mask":1,"replace_exit":"corrupt"}
		]}));
		unknown_after_signal(&trace, "SystemExit", "corrupt remote job file exit.json");
		assert_eq!(trace["polls"].as_array().unwrap().len(), 1);
		let events = trace["events"].as_array().unwrap();
		let replaced = events
			.iter()
			.position(|row| row["kind"] == "replace_exit")
			.unwrap();
		assert!(events[replaced + 1..]
			.iter()
			.any(|row| row["kind"] == "read_exit"));
	}
}

#[test]
fn interrupted_and_empty_pidfd_waits_share_the_original_grace_budget() {
	for steps in [
		json!([]),
		json!([
			{"elapsed_ms":17,"error":"eintr"},
			{"elapsed_ms":23,"error":"eintr"},
			{"elapsed_ms":11,"error":"eintr"}
		]),
	] {
		let trace = exercise(json!({"grace":0.253,"poll_steps":steps}));
		acknowledged(&trace, true);
		let elapsed = trace["elapsed_ns"].as_u64().unwrap();
		assert!((253_000_000..=254_000_000).contains(&elapsed), "{trace:#}");
		for wait in trace["polls"].as_array().unwrap() {
			let at = wait["at_ns"].as_u64().unwrap();
			assert!(
				at < 253_000_000,
				"new wait began after the original deadline"
			);
			// Integer-millisecond poll timeouts can round a float boundary up by 1 ms.
			let requested_end = at + wait["timeout_ms"].as_u64().unwrap() * 1_000_000;
			assert!(
				requested_end <= 254_000_000,
				"wait extended the original deadline"
			);
		}
		assert_eq!(trace["sleeps"], json!([]));
	}
	let submillisecond = exercise(json!({"grace":0.0001}));
	acknowledged(&submillisecond, true);
	assert_eq!(submillisecond["elapsed_ns"], 1_000_000);
	assert_eq!(submillisecond["polls"].as_array().unwrap().len(), 1);
}

#[test]
fn pidfd_error_masks_and_foreign_events_cannot_acknowledge_or_resend() {
	let mut steps = [8, 32, 9, 33, 4, 0]
		.map(|mask| json!({"elapsed_ms":17,"mask":mask}))
		.to_vec();
	steps.push(json!({"elapsed_ms":17,"mask":1,"foreign_fd":true}));
	steps.push(json!({"elapsed_ms":17,"mask":1,"duplicate_event":true}));
	for step in steps {
		let trace = exercise(json!({"poll_steps":[step]}));
		unknown_after_signal(&trace, "RuntimeError", "original supervisor wait invalid");
		assert_eq!(trace["polls"].as_array().unwrap().len(), 1);
	}
}

#[test]
fn pidfd_syscall_failure_and_lost_ack_retain_unknown_without_another_signal() {
	let failed = exercise(json!({"poll_steps":[{"elapsed_ms":17,"error":"badfd"}]}));
	unknown_after_signal(&failed, "OSError", "fixture poll syscall failed");
	assert_eq!(failed["polls"].as_array().unwrap().len(), 1);
	let lost = exercise(json!({"lost_ack":true,"poll_steps":[{"elapsed_ms":17,"mask":1}]}));
	unknown_after_signal(&lost, "BrokenPipeError", "fixture ACK receiver disappeared");
	assert_eq!(lost["polls"].as_array().unwrap().len(), 1);
}

#[test]
fn pidfd_wait_setup_failure_precedes_the_cancellation_receipt_and_signal() {
	for failure in ["poll", "register", "missing_pidfd"] {
		let trace = exercise(json!({"setup_error":failure}));
		assert_eq!(
			trace["error"]["type"],
			if failure == "missing_pidfd" {
				"SystemExit"
			} else {
				"OSError"
			},
			"{trace:#}"
		);
		assert_eq!(trace["stdout"], "");
		assert_eq!(trace["signals"], json!([]));
		assert!(trace["cancel_receipt"].is_null());
		assert_eq!(trace["polls"], json!([]));
		assert_eq!(
			trace["pidfd_closes"],
			usize::from(failure != "missing_pidfd")
		);
		assert_eq!(trace["pidfd_leaked"], false);
	}
}

#[test]
fn non_linux_cancellation_keeps_pid_signal_and_the_original_metadata_cadence() {
	let trace = exercise(json!({"platform":"darwin","exit_after_ms":250}));
	acknowledged(&trace, false);
	assert_eq!(trace["elapsed_ns"], 300_000_000);
	assert_eq!(trace["sleeps"], json!([0.1, 0.1, 0.1]));
	assert_eq!(trace["polls"], json!([]));
	assert!(!trace["events"]
		.as_array()
		.unwrap()
		.iter()
		.any(|row| { row["kind"] == "import_select" || row["kind"] == "pidfd_open" }));
}

#[test]
fn terminal_and_zero_grace_cancellation_do_not_enter_a_wait() {
	let terminal = exercise(json!({"already_exited":true}));
	assert!(terminal["error"].is_null());
	assert_eq!(terminal["signals"], json!([]));
	assert_eq!(terminal["polls"], json!([]));
	assert_eq!(terminal["pidfd_closes"], 0);
	assert!(terminal["cancel_receipt"].is_null());
	let ack: Value = serde_json::from_str(terminal["stdout"].as_str().unwrap()).unwrap();
	assert_eq!(
		ack,
		json!({"job_id":"wait-fixture","result":"already_exited"})
	);
	let zero = exercise(json!({"grace":0}));
	acknowledged(&zero, true);
	assert_eq!(zero["elapsed_ns"], 0);
	assert_eq!(zero["polls"], json!([]));
}
