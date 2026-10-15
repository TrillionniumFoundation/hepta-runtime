// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Lost acknowledgements retain the authorized persistent terminal identity.
use super::*;

fn record() -> TerminalRecord {
	TerminalRecord {
		session_id: "dpty-existing".into(),
		host: "target-host".into(),
		ssh_target: "pinned-target".into(),
		remote_state_dir: "/private/state".into(),
		job_dir: "/private/state/terminals/dpty-existing".into(),
		request: json!({"env":{"SECRET":"credential"}}),
	}
}

#[test]
fn terminal_transport_failure_retains_same_session_for_every_effect() {
	for operation in ["start", "write", "close"] {
		let result = retain_terminal_outcome(
			&record(),
			operation,
			Err(anyhow::anyhow!("SECRET ssh lost acknowledgement")),
			Some(7),
		);
		assert_eq!(result["session_id"], "dpty-existing");
		assert_eq!(result["host"], "target-host");
		assert_eq!(result["outcome"], "unknown");
		assert_eq!(result["automatic_retry"], false);
		assert_eq!(result["persistent_across_runtime_restart"], true);
		assert!(result.get("bytes_written").is_none());
		assert!(!result.to_string().contains("SECRET"));
		assert!(!result.to_string().contains("credential"));
		if operation == "close" {
			assert_eq!(result["termination_confirmed"], false);
		}
	}
}

#[test]
fn terminal_invalid_acknowledgements_never_claim_delivered_input_or_termination() {
	for (operation, values) in [
		(
			"start",
			vec![
				Value::Null,
				json!([]),
				json!({"reused":false,"status":{"state":"invented","output_complete":true}}),
			],
		),
		(
			"write",
			vec![
				json!({"bytes_written":8,"complete":true,"reused":false}),
				json!({"bytes_written":3,"complete":true,"reused":false}),
				json!({"bytes_written":7,"complete":true}),
			],
		),
		(
			"close",
			vec![
				json!({"result":"terminated"}),
				json!({"result":"close_requested","error":"SECRET"}),
			],
		),
	] {
		for ack in values {
			let result = retain_terminal_outcome(&record(), operation, Ok(ack), Some(7));
			assert_eq!(result["outcome"], "unknown", "invalid {operation} ack");
			assert_eq!(result["automatic_retry"], false);
			assert_eq!(result["session_id"], "dpty-existing");
			assert!(!result.to_string().contains("SECRET"));
		}
	}
}

#[test]
fn partial_terminal_write_ack_and_local_binding_survive_completion_audit_failure() {
	let ack = json!({"bytes_written":3,"complete":false,"reused":false,"host":"spoofed-host","session_id":"spoofed-session"});
	let result = retain_terminal_outcome(&record(), "write", Ok(ack), Some(7));
	let result = retain_pty_after_audit(result, Err(anyhow::anyhow!("SECRET audit sync failed")));
	assert_eq!(result["bytes_written"], 3);
	assert_eq!(result["complete"], false);
	assert_eq!(result["host"], "target-host");
	assert_eq!(result["session_id"], "dpty-existing");
	assert_eq!(result["automatic_retry"], false);
	assert_eq!(result["audit_recorded"], false);
	assert!(!result.to_string().contains("SECRET"));
}

#[test]
fn persistent_unknown_start_state_is_preserved_without_becoming_success() {
	for state in ["lost", "launch_unknown"] {
		let result = retain_terminal_outcome(
			&record(),
			"start",
			Ok(json!({"reused":true,"status":{"state":state,"output_complete":false}})),
			None,
		);
		assert_eq!(result["status"]["state"], state);
		assert_eq!(result["outcome"], "unknown");
		assert_eq!(result["automatic_retry"], false);
	}
	let result = retain_terminal_outcome(
		&record(),
		"start",
		Ok(json!({"reused":false,"status":{"state":"running","output_complete":false,"pid":123}})),
		None,
	);
	assert_eq!(result["status"]["pid"], 123);
	assert!(result.get("outcome").is_none());
}

#[test]
fn close_acknowledgement_never_infers_exit_from_absent_owner() {
	for (ack, confirmed) in [("close_requested", false), ("already_exited", false)] {
		let result = retain_terminal_outcome(&record(), "close", Ok(json!({"result":ack})), None);
		let result =
			retain_pty_after_audit(result, Err(anyhow::anyhow!("SECRET audit unavailable")));
		assert_eq!(result["result"], ack);
		assert_eq!(result["termination_confirmed"], confirmed);
		if ack == "already_exited" {
			assert_eq!(result["outcome"], "unknown");
		}
		assert_eq!(result["audit_recorded"], false);
		assert_eq!(result["automatic_retry"], false);
	}
}
