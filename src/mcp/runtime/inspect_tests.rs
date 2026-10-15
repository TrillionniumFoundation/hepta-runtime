// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Pinned-action result retention tests; no actions or sudo privileges are configured.
use super::*;

fn pinned_ack(code: i32, stdout: &str, stderr: &str) -> Value {
	json!({"exit_code":code,"exit_code_authoritative":true,"process_exit_confirmed":true,
		"stdout":stdout,"stderr":stderr,"timed_out":false,"stdout_truncated":false,
		"stderr_truncated":false,"stdout_bytes_seen":stdout.len(),"stderr_bytes_seen":stderr.len(),
		"capture_error":null,"output_complete":true,"output_limit_bytes_per_stream":524288,
		"descendant_termination_confirmed":false})
}

#[test]
fn pinned_action_completion_audit_failure_preserves_real_exit_and_output_without_retry() {
	for code in [0, 7] {
		let output = json!({"exit_code":code,"stdout":"actual action output","stderr":"actual action diagnostics","timed_out":false});
		let retained = retain_privileged_after_audit(
			output.clone(),
			Err(anyhow::anyhow!("PRIVATE_AUDIT_SECRET")),
		);
		for (key, value) in output.as_object().unwrap() {
			assert_eq!(&retained[key], value);
		}
		assert_eq!(retained["audit_recorded"], false);
		assert_eq!(retained["automatic_retry"], false);
		assert!(!retained.to_string().contains("PRIVATE_AUDIT_SECRET"));
	}
	let retained = retain_privileged_after_audit(json!({"exit_code":0,"stdout":"ok"}), Ok(()));
	assert_eq!(retained["audit_recorded"], true);
	assert!(retained.get("audit_warning").is_none());
}

#[test]
fn pinned_action_intent_unknown_ack_and_wire_limits_fail_closed_without_raw_diagnostics() {
	let params: PrivilegedActionParams =
		serde_json::from_value(json!({"host":"main","action":"owned-fixture","args":[]})).unwrap();
	assert!(
		require_privileged_intent(Err(anyhow::anyhow!("SECRET_PATH")))
			.unwrap_err()
			.to_string()
			.contains("no action request dispatched")
	);
	for remote in [
		Err(anyhow::anyhow!("RAW_SECRET")),
		Ok(Value::Null),
		Ok(json!("RAW_SECRET")),
		Ok(json!({"exit_code":0,"stdout":"x","stderr":""})),
	] {
		let result = retain_privileged_outcome(&params, remote);
		assert_eq!(result["outcome"], "unknown");
		assert_eq!(result["automatic_retry"], false);
		assert!(!result.to_string().contains("SECRET"));
	}
	let result = retain_privileged_after_audit(Value::Null, Ok(()));
	assert_eq!(result["outcome"], "unknown");
	let normal124 = retain_privileged_outcome(&params, Ok(pinned_ack(124, "", "")));
	assert_eq!(normal124["exit_code"], 124);
	assert_eq!(normal124["timed_out"], false);
	let mut with_extra = pinned_ack(0, "ok", "");
	with_extra["untrusted_extra"] = json!("ACK_SECRET");
	let filtered = retain_privileged_outcome(&params, Ok(with_extra));
	assert_eq!(filtered["host"], "main");
	assert_eq!(filtered["action"], "owned-fixture");
	assert!(!filtered.to_string().contains("ACK_SECRET"));
	for field in [
		"stdout_truncated",
		"process_exit_confirmed",
		"descendant_termination_confirmed",
		"exit_code_authoritative",
	] {
		let mut malformed = pinned_ack(0, "", "");
		malformed[field] = json!("MALFORMED_SECRET");
		assert_eq!(
			retain_privileged_outcome(&params, Ok(malformed))["outcome"],
			"unknown"
		);
	}
	let mut false_timeout = pinned_ack(0, "", "");
	false_timeout["timed_out"] = json!(true);
	assert_eq!(
		retain_privileged_outcome(&params, Ok(false_timeout))["outcome"],
		"unknown"
	);
	let controlled = retain_privileged_outcome(
		&params,
		Ok(pinned_ack(
			0,
			&"\u{1}".repeat(524288),
			&"\u{1}".repeat(524288),
		)),
	);
	assert_eq!(controlled["exit_code"], 0);
	let oversized = retain_privileged_outcome(&params, Ok(pinned_ack(0, &"x".repeat(524289), "")));
	assert_eq!(oversized["outcome"], "unknown");
}
