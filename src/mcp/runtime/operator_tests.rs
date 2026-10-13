// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Operator argument contracts; no production process is signalled.
use super::*;

#[test]
fn signal_rejects_process_groups_and_wildcards() {
	for pid in [0, u32::MAX, (i32::MAX as u32) + 1] {
		let p: HostSignalParams = serde_json::from_value(json!({"host":"test","pid":pid})).unwrap();
		assert!(validate_signal(&p).is_err());
	}
	let p: HostSignalParams = serde_json::from_value(json!({"host":"test","pid":1234})).unwrap();
	assert_eq!(validate_signal(&p).unwrap(), 15);
}

#[test]
fn signal_keeps_real_pid_scope_and_probe() {
	for number in [0, 9, 15, 19] {
		let p: HostSignalParams = serde_json::from_value(
			json!({"host":"test","pid":1234,"signal":number,"expected_identity":"boot:ticks"}),
		)
		.unwrap();
		assert_eq!(validate_signal(&p).unwrap(), number);
	}
	let p: HostSignalParams =
		serde_json::from_value(json!({"host":"test","pid":1234,"signal":-1})).unwrap();
	assert!(validate_signal(&p).is_err());
}

#[test]
fn sudo_preserves_argv_and_defaults_to_fresh_auth() {
	let p: SudoStartParams = serde_json::from_value(
		json!({"host":"test","executable":"/bin/sh","args":["-c","printf '%s' \"a; b 中文\""]}),
	)
	.unwrap();
	assert!(p.fresh_auth);
	assert_eq!(
		sudo_argv(&p).unwrap(),
		[
			"-k",
			"-u",
			"root",
			"--",
			"/bin/sh",
			"-c",
			"printf '%s' \"a; b 中文\""
		]
	);
}

#[test]
fn sudo_rejects_option_injection_and_supports_noninteractive() {
	let mut p: SudoStartParams = serde_json::from_value(
		json!({"host":"test","executable":"/usr/bin/id","non_interactive":true,"fresh_auth":false}),
	)
	.unwrap();
	assert_eq!(
		sudo_argv(&p).unwrap(),
		["-n", "-u", "root", "--", "/usr/bin/id"]
	);
	p.run_as = Some("-n".into());
	assert!(sudo_argv(&p).is_err());
}

#[test]
fn operator_schemas_reject_hidden_authority_fields() {
	assert!(serde_json::from_value::<HostSignalParams>(
		json!({"host":"test","pid":1234,"execution_mode":"operator"})
	)
	.is_err());
	assert!(serde_json::from_value::<SudoStartParams>(
		json!({"host":"test","executable":"/usr/bin/id","password":"never"})
	)
	.is_err());
}

#[test]
fn failed_signal_intent_is_a_redacted_zero_dispatch_refusal() {
	let error = require_signal_intent(Err(anyhow::anyhow!("PRIVATE_AUDIT_PATH_TOKEN")))
		.unwrap_err()
		.to_string();
	assert_eq!(
		error,
		"Host signal intent audit unavailable; no signal request dispatched"
	);
	assert!(!error.contains("PRIVATE_AUDIT_PATH_TOKEN"));
	assert!(require_signal_intent(Ok(())).is_ok());
}

#[cfg(unix)]
fn signal_output(code: i32, stdout: &str, stderr: &str) -> std::process::Output {
	use std::os::unix::process::ExitStatusExt;
	std::process::Output {
		status: std::process::ExitStatus::from_raw(code << 8),
		stdout: stdout.as_bytes().to_vec(),
		stderr: stderr.as_bytes().to_vec(),
	}
}

#[cfg(unix)]
#[test]
fn signal_ack_survives_completion_audit_failure_and_filters_untrusted_extras() {
	let p: HostSignalParams = serde_json::from_value(
		json!({"host":"main","pid":1234,"signal":15,"expected_identity":"linux:boot:42"}),
	)
	.unwrap();
	let ack = json!({"pid":1234,"signal":15,"identity":"linux:boot:42","result":"signal_sent","atomic_identity":true,"effective_uid":1000,"termination_confirmed":false,"extra":"ACK_SECRET"});
	let result = retain_signal_outcome(&p, 15, Ok(signal_output(0, &ack.to_string(), ""))).unwrap();
	assert_eq!(result["result"], "signal_sent");
	assert!(!result.to_string().contains("ACK_SECRET"));
	let retained = retain_signal_after_audit(result, Err(anyhow::anyhow!("AUDIT_SECRET")));
	assert_eq!(retained["pid"], 1234);
	assert_eq!(retained["identity"], "linux:boot:42");
	assert_eq!(retained["result"], "signal_sent");
	assert_eq!(retained["audit_recorded"], false);
	assert_eq!(retained["automatic_retry"], false);
	assert_eq!(retained["termination_confirmed"], false);
	assert!(!retained.to_string().contains("AUDIT_SECRET"));
}

#[cfg(unix)]
#[test]
fn transport_loss_or_success_without_matching_ack_is_unknown_without_retry() {
	let p: HostSignalParams = serde_json::from_value(
		json!({"host":"mac","pid":1234,"signal":15,"expected_identity":"ps:known-start"}),
	)
	.unwrap();
	for remote in [Err(anyhow::anyhow!("SSH_SECRET")),Ok(signal_output(255,"","SSH_SECRET")),
		Ok(signal_output(0,"INVALID_ACK_SECRET","")),Ok(signal_output(0,"{}","")),
		Ok(signal_output(0,&json!({"pid":1235,"signal":15,"identity":"ps:known-start","result":"signal_sent","atomic_identity":false,"effective_uid":1000,"termination_confirmed":false}).to_string(),""))] {
		let result=retain_signal_outcome(&p,15,remote).unwrap();
		assert_eq!(result["outcome"],"unknown");assert_eq!(result["automatic_retry"],false);
		assert_eq!(result["pid"],1234);assert_eq!(result["expected_identity"],"ps:known-start");
		assert!(!result.to_string().contains("SECRET"));
	}
	let after_syscall = retain_signal_outcome(
		&p,
		15,
		Ok(signal_output(1, "", "PRIVATE syscall cleanup failed")),
	)
	.unwrap();
	assert_eq!(after_syscall["outcome"], "unknown");
	assert_eq!(after_syscall["pid"], 1234);
	assert_eq!(after_syscall["expected_identity"], "ps:known-start");
	assert!(!after_syscall.to_string().contains("PRIVATE"));
	let refused = retain_signal_outcome(&p,15,Ok(signal_output(0,
		&json!({"pid":1234,"signal":15,"result":"signal_refused","signal_syscall_attempted":false,"termination_confirmed":false}).to_string(),"PRIVATE")))
		.unwrap_err().to_string();
	assert!(refused.contains("before the signal syscall"));
	assert!(refused.contains("no signal sent"));
	assert!(!refused.contains("PRIVATE"));
}

#[cfg(unix)]
#[test]
fn zero_signal_probe_remains_a_probe_and_never_confirms_termination() {
	let p: HostSignalParams =
		serde_json::from_value(json!({"host":"main","pid":1234,"signal":0})).unwrap();
	let ack = json!({"pid":1234,"signal":0,"identity":"linux:boot:42","result":"probe_succeeded","atomic_identity":true,"effective_uid":1000,"termination_confirmed":false});
	let result = retain_signal_outcome(&p, 0, Ok(signal_output(0, &ack.to_string(), ""))).unwrap();
	assert_eq!(result["result"], "probe_succeeded");
	assert_eq!(result["termination_confirmed"], false);
	let retained = retain_signal_after_audit(result, Ok(()));
	assert_eq!(retained["audit_recorded"], true);
}

#[cfg(unix)]
#[test]
fn trusted_kernel_permission_refusal_is_denied_but_mismatched_refusal_stays_unknown() {
	let p: HostSignalParams = serde_json::from_value(
		json!({"host":"main","pid":1234,"signal":0,"expected_identity":"linux:boot:42"}),
	)
	.unwrap();
	let ack = json!({"pid":1234,"signal":0,"identity":"linux:boot:42","result":"signal_refused","signal_syscall_attempted":true,"signal_delivery_confirmed":false,"refusal_reason":"kernel_permission_denied","termination_confirmed":false});
	let refused = retain_signal_outcome(&p, 0, Ok(signal_output(0, &ack.to_string(), "PRIVATE")))
		.unwrap_err()
		.to_string();
	assert!(refused.contains("kernel"));
	assert!(refused.contains("no signal delivered"));
	assert!(!refused.contains("PRIVATE"));
	let mut other = ack;
	other["pid"] = json!(1235);
	let result =
		retain_signal_outcome(&p, 0, Ok(signal_output(0, &other.to_string(), ""))).unwrap();
	assert_eq!(result["outcome"], "unknown");
	assert_eq!(result["pid"], 1234);
}
