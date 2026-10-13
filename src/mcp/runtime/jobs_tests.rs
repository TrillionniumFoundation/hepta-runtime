// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Regression tests for jobs.
use super::*;

#[test]
fn ids_are_valid_and_unique() {
	let a = next_job_id();
	let b = next_job_id();
	assert_ne!(a, b);
	assert!(valid_name(&a));
}

#[test]
fn fingerprint_binds_stdin_and_resource_limits() {
	let mut base = ProcessStartParams {
		host: "rog".into(),
		executable: "/usr/bin/printf".into(),
		args: vec!["ok".into()],
		cwd: Some("/tmp".into()),
		env: BTreeMap::new(),
		stdin: None,
		timeout_seconds: Some(10),
		idempotency_key: Some("key".into()),
		nice: Some(1),
		cpu_quota_percent: Some(20),
		memory_max_bytes: Some(134217728),
	};
	let digest = request_digest(&base).unwrap();
	assert_eq!(digest.len(), 64);
	let original = fingerprint(&base);
	base.stdin = Some("different".into());
	assert_ne!(original, fingerprint(&base));
	base.stdin = None;
	base.cpu_quota_percent = Some(21);
	assert_ne!(original, fingerprint(&base));
}

#[test]
fn legacy_binding_does_not_silently_relaunch() {
	let params: ProcessStartParams =
		serde_json::from_value(json!({"host":"rog","executable":"/usr/bin/true"})).unwrap();
	let mut record:JobRecord=serde_json::from_value(json!({"id":"fixture","host":"rog","ssh_target":"hepta-rog","unit":"fixture","remote_job_dir":"/tmp/fixture","executable":"/usr/bin/true","args":[],"cwd":null,"env_keys":[],"created_unix_ms":1,"idempotency_key":"test","request_fingerprint":fingerprint(&params)})).unwrap();
	assert!(matches_request(&record, &params).is_err());
	record.request_digest = Some(request_digest(&params).unwrap());
	assert!(matches_request(&record, &params).unwrap());
	let mut changed = params;
	changed.env.insert("X".into(), "changed".into());
	assert!(!matches_request(&record, &changed).unwrap());
}

fn outcome_fixture(mode: ExecutionMode, system_jobctl: bool, state: &str) -> JobRecord {
	serde_json::from_value(json!({
		"id":"same-job-id","host":"main","ssh_target":"configured-private-target",
		"unit":"hepta-runtime-job-same-job-id","remote_job_dir":"/private-job-root/same-job-id",
		"executable":"/usr/bin/true","args":[],"cwd":null,"env_keys":[],
		"created_unix_ms":1,"idempotency_key":"fixed-key","request_fingerprint":1,
		"request_digest":"a".repeat(64),"launch_state":state,"execution_mode":mode,
		"system_jobctl":system_jobctl
	}))
	.unwrap()
}

#[test]
fn intent_failure_is_redacted_and_prevents_operation_submission() {
	let submitted = std::cell::Cell::new(false);
	let submit = || -> Result<()> {
		require_operation_intent(Err(anyhow::anyhow!("/secret/audit/path: CREDENTIAL")))?;
		submitted.set(true);
		Ok(())
	};
	let error = submit().unwrap_err();
	assert!(!submitted.get());
	let rendered = format!("{error:#}");
	assert!(rendered.contains("no remote operation submitted"));
	assert!(!rendered.contains("/secret"));
	assert!(!rendered.contains("CREDENTIAL"));
	assert!(error.source().is_none());
}

#[test]
fn post_operation_audit_failure_preserves_the_real_result_and_identity() {
	let original =
		json!({"job":{"id":"same-job-id"},"launch":{"ok":true,"pid":1234},"reused":false});
	let result = retain_result_after_audit(
		original.clone(),
		Err(anyhow::anyhow!(
			"permission denied /secret/audit/path TOKEN"
		)),
	);
	assert_eq!(result["job"], original["job"]);
	assert_eq!(result["launch"], original["launch"]);
	assert_eq!(result["reused"], false);
	assert_eq!(result["audit_recorded"], false);
	assert!(result["audit_warning"]
		.as_str()
		.unwrap()
		.contains("existing job_id"));
	let text = result.to_string();
	assert!(!text.contains("/secret"));
	assert!(!text.contains("TOKEN"));
	let ok = retain_result_after_audit(original.clone(), Ok(()));
	assert_eq!(ok["audit_recorded"], true);
	assert_eq!(ok["launch"], original["launch"]);
	assert!(ok.get("audit_warning").is_none());
}

#[test]
fn confirmed_remote_launch_survives_failed_local_completion_save() {
	let mut record = outcome_fixture(ExecutionMode::Operator, false, "pending");
	let original = json!({"ok":true,"backend":"systemd","unit":record.unit,"launcher_pid":5678});
	let saves = std::cell::Cell::new(0);
	let result = preserve_launch_outcome(&mut record, Ok(original.clone()), |r| {
		saves.set(saves.get() + 1);
		assert_eq!(r.launch_state, "launched");
		Err(anyhow::anyhow!("/private-record-path save failed SECRET"))
	});
	assert_eq!(saves.get(), 1);
	assert_eq!(result.value, original);
	assert!(result.local_record_pending);
	assert_eq!(record.launch_state, "launched");
	assert!(record.launch_error.is_none());
	let mut response = json!({"job":record,"launch":result.value});
	attach_launch_record_warning(&mut response, &result);
	assert_eq!(response["job"]["id"], "same-job-id");
	assert_eq!(response["local_record_pending"], true);
	assert_eq!(response["launch"]["launcher_pid"], 5678);
	assert!(!response.to_string().contains("SECRET"));
	assert!(!response.to_string().contains("/private-record-path"));
}

#[test]
fn unknown_remote_launch_retains_job_id_without_claiming_failure_or_success() {
	let mut record = outcome_fixture(ExecutionMode::Operator, false, "pending");
	let saves = std::cell::Cell::new(0);
	let result = preserve_launch_outcome(
		&mut record,
		Err(anyhow::anyhow!(
			"upstream stdout=PRIVATE_FRAGMENT stderr=SECRET /private-target"
		)),
		|r| {
			saves.set(saves.get() + 1);
			assert_eq!(r.launch_state, "launch_unknown");
			Ok(())
		},
	);
	assert_eq!(saves.get(), 1);
	assert_eq!(record.launch_state, "launch_unknown");
	assert_eq!(result.value["job_id"], "same-job-id");
	assert_eq!(result.value["state"], "launch_unknown");
	assert_eq!(result.value["outcome"], "unknown");
	assert_eq!(result.value["status_authoritative"], false);
	assert_eq!(result.value["automatic_retry"], false);
	assert!(result.value.get("ok").is_none());
	assert!(!result.local_record_pending);
	let text = json!({"job":record,"launch":result.value}).to_string();
	for private in ["PRIVATE_FRAGMENT", "SECRET", "/private-target"] {
		assert!(!text.contains(private));
	}
}

#[test]
fn unknown_launch_and_failed_local_save_preserve_reconciliation_identity() {
	let mut record = outcome_fixture(ExecutionMode::Isolated, true, "pending");
	let outcome = preserve_launch_outcome(
		&mut record,
		Err(anyhow::anyhow!("remote connection outcome uncertain")),
		|_| Err(anyhow::anyhow!("local disk unavailable")),
	);
	let mut result = json!({"job":record,"launch":outcome.value});
	attach_launch_record_warning(&mut result, &outcome);
	assert_eq!(result["job"]["id"], "same-job-id");
	assert_eq!(result["local_record_pending"], true);
	assert_eq!(result["launch"]["reconcile_via"], "process_status");
}

#[test]
fn reconcile_retries_are_only_fixed_id_isolated_jobctl_records() {
	for state in ["pending", "launch_failed", "launch_unknown", "launched"] {
		let ordinary = outcome_fixture(ExecutionMode::Operator, false, state);
		assert!(!reconcile_retry_allowed(&ordinary));
		// A corrupted operator-side flag must not open the isolated retry path.
		let operator = outcome_fixture(ExecutionMode::Operator, true, state);
		assert!(!reconcile_retry_allowed(&operator));
		let isolated = outcome_fixture(ExecutionMode::Isolated, true, state);
		assert_eq!(
			reconcile_retry_allowed(&isolated),
			matches!(state, "pending" | "launch_failed")
		);
		let fallback = outcome_fixture(ExecutionMode::Isolated, false, state);
		assert!(!reconcile_retry_allowed(&fallback));
	}
}

#[test]
fn cancel_success_and_unknown_completion_are_identity_bound_and_redacted() {
	let result = retain_cancel_outcome(
		"same-job-id",
		Ok(json!({"job_id":"wrong-helper-id","result":"stop_requested","signal_sent":true})),
	);
	let retained = retain_result_after_audit(
		result,
		Err(anyhow::anyhow!("audit /secret/path failed TOKEN")),
	);
	assert_eq!(retained["job_id"], "same-job-id");
	assert_eq!(retained["result"], "stop_requested");
	assert_eq!(retained["signal_sent"], true);
	assert_eq!(retained["audit_recorded"], false);
	let unknown = retain_cancel_outcome(
		"same-job-id",
		Err(anyhow::anyhow!("remote /private-target failed SECRET")),
	);
	assert_eq!(unknown["job_id"], "same-job-id");
	assert_eq!(unknown["result"], "cancel_unknown");
	assert_eq!(unknown["outcome"], "unknown");
	assert_eq!(unknown["automatic_retry"], false);
	assert!(unknown.get("signal_sent").is_none());
	assert!(!unknown.to_string().contains("/private-target"));
	assert!(!unknown.to_string().contains("SECRET"));
}

#[test]
fn unavailable_reuse_status_never_discloses_upstream_diagnostics() {
	let status = unavailable_status("same-job-id");
	assert_eq!(status["job_id"], "same-job-id");
	assert_eq!(status["state"], "status_unavailable");
	assert_eq!(status["status_authoritative"], false);
	assert_eq!(status["automatic_retry"], false);
	assert!(status.get("error").is_none());
}

#[test]
fn canonical_jobctl_reconciliation_preserves_authoritative_launch_state() {
	for remote_state in [
		"pending",
		"launch_failed",
		"launched",
		"cancelled",
		"unrecognized",
	] {
		let mut record = outcome_fixture(ExecutionMode::Isolated, true, "pending");
		let remote = json!({"ok":true,"reused_remote":true,"backend":"systemd_system",
            "status":{"launch_state":remote_state,"state":"unknown"}});
		let expected = if remote_state == "unrecognized" {
			"launch_unknown"
		} else {
			remote_state
		};
		let outcome = preserve_launch_outcome(&mut record, Ok(remote.clone()), |persisted| {
			assert_eq!(persisted.launch_state, expected);
			Ok(())
		});
		assert_eq!(record.launch_state, expected);
		assert_eq!(outcome.value, remote);
		assert!(!outcome.local_record_pending);
		assert_eq!(
			record.launch_error.is_some(),
			remote_state == "unrecognized"
		);
	}
}
