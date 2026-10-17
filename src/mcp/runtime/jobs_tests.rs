// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Regression tests for jobs.
use super::*;

#[test]
fn macos_detached_resource_bounds_reject_before_new_job_identity() {
	let mut params = ProcessStartParams {
		host: "mac".into(),
		executable: "/usr/bin/python3".into(),
		args: vec!["-c".into(), "print(42)".into()],
		cwd: None,
		env: BTreeMap::new(),
		stdin: None,
		timeout_seconds: Some(30),
		idempotency_key: Some("keep-original-identity".into()),
		nice: Some(5),
		cpu_quota_percent: None,
		memory_max_bytes: None,
	};
	assert!(validate_new_host_resource_limits(Platform::Macos, &params).is_ok());
	params.cpu_quota_percent = Some(25);
	let error = validate_new_host_resource_limits(Platform::Macos, &params)
		.unwrap_err()
		.to_string();
	assert!(error.contains("no new job identity"));
	assert!(error.contains("remote launch submitted"));
	assert!(validate_new_host_resource_limits(Platform::Linux, &params).is_ok());
	params.cpu_quota_percent = None;
	params.memory_max_bytes = Some(32 * 1024 * 1024);
	assert!(validate_new_host_resource_limits(Platform::Macos, &params).is_err());
	assert!(validate_new_host_resource_limits(Platform::Linux, &params).is_ok());
	params.cpu_quota_percent = Some(100);
	assert!(validate_new_host_resource_limits(Platform::Macos, &params).is_err());
	params.cpu_quota_percent = None;
	params.memory_max_bytes = None;
	assert!(validate_new_host_resource_limits(Platform::Macos, &params).is_ok());
	// Other user-provided params, including timeout/nice and exact key, are untouched.
	assert_eq!(
		params.idempotency_key.as_deref(),
		Some("keep-original-identity")
	);
	assert_eq!(params.nice, Some(5));
}

#[test]
fn large_job_inventory_is_complete_redacted_and_wire_bounded() {
	let records: Vec<JobRecord> = (0..3431)
		.map(|index| {
			let mut record = outcome_fixture(ExecutionMode::Operator, false, "launched");
			record.id = format!("owned-job-{index:06}");
			record.host = format!("configured-host-{}", index % 6);
			record.args = vec!["PRIVATE_ARG".repeat(400)];
			record.cwd = Some("/PRIVATE_CWD".to_owned());
			record.ssh_target = "PRIVATE_SSH".to_owned();
			record.remote_job_dir = "/PRIVATE_REMOTE_STATE".to_owned();
			record.executable = "/PRIVATE_EXECUTABLE".to_owned();
			record.env_keys = vec!["PRIVATE_ENV".to_owned()];
			record
		})
		.collect();
	let legacy = serde_json::to_string_pretty(&json!({"jobs":records})).unwrap();
	let legacy_wire = serde_json::to_vec(&rmcp::model::CallToolResult::success(vec![
		rmcp::model::ContentBlock::text(legacy),
	]))
	.unwrap();
	assert!(legacy_wire.len() > 8 * 1024 * 1024);
	let text = job_inventory_response(&records).unwrap();
	let wire = serde_json::to_vec(&rmcp::model::CallToolResult::success(vec![
		rmcp::model::ContentBlock::text(text.clone()),
	]))
	.unwrap();
	assert!(wire.len() <= 1024 * 1024);
	assert!(!text.contains("PRIVATE_"));
	let value: Value = serde_json::from_str(&text).unwrap();
	assert_eq!(value["inventory_complete"], true);
	assert_eq!(value["total"], 3431);
	assert_eq!(value["status_authoritative"], false);
	for (record, summary) in records.iter().zip(value["jobs"].as_array().unwrap()) {
		assert_eq!(summary["id"], record.id);
		assert_eq!(summary["host"], record.host);
		assert_eq!(summary.as_object().unwrap().len(), 5);
	}
}

#[test]
fn compact_inventory_preserves_complete_five_field_inventory_at_real_registry_scale() {
	for count in [4220_usize, 6000] {
		let hosts = ["main", "pocket4", "rog", "mac", "x230", "ai395"];
		let records: Vec<JobRecord> = (0..count)
			.map(|index| {
				let mode = if index.is_multiple_of(2) {
					ExecutionMode::Operator
				} else {
					ExecutionMode::Isolated
				};
				let state = if index.is_multiple_of(3) {
					"launched"
				} else {
					"pending"
				};
				let mut record = outcome_fixture(mode, false, state);
				record.id = format!("1a137800000-b2f-{index:x}");
				record.host = hosts[index % hosts.len()].to_string();
				record.created_unix_ms = 1_791_932_000_000;
				record.args = vec!["PRIVATE_ARG_DO_NOT_PUBLISH".into()];
				record.env_keys = vec!["PRIVATE_ENV_DO_NOT_PUBLISH".into()];
				record
			})
			.collect();
		let text = job_inventory_response(&records).unwrap();
		let value: Value = serde_json::from_str(&text).unwrap();
		let jobs = value["jobs"].as_array().unwrap();
		assert_eq!(value["total"], count);
		assert_eq!(value["inventory_complete"], true);
		assert_eq!(value["status_authoritative"], false);
		assert_eq!(jobs.len(), count);
		assert_eq!(
			value
				.as_object()
				.unwrap()
				.keys()
				.cloned()
				.collect::<std::collections::BTreeSet<_>>(),
			[
				"inventory_complete",
				"jobs",
				"status_authoritative",
				"total"
			]
			.into_iter()
			.map(str::to_string)
			.collect()
		);
		let expected_ids: std::collections::BTreeSet<_> =
			records.iter().map(|record| record.id.as_str()).collect();
		let actual_ids: std::collections::BTreeSet<_> =
			jobs.iter().map(|row| row["id"].as_str().unwrap()).collect();
		assert_eq!(actual_ids, expected_ids);
		for (record, row) in records.iter().zip(jobs) {
			assert_eq!(
				row.as_object()
					.unwrap()
					.keys()
					.cloned()
					.collect::<std::collections::BTreeSet<_>>(),
				[
					"created_unix_ms",
					"execution_mode",
					"host",
					"id",
					"launch_state"
				]
				.into_iter()
				.map(str::to_string)
				.collect()
			);
			assert_eq!(row["id"], record.id);
			assert_eq!(row["host"], record.host);
			assert_eq!(
				row["created_unix_ms"],
				serde_json::to_value(record.created_unix_ms).unwrap()
			);
			assert_eq!(
				row["execution_mode"],
				serde_json::to_value(record.execution_mode).unwrap()
			);
			assert_eq!(row["launch_state"], record.launch_state);
		}
		assert!(!text.contains("PRIVATE_"));
		assert!(!text.contains("configured-private-target"));
		assert!(!text.contains("/private-job-root/"));
		let wire = serde_json::to_vec(&rmcp::model::CallToolResult::success(vec![
			rmcp::model::ContentBlock::text(text.clone()),
		]))
		.unwrap();
		assert!(wire.len() <= 1024 * 1024);
		let original_pretty = serde_json::to_string_pretty(&value).unwrap();
		let original_wire = serde_json::to_vec(&rmcp::model::CallToolResult::success(vec![
			rmcp::model::ContentBlock::text(original_pretty),
		]))
		.unwrap();
		assert!(wire.len() < original_wire.len());
		if count == 6000 {
			assert!(original_wire.len() > 1024 * 1024);
		} else {
			assert!(original_wire.len() <= 1024 * 1024);
		}
	}
}

#[test]
fn inventory_overflow_refuses_the_whole_result_instead_of_silent_partial() {
	let records: Vec<JobRecord> = (0..10000)
		.map(|index| {
			let mut record = outcome_fixture(ExecutionMode::Operator, false, "pending");
			record.id = format!("owned-job-{index}");
			record.host = "bounded-configured-host".repeat(10);
			record
		})
		.collect();
	let error = job_inventory_response(&records).unwrap_err().to_string();
	assert!(error.contains("No partial inventory returned"));
	assert!(error.contains("host filter"));
}

#[test]
fn legacy_audit_failure_cannot_hide_existing_job_status_wait_or_output_cursors() {
	for observation in [
		json!({"state":"succeeded","exit_code":0,"output_complete":true}),
		json!({"state":"running","pid":1234}),
		json!({"stdout":{"text":"retained-output","offset":5,"next_offset":20,"eof":true},"stderr":{"text":"","offset":0,"next_offset":0,"eof":true}}),
	] {
		let retained = retain_observation_after_audit(
			observation.clone(),
			Err(anyhow::anyhow!("PRIVATE_AUDIT_SECRET")),
			"local-host",
			"local-job",
		);
		for (key, value) in observation.as_object().unwrap() {
			assert_eq!(&retained[key], value);
		}
		assert_eq!(retained["audit_recorded"], false);
		assert!(retained["audit_warning"]
			.as_str()
			.unwrap()
			.contains("No new job"));
		assert!(!retained.to_string().contains("PRIVATE_AUDIT_SECRET"));
	}
	let observed = retain_observation_after_audit(
		json!({"state":"succeeded"}),
		Ok(()),
		"local-host",
		"local-job",
	);
	assert_eq!(observed["audit_recorded"], true);
	assert!(observed.get("audit_warning").is_none());
}

#[test]
fn nonobject_observations_are_controlled_unknown_without_panic() {
	for value in [Value::Null, json!("UNTRUSTED_SECRET"), json!([1, 2])] {
		let result = retain_observation_after_audit(value, Ok(()), "local-host", "local-job");
		assert_eq!(result["outcome"], "unknown");
		assert_eq!(result["automatic_retry"], false);
		assert_eq!(result["host"], "local-host");
		assert_eq!(result["job_id"], "local-job");
		assert!(!result.to_string().contains("UNTRUSTED_SECRET"));
	}
}

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
fn untrusted_launch_ack_cannot_promote_pending_to_launched() {
	for ack in [
		Value::Null,
		json!("ACK_SECRET"),
		json!([1]),
		json!({}),
		json!({"ok":false,"backend":"detached","launcher_pid":1234}),
		json!({"ok":true,"backend":"detached","launcher_pid":0}),
		json!({"ok":true,"backend":"systemd","unit":"other-unit"}),
	] {
		let mut record = outcome_fixture(ExecutionMode::Operator, false, "pending");
		let result = preserve_launch_outcome(&mut record, Ok(ack), |_| Ok(()));
		assert_eq!(record.launch_state, "launch_unknown");
		assert_eq!(result.value["job_id"], "same-job-id");
		assert_eq!(result.value["automatic_retry"], false);
		assert!(!result.value.to_string().contains("ACK_SECRET"));
	}
	let mut record = outcome_fixture(ExecutionMode::Operator, false, "pending");
	let result = preserve_launch_outcome(
		&mut record,
		Ok(json!({"ok":true,"reused_remote":true,"backend":"launch_failed"})),
		|_| Ok(()),
	);
	assert_eq!(record.launch_state, "launch_failed");
	assert_eq!(result.value["backend"], "launch_failed");
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
		Ok(
			json!({"job_id":"same-job-id","result":"stop_requested","untrusted_extra":"ACK_SECRET"}),
		),
	);
	let retained = retain_result_after_audit(
		result,
		Err(anyhow::anyhow!("audit /secret/path failed TOKEN")),
	);
	assert_eq!(retained["job_id"], "same-job-id");
	assert_eq!(retained["result"], "stop_requested");
	assert_eq!(retained["termination_confirmed"], false);
	assert_eq!(retained["automatic_retry"], false);
	assert!(!retained.to_string().contains("ACK_SECRET"));
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
fn malformed_or_mismatched_cancel_ack_cannot_claim_a_confirmed_request_or_panic() {
	for ack in [
		Value::Null,
		json!("ACK_SECRET"),
		json!([1]),
		json!({}),
		json!({"job_id":"wrong-helper-id","result":"stop_requested"}),
		json!({"job_id":"same-job-id","result":"terminated"}),
	] {
		let result = retain_cancel_outcome("same-job-id", Ok(ack));
		assert_eq!(result["job_id"], "same-job-id");
		assert_eq!(result["result"], "cancel_unknown");
		assert_eq!(result["status_authoritative"], false);
		assert_eq!(result["automatic_retry"], false);
		assert_eq!(result["termination_confirmed"], false);
		assert!(!result.to_string().contains("ACK_SECRET"));
	}
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

#[tokio::test]
async fn host_bound_start_lock_does_not_block_independent_hosts() {
	let rog = start_lock("hepta-fixture-rog").unwrap();
	let mac = start_lock("hepta-fixture-mac").unwrap();
	assert!(!Arc::ptr_eq(&rog, &mac));
	let guard = rog.lock().await;
	assert!(rog.try_lock().is_err());
	assert!(
		mac.try_lock().is_ok(),
		"another host must not queue behind ROG"
	);
	drop(guard);
}

#[tokio::test]
async fn host_bound_start_lock_preserves_same_host_idempotency_serialization() {
	let first = start_lock("hepta-fixture-pocket4").unwrap();
	let second = start_lock("hepta-fixture-pocket4").unwrap();
	assert!(Arc::ptr_eq(&first, &second));
	let guard = first.lock().await;
	assert!(
		second.try_lock().is_err(),
		"same host must serialize starts"
	);
	drop(guard);
	assert!(second.try_lock().is_ok());
}

fn fixture_write(dir: &Path, record: &JobRecord) {
	let bytes = serde_json::to_vec(record).unwrap();
	let file = dir.join(format!("{}.json", record.id));
	std::fs::write(&file, bytes).unwrap();
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
	}
}

#[cfg(unix)]
#[test]
fn positive_reuse_cache_never_negative_caches_or_allocates_new_identity() {
	let root = tempfile::tempdir().unwrap();
	let cache = Mutex::new(ReuseHitCache::default());
	let mut existing = outcome_fixture(ExecutionMode::Operator, false, "launched");
	existing.id = "same-job-id".to_owned();
	fixture_write(root.path(), &existing);
	let first = find_idempotent_in(root.path(), "main", "fixed-key", &cache)
		.unwrap()
		.unwrap();
	assert_eq!(first.id, existing.id);
	assert_eq!(cache.lock().unwrap().hits.len(), 1);
	let reused = find_idempotent_in(root.path(), "main", "fixed-key", &cache)
		.unwrap()
		.unwrap();
	assert_eq!(reused.id, existing.id);
	assert!(find_idempotent_in(root.path(), "main", "new-key", &cache)
		.unwrap()
		.is_none());
	assert_eq!(cache.lock().unwrap().hits.len(), 1);
}

#[cfg(unix)]
#[test]
fn positive_reuse_corrupted_or_rebound_identity_fails_closed() {
	let root = tempfile::tempdir().unwrap();

	let cache = Mutex::new(ReuseHitCache::default());
	let record = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(root.path(), &record);
	find_idempotent_in(root.path(), "main", "fixed-key", &cache).unwrap();
	let mut rebound = record.clone();
	rebound.idempotency_key = Some("other-key".to_owned());
	fixture_write(root.path(), &rebound);
	let error = find_idempotent_in(root.path(), "main", "fixed-key", &cache)
		.unwrap_err()
		.to_string();
	assert!(error.contains("binding changed"));
	std::fs::remove_file(root.path().join("same-job-id.json")).unwrap();
	assert!(find_idempotent_in(root.path(), "main", "fixed-key", &cache).is_err());
}

#[cfg(unix)]
#[test]
fn positive_reuse_directory_generation_change_renews_complete_scan() {
	let root = tempfile::tempdir().unwrap();
	let cache = Mutex::new(ReuseHitCache::default());
	let record = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(root.path(), &record);
	find_idempotent_in(root.path(), "main", "fixed-key", &cache).unwrap();
	let original = cache.lock().unwrap().epoch;
	let mut another = record.clone();
	another.id = "different-id".to_owned();
	another.idempotency_key = Some("different-key".to_owned());
	std::thread::sleep(Duration::from_millis(5));
	fixture_write(root.path(), &another);

	assert_ne!(original, Some(registry_epoch(root.path()).unwrap()));
	let found = find_idempotent_in(root.path(), "main", "fixed-key", &cache)
		.unwrap()
		.unwrap();
	assert_eq!(found.id, record.id);
	assert_eq!(
		cache.lock().unwrap().epoch,
		Some(registry_epoch(root.path()).unwrap())
	);
}

#[cfg(unix)]
#[test]
fn positive_reuse_duplicate_original_bindings_refuse_after_new_file() {
	let root = tempfile::tempdir().unwrap();
	let cache = Mutex::new(ReuseHitCache::default());
	let record = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(root.path(), &record);
	find_idempotent_in(root.path(), "main", "fixed-key", &cache).unwrap();
	let mut duplicate = record.clone();
	duplicate.id = "conflicting-id".to_owned();
	duplicate.created_unix_ms = 0;
	std::thread::sleep(Duration::from_millis(5));
	fixture_write(root.path(), &duplicate);
	assert!(find_idempotent_in(root.path(), "main", "fixed-key", &cache)
		.unwrap_err()
		.to_string()
		.contains("duplicate original"));
}

#[cfg(unix)]
#[test]
fn pending_or_uncertain_identity_does_not_enter_positive_cache() {
	for state in ["pending", "unknown", "failed"] {
		let root = tempfile::tempdir().unwrap();
		let cache = Mutex::new(ReuseHitCache::default());
		let record = outcome_fixture(ExecutionMode::Operator, false, state);
		fixture_write(root.path(), &record);
		assert_eq!(
			find_idempotent_in(root.path(), "main", "fixed-key", &cache)
				.unwrap()
				.unwrap()
				.id,
			record.id
		);
		assert!(cache.lock().unwrap().hits.is_empty());
	}
}

#[cfg(unix)]
#[test]
fn unknown_key_preserves_full_scan_corruption_refusal() {
	let root = tempfile::tempdir().unwrap();
	let cache = Mutex::new(ReuseHitCache::default());
	let record = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(root.path(), &record);
	find_idempotent_in(root.path(), "main", "fixed-key", &cache).unwrap();
	std::fs::write(root.path().join("damaged.json"), b"not-json").unwrap();
	assert!(find_idempotent_in(root.path(), "main", "not-registered", &cache).is_err());
}

#[cfg(unix)]
#[test]
fn cached_positive_cannot_escape_configured_state_root() {
	let one = tempfile::tempdir().unwrap();
	let two = tempfile::tempdir().unwrap();
	let cache = Mutex::new(ReuseHitCache::default());

	let record = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(one.path(), &record);
	assert!(find_idempotent_in(one.path(), "main", "fixed-key", &cache)
		.unwrap()
		.is_some());
	assert!(find_idempotent_in(two.path(), "main", "fixed-key", &cache)
		.unwrap_err()
		.to_string()
		.contains("registry root changed"));
	assert_eq!(cache.lock().unwrap().root.as_deref(), Some(one.path()));
}

#[cfg(unix)]
#[test]
fn previously_observed_other_keys_survive_unrelated_registry_churn() {
	let root = tempfile::tempdir().unwrap();
	let cache = Mutex::new(ReuseHitCache::default());
	let first = outcome_fixture(ExecutionMode::Operator, false, "launched");
	let mut second = first.clone();
	second.id = "other-record-id".to_owned();
	second.idempotency_key = Some("second-key".to_owned());
	fixture_write(root.path(), &first);
	fixture_write(root.path(), &second);
	find_idempotent_in(root.path(), "main", "fixed-key", &cache).unwrap();
	find_idempotent_in(root.path(), "main", "second-key", &cache).unwrap();
	assert_eq!(cache.lock().unwrap().known.len(), 2);
	// Change directory generation and query a different key first; old
	// identities must still be retained as refusal evidence.
	std::thread::sleep(Duration::from_millis(5));
	std::fs::write(root.path().join("non-record.txt"), b"fixture").unwrap();
	find_idempotent_in(root.path(), "main", "fixed-key", &cache).unwrap();
	assert_eq!(cache.lock().unwrap().known.len(), 2);
	std::fs::remove_file(root.path().join("other-record-id.json")).unwrap();
	assert!(
		find_idempotent_in(root.path(), "main", "second-key", &cache)
			.unwrap_err()
			.to_string()
			.contains("previous idempotency binding")
	);
}

#[cfg(unix)]
#[test]

fn previously_observed_old_key_cannot_be_rebound_to_new_job_id() {
	let root = tempfile::tempdir().unwrap();
	let cache = Mutex::new(ReuseHitCache::default());
	let original = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(root.path(), &original);
	find_idempotent_in(root.path(), "main", "fixed-key", &cache).unwrap();
	std::fs::remove_file(root.path().join("same-job-id.json")).unwrap();
	let mut replacement = original.clone();
	replacement.id = "replacement-job-id".to_owned();
	fixture_write(root.path(), &replacement);
	assert!(find_idempotent_in(root.path(), "main", "fixed-key", &cache)
		.unwrap_err()
		.to_string()
		.contains("previous idempotency binding"));
}

#[cfg(unix)]
#[test]
#[ignore = "manual isolated filesystem microbenchmark; not production TPS"]
fn positive_reuse_microbenchmark_6000_synthetic_records() {
	let root = tempfile::tempdir().unwrap();
	let cache = Mutex::new(ReuseHitCache::default());
	let template = outcome_fixture(ExecutionMode::Operator, false, "launched");
	for i in 0..6000u32 {
		let mut record = template.clone();
		record.id = format!("fixture-job-{i:05}");
		record.created_unix_ms = i as u128;
		record.idempotency_key = Some(format!("unique-key-{i:05}"));
		fixture_write(root.path(), &record);
	}
	let key = "unique-key-05999";
	let cold_start = std::time::Instant::now();
	let cold = find_idempotent_in(root.path(), "main", key, &cache)
		.unwrap()
		.unwrap();
	let cold_ms = cold_start.elapsed().as_secs_f64() * 1000.0;
	let hot_start = std::time::Instant::now();
	let hot = find_idempotent_in(root.path(), "main", key, &cache)
		.unwrap()
		.unwrap();
	let hot_ms = hot_start.elapsed().as_secs_f64() * 1000.0;
	assert_eq!(cold.id, hot.id);
	assert_eq!(hot.id, "fixture-job-05999");
	assert_eq!(cache.lock().unwrap().known.len(), 1);
	let legacy_scan = || {
		let start = std::time::Instant::now();
		let found = all_records_in(root.path())
			.unwrap()
			.into_iter()
			.find(|r| r.host == "main" && r.idempotency_key.as_deref() == Some(key))
			.unwrap();
		assert_eq!(found.id, hot.id);
		start.elapsed().as_secs_f64() * 1000.0
	};
	let streaming_scan = || {
		let start = std::time::Instant::now();
		let found = scan_idempotent_binding_in(root.path(), "main", key)
			.unwrap()
			.unwrap();
		assert_eq!(found.id, hot.id);
		start.elapsed().as_secs_f64() * 1000.0
	};
	let mut legacy_ms = Vec::new();
	let mut streamed_ms = Vec::new();
	for round in 0..6 {
		if round % 2 == 0 {
			legacy_ms.push(legacy_scan());
			streamed_ms.push(streaming_scan());
		} else {
			streamed_ms.push(streaming_scan());
			legacy_ms.push(legacy_scan());
		}
	}
	legacy_ms.sort_by(f64::total_cmp);
	streamed_ms.sort_by(f64::total_cmp);
	println!("isolated_fixture_records=6000 cold_lookup_ms={cold_ms:.3} hot_reuse_ms={hot_ms:.3} legacy_sorted_median_ms={:.3} streamed_median_ms={:.3}",
		(legacy_ms[2] + legacy_ms[3]) / 2.0,
		(streamed_ms[2] + streamed_ms[3]) / 2.0);
}

#[cfg(unix)]
#[test]
fn cached_hit_rejects_permissions_widened_without_directory_mutation() {
	use std::os::unix::fs::PermissionsExt;
	let root = tempfile::tempdir().unwrap();
	let cache = Mutex::new(ReuseHitCache::default());
	let job = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(root.path(), &job);
	find_idempotent_in(root.path(), "main", "fixed-key", &cache).unwrap();
	assert_eq!(cache.lock().unwrap().hits.len(), 1);
	let path = root.path().join("same-job-id.json");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
	let error = find_idempotent_in(root.path(), "main", "fixed-key", &cache)
		.unwrap_err()
		.to_string();
	assert!(error.contains("permissions unsafe"), "{error}");
}

#[cfg(unix)]
#[test]
fn cached_read_refuses_symlink_hardlink_and_oversize_record() {
	use std::os::unix::fs::symlink;
	let external = tempfile::tempdir().unwrap();
	let root = tempfile::tempdir().unwrap();
	let record = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(external.path(), &record);
	let link = root.path().join("same-job-id.json");

	symlink(external.path().join("same-job-id.json"), &link).unwrap();
	assert!(read_verified_cached_record(root.path(), "same-job-id")
		.unwrap_err()
		.to_string()
		.contains("unsafe"));
	std::fs::remove_file(&link).unwrap();
	fixture_write(root.path(), &record);
	assert_eq!(
		read_verified_cached_record(root.path(), "same-job-id")
			.unwrap()
			.id,
		record.id
	);
	std::fs::hard_link(&link, root.path().join("second-hardlink.bak")).unwrap();
	assert!(read_verified_cached_record(root.path(), "same-job-id")
		.unwrap_err()
		.to_string()
		.contains("unsafe"));
	std::fs::remove_file(root.path().join("second-hardlink.bak")).unwrap();
	std::fs::write(&link, vec![b'x'; (MAX_CACHED_RECORD_BYTES + 1) as usize]).unwrap();
	assert!(read_verified_cached_record(root.path(), "same-job-id")
		.unwrap_err()
		.to_string()
		.contains("unsafe"));
}

#[cfg(unix)]
#[test]
fn cached_read_rejects_invalid_record_name() {
	let root = tempfile::tempdir().unwrap();
	let record = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(root.path(), &record);
	assert!(read_verified_cached_record(root.path(), "bad/child").is_err());
	assert!(read_verified_cached_record(root.path(), "same-job-id").is_ok());
}

#[test]
fn streaming_lookup_matches_sorted_legacy_record_scan() {
	let root = tempfile::tempdir().unwrap();
	let template = outcome_fixture(ExecutionMode::Operator, false, "launched");
	for i in 0..128u32 {
		let mut record = template.clone();
		record.id = format!("fixture-stream-{i:04}");
		record.created_unix_ms = i as u128;
		record.idempotency_key = Some(format!("stream-key-{i:04}"));
		record.host = if i % 2 == 0 {
			"main".into()
		} else {
			"mac".into()
		};
		fixture_write(root.path(), &record);
	}
	for i in [0, 1, 16, 63, 126, 127] {
		let host = if i % 2 == 0 { "main" } else { "mac" };
		let key = format!("stream-key-{i:04}");
		let old = all_records_in(root.path())
			.unwrap()
			.into_iter()
			.find(|r| r.host == host && r.idempotency_key.as_deref() == Some(key.as_str()))
			.unwrap();
		let current = scan_idempotent_binding_in(root.path(), host, &key)
			.unwrap()
			.unwrap();
		assert_eq!(old.id, current.id);
	}
	assert!(
		scan_idempotent_binding_in(root.path(), "main", "never-created")
			.unwrap()
			.is_none()
	);
}

#[test]
fn streaming_scan_rejects_corruption_and_duplicate_bindings() {
	let root = tempfile::tempdir().unwrap();
	let mut record = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(root.path(), &record);
	record.id = "second-id".into();
	fixture_write(root.path(), &record);
	assert!(scan_idempotent_binding_in(root.path(), "main", "fixed-key")
		.unwrap_err()
		.to_string()
		.contains("duplicate original"));
	std::fs::remove_file(root.path().join("second-id.json")).unwrap();
	std::fs::write(root.path().join("corrupt.json"), b"{not-json").unwrap();
	assert!(scan_idempotent_binding_in(root.path(), "main", "other")
		.unwrap_err()
		.to_string()
		.contains("corrupt job record"));
}

#[cfg(unix)]
#[test]
fn streaming_scan_rejects_post_enumeration_directory_mutation() {
	let root = tempfile::tempdir().unwrap();
	let old = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(root.path(), &old);
	assert!(
		scan_idempotent_binding_in(root.path(), "main", "never-accepted")
			.unwrap()
			.is_none()
	);

	let mut inserted = old.clone();
	inserted.id = "newly-written-job".into();
	inserted.idempotency_key = Some("never-accepted".into());
	let rejected =
		scan_idempotent_binding_in_with_observer(root.path(), "main", "never-accepted", || {
			// This runs AFTER complete enumeration, BEFORE the authoritative
			// directory epoch comparison. It is not an unreliable race test.
			std::thread::sleep(Duration::from_millis(5));
			fixture_write(root.path(), &inserted);
		})
		.unwrap_err()
		.to_string();
	assert!(
		rejected.contains("registry changed during scan"),
		"{rejected}"
	);
	let accepted = scan_idempotent_binding_in(root.path(), "main", "never-accepted")
		.unwrap()
		.unwrap();
	assert_eq!(accepted.id, inserted.id);

	let mut duplicate = inserted.clone();
	duplicate.id = "second-conflicting-id".into();
	let rejected_existing =
		scan_idempotent_binding_in_with_observer(root.path(), "main", "never-accepted", || {
			std::thread::sleep(Duration::from_millis(5));
			fixture_write(root.path(), &duplicate);
		})
		.unwrap_err()
		.to_string();
	assert!(
		rejected_existing.contains("registry changed during scan"),
		"{rejected_existing}"
	);
	assert!(
		scan_idempotent_binding_in(root.path(), "main", "never-accepted")
			.unwrap_err()
			.to_string()
			.contains("duplicate original")
	);
}
