// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Policy, identity and durable-index regressions for weight experiment sessions.

use super::*;

fn config() -> RuntimeConfig {
	serde_json::from_value(json!({
		"state_dir":"/tmp/weight-controller",
		"controller_workspace_roots":["/tmp/weight-workspace"],
		"hosts":{"fixture":{"ssh_target":"fixture","remote_state_dir":"/tmp/weight-jobs","allow_execute":true,"allow_write":true,"allowed_cwd_prefixes":["/tmp/weight"],"allowed_read_path_prefixes":["/tmp/weight"],"allowed_write_path_prefixes":["/tmp/weight"]}},
		"weight_workers":{"cpu":{"host":"fixture","python_executable":"/usr/bin/python3","worker_path":"/tmp/weight/worker.py","worker_sha256":"a".repeat(64),"session_root":"/tmp/weight/sessions","input_roots":["/tmp/weight/models"],"allowed_providers":["fixture"]}}
	})).expect("valid synthetic profile")
}

fn open_params() -> WeightOpenParams {
	WeightOpenParams {
		profile: "cpu".into(),
		idempotency_key: "experiment-001".into(),
		params: json!({"provider":"fixture","model":"test"}),
	}
}

#[test]
fn policy_preserves_old_configs_and_refuses_authority_escape() {
	let mut policy = config();
	policy.validate().expect("qualified paths and budgets");
	policy.weight_workers.get_mut("cpu").unwrap().session_root = "/etc/outside".into();
	assert!(policy.validate().is_err());
	let mut config = config();
	config.hosts.get_mut("fixture").unwrap().allow_write = false;
	assert!(config.validate().is_err());
	config.weight_workers.clear();
	config
		.validate()
		.expect("existing runtime config remains valid");
}

#[test]
fn worker_pin_and_resource_ceilings_are_required() {
	for field in [
		"worker_sha256",
		"max_cpu_threads",
		"max_memory_bytes",
		"max_request_ms",
	] {
		let mut value = serde_json::to_value(config()).unwrap();
		value["weight_workers"]["cpu"][field] = match field {
			"worker_sha256" => json!("unpinned"),
			"max_cpu_threads" => json!(64),
			"max_memory_bytes" => json!(1),
			_ => json!(600_001),
		};
		let config: RuntimeConfig = serde_json::from_value(value).unwrap();
		assert!(config.validate().is_err(), "{field}");
	}
}

#[test]
fn caller_cannot_replace_owner_paths_or_expand_budget() {
	for field in [
		"output_root",
		"input_roots",
		"run_dir",
		"artifact_root",
		"socket",
		"session_id",
	] {
		let mut input = open_params();
		input.params[field] = json!("/outside");
		assert!(prepare_intent(&config(), input).is_err(), "{field}");
	}
	for (field, value) in [
		("cpu_threads", json!(9)),
		("timeout_ms", json!(600_001)),
		("max_memory_bytes", json!(u64::MAX)),
		("idle_timeout_s", json!(0)),
	] {
		let mut input = open_params();
		input.params[field] = value;
		assert!(prepare_intent(&config(), input).is_err(), "{field}");
	}
	let mut input = open_params();
	input.params["provider"] = json!("arbitrary-python");
	assert!(prepare_intent(&config(), input).is_err());
}

#[test]
fn request_identity_is_stable_but_not_permission_to_change_content() {
	let one = prepare_intent(&config(), open_params()).unwrap();
	let two = prepare_intent(&config(), open_params()).unwrap();
	assert_eq!(one, two);
	let mut changed = open_params();
	changed.params["model"] = json!("different-model");
	let changed = prepare_intent(&config(), changed).unwrap();
	assert_eq!(one.session_id, changed.session_id);
	assert_ne!(one.request_digest, changed.request_digest);
	assert_ne!(one, changed);
	assert!(one.worker_request["params"]["output_root"]
		.as_str()
		.unwrap()
		.starts_with("/tmp/weight/sessions/ws_"));
	assert_eq!(one.worker_request["params"]["cpu_threads"], 2);
}

#[test]
fn both_worker_and_client_use_the_original_process_contract() {
	let intent = prepare_intent(&config(), open_params()).unwrap();
	let worker = worker_start(&intent).unwrap();
	assert_eq!(worker.host, "fixture");
	assert_eq!(worker.executable, "/usr/bin/python3");
	assert!(worker.args.contains(&"--serve".into()));
	assert_eq!(worker.env["OPENBLAS_NUM_THREADS"], "2");
	assert_eq!(worker.cpu_quota_percent, Some(200));
	let request = json!({"id":"probe-1","op":"probe","session_id":intent.session_id,"params":{}});
	let client = client_start(&intent, &request, "probe-1", 5000).unwrap();
	assert_eq!(client.host, worker.host);
	assert!(client.args.contains(&"--client".into()));
	assert_eq!(client.timeout_seconds, Some(45));
	assert!(client
		.idempotency_key
		.unwrap()
		.starts_with("weight-call-ws_"));
	assert_eq!(
		serde_json::from_str::<Value>(&client.stdin.unwrap()).unwrap(),
		request
	);
}

#[test]
fn omitted_native_client_keeps_old_profile_bytes_and_process_spec() {
	let original = config();
	let profile = &original.weight_workers["cpu"];
	let encoded = serde_json::to_value(profile).unwrap();
	assert!(encoded.get("native_client").is_none());
	let mut historic = encoded.clone();
	historic.as_object_mut().unwrap().remove("native_client");
	let decoded: WeightWorkerProfile = serde_json::from_value(historic.clone()).unwrap();
	assert_eq!(serde_json::to_value(&decoded).unwrap(), historic);
	assert_eq!(digest(&decoded).unwrap(), digest(profile).unwrap());
	let intent = prepare_intent(&original, open_params()).unwrap();
	let client = client_start(&intent, &json!({"id":"inspect-1"}), "inspect-1", 5000).unwrap();
	assert_eq!(client.executable, "/usr/bin/python3");
	assert_eq!(client.timeout_seconds, Some(45));
	assert!(!client.env.contains_key("TOKIO_WORKER_THREADS"));
}

#[test]
fn native_client_requires_an_explicit_remote_installation_and_keeps_job_identity() {
	let mut policy = config();
	policy.weight_workers.get_mut("cpu").unwrap().native_client =
		Some(super::super::weight_config::WeightNativeClientProfile {
			executable: "/tmp/weight/bin/hepta-runtime".into(),
			sha256: "f".repeat(64),
		});
	policy.validate().unwrap();
	let native = prepare_intent(&policy, open_params()).unwrap();
	let legacy = prepare_intent(&config(), open_params()).unwrap();
	assert_eq!(native.session_id, legacy.session_id);
	assert_ne!(
		native.profile_digest, legacy.profile_digest,
		"new effects require a new admitted profile"
	);
	let request = json!({"id":"probe-1","op":"probe","session_id":native.session_id,"params":{}});
	let client = client_start(&native, &request, "probe-1", 5000).unwrap();
	let old_client = client_start(&legacy, &request, "probe-1", 5000).unwrap();
	assert_eq!(client.executable, "/tmp/weight/bin/hepta-runtime");
	assert_eq!(client.args[0], "weight-client");
	assert_eq!(client.idempotency_key, old_client.idempotency_key);
	assert_eq!(client.stdin, old_client.stdin);
	assert_eq!(client.host, old_client.host);
	assert_eq!(client.env["TOKIO_WORKER_THREADS"], "1");
	assert_eq!(client.timeout_seconds, Some(80));
	assert!(client.args.contains(&"--expected-client-sha256".into()));
	assert!(!client.args.contains(&"--client".into()));
	assert_eq!(
		worker_start(&native).unwrap().executable,
		"/usr/bin/python3",
		"the resident compute backend is unchanged"
	);
	for path in ["relative/bin", "/etc/outside", "/tmp/weight/../escape"] {
		policy
			.weight_workers
			.get_mut("cpu")
			.unwrap()
			.native_client
			.as_mut()
			.unwrap()
			.executable = path.into();
		assert!(policy.validate().is_err(), "{path}");
	}
}

#[test]
fn bounded_requests_and_closed_operation_schema_reject_arbitrary_code() {
	assert!(bounded_request(&json!({"blob":"x".repeat(MAX_REQUEST_BYTES)})).is_err());
	assert!(serde_json::from_value::<WeightCallParams>(
		json!({"session_id":"ws_x","request_id":"call","op":"exec","params":{}})
	)
	.is_err());
	assert!(serde_json::from_value::<WeightOpenParams>(
		json!({"profile":"cpu","idempotency_key":"a","params":{},"executable":"/bin/sh"})
	)
	.is_err());
	for id in ["../escape", "", "a/b", "x\n"] {
		assert!(check_request_id(id).is_err());
	}
	assert!(check_session_id("ws_012345678901234567890123").is_ok());
	assert!(check_session_id("ws_../../outside").is_err());
}

#[tokio::test]
async fn immutable_index_reopens_and_rejects_changed_semantics_or_tampering() {
	let temp = tempfile::tempdir().unwrap();
	let root = temp.path().join("state");
	private_directory(&root).await.unwrap();
	let intent = prepare_intent(&config(), open_params()).unwrap();
	let name = intent_name(&intent.session_id);
	publish_record(&root, &name, &intent).await.unwrap();
	publish_record(&root, &name, &intent)
		.await
		.expect("identical replay");
	let recovered: SessionIntent = read_record(&root.join(&name)).await.unwrap();
	assert_eq!(recovered, intent);
	let mut changed = intent.clone();
	changed.request_digest = "b".repeat(64);
	assert!(publish_record(&root, &name, &changed).await.is_err());
	let mut wrapper: Value =
		serde_json::from_slice(&tokio::fs::read(root.join(&name)).await.unwrap()).unwrap();
	wrapper["payload"]["request_digest"] = json!("c".repeat(64));
	tokio::fs::write(root.join(&name), serde_json::to_vec(&wrapper).unwrap())
		.await
		.unwrap();
	assert!(read_record::<SessionIntent>(&root.join(&name))
		.await
		.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn state_reads_refuse_symlink_substitution() {
	let temp = tempfile::tempdir().unwrap();
	let file = temp.path().join("outside");
	tokio::fs::write(&file, b"{}").await.unwrap();
	tokio::fs::symlink(&file, temp.path().join("record"))
		.await
		.unwrap();
	assert!(read_record::<Value>(&temp.path().join("record"))
		.await
		.is_err());
}

#[tokio::test]
async fn coordinator_lock_serializes_cooperating_instances() {
	let temp = tempfile::tempdir().unwrap();
	let root = temp.path().join("state");
	private_directory(&root).await.unwrap();
	let one = lock_state(&root).await.unwrap();
	let timeout =
		tokio::time::timeout(std::time::Duration::from_millis(40), lock_state(&root)).await;
	assert!(timeout.is_err());
	drop(one);
	lock_state(&root)
		.await
		.expect("lock available after original owner releases");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn atomic_publication_recovers_after_rename_before_directory_sync_or_ack() {
	use std::os::unix::fs::MetadataExt;
	let temp = tempfile::tempdir().unwrap();
	let root = temp.path().join("state");
	private_directory(&root).await.unwrap();
	let value = json!({"session":"fixture","original_job":"job-001"});
	let bytes =
		serde_json::to_vec(&json!({"sha256":digest(&value).unwrap(),"payload":value})).unwrap();
	let staging = root.join(".pending-crash-window");
	let destination = root.join("receipt.json");
	let mut options = tokio::fs::OpenOptions::new();
	options.write(true).create_new(true).mode(0o600);
	let mut file = options.open(&staging).await.unwrap();
	file.write_all(&bytes).await.unwrap();
	file.sync_all().await.unwrap();
	drop(file);
	// Publication happened, but the interrupted caller has neither synchronized
	// the directory nor received an acknowledgement: the old two-link crash window.
	publish_no_replace(&staging, &destination).await.unwrap();
	assert!(!tokio::fs::try_exists(&staging).await.unwrap());
	assert_eq!(tokio::fs::metadata(&destination).await.unwrap().nlink(), 1);
	assert_eq!(read_record::<Value>(&destination).await.unwrap(), value);
	publish_record(&root, "receipt.json", &value)
		.await
		.expect("retry reconciles and syncs the published original record");
	let other = json!({"session":"fixture","original_job":"different-job"});
	assert!(publish_record(&root, "receipt.json", &other).await.is_err());
	let mut file = options.open(&staging).await.unwrap();
	file.write_all(b"different request").await.unwrap();
	file.sync_all().await.unwrap();
	drop(file);
	assert_eq!(
		publish_no_replace(&staging, &destination)
			.await
			.unwrap_err()
			.kind(),
		std::io::ErrorKind::AlreadyExists
	);
	assert_eq!(read_record::<Value>(&destination).await.unwrap(), value);
	// This is not a relaxation of the original single-link record contract.
	tokio::fs::hard_link(&destination, root.join("untrusted-alias"))
		.await
		.unwrap();
	assert!(read_record::<Value>(&destination).await.is_err());
}

#[tokio::test]
async fn distinct_session_locks_do_not_wait_on_each_other_or_the_index() {
	let temp = tempfile::tempdir().unwrap();
	let root = temp.path().join("state");
	private_directory(&root).await.unwrap();
	let index = lock_state(&root).await.unwrap();
	let one_id = "ws_000000000000000000000001";
	let other_id = "ws_000000000000000000000002";
	let one = lock_session(&root, one_id).await.unwrap();
	let other = tokio::time::timeout(
		std::time::Duration::from_secs(1),
		lock_session(&root, other_id),
	)
	.await
	.unwrap()
	.unwrap();
	assert!(tokio::time::timeout(
		std::time::Duration::from_millis(40),
		lock_session(&root, one_id)
	)
	.await
	.is_err());
	drop(one);
	drop(lock_session(&root, one_id).await.unwrap());
	drop((index, other));
	assert!(lock_session(&root, "../outside").await.is_err());
}

#[test]
fn legacy_session_limit_is_identity_only_and_no_longer_restricts_configuration() {
	for legacy in [0, 1, 8, 9, 1024] {
		let mut policy = config();
		policy
			.weight_workers
			.get_mut("cpu")
			.unwrap()
			.max_active_sessions = legacy;
		policy.validate().unwrap();
	}
}

#[tokio::test]
async fn session_intent_admission_crosses_old_record_ceiling_without_archival() {
	let temp = tempfile::tempdir().unwrap();
	let policy = config();
	let mut original = Vec::new();
	for index in 0..1024 {
		// Absence of a remote binding used to be counted as an active session.
		let mut input = open_params();
		input.idempotency_key = format!("concurrent-{index}");
		let intent = prepare_intent(&policy, input).unwrap();
		let payload = serde_json::to_value(&intent).unwrap();
		let bytes =
			serde_json::to_vec(&json!({"sha256":digest(&payload).unwrap(),"payload":payload}))
				.unwrap();
		let path = temp.path().join(intent_name(&intent.session_id));
		let mut options = tokio::fs::OpenOptions::new();
		options.write(true).create_new(true);
		#[cfg(unix)]
		options.mode(0o600);
		let mut file = options.open(&path).await.unwrap();
		file.write_all(&bytes).await.unwrap();
		file.flush().await.unwrap();
		drop(file);
		original.push((path, bytes));
	}
	let mut input = open_params();
	input.idempotency_key = "concurrent-1024".into();
	let intent = prepare_intent(&policy, input).unwrap();
	publish_session_intent(temp.path(), &intent).await.unwrap();
	publish_session_intent(temp.path(), &intent).await.unwrap();
	assert_eq!(
		read_record::<SessionIntent>(&temp.path().join(intent_name(&intent.session_id)))
			.await
			.unwrap(),
		intent
	);
	let mut conflicting = intent.clone();
	conflicting.request_digest = "changed-original-request".into();
	assert!(publish_session_intent(temp.path(), &conflicting)
		.await
		.is_err());
	for (path, bytes) in original {
		assert_eq!(tokio::fs::read(path).await.unwrap(), bytes);
	}
	// The byte contract remains distinct from the removed session count.
	let filler = tokio::fs::File::create(temp.path().join("stored-bytes.fixture"))
		.await
		.unwrap();
	filler.set_len(MAX_STATE_BYTES).await.unwrap();
	publish_session_intent(temp.path(), &intent).await.unwrap();
	let input = open_params();
	let another = prepare_intent(&policy, input).unwrap();
	let error = publish_session_intent(temp.path(), &another)
		.await
		.unwrap_err();
	assert!(error.to_string().contains("64 MiB quota"));
	assert!(
		!tokio::fs::try_exists(temp.path().join(intent_name(&another.session_id)))
			.await
			.unwrap()
	);
}
