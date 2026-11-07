// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Request ownership, installation binding and hostile-report regressions.

use super::*;

fn config() -> RuntimeConfig {
	serde_json::from_value(json!({
		"state_dir":"/controller/state", "hosts":{"worker":{
			"ssh_target":"configured-worker", "remote_state_dir":"/srv/jobs", "platform":"linux",
			"allow_execute":true, "allow_write":true,
			"allowed_read_path_prefixes":["/srv", "/usr/bin"],
			"allowed_write_path_prefixes":["/srv/hia-state"],
			"allowed_cwd_prefixes":["/srv/hepta"]
		}},
		"hia_worker":{
			"host":"worker", "python_executable":"/usr/bin/python3", "working_directory":"/srv/hepta",
			"state_root":"/srv/hia-state", "artifact_roots":["/srv/inputs"],
			"worker_sha256":"a".repeat(64), "backend_sha256":"b".repeat(64),
			"catalog_sha256":hia_contract::catalog_sha256(), "timeout_seconds":120, "memory_max_bytes":1073741824_u64
		}
	})).unwrap()
}
fn artifact_request(text: &str) -> Value {
	json!({"catalog_sha256":hia_contract::catalog_sha256(), "request_key":"same-key",
		"artifact_profile":{"id":"artifacts", "sha256":"c".repeat(64)}, "source":{"kind":"utf8", "text":text}})
}
fn prepared() -> PreparedRequest {
	prepare_request(
		&config(),
		"hia_describe",
		json!({"section":"manifest"}),
		Path::new("/controller"),
	)
	.unwrap()
}
fn rejected_report(prepared: &PreparedRequest) -> Value {
	json!({"schema":"hia-agent-worker-report-v1", "tool":prepared.worker.tool,
		"request_sha256":prepared.worker.request_sha256, "profile_sha256":prepared.worker.profile_sha256,
		"catalog_sha256":prepared.worker.catalog_sha256, "worker_sha256":prepared.profile.worker_sha256,
		"backend_sha256":prepared.profile.backend_sha256, "complete":true,
		"response":{"contract_version":hia_contract::CONTRACT_VERSION, "request_id":"req-1", "status":"rejected",
			"error":{"code":"HIA_INPUT", "phase":"validation", "message":"Unsupported input", "retry_action":"correct_input", "details_artifact":null}}})
}

#[test]
fn exact_replay_retains_the_same_owner_but_changed_payload_collides() {
	let config = config();
	let first = prepare_request(
		&config,
		"hia_artifact",
		artifact_request("first"),
		Path::new("/controller"),
	)
	.unwrap();
	let repeat = prepare_request(
		&config,
		"hia_artifact",
		artifact_request("first"),
		Path::new("/controller"),
	)
	.unwrap();
	let changed = prepare_request(
		&config,
		"hia_artifact",
		artifact_request("different"),
		Path::new("/controller"),
	)
	.unwrap();
	assert_eq!(first.params.idempotency_key, repeat.params.idempotency_key);
	assert_eq!(
		super::super::runtime::jobs::request_digest(&first.params).unwrap(),
		super::super::runtime::jobs::request_digest(&repeat.params).unwrap()
	);
	assert_eq!(first.params.idempotency_key, changed.params.idempotency_key);
	assert_ne!(
		super::super::runtime::jobs::request_digest(&first.params).unwrap(),
		super::super::runtime::jobs::request_digest(&changed.params).unwrap()
	);
	assert_ne!(first.worker.request_sha256, changed.worker.request_sha256);
}

#[test]
fn code_and_profile_changes_do_not_allocate_a_fresh_mutation_key() {
	let mut config = config();
	let before = prepare_request(
		&config,
		"hia_artifact",
		artifact_request("input"),
		Path::new("/controller"),
	)
	.unwrap();
	config.hia_worker.as_mut().unwrap().worker_sha256 = "d".repeat(64);
	let after = prepare_request(
		&config,
		"hia_artifact",
		artifact_request("input"),
		Path::new("/controller"),
	)
	.unwrap();
	assert_eq!(before.params.idempotency_key, after.params.idempotency_key);
	assert_ne!(before.worker.profile_sha256, after.worker.profile_sha256);
	assert_ne!(before.params.stdin, after.params.stdin);
}

#[test]
fn only_the_installed_admin_command_and_pins_enter_the_process_owner() {
	let request = prepared();
	assert_eq!(request.params.executable, "/usr/bin/python3");
	assert!(request
		.params
		.args
		.contains(&"hepta.hia_agent_worker".into()));
	assert!(request
		.params
		.args
		.contains(&"--expected-worker-sha256".into()));
	assert!(request
		.params
		.args
		.contains(&"--expected-backend-sha256".into()));
	assert!(request
		.params
		.args
		.contains(&"--expected-catalog-sha256".into()));
	assert!(request.params.args.contains(&"--request-json-stdin".into()));
	assert!(!request.params.env.contains_key("PYTHONPATH"));
	assert_eq!(request.params.memory_max_bytes, Some(1073741824));
	assert_eq!(request.params.timeout_seconds, Some(120));
}

#[test]
fn capture_paths_use_the_profile_host_and_reject_foreign_roots_or_authority() {
	let mut arguments = artifact_request("");
	arguments["source"] = json!({"kind":"path", "path":"ssh://worker/srv/inputs/source.hia", "expected_sha256":null, "max_bytes":4096});
	let request = prepare_request(
		&config(),
		"hia_artifact",
		arguments.clone(),
		Path::new("/controller"),
	)
	.unwrap();
	assert_eq!(
		request.worker.arguments["source"]["path"],
		"/srv/inputs/source.hia"
	);
	for path in [
		"relative.hia",
		"/etc/passwd",
		"/srv/inputs/../escape",
		"ssh://other/srv/inputs/a",
		"ssh://root@worker/srv/inputs/a",
		"ssh://worker:2222/srv/inputs/a",
	] {
		arguments["source"]["path"] = json!(path);
		assert!(
			prepare_request(
				&config(),
				"hia_artifact",
				arguments.clone(),
				Path::new("/controller")
			)
			.is_err(),
			"{path}"
		);
	}
}

#[test]
fn profiles_fail_closed_on_missing_pins_root_overlap_and_disallowed_writes() {
	config().validate().unwrap();
	for mutation in ["pin", "catalog", "root", "write", "macos"] {
		let mut config = config();
		match mutation {
			"pin" => config.hia_worker.as_mut().unwrap().worker_sha256 = String::new(),
			"catalog" => config.hia_worker.as_mut().unwrap().catalog_sha256 = "d".repeat(64),
			"root" => config.hia_worker.as_mut().unwrap().state_root = "/srv/hepta/state".into(),
			"write" => config.hosts.get_mut("worker").unwrap().allow_write = false,
			"macos" => config.hosts.get_mut("worker").unwrap().platform = Platform::Macos,
			_ => unreachable!(),
		}
		assert!(config.validate().is_err(), "{mutation}");
	}
}

#[test]
fn zero_exit_is_not_a_domain_result_and_every_report_identity_is_checked() {
	let request = prepared();
	let report = rejected_report(&request);
	validate_report(&request, &serde_json::to_vec(&report).unwrap(), 0).unwrap();
	assert!(validate_report(&request, b"", 0).is_err());
	assert!(validate_report(&request, br#"{"complete":true}"#, 0).is_err());
	assert!(validate_report(&request, &serde_json::to_vec(&report).unwrap(), 1).is_err());
	for field in [
		"schema",
		"tool",
		"request_sha256",
		"profile_sha256",
		"catalog_sha256",
		"worker_sha256",
		"backend_sha256",
	] {
		let mut changed = report.clone();
		changed[field] = json!("wrong");
		assert!(
			validate_report(&request, &serde_json::to_vec(&changed).unwrap(), 0).is_err(),
			"{field}"
		);
	}
	let mut changed = report.clone();
	changed["complete"] = json!(false);
	assert!(validate_report(&request, &serde_json::to_vec(&changed).unwrap(), 0).is_err());
	let mut changed = report;
	changed["unreviewed"] = json!(true);
	assert!(validate_report(&request, &serde_json::to_vec(&changed).unwrap(), 0).is_err());
}

#[test]
fn runtime_operation_is_bound_to_the_complete_original_process() {
	let request = prepared();
	let raw = json!({"job":{"id":"job-1", "host":request.params.host,
		"idempotency_key":request.params.idempotency_key,
		"request_digest":super::super::runtime::jobs::request_digest(&request.params).unwrap()}});
	let handle = operation(&request, &raw).unwrap();
	assert_eq!(handle["request_sha256"], request.worker.request_sha256);
	let accepted = pending(&request, handle.clone(), None).unwrap();
	assert_eq!(accepted["status"], "accepted");
	assert!(accepted.get("result").is_none());
	let unknown = pending(&request, handle, Some(("HIA_UNKNOWN", "Outcome unknown"))).unwrap();
	assert_eq!(unknown["status"], "unknown");
	assert_eq!(unknown["error"]["retry_action"], "observe_original");
	let mut changed = raw;
	changed["job"]["request_digest"] = json!("e".repeat(64));
	assert!(operation(&request, &changed).is_err());
}

#[test]
fn valid_schema_cannot_rebind_a_read_result_to_another_artifact() {
	let artifact = json!({"id":"a", "sha256":"a".repeat(64), "uri":"hia://artifacts/a"});
	let request = prepare_request(
		&config(),
		"hia_read",
		json!({"catalog_sha256":hia_contract::catalog_sha256(), "artifact":artifact}),
		Path::new("/controller"),
	)
	.unwrap();
	let mut report = rejected_report(&request);
	report["response"] = json!({"contract_version":hia_contract::CONTRACT_VERSION, "request_id":"read-1", "status":"completed", "result":{
		"artifact":artifact, "encoding":"utf8", "content":"bytes", "next_cursor":null}});
	validate_report(&request, &serde_json::to_vec(&report).unwrap(), 0).unwrap();
	report["response"]["result"]["artifact"]["sha256"] = json!("e".repeat(64));
	assert!(validate_report(&request, &serde_json::to_vec(&report).unwrap(), 0).is_err());
}

#[test]
fn canonical_request_digest_matches_python_unicode_encoding() {
	let value = json!({"z":"智能\n\"\\", "a":[1,true,null,{"b":2,"a":3}]});
	assert_eq!(
		String::from_utf8(canonical(&value).unwrap()).unwrap(),
		"{\"a\":[1,true,null,{\"a\":3,\"b\":2}],\"z\":\"智能\\n\\\"\\\\\"}"
	);
}

#[test]
fn equivalent_capture_spelling_does_not_change_a_bound_original_request() {
	let config = config();
	let mut args = artifact_request("");
	args["source"] = json!({"kind":"path", "path":"ssh://worker/srv/inputs/a", "expected_sha256":null, "max_bytes":4096});
	let uri = prepare_request(
		&config,
		"hia_artifact",
		args.clone(),
		Path::new("/controller"),
	)
	.unwrap();
	args["source"]["path"] = json!("/srv/inputs/a");
	let absolute =
		prepare_request(&config, "hia_artifact", args, Path::new("/controller")).unwrap();
	assert_eq!(uri.worker.request_sha256, absolute.worker.request_sha256);
	assert_eq!(uri.params.idempotency_key, absolute.params.idempotency_key);
	assert_ne!(
		super::super::runtime::jobs::request_digest(&uri.params).unwrap(),
		super::super::runtime::jobs::request_digest(&absolute.params).unwrap()
	);
}

#[test]
fn pre_execution_admission_errors_offer_correction_without_an_operation_claim() {
	let config = config();
	let mut arguments = artifact_request("input");
	arguments["catalog_sha256"] = json!("f".repeat(64));
	let error = prepare_request(
		&config,
		"hia_artifact",
		arguments.clone(),
		Path::new("/controller"),
	)
	.err()
	.unwrap();
	let response =
		admission_failure("hia_artifact", &arguments, &config, &error.to_string()).unwrap();
	assert_eq!(response["status"], "rejected");
	assert_eq!(response["error"]["retry_action"], "refresh_context");
	assert!(response.get("operation").is_none());
	arguments["catalog_sha256"] = json!(hia_contract::catalog_sha256());
	let response =
		admission_failure("hia_artifact", &arguments, &config, "Capture root refused").unwrap();
	assert_eq!(response["error"]["retry_action"], "correct_input");
}

#[test]
fn maximum_utf8_capture_survives_json_escaping_within_the_full_worker_bound() {
	let config = config();
	for text in ["\0".repeat(65536), "\"".repeat(65536), "智".repeat(65536)] {
		let arguments = artifact_request(&text);
		hia_contract::validate_input("hia_artifact", &arguments).unwrap();
		let request = prepare_request(
			&config,
			"hia_artifact",
			arguments.clone(),
			Path::new("/controller"),
		)
		.unwrap();
		let input = request.params.stdin.as_deref().unwrap();
		assert!(input.len() <= MAX_WORKER_BYTES);
		let decoded: WorkerRequest = serde_json::from_str(input).unwrap();
		assert_eq!(decoded.arguments, arguments);
		assert_eq!(decoded.arguments["source"]["text"], text);
	}
	let too_long = artifact_request(&"\0".repeat(65537));
	assert!(prepare_request(&config, "hia_artifact", too_long, Path::new("/controller")).is_err());
}
