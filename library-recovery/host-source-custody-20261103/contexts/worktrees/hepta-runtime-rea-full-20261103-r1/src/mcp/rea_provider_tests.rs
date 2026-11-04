// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Static profile policy, exact-request recovery and report-binding regressions.

use super::*;

fn profile() -> ReaStaticProfile {
	ReaStaticProfile {
		host: "owned".into(),
		runtime_executable: "/opt/hepta/hepta-runtime".into(),
		runtime_sha256: "1".repeat(64),
		provider: StaticProvider::GnuReadelf,
		backend_executable: "/usr/bin/readelf".into(),
		backend_sha256: "2".repeat(64),
		backend_version: "GNU readelf (GNU Binutils) 2.42".into(),
		working_directory: "/work".into(),
		input_roots: vec!["/work/build".into()],
		allowed_operations: vec![StaticOperation::Headers, StaticOperation::Sections],
		max_artifact_bytes: default_artifact_bytes(),
		max_output_bytes: default_output_bytes(),
		timeout_seconds: default_timeout(),
		memory_max_bytes: default_memory(),
		java_engine: None,
	}
}

fn request() -> ReaStaticRequest {
	ReaStaticRequest {
		profile: "owned_readelf".into(),
		profile_sha256: sha256(&serde_json::to_vec(&profile()).unwrap()),
		idempotency_key: "build-17".into(),
		operation: StaticOperation::Headers,
		artifact_path: "/work/build/object.o".into(),
		artifact_sha256: "3".repeat(64),
	}
}

fn worker() -> WorkerRequest {
	WorkerRequest {
		schema: "hepta.rea.static-request.v1".into(),
		profile: profile(),
		request: request(),
		protected_roots: vec!["/work/build/private".into()],
	}
}

fn config() -> RuntimeConfig {
	serde_json::from_value(json!({"state_dir":"/tmp/hepta-static-tests","controller_workspace_roots":[],
		"hosts":{"owned":{"ssh_target":"owned-target","remote_state_dir":"/work/state","allow_execute":true,
		"allowed_cwd_prefixes":["/work"],"allowed_read_path_prefixes":["/work/build","/opt/hepta","/usr/bin"],
		"protected_path_prefixes":["/work/build/private"]}},
		"rea_static_profiles":{"owned_readelf":profile()}})).unwrap()
}

#[test]
fn static_profiles_are_explicit_and_default_empty() {
	let mut cfg = config();
	validate_profiles(&cfg).unwrap();
	cfg.rea_static_profiles.clear();
	assert!(prepare_request(&cfg, request()).is_err());
	validate_profiles(&cfg).unwrap();
	let empty: RuntimeConfig =
		serde_json::from_value(json!({"state_dir":"/tmp/static","hosts":{}})).unwrap();
	assert!(empty.rea_static_profiles.is_empty());
}

#[test]
fn static_profiles_reject_foreign_hosts_paths_versions_and_budgets() {
	for mutation in 0..8 {
		let mut p = profile();
		match mutation {
			0 => p.runtime_sha256 = "bad".into(),
			1 => p.backend_version = "not a GNU readelf".into(),
			2 => p.backend_version.push('\n'),
			3 => p.input_roots = vec!["relative".into()],
			4 => p.max_output_bytes = 65 * 1024,
			5 => p.timeout_seconds = 121,
			6 => p.memory_max_bytes = p.max_artifact_bytes,
			7 => p.allowed_operations.push(StaticOperation::Headers),
			_ => unreachable!(),
		}
		assert!(validate_profile(&p).is_err(), "mutation {mutation}");
	}
	let mut cfg = config();
	cfg.rea_static_profiles
		.get_mut("owned_readelf")
		.unwrap()
		.input_roots = vec!["/etc".into()];
	assert!(validate_profiles(&cfg).is_err());
	cfg = config();
	cfg.hosts.get_mut("owned").unwrap().allow_execute = false;
	assert!(validate_profiles(&cfg).is_err());
}

#[test]
fn fixed_argv_has_no_caller_options_and_rejects_unsupported_operations() {
	assert_eq!(
		StaticProvider::GnuReadelf
			.arguments(StaticOperation::Headers, "/proc/self/fd/12")
			.unwrap(),
		["--file-header", "--wide", "--", "/proc/self/fd/12"]
	);
	assert_eq!(
		StaticProvider::GnuObjdump
			.arguments(StaticOperation::Relocations, "/proc/self/fd/13")
			.unwrap(),
		["--reloc", "--", "/proc/self/fd/13"]
	);
	assert!(StaticProvider::GnuObjdump
		.arguments(StaticOperation::Notes, "/tmp/a")
		.is_err());
	let mut injected = serde_json::to_value(request()).unwrap();
	injected["executable"] = json!("/bin/sh");
	assert!(serde_json::from_value::<ReaStaticRequest>(injected).is_err());
}

#[test]
fn artifact_admission_refuses_escape_protected_roots_and_unlisted_operation() {
	for path in [
		"/etc/passwd",
		"/work/build/../secret",
		"/work/build/./a",
		"/work/build/private/key",
		"/work/build\n/a",
	] {
		let mut w = worker();
		w.request.artifact_path = path.into();
		assert!(validate_worker_request(&w).is_err(), "{path}");
	}
	let mut w = worker();
	w.request.operation = StaticOperation::Symbols;
	assert!(validate_worker_request(&w).is_err());
	w = worker();
	w.request.artifact_sha256 = "A".repeat(64);
	assert!(validate_worker_request(&w).is_err());
	validate_worker_request(&worker()).unwrap();
}

#[test]
fn same_key_keeps_original_owner_identity_when_payload_changes() {
	let cfg = config();
	let first = prepare_request(&cfg, request()).unwrap();
	let again = prepare_request(&cfg, request()).unwrap();
	assert_eq!(
		serde_json::to_value(&first).unwrap(),
		serde_json::to_value(&again).unwrap()
	);
	let mut changed = request();
	changed.artifact_sha256 = "4".repeat(64);
	let changed = prepare_request(&cfg, changed).unwrap();
	assert_eq!(first.idempotency_key, changed.idempotency_key);
	assert_ne!(first.stdin, changed.stdin);
	assert_eq!(first.args, ["rea-static-worker"]);
	assert_eq!(
		first.executable,
		cfg.rea_static_profiles["owned_readelf"].runtime_executable
	);
	assert!(first.stdin.unwrap().contains("/work/build/private"));
	let mut moved = config();
	moved
		.rea_static_profiles
		.get_mut("owned_readelf")
		.unwrap()
		.backend_version
		.push_str(" new");
	assert!(prepare_request(&moved, request()).is_err());
}

fn report(input: &WorkerRequest) -> Value {
	let mut v = json!({"schema":"hepta.rea.static-report.v1","request_sha256":sha256(&serde_json::to_vec(input).unwrap()),
		"runtime_sha256":input.profile.runtime_sha256,"provider":input.profile.provider,"operation":input.request.operation,
		"backend":{"sha256":input.profile.backend_sha256,"version":input.profile.backend_version},
		"subject":{"selected_path":input.request.artifact_path,"sha256":input.request.artifact_sha256,"size_bytes":4,"snapshot":"sealed_linux_memfd"},
		"backend_success":true,"backend_exit_code":0,"output_complete":true,"rea_evidence_compatible":false,
		"coverage":{"scope":"selected_static_backend_operation","status":"partial"},
		"summary":summary::selected_fields(input.profile.provider,input.request.operation,"ELF\n",true),
		"stdout":"ELF\n","stderr":"","stdout_sha256":sha256(b"ELF\n"),"stderr_sha256":sha256(b""),"stdout_bytes":4,"stderr_bytes":0});
	seal_report(&mut v);
	v
}

fn seal_report(v: &mut Value) {
	v.as_object_mut().unwrap().remove("native_report_id");
	let id = sha256(&serde_json::to_vec(v).unwrap());
	v["native_report_id"] = json!(format!("hepta_rea_static_v1_{id}"));
}

#[test]
fn rehashed_reports_cannot_substitute_source_provider_or_incomplete_output() {
	let w = worker();
	let good = report(&w);
	validate_report(&good, &w, 0).unwrap();
	for case in 0..8 {
		let mut bad = good.clone();
		match case {
			0 => bad["subject"]["sha256"] = json!("5".repeat(64)),
			1 => bad["backend"]["version"] = json!("GNU readelf (GNU Binutils) 9.99"),
			2 => bad["stdout"] = json!("changed"),
			3 => bad["output_complete"] = json!(false),
			4 => bad["rea_evidence_compatible"] = json!(true),
			5 => bad["request_sha256"] = json!("6".repeat(64)),
			6 => {
				bad["summary"]["observations"] =
					json!([{"field":"elf_machine_label","value":"invented","stdout_line":1}])
			}
			7 => bad["coverage"]["status"] = json!("complete"),
			_ => unreachable!(),
		}
		seal_report(&mut bad);
		assert!(validate_report(&bad, &w, 0).is_err(), "case {case}");
	}
	assert!(validate_report(&good, &w, 1).is_err());
}
