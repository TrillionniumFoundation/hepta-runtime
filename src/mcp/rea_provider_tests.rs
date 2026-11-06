// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Static profile policy, exact-request recovery and report-binding regressions.

use super::*;

#[test]
fn static_engine_scratch_states_preserve_unknown_and_legacy_distinction() {
	for scratch in [
		json!({"removed_after_operation":true}),
		json!({"cleanup_owner":"standalone_worker","removed_after_operation":true,"cleanup_pending":false}),
		json!({"cleanup_owner":"durable_job","removed_after_operation":false,"cleanup_pending":true}),
	] {
		assert!(
			valid_worker_scratch(&json!({"scratch":scratch})),
			"{scratch}"
		);
	}
	for scratch in [
		json!({"cleanup_owner":"future-owner","removed_after_operation":true}),
		json!({"cleanup_owner":null,"removed_after_operation":true}),
		json!({"cleanup_owner":"standalone_worker","removed_after_operation":true,"cleanup_pending":true}),
		json!({"cleanup_owner":"durable_job","removed_after_operation":true,"cleanup_pending":true}),
		json!({"removed_after_operation":true,"cleanup_pending":true}),
	] {
		assert!(
			!valid_worker_scratch(&json!({"scratch":scratch})),
			"{scratch}"
		);
	}
}

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
		ghidra_engine: None,
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
		function_address: None,
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

fn jadx_profile() -> ReaStaticProfile {
	let mut p = profile();
	p.provider = StaticProvider::Jadx;
	p.backend_executable = "/opt/jdk21/bin/java".into();
	p.backend_version = "openjdk 21.0.12.1 2026-08-18".into();
	p.allowed_operations = vec![StaticOperation::Classes, StaticOperation::Sources];
	p.max_artifact_bytes = 32 * 1024 * 1024;
	p.memory_max_bytes = 1024 * 1024 * 1024;
	p.java_engine = Some(JavaEngineProfile {
		java_home: "/opt/jdk21".into(),
		jar_path: "/opt/jadx/jadx-1.5.6-all.jar".into(),
		jar_sha256: "4".repeat(64),
		engine_version: "1.5.6".into(),
		release_archive_sha256: "545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974"
			.into(),
		runtime_files: [
			"release",
			"lib/modules",
			"lib/server/libjvm.so",
			"lib/libjava.so",
			"lib/libzip.so",
			"lib/libnio.so",
			"lib/libjli.so",
		]
		.into_iter()
		.map(|name| (name.to_owned(), "5".repeat(64)))
		.collect(),
	});
	p
}

#[test]
fn legacy_gnu_profile_hash_is_unchanged_by_optional_java_support() {
	let encoded = serde_json::to_vec(&profile()).unwrap();
	assert!(!String::from_utf8_lossy(&encoded).contains("java_engine"));
	assert_eq!(
		sha256(&encoded),
		"6c450094a4d413a2be99cb6a3e97070d508b8f5d788f10df10ec01db70fcd69e"
	);
	let decoded: ReaStaticProfile = serde_json::from_slice(&encoded).unwrap();
	assert_eq!(decoded, profile());
}

#[test]
fn java_profiles_require_matching_engine_manifest_and_fixed_operations() {
	let valid = jadx_profile();
	validate_profile(&valid).unwrap();
	for case in 0..7 {
		let mut bad = valid.clone();
		match case {
			0 => bad.java_engine = None,
			1 => bad.provider = StaticProvider::GnuReadelf,
			2 => bad.allowed_operations = vec![StaticOperation::Relocations],
			3 => bad
				.java_engine
				.as_mut()
				.unwrap()
				.runtime_files
				.remove("lib/modules")
				.map(|_| ())
				.unwrap(),
			4 => bad.java_engine.as_mut().unwrap().jar_sha256 = "bad".into(),
			5 => bad.backend_executable = "/other/java".into(),
			6 => bad.max_artifact_bytes = 64 * 1024 * 1024,
			_ => unreachable!(),
		}
		assert!(validate_profile(&bad).is_err(), "case {case}");
	}
	assert!(StaticProvider::Jadx
		.arguments(StaticOperation::Classes, "/proc/self/fd/8")
		.is_err());
	assert!(!StaticProvider::GnuReadelf.supports(StaticOperation::Sources));
}

#[test]
fn java_profile_files_follow_host_read_and_protected_root_policy() {
	let mut cfg = config();
	cfg.rea_static_profiles
		.insert("owned_jadx".into(), jadx_profile());
	assert!(validate_profiles(&cfg).is_err());
	cfg.hosts
		.get_mut("owned")
		.unwrap()
		.allowed_read_path_prefixes
		.extend(["/opt/jdk21".into(), "/opt/jadx".into()]);
	validate_profiles(&cfg).unwrap();
	let mut descendant = cfg.clone();
	descendant
		.hosts
		.get_mut("owned")
		.unwrap()
		.protected_path_prefixes
		.push("/opt/jdk21/lib/modules".into());
	assert!(validate_profiles(&descendant).is_err());
	cfg.hosts
		.get_mut("owned")
		.unwrap()
		.protected_path_prefixes
		.push("/opt/jadx".into());
	assert!(validate_profiles(&cfg).is_err());
}

#[test]
fn java_report_cannot_rebind_engine_or_claim_source_correctness() {
	let mut w = worker();
	w.profile = jadx_profile();
	w.request.operation = StaticOperation::Sources;
	w.request.profile_sha256 = sha256(&serde_json::to_vec(&w.profile).unwrap());
	let mut v = report(&w);
	let observation = json!({
		"schema":"hepta.rea.jadx-observation.v1","engine_version":"1.5.6","operation":"sources",
		"observed_class_count":1,"returned_class_count":1,"omitted_class_count":0,"errors":0,"warnings":0,
		"rows":[{"class_name":"Owned","class_name_complete":true,"declared_methods":1,
			"source_sha256":"6".repeat(64),"source_utf8_bytes":30,"source_preview_complete":true}],
		"target_executed":false,"external_plugins_loaded":false,"source_semantics_validated":false,"coverage":"partial"
	});
	let stdout = serde_json::to_string(&observation).unwrap();
	v["stdout"] = json!(stdout);
	v["stdout_bytes"] = json!(stdout.len());
	v["stdout_sha256"] = json!(sha256(stdout.as_bytes()));
	v["summary"] = summary::selected_fields(w.profile.provider, w.request.operation, &stdout, true);
	v["java_engine"] = serde_json::to_value(&w.profile.java_engine).unwrap();
	v["bridge_sha256"] = json!(sha256(include_str!("rea_jadx_bridge.java").as_bytes()));
	v["backend"]["snapshot"] = json!("verified_installed_inode");
	v["network_syscalls_denied"] = json!(true);
	v["scratch"] = json!({"removed_after_operation":true});
	seal_report(&mut v);
	validate_report(&v, &w, 0).unwrap();
	for case in 0..4 {
		let mut bad = v.clone();
		match case {
			0 => bad["java_engine"]["jar_sha256"] = json!("7".repeat(64)),
			1 => bad["bridge_sha256"] = json!("7".repeat(64)),
			2 => bad["scratch"]["removed_after_operation"] = json!(false),
			3 => {
				let mut changed = observation.clone();
				changed["source_semantics_validated"] = json!(true);
				let text = serde_json::to_string(&changed).unwrap();
				bad["stdout"] = json!(text);
				bad["stdout_bytes"] = json!(text.len());
				bad["stdout_sha256"] = json!(sha256(text.as_bytes()));
				bad["summary"] =
					summary::selected_fields(w.profile.provider, w.request.operation, &text, true);
			}
			_ => unreachable!(),
		}
		seal_report(&mut bad);
		assert!(validate_report(&bad, &w, 0).is_err(), "case {case}");
	}
}

fn ghidra_profile() -> ReaStaticProfile {
	let mut profile = jadx_profile();
	let java = profile.java_engine.take().unwrap();
	profile.provider = StaticProvider::Ghidra;
	profile.backend_executable = "/opt/jdk25/bin/java".into();
	profile.backend_version = "openjdk 25.0.5 2026-10-20 LTS".into();
	profile.allowed_operations = vec![StaticOperation::Inventory];
	profile.max_artifact_bytes = 8 * 1024 * 1024;
	profile.ghidra_engine = Some(GhidraEngineProfile {
		bridge_revision: None,
		java_home: "/opt/jdk25".into(),
		installation_root: "/opt/ghidra/ghidra_12.2_PUBLIC".into(),
		manifest_path: "/opt/ghidra/installation.json".into(),
		manifest_sha256: "6".repeat(64),
		engine_version: "12.2".into(),
		release_archive_sha256: engine_profile::GHIDRA_RELEASE_SHA256.into(),
		runtime_files: java.runtime_files,
	});
	profile
}

#[test]
fn ghidra_profile_admits_only_fixed_import_inventory_and_exact_distribution() {
	let valid = ghidra_profile();
	validate_profile(&valid).unwrap();
	assert!(StaticProvider::Ghidra.supports(StaticOperation::Inventory));
	assert!(!StaticProvider::Ghidra.supports(StaticOperation::Sources));
	for case in 0..6 {
		let mut bad = valid.clone();
		match case {
			0 => bad.ghidra_engine = None,
			1 => bad.ghidra_engine.as_mut().unwrap().release_archive_sha256 = "0".repeat(64),
			2 => bad.allowed_operations = vec![StaticOperation::Symbols],
			3 => bad.java_engine = jadx_profile().java_engine,
			4 => bad.max_artifact_bytes = 16 * 1024 * 1024,
			5 => {
				bad.ghidra_engine.as_mut().unwrap().installation_root =
					"/opt/ghidra:injected".into()
			}
			_ => unreachable!(),
		}
		assert!(validate_profile(&bad).is_err(), "case {case}");
	}
	assert!(
		!String::from_utf8_lossy(&serde_json::to_vec(&profile()).unwrap())
			.contains("ghidra_engine")
	);
	assert!(
		!String::from_utf8_lossy(&serde_json::to_vec(&jadx_profile()).unwrap())
			.contains("ghidra_engine")
	);
}

#[test]
fn ghidra_manifest_rejects_path_escape_classpath_injection_and_identity_drift() {
	use engine_profile::{validate_manifest, InstallationManifest};
	let profile = ghidra_profile();
	let engine = profile.ghidra_engine.as_ref().unwrap();
	let manifest = InstallationManifest {
		schema: "hepta.rea.ghidra-installation.v1".into(),
		engine_version: "12.2".into(),
		release_archive_sha256: engine_profile::GHIDRA_RELEASE_SHA256.into(),
		files: [
			"Ghidra/application.properties",
			"Ghidra/Framework/Utility/lib/Utility.jar",
			"Ghidra/Features/Base/lib/Base.jar",
		]
		.into_iter()
		.map(|path| (path.into(), "7".repeat(64)))
		.collect(),
	};
	validate_manifest(&manifest, engine).unwrap();
	for case in 0..6 {
		let mut bad = manifest.clone();
		match case {
			0 => {
				bad.files.insert("Ghidra/../outside".into(), "7".repeat(64));
			}
			1 => {
				bad.files
					.insert("Ghidra/Features/Injected:jar".into(), "7".repeat(64));
			}
			2 => {
				bad.files.insert("outside/installed".into(), "7".repeat(64));
			}
			3 => {
				bad.files.remove("Ghidra/Features/Base/lib/Base.jar");
			}
			4 => bad.engine_version = "12.1".into(),
			5 => bad.release_archive_sha256 = "0".repeat(64),
			_ => unreachable!(),
		}
		assert!(validate_manifest(&bad, engine).is_err(), "case {case}");
	}
}

#[test]
fn ghidra_report_must_preserve_import_only_semantics_and_manifest_identity() {
	let mut worker = worker();
	worker.profile = ghidra_profile();
	worker.request.operation = StaticOperation::Inventory;
	worker.request.profile_sha256 = sha256(&serde_json::to_vec(&worker.profile).unwrap());
	let mut value = report(&worker);
	let observation = json!({"schema":"hepta.rea.ghidra-observation.v1","engine_version":"12.2","operation":"inventory",
		"target_executed":false,"auto_analysis_performed":false,"decompilation_performed":false,"external_libraries_loaded":false,"project_saved":false});
	let text = serde_json::to_string(&observation).unwrap();
	value["stdout"] = json!(text);
	value["stdout_bytes"] = json!(text.len());
	value["stdout_sha256"] = json!(sha256(text.as_bytes()));
	value["summary"] = summary::selected_fields(
		worker.profile.provider,
		worker.request.operation,
		&text,
		true,
	);
	value["ghidra_engine"] = serde_json::to_value(&worker.profile.ghidra_engine).unwrap();
	value["bridge_sha256"] = json!(sha256(include_str!("rea_ghidra_bridge.java").as_bytes()));
	value["backend"]["snapshot"] = json!("verified_installed_inode");
	value["installation_snapshot"] = json!("verified_installed_paths");
	value["network_syscalls_denied"] = json!(true);
	value["scratch"] = json!({"removed_after_operation":true});
	seal_report(&mut value);
	validate_report(&value, &worker, 0).unwrap();
	for case in 0..3 {
		let mut bad = value.clone();
		match case {
			0 => bad["ghidra_engine"]["manifest_sha256"] = json!("0".repeat(64)),
			1 => bad["installation_snapshot"] = json!("unverified"),
			2 => {
				let mut changed = observation.clone();
				changed["auto_analysis_performed"] = json!(true);
				let text = serde_json::to_string(&changed).unwrap();
				bad["stdout"] = json!(text);
				bad["stdout_bytes"] = json!(text.len());
				bad["stdout_sha256"] = json!(sha256(text.as_bytes()));
				bad["summary"] = summary::selected_fields(
					worker.profile.provider,
					worker.request.operation,
					&text,
					true,
				);
			}
			_ => unreachable!(),
		}
		seal_report(&mut bad);
		assert!(validate_report(&bad, &worker, 0).is_err(), "case {case}");
	}
}

#[test]
fn ghidra_analysis_operations_require_explicit_profile_and_selected_identity() {
	let mut input = worker();
	input.profile = ghidra_profile();
	input.request.operation = StaticOperation::Decompile;
	input.request.function_address = Some("0x401000".into());
	input.request.profile_sha256 = sha256(&serde_json::to_vec(&input.profile).unwrap());
	assert!(validate_worker_request(&input).is_err());
	input
		.profile
		.ghidra_engine
		.as_mut()
		.unwrap()
		.bridge_revision = Some(2);
	input
		.profile
		.allowed_operations
		.push(StaticOperation::Decompile);
	input.request.profile_sha256 = sha256(&serde_json::to_vec(&input.profile).unwrap());
	validate_worker_request(&input).unwrap();
	input.request.function_address = None;
	assert!(validate_worker_request(&input).is_err());
	input.request.operation = StaticOperation::Inventory;
	validate_worker_request(&input).unwrap();
	input.request.function_address = Some("0x401000".into());
	assert!(validate_worker_request(&input).is_err());
}

fn analysis_observation(input: &WorkerRequest) -> Value {
	let code = "int owned(int value) { return value * 7 + 11; }\n";
	json!({"schema":"hepta.rea.ghidra-analysis.v1","engine_version":"12.2","bridge_revision":2,
		"operation":input.request.operation,"analysis_profile":ghidra_contract::ANALYSIS_PROFILE,
		"enabled_analyzers":ghidra_contract::ANALYZERS,
		"analysis_completed":true,"auto_analysis_performed":true,"decompilation_performed":true,
		"target_executed":false,"external_libraries_loaded":false,"project_saved":false,
		"source_semantics_validated":false,"source_sha256":input.request.artifact_sha256,"source_bytes":64,
		"function_address_requested":input.request.function_address,"coverage":"partial",
		"function":{"entry_address":"0x401000","name":"owned","name_sha256":sha256(b"owned"),"external":false},
		"c_code":code,"c_code_utf8_bytes":code.len(),"c_code_sha256":sha256(code.as_bytes()),
		"c_code_preview_sha256":sha256(code.as_bytes()),"c_code_complete":true,
		"decompilation_completed":true,"native_child_cleanup_confirmed":true,"observed_native_children":1})
}

fn rebind_observation(value: &mut Value, input: &WorkerRequest, observation: &Value) {
	let text = serde_json::to_string(observation).unwrap();
	value["stdout"] = json!(text);
	value["stdout_bytes"] = json!(text.len());
	value["stdout_sha256"] = json!(sha256(text.as_bytes()));
	value["summary"] =
		summary::selected_fields(input.profile.provider, input.request.operation, &text, true);
	seal_report(value);
}

#[test]
fn ghidra_decompilation_report_rejects_rehashed_wrong_address_partial_work_and_unconfirmed_children(
) {
	let mut input = worker();
	input.profile = ghidra_profile();
	input
		.profile
		.ghidra_engine
		.as_mut()
		.unwrap()
		.bridge_revision = Some(2);
	input
		.profile
		.allowed_operations
		.push(StaticOperation::Decompile);
	input.request.operation = StaticOperation::Decompile;
	input.request.function_address = Some("0x401000".into());
	input.request.profile_sha256 = sha256(&serde_json::to_vec(&input.profile).unwrap());
	let observation = analysis_observation(&input);
	let mut value = report(&input);
	value["subject"]["size_bytes"] = json!(64);
	value["ghidra_engine"] = serde_json::to_value(&input.profile.ghidra_engine).unwrap();
	value["bridge_sha256"] = json!(sha256(
		ghidra_contract::bridge(StaticOperation::Decompile, Some(2))
			.unwrap()
			.as_bytes()
	));
	value["backend"]["snapshot"] = json!("verified_installed_inode");
	value["installation_snapshot"] = json!("verified_installed_paths");
	value["network_syscalls_denied"] = json!(true);
	value["scratch"] = json!({"removed_after_operation":true});
	rebind_observation(&mut value, &input, &observation);
	validate_report(&value, &input, 0).unwrap();
	for case in 0..10 {
		let mut changed = observation.clone();
		match case {
			0 => changed["function"]["entry_address"] = json!("0x401001"),
			1 => changed["function_address_requested"] = json!("0x401001"),
			2 => changed["analysis_completed"] = json!(false),
			3 => changed["decompilation_completed"] = json!(false),
			4 => changed["native_child_cleanup_confirmed"] = json!(false),
			5 => changed["c_code"] = json!("invented"),
			6 => changed["source_bytes"] = json!(65),
			7 => changed["source_sha256"] = json!("0".repeat(64)),
			8 => changed["source_semantics_validated"] = json!(true),
			9 => changed["enabled_analyzers"] = json!(["Caller Script"]),
			_ => unreachable!(),
		}
		let mut bad = value.clone();
		rebind_observation(&mut bad, &input, &changed);
		assert!(validate_report(&bad, &input, 0).is_err(), "case {case}");
	}
}

#[test]
fn ghidra_revision_two_is_explicit_and_never_rebinds_legacy_profiles() {
	let legacy = ghidra_profile();
	let original = serde_json::to_value(&legacy).unwrap();
	assert!(original["ghidra_engine"].get("bridge_revision").is_none());
	let mut upgraded = legacy.clone();
	upgraded.ghidra_engine.as_mut().unwrap().bridge_revision = Some(2);
	validate_profile(&upgraded).unwrap();
	assert_ne!(
		sha256(&serde_json::to_vec(&legacy).unwrap()),
		sha256(&serde_json::to_vec(&upgraded).unwrap())
	);
	assert_ne!(
		ghidra_contract::bridge(StaticOperation::Inventory, None).unwrap(),
		ghidra_contract::bridge(StaticOperation::Inventory, Some(2)).unwrap()
	);
	let mut invalid = legacy;
	invalid.allowed_operations.push(StaticOperation::Functions);
	assert!(validate_profile(&invalid).is_err());
	invalid.ghidra_engine.as_mut().unwrap().bridge_revision = Some(3);
	assert!(validate_profile(&invalid).is_err());
	assert!(ghidra_contract::bridge(StaticOperation::Functions, None).is_err());
}

#[test]
fn ghidra_inventory_v2_binds_repaired_bridge_and_captured_source() {
	let mut input = worker();
	input.profile = ghidra_profile();
	input
		.profile
		.ghidra_engine
		.as_mut()
		.unwrap()
		.bridge_revision = Some(2);
	input.request.operation = StaticOperation::Inventory;
	let value = json!({"schema":"hepta.rea.ghidra-observation.v2","bridge_revision":2,"engine_version":"12.2","operation":"inventory","target_executed":false,"auto_analysis_performed":false,"decompilation_performed":false,"external_libraries_loaded":false,"project_saved":false,"source_sha256":input.request.artifact_sha256,"source_bytes":64});
	ghidra_contract::validate_observation(&value, &input, 64).unwrap();
	for field in ["schema", "bridge_revision", "source_sha256", "source_bytes"] {
		let mut wrong = value.clone();
		wrong[field] = json!("wrong");
		assert!(ghidra_contract::validate_observation(&wrong, &input, 64).is_err());
	}
	input
		.profile
		.ghidra_engine
		.as_mut()
		.unwrap()
		.bridge_revision = None;
	assert!(ghidra_contract::validate_observation(&value, &input, 64).is_err());
}

fn ghidra_1214_profile() -> ReaStaticProfile {
	let mut profile = ghidra_profile();
	let engine = profile.ghidra_engine.as_mut().unwrap();
	engine.bridge_revision = Some(3);
	engine.engine_version = "12.1.4".into();
	engine.installation_root = "/opt/ghidra/ghidra_12.1.4_PUBLIC".into();
	engine.release_archive_sha256 = engine_profile::GHIDRA_1214_RELEASE_SHA256.into();
	profile
}

#[test]
fn ghidra_release_revision_and_archive_are_one_admission_identity() {
	for revision in [None, Some(2), Some(3), Some(4)] {
		for version in ["12.2", "12.1.4", "12.1.3"] {
			for archive in [
				engine_profile::GHIDRA_RELEASE_SHA256,
				engine_profile::GHIDRA_1214_RELEASE_SHA256,
			] {
				let mut candidate = ghidra_profile();
				let engine = candidate.ghidra_engine.as_mut().unwrap();
				engine.bridge_revision = revision;
				engine.engine_version = version.into();
				engine.release_archive_sha256 = archive.into();
				let admitted = (matches!(revision, None | Some(2))
					&& version == "12.2"
					&& archive == engine_profile::GHIDRA_RELEASE_SHA256)
					|| (revision == Some(3)
						&& version == "12.1.4"
						&& archive == engine_profile::GHIDRA_1214_RELEASE_SHA256);
				assert_eq!(
					validate_profile(&candidate).is_ok(),
					admitted,
					"revision {revision:?}, version {version}, archive {archive}"
				);
			}
		}
	}
	let selected = ghidra_1214_profile();
	validate_profile(&selected).unwrap();
	assert_ne!(
		sha256(&serde_json::to_vec(&selected).unwrap()),
		sha256(&serde_json::to_vec(&ghidra_profile()).unwrap())
	);
}

#[test]
fn ghidra_1214_inventory_rejects_cross_release_or_revision_observations() {
	let mut input = worker();
	input.profile = ghidra_1214_profile();
	input.request.operation = StaticOperation::Inventory;
	let value = json!({"schema":"hepta.rea.ghidra-observation.v2","bridge_revision":3,"engine_version":"12.1.4","operation":"inventory","target_executed":false,"auto_analysis_performed":false,"decompilation_performed":false,"external_libraries_loaded":false,"project_saved":false,"source_sha256":input.request.artifact_sha256,"source_bytes":64});
	ghidra_contract::validate_observation(&value, &input, 64).unwrap();
	for case in 0..5 {
		let mut wrong = value.clone();
		match case {
			0 => wrong["engine_version"] = json!("12.2"),
			1 => wrong["bridge_revision"] = json!(2),
			2 => wrong["source_sha256"] = json!("0".repeat(64)),
			3 => wrong["source_bytes"] = json!(65),
			4 => wrong["auto_analysis_performed"] = json!(true),
			_ => unreachable!(),
		}
		assert!(ghidra_contract::validate_observation(&wrong, &input, 64).is_err());
	}
	input.profile = ghidra_profile();
	input
		.profile
		.ghidra_engine
		.as_mut()
		.unwrap()
		.bridge_revision = Some(2);
	assert!(ghidra_contract::validate_observation(&value, &input, 64).is_err());
}

#[test]
fn ghidra_1214_analysis_rejects_rehashed_engine_and_bridge_substitution() {
	let mut input = worker();
	input.profile = ghidra_1214_profile();
	input
		.profile
		.allowed_operations
		.push(StaticOperation::Decompile);
	input.request.operation = StaticOperation::Decompile;
	input.request.function_address = Some("0x401000".into());
	input.request.profile_sha256 = sha256(&serde_json::to_vec(&input.profile).unwrap());
	validate_worker_request(&input).unwrap();
	let mut observation = analysis_observation(&input);
	observation["engine_version"] = json!("12.1.4");
	observation["bridge_revision"] = json!(3);
	observation["analysis_profile"] = json!(ghidra_contract::ANALYSIS_PROFILE_1214);
	let mut value = report(&input);
	value["subject"]["size_bytes"] = json!(64);
	value["ghidra_engine"] = serde_json::to_value(&input.profile.ghidra_engine).unwrap();
	value["bridge_sha256"] = json!(sha256(
		ghidra_contract::bridge(StaticOperation::Decompile, Some(3))
			.unwrap()
			.as_bytes()
	));
	value["backend"]["snapshot"] = json!("verified_installed_inode");
	value["installation_snapshot"] = json!("verified_installed_paths");
	value["network_syscalls_denied"] = json!(true);
	value["scratch"] = json!({"removed_after_operation":true});
	rebind_observation(&mut value, &input, &observation);
	validate_report(&value, &input, 0).unwrap();
	for case in 0..6 {
		let mut bad = value.clone();
		let mut changed = observation.clone();
		match case {
			0 => changed["engine_version"] = json!("12.2"),
			1 => changed["bridge_revision"] = json!(2),
			2 => changed["analysis_profile"] = json!(ghidra_contract::ANALYSIS_PROFILE),
			3 => {
				bad["bridge_sha256"] = json!(sha256(
					ghidra_contract::bridge(StaticOperation::Decompile, Some(2))
						.unwrap()
						.as_bytes()
				))
			}
			4 => {
				bad["ghidra_engine"]["release_archive_sha256"] =
					json!(engine_profile::GHIDRA_RELEASE_SHA256)
			}
			5 => changed["native_child_cleanup_confirmed"] = json!(false),
			_ => unreachable!(),
		}
		rebind_observation(&mut bad, &input, &changed);
		assert!(validate_report(&bad, &input, 0).is_err(), "case {case}");
	}
}
