// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Public request routing through a complete admitted native profile.
//! The installed images are explicit fixtures: this tests controller admission
//! and exact transport frames, not HIA algorithms or a remote workload launch.

use super::super::native_jobs::{admit, prepare, NativeJobOperation};
use super::*;
use crate::mcp::{hia_contract, hia_controller_release};

fn fixture_image() -> Vec<u8> {
	// Valid x86-64 ELF that emits one zero-wait poll response. The status callback
	// returns a sentinel before any remote operation or terminal projection.
	let mut image = vec![0_u8; 120];
	image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
	image[16..20].copy_from_slice(&[2, 0, 62, 0]);
	image[20..24].copy_from_slice(&1_u32.to_le_bytes());
	image[24..32].copy_from_slice(&0x400078_u64.to_le_bytes());
	image[32..40].copy_from_slice(&64_u64.to_le_bytes());
	image[52..58].copy_from_slice(&[64, 0, 56, 0, 1, 0]);
	image[64..72].copy_from_slice(&[1, 0, 0, 0, 5, 0, 0, 0]);
	image[80..88].copy_from_slice(&0x400000_u64.to_le_bytes());
	image[88..96].copy_from_slice(&0x400000_u64.to_le_bytes());
	image[112..120].copy_from_slice(&4096_u64.to_le_bytes());
	image.extend_from_slice(&[
		0xb8, 1, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0x48, 0x8d, 0x35, 16, 0, 0, 0, 0xba, 24, 0, 0, 0, 0x0f,
		0x05, 0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05,
	]);
	image.extend_from_slice(b"HIAJPO01");
	image.extend_from_slice(&[0; 16]);
	let length = image.len() as u64;
	image[96..104].copy_from_slice(&length.to_le_bytes());
	image[104..112].copy_from_slice(&length.to_le_bytes());
	image
}

fn fixture() -> (tempfile::TempDir, PathBuf, String, HostConfig) {
	let directory = tempfile::tempdir().unwrap();
	let root = directory.path().canonicalize().unwrap();
	let image = fixture_image();
	let mut pins = BTreeMap::new();
	for name in [
		"hia-agent-mcp-request",
		"hia-agent-mcp-reply",
		"hia-agent-mcp-terminal",
		"hia-agent-mcp-negotiation",
		"hia-agent-mcp-catalog",
		"hia-agent-mcp-uri",
		"hia-agent-mcp-input-schema",
		"hia-agent-mcp-response-schema",
		"hia-agent-mcp-proof-schema",
		"hia-worker-prepare",
		"hia-job-receipt",
		"hia-agent-job-terminal-receipt",
		"hia-job-supervisor",
		"hia-job-entry",
		"hia-job-submit",
		"hia-job-observation",
		"hia-job-cancel",
		"hia-job-launch",
		"HIA_AGENT_NATIVE_TOOL_CATALOG.json",
	] {
		let bytes = if name.ends_with(".json") {
			hia_contract::CATALOG_BYTES
		} else {
			&image
		};
		std::fs::write(root.join(name), bytes).unwrap();
		pins.insert(name, hia_contract::sha256(bytes));
	}
	let manifest = root.join("hia-controller.json");
	let bytes =
		serde_json::to_vec(&json!({"schema":"hepta.hia.mcp.controller.v26","files":pins})).unwrap();
	std::fs::write(&manifest, &bytes).unwrap();
	let mut roles = serde_json::Map::new();
	for (field, name) in [
		("entry", "hia-job-entry"),
		("submit", "hia-job-submit"),
		("observation", "hia-job-observation"),
		("cancel", "hia-job-cancel"),
		("launcher", "hia-job-launch"),
	] {
		roles.insert(
			field.into(),
			json!({"executable":format!("/installed/{name}"),"sha256":pins[name]}),
		);
	}
	let host = serde_json::from_value(json!({
		"ssh_target":"never-connect.invalid", "platform":"linux", "execution_mode":"operator",
		"remote_state_dir":"/state", "allow_execute":true, "allow_job_network":false,
		"allow_detached_fallback":false, "allowed_cwd_prefixes":["/work/allowed"],
		"native_jobs":roles,
	}))
	.unwrap();
	(directory, manifest, hia_contract::sha256(&bytes), host)
}

fn params(key: Option<&str>, stdin: Option<&str>) -> ProcessStartParams {
	serde_json::from_value(json!({
		"host":"fixture", "executable":"/usr/bin/true", "args":["opaque argument", "--unchanged"],
		"cwd":"/work/allowed/project", "env":{"TEST_VALUE":"unchanged value"},
		"stdin":stdin, "idempotency_key":key, "timeout_seconds":9, "nice":7,
		"cpu_quota_percent":25, "memory_max_bytes":67108864,
	}))
	.unwrap()
}

fn record(params: &ProcessStartParams) -> JobRecord {
	let digest = request_digest(params).unwrap();
	serde_json::from_value(json!({
		"id":"original-job", "host":"fixture", "ssh_target":"never-connect.invalid",
		"unit":"hepta-runtime-job-original-job", "remote_job_dir":"/state/jobs/original-job",
		"executable":params.executable, "args":params.args, "cwd":params.cwd,
		"env_keys":["TEST_VALUE"], "created_unix_ms":1, "idempotency_key":params.idempotency_key,
		"request_fingerprint":fingerprint(&digest), "request_digest":digest,
		"launch_state":"pending", "execution_mode":"operator", "system_jobctl":false,
	}))
	.unwrap()
}

fn word(bytes: &[u8], offset: usize) -> u64 {
	u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[test]
fn public_native_profile_owns_start_and_status_without_reserved_keys() {
	const CHILD: &str = "HEPTA_NATIVE_PUBLIC_PROFILE_TEST_CHILD";
	if std::env::var_os(CHILD).is_none() {
		let output = std::process::Command::new(std::env::current_exe().unwrap())
			.args([
				"mcp::runtime::jobs::native_profile_tests::public_native_profile_owns_start_and_status_without_reserved_keys",
				"--exact", "--test-threads=1",
			])
			.env(CHILD, "1").output().unwrap();
		assert!(
			output.status.success(),
			"{}\n{}",
			String::from_utf8_lossy(&output.stdout),
			String::from_utf8_lossy(&output.stderr)
		);
		return;
	}
	let (_directory, manifest, pin, host) = fixture();
	let initial_params = params(Some("ordinary-public-request"), None);
	let initial_record = record(&initial_params);
	assert!(launch_request(&host, &initial_record, &initial_params)
		.unwrap_err()
		.to_string()
		.contains("admitted v26"));
	let mut legacy = host.clone();
	legacy.native_jobs = None;
	assert!(admit(&legacy).unwrap().is_none());
	hia_controller_release::install(&manifest, &pin).unwrap();

	for key in [Some("ordinary-public-request"), None] {
		for stdin in [None, Some(""), Some("opaque input\n")] {
			let params = params(key, stdin);
			let record = record(&params);
			let old_request = launch_request(&legacy, &record, &params).unwrap();
			// Reproduce the old generic request: no reserved worker argv/key means
			// the complete native submit contract refuses before remote dispatch.
			let refusal = prepare(&host, NativeJobOperation::Submit(&old_request))
				.err()
				.unwrap();
			assert!(refusal
				.to_string()
				.contains("complete HIA authority profile"));
			let request = launch_request(&host, &record, &params).unwrap();
			for (name, value) in old_request.as_object().unwrap() {
				assert_eq!(&request[name], value, "original field {name}");
			}
			let prepared = prepare(&host, NativeJobOperation::Submit(&request)).unwrap();
			assert_eq!(prepared.command, "'/installed/hia-job-entry'");
			let frame = prepared.input.wire().unwrap();
			let start = 96 + word(&frame, 16) as usize;
			let payload = &frame[start..];
			assert_eq!(&payload[..8], b"HIAJSB01");
			assert_eq!(
				word(payload, 16),
				stdin.map_or(u64::MAX, |value| value.len() as u64)
			);
			let metadata: Value =
				serde_json::from_slice(&payload[64..64 + word(payload, 8) as usize]).unwrap();
			for (name, value) in old_request.as_object().unwrap() {
				if name != "stdin" {
					assert_eq!(&metadata[name], value, "wire field {name}");
				}
			}
			assert!(metadata.get("stdin").is_none());
			assert_eq!(metadata["hia_job_entry_path"], "/installed/hia-job-entry");
			assert_eq!(
				request_digest(&params).unwrap(),
				record.request_digest.as_deref().unwrap()
			);
			if let Some(stdin) = stdin {
				assert!(payload.ends_with(stdin.as_bytes()));
			}
		}
	}

	// Even an unused role must match; the native-only selection never falls back.
	for role in ["entry", "submit", "observation", "cancel", "launcher"] {
		let mut invalid = serde_json::to_value(&host).unwrap();
		invalid["native_jobs"][role]["sha256"] = json!("0".repeat(64));
		let invalid: HostConfig = serde_json::from_value(invalid).unwrap();
		assert!(
			launch_request(&invalid, &initial_record, &initial_params).is_err(),
			"role {role}"
		);
		assert!(admit(&invalid).is_err(), "status role {role}");
	}
	let mut wrong_platform = host.clone();
	wrong_platform.platform = Platform::Macos;
	assert!(launch_request(&wrong_platform, &initial_record, &initial_params).is_err());
	let mut system = initial_record.clone();
	system.system_jobctl = true;
	assert!(launch_request(&host, &system, &initial_params)
		.unwrap_err()
		.to_string()
		.contains("legacy system jobctl"));

	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.unwrap();
	runtime.block_on(async {
		let old = observe_operator_status(
			&initial_record,
			0,
			None,
			|snapshot, terminal, lifecycle, witness| {
				std::future::ready(Ok(operator_status_request(
					&initial_record,
					0,
					snapshot,
					terminal,
					lifecycle,
					witness,
				)))
			},
		)
		.await
		.unwrap();
		assert!(prepare(&host, NativeJobOperation::Status(&old)).is_err());
		let mut revoked = host.clone();
		revoked.allow_execute = false;
		let admission = admit(&revoked).unwrap();
		let called = std::cell::Cell::new(false);
		let error = observe_operator_status(
			&initial_record,
			30,
			admission,
			|snapshot, terminal, lifecycle, witness| {
				assert_eq!(
					(snapshot, terminal, lifecycle, witness),
					(true, true, true, true)
				);
				let request = operator_status_request(
					&initial_record,
					30,
					snapshot,
					terminal,
					lifecycle,
					witness,
				);
				assert_eq!(request["wait_seconds"], 0);
				let frame = prepare(&revoked, NativeJobOperation::Status(&request))
					.unwrap()
					.input
					.wire()
					.unwrap();
				let payload = &frame[96 + word(&frame, 16) as usize..];
				assert_eq!(&payload[..8], b"HIAJOBQ1");
				assert_eq!(word(payload, 72), 63);
				called.set(true);
				std::future::ready(Err(anyhow::anyhow!("stop-before-remote-status")))
			},
		)
		.await
		.unwrap_err();
		assert!(called.get());
		assert_eq!(error.to_string(), "stop-before-remote-status");
	});
}
