// Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
//! File entry regressions using the unbounded queue and isolated owner.
use super::*;
use crate::mcp::runtime::{binary, ssh};

#[test]
fn file_response_parsing_uses_original_output_on_every_outcome() {
	let host = serde_json::from_value::<crate::mcp::runtime::config::HostConfig>(json!({
		"ssh_target":"original-fixture", "remote_state_dir":"/private/jobs-fixture"
	}))
	.unwrap();
	for (code, bytes, expected) in [
		(
			0,
			b"{\"version\":\"original\",\"eof\":true}".as_slice(),
			Some(json!({"version":"original","eof":true})),
		),
		(
			0,
			b"{\"status\":\"conflict\",\"error\":\"version mismatch\"}".as_slice(),
			Some(json!({"status":"conflict","error":"version mismatch"})),
		),
		(7, b"original stdout".as_slice(), None),
		(0, b"invalid original JSON".as_slice(), None),
	] {
		let output = Captured {
			output: Output {
				status: ExitStatus::from_raw(code << 8),
				stdout: bytes.to_vec(),
				stderr: b"original stderr".to_vec(),
			},
		};
		let result = ssh::parse_file_observation(&host, &output);
		if let Some(expected) = expected {
			assert_eq!(result.unwrap(), expected);
		} else {
			let error = result.unwrap_err().to_string();
			assert!(error.contains("original-fixture"), "{error}");
			assert!(
				error.contains(std::str::from_utf8(bytes).unwrap()),
				"{error}"
			);
			if code != 0 {
				assert!(error.contains("failed with 7"));
				assert!(error.contains("original stderr"));
			} else {
				assert!(error.contains("invalid JSON"));
			}
		}
		drop(output);
	}
}

#[tokio::test(flavor = "current_thread")]
async fn queued_file_wire_retains_its_original_payload_deadline_and_cancel_identity() {
	let (proxy, mut receiver) = proxy_admission_fixture();
	let deadline = Instant::now() + Duration::from_secs(30);
	let earlier = fill_proxy_channel(&proxy, deadline).await;
	let (command, input) = ssh::prepare_file_observation(ssh::FileObservation::Read {
		root: "/allowed/nested",
		path: "/allowed/nested/file",
		offset: Some(19),
		limit: 65536,
		expected_version: Some("original-version"),
	})
	.unwrap();
	let cancel = CancellationToken::new();
	let (send, _receive) = oneshot::channel();
	proxy
		.enqueue(
			"fixture",
			command.clone(),
			input.clone(),
			deadline,
			cancel.clone(),
			send,
		)
		.await
		.unwrap();
	assert_eq!(receiver.len(), 33);
	for _ in 0..32 {
		drop(receiver.recv().await.unwrap());
	}
	let request = receiver.recv().await.unwrap();
	assert_eq!(request.command, command);
	assert_eq!(request.input, input);
	assert_eq!(request.deadline, deadline);
	cancel.cancel();
	assert!(request.cancel.is_cancelled());
	drop(request);
	drop(earlier);
}

#[test]
fn isolated_file_pool_startup_intent_and_no_fallback_fixtures() {
	for kind in ["off", "refused", "enabled"] {
		let mut child = std::process::Command::new(std::env::current_exe().unwrap())
			.args(["--exact", "mcp::runtime::ssh::observation_pool::tests::file_observations::isolated_file_helper", "--ignored", "--nocapture"])
			.env("HEPTA_A36_FILE_POOL_FIXTURE", kind)
			.stdin(Stdio::null())
			.stdout(Stdio::null())
			.stderr(Stdio::inherit())
			.spawn().unwrap();
		let deadline = std::time::Instant::now() + Duration::from_secs(45);
		let status = loop {
			if let Some(status) = child.try_wait().unwrap() {
				break status;
			}
			if std::time::Instant::now() >= deadline {
				child.kill().unwrap();
				child.wait().unwrap();
				panic!("isolated file pool fixture deadline: {kind}");
			}
			std::thread::sleep(Duration::from_millis(20));
		};
		assert!(
			status.success(),
			"isolated file pool fixture failed: {kind}"
		);
	}
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "launched only by the bounded isolated file pool test"]
async fn isolated_file_helper() {
	let kind =
		std::env::var("HEPTA_A36_FILE_POOL_FIXTURE").expect("isolated file fixture required");
	let (_root, path, agent, control) = fixture_with_file_policy(true, true).await;
	assert!(!ssh::file_observation_pool_requested());
	if kind == "refused" {
		let mut spec: serde_json::Value =
			serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
		spec["allow_bounded_cached_authentication"] = json!(false);
		private_write(&path, &serde_json::to_vec(&spec).unwrap());
		assert!(ssh::start_observation_pool(Some(&path), true)
			.await
			.is_err());
		assert!(!ssh::file_observation_pool_requested());
		assert!(!requested());
		assert_eq!(control.requests.load(Ordering::Acquire), 0);
	} else {
		let enabled = match kind.as_str() {
			"off" => false,
			"enabled" => true,
			_ => panic!("unknown fixture"),
		};
		let guard = ssh::start_observation_pool(Some(&path), enabled)
			.await
			.unwrap()
			.unwrap();
		assert!(requested());
		assert_eq!(ssh::file_observation_pool_requested(), enabled);
		let before = control.requests.load(Ordering::Acquire);
		if enabled {
			for (host, path, message) in [
				("unknown", "/allowed/f", "unknown host"),
				("cold", "/allowed/f", "require an operator host"),
				("fixture", "relative", "absolute target path"),
				("fixture", "/allowed/../outside", "traversal"),
				("fixture", "/outside/f", "outside configured read roots"),
			] {
				let error = binary::info(binary::FileInfoParams {
					host: host.into(),
					path: path.into(),
				})
				.await
				.unwrap_err();
				assert!(error.to_string().contains(message), "{error:#}");
			}
			let error = binary::read(binary::BinaryReadParams {
				host: "fixture".into(),
				path: "/allowed/nested/f".into(),
				offset: None,
				limit: None,
				expected_version: Some("v".repeat(ssh::MAX_OBSERVATION_BYTES + 1)),
			})
			.await
			.unwrap_err();
			assert!(error
				.to_string()
				.contains("observation_pool_payload_unsupported"));
			let error = binary::info(binary::FileInfoParams {
				host: "fixture".into(),
				path: format!("/allowed/{}", "f".repeat(ssh::MAX_OBSERVATION_BYTES)),
			})
			.await
			.unwrap_err();
			assert!(error
				.to_string()
				.contains("observation_pool_payload_unsupported"));
			assert_eq!(control.requests.load(Ordering::Acquire), before);
			ssh::freeze_observation_pool();
			assert!(ssh::file_observation_pool_requested());
			for result in [
				binary::info(binary::FileInfoParams {
					host: "fixture".into(),
					path: "/allowed/nested/f".into(),
				})
				.await,
				binary::read(binary::BinaryReadParams {
					host: "fixture".into(),
					path: "/allowed/nested/f".into(),
					offset: Some(0),
					limit: Some(1),
					expected_version: Some("v1".into()),
				})
				.await,
			] {
				let error = result.unwrap_err();
				assert!(
					error.to_string().contains("observation pool unavailable"),
					"{error:#}"
				);
			}
			// Mutating APIs still reach their original write policy after pool freeze.
			for result in [
				binary::write(binary::BinaryWriteParams {
					host: "fixture".into(),
					path: "/allowed/f".into(),
					data_base64: "AA==".into(),
					expected_version: "absent".into(),
				})
				.await,
				binary::upload(binary::BinaryUploadParams {
					host: "fixture".into(),
					path: "/allowed/f".into(),
					action: binary::UploadAction::Abort,
					upload_id: "original-id".into(),
					offset: None,
					data_base64: None,
					expected_version: None,
					size: None,
					sha256: None,
				})
				.await,
				binary::patch_inode(binary::InodePatchParams {
					host: "fixture".into(),
					path: "/allowed/f".into(),
					action: binary::InodeAction::Status,
					transaction_id: "original-id".into(),
					acknowledge_non_atomic: true,
					preserve_special_bits: false,
					offset: None,
					expected_version: None,
					expected_sha256: None,
					data_base64: None,
				})
				.await,
			] {
				assert!(result
					.unwrap_err()
					.to_string()
					.contains("remote writes are disabled"));
			}
			assert_eq!(control.requests.load(Ordering::Acquire), before);
		}
		guard.shutdown().await.unwrap();
		assert!(POOL.get().unwrap().thread.lock().unwrap().is_none());
		assert!(ssh::start_observation_pool(None, false)
			.await
			.unwrap()
			.is_none());
		assert_eq!(ssh::file_observation_pool_requested(), enabled);
	}
	agent.abort();
	let _ = agent.await;
}
