// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Binary tool inputs bind explicit hosts and reject hidden authority fields.
use super::*;

#[test]
fn binary_schemas_reject_hidden_authority() {
	assert!(serde_json::from_value::<BinaryReadParams>(
		json!({"host":"main","path":"/tmp/a","root":"/"})
	)
	.is_err());
	assert!(serde_json::from_value::<BinaryWriteParams>(json!({"host":"main","path":"/tmp/a","data_base64":"AA==","expected_version":"absent","sudo":true})).is_err());
	assert!(serde_json::from_value::<FileInfoParams>(
		json!({"host":"main","path":"/tmp/a","ssh_target":"attacker"})
	)
	.is_err());
}

#[test]
fn binary_writes_require_version_and_named_host() {
	assert!(serde_json::from_value::<BinaryWriteParams>(
		json!({"host":"main","path":"/tmp/a","data_base64":"AA=="})
	)
	.is_err());
	assert!(serde_json::from_value::<BinaryReadParams>(json!({"path":"/tmp/a"})).is_err());
	assert!(serde_json::from_value::<BinaryWriteParams>(
		json!({"host":"main","path":"/tmp/a","data_base64":"AA==","expected_version":"absent"})
	)
	.is_ok());
}

#[test]
fn upload_action_is_typed_and_extra_fields_rejected() {
	assert!(serde_json::from_value::<BinaryUploadParams>(
		json!({"host":"main","path":"/tmp/a","upload_id":"test-key","action":"execute"})
	)
	.is_err());
	assert!(serde_json::from_value::<BinaryUploadParams>(
		json!({"host":"main","path":"/tmp/a","upload_id":"test-key","action":"abort","command":"rm"})
	)
	.is_err());
	assert!(serde_json::from_value::<BinaryUploadParams>(
		json!({"host":"main","path":"/tmp/a","upload_id":"test-key","action":"abort"})
	)
	.is_ok());
}

#[test]
fn inode_patch_requires_explicit_semantics_and_rejects_hidden_privileges() {
	assert!(serde_json::from_value::<InodePatchParams>(
		json!({"host":"main","path":"/tmp/a","action":"apply","transaction_id":"fixture-1"})
	)
	.is_err());
	assert!(serde_json::from_value::<InodePatchParams>(json!({"host":"main","path":"/tmp/a","action":"apply","transaction_id":"fixture-1","acknowledge_non_atomic":true,"sudo":true})).is_err());
	assert!(serde_json::from_value::<InodePatchParams>(json!({"host":"main","path":"/tmp/a","action":"recover","transaction_id":"fixture-1","acknowledge_non_atomic":true})).is_ok());
}

#[test]
fn file_observation_policy_selects_only_the_original_longest_read_root() {
	use std::process::{Command, Stdio};
	let mut child = Command::new(std::env::current_exe().unwrap())
		.args([
			"--exact",
			"mcp::runtime::binary::tests::isolated_file_policy_helper",
			"--ignored",
			"--nocapture",
		])
		.env("HEPTA_A36_FILE_POLICY_FIXTURE", "1")
		.stdin(Stdio::null())
		.stdout(Stdio::null())
		.stderr(Stdio::inherit())
		.spawn()
		.unwrap();
	let deadline = std::time::Instant::now() + Duration::from_secs(30);
	let status = loop {
		if let Some(status) = child.try_wait().unwrap() {
			break status;
		}
		if std::time::Instant::now() >= deadline {
			child.kill().unwrap();
			child.wait().unwrap();
			panic!("isolated file policy fixture deadline");
		}
		std::thread::sleep(Duration::from_millis(20));
	};
	assert!(status.success(), "isolated file policy fixture failed");
}

#[test]
#[ignore = "launched only by the bounded isolated file policy test"]
fn isolated_file_policy_helper() {
	assert_eq!(std::env::var("HEPTA_A36_FILE_POLICY_FIXTURE").unwrap(), "1");
	let root = tempfile::tempdir().unwrap();
	let config = serde_json::from_value::<super::super::config::RuntimeConfig>(json!({
		"state_dir":root.path().join("state"), "hosts":{
			"operator":{"ssh_target":"unused-operator","execution_mode":"operator",
				"remote_state_dir":"/jobs","allow_write":false,
				"allowed_read_path_prefixes":["/allowed","/allowed/nested/"],
				"allowed_write_path_prefixes":["/write-only"]},
			"isolated":{"ssh_target":"unused-isolated","remote_state_dir":"/jobs",
				"allowed_read_path_prefixes":["/allowed"]}
		}
	}))
	.unwrap();
	super::super::config::init_runtime(config).unwrap();
	for (path, expected) in [
		("/allowed", "/allowed"),
		("/allowed/f", "/allowed"),
		("/allowed/nested/", "/allowed/nested/"),
		("/allowed/nested/f", "/allowed/nested/"),
		("/allowed/nested-sibling/f", "/allowed"),
	] {
		assert_eq!(observation_read_root("operator", path).unwrap(), expected);
	}
	for (host, path) in [
		("unknown", "/allowed/f"),
		("isolated", "/allowed/f"),
		("operator", "relative"),
		("operator", "/allowed/../outside"),
		("operator", "/allowed-sibling/f"),
		("operator", "/write-only/f"),
	] {
		assert!(observation_read_root(host, path).is_err(), "{host}: {path}");
	}
}
