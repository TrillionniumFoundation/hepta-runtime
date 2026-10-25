// Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
//! Closed file wire protocol and startup rejection without network I/O.
use super::*;
use serde_json::{json, Value};

#[test]
fn file_observation_wire_preserves_the_original_helper_and_data_protocol() {
	let source = concat!(
		include_str!("file_metadata.py"),
		"\n",
		include_str!("inode_patch.py"),
		"\n",
		include_str!("binary_file.py")
	);
	let fixed_command = python_json_command("python3", source).unwrap();
	let data = "/allowed/'\"; SHOULD_NEVER_BE_CODE\n";
	let (command, input) = prepare_file_observation(FileObservation::Info {
		root: "/allowed",
		path: data,
	})
	.unwrap();
	assert_eq!(command, fixed_command);
	assert!(!command.contains("SHOULD_NEVER_BE_CODE"));
	assert_eq!(
		serde_json::from_slice::<Value>(&input).unwrap(),
		json!({"op":"info","root":"/allowed","path":data})
	);
	for (offset, limit, expected_version) in [
		(None, 32768, None),
		(Some(0), 1, Some("")),
		(Some(u64::MAX), 65536, Some("version\n'\"; NOT_AN_OP")),
	] {
		let (command, input) = prepare_file_observation(FileObservation::Read {
			root: "/allowed",
			path: data,
			offset,
			limit,
			expected_version,
		})
		.unwrap();
		assert_eq!(command, fixed_command);
		assert!(!command.contains("NOT_AN_OP"));
		assert_eq!(
			serde_json::from_slice::<Value>(&input).unwrap(),
			json!({"op":"read","root":"/allowed","path":data,
				"offset":offset,"limit":limit,"expected_version":expected_version})
		);
	}
}

#[test]
fn file_observation_rejects_each_raw_field_and_encoded_expansion_before_dispatch() {
	let raw = "x".repeat(MAX_OBSERVATION_BYTES + 1);
	let half = "x".repeat(MAX_OBSERVATION_BYTES / 2 + 1);
	for observation in [
		FileObservation::Info {
			root: &raw,
			path: "/allowed/f",
		},
		FileObservation::Info {
			root: "/allowed",
			path: &raw,
		},
		FileObservation::Info {
			root: &half,
			path: &half,
		},
		FileObservation::Read {
			root: "/allowed",
			path: "/allowed/f",
			offset: None,
			limit: 1,
			expected_version: Some(&raw),
		},
	] {
		let error = prepare_file_observation(observation).unwrap_err();
		assert!(
			error.to_string().contains("original file fields"),
			"{error:#}"
		);
	}
	for expanded in [
		"\n".repeat(MAX_OBSERVATION_BYTES / 2),
		"x".repeat(MAX_OBSERVATION_BYTES - 100),
	] {
		let error = prepare_file_observation(FileObservation::Read {
			root: "/allowed",
			path: "/allowed/f",
			offset: None,
			limit: 1,
			expected_version: Some(&expanded),
		})
		.unwrap_err();
		assert!(
			error.to_string().contains("queued command and stdin"),
			"{error:#}"
		);
	}
}

#[test]
fn file_observation_accepts_exact_combined_boundary_and_rejects_one_more_byte() {
	for read in [false, true] {
		let prepare = |path| {
			prepare_file_observation(if read {
				FileObservation::Read {
					root: "/allowed",
					path,
					offset: None,
					limit: 65536,
					expected_version: Some("v1"),
				}
			} else {
				FileObservation::Info {
					root: "/allowed",
					path,
				}
			})
		};
		let (command, input) = prepare("").unwrap();
		let path = "x".repeat(MAX_OBSERVATION_BYTES - command.len() - input.len());
		let (command, input) = prepare(&path).unwrap();
		assert_eq!(command.len() + input.len(), MAX_OBSERVATION_BYTES);
		let error = prepare(&format!("{path}x")).unwrap_err();
		assert!(error
			.to_string()
			.contains("observation_pool_payload_unsupported"));
	}
}

#[test]
fn public_file_inputs_cannot_select_pool_authority_or_write_operations() {
	use crate::mcp::runtime::binary::{BinaryReadParams, FileInfoParams};
	for field in [
		"root",
		"op",
		"write",
		"command",
		"code",
		"interpreter",
		"ssh_target",
	] {
		let mut input = json!({"host":"fixture","path":"/allowed/f"});
		input[field] = json!("attacker_selected");
		assert!(serde_json::from_value::<FileInfoParams>(input.clone()).is_err());
		assert!(serde_json::from_value::<BinaryReadParams>(input).is_err());
	}
}

#[tokio::test(flavor = "current_thread")]
async fn file_pool_missing_profile_fails_without_enabling_routing() {
	assert!(!file_observation_pool_requested());
	assert!(start_observation_pool(None, false).await.unwrap().is_none());
	assert!(start_observation_pool(None, true).await.is_err());
	assert!(!file_observation_pool_requested());
	let error = run_file_observation(
		"not-configured",
		FileObservation::Info {
			root: "/allowed",
			path: "/allowed/f",
		},
	)
	.await
	.unwrap_err();
	assert_eq!(error.to_string(), "file observation pool was not requested");
}

#[cfg(not(target_os = "linux"))]
#[tokio::test(flavor = "current_thread")]
async fn file_pool_explicit_profile_is_rejected_on_non_linux_before_listening() {
	let outcome = start_observation_pool(Some(Path::new("never-opened-profile")), true).await;
	let Err(error) = outcome else {
		panic!("non-Linux startup must refuse the opt-in")
	};
	assert!(error.to_string().contains("requires Linux"));
	assert!(!file_observation_pool_requested());
}
