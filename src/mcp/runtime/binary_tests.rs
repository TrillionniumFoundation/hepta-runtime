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
