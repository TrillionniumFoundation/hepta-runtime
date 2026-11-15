// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Schema tests: no caller-selected executable, image root or authority overrides.
use super::*;

#[test]
fn checkpoint_schema_rejects_hidden_authority() {
	for key in [
		"configured_binary",
		"configured_sha256",
		"sudo",
		"image_path",
	] {
		let mut value = json!({"host":"x230","action":"inspect","pid":123});
		value[key] = json!("override");
		assert!(serde_json::from_value::<CheckpointParams>(value).is_err());
	}
}
#[test]
fn checkpoint_actions_and_identity_are_typed() {
	assert!(serde_json::from_value::<CheckpointParams>(
		json!({"host":"x230","action":"execute","pid":123})
	)
	.is_err());
	assert!(serde_json::from_value::<CheckpointIdentity>(
		json!({"pid":123,"uid":1000,"boot_id":"boot","start_ticks":10,"root":true})
	)
	.is_err());
	assert!(serde_json::from_value::<CheckpointParams>(json!({"host":"x230","action":"dump","pid":123,"checkpoint_id":"fixture-001","acknowledge_process_stop":true,"expected_identity":{"pid":123,"uid":1000,"boot_id":"boot","start_ticks":10}})).is_ok());
}

#[test]
fn restore_and_resume_require_separate_acknowledgements() {
	let mut p: CheckpointParams =
		serde_json::from_value(json!({"host":"x230","action":"resume","checkpoint_id":"test-001"}))
			.unwrap();
	assert!(validate_request(&p).is_err());
	p.acknowledge_resume = true;
	assert!(validate_request(&p).is_err());
	p.expected_identity = Some(CheckpointIdentity {
		pid: 22,
		uid: 1000,
		boot_id: "boot".into(),
		start_ticks: 1,
	});
	assert!(validate_request(&p).is_ok());
	p.action = CheckpointAction::Restore;
	assert!(validate_request(&p).is_err());
	p.acknowledge_process_stop = true;
	assert!(validate_request(&p).is_ok());
}
#[test]
fn status_is_not_a_process_stop_request() {
	let p: CheckpointParams =
		serde_json::from_value(json!({"host":"x230","action":"status","checkpoint_id":"test-001"}))
			.unwrap();
	assert!(validate_request(&p).is_ok());
}
