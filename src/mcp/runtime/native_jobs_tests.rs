// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Native frame, shared image and complete profile boundary tests.
use super::*;

fn bound() -> Value {
	json!({"job_dir":"/state/jobs/id","job_id":"id","unit":"unit.service","request_digest":"a".repeat(64),
            "stdout_offset":u64::MAX,"stderr_offset":17,"limit":65536,"wait_seconds":0})
}

#[test]
fn observation_wire_preserves_large_offsets_and_exact_extents() {
	let request = bound();
	let wire = observation_payload(&request, false).unwrap();
	assert_eq!(&wire[..8], b"HIAJOBQ1");
	assert_eq!(&wire[16..24], &u64::MAX.to_le_bytes());
	let lengths: Vec<usize> = (0..4)
		.map(|index| {
			u64::from_le_bytes(wire[40 + index * 8..48 + index * 8].try_into().unwrap()) as usize
		})
		.collect();
	assert_eq!(wire.len(), 80 + lengths.iter().sum::<usize>());
	assert_eq!(&wire[80..80 + lengths[0]], b"/state/jobs/id");
}

#[test]
fn native_status_requires_complete_snapshot_without_remote_wait() {
	let mut request = bound();
	let flags = [
		"hia_status_snapshot",
		"hia_status_terminal_facts",
		"hia_status_terminal_witness",
		"hia_status_native_receipt",
		"hia_status_lifecycle_facts",
		"hia_status_lifecycle_owner",
	];
	assert!(observation_payload(&request, true).is_err());
	for flag in flags {
		request[flag] = json!(true);
	}
	let wire = observation_payload(&request, true).unwrap();
	assert_eq!(&wire[8..16], &1u64.to_le_bytes());
	assert_eq!(&wire[72..80], &63u64.to_le_bytes());
	for flag in flags {
		let mut missing = request.clone();
		missing[flag] = json!(false);
		assert!(observation_payload(&missing, true).is_err());
	}
	request["wait_seconds"] = json!(1);
	assert!(observation_payload(&request, true).is_err());
}

#[test]
fn native_pool_shares_image_and_preserves_control_budget() {
	let image: Arc<[u8]> = vec![0; 4_194_304].into();
	let mut header = [0; 96];
	header[8..16].copy_from_slice(&2u64.to_le_bytes());
	let mut input = NativeJobInput {
		header,
		image: image.clone(),
		payload: vec![0; 65_536 - 96 - 1],
	};
	assert!(input.validate_observation("x").is_ok());
	assert!(Arc::ptr_eq(&image, &input.image));
	input.payload.push(0);
	assert!(input.validate_observation("x").is_err());
	input.payload.clear();
	input.header[8..16].copy_from_slice(&1u64.to_le_bytes());
	assert!(input.validate_observation("x").is_err());
}

#[test]
fn native_binding_and_digest_fail_closed() {
	let mut request = bound();
	request["request_digest"] = Value::Null;
	assert!(observation_payload(&request, false).is_err());
	assert_eq!(raw_sha(&"af".repeat(32)).unwrap(), [175; 32]);
	assert!(raw_sha(&"AF".repeat(32)).is_err());
	assert!(raw_sha(&"a".repeat(63)).is_err());
}

fn configured_entries() -> Value {
	let mut roles = serde_json::Map::new();
	for (field, role) in [
		("entry", "hia-job-entry"),
		("submit", "hia-job-submit"),
		("observation", "hia-job-observation"),
		("cancel", "hia-job-cancel"),
		("launcher", "hia-job-launch"),
	] {
		roles.insert(
			field.into(),
			json!({"executable":format!("/installed/{role}"),"sha256":"a".repeat(64)}),
		);
	}
	Value::Object(roles)
}

#[test]
fn complete_native_profile_rejects_missing_unknown_or_misbound_roles() {
	let valid = configured_entries();
	let entries: NativeJobEntries = serde_json::from_value(valid.clone()).unwrap();
	entries.validate().unwrap();
	for role in ["entry", "submit", "observation", "cancel", "launcher"] {
		let mut missing = valid.clone();
		missing.as_object_mut().unwrap().remove(role);
		assert!(serde_json::from_value::<NativeJobEntries>(missing).is_err());
	}
	let mut extra = valid.clone();
	extra["arbitrary_program"] = valid["submit"].clone();
	assert!(serde_json::from_value::<NativeJobEntries>(extra).is_err());
	for path in [
		"relative/hia-job-entry",
		"/installed/../hia-job-entry",
		"/installed//hia-job-entry",
		"/installed/hia-job-submit",
	] {
		let mut invalid = valid.clone();
		invalid["entry"]["executable"] = json!(path);
		assert!(serde_json::from_value::<NativeJobEntries>(invalid)
			.unwrap()
			.validate()
			.is_err());
	}
	let mut invalid = valid;
	invalid["cancel"]["sha256"] = json!("A".repeat(64));
	assert!(serde_json::from_value::<NativeJobEntries>(invalid)
		.unwrap()
		.validate()
		.is_err());
}

#[test]
fn absent_native_profile_preserves_legacy_serialized_identity() {
	let mut value = json!({"ssh_target":"fixture","remote_state_dir":"/state"});
	let legacy: HostConfig = serde_json::from_value(value.clone()).unwrap();
	assert!(legacy.native_jobs.is_none());
	assert!(serde_json::to_value(legacy)
		.unwrap()
		.get("native_jobs")
		.is_none());
	value["native_jobs"] = configured_entries();
	let configured: HostConfig = serde_json::from_value(value).unwrap();
	configured.native_jobs.as_ref().unwrap().validate().unwrap();
	// Execution revocation must not remove observation of an existing identity.
	assert!(!configured.allow_execute);
	assert!(serde_json::to_value(configured)
		.unwrap()
		.get("native_jobs")
		.is_some());
}
