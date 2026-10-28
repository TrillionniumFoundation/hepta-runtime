// Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
use super::*;
use serde_json::{json, Value};

#[test]
fn typed_system_observations_keep_the_exact_old_closed_protocol() {
	let (command, input, timeout, system) = prepare_observation(JobObservation::SystemStatus {
		job_id: "original-123",
	})
	.unwrap();
	assert_eq!(command, "sudo -n /usr/local/libexec/hepta-runtime-jobctl");
	assert_eq!(
		input,
		[
			serde_json::to_vec(&json!({"op":"status","job_id":"original-123"})).unwrap(),
			vec![b'\n']
		]
		.concat()
	);
	assert_eq!(timeout, Duration::from_secs(20));
	assert!(system);
	let (_, input, _, _) = prepare_observation(JobObservation::SystemRead {
		job_id: "original-123",
		stdout_offset: 17,
		stderr_offset: 29,
		limit: u64::MAX,
	})
	.unwrap();
	assert_eq!(input.last(), Some(&b'\n'));
	assert_eq!(
		serde_json::from_slice::<Value>(&input).unwrap(),
		json!({"op":"read","job_id":"original-123","stdout_offset":17,"stderr_offset":29,"limit":u64::MAX})
	);
}

#[test]
fn typed_python_observations_preserve_scripts_payload_and_deadlines() {
	for wait in [0, 1, 30, u64::MAX] {
		let (command, input, timeout, system) = prepare_observation(JobObservation::PythonStatus {
			job_id: "original-123",
			job_dir: "/private/jobs/original-123",
			unit: "fixed-unit",
			request_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			wait_seconds: wait,
		})
		.unwrap();
		assert_eq!(
			command,
			python_json_command(
				"python3",
				&super::super::jobs::observation_script(ObservationScript::Status).unwrap()
			)
			.unwrap()
		);
		assert_eq!(
			serde_json::from_slice::<Value>(&input).unwrap(),
			json!({"job_id":"original-123","job_dir":"/private/jobs/original-123","request_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","unit":"fixed-unit","wait_seconds":wait.min(30)})
		);
		assert_eq!(timeout, Duration::from_secs(wait.min(30) + 10));
		assert!(!system);
	}
	let (command, input, timeout, system) = prepare_observation(JobObservation::PythonRead {
		unit: "fixed-unit",
		request_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		job_id: "original-123",
		job_dir: "/private/jobs/original-123",
		stdout_offset: 17,
		stderr_offset: 29,
		limit: 16384,
	})
	.unwrap();
	assert_eq!(
		command,
		python_json_command(
			"python3",
			&super::super::jobs::observation_script(ObservationScript::Read).unwrap()
		)
		.unwrap()
	);
	assert_eq!(
		serde_json::from_slice::<Value>(&input).unwrap(),
		json!({"job_id":"original-123","job_dir":"/private/jobs/original-123","request_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","unit":"fixed-unit","stdout_offset":17,"stderr_offset":29,"limit":16384})
	);
	assert_eq!(timeout, Duration::from_secs(15));
	assert!(!system);
}

#[test]
fn observation_identity_data_never_becomes_remote_code() {
	let injected = "job'; touch SHOULD_NEVER_BE_COMMAND; #";
	let (command, input, _, _) = prepare_observation(JobObservation::PythonRead {
		unit: "fixed-unit",
		request_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		job_id: injected,
		job_dir: injected,
		stdout_offset: 0,
		stderr_offset: 0,
		limit: 1,
	})
	.unwrap();
	assert!(!command.contains("SHOULD_NEVER_BE_COMMAND"));
	assert_eq!(
		serde_json::from_slice::<Value>(&input).unwrap()["job_id"],
		injected
	);
}

#[test]
fn opt_in_observation_bound_checks_raw_encoded_and_script_bytes_before_dispatch() {
	let raw = "x".repeat(MAX_OBSERVATION_BYTES + 1);
	let escaped = "\n".repeat(MAX_OBSERVATION_BYTES / 2);
	let script_budget = "x".repeat(MAX_OBSERVATION_BYTES - 100);
	for job_dir in [&raw, &escaped, &script_budget] {
		let error = prepare_observation(JobObservation::PythonRead {
			unit: "fixed-unit",
			request_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			job_id: "original-123",
			job_dir,
			stdout_offset: 0,
			stderr_offset: 0,
			limit: 1,
		})
		.unwrap_err();
		assert!(
			error
				.to_string()
				.contains("observation_pool_payload_unsupported"),
			"{error:#}"
		);
	}
	assert!(validate_observation_bytes(&"x".repeat(MAX_OBSERVATION_BYTES), &[]).is_ok());
	assert!(validate_observation_bytes(&"x".repeat(MAX_OBSERVATION_BYTES), &[0]).is_err());
}
