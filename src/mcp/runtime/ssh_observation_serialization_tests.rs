// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Exact legacy request bytes, numeric domains and payload-budget boundaries.
use super::*;
use serde_json::{json, Value};

// Original R24/R25/R26 implementation, kept as a separate byte/error oracle.
fn legacy_prepare_observation(value: JobObservation<'_>) -> Result<(String, Vec<u8>, Duration, bool)> {
	use serde_json::json;
	let fields: &[&str] = match &value {
		JobObservation::PythonStatus {
			job_id,
			job_dir,
			unit,
			request_digest,
			..
		} => &[job_id, job_dir, unit, request_digest],
		JobObservation::PythonRead {
			job_id,
			job_dir,
			unit,
			request_digest,
			..
		} => &[job_id, job_dir, unit, request_digest],
		JobObservation::SystemStatus { job_id } | JobObservation::SystemRead { job_id, .. } => {
			&[job_id]
		}
	};
	// Reject before json! clones or expands an oversized original string.
	if fields
		.iter()
		.try_fold(0usize, |total, field| total.checked_add(field.len()))
		.is_none_or(|bytes| bytes > MAX_OBSERVATION_BYTES)
	{
		bail!("observation_pool_payload_unsupported: original observation fields exceed64KiB; no fallback");
	}
	let (script, input, timeout, system) = match value {
		JobObservation::PythonStatus {
			job_id,
			job_dir,
			unit,
			request_digest,
			wait_seconds,
		} => (
			Some(ObservationScript::Status),
			json!({"job_id":job_id,"job_dir":job_dir,"request_digest":request_digest,"unit":unit,"wait_seconds":wait_seconds.min(30)}),
			Duration::from_secs(wait_seconds.min(30) + 10),
			false,
		),
		JobObservation::PythonRead {
			job_id,
			job_dir,
			unit,
			request_digest,
			stdout_offset,
			stderr_offset,
			limit,
		} => (
			Some(ObservationScript::Read),
			json!({"job_id":job_id,"job_dir":job_dir,"request_digest":request_digest,"unit":unit,"stdout_offset":stdout_offset,"stderr_offset":stderr_offset,"limit":limit}),
			Duration::from_secs(15),
			false,
		),
		JobObservation::SystemStatus { job_id } => (
			None,
			json!({"op":"status","job_id":job_id}),
			Duration::from_secs(20),
			true,
		),
		JobObservation::SystemRead {
			job_id,
			stdout_offset,
			stderr_offset,
			limit,
		} => (
			None,
			json!({"op":"read","job_id":job_id,"stdout_offset":stdout_offset,"stderr_offset":stderr_offset,"limit":limit}),
			Duration::from_secs(20),
			true,
		),
	};
	let command = match script {
		Some(script) => job_observation_command(script)?.to_owned(),
		None => "sudo -n /usr/local/libexec/hepta-runtime-jobctl".to_owned(),
	};
	let mut bytes = serde_json::to_vec(&input)?;
	if system {
		bytes.push(b'\n');
	}
	validate_observation_bytes(&command, &bytes)?;
	Ok((command, bytes, timeout, system))
}

const ESCAPED: &str = "中文λ🦀e\u{301}\u{2028}\u{2029}\"\\\0\n\r\t\u{8}\u{c}";
const RAW_ERROR: &str =
	"observation_pool_payload_unsupported: original observation fields exceed64KiB; no fallback";
const ENCODED_ERROR: &str =
	"observation_pool_payload_unsupported: queued command and stdin exceed64KiB; no fallback";

fn assert_reference_equivalence<'a>(
	make: impl Fn() -> JobObservation<'a>,
) -> Result<(String, Vec<u8>, Duration, bool)> {
	let expected = legacy_prepare_observation(make());
	let actual = prepare_observation(make());
	match (&expected, &actual) {
		(Ok(expected), Ok(actual)) => assert_eq!(actual, expected),
		(Err(expected), Err(actual)) => {
			assert_eq!(format!("{actual:#}"), format!("{expected:#}"));
		}
		_ => panic!("legacy outcome {expected:?} differs from borrowed outcome {actual:?}"),
	}
	actual
}

#[test]
fn locked_json_map_order_is_lexicographic() {
	let mut map = serde_json::Map::new();
	for (key, value) in [("z", 1), ("a", 2), ("m", 3)] {
		map.insert(key.to_owned(), json!(value));
	}
	let bytes = serde_json::to_vec(&Value::Object(map)).unwrap();
	assert_eq!(
		bytes.as_slice(),
		br#"{"a":2,"m":3,"z":1}"#,
		"the borrowed request field order must be reviewed if serde_json Map order changes"
	);
}

#[test]
fn borrowed_python_status_matches_legacy_bytes_and_wait_clamp() {
	for (job_id, job_dir, unit, request_digest) in [
		("", "", "", ""),
		("original-123", "/private/jobs/original-123", "fixed-unit", "digest-123"),
		(ESCAPED, ESCAPED, ESCAPED, ESCAPED),
	] {
		for wait_seconds in [0, 1, 30, 31, u64::MAX] {
			let (_, input, timeout, system) =
				assert_reference_equivalence(|| JobObservation::PythonStatus {
					job_id,
					job_dir,
					unit,
					request_digest,
					wait_seconds,
				})
				.unwrap();
			assert_eq!(timeout, Duration::from_secs(wait_seconds.min(30) + 10));
			assert!(!system);
			assert_ne!(input.last(), Some(&b'\n'));
		}
	}
}

#[test]
fn borrowed_python_read_matches_legacy_bytes_for_the_full_unsigned_domain() {
	for (job_id, job_dir, unit, request_digest) in [
		("", "", "", ""),
		("original-123", "/private/jobs/original-123", "fixed-unit", "digest-123"),
		(ESCAPED, ESCAPED, ESCAPED, ESCAPED),
	] {
		for (stdout_offset, stderr_offset, limit) in [
			(0, 0, 0),
			(17, 29, 16_384),
			(u64::MAX, u64::MAX - 1, u64::MAX),
		] {
			let (_, input, timeout, system) =
				assert_reference_equivalence(|| JobObservation::PythonRead {
					job_id,
					job_dir,
					unit,
					request_digest,
					stdout_offset,
					stderr_offset,
					limit,
				})
				.unwrap();
			assert_eq!(timeout, Duration::from_secs(15));
			assert!(!system);
			assert_ne!(input.last(), Some(&b'\n'));
		}
	}
}

#[test]
fn borrowed_system_requests_match_legacy_bytes_and_one_trailing_newline() {
	for job_id in ["", "original-123", ESCAPED] {
		let (command, input, timeout, system) =
			assert_reference_equivalence(|| JobObservation::SystemStatus { job_id }).unwrap();
		assert_eq!(command, "sudo -n /usr/local/libexec/hepta-runtime-jobctl");
		assert_eq!(timeout, Duration::from_secs(20));
		assert!(system);
		assert_eq!(input.last(), Some(&b'\n'));
		assert_eq!(input.iter().filter(|byte| **byte == b'\n').count(), 1);
		for (stdout_offset, stderr_offset, limit) in [
			(0, 0, 0),
			(17, 29, 16_384),
			(u64::MAX, u64::MAX - 1, u64::MAX),
		] {
			let (command, input, timeout, system) =
				assert_reference_equivalence(|| JobObservation::SystemRead {
					job_id,
					stdout_offset,
					stderr_offset,
					limit,
				})
				.unwrap();
			assert_eq!(command, "sudo -n /usr/local/libexec/hepta-runtime-jobctl");
			assert_eq!(timeout, Duration::from_secs(20));
			assert!(system);
			assert_eq!(input.last(), Some(&b'\n'));
			assert_eq!(input.iter().filter(|byte| **byte == b'\n').count(), 1);
		}
	}
}

#[test]
fn missing_and_null_public_read_options_still_produce_explicit_default_fields() {
	use super::super::jobs::ProcessReadParams;
	for input in [
		json!({"host":"never-contacted","job_id":"original-123"}),
		json!({"host":"never-contacted","job_id":"original-123",
			"stdout_offset":null,"stderr_offset":null,"limit":null}),
	] {
		let params: ProcessReadParams = serde_json::from_value(input).unwrap();
		assert!(params.stdout_offset.is_none());
		assert!(params.stderr_offset.is_none());
		assert!(params.limit.is_none());
		// The public caller resolves these options before preparing a request.
		// Its current 16 KiB cap and required stored digest are left unchanged.
		let (_, python, _, _) = assert_reference_equivalence(|| JobObservation::PythonRead {
			job_id: &params.job_id,
			job_dir: "/private/jobs/original-123",
			unit: "fixed-unit",
			request_digest: "digest-123",
			stdout_offset: params.stdout_offset.unwrap_or(0),
			stderr_offset: params.stderr_offset.unwrap_or(0),
			limit: params.limit.unwrap_or(65_536).min(16_384),
		})
		.unwrap();
		assert_eq!(
			python.as_slice(),
			br#"{"job_dir":"/private/jobs/original-123","job_id":"original-123","limit":16384,"request_digest":"digest-123","stderr_offset":0,"stdout_offset":0,"unit":"fixed-unit"}"#
		);
		let (_, system, _, _) = assert_reference_equivalence(|| JobObservation::SystemRead {
			job_id: &params.job_id,
			stdout_offset: params.stdout_offset.unwrap_or(0),
			stderr_offset: params.stderr_offset.unwrap_or(0),
			limit: params.limit.unwrap_or(16_384),
		})
		.unwrap();
		assert_eq!(
			system,
			[
				br#"{"job_id":"original-123","limit":16384,"op":"read","stderr_offset":0,"stdout_offset":0}"#.as_slice(),
				b"\n",
			]
			.concat()
		);
	}
}

#[test]
fn borrowed_requests_keep_raw_and_encoded_rejection_precedence() {
	let raw = "x".repeat(MAX_OBSERVATION_BYTES + 1);
	let raw_utf8 = "🦀".repeat(MAX_OBSERVATION_BYTES / 4 + 1);
	let half = "x".repeat(MAX_OBSERVATION_BYTES / 2 + 1);
	for (job_id, job_dir, unit, request_digest) in [
		(raw.as_str(), "", "", ""),
		("", raw.as_str(), "", ""),
		("", "", raw.as_str(), ""),
		("", "", "", raw.as_str()),
		("", raw_utf8.as_str(), "", ""),
		(half.as_str(), half.as_str(), "", ""),
	] {
		let error = assert_reference_equivalence(|| JobObservation::PythonRead {
			job_id,
			job_dir,
			unit,
			request_digest,
			stdout_offset: 0,
			stderr_offset: 0,
			limit: 1,
		})
		.unwrap_err();
		assert_eq!(error.to_string(), RAW_ERROR);
	}
	let error =
		assert_reference_equivalence(|| JobObservation::SystemStatus { job_id: &raw }).unwrap_err();
	assert_eq!(error.to_string(), RAW_ERROR);

	// Exact raw size passes the first check; metadata/code still exceed the
	// combined budget. Control-character expansion must fail at that same check.
	for job_dir in [
		"x".repeat(MAX_OBSERVATION_BYTES),
		"\0".repeat(MAX_OBSERVATION_BYTES / 6 + 1),
	] {
		let error = assert_reference_equivalence(|| JobObservation::PythonRead {
			job_id: "",
			job_dir: &job_dir,
			unit: "",
			request_digest: "",
			stdout_offset: 0,
			stderr_offset: 0,
			limit: 1,
		})
		.unwrap_err();
		assert_eq!(error.to_string(), ENCODED_ERROR);
		let error = assert_reference_equivalence(|| JobObservation::SystemStatus {
			job_id: &job_dir,
		})
		.unwrap_err();
		assert_eq!(error.to_string(), ENCODED_ERROR);
	}
}

fn boundary_request(kind: u8, job_id: &str) -> JobObservation<'_> {
	match kind {
		0 => JobObservation::PythonStatus {
			job_id,
			job_dir: "/private/jobs",
			unit: "fixed-unit",
			request_digest: "digest-123",
			wait_seconds: u64::MAX,
		},
		1 => JobObservation::PythonRead {
			job_id,
			job_dir: "/private/jobs",
			unit: "fixed-unit",
			request_digest: "digest-123",
			stdout_offset: u64::MAX,
			stderr_offset: u64::MAX - 1,
			limit: u64::MAX,
		},
		2 => JobObservation::SystemStatus { job_id },
		3 => JobObservation::SystemRead {
			job_id,
			stdout_offset: u64::MAX,
			stderr_offset: u64::MAX - 1,
			limit: u64::MAX,
		},
		_ => panic!("unexpected boundary fixture"),
	}
}

#[test]
fn borrowed_requests_keep_the_exact_combined_boundary_for_all_variants() {
	for kind in 0..4 {
		let (command, input, _, _) =
			assert_reference_equivalence(|| boundary_request(kind, "")).unwrap();
		let job_id = "x".repeat(MAX_OBSERVATION_BYTES - command.len() - input.len());
		let (command, input, _, system) =
			assert_reference_equivalence(|| boundary_request(kind, &job_id)).unwrap();
		assert_eq!(command.len() + input.len(), MAX_OBSERVATION_BYTES);
		assert_eq!(input.last() == Some(&b'\n'), system);
		let one_more = format!("{job_id}x");
		let error =
			assert_reference_equivalence(|| boundary_request(kind, &one_more)).unwrap_err();
		assert_eq!(error.to_string(), ENCODED_ERROR);
	}
}
