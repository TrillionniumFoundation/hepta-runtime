// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Full-schema validation and original-owner preservation during projected scans.
use super::*;

fn fixture() -> Value {
	json!({
		"id":"original", "host":"main", "ssh_target":"never-connect.invalid",
		"unit":"original-unit", "remote_job_dir":"/never-launch/original",
		"executable":"/usr/bin/true", "args":["alpha", "escaped\n中文\\\""],
		"cwd":"/never-launch", "env_keys":["EXAMPLE"], "created_unix_ms":1,
		"idempotency_key":"original-key", "request_fingerprint":42,
		"request_digest":"a".repeat(64), "launch_state":"pending",
		"launch_error":"uncertain\nkeep original identity", "execution_mode":"operator",
		"system_jobctl":false
	})
}

fn equivalent(bytes: &[u8]) -> bool {
	let owned = serde_json::from_slice::<JobRecord>(bytes);
	let generic_owned = serde_json::from_slice::<JobRecordData<String>>(bytes);
	let projected = serde_json::from_slice::<JobRecordData<BorrowedJobString<'_>>>(bytes);
	assert_eq!(
		owned.is_ok(),
		generic_owned.is_ok(),
		"owned parser disagreement"
	);
	assert_eq!(owned.is_ok(), projected.is_ok(), "parser disagreement");
	match (owned, generic_owned, projected) {
		(Ok(owned), Ok(generic_owned), Ok(projected)) => {
			// Restore the concrete decoder without changing the durable bytes,
			// including field order, defaults and every private payload field.
			assert_eq!(
				serde_json::to_vec(&owned).unwrap(),
				serde_json::to_vec(&generic_owned).unwrap()
			);
			assert_eq!(owned.id, projected.id);
			assert_eq!(owned.host, projected.host);
			assert_eq!(owned.idempotency_key, projected.idempotency_key);
			assert_eq!(owned.launch_state, projected.launch_state);
			assert_eq!(owned.created_unix_ms, projected.created_unix_ms);
			assert_eq!(owned.request_fingerprint, projected.request_fingerprint);
			assert_eq!(owned.args.len(), projected.args.len());
			assert_eq!(owned.env_keys.len(), projected.env_keys.len());
			assert_eq!(owned.cwd.is_some(), projected.cwd.is_some());
			assert_eq!(
				owned.request_digest.is_some(),
				projected.request_digest.is_some()
			);
			assert_eq!(
				owned.launch_error.is_some(),
				projected.launch_error.is_some()
			);
			assert_eq!(owned, projected.into_owned());
			true
		}
		(Err(owned), Err(generic_owned), Err(projected)) => {
			assert_eq!(owned.classify(), generic_owned.classify());
			assert_eq!(owned.classify(), projected.classify());
			false
		}
		_ => unreachable!("parser success parity checked above"),
	}
}

#[test]
fn projection_preserves_defaults_optional_fields_escapes_and_unknown_fields() {
	assert!(equivalent(&serde_json::to_vec(&fixture()).unwrap()));
	let mut value = fixture();
	for field in [
		"execution_mode",
		"system_jobctl",
		"launch_state",
		"request_digest",
		"launch_error",
	] {
		value.as_object_mut().unwrap().remove(field);
	}
	value["cwd"] = Value::Null;
	value["idempotency_key"] = Value::Null;
	value["future_metadata"] = json!({"nested":[true, null, {"unknown":"accepted"}]});
	assert!(equivalent(&serde_json::to_vec(&value).unwrap()));
	let text = serde_json::to_string(&fixture()).unwrap();
	assert!(equivalent(text.replace("alpha", "\\u0061lpha").as_bytes()));
	assert!(equivalent(
		text.replace("alpha", "\\uD83D\\uDE00").as_bytes()
	));
	assert!(!equivalent(text.replace("alpha", "\\uD83D").as_bytes()));
}

#[test]
fn nested_payloads_borrow_plain_text_and_own_decoded_escapes() {
	let mut value = fixture();
	value["args"] = json!(["alpha", "中文", "escaped\n\\\""]);
	value["env_keys"] = json!(["EXAMPLE", "ESCAPED\tKEY"]);
	let text = serde_json::to_string(&value).unwrap();
	let projected = serde_json::from_str::<JobRecordData<BorrowedJobString<'_>>>(&text).unwrap();
	assert!(projected.remote_job_dir.is_borrowed());
	assert!(projected.cwd.as_ref().unwrap().is_borrowed());
	assert!(projected.args[0].is_borrowed());
	assert!(projected.args[1].is_borrowed());
	assert!(!projected.args[2].is_borrowed());
	assert!(projected.env_keys[0].is_borrowed());
	assert!(!projected.env_keys[1].is_borrowed());
	assert_eq!(
		projected.into_owned(),
		serde_json::from_str::<JobRecord>(&text).unwrap()
	);

	let escaped = text
		.replace("alpha", "\\u0061lpha")
		.replace("中文", "\\u4e2d\\u6587");
	let projected = serde_json::from_str::<JobRecordData<BorrowedJobString<'_>>>(&escaped).unwrap();
	assert!(!projected.args[0].is_borrowed());
	assert!(!projected.args[1].is_borrowed());
	assert!(projected.remote_job_dir.is_borrowed());
	assert_eq!(
		projected.into_owned(),
		serde_json::from_str::<JobRecord>(&text).unwrap()
	);
}

#[test]
fn every_projected_payload_rejects_wrong_json_types_and_duplicate_fields() {
	let base = fixture();
	for field in [
		"ssh_target",
		"unit",
		"remote_job_dir",
		"executable",
		"cwd",
		"request_digest",
		"launch_error",
	] {
		for invalid in [json!(false), json!(17), json!([]), json!({})] {
			let mut value = base.clone();
			value[field] = invalid;
			assert!(!equivalent(&serde_json::to_vec(&value).unwrap()), "{field}");
		}
	}
	for field in ["args", "env_keys"] {
		for invalid in [
			Value::Null,
			json!(false),
			json!(17),
			json!("text"),
			json!({}),
			json!(["valid", null]),
			json!([[]]),
		] {
			let mut value = base.clone();
			value[field] = invalid;
			assert!(!equivalent(&serde_json::to_vec(&value).unwrap()), "{field}");
		}
	}
	let body = serde_json::to_string(&base).unwrap();
	for (field, value) in base.as_object().unwrap() {
		let duplicate = format!(
			"{{{}:{},{}",
			serde_json::to_string(field).unwrap(),
			value,
			&body[1..]
		);
		assert!(!equivalent(duplicate.as_bytes()), "duplicate {field}");
	}
}

#[test]
fn projected_schema_preserves_required_fields_enum_validation_and_integer_bounds() {
	for field in [
		"id",
		"host",
		"ssh_target",
		"unit",
		"remote_job_dir",
		"executable",
		"args",
		"env_keys",
		"created_unix_ms",
		"request_fingerprint",
	] {
		let mut value = fixture();
		value.as_object_mut().unwrap().remove(field);
		assert!(
			!equivalent(&serde_json::to_vec(&value).unwrap()),
			"missing {field}"
		);
	}
	for (field, invalid) in [
		("execution_mode", json!("unrecognized")),
		("system_jobctl", json!("false")),
		("created_unix_ms", json!(-1)),
		("request_fingerprint", json!(1.5)),
	] {
		let mut value = fixture();
		value[field] = invalid;
		assert!(
			!equivalent(&serde_json::to_vec(&value).unwrap()),
			"invalid {field}"
		);
	}
	let text = serde_json::to_string(&fixture()).unwrap();
	for invalid in ["18446744073709551616", "1e100", "-1"] {
		assert!(!equivalent(
			text.replace(
				"\"request_fingerprint\":42",
				&format!("\"request_fingerprint\":{invalid}")
			)
			.as_bytes()
		));
	}
}

#[test]
fn projected_scan_returns_full_original_and_validates_unrelated_receipts() {
	let root = tempfile::tempdir().unwrap();
	let original: JobRecord = serde_json::from_value(fixture()).unwrap();
	save_record_at(&root.path().join("original.json"), &original).unwrap();
	let mut unrelated = original.clone();
	unrelated.id = "unrelated".into();
	unrelated.idempotency_key = Some("unrelated-key".into());
	unrelated.args = vec!["x".repeat(128 * 1024)];
	save_record_at(&root.path().join("unrelated.json"), &unrelated).unwrap();
	for fingerprint in [false, true] {
		let (found, digest) =
			scan_registry_records(root.path(), "main", "original-key", fingerprint).unwrap();
		assert_eq!(found.as_ref(), Some(&original));
		assert_eq!(digest.is_some(), fingerprint);
		assert!(
			scan_registry_records(root.path(), "main", "absent-key", fingerprint)
				.unwrap()
				.0
				.is_none()
		);
	}
	let mut corrupt = serde_json::to_value(unrelated).unwrap();
	corrupt["args"] = json!(["first valid", 3]);
	std::fs::write(
		root.path().join("unrelated.json"),
		serde_json::to_vec(&corrupt).unwrap(),
	)
	.unwrap();
	for key in ["original-key", "absent-key"] {
		assert!(scan_registry_records(root.path(), "main", key, false).is_err());
	}
}

#[test]
fn projected_scan_keeps_duplicate_owner_refusal_and_full_cohort_binding() {
	let root = tempfile::tempdir().unwrap();
	let mut original: JobRecord = serde_json::from_value(fixture()).unwrap();
	original.launch_state = "launched".into();
	save_record_at(&root.path().join("original.json"), &original).unwrap();
	let mut cohort = [RegistryColdTarget {
		identity: ("main".into(), "original-key".into()),
		seen: false,
		candidate: None,
	}];
	assert!(
		scan_registry_records_observed(root.path(), "main", "absent-key", false, &mut cohort)
			.unwrap()
			.0
			.is_none()
	);
	assert!(cohort[0].seen);
	assert_eq!(
		cohort[0].candidate,
		Some((
			original.id.clone(),
			job_record_binding_digest(&original).unwrap()
		))
	);
	let mut duplicate = original.clone();
	duplicate.id = "duplicate".into();
	save_record_at(&root.path().join("duplicate.json"), &duplicate).unwrap();
	assert!(scan_registry_records(root.path(), "main", "original-key", false).is_err());
	cohort[0].seen = false;
	cohort[0].candidate = None;
	assert!(
		scan_registry_records_observed(root.path(), "main", "absent-key", false, &mut cohort)
			.unwrap()
			.0
			.is_none()
	);
	assert!(cohort[0].seen);
	assert!(cohort[0].candidate.is_none());
}

#[test]
fn projected_reader_still_rejects_filename_identity_mismatch_and_clears_failed_buffer() {
	let root = tempfile::tempdir().unwrap();
	let path = root.path().join("different-id.json");
	std::fs::write(&path, serde_json::to_vec(&fixture()).unwrap()).unwrap();
	assert!(scan_registry_records(root.path(), "main", "absent-key", false).is_err());
	let mut bytes = vec![b'x'; 16];
	assert!(
		with_record_read_buffer(&mut bytes, |bytes| read_borrowed_record_at_into(
			&path,
			"different-id",
			bytes
		)
		.map(|_| ()))
		.is_err()
	);
	assert!(bytes.is_empty());
}

#[cfg(unix)]
#[test]
fn concrete_and_borrowed_readers_share_descriptor_guards() {
	use std::os::unix::fs::symlink;

	let root = tempfile::tempdir().unwrap();
	let path = root.path().join("original.json");
	let original: JobRecord = serde_json::from_value(fixture()).unwrap();
	save_record_at(&path, &original).unwrap();
	let mut bytes = Vec::new();
	assert_eq!(
		read_record_at_with_buffer(&path, "original", &mut bytes).unwrap(),
		original
	);
	assert!(bytes.is_empty());
	assert_eq!(
		with_record_read_buffer(&mut bytes, |bytes| {
			read_borrowed_record_at_into(&path, "original", bytes).map(JobRecordData::into_owned)
		})
		.unwrap(),
		original
	);
	assert!(bytes.is_empty());

	let reject_both = |path: &Path| {
		let mut bytes = vec![b'x'; 16];
		assert!(read_record_at_with_buffer(path, "original", &mut bytes).is_err());
		assert!(bytes.is_empty());
		bytes.extend_from_slice(b"prior receipt");
		assert!(with_record_read_buffer(&mut bytes, |bytes| {
			read_borrowed_record_at_into(path, "original", bytes).map(|_| ())
		})
		.is_err());
		assert!(bytes.is_empty());
	};
	let link = root.path().join("symlink.json");
	symlink(&path, &link).unwrap();
	reject_both(&link);
	let hardlink = root.path().join("hardlink.json");
	std::fs::hard_link(&path, &hardlink).unwrap();
	reject_both(&path);
	std::fs::remove_file(hardlink).unwrap();
	let oversized = OpenOptions::new().write(true).open(&path).unwrap();
	oversized.set_len(MAX_JOB_RECORD_BYTES + 1).unwrap();
	drop(oversized);
	reject_both(&path);
}

#[test]
#[ignore = "diagnostic only: in-memory concrete/generic owned serde ABBA; no filesystem or remote IO"]
fn concrete_and_generic_owned_decode_diagnostic() {
	use std::time::Instant;

	const CALLS: usize = 4096;
	let mut value = fixture();
	value["args"] = json!(["x".repeat(32768)]);
	let bytes = serde_json::to_vec(&value).unwrap();
	assert!(equivalent(&bytes));
	macro_rules! layout {
		($record:ty) => {
			json!({
				"size": std::mem::size_of::<$record>(),
				"alignment": std::mem::align_of::<$record>(),
				"offsets": {
					"execution_mode": std::mem::offset_of!($record, execution_mode),
					"system_jobctl": std::mem::offset_of!($record, system_jobctl),
					"id": std::mem::offset_of!($record, id),
					"host": std::mem::offset_of!($record, host),
					"ssh_target": std::mem::offset_of!($record, ssh_target),
					"unit": std::mem::offset_of!($record, unit),
					"remote_job_dir": std::mem::offset_of!($record, remote_job_dir),
					"executable": std::mem::offset_of!($record, executable),
					"args": std::mem::offset_of!($record, args),
					"cwd": std::mem::offset_of!($record, cwd),
					"env_keys": std::mem::offset_of!($record, env_keys),
					"created_unix_ms": std::mem::offset_of!($record, created_unix_ms),
					"idempotency_key": std::mem::offset_of!($record, idempotency_key),
					"request_fingerprint": std::mem::offset_of!($record, request_fingerprint),
					"request_digest": std::mem::offset_of!($record, request_digest),
					"launch_state": std::mem::offset_of!($record, launch_state),
					"launch_error": std::mem::offset_of!($record, launch_error)
				}
			})
		};
	}
	fn decode<Record: serde::de::DeserializeOwned>(bytes: &[u8]) {
		drop(std::hint::black_box(
			serde_json::from_slice::<Record>(std::hint::black_box(bytes)).unwrap(),
		));
	}
	println!(
		"OWNED_RECORD_DECODE_LAYOUT {}",
		json!({"concrete":layout!(JobRecord), "generic":layout!(JobRecordData<String>)})
	);
	for _ in 0..16 {
		decode::<JobRecord>(&bytes);
		decode::<JobRecordData<String>>(&bytes);
	}
	for (index, arm) in "ABBAABBA".chars().enumerate() {
		let started = Instant::now();
		for _ in 0..CALLS {
			match arm {
				'A' => decode::<JobRecord>(&bytes),
				'B' => decode::<JobRecordData<String>>(&bytes),
				_ => unreachable!(),
			}
		}
		let seconds = started.elapsed().as_secs_f64();
		println!(
			"OWNED_RECORD_DECODE_SAMPLE {}",
			json!({"sample":index+1, "block":index/4+1, "arm":arm.to_string(),
				"calls":CALLS, "receipt_bytes":bytes.len(), "seconds":seconds,
				"calls_per_second":CALLS as f64/seconds,
				"scope":"one-process warmed in-memory parse/drop; A concrete, B generic owned; not release inventory throughput"})
		);
		std::io::stdout().flush().unwrap();
	}
}
