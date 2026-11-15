// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Independent original-encoder checks and an actual JobRecord allocation/CPU probe.

use super::*;
use crate::mcp::runtime::jobs::{read_record_at, save_record_at};
use serde_json::json;

fn fixture(size: usize, escaped: bool) -> JobRecord {
	let mut record: JobRecord = serde_json::from_value(json!({
		"execution_mode":"operator", "system_jobctl":false,
		"id":"persistence-probe-original", "host":"main",
		"ssh_target":"never-connect.invalid", "unit":"fixture-unit",
		"remote_job_dir":"/never-launch/persistence-probe-original",
		"executable":"/usr/bin/true", "args":[""], "cwd":null,
		"env_keys":["EXAMPLE"], "created_unix_ms":1793700000000u64,
		"idempotency_key":"fixture-only", "request_fingerprint":7,
		"request_digest":"a".repeat(64), "launch_state":"pending",
		"launch_error":"UTF8 中文 and punctuation"
	}))
	.unwrap();
	let overhead = serde_json::to_vec_pretty(&record).unwrap().len();
	assert!(size >= overhead);
	let spare = size - overhead;
	record.args[0] = if escaped {
		let mut payload = "\n\\\"\t".repeat(spare / 8);
		payload.push_str(&"x".repeat(spare % 8));
		payload
	} else {
		"x".repeat(spare)
	};
	assert_eq!(serde_json::to_vec_pretty(&record).unwrap().len(), size);
	record
}

#[test]
fn bounded_encoder_preserves_original_bytes_and_owned_recovery() {
	for size in [1024, 65536, 786432, MAX_JOB_RECORD_BYTES as usize] {
		for escaped in [false, true] {
			let record = fixture(size, escaped);
			let expected = serde_json::to_vec_pretty(&record).unwrap();
			let actual = encode_record(&record).unwrap();
			assert_eq!(actual, expected);
			assert!(actual.capacity() <= MAX_JOB_RECORD_BYTES as usize);
			let decoded: JobRecord = serde_json::from_slice(&actual).unwrap();
			assert_eq!(decoded, record);
		}
	}
}

#[test]
fn bounded_encoder_preserves_optional_fields_unicode_and_control_escapes() {
	let mut record = fixture(1024, false);
	for present in [false, true] {
		let special = "\0\u{1}\u{b}\r\n\t\"\\中文🙂";
		record.cwd = present.then(|| special.into());
		record.idempotency_key = present.then(|| special.into());
		record.request_digest = present.then(|| special.into());
		record.launch_error = present.then(|| special.into());
		record.args = if present {
			vec![String::new(), special.into(), "x".repeat(2048)]
		} else {
			Vec::new()
		};
		record.env_keys = record.args.clone();
		record.created_unix_ms = u128::MAX;
		record.request_fingerprint = u64::MAX;
		record.system_jobctl = present;
		assert_eq!(
			encode_record(&record).unwrap(),
			serde_json::to_vec_pretty(&record).unwrap()
		);
	}
}

#[test]
fn encoded_limit_refuses_plain_and_escaped_overflow_without_temporary_files() {
	for escaped in [false, true] {
		let root = tempfile::tempdir().unwrap();
		let path = root.path().join("persistence-probe-original.json");
		let record = fixture(MAX_JOB_RECORD_BYTES as usize + 1, escaped);
		let error = save_record_at(&path, &record).unwrap_err();
		assert!(error.to_string().contains("durable job record exceeds"));
		assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
	}
}

#[test]
fn oversized_outcome_preserves_the_prior_durable_receipt() {
	for escaped in [false, true] {
		let root = tempfile::tempdir().unwrap();
		let path = root.path().join("persistence-probe-original.json");
		let original = fixture(1024, false);
		save_record_at(&path, &original).unwrap();
		let before = std::fs::read(&path).unwrap();
		let mut replacement = fixture(MAX_JOB_RECORD_BYTES as usize + 1, escaped);
		replacement.launch_state = "unknown".into();
		let error = save_record_at(&path, &replacement).unwrap_err();
		assert!(error.to_string().contains("durable job record exceeds"));
		assert_eq!(std::fs::read(&path).unwrap(), before);
		assert_eq!(read_record_at(&path, &original.id).unwrap(), original);
		assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
	}
}

#[test]
fn write_buffer_accepts_exact_limit_and_never_partially_appends_overflow() {
	let limit = MAX_JOB_RECORD_BYTES as usize;
	let mut buffer = RecordBuffer::new(1).unwrap();
	buffer.write_all(&vec![b'a'; limit - 2]).unwrap();
	assert!(buffer.bytes.capacity() <= limit);
	assert!(buffer.write_all(b"xyz").is_err());
	assert_eq!(buffer.bytes.len(), limit - 2);
	assert!(buffer.limit_exceeded);
	buffer.write_all(b"bc").unwrap();
	buffer.flush().unwrap();
	assert_eq!(buffer.bytes.len(), limit);
	assert!(buffer.bytes.capacity() <= limit);
	assert_eq!(&buffer.bytes[limit - 2..], b"bc");
	assert!(buffer.write_all(b"z").is_err());
	assert_eq!(buffer.bytes.len(), limit);
}

#[test]
fn saturated_capacity_hint_does_not_replace_the_encoded_byte_limit() {
	let mut record = fixture(1024, false);
	record.args = vec!["\0".repeat(MAX_JOB_RECORD_BYTES as usize / 6)];
	assert!(capacity_hint(&record) < MAX_JOB_RECORD_BYTES as usize);
	assert!(encode_record(&record)
		.unwrap_err()
		.to_string()
		.contains("durable job record exceeds"));
	let buffer = RecordBuffer::new(usize::MAX).unwrap();
	assert!(buffer.bytes.capacity() <= MAX_JOB_RECORD_BYTES as usize);
}

#[cfg(target_os = "linux")]
fn cpu_seconds() -> f64 {
	let mut value: libc::timespec = unsafe { std::mem::zeroed() };
	assert_eq!(
		unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut value) },
		0
	);
	value.tv_sec as f64 + value.tv_nsec as f64 / 1_000_000_000.0
}

#[cfg(target_os = "linux")]
fn original_encoding(record: &JobRecord) -> Result<Vec<u8>> {
	let bytes = serde_json::to_vec_pretty(record)?;
	if bytes.len() as u64 > MAX_JOB_RECORD_BYTES {
		bail!("durable job record exceeds {} bytes", MAX_JOB_RECORD_BYTES);
	}
	Ok(bytes)
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "isolated actual JobRecord ABBA encoding and durable-save benchmark; no remote effects"]
fn bounded_receipt_encoding_and_durable_save_benchmark() {
	use std::fs::{File, OpenOptions};
	use std::hint::black_box;
	use std::os::unix::fs::OpenOptionsExt;
	use std::time::Instant;
	let root = tempfile::tempdir().unwrap();
	let mut rows = Vec::new();
	let mut buffers = Vec::new();
	let mut durable_rows = Vec::new();
	for size in [1024, 65536, 786432, MAX_JOB_RECORD_BYTES as usize - 32] {
		for escaped in [false, true] {
			let record = fixture(size, escaped);
			let expected = original_encoding(&record).unwrap();
			let encoded_sha256 = {
				use sha2::{Digest, Sha256};
				Sha256::digest(&expected)
					.iter()
					.map(|byte| format!("{byte:02x}"))
					.collect::<String>()
			};
			for bounded in [false, true] {
				let bytes = if bounded {
					encode_record(&record).unwrap()
				} else {
					original_encoding(&record).unwrap()
				};
				assert_eq!(bytes, expected);
				buffers.push(json!({
					"size":size,"escaped":escaped,"bounded":bounded,
					"length":bytes.len(),"final_vec_capacity":bytes.capacity(),
					"encoded_sha256":encoded_sha256
				}));
			}
			let iterations = match size {
				1024 => 512,
				65536 => 64,
				786432 => 8,
				_ => 3,
			};
			for cycle in 0..3 {
				for (position, bounded) in [false, true, true, false].into_iter().enumerate() {
					let before = cpu_seconds();
					let started = Instant::now();
					for _ in 0..iterations {
						let bytes = if bounded {
							encode_record(black_box(&record)).unwrap()
						} else {
							original_encoding(black_box(&record)).unwrap()
						};
						assert_eq!(bytes.len(), size);
						black_box(bytes);
					}
					let wall = started.elapsed().as_secs_f64();
					let cpu = cpu_seconds() - before;
					rows.push(json!({
						"size":size,"escaped":escaped,"bounded":bounded,
						"cycle":cycle,"position":position,"iterations":iterations,
						"wall_seconds":wall,"cpu_seconds":cpu,
						"cpu_seconds_per_call":cpu / iterations as f64
					}));
				}
			}
			// Both arms use the same original publication barriers and same directory.
			// The bounded arm calls the real production save, not a substitute writer.
			for cycle in 0..2 {
				for (position, bounded) in [false, true, true, false].into_iter().enumerate() {
					let path = root.path().join("persistence-probe-original.json");
					let before = cpu_seconds();
					let started = Instant::now();
					if bounded {
						save_record_at(&path, &record).unwrap();
					} else {
						let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
						let bytes = original_encoding(&record).unwrap();
						let mut file = OpenOptions::new()
							.create_new(true)
							.write(true)
							.mode(0o600)
							.open(&tmp)
							.unwrap();
						file.write_all(&bytes).unwrap();
						file.sync_all().unwrap();
						drop(file);
						std::fs::rename(&tmp, &path).unwrap();
						File::open(root.path()).unwrap().sync_all().unwrap();
					}
					let wall = started.elapsed().as_secs_f64();
					let cpu = cpu_seconds() - before;
					assert_eq!(std::fs::read(&path).unwrap(), expected);
					assert_eq!(read_record_at(&path, &record.id).unwrap(), record);
					durable_rows.push(json!({
						"size":size,"escaped":escaped,"bounded":bounded,
						"cycle":cycle,"position":position,
						"wall_seconds":wall,"cpu_seconds":cpu
					}));
				}
			}
		}
	}
	let result = json!({
		"schema":"hepta-bounded-receipt-encoding-v1",
		"pure_rows":rows,"buffer_rows":buffers,"durable_rows":durable_rows,
		"measurement":{
			"type":"actual production JobRecord struct, same input and same binary for both arms",
			"baseline":"original serde_json::to_vec_pretty followed by 4MiB encoded length check",
			"candidate":"production bounded encoder; real save_record_at for durable arm",
			"cpu":"CLOCK_THREAD_CPUTIME_ID; main benchmark test thread only",
			"order":"three pure ABBA cycles and two durable ABBA cycles per case",
			"buffer":"final Vec capacity, excluding fixture/report and allocator metadata; not peak RSS or allocation count",
			"limits":"local encoding and saves; no launch throughput, interprocess ownership or power-loss claim"
		}
	});
	if let Ok(path) = std::env::var("HEPTA_PERSISTENCE_BENCH_OUTPUT") {
		std::fs::write(path, serde_json::to_vec_pretty(&result).unwrap()).unwrap();
	}
	println!("BOUNDED_RECEIPT_ENCODING_BENCH {result}");
}
