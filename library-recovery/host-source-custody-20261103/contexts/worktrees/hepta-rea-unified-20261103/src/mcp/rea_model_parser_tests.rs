// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Real sparse files and malformed directory fixtures exercise payload-size
//! independence, format uncertainty, pagination and exact byte boundaries.

#![cfg(unix)]

use super::*;
use std::io::Write;

fn inspect() -> WorkerRequest {
	WorkerRequest::Inspect {
		collection: Collection::Tensors,
		offset: 0,
		limit: 64,
	}
}

fn safetensors(header: &[u8], payload: &[u8]) -> tempfile::NamedTempFile {
	let mut file = tempfile::NamedTempFile::new().expect("fixture");
	file.write_all(&(header.len() as u64).to_le_bytes())
		.expect("length");
	file.write_all(header).expect("header");
	file.write_all(payload).expect("payload");
	file.flush().expect("flush");
	file
}

#[test]
fn sparse_four_gib_model_has_bounded_directory_and_reads_last_tensor_bytes() {
	let payload_len = 4_u64 * 1024 * 1024 * 1024;
	let header = serde_json::to_vec(&json!({
		"weights":{"dtype":"U8","shape":[payload_len],"data_offsets":[0,payload_len]}
	}))
	.expect("header");
	let mut file = safetensors(&header, &[]);
	let data_offset = 8 + header.len() as u64;
	file.as_file_mut()
		.set_len(data_offset + payload_len)
		.expect("sparse extent");
	file.as_file_mut()
		.seek(SeekFrom::End(-4))
		.expect("last range");
	file.write_all(&[1, 2, 3, 4]).expect("selected values");
	let report = inspect_file(file.as_file_mut(), &inspect()).expect("large model header");
	assert_eq!(report["source"]["size_bytes"], data_offset + payload_len);
	assert_eq!(report["source"]["header_bytes"], data_offset);
	assert_eq!(report["tensor_count"], 1);
	assert_eq!(report["result"]["rows"][0]["byte_length"], payload_len);
	assert!(serde_json::to_vec(&report).expect("encode").len() < 4096);
	let range = inspect_file(
		file.as_file_mut(),
		&WorkerRequest::Read {
			tensor_name: Some("weights".to_string()),
			offset: payload_len - 4,
			length: 4,
		},
	)
	.expect("bounded last tensor bytes");
	assert_eq!(range["result"]["bytes_hex"], "01020304");
	assert!(range["result"]["next_offset"].is_null());
	assert!(inspect_file(
		file.as_file_mut(),
		&WorkerRequest::Read {
			tensor_name: Some("weights".to_string()),
			offset: payload_len - 3,
			length: 4,
		}
	)
	.is_err());
}

#[test]
fn safetensors_pages_are_stable_and_do_not_change_coverage_or_header_identity() {
	let header = br#"{"z":{"dtype":"F32","shape":[1],"data_offsets":[4,8]},"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]},"__metadata__":{"producer":"fixture"}}"#;
	let mut file = safetensors(header, &[0; 8]);
	let first = inspect_file(
		file.as_file_mut(),
		&WorkerRequest::Inspect {
			collection: Collection::Tensors,
			offset: 0,
			limit: 1,
		},
	)
	.expect("first page");
	let second = inspect_file(
		file.as_file_mut(),
		&WorkerRequest::Inspect {
			collection: Collection::Tensors,
			offset: 1,
			limit: 1,
		},
	)
	.expect("second page");
	assert_eq!(first["result"]["rows"][0]["name"], "a");
	assert_eq!(second["result"]["rows"][0]["name"], "z");
	assert_eq!(first["result"]["next_offset"], 1);
	assert!(second["result"]["next_offset"].is_null());
	assert_eq!(first["source"], second["source"]);
	assert_eq!(first["coverage"], second["coverage"]);
	let metadata = inspect_file(
		file.as_file_mut(),
		&WorkerRequest::Inspect {
			collection: Collection::Metadata,
			offset: 0,
			limit: 1,
		},
	)
	.expect("metadata");
	assert_eq!(metadata["result"]["rows"][0]["value"], "fixture");
	assert!(inspect_file(
		file.as_file_mut(),
		&WorkerRequest::Inspect {
			collection: Collection::Tensors,
			offset: 3,
			limit: 1,
		}
	)
	.is_err());
}

#[test]
fn strict_safetensors_directory_rejects_duplicates_overflow_gaps_and_truncation() {
	let cases: &[(&[u8], &[u8])] = &[
		(br#"{"w":{"dtype":"U8","shape":[1],"shape":[1],"data_offsets":[0,1]}}"#, &[0]),
		(br#"{"w":{"dtype":"U8","shape":[2],"data_offsets":[0,1]}}"#, &[0]),
		(br#"{"w":{"dtype":"U8","shape":[18446744073709551615,2,0],"data_offsets":[0,0]}}"#, &[]),
		(br#"{"w":{"dtype":"U8","shape":[1],"data_offsets":[1,2]}}"#, &[0, 1]),
		(br#"{"a":{"dtype":"U8","shape":[2],"data_offsets":[0,2]},"b":{"dtype":"U8","shape":[1],"data_offsets":[1,2]}}"#, &[0, 1]),
		(br#"{"w":{"dtype":"U8","shape":[2],"data_offsets":[0,2]}}"#, &[0]),
		(br#"{"w":{"dtype":"U8","shape":[1.0],"data_offsets":[0,1]}}"#, &[0]),
		(br#"{"__metadata__":{"key":17}}"#, &[]),
	];
	for (header, bytes) in cases {
		let mut file = safetensors(header, bytes);
		assert!(
			inspect_file(file.as_file_mut(), &inspect()).is_err(),
			"{}",
			String::from_utf8_lossy(header)
		);
	}
	let mut file = tempfile::NamedTempFile::new().expect("fixture");
	file.write_all(&u64::MAX.to_le_bytes())
		.expect("huge declared header");
	assert!(inspect_file(file.as_file_mut(), &inspect()).is_err());
}

#[test]
fn unknown_safetensors_dtype_retains_declared_range_without_claiming_layout() {
	let mut file = safetensors(
		br#"{"w":{"dtype":"FUTURE_DTYPE","shape":[999],"data_offsets":[0,2]}}"#,
		&[7, 8],
	);
	let report = inspect_file(file.as_file_mut(), &inspect()).expect("unknown dtype");
	assert_eq!(report["unknown_storage_count"], 1);
	assert_eq!(report["result"]["rows"][0]["byte_length"], 2);
	assert_eq!(
		report["result"]["rows"][0]["storage_length_verified"],
		false
	);
	let read = inspect_file(
		file.as_file_mut(),
		&WorkerRequest::Read {
			tensor_name: Some("w".to_string()),
			offset: 0,
			length: 2,
		},
	)
	.expect("read declared raw bytes");
	assert_eq!(read["result"]["bytes_hex"], "0708");
}

fn append_u32(bytes: &mut Vec<u8>, value: u32, little: bool) {
	bytes.extend_from_slice(&if little {
		value.to_le_bytes()
	} else {
		value.to_be_bytes()
	});
}
fn append_u64(bytes: &mut Vec<u8>, value: u64, little: bool) {
	bytes.extend_from_slice(&if little {
		value.to_le_bytes()
	} else {
		value.to_be_bytes()
	});
}
fn append_string(bytes: &mut Vec<u8>, value: &str, little: bool) {
	append_u64(bytes, value.len() as u64, little);
	bytes.extend_from_slice(value.as_bytes());
}

fn gguf(little: bool, dtype: u32, shape: u64) -> tempfile::NamedTempFile {
	let mut bytes = b"GGUF".to_vec();
	append_u32(&mut bytes, 3, little);
	append_u64(&mut bytes, 1, little);
	append_u64(&mut bytes, 1, little);
	append_string(&mut bytes, "general.name", little);
	append_u32(&mut bytes, 8, little);
	append_string(&mut bytes, "fixture", little);
	append_string(&mut bytes, "weights", little);
	append_u32(&mut bytes, 1, little);
	append_u64(&mut bytes, shape, little);
	append_u32(&mut bytes, dtype, little);
	append_u64(&mut bytes, 0, little);
	bytes.resize(bytes.len().div_ceil(32) * 32, 0);
	bytes.extend_from_slice(&[1, 2, 3, 4]);
	let mut file = tempfile::NamedTempFile::new().expect("fixture");
	file.write_all(&bytes).expect("GGUF");
	file
}

#[test]
fn gguf_scalar_directories_support_both_byte_orders() {
	for little in [true, false] {
		let mut file = gguf(little, 0, 1);
		let report = inspect_file(file.as_file_mut(), &inspect()).expect("GGUF directory");
		assert_eq!(report["format"], "gguf");
		assert_eq!(report["byte_order"], if little { "little" } else { "big" });
		assert_eq!(report["result"]["rows"][0]["byte_length"], 4);
		let bytes = inspect_file(
			file.as_file_mut(),
			&WorkerRequest::Read {
				tensor_name: Some("weights".to_string()),
				offset: 1,
				length: 2,
			},
		)
		.expect("tensor bytes");
		assert_eq!(bytes["result"]["bytes_hex"], "0203");
	}
}

#[test]
fn unknown_gguf_layout_is_not_guessed_from_file_size() {
	let mut file = gguf(true, 2, 32);
	let report = inspect_file(file.as_file_mut(), &inspect()).expect("unknown layout preserved");
	assert_eq!(report["unknown_storage_count"], 1);
	assert!(report["result"]["rows"][0]["byte_length"].is_null());
	assert!(inspect_file(
		file.as_file_mut(),
		&WorkerRequest::Read {
			tensor_name: Some("weights".to_string()),
			offset: 0,
			length: 1,
		}
	)
	.is_err());
	let offset = report["tensor_data_offset"]
		.as_u64()
		.expect("payload offset");
	let raw = inspect_file(
		file.as_file_mut(),
		&WorkerRequest::Read {
			tensor_name: None,
			offset,
			length: 4,
		},
	)
	.expect("explicit file range");
	assert_eq!(raw["result"]["bytes_hex"], "01020304");
}

#[test]
fn gguf_declared_storage_outside_payload_and_truncated_directory_are_rejected() {
	let mut outside = gguf(true, 0, 2);
	assert!(inspect_file(outside.as_file_mut(), &inspect()).is_err());
	let mut truncated = gguf(true, 0, 1);
	truncated
		.as_file_mut()
		.set_len(40)
		.expect("truncate header");
	assert!(inspect_file(truncated.as_file_mut(), &inspect()).is_err());
	let mut excessive = tempfile::NamedTempFile::new().expect("fixture");
	let mut bytes = b"GGUF".to_vec();
	append_u32(&mut bytes, 3, true);
	append_u64(&mut bytes, u64::MAX, true);
	append_u64(&mut bytes, 0, true);
	excessive.write_all(&bytes).expect("count fixture");
	assert!(inspect_file(excessive.as_file_mut(), &inspect()).is_err());
}
