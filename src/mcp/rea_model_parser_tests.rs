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
	let mut file = gguf(true, 999, 32);
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

// These byte extents also run through the pinned REA 6.8.0 parser in
// scripts/rea-model-gguf-layout-diff.mjs; they are not derived from ggml_layout.
fn gguf_rows(
	little: bool,
	rows: &[(&str, u32, &[u64], u64)],
	payload: &[u8],
) -> tempfile::NamedTempFile {
	let mut bytes = b"GGUF".to_vec();
	append_u32(&mut bytes, 3, little);
	append_u64(&mut bytes, rows.len() as u64, little);
	// Producer metadata cannot disambiguate historical type/layout collisions.
	append_u64(&mut bytes, 2, little);
	for (key, value) in [
		("general.quantization_version", 2),
		("general.file_type", 7),
	] {
		append_string(&mut bytes, key, little);
		append_u32(&mut bytes, 4, little);
		append_u32(&mut bytes, value, little);
	}
	for (name, dtype, shape, offset) in rows {
		append_string(&mut bytes, name, little);
		append_u32(&mut bytes, shape.len() as u32, little);
		for dimension in *shape {
			append_u64(&mut bytes, *dimension, little);
		}
		append_u32(&mut bytes, *dtype, little);
		append_u64(&mut bytes, *offset, little);
	}
	bytes.resize(bytes.len().div_ceil(32) * 32, 0);
	bytes.extend_from_slice(payload);
	let mut file = tempfile::NamedTempFile::new().expect("fixture");
	file.write_all(&bytes).expect("GGUF rows");
	file
}

#[test]
fn stable_gguf_block_layouts_validate_rows_extents_and_exact_tensor_reads() {
	let layouts = [
		(0, "F32", 1, 4),
		(1, "F16", 1, 2),
		(2, "Q4_0", 32, 18),
		(3, "Q4_1", 32, 20),
		(6, "Q5_0", 32, 22),
		(7, "Q5_1", 32, 24),
		(8, "Q8_0", 32, 34),
		(26, "I32", 1, 4),
		(27, "I64", 1, 8),
		(28, "F64", 1, 8),
		(29, "IQ1_M", 256, 56),
		(30, "BF16", 1, 2),
		(34, "TQ1_0", 256, 54),
		(35, "TQ2_0", 256, 66),
		(39, "MXFP4", 32, 17),
		(40, "NVFP4", 64, 36),
		(41, "Q1_0", 128, 18),
		(42, "Q2_0", 64, 18),
	];
	for (id, name, block_elements, block_bytes) in layouts {
		let length = 12 * block_bytes;
		let payload: Vec<_> = (0..length).map(|n| n as u8).collect();
		for little in [true, false] {
			let shape = [block_elements * 2, 3, 2];
			let mut file = gguf_rows(little, &[("weights", id, &shape, 0)], &payload);
			let report = inspect_file(file.as_file_mut(), &inspect()).expect("stable GGML");
			let row = &report["result"]["rows"][0];
			assert_eq!(row["dtype"], name, "id {id}");
			assert_eq!(row["byte_length"], length, "id {id}");
			assert_eq!(row["elements"], (block_elements * 12).to_string());
			assert_eq!(row["storage_length_verified"], true);
			assert_eq!(report["unknown_storage_count"], 0);
			let range = WorkerRequest::Read {
				tensor_name: Some("weights".into()),
				offset: length as u64 - 2,
				length: 2,
			};
			let read = inspect_file(file.as_file_mut(), &range).expect("last block bytes");
			assert_eq!(
				read["result"]["bytes_hex"],
				digest_hex(&payload[length - 2..])
			);
			assert_eq!(
				read["result"]["sha256"],
				digest_hex(&Sha256::digest(&payload[length - 2..]))
			);
			assert!(inspect_file(
				file.as_file_mut(),
				&WorkerRequest::Read {
					tensor_name: Some("weights".into()),
					offset: length as u64 - 1,
					length: 2,
				}
			)
			.is_err());
			let mut truncated = gguf_rows(
				little,
				&[("weights", id, &shape, 0)],
				&payload[..length - 1],
			);
			assert!(inspect_file(truncated.as_file_mut(), &inspect()).is_err());
		}
	}
}

#[test]
fn gguf_row_divisibility_cannot_be_replaced_by_total_element_divisibility() {
	for (dtype, row_multiple) in [(2, 32), (9, 32), (10, 64), (29, 256), (40, 64)] {
		for last in [0, 2] {
			let shape = [row_multiple / 2, last];
			let mut file = gguf_rows(true, &[("weights", dtype, &shape, 0)], &[0; 1024]);
			let error = inspect_file(file.as_file_mut(), &inspect()).unwrap_err();
			assert!(error.to_string().contains("first dimension"), "{error}");
		}
	}
}

#[test]
fn historical_gguf_layouts_preserve_ambiguity_despite_versions_padding_and_zeroes() {
	for dtype in 9..=25 {
		let row_multiple = if dtype == 9 {
			32
		} else if dtype <= 15 {
			64
		} else {
			1
		};
		for little in [true, false] {
			let mut file = gguf_rows(
				little,
				&[("weights", dtype, &[row_multiple, 2], 0)],
				&[0; 1024],
			);
			let report = inspect_file(file.as_file_mut(), &inspect()).expect("ambiguous GGML");
			let row = &report["result"]["rows"][0];
			assert!(row["byte_length"].is_null(), "type {dtype}");
			assert_eq!(row["storage_length_verified"], false);
			assert_eq!(report["unknown_storage_count"], 1);
			assert!(report["limitations"]
				.as_array()
				.unwrap()
				.iter()
				.any(|reason| {
					reason.as_str().unwrap().contains("have released")
						|| reason.as_str().unwrap().contains("has released")
				}));
			if dtype >= 16 {
				assert_eq!(row["dtype"], format!("AMBIGUOUS_{dtype}"));
			}
			assert!(inspect_file(
				file.as_file_mut(),
				&WorkerRequest::Read {
					tensor_name: Some("weights".into()),
					offset: 0,
					length: 1,
				}
			)
			.is_err());
		}
		let mut empty = gguf_rows(true, &[("empty", dtype, &[row_multiple, 0], 0)], &[]);
		let report = inspect_file(empty.as_file_mut(), &inspect()).expect("empty known type");
		assert_eq!(report["result"]["rows"][0]["byte_length"], 0);
		assert_eq!(report["result"]["rows"][0]["storage_length_verified"], true);
		if dtype >= 16 {
			assert!(report["limitations"]
				.as_array()
				.unwrap()
				.iter()
				.any(|reason| reason.as_str().unwrap().contains("conflicting")));
		}
	}
}

#[test]
fn unknown_or_removed_gguf_types_stay_unverified_even_with_zero_elements() {
	for dtype in [4, 5, 31, 32, 33, 36, 37, 38, 43, u32::MAX] {
		let mut file = gguf_rows(true, &[("empty", dtype, &[0], 0)], &[]);
		let report = inspect_file(file.as_file_mut(), &inspect()).expect("unknown empty type");
		assert!(report["result"]["rows"][0]["byte_length"].is_null());
		assert_eq!(
			report["result"]["rows"][0]["storage_length_verified"],
			false
		);
		assert_eq!(report["unknown_storage_count"], 1);
	}
}

#[test]
fn gguf_stable_quantized_extents_detect_overlap_without_requiring_contiguous_padding() {
	let shape = [64];
	let rows = [("first", 2, &shape[..], 0), ("second", 2, &shape[..], 32)];
	let mut overlapping = gguf_rows(true, &rows, &[0; 128]);
	let error = inspect_file(overlapping.as_file_mut(), &inspect()).unwrap_err();
	assert!(error.to_string().contains("overlaps"));
	let rows = [("first", 2, &shape[..], 0), ("second", 2, &shape[..], 64)];
	let mut padded = gguf_rows(true, &rows, &[0; 100]);
	let report = inspect_file(padded.as_file_mut(), &inspect()).expect("aligned gap allowed");
	assert_eq!(report["result"]["rows"][1]["byte_length"], 36);
	let mut unaligned = gguf_rows(true, &[("weights", 2, &shape, 1)], &[0; 128]);
	assert!(inspect_file(unaligned.as_file_mut(), &inspect())
		.unwrap_err()
		.to_string()
		.contains("alignment"));
}

#[test]
fn gguf_new_scalar_layouts_reject_storage_overflow_and_absolute_offset_overflow() {
	let mut length_overflow = gguf_rows(true, &[("weights", 27, &[u64::MAX / 8 + 1], 0)], &[]);
	assert!(inspect_file(length_overflow.as_file_mut(), &inspect())
		.unwrap_err()
		.to_string()
		.contains("storage length overflow"));
	let mut offset_overflow = gguf_rows(true, &[("weights", 2, &[32], u64::MAX - 31)], &[0; 32]);
	assert!(inspect_file(offset_overflow.as_file_mut(), &inspect())
		.unwrap_err()
		.to_string()
		.contains("absolute offset overflow"));
}
