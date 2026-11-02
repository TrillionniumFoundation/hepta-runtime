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

//! Native REA preview parser and workspace admission negative tests.

use super::*;

#[test]
fn elf64_header_is_observed_but_not_claimed_as_full_analysis() {
	let mut bytes = vec![0; 64];
	bytes[..4].copy_from_slice(b"\x7fELF");
	bytes[4] = 2;
	bytes[5] = 1;
	bytes[6] = 1;
	bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
	bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
	bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
	bytes[24..32].copy_from_slice(&0x401000_u64.to_le_bytes());
	bytes[60..62].copy_from_slice(&3_u16.to_le_bytes());
	let result = inspect_bytes(&bytes, "/controlled/elf").expect("ELF");
	assert_eq!(result["normalized_result"]["format"], "elf");
	assert_eq!(result["normalized_result"]["architecture"], "x86_64");
	assert_eq!(
		result["normalized_result"]["header_facts"]["entry_point"],
		"0x401000"
	);
	assert_eq!(result["coverage"]["status"], "partial");
	assert_eq!(result["rea_evidence_compatible"], false);
	assert!(result.get("evidence_id").is_none());
}

#[test]
fn pe_header_is_observed_without_claiming_a_signed_image() {
	let mut bytes = vec![0; 0xa0];
	bytes[..2].copy_from_slice(b"MZ");
	bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
	bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
	bytes[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
	bytes[0x86..0x88].copy_from_slice(&2_u16.to_le_bytes());
	bytes[0x94..0x96].copy_from_slice(&2_u16.to_le_bytes());
	bytes[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
	let report = inspect_bytes(&bytes, "/controlled/app.exe").expect("PE");
	assert_eq!(report["normalized_result"]["format"], "pe");
	assert_eq!(report["normalized_result"]["architecture"], "x86_64");
	assert_eq!(report["normalized_result"]["word_size_bits"], 64);
}

#[test]
fn wasm_header_is_versioned() {
	let report = inspect_bytes(b"\0asm\x01\0\0\0", "/controlled/demo.wasm").expect("WASM");
	assert_eq!(report["normalized_result"]["format"], "wasm");
	assert!(inspect_bytes(b"\0asm\x02\0\0\0", "/controlled/demo.wasm").is_err());
}

#[test]
fn gguf_header_is_bounded_observation() {
	let mut bytes = b"GGUF".to_vec();
	bytes.extend(3_u32.to_le_bytes());
	bytes.extend(2_u64.to_le_bytes());
	bytes.extend(1_u64.to_le_bytes());
	let report = inspect_bytes(&bytes, "/controlled/model.gguf").expect("GGUF");
	assert_eq!(report["normalized_result"]["format"], "gguf");
	assert_eq!(
		report["normalized_result"]["header_facts"]["declared_tensors"],
		2
	);
}

#[test]
fn elf32_big_endian_is_not_read_as_little_endian() {
	let mut bytes = vec![0; 52];
	bytes[..4].copy_from_slice(b"\x7fELF");
	bytes[4] = 1;
	bytes[5] = 2;
	bytes[6] = 1;
	bytes[16..18].copy_from_slice(&2_u16.to_be_bytes());
	bytes[18..20].copy_from_slice(&40_u16.to_be_bytes());
	bytes[20..24].copy_from_slice(&1_u32.to_be_bytes());
	bytes[24..28].copy_from_slice(&0x1234_u32.to_be_bytes());
	let report = inspect_bytes(&bytes, "/controlled/arm-big-endian").expect("big endian ELF");
	assert_eq!(report["normalized_result"]["format"], "elf");
	assert_eq!(report["normalized_result"]["architecture"], "arm");
	assert_eq!(report["normalized_result"]["word_size_bits"], 32);
	assert_eq!(report["normalized_result"]["byte_order"], "big");
	assert_eq!(
		report["normalized_result"]["header_facts"]["entry_point"],
		"0x1234"
	);
}

#[test]
fn macho_fat_and_zip_do_not_claim_full_slice_or_apk_identity() {
	let fat = inspect_bytes(
		&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2],
		"/controlled/universal",
	)
	.expect("fat MachO");
	assert_eq!(fat["normalized_result"]["format"], "macho-fat");
	assert_eq!(
		fat["normalized_result"]["header_facts"]["declared_slices"],
		2
	);
	assert_eq!(fat["normalized_result"]["architecture"], Value::Null);
	let zip = inspect_bytes(b"PK\x03\x04truncated", "/controlled/app.apk").expect("zip signature");
	assert_eq!(zip["normalized_result"]["format"], "zip");
	assert_eq!(zip["coverage"]["status"], "partial");
}

#[test]
fn safetensors_header_is_detected_without_validating_payload() {
	let header = br#"{"weight":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#;
	let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
	bytes.extend(header);
	bytes.extend([0_u8; 4]);
	let report = inspect_bytes(&bytes, "/controlled/model.safetensors").expect("tensor header");
	assert_eq!(report["normalized_result"]["format"], "safetensors");
	assert_eq!(
		report["normalized_result"]["header_facts"]["declared_tensors"],
		1
	);
}

#[test]
fn safetensors_rejects_overlaps_gaps_trailing_data_and_shape_mismatch() {
	for (header, payload_size) in [
		(
			r#"{"a":{"dtype":"F32","shape":[1],"data_offsets":[0,5]}}"#,
			5,
		),
		(
			r#"{"a":{"dtype":"F32","shape":[1],"data_offsets":[1,5]}}"#,
			5,
		),
		(
			r#"{"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#,
			8,
		),
		(
			r#"{"a":{"dtype":"F32","shape":[2],"data_offsets":[0,4]}}"#,
			4,
		),
		(
			r#"{"a":{"dtype":"F32","shape":[1],"data_offsets":[0,9]}}"#,
			4,
		),
		(
			r#"{"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]},"b":{"dtype":"F32","shape":[1],"data_offsets":[2,6]}}"#,
			6,
		),
	] {
		let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
		bytes.extend(header.as_bytes());
		bytes.extend(vec![0u8; payload_size]);
		assert!(
			inspect_bytes(&bytes, "/controlled/rejected.safetensors").is_err(),
			"{header}"
		);
	}
}

#[test]
fn safetensors_rejects_duplicate_metadata_and_duplicate_tensor_names() {
	for header in [
		r#"{"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]},"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#,
		r#"{"__metadata__":{"owner":"a","owner":"b"},"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#,
		r#"{"a":{"dtype":"F32","dtype":"I32","shape":[1],"data_offsets":[0,4]}}"#,
	] {
		let mut data = (header.len() as u64).to_le_bytes().to_vec();
		data.extend(header.as_bytes());
		data.extend([0_u8; 4]);
		assert!(
			inspect_bytes(&data, "/controlled/duplicate.safetensors").is_err(),
			"{header}"
		);
	}
}

#[test]
fn safetensors_reports_unknown_type_as_unknown_not_validated() {
	let header = r#"{"a":{"dtype":"VENDOR_UNKNOWN","shape":[1],"data_offsets":[0,3]}}"#;
	let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
	bytes.extend(header.as_bytes());
	bytes.extend([0u8; 3]);
	let report = inspect_bytes(&bytes, "/controlled/unknown-dtype.safetensors")
		.expect("unknown dtype is admitted");
	assert_eq!(
		report["normalized_result"]["header_facts"]["unknown_dtype_tensors"],
		1
	);
	assert_eq!(
		report["normalized_result"]["header_facts"]["validated_storage_lengths"],
		0
	);
	assert_eq!(report["coverage"]["status"], "partial");
}

#[test]
fn unknown_is_not_relabelled_as_an_absent_feature() {
	let report = inspect_bytes(b"not a known binary", "/controlled/unknown").expect("unknown");
	assert_eq!(report["normalized_result"]["format"], "unknown");
	assert_eq!(report["normalized_result"]["architecture"], Value::Null);
}

#[test]
fn malformed_headers_fail_closed() {
	assert!(inspect_bytes(b"\x7fELF\x02\x01\x01", "/controlled/truncated").is_err());
	assert!(inspect_bytes(b"MZ", "/controlled/truncated.exe").is_err());
	assert!(inspect_bytes(b"GGUF\x03", "/controlled/truncated.gguf").is_err());
	let mut broken = vec![0; 72];
	broken[..4].copy_from_slice(b"\x7fELF");
	broken[4] = 2;
	broken[5] = 1;
	broken[6] = 1;
	assert!(inspect_bytes(&broken, "/controlled/invalid-elf").is_err());
}

#[test]
fn evidence_identity_is_deterministic_and_not_a_claim_of_rea_equivalence() {
	let left = inspect_bytes(b"example", "/controlled/first").expect("left");
	let right = inspect_bytes(b"example", "/controlled/second").expect("right");
	assert_eq!(left["native_evidence_id"], right["native_evidence_id"]);
	assert_ne!(
		left["subject"]["local_path"],
		right["subject"]["local_path"]
	);
	assert_eq!(left["rea_evidence_compatible"], false);
}

#[tokio::test]
async fn controller_workspace_allows_only_registered_roots() {
	let workspace = tempfile::tempdir().expect("workspace");
	let out = tempfile::tempdir().expect("outside");
	let inside = workspace.path().join("artifact");
	let outside = out.path().join("artifact");
	tokio::fs::write(&inside, b"\0asm\x01\0\0\0")
		.await
		.expect("write inside");
	tokio::fs::write(&outside, b"\0asm\x01\0\0\0")
		.await
		.expect("write outside");
	let roots = vec![workspace.path().to_path_buf()];
	assert!(inspect_with_roots(&inside, &roots).await.is_ok());
	assert!(inspect_with_roots(&outside, &roots).await.is_err());
	assert!(inspect_with_roots(&inside, &[]).await.is_err());
	assert!(inspect_with_roots(workspace.path(), &roots).await.is_err());
	assert!(inspect_with_roots(Path::new("relative-file"), &roots)
		.await
		.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_outside_workspace_is_refused() {
	let workspace = tempfile::tempdir().expect("workspace");
	let outside = tempfile::tempdir().expect("outside");
	let target = outside.path().join("secret");
	tokio::fs::write(&target, b"private")
		.await
		.expect("write secret");
	let link = workspace.path().join("symlink");
	std::os::unix::fs::symlink(&target, &link).expect("create symlink");
	let roots = vec![workspace.path().to_path_buf()];
	assert!(inspect_with_roots(&link, &roots).await.is_err());
}

#[test]
fn malformed_header_fuzz_does_not_panic() {
	// Repeatable deterministic adversarial mutations of every native preview
	// family. Successful unknowns must never imply complete format coverage.
	let seeds: &[&[u8]] = &[
		b"\x7fELF",
		b"MZ",
		b"\0asm",
		b"GGUF",
		b"PK\x03\x04",
		b"\xca\xfe\xba\xbe",
		b"\xfe\xed\xfa\xcf",
		b"\x20\0\0\0\0\0\0\0{",
	];
	let mut state = 0x9e37_79b9_7f4a_7c15_u64;
	for seed in seeds {
		for round in 0..192 {
			let mut data = seed.to_vec();
			for _ in 0..(round % 3) {
				data.extend_from_slice(seed);
			}
			for _ in 0..((round % 17) + 1) {
				state ^= state << 13;
				state ^= state >> 7;
				state ^= state << 17;
				let pos = (state as usize) % (data.len() + 1);
				if pos == data.len() {
					data.push(state as u8);
				} else {
					data[pos] ^= (state >> 8) as u8;
				}
			}
			let parsed = std::panic::catch_unwind(|| inspect_bytes(&data, "/controlled/fuzz"));
			assert!(parsed.is_ok(), "parser panic on seed {seed:?} iteration {round}");
			if let Ok(Ok(report)) = parsed {
				assert_eq!(report["coverage"]["status"], "partial");
				assert_eq!(report["rea_evidence_compatible"], false);
			}
		}
	}
}

#[test]
fn safetensors_extreme_header_lengths_never_allocate_or_bypass_budgets() {
	let mut huge = u64::MAX.to_le_bytes().to_vec();
	huge.push(b'{');
	let report = inspect_bytes(&huge, "/controlled/overflow");
	// A truncated or unsupported candidate must never report verified tensors.
	if let Ok(report) = report {
		assert_ne!(report["normalized_result"]["format"], "safetensors");
		assert_eq!(report["coverage"]["status"], "partial");
	}
	let mut over_budget = (8_u64 * 1024 * 1024 + 1).to_le_bytes().to_vec();
	over_budget.push(b'{');
	let report = inspect_bytes(&over_budget, "/controlled/over-budget");
	if let Ok(report) = report {
		assert_ne!(report["normalized_result"]["format"], "safetensors");
	}
}
