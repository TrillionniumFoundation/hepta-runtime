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

//! Independent zipfile containers, sparse files and malformed directory tests.
//! APK/JAR role fixtures are inert, not executable or installable packages.

#![cfg(unix)]

use super::*;
use std::io::Write;
const APK: &[u8] = include_bytes!("../../tests/fixtures/rea_artifact_sample.apk");
const JAR: &[u8] = include_bytes!("../../tests/fixtures/rea_artifact_sample.jar");
const ZIP: &[u8] = include_bytes!("../../tests/fixtures/rea_artifact_sample.zip");

fn fixture(bytes: &[u8]) -> tempfile::NamedTempFile {
	let mut file = tempfile::NamedTempFile::new().expect("fixture");
	file.write_all(bytes).expect("fixture bytes");
	file.flush().expect("flush");
	file
}
fn all() -> Request {
	Request {
		filter: ArchiveFilter::All,
		offset: 0,
		limit: 64,
	}
}

#[test]
fn independently_generated_zip_jar_and_apk_containers_retain_partial_semantics() {
	for (bytes, count, hint) in [
		(ZIP, 2, None),
		(JAR, 2, Some("jar_candidate")),
		(APK, 4, Some("apk_candidate")),
	] {
		let mut file = fixture(bytes);
		let report =
			inspect_file(file.as_file_mut(), &all()).expect("valid independently generated ZIP");
		assert_eq!(report["entry_count"], count);
		assert_eq!(report["coverage"]["payload_crc32"], "not_verified");
		assert_eq!(report["coverage"]["signatures"], "not_verified");
		assert!(report["result"]["rows"]
			.as_array()
			.expect("rows")
			.iter()
			.all(|row| row["content_verified"] == false));
		if let Some(hint) = hint {
			assert_eq!(report["application_kind_candidates"][0], hint);
		}
	}
}

#[test]
fn archive_filters_and_pages_do_not_invent_content_coverage() {
	let mut file = fixture(APK);
	let first = inspect_file(
		file.as_file_mut(),
		&Request {
			filter: ArchiveFilter::All,
			offset: 0,
			limit: 1,
		},
	)
	.expect("page one");
	let second = inspect_file(
		file.as_file_mut(),
		&Request {
			filter: ArchiveFilter::All,
			offset: 1,
			limit: 1,
		},
	)
	.expect("page two");
	assert_eq!(first["result"]["next_offset"], 1);
	assert_eq!(second["result"]["rows"][0]["name"], "classes.dex");
	assert_eq!(first["source"], second["source"]);
	assert_eq!(first["coverage"], second["coverage"]);
	for (filter, name) in [
		(ArchiveFilter::Manifest, "AndroidManifest.xml"),
		(ArchiveFilter::Dex, "classes.dex"),
		(ArchiveFilter::NativeLibrary, "lib/arm64-v8a/libfixture.so"),
	] {
		let report = inspect_file(
			file.as_file_mut(),
			&Request {
				filter,
				offset: 0,
				limit: 1,
			},
		)
		.expect("filter");
		assert_eq!(report["result"]["total"], 1);
		assert_eq!(report["result"]["rows"][0]["name"], name);
	}
}

#[test]
fn central_local_boundary_zip64_and_encoding_errors_are_explicit() {
	let central = ZIP
		.windows(4)
		.position(|part| part == b"PK\x01\x02")
		.expect("central header");
	let eocd = ZIP.len() - 22;
	let mut malformed = Vec::new();
	let mut bytes = ZIP.to_vec();
	bytes[central + 42..central + 46].copy_from_slice(&(central as u32).to_le_bytes());
	malformed.push(bytes);
	let mut bytes = ZIP.to_vec();
	bytes[central + 20..central + 24].copy_from_slice(&u32::MAX.to_le_bytes());
	malformed.push(bytes);
	let mut bytes = ZIP.to_vec();
	bytes[eocd + 8..eocd + 12].copy_from_slice(&[255; 4]);
	malformed.push(bytes);
	let mut bytes = ZIP.to_vec();
	bytes[30] = 255;
	bytes[central + 46] = 255;
	malformed.push(bytes);
	let mut bytes = ZIP.to_vec();
	bytes[central + 46] ^= 1;
	malformed.push(bytes);
	let mut bytes = ZIP.to_vec();
	bytes.extend_from_slice(b"unindexed overlay");
	malformed.push(bytes);
	for bytes in malformed {
		let mut file = fixture(&bytes);
		assert!(inspect_file(file.as_file_mut(), &all()).is_err());
	}
	assert!(extra_fields(&[1, 0, 0, 0])
		.expect_err("ZIP64 extra")
		.to_string()
		.contains("ZIP64"));
	assert!(extra_fields(&[0x75, 0x70, 0, 0]).is_err());
	assert!(extra_fields(&[2, 0, 9, 0, 1]).is_err());
	assert!(member_name(&[255], 1 << 11).is_err());
}

#[test]
fn android_align32_zero_padding_is_local_and_exact() {
	for padding in [&[0][..], &[0, 0], &[0, 0, 0]] {
		validate_local_extra(padding, 0, 0, 44).expect("minimal local align32 padding");
		assert!(
			extra_fields(padding).is_err(),
			"central extras remain strict TLVs"
		);
	}
	validate_local_extra(&[], 8, 0, 43).expect("empty extras are unchanged");
	validate_local_extra(&[0x34, 0x12, 2, 0, 1, 2], 0, 0, 47)
		.expect("complete ordinary local TLV remains valid without alignment");
}

#[test]
fn local_alignment_does_not_hide_malformed_or_unsupported_extra_fields() {
	for bytes in [
		&[1][..],
		&[0, 1],
		&[0, 0, 1],
		&[0, 0, 0, 0, 0],
		&[2, 0, 0, 0, 0],
		&[2, 0, 1, 0],
		&[1, 0, 0, 0],
		&[0x75, 0x70, 0, 0],
	] {
		assert!(
			validate_local_extra(bytes, 0, 0, 44).is_err(),
			"nonzero, mixed, truncated and unsupported extras stay refused: {bytes:?}"
		);
	}
	for padding in [&[0][..], &[0, 0], &[0, 0, 0]] {
		for payload_offset in [41, 42, 43] {
			assert!(validate_local_extra(padding, 0, 0, payload_offset).is_err());
		}
		assert!(validate_local_extra(padding, 8, 0, 44).is_err());
		for flags in [1, 0x40, 0x41] {
			assert!(validate_local_extra(padding, 0, flags, 44).is_err());
		}
	}
}

#[test]
fn actual_aapt2_local_alignment_preserves_the_declared_payload_extent() {
	let bytes = include_bytes!("../../tests/fixtures/rea_application/owned-aapt2.apk");
	let mut file = fixture(bytes);
	let report = inspect_file(file.as_file_mut(), &all()).expect("unaltered aapt2 output");
	assert_eq!(report["entry_count"], 2);
	let resources = report["result"]["rows"]
		.as_array()
		.expect("directory rows")
		.iter()
		.find(|entry| entry["name"] == "resources.arsc")
		.expect("aapt2 resource table");
	assert_eq!(resources["local_header_offset"], 1131);
	assert_eq!(resources["payload_offset"], 1176);
	assert_eq!(resources["compressed_bytes"], 40);
	assert_eq!(resources["compression_method"], 0);
	assert_eq!(resources["central_extra_field_ids"], json!([]));
	assert_eq!(resources["content_verified"], false);
}

fn single_stored(payload_size: u32, crc: u32, descriptor: bool) -> tempfile::NamedTempFile {
	let name = b"weights.bin";
	let flags: u16 = if descriptor { 8 } else { 0 };
	let mut local = vec![0_u8; 30];
	local[..4].copy_from_slice(b"PK\x03\x04");
	local[4..6].copy_from_slice(&20_u16.to_le_bytes());
	local[6..8].copy_from_slice(&flags.to_le_bytes());
	if !descriptor {
		local[14..18].copy_from_slice(&crc.to_le_bytes());
		local[18..22].copy_from_slice(&payload_size.to_le_bytes());
		local[22..26].copy_from_slice(&payload_size.to_le_bytes());
	}
	local[26..28].copy_from_slice(&(name.len() as u16).to_le_bytes());
	local.extend_from_slice(name);
	let mut file = fixture(&local);
	let end = local.len() as u64 + u64::from(payload_size);
	file.as_file_mut()
		.set_len(end)
		.expect("sparse archive payload");
	file.as_file_mut()
		.seek(SeekFrom::Start(end))
		.expect("directory seek");
	if descriptor {
		file.write_all(b"PK\x07\x08").expect("descriptor signature");
		for value in [crc, payload_size, payload_size] {
			file.write_all(&value.to_le_bytes())
				.expect("descriptor field");
		}
	}
	let central_offset = end + if descriptor { 16 } else { 0 };
	let mut central = vec![0_u8; 46];
	central[..4].copy_from_slice(b"PK\x01\x02");
	central[6..8].copy_from_slice(&20_u16.to_le_bytes());
	central[8..10].copy_from_slice(&flags.to_le_bytes());
	central[16..20].copy_from_slice(&crc.to_le_bytes());
	central[20..24].copy_from_slice(&payload_size.to_le_bytes());
	central[24..28].copy_from_slice(&payload_size.to_le_bytes());
	central[28..30].copy_from_slice(&(name.len() as u16).to_le_bytes());
	central.extend_from_slice(name);
	file.write_all(&central).expect("central");
	let mut eocd = vec![0_u8; 22];
	eocd[..4].copy_from_slice(b"PK\x05\x06");
	eocd[8..10].copy_from_slice(&1_u16.to_le_bytes());
	eocd[10..12].copy_from_slice(&1_u16.to_le_bytes());
	eocd[12..16].copy_from_slice(&(central.len() as u32).to_le_bytes());
	eocd[16..20].copy_from_slice(&(central_offset as u32).to_le_bytes());
	file.write_all(&eocd).expect("EOCD");
	file.flush().expect("flush");
	file
}

#[test]
fn forty_mib_archive_is_indexed_without_payload_buffer_or_crc_claim() {
	let mut file = single_stored(40 * 1024 * 1024, 0xfeeb_63ea, false);
	let report = inspect_file(file.as_file_mut(), &all()).expect("large archive");
	assert_eq!(
		report["result"]["rows"][0]["uncompressed_bytes"],
		40 * 1024 * 1024
	);
	assert_eq!(report["result"]["rows"][0]["declared_crc32"], "feeb63ea");
	assert_eq!(
		report["coverage"]["entry_payloads"],
		"not_interpreted_or_decompressed"
	);
	assert!(serde_json::to_vec(&report).expect("JSON").len() < 4096);
}

#[test]
fn data_descriptor_must_match_central_declarations() {
	let mut file = single_stored(0, 0, true);
	let report = inspect_file(file.as_file_mut(), &all()).expect("descriptor mode");
	assert_eq!(report["result"]["rows"][0]["data_descriptor_bytes"], 16);
	let descriptor_offset = report["result"]["rows"][0]["payload_offset"]
		.as_u64()
		.expect("offset");
	file.as_file_mut()
		.seek(SeekFrom::Start(descriptor_offset + 4))
		.expect("alter declaration");
	file.write_all(&1_u32.to_le_bytes())
		.expect("changed declared CRC");
	assert!(inspect_file(file.as_file_mut(), &all()).is_err());
}
