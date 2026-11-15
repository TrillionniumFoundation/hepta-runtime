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

//! Real aapt/aapt2 and javac/jar fixtures, bounded decompression, byte-level
//! identity, malformed format handling and descriptor admission regression tests.

use super::*;
use std::io::Write as _;

const APK: &[u8] = include_bytes!("../../tests/fixtures/rea_application/owned-aapt.apk");
const APK2: &[u8] = include_bytes!("../../tests/fixtures/rea_application/owned-aapt2.apk");
const JAR: &[u8] = include_bytes!("../../tests/fixtures/rea_application/owned.jar");

fn params(kind: ApplicationKind, collection: ApplicationCollection) -> InspectApplicationParams {
	InspectApplicationParams {
		path: "/unused/owned-application".into(),
		kind,
		collection,
		expected_sha256: None,
		offset: 0,
		limit: 64,
	}
}

fn inspect(bytes: &[u8], params: &InspectApplicationParams) -> Result<Value> {
	let mut file = tempfile::tempfile()?;
	file.write_all(bytes)?;
	let before = file.metadata()?;
	inspect_file(file, before, params)
}

fn fixed_manifest(bytes: &[u8], kind: ApplicationKind) -> Vec<u8> {
	let mut file = tempfile::tempfile().expect("fixture file");
	file.write_all(bytes).expect("write fixture");
	let index = crate::mcp::rea_artifact_zip::inspect_application_directory(&mut file)
		.expect("fixture ZIP index");
	let entry = index["result"]["rows"]
		.as_array()
		.expect("rows")
		.iter()
		.find(|row| row["name"] == kind.member())
		.expect("fixed manifest");
	let offset = number(entry, "payload_offset").expect("offset") as usize;
	let compressed = number(entry, "compressed_bytes").expect("length") as usize;
	decode_manifest(
		&bytes[offset..offset + compressed],
		number(entry, "compression_method").expect("method") as u16,
		number(entry, "uncompressed_bytes").expect("uncompressed") as usize,
		u32::from_str_radix(entry["declared_crc32"].as_str().expect("CRC"), 16).expect("CRC hex"),
	)
	.expect("fixture decompression")
}

fn deflate(bytes: &[u8]) -> Vec<u8> {
	let mut encoder =
		flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
	encoder.write_all(bytes).expect("deflate input");
	encoder.finish().expect("deflate stream")
}

fn push16(bytes: &mut Vec<u8>, value: u16) {
	bytes.extend_from_slice(&value.to_le_bytes());
}
fn push32(bytes: &mut Vec<u8>, value: u32) {
	bytes.extend_from_slice(&value.to_le_bytes());
}

// Test-only ZIP writer. Production parsing remains the shared archive indexer.
fn zip(entries: &[(&str, &[u8], u16)]) -> Vec<u8> {
	let mut output = Vec::new();
	let mut directory = Vec::new();
	for (name, bytes, method) in entries {
		let compressed = if *method == 8 {
			deflate(bytes)
		} else {
			bytes.to_vec()
		};
		let offset = output.len() as u32;
		let crc = crc32(bytes);
		push32(&mut output, 0x0403_4b50);
		for value in [20, 0, *method, 0, 0] {
			push16(&mut output, value);
		}
		for value in [crc, compressed.len() as u32, bytes.len() as u32] {
			push32(&mut output, value);
		}
		push16(&mut output, name.len() as u16);
		push16(&mut output, 0);
		output.extend_from_slice(name.as_bytes());
		output.extend_from_slice(&compressed);
		push32(&mut directory, 0x0201_4b50);
		for value in [20, 20, 0, *method, 0, 0] {
			push16(&mut directory, value);
		}
		for value in [crc, compressed.len() as u32, bytes.len() as u32] {
			push32(&mut directory, value);
		}
		for value in [name.len() as u16, 0, 0, 0, 0] {
			push16(&mut directory, value);
		}
		push32(&mut directory, 0);
		push32(&mut directory, offset);
		directory.extend_from_slice(name.as_bytes());
	}
	let offset = output.len() as u32;
	let size = directory.len() as u32;
	output.extend_from_slice(&directory);
	push32(&mut output, 0x0605_4b50);
	for value in [0, 0, entries.len() as u16, entries.len() as u16] {
		push16(&mut output, value);
	}
	push32(&mut output, size);
	push32(&mut output, offset);
	push16(&mut output, 0);
	output
}

fn parse_manifest(bytes: &[u8], kind: ApplicationKind) -> Result<parser::ManifestReport> {
	parser::parse(bytes, kind, Instant::now() + Duration::from_secs(10))
}

#[test]
fn actual_aapt_and_aapt2_manifest_declarations_match_the_owned_sources() {
	for fixture in [APK, APK2] {
		let report = inspect(
			fixture,
			&params(ApplicationKind::Apk, ApplicationCollection::Summary),
		)
		.expect("real aapt manifest");
		assert_eq!(report["source"]["sha256"], sha256(fixture));
		assert_eq!(report["manifest"]["crc32_verified"], true);
		assert_eq!(
			report["manifest"]["format"],
			"android_binary_xml_declarations"
		);
		assert_eq!(report["summary"]["package"]["value"], "org.hepta.fixture");
		assert_eq!(report["summary"]["version_code"]["value"], 7);
		assert_eq!(report["summary"]["version_name"]["value"], "1.2");
		assert_eq!(
			report["summary"]["sdk_declarations"][0]["min_sdk"]["value"],
			23
		);
		assert_eq!(
			report["summary"]["sdk_declarations"][0]["target_sdk"]["value"],
			35
		);
		assert_eq!(report["summary"]["component_declaration_count"], 5);
		assert_eq!(report["summary"]["permission_declaration_count"], 3);
		assert_eq!(report["coverage"]["signatures"], "not verified");
		assert!(report["rows"].as_array().expect("summary rows").is_empty());
	}
}

#[test]
fn actual_javac_jar_preserves_main_attributes_and_multibyte_continuations() {
	let report = inspect(
		JAR,
		&params(ApplicationKind::Jar, ApplicationCollection::Attributes),
	)
	.expect("real javac/jar fixture");
	assert_eq!(report["summary"]["manifest_version"], "1.0");
	assert_eq!(report["summary"]["main_class"], "org.hepta.Fixture");
	assert_eq!(
		report["summary"]["automatic_module_name"],
		"org.hepta.fixture"
	);
	assert_eq!(
		report["summary"]["class_path_declaration"],
		"lib/first.jar lib/second.jar"
	);
	assert_eq!(report["summary"]["class_files_inspected"], false);
	let long = report["rows"]
		.as_array()
		.expect("attributes")
		.iter()
		.find(|row| row["name"] == "X-Owned-Long")
		.expect("long attribute");
	assert_eq!(long["value"], "已保存工件".repeat(20));
	assert!(long["source_first_line"].as_u64().expect("line") > 1);
	assert_eq!(report["source"]["sha256"], sha256(JAR));
}

#[test]
fn stored_and_deflated_fixed_manifests_have_identical_content_identity() {
	for (fixture, kind) in [(APK, ApplicationKind::Apk), (JAR, ApplicationKind::Jar)] {
		let manifest = fixed_manifest(fixture, kind);
		let stored = zip(&[(kind.member(), &manifest, 0)]);
		let deflated = zip(&[(kind.member(), &manifest, 8)]);
		let left = inspect(&stored, &params(kind, ApplicationCollection::Summary)).expect("stored");
		let right =
			inspect(&deflated, &params(kind, ApplicationCollection::Summary)).expect("deflated");
		assert_eq!(left["manifest"]["sha256"], right["manifest"]["sha256"]);
		assert_ne!(left["source"]["sha256"], right["source"]["sha256"]);
		assert_eq!(left["summary"], right["summary"]);
	}
}

#[test]
fn components_and_permissions_keep_literal_names_types_and_byte_provenance() {
	let report = inspect(
		APK,
		&params(ApplicationKind::Apk, ApplicationCollection::Components),
	)
	.expect("components");
	let rows = report["rows"].as_array().expect("rows");
	assert_eq!(rows.len(), 5);
	let activity = rows
		.iter()
		.find(|row| row["element"] == "activity")
		.expect("activity");
	assert_eq!(activity["name_declaration"]["value"], ".MainActivity");
	assert!(activity["source_chunk_offset"].as_u64().expect("offset") > 0);
	let exported = activity["attributes"]
		.as_array()
		.expect("attributes")
		.iter()
		.find(|row| row["name"] == "exported")
		.expect("exported");
	assert_eq!(exported["typed_value"]["type"], "boolean");
	assert_eq!(exported["typed_value"]["value"], false);
	assert_eq!(
		exported["namespace"],
		"http://schemas.android.com/apk/res/android"
	);
	assert!(exported["resource_id"]
		.as_str()
		.expect("resource id")
		.starts_with("0x01"));
	let report = inspect(
		APK,
		&params(ApplicationKind::Apk, ApplicationCollection::Permissions),
	)
	.expect("permissions");
	assert!(report["rows"]
		.as_array()
		.expect("permissions")
		.iter()
		.any(|row| row["element"] == "uses-permission-sdk-23"
			&& row["name_declaration"]["value"] == "android.permission.CAMERA"));
}

#[test]
fn continuation_requires_and_checks_the_entire_archive_identity() {
	let mut selection = params(ApplicationKind::Apk, ApplicationCollection::Components);
	selection.limit = 2;
	let first = inspect(APK, &selection).expect("page one");
	assert_eq!(first["next_offset"], 2);
	selection.offset = 2;
	assert!(inspect(APK, &selection)
		.unwrap_err()
		.to_string()
		.contains("requires expected_sha256"));
	selection.expected_sha256 = Some(sha256(APK));
	let second = inspect(APK, &selection).expect("page two");
	assert_eq!(second["rows"].as_array().expect("rows").len(), 2);
	assert_eq!(second["offset"], 2);
	selection.expected_sha256 = Some("0".repeat(64));
	assert!(inspect(APK, &selection)
		.unwrap_err()
		.to_string()
		.contains("SHA-256 changed"));
}

#[test]
fn crc32_standard_vector_and_manifest_mismatch_are_checked() {
	assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
	let mut bytes = zip(&[("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n\r\n", 0)]);
	let central = bytes
		.windows(4)
		.position(|window| window == [0x50, 0x4b, 0x01, 0x02])
		.expect("central");
	let bad = 0x1234_5678_u32.to_le_bytes();
	bytes[14..18].copy_from_slice(&bad);
	bytes[central + 16..central + 20].copy_from_slice(&bad);
	assert!(inspect(
		&bytes,
		&params(ApplicationKind::Jar, ApplicationCollection::Summary)
	)
	.unwrap_err()
	.to_string()
	.contains("CRC32"));
}

#[test]
fn raw_deflate_requires_exact_size_complete_stream_and_no_trailing_bytes() {
	let plain = b"Manifest-Version: 1.0\r\n\r\n";
	let compressed = deflate(plain);
	assert_eq!(
		decode_manifest(&compressed, 8, plain.len(), crc32(plain)).expect("valid"),
		plain
	);
	let mut trailing = compressed.clone();
	trailing.push(0);
	assert!(decode_manifest(&trailing, 8, plain.len(), crc32(plain)).is_err());
	assert!(decode_manifest(
		&compressed[..compressed.len() - 1],
		8,
		plain.len(),
		crc32(plain)
	)
	.is_err());
	assert!(decode_manifest(&compressed, 8, plain.len() - 1, crc32(plain)).is_err());
	assert!(decode_manifest(&compressed, 8, plain.len() + 1, crc32(plain)).is_err());
	assert!(decode_manifest(plain, 0, plain.len() + 1, crc32(plain)).is_err());
}

#[test]
fn manifest_expansion_and_source_size_budgets_are_hard_limits() {
	assert!(decode_manifest(b"", 8, MAX_MANIFEST_BYTES + 1, 0).is_err());
	assert!(decode_manifest(&vec![0; MAX_MANIFEST_BYTES + 1], 0, 0, 0).is_err());
	let expanded = vec![b'x'; MAX_MANIFEST_BYTES + 1];
	let bomb = deflate(&expanded);
	assert!(bomb.len() < 64 * 1024);
	assert!(decode_manifest(&bomb, 8, 8, 0).is_err());
	let file = tempfile::tempfile().expect("sparse source");
	file.set_len(MAX_ARCHIVE_BYTES + 1).expect("sparse length");
	let before = file.metadata().expect("metadata");
	assert!(inspect_file(
		file,
		before,
		&params(ApplicationKind::Jar, ApplicationCollection::Summary)
	)
	.unwrap_err()
	.to_string()
	.contains("512 MiB"));
}

#[test]
fn duplicate_zip_names_and_nonfixed_manifest_names_fail_closed() {
	let main = b"Manifest-Version: 1.0\r\n\r\n";
	for entries in [
		vec![
			("META-INF/MANIFEST.MF", main.as_slice(), 0),
			("META-INF/MANIFEST.MF", main.as_slice(), 0),
		],
		vec![
			("META-INF/MANIFEST.MF", main.as_slice(), 0),
			("extra", b"a".as_slice(), 0),
			("extra", b"b".as_slice(), 0),
		],
	] {
		assert!(inspect(
			&zip(&entries),
			&params(ApplicationKind::Jar, ApplicationCollection::Summary)
		)
		.unwrap_err()
		.to_string()
		.contains("duplicate"));
	}
	assert!(inspect(
		&zip(&[("meta-inf/manifest.mf", main, 0)]),
		&params(ApplicationKind::Jar, ApplicationCollection::Summary)
	)
	.unwrap_err()
	.to_string()
	.contains("no fixed"));
}

#[test]
fn selected_manifest_rejects_encryption_and_unsupported_compression() {
	let base = zip(&[("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n\r\n", 0)]);
	let central = base
		.windows(4)
		.position(|window| window == [0x50, 0x4b, 0x01, 0x02])
		.expect("central");
	let mut method = base.clone();
	method[8..10].copy_from_slice(&12_u16.to_le_bytes());
	method[central + 10..central + 12].copy_from_slice(&12_u16.to_le_bytes());
	assert!(inspect(
		&method,
		&params(ApplicationKind::Jar, ApplicationCollection::Summary)
	)
	.is_err());
	let mut encrypted = base;
	encrypted[6..8].copy_from_slice(&1_u16.to_le_bytes());
	encrypted[central + 8..central + 10].copy_from_slice(&1_u16.to_le_bytes());
	assert!(inspect(
		&encrypted,
		&params(ApplicationKind::Jar, ApplicationCollection::Summary)
	)
	.is_err());
}

fn utf8_length(bytes: &mut Vec<u8>, value: usize) {
	assert!(value < 32768);
	if value < 128 {
		bytes.push(value as u8);
	} else {
		bytes.push(((value >> 8) as u8) | 0x80);
		bytes.push(value as u8);
	}
}

fn utf8_axml(attribute_name: &str, value: &str, duplicate: bool) -> Vec<u8> {
	let strings = ["manifest", attribute_name, value];
	let mut data = Vec::new();
	let mut offsets = Vec::new();
	for text in strings {
		offsets.push(data.len() as u32);
		utf8_length(&mut data, text.encode_utf16().count());
		utf8_length(&mut data, text.len());
		data.extend_from_slice(text.as_bytes());
		data.push(0);
	}
	while data.len() % 4 != 0 {
		data.push(0);
	}
	let mut pool = Vec::new();
	push16(&mut pool, 1);
	push16(&mut pool, 28);
	push32(&mut pool, (28 + offsets.len() * 4 + data.len()) as u32);
	push32(&mut pool, offsets.len() as u32);
	push32(&mut pool, 0);
	push32(&mut pool, 0x100);
	push32(&mut pool, (28 + offsets.len() * 4) as u32);
	push32(&mut pool, 0);
	for offset in offsets {
		push32(&mut pool, offset);
	}
	pool.extend_from_slice(&data);
	let count = if duplicate { 2 } else { 1 };
	let mut node = Vec::new();
	push16(&mut node, 0x102);
	push16(&mut node, 16);
	push32(&mut node, 36 + 20 * count);
	push32(&mut node, 1);
	push32(&mut node, u32::MAX);
	push32(&mut node, u32::MAX);
	push32(&mut node, 0);
	for value in [20, 20, count as u16, 0, 0, 0] {
		push16(&mut node, value);
	}
	for _ in 0..count {
		push32(&mut node, u32::MAX);
		push32(&mut node, 1);
		push32(&mut node, 2);
		push16(&mut node, 8);
		node.push(0);
		node.push(3);
		push32(&mut node, 2);
	}
	push16(&mut node, 0x103);
	push16(&mut node, 16);
	push32(&mut node, 24);
	push32(&mut node, 1);
	push32(&mut node, u32::MAX);
	push32(&mut node, u32::MAX);
	push32(&mut node, 0);
	let mut output = Vec::new();
	push16(&mut output, 3);
	push16(&mut output, 8);
	push32(&mut output, (8 + pool.len() + node.len()) as u32);
	output.extend_from_slice(&pool);
	output.extend_from_slice(&node);
	output
}

#[test]
fn axml_utf8_utf16_lengths_and_namespace_identity_are_not_guessed() {
	let xml = utf8_axml("package", "org.测试.😀", false);
	let report = parse_manifest(&xml, ApplicationKind::Apk).expect("UTF-8 binary XML");
	assert_eq!(report.summary["package"]["value"], "org.测试.😀");
	let report = parse_manifest(
		&utf8_axml("versionCode", "spoofed", false),
		ApplicationKind::Apk,
	)
	.expect("unqualified attribute data");
	assert!(
		report.summary["version_code"].is_null(),
		"an unqualified name is not an Android namespace declaration"
	);
	assert!(parse_manifest(&utf8_axml("package", "x", true), ApplicationKind::Apk).is_err());
	let mut utf16 = fixed_manifest(APK, ApplicationKind::Apk);
	let pool_start = 8_usize;
	let strings_start = u32::from_le_bytes(
		utf16[pool_start + 20..pool_start + 24]
			.try_into()
			.expect("start"),
	) as usize;
	let first_offset = u32::from_le_bytes(
		utf16[pool_start + 28..pool_start + 32]
			.try_into()
			.expect("offset"),
	) as usize;
	let first_unit = pool_start + strings_start + first_offset + 2;
	utf16[first_unit..first_unit + 2].copy_from_slice(&0xd800_u16.to_le_bytes());
	assert!(
		parse_manifest(&utf16, ApplicationKind::Apk).is_err(),
		"unpaired surrogate must fail"
	);
}

#[test]
fn axml_truncated_chunks_bad_indices_and_pool_budgets_are_rejected() {
	let original = utf8_axml("package", "org.hepta", false);
	let mut truncated = original[..original.len() - 24].to_vec();
	let length = truncated.len() as u32;
	truncated[4..8].copy_from_slice(&length.to_le_bytes());
	assert!(parse_manifest(&truncated, ApplicationKind::Apk).is_err());
	let mut bad_index = original.clone();
	bad_index[8 + 28..8 + 32].copy_from_slice(&u32::MAX.to_le_bytes());
	assert!(parse_manifest(&bad_index, ApplicationKind::Apk).is_err());
	let mut excess = original.clone();
	excess[8 + 8..8 + 12].copy_from_slice(&65_537_u32.to_le_bytes());
	assert!(parse_manifest(&excess, ApplicationKind::Apk).is_err());
	let mut style = original.clone();
	style[8 + 12..8 + 16].copy_from_slice(&1_u32.to_le_bytes());
	assert!(parse_manifest(&style, ApplicationKind::Apk).is_err());
	let mut end_mismatch = original;
	let name_offset = end_mismatch.len() - 4;
	end_mismatch[name_offset..].copy_from_slice(&1_u32.to_le_bytes());
	assert!(parse_manifest(&end_mismatch, ApplicationKind::Apk).is_err());
}

#[test]
fn jar_main_section_validation_rejects_ambiguity_and_broken_encoding() {
	let cases: &[&[u8]] = &[
		b"Manifest-Version: 1.0\nMain-Class: A\nmain-class: B\n\n",
		b" continuation\n\n",
		b"Manifest-Version: 1.0\nName: x\n\n",
		b"Manifest-Version: 1.0\n",
		b"Main-Class: A\n\n",
		b"Manifest-Version: one\n\n",
		b"Manifest-Version: 1.0\nX: \xff\n\n",
		b"Manifest-Version: 1.0\nX: a\0b\n\n",
	];
	for bytes in cases {
		assert!(
			parse_manifest(bytes, ApplicationKind::Jar).is_err(),
			"{bytes:?}"
		);
	}
	let long = format!("Manifest-Version: 1.0\nX: {}\n\n", "a".repeat(70));
	assert!(parse_manifest(long.as_bytes(), ApplicationKind::Jar).is_err());
}

#[test]
fn jar_newline_forms_unfold_before_utf8_and_stop_before_per_entry_data() {
	for newline in ["\r\n", "\n", "\r"] {
		let bytes=format!("Manifest-Version: 1.0{newline}Main-Class: org.hepta.{newline} Fixture{newline}{newline}unparsed per-entry bytes");
		let report =
			parse_manifest(bytes.as_bytes(), ApplicationKind::Jar).expect("legal line form");
		assert_eq!(report.summary["main_class"], "org.hepta.Fixture");
		assert_eq!(report.summary["unparsed_per_entry_bytes"], 24);
	}
	let mut split = b"Manifest-Version: 1.0\nX: ".to_vec();
	split.push(0xe4);
	split.extend_from_slice(b"\n ");
	split.extend_from_slice(&[0xb8, 0xad]);
	split.extend_from_slice(b"\n\n");
	let report =
		parse_manifest(&split, ApplicationKind::Jar).expect("unfold a split UTF-8 code point");
	assert_eq!(report.attributes[1]["value"], "中");
}

#[test]
fn request_schema_limits_and_parser_deadline_are_enforced() {
	let mut request = params(ApplicationKind::Jar, ApplicationCollection::Summary);
	request.limit = 0;
	assert!(validate(&request).is_err());
	request.limit = 257;
	assert!(validate(&request).is_err());
	request.limit = 1;
	request.collection = ApplicationCollection::Components;
	assert!(validate(&request).is_err());
	assert!(serde_json::from_value::<InspectApplicationParams>(json!({
		"path":"/a","kind":"jar","arbitrary_member":"other"
	}))
	.is_err());
	assert!(parser::parse(
		b"Manifest-Version: 1.0\n\n",
		ApplicationKind::Jar,
		Instant::now() - Duration::from_secs(1)
	)
	.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn actual_file_admission_denies_outside_roots_and_symlink_components() {
	let root = tempfile::tempdir().expect("root");
	let workspace = root.path().join("workspace");
	tokio::fs::create_dir(&workspace).await.expect("workspace");
	let jar = workspace.join("owned.jar");
	tokio::fs::write(&jar, JAR).await.expect("fixture");
	let outside = root.path().join("outside.jar");
	tokio::fs::write(&outside, JAR).await.expect("outside");
	let mut request = params(ApplicationKind::Jar, ApplicationCollection::Summary);
	request.path = jar.to_string_lossy().into_owned();
	let result = inspect_with_roots(request.clone(), std::slice::from_ref(&workspace))
		.await
		.expect("admitted fixture");
	let parsed: Value = serde_json::from_str(&result).expect("report");
	assert_eq!(parsed["source"]["sha256"], sha256(JAR));
	request.path = outside.to_string_lossy().into_owned();
	assert!(
		inspect_with_roots(request.clone(), std::slice::from_ref(&workspace))
			.await
			.is_err()
	);
	let link = workspace.join("link.jar");
	std::os::unix::fs::symlink(&jar, &link).expect("test symlink");
	request.path = link.to_string_lossy().into_owned();
	assert!(inspect_with_roots(request, &[workspace]).await.is_err());
}

#[test]
fn axml_repeated_offsets_and_element_depth_have_independent_hard_budgets() {
	let text = "x".repeat(16_384);
	let mut string_data = Vec::new();
	utf8_length(&mut string_data, text.len());
	utf8_length(&mut string_data, text.len());
	string_data.extend_from_slice(text.as_bytes());
	string_data.push(0);
	while string_data.len() % 4 != 0 {
		string_data.push(0);
	}
	let count = 513_usize;
	let pool_size = 28 + count * 4 + string_data.len();
	let mut bytes = Vec::new();
	push16(&mut bytes, 3);
	push16(&mut bytes, 8);
	push32(&mut bytes, (8 + pool_size) as u32);
	push16(&mut bytes, 1);
	push16(&mut bytes, 28);
	push32(&mut bytes, pool_size as u32);
	push32(&mut bytes, count as u32);
	push32(&mut bytes, 0);
	push32(&mut bytes, 0x100);
	push32(&mut bytes, (28 + count * 4) as u32);
	push32(&mut bytes, 0);
	for _ in 0..count {
		push32(&mut bytes, 0);
	}
	bytes.extend_from_slice(&string_data);
	assert!(parse_manifest(&bytes, ApplicationKind::Apk)
		.err()
		.expect("decode budget")
		.to_string()
		.contains("8 MiB"));

	let original = utf8_axml("package", "org.hepta", false);
	let pool_length = u32::from_le_bytes(original[12..16].try_into().expect("pool size")) as usize;
	let start = 8 + pool_length;
	let start_node = &original[start..original.len() - 24];
	let end_node = &original[original.len() - 24..];
	let mut deep = original[..start].to_vec();
	for _ in 0..65 {
		deep.extend_from_slice(start_node);
	}
	for _ in 0..65 {
		deep.extend_from_slice(end_node);
	}
	let total = deep.len() as u32;
	deep[4..8].copy_from_slice(&total.to_le_bytes());
	assert!(parse_manifest(&deep, ApplicationKind::Apk)
		.err()
		.expect("depth budget")
		.to_string()
		.contains("64 element levels"));
}

#[cfg(unix)]
#[tokio::test]
async fn response_budget_rejects_large_pages_but_allows_a_smaller_selection() {
	let mut manifest = b"Manifest-Version: 1.0\r\n".to_vec();
	for index in 0..20 {
		manifest.extend_from_slice(format!("X-{index}: ").as_bytes());
		manifest.extend_from_slice(b"a\r\n");
		let value = vec![b'a'; 60_000];
		for part in value.chunks(71) {
			manifest.push(b' ');
			manifest.extend_from_slice(part);
			manifest.extend_from_slice(b"\r\n");
		}
	}
	manifest.extend_from_slice(b"\r\n");
	let bytes = zip(&[("META-INF/MANIFEST.MF", &manifest, 8)]);
	let root = tempfile::tempdir().expect("root");
	let path = root.path().join("large-main.jar");
	tokio::fs::write(&path, bytes).await.expect("source");
	let mut request = params(ApplicationKind::Jar, ApplicationCollection::Attributes);
	request.path = path.to_string_lossy().into_owned();
	request.limit = 256;
	assert!(
		inspect_with_roots(request.clone(), &[root.path().to_owned()])
			.await
			.unwrap_err()
			.to_string()
			.contains("response exceeds 1 MiB")
	);
	request.limit = 1;
	let result = inspect_with_roots(request, &[root.path().to_owned()])
		.await
		.expect("small page");
	let result: Value = serde_json::from_str(&result).expect("result");
	assert_eq!(result["total_rows"], 21);
	assert_eq!(result["rows"].as_array().expect("rows").len(), 1);
}
