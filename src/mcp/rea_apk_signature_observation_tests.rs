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

//! Actual Android fixtures and adversarial declaration/verification separation.

use super::*;

fn refusal_fixture_bytes(row: &serde_json::Value) -> Vec<u8> {
	use std::io::Read;
	let encoded = row["data"].as_str().unwrap();
	assert_eq!(row["encoding"], "zlib-hex");
	assert_eq!(encoded.len() % 2, 0);
	let compressed = encoded
		.as_bytes()
		.chunks_exact(2)
		.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect::<Vec<_>>();
	assert_eq!(
		fingerprint(&compressed),
		row["compressed_sha256"].as_str().unwrap()
	);
	let size = row["bytes"].as_u64().unwrap();
	assert!(
		size <= 8 * 1024 * 1024,
		"large file-size fixture belongs to capture tests"
	);
	let mut bytes = Vec::new();
	flate2::read::ZlibDecoder::new(compressed.as_slice())
		.take(size + 1)
		.read_to_end(&mut bytes)
		.unwrap();
	assert_eq!(bytes.len() as u64, size);
	assert_eq!(fingerprint(&bytes), row["sha256"].as_str().unwrap());
	bytes
}

#[test]
fn frozen_refusals_preserve_the_complete_original_producer_facts() {
	let input: serde_json::Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_apk_signature/service-error-bytes-r1.json"
	))
	.unwrap();
	let golden: serde_json::Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_apk_signature/service-errors-r1.json"
	))
	.unwrap();
	let cases = input["cases"].as_array().unwrap();
	assert_eq!(cases.len(), 24);
	assert_eq!(input["capture_only"].as_array().unwrap().len(), 1);
	for case in cases {
		let bytes = refusal_fixture_bytes(case);
		let expected = golden["cases"]
			.as_array()
			.unwrap()
			.iter()
			.find(|row| row["name"] == case["name"])
			.unwrap();
		let error = inspect_with_limits(&bytes, StaticLimits::REA_6_8_0).unwrap_err();
		assert_eq!(
			serde_json::to_value(error.tag).unwrap(),
			expected["typed_error"]["_tag"],
			"{}",
			case["name"]
		);
		let details = &expected["expected"]["details"];
		let reason = if error.tag == ApkErrorTag::AnalysisInputError {
			&details["issues"][0]["message"]
		} else {
			&details["reason"]
		};
		assert_eq!(
			error.reason.as_ref(),
			reason.as_str().unwrap(),
			"{}",
			case["name"]
		);
		if error.resource == Some(ApkResource::Capacity) {
			assert_eq!(
				serde_json::to_value(&error.reported_limits).unwrap(),
				details["reported_limits"],
				"{}",
				case["name"]
			);
		}
		if error.tag == ApkErrorTag::AnalysisUnsupportedTargetError {
			assert_eq!(
				error.remediation_action.as_deref().map(String::as_str),
				expected["typed_error"]["remediationAction"].as_str(),
				"{}",
				case["name"]
			);
		}
	}
}

#[test]
fn legacy_profile_preserves_the_observed_pre_change_results() {
	let input: serde_json::Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_apk_signature/service-error-bytes-r1.json"
	))
	.unwrap();
	assert_eq!(
		input["legacy_baseline_binary_sha256"],
		"9399f9799852deba4f03c9616a424326cbeb0ac008d74c76e083498bc9707558"
	);
	for case in input["cases"].as_array().unwrap() {
		let bytes = refusal_fixture_bytes(case);
		let result = match inspect(&bytes) {
			Ok(value) => serde_json::json!({"ok": true, "value": value}),
			Err(error) => serde_json::json!({"ok": false, "error": error}),
		};
		let expected = input["legacy_expected"]
			.as_array()
			.unwrap()
			.iter()
			.find(|row| row["name"] == case["name"])
			.unwrap();
		assert_eq!(result, expected["result"], "{}", case["name"]);
	}
}

#[test]
fn path_binding_counts_the_entire_utf8_json_at_the_frozen_boundary() {
	let mut inspection = inspect_with_limits(CUSTOM, StaticLimits::REA_6_8_0).unwrap();
	inspection.result.artifact.path = Some(String::new());
	let limit = StaticLimits::REA_6_8_0.output_bytes;
	let fill = limit - serialized_output_bytes(&inspection).unwrap();
	inspection.limitations.push("x".repeat(fill - 3));
	assert_eq!(serialized_output_bytes(&inspection).unwrap(), limit);
	// The counter includes the escaped quote and the four UTF-8 bytes of the
	// supplementary scalar, not the source string's scalar or UTF-16 count.
	let path = "/\"\u{10000}";
	inspection
		.limitations
		.last_mut()
		.unwrap()
		.truncate(fill - 10);
	let bound = bind_static_path(inspection.clone(), path).unwrap();
	assert_eq!(serialized_output_bytes(&bound).unwrap(), limit);
	assert_eq!(serde_json::to_vec(&bound).unwrap().len(), limit);
	let error = bind_static_path(inspection, &format!("{path}a")).unwrap_err();
	assert_eq!(error.tag, ApkErrorTag::AnalysisResourceConstraintError);
	assert_eq!(error.resource, Some(ApkResource::Capacity));
	assert_eq!(
		*error.reported_limits,
		BTreeMap::from([("max_output_bytes".into(), limit)])
	);
	assert_eq!(
		error.reason.as_ref(),
		format!(
			"The decoded signing report ({} bytes) exceeds the {limit}-byte output budget.",
			limit + 1
		)
	);
}

const CUSTOM: &[u8] = include_bytes!("../../tests/fixtures/rea_apk_signature/custom-0103-rsa.apk");
const V1_APK: &[u8] = include_bytes!("../../tests/fixtures/rea_apk_signature/v1-v2-v3.apk");
const ROTATED: &[u8] = include_bytes!("../../tests/fixtures/rea_apk_signature/rotation-v31.apk");

fn tlv(tag: u8, bytes: &[u8]) -> Vec<u8> {
	let mut result = vec![tag];
	if bytes.len() < 128 {
		result.push(bytes.len() as u8);
	} else {
		let encoded = (bytes.len() as u32).to_be_bytes();
		let start = encoded.iter().position(|b| *b != 0).unwrap();
		result.push(0x80 | (4 - start) as u8);
		result.extend(&encoded[start..]);
	}
	result.extend(bytes);
	result
}

fn certificate() -> Vec<u8> {
	let tail = archive::zip_tail(CUSTOM, StaticLimits::LEGACY).unwrap();
	let block = archive::signing_block(CUSTOM, &tail, StaticLimits::LEGACY).unwrap();
	scheme(&block, V2, "v2", StaticLimits::LEGACY)
		.unwrap()
		.signers[0]
		.certificate
		.unwrap()
		.to_vec()
}

fn certificate_field(cert: &[u8], index: usize, replacement: &[u8]) -> Vec<u8> {
	let root = certificate::BerReader::new(cert)
		.read(0, cert.len(), 0)
		.unwrap();
	let fields = &root.children[0].children;
	let offset = usize::from(fields[0].tag == 0xa0);
	let body = fields
		.iter()
		.enumerate()
		.flat_map(|(at, node)| {
			if at == offset + index {
				replacement.to_vec()
			} else {
				node.full.to_vec()
			}
		})
		.collect::<Vec<_>>();
	tlv(
		0x30,
		&[
			tlv(0x30, &body),
			root.children[1].full.to_vec(),
			root.children[2].full.to_vec(),
		]
		.concat(),
	)
}

fn cms() -> Vec<u8> {
	let cert = certificate();
	let root = certificate::BerReader::new(&cert)
		.read(0, cert.len(), 0)
		.unwrap();
	let fields = &root.children[0].children;
	let offset = usize::from(fields[0].tag == 0xa0);
	let sha256 = tlv(0x30, &tlv(0x06, b"\x60\x86\x48\x01\x65\x03\x04\x02\x01"));
	let rsa = tlv(0x30, &tlv(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"));
	let signer = tlv(
		0x30,
		&[
			tlv(2, &[1]),
			tlv(
				0x30,
				&[fields[offset + 2].full, fields[offset].full].concat(),
			),
			sha256.clone(),
			rsa,
			tlv(4, b"declared-only-not-a-signature"),
		]
		.concat(),
	);
	let signed = tlv(
		0x30,
		&[
			tlv(2, &[1]),
			tlv(0x31, &sha256),
			tlv(0x30, &tlv(6, b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01")),
			tlv(0xa0, &cert),
			tlv(0x31, &signer),
		]
		.concat(),
	);
	tlv(
		0x30,
		&[
			tlv(6, b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02"),
			tlv(0xa0, &signed),
		]
		.concat(),
	)
}

fn zip(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
	let mut bytes = Vec::new();
	let mut directory = Vec::new();
	for (name, data) in entries {
		let offset = bytes.len() as u32;
		let mut local = vec![0; 30];
		local[..4].copy_from_slice(b"PK\x03\x04");
		local[18..22].copy_from_slice(&(data.len() as u32).to_le_bytes());
		local[22..26].copy_from_slice(&(data.len() as u32).to_le_bytes());
		local[26..28].copy_from_slice(&(name.len() as u16).to_le_bytes());
		bytes.extend(local);
		bytes.extend(*name);
		bytes.extend(*data);
		let mut central = vec![0; 46];
		central[..4].copy_from_slice(b"PK\x01\x02");
		central[20..24].copy_from_slice(&(data.len() as u32).to_le_bytes());
		central[24..28].copy_from_slice(&(data.len() as u32).to_le_bytes());
		central[28..30].copy_from_slice(&(name.len() as u16).to_le_bytes());
		central[42..46].copy_from_slice(&offset.to_le_bytes());
		directory.extend(central);
		directory.extend(*name);
	}
	let central = bytes.len();
	let size = directory.len();
	bytes.extend(directory);
	let mut end = vec![0; 22];
	end[..4].copy_from_slice(b"PK\x05\x06");
	end[8..10].copy_from_slice(&(entries.len() as u16).to_le_bytes());
	end[10..12].copy_from_slice(&(entries.len() as u16).to_le_bytes());
	end[12..16].copy_from_slice(&(size as u32).to_le_bytes());
	end[16..20].copy_from_slice(&(central as u32).to_le_bytes());
	bytes.extend(end);
	bytes
}

fn rebuild(pairs: &[(u32, Vec<u8>)]) -> Vec<u8> {
	let tail = archive::zip_tail(CUSTOM, StaticLimits::LEGACY).unwrap();
	let old = archive::signing_block(CUSTOM, &tail, StaticLimits::LEGACY)
		.unwrap()
		.unwrap();
	let mut values = Vec::new();
	for (id, bytes) in pairs {
		values.extend(((bytes.len() + 4) as u64).to_le_bytes());
		values.extend(id.to_le_bytes());
		values.extend(bytes);
	}
	let size = (values.len() + 24) as u64;
	let mut bytes = CUSTOM[..old.start].to_vec();
	bytes.extend(size.to_le_bytes());
	bytes.extend(values);
	bytes.extend(size.to_le_bytes());
	bytes.extend(b"APK Sig Block 42");
	let central = bytes.len();
	bytes.extend(&CUSTOM[tail.central..tail.eocd]);
	let mut end = CUSTOM[tail.eocd..].to_vec();
	end[16..20].copy_from_slice(&(central as u32).to_le_bytes());
	bytes.extend(end);
	bytes
}

#[test]
fn real_android_v1_and_v31_declarations_are_complete_typed_observations() {
	let observed = inspect(V1_APK).unwrap();
	let v1 = &observed.result.schemes.v1;
	assert!(v1.present && v1.has_manifest);
	assert_eq!(v1.signers.len(), 1);
	let signer = &v1.signers[0];
	assert!(signer.decode_error.is_none());
	assert_eq!(
		signer.signer_infos[0].identified_by,
		SignerIdentifier::IssuerAndSerial
	);
	let cert = signer.certificate.as_ref().unwrap();
	assert_eq!(
		signer.signer_infos[0].certificate_sha256.as_deref(),
		Some(cert.sha256_fingerprint.as_str())
	);
	assert_eq!(cert.public_key_algorithm.as_deref(), Some("rsa"));
	assert_eq!(cert.serial_number.as_deref(), Some("11"));
	assert_eq!(
		observed.result.posture.v1_signers_match_block_signers,
		Some(true)
	);
	assert_eq!(observed.result.posture.self_consistent, Some(true));
	let observed = inspect(ROTATED).unwrap();
	assert!(observed.result.schemes.v3_1.present);
	assert_eq!(
		observed.result.posture.strongest_scheme,
		StrongestScheme::V31
	);
	let lineage = &observed.result.schemes.v3_1.signers[0].rotation;
	assert!(lineage.present && lineage.decode_error.is_none());
	assert_eq!(lineage.lineage.len(), 2);
	assert_eq!(
		observed.result.posture.signer_change_declared_by_rotation,
		Some(true)
	);
	assert_eq!(
		observed.result.runtime_execution,
		RuntimeExecution::NotPerformed
	);
	let json = serde_json::to_value(&observed).unwrap();
	assert_eq!(
		serde_json::from_value::<ApkStaticInspection>(json).unwrap(),
		observed
	);
}

#[test]
fn declared_signers_survive_extra_crypto_refusal_without_a_verification_pass() {
	let tail = archive::zip_tail(CUSTOM, StaticLimits::LEGACY).unwrap();
	let block = archive::signing_block(CUSTOM, &tail, StaticLimits::LEGACY)
		.unwrap()
		.unwrap();
	let pair = block.pairs.iter().find(|(id, _)| *id == V2).unwrap();
	let changed = rebuild(&[(pair.0, pair.1.to_vec()), (pair.0, pair.1.to_vec())]);
	assert!(super::super::parser::inspect(&changed).is_err());
	let declared = inspect(&changed).unwrap();
	assert_eq!(declared.result.schemes.v2.signers.len(), 1);
	assert_eq!(declared.result.posture.self_consistent, Some(true));
	let report = super::super::parser::inspect_with_observations(&changed).unwrap();
	assert_eq!(
		report["cryptographic_inspection"]["status"],
		"not_performed"
	);
	assert_eq!(report["verification"]["v2_v3_records"], "not_performed");
	assert_eq!(
		report["verification"]["complete_android_verification"],
		false
	);
	assert_eq!(
		report["static_inspection"]["result"]["schemes"]["v2"]["signers"]
			.as_array()
			.unwrap()
			.len(),
		1
	);
}

#[test]
fn one_damaged_pkcs7_block_does_not_hide_an_independent_declared_signer() {
	let block = cms();
	let bytes = zip(&[
		(b"META-INF/MANIFEST.MF", b""),
		(b"META-INF/GOOD.SF", b""),
		(b"META-INF/GOOD.RSA", &block),
		(b"META-INF/BAD.SF", b""),
		(b"META-INF/BAD.RSA", b"\x30\x80"),
	]);
	let observed = inspect(&bytes).unwrap();
	let signers = &observed.result.schemes.v1.signers;
	assert_eq!(signers.len(), 2);
	assert!(signers[0].decode_error.is_none());
	assert_eq!(
		signers[0].certificate.as_ref().unwrap().sha256_fingerprint,
		fingerprint(&certificate())
	);
	assert!(
		signers[1]
			.decode_error
			.as_ref()
			.unwrap()
			.contains("Indefinite ASN.1 value has no end-of-contents marker")
	);
	assert!(signers[1].certificate.is_none());
	assert!(observed.result.posture.v1_only);
	assert_eq!(observed.result.posture.self_consistent, None);
}

#[test]
fn v1_pairing_is_case_sensitive_and_duplicate_metadata_preserves_unknown() {
	let block = cms();
	let bytes = zip(&[(b"META-INF/GOOD.sf", b""), (b"META-INF/GOOD.RSA", &block)]);
	let result = inspect(&bytes).unwrap();
	assert!(!result.result.schemes.v1.present);
	assert_eq!(result.result.schemes.v1.block_files, ["META-INF/GOOD.RSA"]);
	let bytes = zip(&[
		(b"META-INF/GOOD.SF", b""),
		(b"META-INF/GOOD.SF", b""),
		(b"META-INF/GOOD.RSA", &block),
	]);
	let result = inspect(&bytes).unwrap();
	assert!(result.result.schemes.v1.present);
	assert_eq!(
		result.result.schemes.v1.signers[0].decode_error.as_deref(),
		Some("duplicate entry: META-INF/GOOD.SF")
	);
	assert!(
		result
			.limitations
			.iter()
			.any(|note| note.contains("Duplicate entry"))
	);
}

#[test]
fn java_name_replacement_does_not_split_an_encoded_surrogate() {
	for (raw, expected) in [
		(b"a\xed\xa0\x80b".as_slice(), "a\u{fffd}b"),
		(b"\xed\xa0".as_slice(), "\u{fffd}"),
		(b"\xe0\x80\x80".as_slice(), "\u{fffd}\u{fffd}\u{fffd}"),
		(b"\xf0\x90\x80".as_slice(), "\u{fffd}"),
		(b"\xef\xbb\xbfZ".as_slice(), "\u{feff}Z"),
	] {
		assert_eq!(archive::java_name(raw), expected);
	}
}

#[test]
fn certificate_offsets_are_normalized_before_emitting_utc_dates() {
	let cert = certificate();
	let root = certificate::BerReader::new(&cert)
		.read(0, cert.len(), 0)
		.unwrap();
	let fields = &root.children[0].children;
	let offset = usize::from(fields[0].tag == 0xa0);
	let not_after = fields[offset + 3].children[1].full;
	for (tag, encoded, expected) in [
		(
			0x17,
			b"261104010203+0100".as_slice(),
			"2026-11-04T00:02:03.000Z",
		),
		(
			0x17,
			b"261104000203+0100".as_slice(),
			"2026-11-03T23:02:03.000Z",
		),
		(
			0x17,
			b"000101000000+0200".as_slice(),
			"1999-12-31T22:00:00.000Z",
		),
		(
			0x17,
			b"000301000000+0200".as_slice(),
			"2000-02-29T22:00:00.000Z",
		),
		(
			0x17,
			b"991231230000-0200".as_slice(),
			"2000-01-01T01:00:00.000Z",
		),
		(
			0x18,
			b"20500101000000-0100".as_slice(),
			"2050-01-01T01:00:00.000Z",
		),
	] {
		let validity = tlv(0x30, &[tlv(tag, encoded), not_after.to_vec()].concat());
		let modified = certificate_field(&cert, 3, &validity);
		let facts = certificate::facts(&modified);
		assert_eq!(facts.not_before.as_deref(), Some(expected));
		assert_eq!(facts.serial_number.as_deref(), Some("11"));
		assert_eq!(facts.public_key_algorithm.as_deref(), Some("rsa"));
	}
}

#[test]
fn unreadable_public_key_does_not_hide_other_certificate_facts() {
	let cert = certificate();
	let signature = |algorithm: Vec<u8>, key: Vec<u8>| {
		tlv(
			0x30,
			&[tlv(0x30, &algorithm), tlv(3, &[vec![0], key].concat())].concat(),
		)
	};
	let ec = tlv(6, b"\x2a\x86\x48\xce\x3d\x02\x01");
	let p256 = tlv(6, b"\x2a\x86\x48\xce\x3d\x03\x01\x07");
	let rsa = tlv(6, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01");
	let ed25519 = tlv(6, b"\x2b\x65\x70");
	for key in [
		signature(
			[ec.clone(), p256.clone()].concat(),
			[vec![4], vec![0; 64]].concat(),
		),
		signature([ec, p256].concat(), vec![4, 1]),
		signature(rsa.clone(), tlv(0x30, &tlv(2, &[1]).repeat(3))),
		signature([ed25519, tlv(5, &[])].concat(), vec![1; 32]),
	] {
		let modified = certificate_field(&cert, 5, &key);
		let facts = certificate::facts(&modified);
		assert_eq!(facts.sha256_fingerprint, fingerprint(&modified));
		assert_eq!(facts.subject.as_deref(), Some("CN=Hepta APK test rsa"));
		assert_eq!(facts.serial_number.as_deref(), Some("11"));
		assert_eq!(facts.public_key_algorithm, None);
	}
	let inner = [
		tlv(0x30, &[tlv(2, &[1]), tlv(2, &[3])].concat()),
		b"accepted inner suffix".to_vec(),
	]
	.concat();
	let modified = certificate_field(&cert, 5, &signature(rsa, inner));
	assert_eq!(
		certificate::facts(&modified)
			.public_key_algorithm
			.as_deref(),
		Some("rsa")
	);
}

#[test]
fn typed_global_refusals_separate_format_damage_and_fixed_capacity() {
	for bytes in [b"".as_slice(), b"not a zip"] {
		assert_eq!(
			inspect(bytes).unwrap_err().tag,
			ApkErrorTag::AnalysisUnsupportedTargetError
		);
	}
	let mut truncated = b"PK\x03\x04".to_vec();
	truncated.extend([0; 30]);
	assert_eq!(
		inspect(&truncated).unwrap_err().tag,
		ApkErrorTag::AnalysisInputError
	);
	let bytes = rebuild(&(0..129).map(|id| (id, Vec::new())).collect::<Vec<_>>());
	let error = inspect(&bytes).unwrap_err();
	assert_eq!(error.tag, ApkErrorTag::AnalysisResourceConstraintError);
	assert_eq!(error.reported_limits["max_signing_block_pairs"], 128);
	let value = serde_json::to_value(&error).unwrap();
	assert_eq!(
		serde_json::from_value::<ApkInspectionError>(value).unwrap(),
		error
	);
}

fn zip64_directory(bytes: &[u8], classic_count: u16) -> Vec<u8> {
	let tail = archive::zip_tail(bytes, StaticLimits::REA_6_8_0).unwrap();
	let mut result = bytes[..tail.eocd].to_vec();
	result.extend(0x0606_4b50u32.to_le_bytes());
	result.extend(44u64.to_le_bytes());
	result.extend(45u16.to_le_bytes());
	result.extend(45u16.to_le_bytes());
	result.extend([0; 8]);
	result.extend((tail.count as u64).to_le_bytes());
	result.extend((tail.count as u64).to_le_bytes());
	result.extend((tail.central_size as u64).to_le_bytes());
	result.extend((tail.central as u64).to_le_bytes());
	result.extend(0x0706_4b50u32.to_le_bytes());
	result.extend(0u32.to_le_bytes());
	result.extend((tail.eocd as u64).to_le_bytes());
	result.extend(1u32.to_le_bytes());
	let mut end = bytes[tail.eocd..].to_vec();
	end[8..10].copy_from_slice(&classic_count.to_le_bytes());
	end[10..12].copy_from_slice(&classic_count.to_le_bytes());
	end[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
	result.extend(end);
	result
}

#[test]
fn frozen_profile_does_not_inherit_legacy_pair_or_directory_limits() {
	let pairs = (0..4096).map(|id| (id, Vec::new())).collect::<Vec<_>>();
	let bytes = rebuild(&pairs);
	assert_eq!(
		inspect(&bytes).unwrap_err().reported_limits["max_signing_block_pairs"],
		128
	);
	assert!(inspect_with_limits(&bytes, StaticLimits::REA_6_8_0).is_ok());
	let too_many = rebuild(&[pairs, vec![(4096, Vec::new())]].concat());
	assert_eq!(
		inspect_with_limits(&too_many, StaticLimits::REA_6_8_0)
			.unwrap_err()
			.reported_limits["max_signing_block_pairs"],
		4096
	);
	let bytes = zip(&vec![(b"not-metadata".as_slice(), b"".as_slice()); 50_001]);
	assert_eq!(
		inspect(&bytes).unwrap_err().reported_limits["max_zip_entries"],
		50_000
	);
	let observed = inspect_with_limits(&bytes, StaticLimits::REA_6_8_0).unwrap();
	assert!(!observed.result.schemes.v1.present);
	assert!(
		observed
			.limitations
			.iter()
			.any(|note| note.contains("1 name more than once"))
	);
}

#[test]
fn zip64_read_scope_does_not_change_the_frozen_metadata_pairing_rule() {
	let block = cms();
	let plain = zip(&[
		(b"META-INF/MANIFEST.MF", b""),
		(b"META-INF/GOOD.SF", b""),
		(b"META-INF/GOOD.RSA", &block),
		(b"META-INF/GOOD.SF", b""),
	]);
	let bytes = zip64_directory(&plain, 3);
	let observed = inspect_with_limits(&bytes, StaticLimits::REA_6_8_0).unwrap();
	assert!(observed.result.schemes.v1.present);
	assert_eq!(
		observed.result.schemes.v1.signers[0]
			.decode_error
			.as_deref(),
		Some("duplicate entry: META-INF/GOOD.SF")
	);
	assert!(observed.result.schemes.v1.signers[0].certificate.is_none());
	assert!(
		observed
			.limitations
			.iter()
			.any(|note| note.contains("only the first 3 of the 4")
				&& note.contains("duplicated only by records past those"))
	);
	let bytes = zip64_directory(&plain, 4);
	assert_eq!(
		inspect_with_limits(&bytes, StaticLimits::REA_6_8_0)
			.unwrap()
			.result
			.schemes
			.v1
			.signers[0]
			.decode_error
			.as_deref(),
		Some("duplicate entry: META-INF/GOOD.SF")
	);
}

#[test]
fn complete_preflight_counts_and_later_structure_errors_match_the_original_service() {
	let fixture: serde_json::Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_apk_signature/preflight-errors-r1.json"
	))
	.unwrap();
	assert_eq!(
		fixture["frozen_npm_tarball_sha256"],
		"8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb"
	);
	let cases = fixture["cases"].as_array().unwrap();
	assert_eq!(cases.len(), 4);
	let mut capacities = 0;
	let mut structural_errors = 0;
	for case in cases {
		let bytes = refusal_fixture_bytes(case);
		let expected = &case["reference"];
		let error = inspect_with_limits(&bytes, StaticLimits::REA_6_8_0).unwrap_err();
		assert_eq!(
			serde_json::to_value(error.tag).unwrap(),
			expected["typed_error"]["_tag"],
			"{}",
			case["name"]
		);
		let details = &expected["expected"]["details"];
		match error.tag {
			ApkErrorTag::AnalysisInputError => {
				structural_errors += 1;
				assert_eq!(
					error.reason.as_ref(),
					details["issues"][0]["message"].as_str().unwrap(),
					"{}",
					case["name"]
				);
				assert_eq!(error.scheme.as_deref(), Some("v3"));
				assert!(error.reported_limits.is_empty());
			}
			ApkErrorTag::AnalysisResourceConstraintError => {
				capacities += 1;
				assert_eq!(error.resource, Some(ApkResource::Capacity));
				assert_eq!(
					error.reason.as_ref(),
					details["reason"].as_str().unwrap(),
					"{}",
					case["name"]
				);
				assert_eq!(
					serde_json::to_value(&error.reported_limits).unwrap(),
					details["reported_limits"],
					"{}",
					case["name"]
				);
			}
			other => panic!("unexpected original classification {other:?}"),
		}
	}
	assert_eq!((capacities, structural_errors), (2, 2));
}
