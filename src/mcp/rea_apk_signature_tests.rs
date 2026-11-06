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

//! Real Android/OpenSSL producers, independently computed expected digests,
//! adversarial mutations, finite parsing budgets and confined source admission.

use super::*;
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};

const V2: u32 = 0x7109_871a;
const V3: u32 = 0xf053_68c0;
const RSA: &[u8] = include_bytes!("../../tests/fixtures/rea_apk_signature/rsa-v2-v3.apk");
const CUSTOM: &[u8] = include_bytes!("../../tests/fixtures/rea_apk_signature/custom-0103-rsa.apk");
const FIXTURES: &[(&str, &[u8])] = &[
	(
		"rsa-v2.apk",
		include_bytes!("../../tests/fixtures/rea_apk_signature/rsa-v2.apk"),
	),
	("rsa-v2-v3.apk", RSA),
	(
		"ecdsa-v2-v3.apk",
		include_bytes!("../../tests/fixtures/rea_apk_signature/ecdsa-v2-v3.apk"),
	),
	(
		"v1-only.apk",
		include_bytes!("../../tests/fixtures/rea_apk_signature/v1-only.apk"),
	),
	(
		"v1-v2-v3.apk",
		include_bytes!("../../tests/fixtures/rea_apk_signature/v1-v2-v3.apk"),
	),
	(
		"chunk-boundary.apk",
		include_bytes!("../../tests/fixtures/rea_apk_signature/chunk-boundary.apk"),
	),
	(
		"custom-0101-rsa.apk",
		include_bytes!("../../tests/fixtures/rea_apk_signature/custom-0101-rsa.apk"),
	),
	(
		"custom-0102-rsa.apk",
		include_bytes!("../../tests/fixtures/rea_apk_signature/custom-0102-rsa.apk"),
	),
	("custom-0103-rsa.apk", CUSTOM),
	(
		"custom-0103-rsa1024.apk",
		include_bytes!("../../tests/fixtures/rea_apk_signature/custom-0103-rsa1024.apk"),
	),
	(
		"custom-0103-rsa34.apk",
		include_bytes!("../../tests/fixtures/rea_apk_signature/custom-0103-rsa34.apk"),
	),
	(
		"custom-0103-rsa33.apk",
		include_bytes!("../../tests/fixtures/rea_apk_signature/custom-0103-rsa33.apk"),
	),
	(
		"custom-0103-rsa34audit.apk",
		include_bytes!("../../tests/fixtures/rea_apk_signature/custom-0103-rsa34audit.apk"),
	),
	(
		"custom-0104-rsa.apk",
		include_bytes!("../../tests/fixtures/rea_apk_signature/custom-0104-rsa.apk"),
	),
	(
		"custom-0201-p384.apk",
		include_bytes!("../../tests/fixtures/rea_apk_signature/custom-0201-p384.apk"),
	),
	(
		"custom-0202-p521.apk",
		include_bytes!("../../tests/fixtures/rea_apk_signature/custom-0202-p521.apk"),
	),
	(
		"two-signers-v2.apk",
		include_bytes!("../../tests/fixtures/rea_apk_signature/two-signers-v2.apk"),
	),
	(
		"rotation-v3.apk",
		include_bytes!("../../tests/fixtures/rea_apk_signature/rotation-v3.apk"),
	),
	(
		"rotation-v31.apk",
		include_bytes!("../../tests/fixtures/rea_apk_signature/rotation-v31.apk"),
	),
];

fn word(bytes: &[u8], at: usize) -> usize {
	u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize
}

fn lp(bytes: &[u8]) -> Vec<u8> {
	let mut result = (bytes.len() as u32).to_le_bytes().to_vec();
	result.extend(bytes);
	result
}

fn take_lp(bytes: &[u8], at: &mut usize) -> Vec<u8> {
	let len = word(bytes, *at);
	let start = *at + 4;
	*at = start + len;
	bytes[start..*at].to_vec()
}

fn layout(bytes: &[u8]) -> (usize, usize, usize) {
	let end = bytes.windows(4).rposition(|b| b == b"PK\x05\x06").unwrap();
	let central = word(bytes, end + 16);
	let size = u64::from_le_bytes(bytes[central - 24..central - 16].try_into().unwrap()) as usize;
	(central - size - 8, central, end)
}

fn pairs(bytes: &[u8]) -> Vec<(u32, Vec<u8>)> {
	let (start, central, _) = layout(bytes);
	let mut at = start + 8;
	let mut result = Vec::new();
	while at < central - 24 {
		let len = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap()) as usize;
		result.push((
			word(bytes, at + 8) as u32,
			bytes[at + 12..at + 8 + len].to_vec(),
		));
		at += 8 + len;
	}
	result
}

fn rebuild(bytes: &[u8], values: &[(u32, Vec<u8>)], trailing: &[u8]) -> Vec<u8> {
	let (start, central, end) = layout(bytes);
	let mut entries = Vec::new();
	for (id, value) in values {
		entries.extend(((value.len() + 4) as u64).to_le_bytes());
		entries.extend(id.to_le_bytes());
		entries.extend(value);
	}
	entries.extend(trailing);
	let size = ((entries.len() + 24) as u64).to_le_bytes();
	let mut out = bytes[..start].to_vec();
	out.extend(size);
	out.extend(entries);
	out.extend(size);
	out.extend(b"APK Sig Block 42");
	let new_central = out.len();
	out.extend(&bytes[central..end]);
	let mut ending = bytes[end..].to_vec();
	ending[16..20].copy_from_slice(&(new_central as u32).to_le_bytes());
	out.extend(ending);
	out
}

#[derive(Clone)]
struct RawSigner {
	data: Vec<u8>,
	sdk: Vec<u8>,
	signatures: Vec<u8>,
	key: Vec<u8>,
}

impl RawSigner {
	fn encode(&self) -> Vec<u8> {
		[
			lp(&self.data),
			self.sdk.clone(),
			lp(&self.signatures),
			lp(&self.key),
		]
		.concat()
	}
}

fn raw_signers(value: &[u8], v3: bool) -> Vec<RawSigner> {
	let list = take_lp(value, &mut 0);
	let mut at = 0;
	let mut result = Vec::new();
	while at < list.len() {
		let encoded = take_lp(&list, &mut at);
		let mut p = 0;
		let data = take_lp(&encoded, &mut p);
		let sdk = if v3 {
			let bytes = encoded[p..p + 8].to_vec();
			p += 8;
			bytes
		} else {
			Vec::new()
		};
		let signatures = take_lp(&encoded, &mut p);
		let key = take_lp(&encoded, &mut p);
		assert_eq!(p, encoded.len());
		result.push(RawSigner {
			data,
			sdk,
			signatures,
			key,
		});
	}
	result
}

fn edit_signers(bytes: &[u8], id: u32, edit: impl FnOnce(&mut Vec<RawSigner>)) -> Vec<u8> {
	let mut values = pairs(bytes);
	let item = values.iter_mut().find(|item| item.0 == id).unwrap();
	let mut signers = raw_signers(&item.1, id == V3);
	edit(&mut signers);
	item.1 = lp(&signers
		.iter()
		.flat_map(|s| lp(&s.encode()))
		.collect::<Vec<_>>());
	rebuild(bytes, &values, &[])
}

fn assert_invalid(bytes: &[u8]) -> Value {
	let report = parser::inspect(bytes).unwrap();
	assert_eq!(report["verification"]["v2_v3_records"], "invalid");
	assert_eq!(
		report["verification"]["complete_android_verification"],
		false
	);
	report
}

#[test]
fn android_and_independent_producers_match_frozen_digest_expectations() {
	let provenance: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_apk_signature/provenance.json"
	))
	.unwrap();
	for (name, bytes) in FIXTURES {
		let expected = provenance["fixtures"]
			.as_array()
			.unwrap()
			.iter()
			.find(|v| v["file"] == *name)
			.unwrap();
		let report = parser::inspect(bytes).unwrap_or_else(|error| panic!("{name}: {error:#}"));
		assert_eq!(report["source"]["sha256"], expected["sha256"], "{name}");
		assert_eq!(
			report["source"]["byte_length"], expected["byte_length"],
			"{name}"
		);
		assert_eq!(expected["apksigner_verify_exit"], 0);
		let status = match *name {
			"v1-only.apk" => "absent",
			"custom-0202-p521.apk"
			| "custom-0103-rsa1024.apk"
			| "custom-0103-rsa34.apk"
			| "custom-0103-rsa34audit.apk" => "partial",
			_ => "verified",
		};
		assert_eq!(report["verification"]["v2_v3_records"], status, "{name}");
		assert_eq!(
			report["verification"]["complete_android_verification"],
			false
		);
		assert_eq!(
			report["verification"]["android_installability"],
			"not_evaluated"
		);
		if report["signing_block"]["present"] == true {
			assert_eq!(
				report["computed_content_digests"]["chunked_sha256"],
				expected["independent_chunked_sha256"],
				"{name}"
			);
			assert_eq!(
				report["computed_content_digests"]["chunked_sha512"],
				expected["independent_chunked_sha512"],
				"{name}"
			);
		}
		for signer in report["signers"].as_array().unwrap() {
			assert_eq!(signer["certificate_public_key_binding"], "match");
			assert_eq!(signer["certificate_trust"], "not_evaluated");
			for algorithm in signer["algorithms"].as_array().unwrap() {
				assert_eq!(algorithm["content_digest_status"], "match");
				assert_eq!(
					algorithm["signature_status"],
					if status == "partial" {
						"unsupported"
					} else {
						"verified"
					}
				);
			}
		}
	}
}

#[test]
fn real_v2_reserved_signed_bytes_are_retained_and_authenticated() {
	let report = parser::inspect(RSA).unwrap();
	assert_eq!(report["signers"][0]["uninterpreted_signed_data_bytes"], 4);
	let forged = edit_signers(RSA, V2, |s| {
		*s[0].data.last_mut().unwrap() ^= 1;
	});
	let report = assert_invalid(&forged);
	assert_eq!(
		report["signers"][0]["algorithms"][0]["content_digest_status"],
		"match"
	);
	assert_eq!(
		report["signers"][0]["algorithms"][0]["signature_status"],
		"invalid"
	);
}

#[test]
fn multiple_real_signers_and_rotation_keep_their_explicit_scope() {
	let fixture = |name| FIXTURES.iter().find(|(n, _)| *n == name).unwrap().1;
	let report = parser::inspect(fixture("two-signers-v2.apk")).unwrap();
	assert_eq!(report["signers"].as_array().unwrap().len(), 2);
	assert_ne!(
		report["signers"][0]["certificates"][0]["sha256"],
		report["signers"][1]["certificates"][0]["sha256"]
	);
	let report = parser::inspect(fixture("rotation-v3.apk")).unwrap();
	assert_eq!(
		report["verification"]["rotation_lineage"],
		"present_unverified"
	);
	let report = parser::inspect(fixture("rotation-v31.apk")).unwrap();
	assert_eq!(report["verification"]["v3_1"], "present_unverified");
	assert_ne!(report["verification"]["rotation_lineage"], "absent");
	let report = parser::inspect(fixture("v1-only.apk")).unwrap();
	assert_eq!(report["verification"]["v1"], "markers_present_unverified");
	assert!(report["signers"].as_array().unwrap().is_empty());
}

#[test]
fn payload_tampering_is_not_confused_with_signature_tampering() {
	let mut changed = CUSTOM.to_vec();
	let name = u16::from_le_bytes(changed[26..28].try_into().unwrap()) as usize;
	let extra = u16::from_le_bytes(changed[28..30].try_into().unwrap()) as usize;
	changed[30 + name + extra] ^= 1;
	let report = assert_invalid(&changed);
	assert_eq!(
		report["signers"][0]["algorithms"][0]["signature_status"],
		"verified"
	);
	assert_eq!(
		report["signers"][0]["algorithms"][0]["content_digest_status"],
		"mismatch"
	);
	let changed = edit_signers(CUSTOM, V2, |s| {
		*s[0].signatures.last_mut().unwrap() ^= 1;
	});
	let report = assert_invalid(&changed);
	assert_eq!(
		report["signers"][0]["algorithms"][0]["signature_status"],
		"invalid"
	);
	assert_eq!(
		report["signers"][0]["algorithms"][0]["content_digest_status"],
		"match"
	);
}

#[test]
fn forged_matching_declaration_still_requires_a_real_signature() {
	let bytes = include_bytes!("../../tests/fixtures/rea_apk_signature/forged-matching-digest.apk");
	let report = assert_invalid(bytes);
	assert_eq!(
		report["signers"][0]["algorithms"][0]["signature_status"],
		"invalid"
	);
	assert_eq!(
		report["signers"][0]["algorithms"][0]["content_digest_status"],
		"match"
	);
}

#[test]
fn certificate_key_binding_is_checked_independently() {
	let changed = edit_signers(CUSTOM, V2, |s| {
		let len = s[0].key.len();
		s[0].key[len - 12] ^= 1;
	});
	let report = assert_invalid(&changed);
	assert_eq!(
		report["signers"][0]["certificate_public_key_binding"],
		"mismatch"
	);
	assert_eq!(
		report["signers"][0]["algorithms"][0]["content_digest_status"],
		"match"
	);
}

#[test]
fn v3_signed_sdk_copies_and_v2_stripping_protection_are_checked() {
	let changed = edit_signers(RSA, V3, |s| {
		s[0].sdk[0] ^= 1;
	});
	let report = assert_invalid(&changed);
	let v3 = report["signers"]
		.as_array()
		.unwrap()
		.iter()
		.find(|s| s["scheme"] == "v3")
		.unwrap();
	assert_eq!(v3["signed_and_unsigned_sdk_ranges_match"], false);
	assert_eq!(v3["algorithms"][0]["signature_status"], "verified");
	let remaining = pairs(RSA)
		.into_iter()
		.filter(|(id, _)| *id != V3)
		.collect::<Vec<_>>();
	let report = assert_invalid(&rebuild(RSA, &remaining, &[]));
	assert!(report["signers"][0]["additional_attributes"]
		.as_array()
		.unwrap()
		.iter()
		.any(|a| a["interpretation"] == "v3_presence_requirement_missing"));
}

#[test]
fn algorithm_order_duplicates_and_unknown_algorithms_are_not_silently_accepted() {
	let changed = edit_signers(CUSTOM, V2, |s| {
		s[0].data[8..12].copy_from_slice(&0x0104u32.to_le_bytes());
	});
	assert!(parser::inspect(&changed)
		.unwrap_err()
		.to_string()
		.contains("sequences disagree"));
	let changed = edit_signers(CUSTOM, V2, |s| {
		let mut at = 0;
		let digests = take_lp(&s[0].data, &mut at);
		s[0].data = [
			lp(&[digests.clone(), digests].concat()),
			s[0].data[at..].to_vec(),
		]
		.concat();
	});
	assert!(parser::inspect(&changed)
		.unwrap_err()
		.to_string()
		.contains("duplicate algorithm"));
	let changed = edit_signers(CUSTOM, V2, |s| {
		s[0].data[8..12].copy_from_slice(&0x8888u32.to_le_bytes());
		s[0].signatures[4..8].copy_from_slice(&0x8888u32.to_le_bytes());
	});
	let report = parser::inspect(&changed).unwrap();
	assert_eq!(report["verification"]["v2_v3_records"], "partial");
	assert_eq!(
		report["signers"][0]["algorithms"][0]["signature_status"],
		"unsupported"
	);
}

#[test]
fn malformed_der_and_excessive_certificate_lengths_fail_closed() {
	let changed = edit_signers(CUSTOM, V2, |s| {
		let mut at = 0;
		let digests = take_lp(&s[0].data, &mut at);
		let _certificates = take_lp(&s[0].data, &mut at);
		s[0].data = [
			lp(&digests),
			lp(&lp(&[0x30, 0x80, 0, 0])),
			s[0].data[at..].to_vec(),
		]
		.concat();
	});
	assert!(parser::inspect(&changed)
		.unwrap_err()
		.to_string()
		.contains("DER length"));
	let changed = edit_signers(CUSTOM, V2, |s| {
		let mut at = 0;
		let digests = take_lp(&s[0].data, &mut at);
		let _certificates = take_lp(&s[0].data, &mut at);
		s[0].data = [
			lp(&digests),
			lp(&lp(&vec![0; 65537])),
			s[0].data[at..].to_vec(),
		]
		.concat();
	});
	assert!(parser::inspect(&changed)
		.unwrap_err()
		.to_string()
		.contains("65536 byte budget"));
}

#[test]
fn signing_block_and_signer_budgets_are_enforced() {
	let changed = edit_signers(CUSTOM, V2, |s| {
		*s = vec![s[0].clone(); 33];
	});
	assert!(parser::inspect(&changed)
		.unwrap_err()
		.to_string()
		.contains("32 signers"));
	let changed = rebuild(
		CUSTOM,
		&(0..129).map(|id| (id, vec![])).collect::<Vec<_>>(),
		&[],
	);
	assert!(parser::inspect(&changed)
		.unwrap_err()
		.to_string()
		.contains("128 ID pairs"));
	let values = pairs(CUSTOM);
	let changed = rebuild(CUSTOM, &[values[0].clone(), values[0].clone()], &[]);
	assert!(parser::inspect(&changed)
		.unwrap_err()
		.to_string()
		.contains("duplicate ID"));
	let changed = rebuild(CUSTOM, &values, &[1, 2, 3]);
	assert!(parser::inspect(&changed)
		.unwrap_err()
		.to_string()
		.contains("pair length"));
	let changed = rebuild(CUSTOM, &[(42, vec![0; 16 * 1024 * 1024])], &[]);
	assert!(parser::inspect(&changed)
		.unwrap_err()
		.to_string()
		.contains("16 MiB"));
}

#[test]
fn truncated_zip_and_signing_lengths_never_panic_or_verify() {
	for end in (0..CUSTOM.len()).step_by(17) {
		assert!(parser::inspect(&CUSTOM[..end]).is_err(), "truncation {end}");
	}
	let (start, central, end) = layout(CUSTOM);
	for offset in [start, start + 8, central - 24] {
		let mut changed = CUSTOM.to_vec();
		changed[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
		assert!(parser::inspect(&changed).is_err(), "length at {offset}");
	}
	let mut changed = CUSTOM.to_vec();
	changed[end + 16..end + 20].copy_from_slice(&u32::MAX.to_le_bytes());
	assert!(parser::inspect(&changed).is_err());
	let mut changed = CUSTOM.to_vec();
	changed[30] ^= 1;
	assert!(parser::inspect(&changed).is_err());
	let mut changed = CUSTOM.to_vec();
	changed[end + 20..end + 22].copy_from_slice(&22u16.to_le_bytes());
	changed.extend(b"PK\x05\x06");
	changed.extend([0; 18]);
	assert!(parser::inspect(&changed)
		.unwrap_err()
		.to_string()
		.contains("unambiguous"));
}

async fn directory() -> PathBuf {
	static NEXT: AtomicU64 = AtomicU64::new(1);
	let path = std::env::temp_dir().join(format!(
		"hepta-apk-signature-{}-{}",
		std::process::id(),
		NEXT.fetch_add(1, Ordering::Relaxed)
	));
	tokio::fs::create_dir(&path).await.unwrap();
	path
}

#[tokio::test]
async fn confined_capture_and_expected_identity_bind_the_report() {
	let dir = directory().await;
	let path = dir.join("owned.apk");
	tokio::fs::write(&path, CUSTOM).await.unwrap();
	let digest = parser::hex(&Sha256::digest(CUSTOM));
	let params = InspectApkSignatureParams {
		path: path.display().to_string(),
		expected_sha256: Some(digest.clone()),
	};
	let report: Value = serde_json::from_str(
		&inspect_with_roots(
			params.clone(),
			std::slice::from_ref(&dir),
			&CancellationToken::new(),
		)
		.await
		.unwrap(),
	)
	.unwrap();
	assert_eq!(report["source"]["sha256"], digest);
	let mut mismatch = params.clone();
	mismatch.expected_sha256 = Some("0".repeat(64));
	assert!(inspect_with_roots(
		mismatch,
		std::slice::from_ref(&dir),
		&CancellationToken::new()
	)
	.await
	.unwrap_err()
	.to_string()
	.contains("SHA-256 differs"));
	assert!(
		inspect_with_roots(params, &[dir.join("elsewhere")], &CancellationToken::new())
			.await
			.is_err()
	);
	tokio::fs::remove_dir_all(dir).await.unwrap();
}

#[tokio::test]
async fn cancellation_and_parameter_validation_precede_file_access() {
	let cancellation = CancellationToken::new();
	cancellation.cancel();
	let params = InspectApkSignatureParams {
		path: "/does-not-exist.apk".into(),
		expected_sha256: None,
	};
	assert!(inspect_with_roots(params.clone(), &[], &cancellation)
		.await
		.unwrap_err()
		.to_string()
		.contains("cancelled"));
	let mut bad = params;
	bad.expected_sha256 = Some("ABC".into());
	assert!(inspect_with_roots(bad, &[], &CancellationToken::new())
		.await
		.unwrap_err()
		.to_string()
		.contains("lowercase"));
	assert!(serde_json::from_value::<InspectApkSignatureParams>(
		json!({"path":"/tmp/a.apk","run":true})
	)
	.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn symlinks_and_non_regular_files_are_rejected() {
	let dir = directory().await;
	let source = dir.join("source.apk");
	let link = dir.join("alias.apk");
	tokio::fs::write(&source, CUSTOM).await.unwrap();
	tokio::fs::symlink(&source, &link).await.unwrap();
	for path in [link, dir.clone()] {
		let params = InspectApkSignatureParams {
			path: path.display().to_string(),
			expected_sha256: None,
		};
		assert!(inspect_with_roots(
			params,
			std::slice::from_ref(&dir),
			&CancellationToken::new()
		)
		.await
		.is_err());
	}
	tokio::fs::remove_dir_all(dir).await.unwrap();
}
