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

//! Node.js SHA-256/JSON.stringify reference projection fixtures, not
//! independently executed complete REA 6.8.0 end-to-end Evidence records.

use super::*;

fn reference_record() -> Value {
	json!({
		"subject": {
			"name": "demo",
			"digest": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			"local_path": "/tmp/first",
			"format": "elf",
			"architecture": "x86_64"
		},
		"provider": {"id":"test","name":"test","version":null},
		"analysis_profile": null,
		"predicate_type": "rea.analysis",
		"operation": "inspect_test",
		"parameters": {"k":1},
		"raw_result": null,
		"normalized_result": {"items":[],"value":true},
		"confidence": "observed",
		"authority": "shipped-artifact",
		"environment": null,
		"limitations": [],
		"relationship_coverage": null,
		"locations": [],
		"evidence_links": [],
		"evidence_id": "ev_810ade79c277c37e86e4fdf3dbc917ff699f83a7b162d13373967232dbf1a6fc"
	})
}

#[test]
fn native_digest_matches_independent_node_safe_integer_reference() {
	let checked = verify_record(&reference_record()).expect("canonical SHA-256 matches");
	assert_eq!(checked["status"], "subset_digest_verified");
	assert_eq!(checked["rea_full_schema_qualified"], false);
}

#[test]
fn display_paths_do_not_modify_rea_semantic_identity() {
	let mut evidence = reference_record();
	evidence["subject"]["name"] = json!("renamed");
	evidence["subject"]["local_path"] = json!("/different/place");
	evidence["caller_input_path"] = json!("/original/request");
	assert!(verify_record(&evidence).is_ok());
}

#[test]
fn utf16_key_order_differs_from_utf8_key_order_and_matches_node() {
	let mut evidence = reference_record();
	evidence["parameters"] = json!({"𐀀":1, "\u{e000}":2});
	evidence["evidence_id"] =
		json!("ev_42e38ac024ee19a3bd0a88c683bf31a6b2347f59b753458ed9e937c49a5e4abc");
	assert!(verify_record(&evidence).is_ok());
}

#[test]
fn refuses_digest_tamper_and_legacy_null_coverage_omission() {
	let mut evidence = reference_record();
	evidence["normalized_result"]["value"] = json!(false);
	assert!(verify_record(&evidence).is_err());

	let mut evidence = reference_record();
	evidence["evidence_id"] =
		json!("ev_3bcefced5a4b4678a49ff1deffd317ae68660c5be7a6e567c09e321536f55d11");
	assert!(verify_record(&evidence).is_err());

	let mut evidence = reference_record();
	evidence
		.as_object_mut()
		.expect("object")
		.remove("relationship_coverage");
	assert!(verify_record(&evidence).is_err());
}

#[test]
fn refuses_tampered_numeric_identity_and_invalid_profile() {
	let mut evidence = reference_record();
	evidence["parameters"] = json!({"fraction":0.25});
	assert!(verify_record(&evidence).is_err());

	let mut evidence = reference_record();
	evidence["parameters"] = json!({"unsafe_integer":9_007_199_254_740_993_u64});
	assert!(verify_record(&evidence).is_err());

	let mut evidence = reference_record();
	evidence["analysis_profile"] = json!({
		"provider":{"id":"test","name":"test","version":"mismatch"},
		"parameters":{},
		"digest":"0000000000000000000000000000000000000000000000000000000000000000"
	});
	assert!(verify_record(&evidence).is_err());
}

#[test]
fn rejects_nested_duplicate_json_members_and_extra_evidence_fields() {
	let raw = br#"{"parent":{"same":1,"same":2}}"#;
	assert!(serde_json::from_slice::<UniqueJson>(raw).is_err());

	let mut evidence = reference_record();
	evidence["injected"] = json!("unexpected");
	assert!(verify_record(&evidence).is_err());
}

#[test]
fn unknown_relation_preserved_not_silently_complete() {
	let mut evidence = reference_record();
	evidence["relationship_coverage"] = json!({"status":"unknown","reason":"not inspected"});
	let record = evidence.as_object().expect("record");
	coverage(field(record, "relationship_coverage").expect("coverage")).expect("unknown is valid");
	assert!(verify_record(&evidence).is_err());
}

#[test]
#[ignore = "requires real rea-agents@6.8.0 CLI Evidence from the P0 npm oracle"]
fn real_npm_reference_evidence_matches_native_subset_identity() {
	let path = std::env::var("REA_REAL_EVIDENCE_JSON").expect("real REA fixture path");
	let data = std::fs::read(path).expect("read upstream Evidence fixture");
	let record: UniqueJson = serde_json::from_slice(&data).expect("parse authentic Evidence");
	let outcome = verify_record(&record.0).expect("native canonical SHA matches upstream REA");
	assert_eq!(outcome["evidence_id"], record.0["evidence_id"]);
	let mut tampered = record.0.clone();
	tampered["normalized_result"]["machine"] = json!(999);
	assert!(
		verify_record(&tampered).is_err(),
		"actual Evidence tampering rejected"
	);
	let mut changed_path = record.0.clone();
	changed_path["subject"]["local_path"] = json!("/some/other/location");
	assert!(
		verify_record(&changed_path).is_ok(),
		"display path excluded from semantic hash"
	);
}

#[test]
fn upstream_subject_format_architecture_discriminant_is_strict() {
	let base = reference_record()["subject"].clone();
	assert!(
		subject(&base).is_ok(),
		"record fixture is a valid ELF subject"
	);

	let mut bad = base.clone();
	bad["format"] = json!("nonsense-file-format");
	assert!(
		subject(&bad).is_err(),
		"unknown formats must not become valid Evidence"
	);

	let mut bad = base.clone();
	bad["architecture"] = json!("not-a-real-isa");
	assert!(subject(&bad).is_err(), "unregistered CPU family must fail");

	let mut bad = base.clone();
	bad["architecture"] = json!("6502");
	assert!(
		subject(&bad).is_err(),
		"detected ELF cannot claim raw-only CPU"
	);

	let mut raw = base.clone();
	raw["format"] = json!("raw-binary");
	raw["architecture"] = json!("6502");
	assert!(
		subject(&raw).is_ok(),
		"explicit raw-binary can use raw-only CPU"
	);

	let mut dol = base.clone();
	dol["format"] = json!("gamecube-dol");
	dol["architecture"] = Value::Null;
	assert!(subject(&dol).is_err(), "DOL requires powerpc");
	dol["architecture"] = json!("powerpc");
	assert!(subject(&dol).is_ok());
}

#[test]
fn committed_profile_refuses_unknown_version_even_with_matching_evidence_provider() {
	let owner = json!({"id":"provider","name":"provider","version":null});
	// Ordinary Evidence accepts an unknown provider version, but an analysis
	// profile commits to a concrete, non-null version.
	assert!(provider(&owner).is_ok());
	let profile_record = json!({
		"provider": owner,
		"parameters": {},
		"digest": "0000000000000000000000000000000000000000000000000000000000000000"
	});
	let error = profile(&profile_record, &profile_record["provider"])
		.expect_err("noncommitted profile provider rejected");
	assert!(
		error.to_string().contains("profile.provider.version"),
		"{error}"
	);
}

#[test]
fn ordinary_provider_version_matches_published_nullable_and_empty_string_schema() {
	let null_version = json!({"id":"provider","name":"provider","version":null});
	let empty_version = json!({"id":"provider","name":"provider","version":""});
	assert!(provider(&null_version).is_ok());
	assert!(provider(&empty_version).is_ok());

	for wrong in [json!(123), json!(false), json!({}), json!([])] {
		let invalid = json!({"id":"provider","name":"provider","version":wrong});
		assert!(provider(&invalid).is_err());
	}

	let uncommitted = json!({
		"provider":empty_version,
		"parameters":{},
		"digest":"0000000000000000000000000000000000000000000000000000000000000000"
	});
	assert!(
		profile(&uncommitted, &uncommitted["provider"]).is_err(),
		"a profile's version must remain nonempty even when ordinary Evidence permits empty"
	);
}

#[test]
fn finite_number_renderer_matches_ecmascript_boundary_examples() {
	let cases = [
		("-0", "0"),
		("0.0", "0"),
		("0.25", "0.25"),
		("-1.5", "-1.5"),
		("1e-7", "1e-7"),
		("1e-6", "0.000001"),
		("0.0000123", "0.0000123"),
		("1e20", "100000000000000000000"),
		("1e21", "1e+21"),
		("-1e22", "-1e+22"),
		("5e-324", "5e-324"),
		("1.7976931348623157e308", "1.7976931348623157e+308"),
		("9007199254740991", "9007199254740991"),
	];
	for (input, expected) in cases {
		let number: Number = serde_json::from_str(input).expect("parse JSON number");
		assert_eq!(
			canonical_js_number(&number).expect("render"),
			expected,
			"{input}"
		);
	}
}

#[test]
fn file_offset_location_obeys_js_safe_integer_rules() {
	for value in [json!(0), json!(1.0), json!(9_007_199_254_740_991_u64)] {
		assert!(json_safe_unsigned(&value), "{value}");
	}
	for value in [
		json!(-1),
		json!(-0.25),
		json!(3.5),
		json!(9_007_199_254_740_993_u64),
	] {
		assert!(!json_safe_unsigned(&value), "{value}");
	}
}

#[test]
#[ignore = "requires real published rea-agents@6.8.0 numeric Evidence output from P0 npm CI"]
fn real_npm_fractional_reference_evidence_matches_native() {
	let path = std::env::var("REA_REAL_FLOAT_EVIDENCE_JSON")
		.expect("actual npm finite-number Evidence corpus path");
	let bytes = std::fs::read(path).expect("read published npm corpus");
	let root: UniqueJson = serde_json::from_slice(&bytes).expect("unique-key JSON corpus");
	let cases = root.0["cases"].as_array().expect("cases array");
	assert!(
		cases.len() >= 400,
		"must exercise extensive fixed and bit-pattern samples"
	);
	assert!(
		cases
			.iter()
			.any(|record| record["provider"]["version"] == ""),
		"the genuine npm oracle must include empty ordinary provider version"
	);
	assert!(
		cases
			.iter()
			.any(|record| record["provider"]["version"].is_null()),
		"the genuine npm oracle must include null ordinary provider version"
	);
	for (index, record) in cases.iter().enumerate() {
		let checked = verify_record(record)
			.unwrap_or_else(|error| panic!("npm Evidence case {index}: {error}"));
		assert_eq!(
			checked["evidence_id"], record["evidence_id"],
			"case {index}"
		);
		assert_eq!(checked["rea_full_schema_qualified"], false);
	}
	let mut tampered = cases[4].clone();
	tampered["normalized_result"]["number"] = json!(0.75);
	assert!(
		verify_record(&tampered).is_err(),
		"fractional numeric tamper rejected"
	);
}

#[test]
fn parsed_extreme_exponent_preserves_exact_javascript_ieee754_bits() {
	// A reference npm Evidence profile exposed a 1-ULP parsing mismatch at
	// 0x7feffffffffffffe when serde_json float_roundtrip was disabled.
	let source = "1.7976931348623155e308";
	let decoded: Number = serde_json::from_str(source).expect("finite JSON number");
	assert_eq!(
		decoded.as_f64().expect("f64").to_bits(),
		0x7feffffffffffffe_u64,
		"JSON parsing may not silently round to f64::MAX"
	);
	assert_eq!(
		canonical_js_number(&decoded).expect("JCS render"),
		"1.7976931348623155e+308"
	);
}

#[test]
#[ignore = "requires hash-consistent schema-negative records from real published REA npm"]
fn real_npm_rejected_schema_matrix_is_independently_rejected_by_rust() {
	let path = std::env::var("REA_REAL_INVALID_EVIDENCE_JSON")
		.expect("published REA schema-negative fixture path");
	let bytes = std::fs::read(path).expect("read authentic npm schema-negatives");
	let parsed: UniqueJson = serde_json::from_slice(&bytes).expect("unique-key negative JSON");
	let cases = parsed.0["cases"].as_array().expect("schema-negative cases");
	assert_eq!(cases.len(), 20, "all upstream Zod-negative variants required");
	for test in cases {
		let label = test["label"].as_str().expect("negative label");
		assert_eq!(
			test["authenticatedHashButRejectedSchema"],
			true,
			"upstream negative {label} must have a recomputed hash"
		);
		let record = &test["record"];
		let error = match verify_record(record) {
			Ok(_) => panic!("Rust accepted upstream-invalid Evidence {label}"),
			Err(error) => error,
		};
		assert!(
			!error.to_string().contains("semantic digest mismatch"),
			"Rust must reject upstream invalid schema before ID mismatch: {label}: {error}"
		);
	}
}
