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
	let mut evidence=reference_record();
	evidence["subject"]["name"]=json!("renamed");
	evidence["subject"]["local_path"]=json!("/different/place");
	evidence["caller_input_path"]=json!("/original/request");
	assert!(verify_record(&evidence).is_ok());
}

#[test]
fn utf16_key_order_differs_from_utf8_key_order_and_matches_node() {
	let mut evidence=reference_record();
	evidence["parameters"]=json!({"𐀀":1, "\u{e000}":2});
	evidence["evidence_id"]=json!("ev_42e38ac024ee19a3bd0a88c683bf31a6b2347f59b753458ed9e937c49a5e4abc");
	assert!(verify_record(&evidence).is_ok());
}

#[test]
fn refuses_digest_tamper_and_legacy_null_coverage_omission() {
	let mut evidence=reference_record();
	evidence["normalized_result"]["value"]=json!(false);
	assert!(verify_record(&evidence).is_err());

	let mut evidence=reference_record();
	evidence["evidence_id"]=json!("ev_3bcefced5a4b4678a49ff1deffd317ae68660c5be7a6e567c09e321536f55d11");
	assert!(verify_record(&evidence).is_err());

	let mut evidence=reference_record();
	evidence.as_object_mut().expect("object").remove("relationship_coverage");
	assert!(verify_record(&evidence).is_err());
}

#[test]
fn refuses_unsafe_numbers_and_invalid_profile() {
	let mut evidence=reference_record();
	evidence["parameters"]=json!({"fraction":0.25});
	assert!(verify_record(&evidence).is_err());

	let mut evidence=reference_record();
	evidence["parameters"]=json!({"unsafe_integer":9_007_199_254_740_993_u64});
	assert!(verify_record(&evidence).is_err());

	let mut evidence=reference_record();
	evidence["analysis_profile"]=json!({
		"provider":{"id":"test","name":"test","version":"mismatch"},
		"parameters":{},
		"digest":"0000000000000000000000000000000000000000000000000000000000000000"
	});
	assert!(verify_record(&evidence).is_err());
}

#[test]
fn rejects_nested_duplicate_json_members_and_extra_evidence_fields() {
	let raw=br#"{"parent":{"same":1,"same":2}}"#;
	assert!(serde_json::from_slice::<UniqueJson>(raw).is_err());

	let mut evidence=reference_record();
	evidence["injected"]=json!("unexpected");
	assert!(verify_record(&evidence).is_err());
}

#[test]
fn unknown_relation_preserved_not_silently_complete() {
	let mut evidence=reference_record();
	evidence["relationship_coverage"]=json!({"status":"unknown","reason":"not inspected"});
	let record=evidence.as_object().expect("record");
	coverage(field(record,"relationship_coverage").expect("coverage")).expect("unknown is valid");
	assert!(verify_record(&evidence).is_err());
}
