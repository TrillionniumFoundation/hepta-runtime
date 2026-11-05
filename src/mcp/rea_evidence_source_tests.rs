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

//! Original REA source-authentication differentials and owned-payload invariants.

use super::*;

fn schema_reference() -> Value {
	serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_evidence_source/schema-reference-r1.json"
	))
	.unwrap()
}

fn file_reference() -> Value {
	serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_evidence_source/file-reference-r1.json"
	))
	.unwrap()
}

fn apply_change(record: &mut Value, change: &Value) {
	let path = change["path"].as_array().unwrap();
	if path.is_empty() {
		*record = change["value"].clone();
		return;
	}
	let mut parent = record;
	for key in &path[..path.len() - 1] {
		parent = if let Some(key) = key.as_str() {
			parent.get_mut(key).unwrap()
		} else {
			parent.get_mut(key.as_u64().unwrap() as usize).unwrap()
		};
	}
	let key = path.last().unwrap();
	if change.get("delete") == Some(&Value::Bool(true)) {
		parent
			.as_object_mut()
			.unwrap()
			.remove(key.as_str().unwrap());
	} else if let Some(key) = key.as_str() {
		parent
			.as_object_mut()
			.unwrap()
			.insert(key.to_owned(), change["value"].clone());
	} else {
		parent[key.as_u64().unwrap() as usize] = change["value"].clone();
	}
}

#[test]
fn original_109_complete_schema_issues_and_descriptions() {
	let reference = schema_reference();
	let cases = reference["cases"].as_array().unwrap();
	assert_eq!(cases.len(), 109);
	let mut passed = 0;
	let mut failed = Vec::new();
	for case in cases {
		let mut input = reference["seed"].clone();
		for change in case["changes"].as_array().unwrap() {
			apply_change(&mut input, change);
		}
		let order = if case["name"] == "two-unknown" {
			let mut keys: Vec<String> = RECORD_FIELDS
				.iter()
				.filter(|key| input.get(**key).is_some())
				.map(|key| (*key).into())
				.collect();
			// These two insertion positions are recorded in the original producer recipe.
			keys.extend(["z_unknown".into(), "a_unknown".into()]);
			Some(keys)
		} else {
			None
		};
		let resolver = |path: &[Value]| if path.is_empty() { order.clone() } else { None };
		let actual = match authenticate_inline_with_order(input, Some(&resolver)) {
			Ok(_) => json!({"ok": true}),
			Err(SourceError::InvalidRecord {
				issues,
				description,
			}) => json!({"ok": false, "issues": issues, "description": description}),
			Err(error) => serde_json::to_value(error).unwrap(),
		};
		let mut expected = case["expected"].clone();
		expected.as_object_mut().unwrap().remove("raw_issues");
		if actual == expected {
			passed += 1;
		} else {
			failed.push(json!({"name": case["name"], "actual": actual, "expected": expected}));
		}
	}
	assert!(
		failed.is_empty(),
		"{}",
		serde_json::to_string_pretty(&failed).unwrap()
	);
	assert_eq!(passed, 109);
}

#[test]
fn original_18_file_authentication_and_selector_messages() {
	let reference = file_reference();
	let orders: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_evidence_source/file-reference-root-order-r1.json"
	))
	.unwrap();
	let cases = reference["cases"].as_array().unwrap();
	assert_eq!(cases.len(), 18);
	let mut failed = Vec::new();
	for case in cases {
		let expected = &case["expected"];
		let keys: Vec<String> = orders[case["name"].as_str().unwrap()]
			.as_array()
			.unwrap()
			.iter()
			.map(|key| key.as_str().unwrap().to_owned())
			.collect();
		let resolver = |path: &[Value]| {
			if path.is_empty() {
				Some(keys.clone())
			} else {
				None
			}
		};
		let result = authenticate_file_with_order(
			case["input"].clone(),
			case["path"].as_str().unwrap(),
			case.get("selected").and_then(Value::as_str),
			Some(&resolver),
		);
		let actual = match result {
			Ok(record) => json!({"ok": true, "evidence_id": record["evidence_id"]}),
			Err(SourceError::Selection { message }) => {
				json!({"ok": false, "tag": "AnalysisInputError", "message": message})
			}
			Err(SourceError::InvalidBundle { message }) => {
				json!({"ok": false, "tag": "EvidenceIntegrityError", "message": message})
			}
			Err(SourceError::InvalidRecord { issues, .. }) => {
				json!({"ok": false, "tag": "EvidenceFileError", "issues": issues})
			}
			Err(error) => serde_json::to_value(error).unwrap(),
		};
		let expected = if expected["ok"] == true {
			expected.clone()
		} else if expected["typed_error"]["_tag"] == "EvidenceFileError" {
			json!({"ok": false, "tag": "EvidenceFileError", "issues": expected["typed_error"]["contentIssues"]})
		} else {
			json!({"ok": false, "tag": expected["typed_error"]["_tag"], "message": expected["typed_error"]["userMessage"]})
		};
		if actual != expected {
			failed.push(json!({"name": case["name"], "actual": actual, "expected": expected}));
		}
	}
	assert!(
		failed.is_empty(),
		"{}",
		serde_json::to_string_pretty(&failed).unwrap()
	);
}

#[test]
fn several_unknown_keys_require_original_order_metadata() {
	let reference = schema_reference();
	let mut record = reference["seed"].clone();
	record["z_unknown"] = json!(true);
	record["a_unknown"] = json!(true);
	assert!(matches!(
		authenticate_inline(record.clone()),
		Err(SourceError::ProfileGap {
			feature: "unknown-key-order-metadata-unavailable"
		})
	));
	for hints in [
		vec!["z_unknown".to_owned()],
		vec!["a_unknown".to_owned(); record.as_object().unwrap().len()],
	] {
		let resolver = |_: &[Value]| Some(hints.clone());
		assert!(matches!(
			authenticate_inline_with_order(record.clone(), Some(&resolver)),
			Err(SourceError::ProfileGap {
				feature: "unknown-key-order-metadata-invalid"
			})
		));
	}
	let mut hints: Vec<String> = RECORD_FIELDS
		.iter()
		.filter(|key| record.get(**key).is_some())
		.map(|key| (*key).into())
		.collect();
	hints.extend(["z_unknown".into(), "a_unknown".into()]);
	let resolver = |_: &[Value]| Some(hints.clone());
	let Err(SourceError::InvalidRecord { issues, .. }) =
		authenticate_inline_with_order(record, Some(&resolver))
	else {
		panic!("expected ordered issues")
	};
	assert_eq!(
		issues,
		vec![
			json!({"path":["z_unknown"],"reason":"unknown_argument"}),
			json!({"path":["a_unknown"],"reason":"unknown_argument"})
		]
	);
}

#[test]
fn owned_inline_and_bundle_results_are_moved_without_payload_copies() {
	let reference = schema_reference();
	let record = reference["seed"].clone();
	let payload = record["normalized_result"]
		.as_object()
		.unwrap()
		.keys()
		.next()
		.unwrap()
		.as_ptr();
	let authenticated = authenticate_inline(record).unwrap();
	assert_eq!(
		payload,
		authenticated["normalized_result"]
			.as_object()
			.unwrap()
			.keys()
			.next()
			.unwrap()
			.as_ptr()
	);
	let files = file_reference();
	let case = files["cases"]
		.as_array()
		.unwrap()
		.iter()
		.find(|case| case["name"] == "two-selected")
		.unwrap();
	let bundle = case["input"].clone();
	let selected = case["selected"].as_str().unwrap();
	let selected_record = bundle["records"]
		.as_array()
		.unwrap()
		.iter()
		.find(|record| record["evidence_id"] == selected)
		.unwrap();
	let payload = selected_record["normalized_result"]
		.as_object()
		.unwrap()
		.keys()
		.next()
		.unwrap()
		.as_ptr();
	let authenticated = authenticate_file(bundle, "display-only.json", Some(selected)).unwrap();
	assert_eq!(
		payload,
		authenticated["normalized_result"]
			.as_object()
			.unwrap()
			.keys()
			.next()
			.unwrap()
			.as_ptr()
	);
}

#[test]
fn existing_canonical_stream_and_new_borrowed_identity_agree() {
	let reference = schema_reference();
	let original = &reference["seed"];
	let digest = rea_evidence::semantic_digest(original).unwrap();
	assert_eq!(original["evidence_id"], format!("ev_{digest}"));
	assert_eq!(
		record_digest(original, false).unwrap(),
		format!("ev_{digest}")
	);
	let mut display = original.clone();
	display["subject"]["name"] = json!("renamed");
	display["subject"]["local_path"] = json!("/other/presentation/path");
	assert!(rea_evidence::semantic_equal(original, &display).unwrap());
	assert!(authenticate_inline(display).is_ok());
	let parameters = json!({"number":2.0});
	let provider = json!({"id":"owned","name":"owned","version":"1"});
	assert_eq!(
		digest_fields(&[("parameters", &parameters), ("provider", &provider)]).unwrap(),
		rea_evidence::canonical_digest(&json!({"parameters":parameters,"provider":provider}))
			.unwrap()
	);
}

#[test]
fn unsupported_authentication_profiles_are_separate_from_corrupt_records() {
	let files = file_reference();
	let case = files["cases"]
		.as_array()
		.unwrap()
		.iter()
		.find(|case| case["name"] == "one")
		.unwrap();
	let mut unknowns = case["input"].clone();
	unknowns["unknowns"] = json!([{}]);
	assert!(matches!(
		authenticate_file(unknowns, "unknowns.json", None),
		Err(SourceError::ProfileGap {
			feature: "residual-unknown-schema-and-history-authentication"
		})
	));
	let mut capture = case["input"].clone();
	capture["records"][0]["predicate_type"] = json!("rea.process-capture");
	capture["records"][0]["evidence_id"] =
		json!(record_digest(&capture["records"][0], false).unwrap());
	capture["captures"] = json!([{"evidence_id":capture["records"][0]["evidence_id"],"predicate_type":"rea.process-capture"}]);
	assert!(matches!(
		authenticate_file(capture, "capture.json", None),
		Err(SourceError::ProfileGap {
			feature: "process-capture-payload-authentication"
		})
	));
}

#[test]
fn deep_json_is_explicitly_outside_the_current_canonical_profile() {
	let reference = schema_reference();
	let mut record = reference["seed"].clone();
	let mut nested = json!(null);
	for _ in 0..128 {
		nested = json!([nested]);
	}
	assert!(deeper_than(&nested, 127));
	assert!(!deeper_than(&nested, 1000));
	record["raw_result"] = nested;
	assert!(matches!(
		authenticate_inline(record),
		Err(SourceError::ProfileGap {
			feature: "canonical-json-depth-over-127"
		})
	));
	let mut wide = Vec::new();
	for _ in 0..4096 {
		wide.push(json!({"leaf": true}));
	}
	assert!(!deeper_than(&Value::Array(wide), 2));
}
