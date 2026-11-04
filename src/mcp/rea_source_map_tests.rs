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

//! Independent hand-decoded maps and refusal cases for the native declaration
//! reader. External differential tests use an independently installed consumer.

use super::*;
use serde_json::{json, Value};

fn request(map: Value) -> WorkerRequest {
	WorkerRequest {
		text: map.to_string(),
		expected_analysis_sha256: None,
		collection: SourceMapCollection::Mappings,
		offset: 0,
		limit: 256,
		generated_position: None,
	}
}

fn basic(mappings: &str) -> Value {
	json!({"version":3,"sources":["foo.ts","bar.ts"],"names":["foo","bar"],"mappings":mappings})
}

#[test]
fn named_mapping_is_decoded_without_column_interpolation() {
	// ECMA example: K=5, A=0, yC=41, I=4, A=0.
	let mut query = request(basic("KAyCIA"));
	query.generated_position = Some(GeneratedPosition { line: 1, column: 9 });
	let report = parser::report(&query).unwrap();
	assert_eq!(report["rows"][0]["generated"], json!({"line":1,"column":5}));
	assert_eq!(report["rows"][0]["original"]["line"], 42);
	assert_eq!(report["rows"][0]["original"]["column"], 4);
	assert_eq!(report["query"]["mappings"][0]["original"]["column"], 4);
	assert_eq!(report["query"]["column_interpolated"], false);
}

#[test]
fn source_original_and_name_deltas_persist_across_generated_lines() {
	let report = parser::report(&request(basic("AAAAA,KCCEC;ADDDD"))).unwrap();
	assert_eq!(report["rows"][1]["original"]["source"], "bar.ts");
	assert_eq!(report["rows"][1]["original"]["line"], 2);
	assert_eq!(report["rows"][1]["original"]["column"], 2);
	assert_eq!(report["rows"][2]["generated"], json!({"line":2,"column":0}));
	assert_eq!(report["rows"][2]["original"]["source"], "foo.ts");
	assert_eq!(report["rows"][2]["original"]["line"], 1);
	assert_eq!(report["rows"][2]["original"]["column"], 1);
}

#[test]
fn unmapped_segments_remain_unmapped_when_lookup_crosses_lines() {
	let mut query = request(basic("AAAA,K;"));
	query.generated_position = Some(GeneratedPosition { line: 1, column: 8 });
	assert_eq!(
		parser::report(&query).unwrap()["query"]["status"],
		"explicitly_unmapped"
	);
	query.generated_position = Some(GeneratedPosition { line: 2, column: 8 });
	let output = parser::report(&query).unwrap();
	assert_eq!(output["query"]["status"], "explicitly_unmapped");
	assert_eq!(
		output["query"]["matched_generated_position"],
		json!({"line":1,"column":5})
	);
}

#[test]
fn point_lookup_crosses_empty_lines_and_preserves_actual_selected_position() {
	let mut query = request(basic("KAAA;;KACA"));
	query.generated_position = Some(GeneratedPosition { line: 3, column: 1 });
	let output = parser::report(&query).unwrap();
	assert_eq!(
		output["query"]["matched_generated_position"],
		json!({"line":1,"column":5})
	);
	assert_eq!(output["query"]["mappings"][0]["original"]["line"], 1);
	query.generated_position = Some(GeneratedPosition { line: 1, column: 4 });
	assert_eq!(
		parser::report(&query).unwrap()["query"]["status"],
		"no_recorded_mapping"
	);
}

#[test]
fn coincident_mappings_and_negative_column_delta_are_preserved() {
	let mut query = request(basic("KAAA,LCAA,ADAA"));
	query.generated_position = Some(GeneratedPosition { line: 1, column: 3 });
	let output = parser::report(&query).unwrap();
	assert_eq!(output["rows"][0]["generated"]["column"], 0);
	assert_eq!(output["rows"][2]["generated"]["column"], 5);
	assert_eq!(output["query"]["status"], "coincident_mappings");
	assert_eq!(output["query"]["mappings"].as_array().unwrap().len(), 2);
}

#[test]
fn indexed_offsets_apply_column_only_to_first_child_line() {
	let map = json!({"version":3,"sections":[
		{"offset":{"line":2,"column":7},"map":basic("AAAA;AACA")},
		{"offset":{"line":5,"column":4},"map":basic("CAAA")}
	]});
	let output = parser::report(&request(map)).unwrap();
	let coordinates: Vec<_> = output["rows"]
		.as_array()
		.unwrap()
		.iter()
		.map(|r| r["generated"].clone())
		.collect();
	assert_eq!(
		coordinates,
		json!([{"line":3,"column":7},{"line":4,"column":0},{"line":6,"column":5}])
			.as_array()
			.unwrap()
			.clone()
	);
	assert_eq!(output["rows"][2]["original"]["source_index"], 2);
}

#[test]
fn nested_sections_compose_offsets_without_source_inheritance() {
	let map = json!({"version":3,"sections":[{"offset":{"line":2,"column":9},"map":{
		"version":3,"sections":[{"offset":{"line":1,"column":3},"map":basic("CAAA;AACA")}]
	}}]});
	let output = parser::report(&request(map)).unwrap();
	assert_eq!(output["rows"][0]["generated"], json!({"line":4,"column":4}));
	assert_eq!(output["rows"][1]["generated"], json!({"line":5,"column":0}));
	assert_eq!(output["rows"][0]["original"]["source_root"], Value::Null);
}

#[test]
fn missing_empty_and_present_embedded_content_are_distinct() {
	let mut input = request(
		json!({"version":3,"sources":[null,"empty.js","unicode.js","missing.js"],
		"sourceRoot":"https://example.invalid/src","sourcesContent":[null,"","a🔥b"],
		"ignoreList":[2],"mappings":"","names":[],"future_extension":{"ignored":true}}),
	);
	input.collection = SourceMapCollection::Sources;
	let output = parser::report(&input).unwrap();
	assert_eq!(output["rows"][0]["source"], Value::Null);
	assert_eq!(output["rows"][0]["embedded_content"]["present"], false);
	assert_eq!(output["rows"][1]["embedded_content"]["bytes"], 0);
	assert_eq!(output["rows"][1]["embedded_content"]["sha256"], sha256(b""));
	assert_eq!(output["rows"][2]["embedded_content"]["bytes"], 6);
	assert_eq!(output["rows"][2]["ignored"], true);
	assert_eq!(output["rows"][3]["embedded_content"]["present"], false);
	assert_eq!(output["network_requests"], 0);
	assert_eq!(output["source_files_opened"], 0);
}

#[test]
fn page_identity_rejects_changed_map_and_empty_content_does_not_equal_missing() {
	let mut input = request(basic("AAAA,CAAC,EAAE"));
	input.limit = 1;
	let first = parser::report(&input).unwrap();
	input.offset = 1;
	assert!(parser::report(&input).is_err());
	input.expected_analysis_sha256 = first["analysis_sha256"].as_str().map(str::to_owned);
	assert_eq!(
		parser::report(&input).unwrap()["rows"]
			.as_array()
			.unwrap()
			.len(),
		1
	);
	input.text.push(' ');
	assert!(parser::report(&input).is_err());
}

#[test]
fn malformed_vlq_segments_and_out_of_bounds_indexes_are_errors() {
	for mappings in [
		",",
		"AAAA,",
		"A,,A",
		"!",
		"g",
		"gggggggA",
		"//////E",
		"AA",
		"AAA",
		"AAAAAA",
		"BAAA",
		"AEAA",
		"AACA,AAFA",
		"AAAAE",
	] {
		assert!(
			parser::report(&request(basic(mappings))).is_err(),
			"accepted {mappings:?}"
		);
	}
}

#[test]
fn signed_zero_vlq_is_minimum_integer_instead_of_zero() {
	// A minimum-integer delta from zero is invalid. Interpreting B as -0
	// would silently turn both examples into valid references.
	for mappings in ["BAAA", "ABAA", "AABA", "AAAB", "AAAAB"] {
		assert!(
			parser::report(&request(basic(mappings))).is_err(),
			"accepted {mappings:?}"
		);
	}
}

#[test]
fn invalid_indexes_duplicate_contract_members_and_mixed_maps_are_errors() {
	for map in [
		json!({"version":2,"mappings":"","sources":[],"names":[]}),
		json!({"version":3,"mappings":"","sources":[],"ignoreList":[0]}),
		json!({"version":3,"mappings":"","sections":[]}),
		json!({"version":3,"sections":[{"offset":{"line":0,"column":0},"url":"https://invalid/map"}]}),
		json!({"version":3,"sections":[{"offset":{"line":0,"column":0},"map":basic("AAAA"),"url":"file:///tmp/x"}]}),
	] {
		assert!(parser::report(&request(map)).is_err());
	}
	let mut input = request(basic(""));
	input.text = r#"{"version":3,"version":3,"mappings":"","sources":[]}"#.to_owned();
	assert!(parser::report(&input).is_err());
}

#[test]
fn section_overlap_overflow_and_depth_refuse_all_output() {
	let overlapping = json!({"version":3,"sections":[
		{"offset":{"line":0,"column":0},"map":basic("AAAA;AAAA;AAAA")},
		{"offset":{"line":1,"column":0},"map":basic("AAAA")}]});
	assert!(parser::report(&request(overlapping)).is_err());
	let touching = json!({"version":3,"sections":[
		{"offset":{"line":0,"column":0},"map":basic("AAAA;AAAA")},
		{"offset":{"line":1,"column":0},"map":basic("AAAA")}]});
	assert!(parser::report(&request(touching)).is_err());
	let overflowing = json!({"version":3,"sections":[{"offset":{"line":4294967295_u64,"column":0},"map":basic("AAAA")}]});
	assert!(parser::report(&request(overflowing)).is_err());
	let mut deep = basic("AAAA");
	for _ in 0..9 {
		deep = json!({"version":3,"sections":[{"offset":{"line":0,"column":0},"map":deep}]});
	}
	assert!(parser::report(&request(deep)).is_err());
}

#[test]
fn mapping_and_query_budgets_fail_without_truncating_coverage() {
	let many = std::iter::repeat_n("A", MAX_MAPPINGS + 1)
		.collect::<Vec<_>>()
		.join(",");
	assert!(parser::report(&request(basic(&many))).is_err());
	let coincident = std::iter::repeat_n("AAAA", 257)
		.collect::<Vec<_>>()
		.join(",");
	let mut input = request(basic(&coincident));
	input.generated_position = Some(GeneratedPosition { line: 1, column: 0 });
	assert!(parser::report(&input).is_err());
	input.generated_position = None;
	assert_eq!(parser::report(&input).unwrap()["counts"]["mappings"], 257);
}

#[tokio::test]
async fn file_admission_identity_and_cancellation_are_enforced() {
	let root = tempfile::tempdir().unwrap();
	let file = root.path().join("input.map");
	tokio::fs::write(&file, basic("AAAA").to_string())
		.await
		.unwrap();
	let mut params = InspectSourceMapParams {
		path: file.to_string_lossy().into_owned(),
		expected_sha256: None,
		expected_analysis_sha256: None,
		collection: SourceMapCollection::Summary,
		offset: 0,
		limit: 64,
		generated_position: None,
	};
	let roots = vec![root.path().to_owned()];
	let token = CancellationToken::new();
	let first = inspect_with_roots(params.clone(), &roots, &token)
		.await
		.unwrap();
	let first: Value = serde_json::from_str(&first).unwrap();
	params.expected_sha256 = first["map_sha256"].as_str().map(str::to_owned);
	tokio::fs::write(&file, basic("CAAA").to_string())
		.await
		.unwrap();
	assert!(inspect_with_roots(params.clone(), &roots, &token)
		.await
		.is_err());
	params.expected_sha256 = None;
	token.cancel();
	assert!(inspect_with_roots(params, &roots, &token).await.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn source_map_symlink_is_not_followed() {
	let root = tempfile::tempdir().unwrap();
	let outside = tempfile::NamedTempFile::new().unwrap();
	tokio::fs::write(outside.path(), basic("AAAA").to_string())
		.await
		.unwrap();
	let link = root.path().join("link.map");
	tokio::fs::symlink(outside.path(), &link).await.unwrap();
	let params = InspectSourceMapParams {
		path: link.to_string_lossy().into_owned(),
		expected_sha256: None,
		expected_analysis_sha256: None,
		collection: SourceMapCollection::Summary,
		offset: 0,
		limit: 64,
		generated_position: None,
	};
	assert!(
		inspect_with_roots(params, &[root.path().to_owned()], &CancellationToken::new())
			.await
			.is_err()
	);
}
