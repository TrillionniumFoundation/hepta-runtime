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

fn original_content_projection(row: &Value) -> Value {
	if row["state"] != "mapped" {
		return json!({"mapped":false});
	}
	let content = &row["content"];
	let embedded = content["state"] == "embedded";
	json!({
		"mapped":true,"source_index":row["flattened_source_index"],
		"source":row["reported_source"],"root":row["reported_source_root"],
		"line":row["original_position"]["line"],"column":row["original_position"]["column"],
		"offset":row["original_position"]["offset"],
		"content_position":row["original_position"]["content_position"],
		"ignored":row["ignored"],"name":row["name"],"section":row["section_path"],
		"content_present":embedded,
		"content_sha256":if embedded {content["utf8_sha256"].clone()} else {Value::Null},
		"content_bytes":if embedded {content["utf8_bytes"].clone()} else {Value::Null},
	})
}

fn native_content_projection(row: &Value, sources: &[Value]) -> Value {
	if row["mapped"] != true {
		return json!({"mapped":false});
	}
	let original = &row["original"];
	let source = &sources[original["source_index"].as_u64().unwrap() as usize];
	let path: Vec<_> = row["section_pointer"]
		.as_str()
		.unwrap()
		.split('/')
		.collect();
	let sections: Vec<_> = path
		.windows(2)
		.filter(|pair| pair[0] == "sections")
		.map(|pair| pair[1].parse::<u64>().unwrap())
		.collect();
	assert_eq!(
		original["source_content_verified"],
		!original["offset"].is_null(),
	);
	json!({
		"mapped":true,"source_index":original["source_index"],
		"source":original["source"],"root":original["source_root"],
		"line":original["line"],"column":original["column"],
		"offset":original["offset"],"content_position":original["content_position"],
		"ignored":original["ignored"],"name":original["name"],"section":sections,
		"content_present":source["embedded_content"]["present"],
		"content_sha256":source["embedded_content"]["sha256"],
		"content_bytes":source["embedded_content"]["bytes"],
	})
}

#[test]
fn frozen_real_rea_content_positions_cover_121_admitted_6_refused_and_6_profile_gaps() {
	let raw = include_bytes!("../../tests/fixtures/rea_source_map/content-position-rea-6_8_0.json");
	assert_eq!(
		sha256(raw),
		"d7759254c1fa7732aed2cce36b118dd36bc14f2616e6756afdf10fa4192c72b1"
	);
	let fixture: Value = serde_json::from_slice(raw).unwrap();
	assert_eq!(
		fixture["counts"],
		json!({"cases":133,"direct_offsets":11,"exact":121,"explicit_profile_gaps":6,"maps":26,"refused":6}),
	);
	assert_eq!(fixture["producer"]["node"]["version"], "v22.23.4");
	assert_eq!(
		fixture["producer"]["node"]["sha256"],
		"94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90",
	);
	assert_eq!(
		fixture["producer"]["script"]["sha256"],
		sha256(include_bytes!(
			"../../scripts/rea-source-map-content-reference.mjs"
		)),
	);
	assert_eq!(
		fixture["producer"]["fixed_original"]["trace"]["sha256"],
		"2bf3b1e6d022bffc2e931133275846188141ffa6bd6e5b636c24d54225986ea1",
	);
	assert_eq!(
		fixture["producer"]["fixed_original"]["offset"]["sha256"],
		"85450f73f3c9e4ffe9484dc5709b0fbe8a00c5f368380d7d47578a2063caa77b",
	);
	let (mut exact, mut refused, mut gaps) = (0, 0, 0);
	let mut states = std::collections::BTreeSet::new();
	for case in fixture["cases"].as_array().unwrap() {
		let id = case["id"].as_str().unwrap();
		let text = case["map_text"].as_str().unwrap();
		assert_eq!(sha256(text.as_bytes()), case["map_sha256"], "{id}");
		let original_raw = case["reference_json"].as_str().unwrap();
		assert_eq!(
			sha256(original_raw.as_bytes()),
			case["reference_sha256"],
			"{id}"
		);
		let input = WorkerRequest {
			text: text.to_owned(),
			expected_analysis_sha256: None,
			collection: SourceMapCollection::Sources,
			offset: 0,
			limit: 256,
			generated_position: Some(
				serde_json::from_value(case["generated_position"].clone()).unwrap(),
			),
		};
		match case["native_admission"].as_str().unwrap() {
			"exact" => {
				assert_eq!(case["reference_status"], "ok", "{id}");
				let original: Value = serde_json::from_str(original_raw).unwrap();
				let actual =
					parser::report(&input).unwrap_or_else(|error| panic!("{id}: {error:#}"));
				assert_eq!(actual["record_format"], "hepta.source-map-declarations.v2");
				assert_eq!(actual["rea_evidence_compatible"], false);
				assert_eq!(actual["source_files_opened"], 0);
				assert_eq!(actual["network_requests"], 0);
				assert_eq!(actual["javascript_executed"], false);
				assert_eq!(actual["next_offset"], Value::Null, "{id}");
				assert_eq!(
					actual["query"]["matched_generated_position"],
					original["lookup"]["matched_generated_position"],
					"{id}",
				);
				let expected: Vec<_> = original["matches"]
					.as_array()
					.unwrap()
					.iter()
					.map(original_content_projection)
					.collect();
				assert_eq!(
					case["reference_projection"]["matches"],
					json!(expected),
					"{id}"
				);
				let sources = actual["rows"].as_array().unwrap();
				let observed: Vec<_> = actual["query"]["mappings"]
					.as_array()
					.unwrap()
					.iter()
					.map(|row| native_content_projection(row, sources))
					.collect();
				assert_eq!(observed, expected, "{id}");
				for row in observed {
					if row["mapped"] == true {
						states.insert(row["content_position"].as_str().unwrap().to_owned());
					}
				}
				exact += 1;
			}
			"refuse" => {
				assert_eq!(case["reference_status"], "error", "{id}");
				assert!(
					parser::report(&input).is_err(),
					"accepted damaged original control {id}"
				);
				refused += 1;
			}
			"profile-gap" => {
				assert_eq!(case["reference_status"], "ok", "{id}");
				assert!(matches!(
					case["map_id"].as_str().unwrap(),
					"lone-high" | "lone-low" | "reversed-surrogates"
				));
				assert!(
					parser::report(&input).is_err(),
					"isolated surrogate admitted as scalar text: {id}"
				);
				gaps += 1;
			}
			other => panic!("unreviewed original control category {other}: {id}"),
		}
	}
	assert_eq!((exact, refused, gaps), (121, 6, 6));
	assert_eq!(
		states,
		[
			"content-unavailable",
			"outside-embedded-text",
			"verified-in-embedded-text"
		]
		.into_iter()
		.map(str::to_owned)
		.collect::<std::collections::BTreeSet<_>>()
	);
}

#[test]
fn content_position_profile_change_invalidates_old_continuations() {
	let mut input = request(basic("AAAA,CAAC"));
	input.limit = 1;
	let first = parser::report(&input).unwrap();
	let old = sha256(
		format!(
			"hepta.source-map-declarations.v1\0{}",
			sha256(input.text.as_bytes())
		)
		.as_bytes(),
	);
	assert_ne!(first["analysis_sha256"], old);
	input.offset = 1;
	input.expected_analysis_sha256 = Some(old);
	assert!(parser::report(&input).is_err());
	input.expected_analysis_sha256 = first["analysis_sha256"].as_str().map(str::to_owned);
	assert_eq!(
		parser::report(&input).unwrap()["rows"]
			.as_array()
			.unwrap()
			.len(),
		1
	);
}

#[test]
fn embedded_line_budget_is_checked_for_the_complete_map_before_returning_summary() {
	let content = "\n".repeat(999_999);
	let mut input = request(
		json!({"version":3,"sources":["maximum.js"],"sourcesContent":[content],
		"names":[],"mappings":"AAAA"}),
	);
	input.collection = SourceMapCollection::Summary;
	let admitted = parser::report(&input).unwrap();
	assert_eq!(admitted["counts"]["embedded_source_lines"], 1_000_000);
	let content = "\n".repeat(499_999);
	input.text = json!({"version":3,"sections":[
		{"offset":{"line":0,"column":0},"map":{"version":3,"sources":["a"],"sourcesContent":[content],
			"names":[],"mappings":"AAAA"}},
		{"offset":{"line":1,"column":0},"map":{"version":3,"sources":["b","empty"],"sourcesContent":[content,""],
			"names":[],"mappings":"AAAA"}}
	]}).to_string();
	let error = parser::report(&input).unwrap_err();
	assert!(error.to_string().contains("1000000 indexed lines"));
}
