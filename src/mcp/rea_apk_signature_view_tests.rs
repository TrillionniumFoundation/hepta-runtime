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

use super::*;

fn parent_id() -> String {
	format!("ev_{}", "a".repeat(64))
}

fn report() -> Value {
	let inspection = super::super::observation::inspect_with_limits(
		include_bytes!("../../tests/fixtures/rea_apk_signature/rotation-v31.apk"),
		super::super::observation::StaticLimits::REA_6_8_0,
	)
	.unwrap();
	let mut value = serde_json::to_value(inspection.result).unwrap();
	value["artifact"]["path"] = json!("/owned/rotation.apk");
	value
}

#[test]
fn subject_binding_is_checked_for_every_projection() {
	let report = report();
	let subject = json!({"local_path":report["artifact"]["path"], "digest":{"sha256":report["artifact"]["sha256"]}});
	assert!(project_static_view(
		&report,
		&parent_id(),
		Some(&subject),
		&[],
		&json!({"kind":"summary"})
	)
	.is_ok());
	let mut stale = subject.clone();
	stale["local_path"] = json!("/different/presentation.apk");
	let error = project_static_view(
		&report,
		&parent_id(),
		Some(&stale),
		&[],
		&json!({"kind":"summary"}),
	)
	.unwrap_err();
	assert_eq!(
		error.issues[0].path,
		vec![json!("source"), json!("subject")]
	);
	assert!(
		project_static_view(&report, &parent_id(), None, &[], &json!({"kind":"summary"})).is_ok()
	);
	assert!(project_static_view(
		&report,
		&parent_id().replacen("ev_", "ev:", 1),
		None,
		&[],
		&json!({"kind":"summary"})
	)
	.is_err());
}

#[test]
fn projection_retains_declared_unknowns_and_original_row_identities() {
	let mut report = report();
	report["schemes"]["v3"]["signers"][0]["certificate"] = Value::Null;
	report["schemes"]["v3"]["signers"][0]["rotation"]["decode_error"] =
		json!("lineage is truncated");
	let summary =
		project_static_view(&report, &parent_id(), None, &[], &json!({"kind":"summary"})).unwrap();
	assert_eq!(
		summary["summary"]["source_coverage"]["signer_identity"],
		"partial"
	);
	assert_eq!(
		summary["summary"]["source_coverage"]["lineage_decoding"],
		"partial"
	);
	assert_eq!(
		summary["summary"]["source_coverage"]["authenticity"],
		"unknown"
	);
	let view = json!({"kind":"apk-signature", "collection":"signers", "schemes":["v3.1","v3"], "offset":1, "limit":1, "fields":[]});
	let page = project_static_view(&report, &parent_id(), None, &[], &view).unwrap();
	assert_eq!(page["items"][0]["scheme"], "v3.1");
	assert_eq!(page["items"][0]["index"], 0);
	assert_eq!(page["items"][0].as_object().unwrap().len(), 4);
	assert_eq!(page["coverage"]["total"], 2);
}

#[test]
fn empty_filters_and_past_end_offsets_have_honest_filtered_coverage() {
	let report = report();
	for extra in [
		json!({"ids":[]}),
		json!({"signer_ids":[]}),
		json!({"schemes":[]}),
	] {
		let mut view = json!({"kind":"apk-signature", "collection":"signers"});
		view.as_object_mut()
			.unwrap()
			.extend(extra.as_object().unwrap().clone());
		let page = project_static_view(&report, &parent_id(), None, &[], &view).unwrap();
		assert_eq!(
			page["coverage"],
			json!({"status":"empty","examined":0,"total":0,"next_offset":null,"exhausted":true})
		);
	}
	let page = project_static_view(
		&report,
		&parent_id(),
		None,
		&[],
		&json!({"kind":"apk-signature","collection":"signers","offset":10000}),
	)
	.unwrap();
	assert_eq!(page["coverage"]["status"], "empty");
	assert!(page["coverage"]["total"].as_u64().unwrap() > 0);
	assert_eq!(page["coverage"]["exhausted"], true);
}

#[test]
fn retained_schema_accepts_wider_declared_numbers_without_weakening_binary_bounds() {
	let mut report = report();
	report["artifact"]["bytes"] = json!(1.0);
	report["schemes"]["v3.1"]["signers"][0]["min_sdk"] = json!(-9_007_199_254_740_991i64);
	report["schemes"]["v3.1"]["signers"][0]["rotation"]["lineage"][0]["flags"] =
		json!(9_007_199_254_740_991u64);
	validate_static_report(&report).unwrap();
	let page = project_static_view(
		&report,
		&parent_id(),
		None,
		&[],
		&json!({"kind":"apk-signature","collection":"lineage","schemes":["v3.1"],"fields":["flags"]}),
	)
	.unwrap();
	assert_eq!(page["items"][0]["flags"], 9_007_199_254_740_991u64);
	report["schemes"]["v3.1"]["signers"][0]["rotation"]["lineage"][0]["flags"] =
		json!(9_007_199_254_740_992u64);
	assert!(validate_static_report(&report).is_err());
}

#[test]
fn strict_report_and_selector_errors_never_become_successful_empty_results() {
	let mut report = report();
	report["schemes"]["v3.1"]["signers"][0]["certificate"]["unexpected"] =
		json!("do not reflect this secret");
	let error = project_static_view(&report, &parent_id(), None, &[], &json!({"kind":"summary"}))
		.unwrap_err();
	assert_eq!(error.tag, "AnalysisInputError");
	assert!(error
		.issues
		.iter()
		.any(|issue| issue.reason == "unknown_argument"));
	assert!(!serde_json::to_string(&error)
		.unwrap()
		.contains("do not reflect"));
	for selector in [
		json!({"kind":"summary","extra":true}),
		json!({"kind":"apk-signature","collection":"signers","limit":0}),
		json!({"kind":"apk-signature","collection":"signers","fields":["digests"]}),
		json!({"kind":"apk-signature","collection":"digests","offset":1.5}),
	] {
		assert!(project_static_view(&report, &parent_id(), None, &[], &selector).is_err());
	}
}

#[test]
fn messages_use_code_point_order_and_utf16_wire_cost() {
	let messages = vec![
		"\u{10000}".to_owned(),
		"\u{e000}".to_owned(),
		"\u{10000}".to_owned(),
	];
	assert_eq!(
		bounded_messages(&messages, &parent_id(), "limitations"),
		["\u{e000}", "\u{10000}"]
	);
	assert_eq!(message_cost("\u{10000}"), 126);
	let messages = vec!["x".repeat(10000), "small".into(), "small".into()];
	let selected = bounded_messages(&messages, &parent_id(), "limitations");
	assert_eq!(selected.len(), 2);
	assert_eq!(selected[0], "small");
	assert!(selected[1].starts_with("1 additional limitations omitted"));
	assert!(
		selected
			.iter()
			.map(|text| message_cost(text))
			.sum::<usize>()
			<= MESSAGE_BYTE_LIMIT
	);
}
