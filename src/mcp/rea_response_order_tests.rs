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

use super::super::rea_response_encoding::{self as encoding, Budget, JsonView, Representations};
use super::*;
use serde_json::json;

fn number(value: &serde_json::Number) -> Result<String> {
	super::super::rea_evidence::canonical_js_number(value)
}

fn record() -> Value {
	let digest = "0".repeat(64);
	json!({
		"evidence_id":format!("ev_{digest}"),
		"subject":{"name":"test.elf","digest":{"sha256":digest},"local_path":"/workspace/test.elf","format":"elf","architecture":"arm64"},
		"provider":{"id":"elf-notes","name":"ELF notes","version":"1"},
		"analysis_profile":null,"predicate_type":"rea.analysis","operation":"inspect_elf_notes",
		"parameters":{"path":"/workspace/test.elf","max_file_bytes":67108864,"max_entries":256},
		"raw_result":null,
		"normalized_result":{"artifact":{"path":"/workspace/test.elf","sha256":digest,"bytes":64},"format":"elf64","byte_order":"little","machine":183,"type":2,"type_name":"executable","tables":[],"entries":[],"coverage":{"status":"complete","examined_tables":0,"examined_entries":0},"limitations":[]},
		"confidence":"observed","authority":"shipped-artifact","environment":null,"limitations":[],"relationship_coverage":null,
		"locations":[{"kind":"artifact-path","path":"/workspace/test.elf"}],"evidence_links":[]
	})
}

fn selected<'a>(
	schema: &Value,
	value: &'a Value,
	path: &[PathComponent<'_>],
) -> Result<Vec<&'a str>> {
	let at = locate(schema, vec![schema], value, path)?;
	let object = at.value.as_object().context("Expected test object")?;
	keys_at(at, object)
}

#[test]
fn all_frozen_property_annotations_are_complete_and_unique() {
	let source = schemas().unwrap();
	for schema in [&source.elf, &source.apk, &source.bundle] {
		validate_annotations(schema).unwrap();
	}
	let bad = json!({"properties":{"a":{}},"x-hepta-object-order":["a","a"]});
	assert!(validate_annotations(&bad).is_err());
	assert!(validate_annotations(&json!({"properties":{"a":{}}})).is_err());
}

#[test]
fn record_envelope_and_optional_caller_path_follow_the_original_sequence() {
	let mut value = record();
	let object = value.as_object().unwrap();
	let keys = RecordOrder::new(&value, RecordOrigin::NativeTool)
		.keys(&[], object)
		.unwrap();
	assert_eq!(
		&keys[..7],
		[
			"evidence_id",
			"subject",
			"provider",
			"analysis_profile",
			"predicate_type",
			"operation",
			"parameters"
		]
	);
	assert_eq!(keys[7], "raw_result");
	value["caller_input_path"] = json!("/selected/test.elf");
	let keys = RecordOrder::new(&value, RecordOrigin::NativeTool)
		.keys(&[], value.as_object().unwrap())
		.unwrap();
	assert_eq!(keys[7], "caller_input_path");
	assert_eq!(keys[8], "raw_result");
}

#[test]
fn subject_resolves_anyof_then_oneof_and_checks_both_discriminators() {
	for (format, architecture) in [
		("elf", "arm64"),
		("raw-binary", "m68k"),
		("gamecube-dol", "powerpc"),
	] {
		let mut value = record();
		value["subject"]["format"] = json!(format);
		value["subject"]["architecture"] = json!(architecture);
		let keys = RecordOrder::new(&value, RecordOrigin::NativeTool)
			.keys(
				&[PathComponent::Key("subject")],
				value["subject"].as_object().unwrap(),
			)
			.unwrap();
		assert_eq!(
			keys,
			["name", "digest", "local_path", "format", "architecture"]
		);
	}
	let mut value = record();
	value["subject"]["format"] = json!("gamecube-dol");
	value["subject"]["architecture"] = json!("arm64");
	assert!(RecordOrder::new(&value, RecordOrigin::NativeTool)
		.keys(&[], value.as_object().unwrap())
		.is_err());
}

#[test]
fn note_parameter_order_is_source_declared_and_requires_complete_known_fields() {
	let mut value = record();
	assert_eq!(
		RecordOrder::new(&value, RecordOrigin::NativeTool)
			.keys(
				&[PathComponent::Key("parameters")],
				value["parameters"].as_object().unwrap()
			)
			.unwrap(),
		["path", "max_file_bytes", "max_entries"]
	);
	value["parameters"]["surprise"] = json!(true);
	assert!(RecordOrder::new(&value, RecordOrigin::NativeTool)
		.keys(
			&[PathComponent::Key("parameters")],
			value["parameters"].as_object().unwrap()
		)
		.is_err());
	value["parameters"]
		.as_object_mut()
		.unwrap()
		.remove("surprise");
	value["parameters"]
		.as_object_mut()
		.unwrap()
		.remove("max_entries");
	assert!(RecordOrder::new(&value, RecordOrigin::NativeTool)
		.keys(
			&[PathComponent::Key("parameters")],
			value["parameters"].as_object().unwrap()
		)
		.is_err());
}

#[test]
fn unknown_producers_or_raw_object_orders_are_never_guessed() {
	let mut value = record();
	value["operation"] = json!("inspect_unimplemented");
	assert!(RecordOrder::new(&value, RecordOrigin::NativeTool)
		.keys(&[], value.as_object().unwrap())
		.is_err());
	value["operation"] = json!("inspect_analysis_view");
	value["normalized_result"]["parent_operation"] = json!("inspect_other");
	assert!(RecordOrder::new(&value, RecordOrigin::NativeTool)
		.keys(&[], value.as_object().unwrap())
		.is_err());
	let mut value = record();
	value["raw_result"] = json!({"second":2,"first":1});
	assert!(RecordOrder::new(&value, RecordOrigin::NativeTool)
		.keys(
			&[PathComponent::Key("raw_result")],
			value["raw_result"].as_object().unwrap()
		)
		.is_err());
	value["raw_result"] = json!({});
	assert!(RecordOrder::new(&value, RecordOrigin::NativeTool)
		.keys(
			&[PathComponent::Key("raw_result")],
			value["raw_result"].as_object().unwrap()
		)
		.unwrap()
		.is_empty());
}

#[test]
fn actual_object_identity_must_match_the_context_path() {
	let value = record();
	let copied = value.clone();
	assert!(RecordOrder::new(&value, RecordOrigin::NativeTool)
		.keys(&[], copied.as_object().unwrap())
		.is_err());
	assert!(RecordOrder::new(&value, RecordOrigin::NativeTool)
		.keys(
			&[PathComponent::Key("subject")],
			value["provider"].as_object().unwrap()
		)
		.is_err());
}

#[test]
fn schema_union_candidates_are_resolved_at_each_array_element() {
	let schema = json!({"type":"object","properties":{"rows":{"anyOf":[
		{"type":"array","items":{"type":"object","properties":{"kind":{"const":"a"},"a":{}},"required":["kind","a"],"additionalProperties":false,"x-hepta-object-order":["kind","a"]}},
		{"type":"array","items":{"type":"object","properties":{"b":{},"kind":{"const":"b"}},"required":["kind","b"],"additionalProperties":false,"x-hepta-object-order":["b","kind"]}}
	]}},"required":["rows"],"additionalProperties":false,"x-hepta-object-order":["rows"]});
	for (value, expected) in [
		(json!({"rows":[{"kind":"a","a":1}]}), vec!["kind", "a"]),
		(json!({"rows":[{"kind":"b","b":2}]}), vec!["b", "kind"]),
	] {
		assert_eq!(
			selected(
				&schema,
				&value,
				&[PathComponent::Key("rows"), PathComponent::Index(0)]
			)
			.unwrap(),
			expected
		);
	}
	assert_eq!(
		selected(&schema, &json!({"rows":[]}), &[]).unwrap(),
		["rows"]
	);
}

#[test]
fn differently_ordered_valid_anyof_branches_are_an_explicit_ambiguity() {
	let a = json!({"type":"object","properties":{"a":{},"b":{}},"required":["a","b"],"additionalProperties":false,"x-hepta-object-order":["a","b"]});
	let mut b = a.clone();
	b["x-hepta-object-order"] = json!(["b", "a"]);
	assert!(selected(&json!({"anyOf":[a.clone(),b]}), &json!({"a":1,"b":2}), &[]).is_err());
	assert!(selected(
		&json!({"oneOf":[a.clone(),a.clone()]}),
		&json!({"a":1,"b":2}),
		&[]
	)
	.is_err());
	assert_eq!(
		selected(&json!({"anyOf":[a.clone(),a]}), &json!({"a":1,"b":2}), &[]).unwrap(),
		["a", "b"]
	);
}

#[test]
fn scalar_discriminators_required_fields_and_additional_properties_select_branches() {
	let schema = json!({"oneOf":[
		{"type":"object","properties":{"kind":{"enum":["first","also-first"]},"value":{"type":"integer"}},"required":["kind","value"],"additionalProperties":false,"x-hepta-object-order":["kind","value"]},
		{"type":"object","properties":{"value":{"type":"string"},"kind":{"const":"second"}},"required":["kind","value"],"additionalProperties":false,"x-hepta-object-order":["value","kind"]}
	]});
	assert_eq!(
		selected(&schema, &json!({"kind":"first","value":1.0}), &[]).unwrap(),
		["kind", "value"]
	);
	assert_eq!(
		selected(&schema, &json!({"kind":"second","value":"ok"}), &[]).unwrap(),
		["value", "kind"]
	);
	for invalid in [
		json!({"kind":"first"}),
		json!({"kind":"first","value":1.5}),
		json!({"kind":"second","value":"ok","extra":null}),
	] {
		assert!(selected(&schema, &invalid, &[]).is_err());
	}
}

#[test]
fn recursive_ref_and_external_ref_fail_without_looping() {
	let value = json!({});
	let cycle = json!({"$ref":"#/$defs/self","$defs":{"self":{"$ref":"#/$defs/self"}}});
	assert!(selected(&cycle, &value, &[]).is_err());
	assert!(selected(
		&json!({"$ref":"https://example.invalid/schema"}),
		&value,
		&[]
	)
	.is_err());
}

#[test]
fn generic_nonempty_objects_need_an_explicit_producer_rule() {
	assert!(selected(&json!({}), &json!({"b":2,"a":1}), &[]).is_err());
	assert!(selected(&json!({}), &json!({}), &[]).unwrap().is_empty());
}

#[test]
fn borrowed_bundle_routes_each_complete_record_to_its_operation_schema() {
	let value = record();
	let records = vec![&value];
	let artifact =
		json!({"digest":{"sha256":"0".repeat(64)},"format":"elf","architecture":"arm64"});
	let artifacts = vec![&artifact];
	let provider = vec![&value["provider"]];
	let fields = [
		("artifacts", JsonView::Values(&artifacts)),
		("providers", JsonView::Values(&provider)),
		("environments", JsonView::Array(&[])),
		("scenarios", JsonView::Array(&[])),
		("captures", JsonView::Array(&[])),
		("unknowns", JsonView::Array(&[])),
		("records", JsonView::Values(&records)),
	];
	let root = [("result", JsonView::Object(&fields))];
	let mut bytes = Vec::new();
	encoding::write_json_view(
		JsonView::Object(&root),
		&BundleOrder::new(&records, &[RecordOrigin::NativeTool]).unwrap(),
		number,
		&mut bytes,
	)
	.unwrap();
	let text = String::from_utf8(bytes).unwrap();
	assert!(text.starts_with("{\"result\":{\"artifacts\":[{\"digest\":{\"sha256\":"));
	assert!(text.contains("\"records\":[{\"evidence_id\":"));
	assert!(text.contains("\"normalized_result\":{\"artifact\":{\"path\":"));
	assert!(BundleOrder::new(&records, &[RecordOrigin::NativeTool])
		.unwrap()
		.keys(
			&[
				PathComponent::Key("result"),
				PathComponent::Key("records"),
				PathComponent::Index(1)
			],
			value.as_object().unwrap()
		)
		.is_err());
}

#[test]
fn bundle_manifest_fields_and_unknowns_are_closed_world() {
	let fields = json!({"id":"provider","name":"Provider","version":null});
	assert_eq!(
		BundleOrder::new(&[], &[])
			.unwrap()
			.keys(
				&[
					PathComponent::Key("result"),
					PathComponent::Key("providers"),
					PathComponent::Index(0)
				],
				fields.as_object().unwrap()
			)
			.unwrap(),
		["id", "name", "version"]
	);
	assert!(BundleOrder::new(&[], &[])
		.unwrap()
		.keys(
			&[
				PathComponent::Key("result"),
				PathComponent::Key("unknowns"),
				PathComponent::Index(0)
			],
			fields.as_object().unwrap()
		)
		.is_err());
	assert!(BundleOrder::new(&[], &[])
		.unwrap()
		.keys(
			&[
				PathComponent::Key("result"),
				PathComponent::Key("providers"),
				PathComponent::Index(0)
			],
			json!({"id":"p","name":"P","version":null,"extra":0})
				.as_object()
				.unwrap()
		)
		.is_err());
}

#[test]
fn bundle_summary_uses_real_kind_and_dynamic_filter_sequence() {
	let record = record();
	let summary = json!({"result":{"kind":"evidence-bundle-summary","filters":{"procedure_address":"1","operation":"inspect_elf_notes","evidence_id":record["evidence_id"]},"total_retained_records":1,"matching_records":1,"unknown_revisions":0,"records":[{"evidence_id":record["evidence_id"],"subject":record["subject"],"provider":record["provider"],"operation":record["operation"],"confidence":"observed","authority":"shipped-artifact","analysis_profile_digest":null,"retention":"complete-record","limitation_count":0,"native_dossier":{"available":false,"reason":"different-operation"}}]}});
	let order = BundleSummaryOrder(&summary);
	let mut out = Vec::new();
	encoding::write_json(&summary, &order, number, &mut out).unwrap();
	let text = String::from_utf8(out).unwrap();
	assert!(text.starts_with(
		"{\"result\":{\"kind\":\"evidence-bundle-summary\",\"filters\":{\"evidence_id\":"
	));
	assert_eq!(
		order
			.keys(
				&[PathComponent::Key("result"), PathComponent::Key("filters")],
				summary["result"]["filters"].as_object().unwrap()
			)
			.unwrap(),
		["evidence_id", "operation", "procedure_address"]
	);
	let b = Budget {
		bytes: 1,
		representations: Representations::StructuredAndText,
		target_content: true,
	};
	assert!(matches!(
		encoding::measure(&summary, &order, number, b).unwrap(),
		encoding::Measurement::Overflow { .. }
	));
	let mut bad = summary.clone();
	bad["result"]["filters"]["unknown"] = json!("bad");
	assert!(BundleSummaryOrder(&bad)
		.keys(
			&[PathComponent::Key("result"), PathComponent::Key("filters")],
			bad["result"]["filters"].as_object().unwrap()
		)
		.is_err());
}

#[test]
fn derived_view_parameter_order_requires_the_explicit_creation_origin() {
	let mut value = record();
	let digest = "0".repeat(64);
	let parent = format!("ev_{digest}");
	let view =
		json!({"kind":"apk-signature","offset":0,"limit":1,"collection":"signers","fields":["id"]});
	value["operation"] = json!("inspect_analysis_view");
	value["parameters"] = json!({"parent_evidence_id":parent,"view":view});
	value["normalized_result"] = json!({"parent_evidence_id":parent,"parent_operation":"inspect_apk_signature","parent_digest":digest,"view_digest":digest,"artifact":{"path":"/workspace/test.apk","sha256":digest},"coverage":{"status":"empty","examined":0,"total":0,"next_offset":null,"exhausted":true},"limitations":[],"unknowns":[],"kind":"apk-signature","view":view,"items":[],"source_coverage":{"scope":"declared-signing-records","uninterpreted_bytes":0,"signer_identity":"complete-within-records","lineage_decoding":"complete-within-records","signature_verification":"not-performed","v1_entry_coverage":"unknown","authenticity":"unknown"}});
	let path = [PathComponent::Key("parameters"), PathComponent::Key("view")];
	let object = value["parameters"]["view"].as_object().unwrap();
	assert_eq!(
		RecordOrder::new(&value, RecordOrigin::ApkToolDerived)
			.keys(&path, object)
			.unwrap(),
		["kind", "offset", "limit", "collection", "fields"]
	);
	assert_eq!(
		RecordOrder::new(&value, RecordOrigin::AnalysisViewToolDerived)
			.keys(&path, object)
			.unwrap(),
		["offset", "limit", "collection", "fields", "kind"]
	);
	for origin in [RecordOrigin::Unknown, RecordOrigin::NativeTool] {
		assert!(RecordOrder::new(&value, origin)
			.keys(&path, object)
			.is_err());
	}
}

#[test]
fn missing_or_incompatible_retention_provenance_is_not_inferred() {
	let value = record();
	let records = vec![&value];
	assert!(BundleOrder::new(&records, &[]).is_err());
	for origin in [
		RecordOrigin::Unknown,
		RecordOrigin::ApkToolDerived,
		RecordOrigin::AnalysisViewToolDerived,
	] {
		assert!(RecordOrder::new(&value, origin)
			.keys(&[], value.as_object().unwrap())
			.is_err());
		assert!(BundleOrder::new(&records, &[origin])
			.unwrap()
			.keys(
				&[
					PathComponent::Key("result"),
					PathComponent::Key("records"),
					PathComponent::Index(0)
				],
				value.as_object().unwrap()
			)
			.is_err());
	}
}
