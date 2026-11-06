// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Original opaque error text remains the oracle at the error encoder boundary.

use super::*;

fn fixture() -> Value {
	serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_elf_evidence_error_text.json"
	))
	.unwrap()
}

fn original_failure(case: &Value) -> Value {
	let original: Value = serde_json::from_str(case["original_text"].as_str().unwrap()).unwrap();
	original["error"].clone()
}

fn failure_from_public_constructor(case: &Value) -> Failure {
	if case["id"] == "producer/invalid-limit" {
		// The MCP schema guard supplies its own message and aggregated issue.
		// Reuse the original call's arguments; this guard never reads the path.
		return super::super::rea_mcp_input::elf(&json!({
			"path":concat!(
				"/home/qian-qi/work/",
				"hepta-rea-family-ecb0b9d61c75-20261106-evidence/",
				"elf-family-r1/workspace/small.elf"
			),
			"max_entries":false
		}))
		.unwrap_err();
	}
	let error = original_failure(case);
	let details = &error["details"];
	let operation = details["operation"].as_str().unwrap();
	match error["code"].as_str().unwrap() {
		"invalid_request" => {
			Failure::input(operation, details["issues"].as_array().unwrap().clone())
		}
		"unsupported_target" => Failure::unsupported(
			operation,
			details["path"].as_str().unwrap(),
			details["reason"].as_str().unwrap(),
		),
		"resource_constraint" if details["resource"] == "transport" => {
			let limits = &details["reported_limits"];
			let measured = WireMeasurement {
				bytes: limits["response_bytes_at_least"].as_u64().unwrap(),
				code_units: limits["response_code_units_at_least"].as_u64().unwrap(),
				constraint: "receive-buffer",
			};
			assert_eq!(limits["constraint"], "receive-buffer");
			overflow(
				operation,
				limits["result_budget_bytes"].as_u64().unwrap() as usize + ENVELOPE_RESERVATION,
				&measured,
				limits.get("evidence_reference").cloned(),
				false,
			)
		}
		"resource_constraint" => Failure::resource(
			operation,
			details["resource"].as_str().unwrap(),
			details["reason"].as_str().unwrap(),
			details["reported_limits"].clone(),
			error["retryable"].as_bool().unwrap(),
			error["remediation"]["action"].as_str().unwrap(),
		),
		other => panic!("Unadmitted original fixture failure: {other}"),
	}
}

#[test]
fn original_elf_evidence_failure_text_matches_without_normalizing_the_oracle() {
	let reference = fixture();
	let cases = reference["cases"].as_array().unwrap();
	assert_eq!(cases.len(), 10);
	for case in cases {
		let failure = failure_from_public_constructor(case);
		let result = failure.wire();
		assert_eq!(result.is_error, Some(true));
		assert!(result.structured_content.is_none());
		// The SDK subsequently applies negotiated resultType normalization.
		// Opaque content.text and provenance must already match the actual
		// original wire; parsing the oracle above never rewrites this expected text.
		assert_eq!(
			result.content[0].as_text().unwrap().text.as_bytes(),
			case["original_text"].as_str().unwrap().as_bytes(),
			"{}",
			case["id"]
		);
		assert_eq!(
			serde_json::to_value(&result.content).unwrap(),
			case["original_result"]["content"],
			"{}",
			case["id"]
		);
		assert_eq!(
			serde_json::to_value(&result.meta).unwrap(),
			case["original_result"]["_meta"],
			"{}",
			case["id"]
		);
	}
}

#[test]
fn unknown_members_at_each_admitted_level_preserve_the_complete_fallback() {
	let reference = fixture();
	let cases = reference["cases"].as_array().unwrap();
	for (id, pointer) in [
		("producer/corrupt-elf", ""),
		("producer/corrupt-elf", "/remediation"),
		("producer/corrupt-elf", "/recovery"),
		("producer/corrupt-elf", "/details"),
		("producer/corrupt-elf", "/details/issues/0"),
		("producer/file-budget", "/details/reported_limits"),
		("producer/body-overflow", "/details/reported_limits"),
		(
			"producer/body-overflow",
			"/details/reported_limits/evidence_reference",
		),
	] {
		let case = cases.iter().find(|case| case["id"] == id).unwrap();
		let mut error = original_failure(case);
		error
			.pointer_mut(pointer)
			.unwrap()
			.as_object_mut()
			.unwrap()
			.insert("native_diagnostic".to_owned(), json!({"z":1,"a":[2,3]}));
		let expected = json!({"error":error.clone()}).to_string();
		let result = Failure(error).wire();
		assert_eq!(
			result.content[0].as_text().unwrap().text,
			expected,
			"{id}: {pointer}"
		);
		assert_eq!(result.is_error, Some(true));
	}
}

#[test]
fn nonfamily_failures_and_native_budgets_keep_the_existing_complete_text() {
	for failure in [
		Failure::input(
			"import_evidence_bundle",
			vec![json!({"path":["path"],"reason":"invalid_value","message":"unchanged import"})],
		),
		Failure::unsupported("inspect_apk_signature", "/fixture.apk", "other operation"),
		Failure::resource(
			"rea_read_evidence_bundle",
			"capacity",
			"native snapshot limit",
			json!({"native_profile":true,"concurrent_snapshots":4}),
			false,
			"Release an owned snapshot.",
		),
		Failure::resource(
			"inspect_elf_notes",
			"capacity",
			"native parser capacity",
			json!({"native_workers":4}),
			true,
			"Wait for an owned worker.",
		),
		Failure::cancelled("inspect_elf_notes")
			.partial(json!({"kind":"retained-evidence","evidence_id":"opaque"})),
	] {
		let expected = json!({"error":failure.0.clone()}).to_string();
		assert_eq!(failure.wire().content[0].as_text().unwrap().text, expected);
	}
	let message = "Cannot convert object to primitive value";
	assert_eq!(
		Failure::schema_exception(message).wire().content[0]
			.as_text()
			.unwrap()
			.text,
		message
	);
}
