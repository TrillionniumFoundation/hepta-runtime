// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Two real public overflow frames, with synthetic conservative fallback controls.
//! Production compilation/execution is separate from the offline fixture capture.

use super::*;
use sha2::{Digest, Sha256};

const FIXTURE: &[u8] = include_bytes!(
	"../../tests/fixtures/rea_evidence_file/overflow-error-text-original-rea-6_8_0-679ccf.json"
);

fn hex(bytes: impl AsRef<[u8]>) -> String {
	Sha256::digest(bytes)
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}

fn fixture() -> Value {
	assert_eq!(
		hex(FIXTURE),
		"2da4d1780865ac45738d1fa97d4869b02f02663f1951cb12e9c87127c6333442"
	);
	serde_json::from_slice(FIXTURE).unwrap()
}

fn unhex(text: &str) -> Vec<u8> {
	assert!(text.len().is_multiple_of(2));
	(0..text.len())
		.step_by(2)
		.map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
		.collect()
}

fn response(capture: &Value) -> Value {
	serde_json::from_slice(&unhex(capture["response_wire_hex"].as_str().unwrap())).unwrap()
}

fn error(case: &Value) -> Value {
	let frame = response(&case["reference"]);
	serde_json::from_str::<Value>(frame["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
		["error"]
		.clone()
}

fn legacy_public_result(result: &CallToolResult) -> Value {
	assert_eq!(
		serde_json::to_value(result).unwrap()["resultType"],
		"complete"
	);
	let mut response = rmcp::model::ServerResult::CallToolResult(result.clone());
	response.strip_result_type_for_legacy_peer();
	serde_json::to_value(response).unwrap()
}

fn prior_projection(value: Value) {
	let prior = Failure(value.clone()).wire();
	let actual = Failure(value).wire_overflow();
	assert_eq!(
		serde_json::to_value(actual).unwrap(),
		serde_json::to_value(prior).unwrap(),
		"unobserved data must retain the entire previous result"
	);
}

#[test]
fn actual_overflow_fixture_binds_both_original_and_native_frames_and_inputs() {
	let fixture = fixture();
	assert_eq!(
		fixture["schema"],
		"hepta.rea.overflow-error-text.original.v1"
	);
	assert_eq!(fixture["qualified"], false);
	assert_eq!(fixture["provenance"]["original_red_preserved"], true);
	assert_eq!(
		fixture["provenance"]["source_commit"],
		"6c224e4d913dd596e44fb936e22b447531f8962b"
	);
	assert_eq!(
		fixture["provenance"]["runtime"]["sha256"],
		"170117339fdeeb6632a6df545fbfba4fce8254f41dd763b55df6b38cee57858f"
	);
	assert_eq!(
		fixture["provenance"]["reference_package"]["version"],
		"6.8.0"
	);
	assert_eq!(
		fixture["provenance"]["reference_package"]["file_count"],
		2398
	);
	assert_eq!(
		fixture["provenance"]["node"]["sha256"],
		"94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90"
	);
	let cases = fixture["cases"].as_array().unwrap();
	assert_eq!(cases.len(), 2);
	assert_eq!(cases[0]["id"], "producer/body-overflow");
	assert_eq!(cases[1]["id"], "import/bundle-overflow");
	for case in cases {
		for label in ["reference", "native"] {
			let capture = &case[label];
			assert_eq!(capture["operation"], case["operation"]);
			assert_eq!(capture["arguments"], case["arguments"]);
			assert_eq!(capture["initialization"]["protocol_version"], "2025-11-25");
			let request_raw = unhex(capture["request_wire_hex"].as_str().unwrap());
			let response_raw = unhex(capture["response_wire_hex"].as_str().unwrap());
			assert_eq!(request_raw.last(), Some(&b'\n'));
			assert_eq!(response_raw.last(), Some(&b'\n'));
			assert_eq!(
				hex(&request_raw),
				capture["request_wire_record"]["raw_sha256"]
					.as_str()
					.unwrap()
			);
			assert_eq!(
				hex(&response_raw),
				capture["response_wire_record"]["raw_sha256"]
					.as_str()
					.unwrap()
			);
			let request: Value = serde_json::from_slice(&request_raw).unwrap();
			let reply: Value = serde_json::from_slice(&response_raw).unwrap();
			assert_eq!(request["method"], "tools/call");
			assert_eq!(request["params"]["arguments"], case["arguments"]);
			assert_eq!(request["id"], reply["id"]);
			assert_eq!(reply["result"]["isError"], true);
			assert!(reply["result"].get("structuredContent").is_none());
			assert_eq!(capture["close"]["returncode"], 0);
			assert_eq!(capture["close"]["owner_pidfd_exited"], true);
			assert_eq!(capture["close"]["process_group_gone"], true);
		}
	}
	assert_eq!(fixture["inputs"].as_array().unwrap().len(), 2);
	assert_eq!(fixture["setup"].as_array().unwrap().len(), 2);
	assert_eq!(cases[0]["arguments"]["path"], fixture["inputs"][0]["path"]);
	for setup in fixture["setup"].as_array().unwrap() {
		assert_eq!(setup["call"]["operation"], "import_evidence_bundle");
		assert_eq!(
			setup["call"]["arguments"]["path"],
			fixture["inputs"][1]["path"]
		);
		assert_eq!(setup["seed_input"], fixture["inputs"][1]);
	}
}

#[test]
fn observed_overflow_factory_matches_original_complete_error_text() {
	let fixture = fixture();
	for case in fixture["cases"].as_array().unwrap() {
		let measured = &case["measurement"];
		let failure = overflow(
			case["operation"].as_str().unwrap(),
			measured["response_bytes"].as_u64().unwrap() as usize,
			&WireMeasurement {
				bytes: measured["bytes_at_least"].as_u64().unwrap(),
				code_units: measured["code_units_at_least"].as_u64().unwrap(),
				constraint: "receive-buffer",
			},
			(!case["retained"].is_null()).then(|| case["retained"].clone()),
			case["bundle_summary"].as_bool().unwrap(),
		);
		assert_eq!(failure.0, error(case), "{}", case["id"]);
		let prior = failure.clone().wire();
		let actual = failure.wire_overflow();
		let expected = response(&case["reference"]);
		let observed_native = response(&case["native"]);
		assert_eq!(
			legacy_public_result(&prior),
			observed_native["result"],
			"the fixture must retain the real pre-fix public result"
		);
		assert_eq!(
			legacy_public_result(&actual),
			expected["result"],
			"{}",
			case["id"]
		);
		let before = &prior.content[0].as_text().unwrap().text;
		let after = &actual.content[0].as_text().unwrap().text;
		assert_ne!(
			before, after,
			"the actual fixture must detect the former gap"
		);
		assert_eq!(
			after.as_bytes(),
			expected["result"]["content"][0]["text"]
				.as_str()
				.unwrap()
				.as_bytes()
		);
		assert_eq!(
			serde_json::from_str::<Value>(before).unwrap(),
			serde_json::from_str::<Value>(after).unwrap(),
			"member order must not alter payload values"
		);
		assert!(actual.structured_content.is_none());
	}
}

#[test]
fn every_missing_or_additional_overflow_member_keeps_the_prior_projection() {
	let fixture = fixture();
	for case in fixture["cases"].as_array().unwrap() {
		let original = error(case);
		let mut paths = vec!["", "/remediation", "/details", "/details/reported_limits"];
		if !case["retained"].is_null() {
			paths.push("/details/reported_limits/evidence_reference");
		}
		for path in paths {
			let keys: Vec<_> = original
				.pointer(path)
				.unwrap()
				.as_object()
				.unwrap()
				.keys()
				.cloned()
				.collect();
			for key in keys {
				let mut missing = original.clone();
				missing
					.pointer_mut(path)
					.unwrap()
					.as_object_mut()
					.unwrap()
					.remove(&key);
				prior_projection(missing);
			}
			let mut extra = original.clone();
			extra.pointer_mut(path).unwrap()["unobserved"] =
				json!({"full_nested_payload":["keep", 1, true]});
			prior_projection(extra);
			let mut empty = original.clone();
			*empty.pointer_mut(path).unwrap() = json!({});
			prior_projection(empty);
		}
		prior_projection(
			Failure(original)
				.partial(json!({"observation":"must be preserved"}))
				.0,
		);
	}
}

#[test]
fn unobserved_overflow_semantics_and_scalar_types_are_not_reclassified() {
	let fixture = fixture();
	for case in fixture["cases"].as_array().unwrap() {
		let original = error(case);
		for (path, value) in [
			("/code", json!("different")),
			("/category", json!("execution_failure")),
			("/retryable", json!(true)),
			("/message", json!("unobserved wording")),
			("/remediation/action", json!("unobserved remediation")),
			("/details/operation", json!("inspect_elf_notes")),
			("/details/resource", json!("memory")),
			("/details/reason", json!("different reason")),
			("/details/reported_limits/boundary", json!("other")),
			(
				"/details/reported_limits/constraint",
				json!("string-length"),
			),
			(
				"/details/reported_limits/default_receive_buffer_bytes",
				json!(1),
			),
			(
				"/details/reported_limits/result_budget_bytes",
				json!(20_970_496),
			),
			("/details/reported_limits/max_string_code_units", json!(1)),
			("/details/reported_limits/response_bytes_at_least", json!(1)),
			(
				"/details/reported_limits/response_code_units_at_least",
				json!(0),
			),
		] {
			let mut changed = original.clone();
			*changed.pointer_mut(path).unwrap() = value;
			prior_projection(changed);
		}
		for path in [
			"/code",
			"/category",
			"/message",
			"/retryable",
			"/remediation/action",
			"/details/operation",
			"/details/resource",
			"/details/reason",
			"/details/reported_limits/boundary",
			"/details/reported_limits/constraint",
			"/details/reported_limits/default_receive_buffer_bytes",
			"/details/reported_limits/result_budget_bytes",
			"/details/reported_limits/max_string_code_units",
			"/details/reported_limits/response_bytes_at_least",
			"/details/reported_limits/response_code_units_at_least",
		] {
			let mut wrong_type = original.clone();
			*wrong_type.pointer_mut(path).unwrap() = json!({"unexpected":true});
			prior_projection(wrong_type);
		}
	}
	let retained = error(&fixture["cases"][0]);
	for (path, value) in [
		("/details/reported_limits/evidence_id", json!("ev_invalid")),
		(
			"/details/reported_limits/evidence_reference/kind",
			json!("unknown"),
		),
		(
			"/details/reported_limits/evidence_reference/evidence_id",
			json!(format!("ev_{}", "0".repeat(64))),
		),
	] {
		let mut changed = retained.clone();
		*changed.pointer_mut(path).unwrap() = value;
		prior_projection(changed);
	}
	let mut no_reference = retained;
	no_reference["details"]["reported_limits"]
		.as_object_mut()
		.unwrap()
		.remove("evidence_reference");
	prior_projection(no_reference);
	let mut unexpected_reference = error(&fixture["cases"][1]);
	unexpected_reference["details"]["reported_limits"]["evidence_reference"] =
		fixture["cases"][0]["retained"].clone();
	prior_projection(unexpected_reference);
}

#[test]
fn unrelated_and_plain_sdk_errors_keep_the_generic_wire_path() {
	prior_projection(Failure::integrity("unobserved reason").0);
	prior_projection(Failure::schema_exception("Cannot convert undefined or null to object").0);
	prior_projection(Failure::output("inspect_apk_signature", "independent failure").0);
}
