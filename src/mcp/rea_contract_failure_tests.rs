// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Actual REA 6.8.0 response bodies, through the production import error route.
//! The observed diagnostic is an input here; parser and frame parity are separate.

use super::*;
use sha2::{Digest, Sha256};

const ORIGINAL: &[u8] = include_bytes!(
	"../../tests/fixtures/rea_evidence_file/import-error-text-original-rea-6_8_0-679ccf.json"
);
const ORIGINAL_SHA256: &str = "b74ccf73b6399eaa757514d8eed343a251a60ea11855f30deebb554d581e4d23";

fn original() -> Value {
	assert_eq!(format!("{:x}", Sha256::digest(ORIGINAL)), ORIGINAL_SHA256);
	serde_json::from_slice(ORIGINAL).unwrap()
}

fn unhex(text: &str) -> Vec<u8> {
	assert!(text.len().is_multiple_of(2));
	(0..text.len())
		.step_by(2)
		.map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
		.collect()
}

fn expected_error(case: &Value) -> Value {
	let response = &case["response"];
	let text = response["result"]["content"][0]["text"].as_str().unwrap();
	serde_json::from_str::<Value>(text).unwrap()["error"].clone()
}

fn prior_projection(error: Failure) {
	let before = serde_json::to_value(error.clone().wire()).unwrap();
	let after = serde_json::to_value(error_result(error)).unwrap();
	assert_eq!(after, before);
}

#[test]
fn original_import_error_fixture_preserves_source_and_response_bytes() {
	let fixture = original();
	assert_eq!(fixture["schema"], "hepta.rea.import-error-text.original.v1");
	assert_eq!(fixture["qualified"], false);
	assert_eq!(
		fixture["provenance"]["observation"]["sha256"],
		"797b320f3b9d7dec1b1677892531689469dbdf11ad12003482fa6195bf7f03b2"
	);
	assert_eq!(
		fixture["provenance"]["node"]["sha256"],
		"94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90"
	);
	assert_eq!(
		fixture["provenance"]["package"]["tarball"]["sha256"],
		"8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb"
	);
	let cases = fixture["cases"].as_array().unwrap();
	assert_eq!(cases.len(), 6);
	for case in cases {
		let wire = unhex(case["response_wire_hex"].as_str().unwrap());
		assert_eq!(
			serde_json::from_slice::<Value>(&wire).unwrap(),
			case["response"],
			"{}",
			case["id"]
		);
		assert_eq!(wire.last(), Some(&b'\n'));
		assert_eq!(
			format!(
				"{:x}",
				Sha256::digest(unhex(case["input_hex"].as_str().unwrap()))
			),
			case["input_identity"]["sha256"].as_str().unwrap()
		);
		assert_eq!(case["arguments"]["path"], case["input_identity"]["path"]);
	}
}

#[test]
fn observed_import_failures_match_the_original_complete_tool_results() {
	let fixture = original();
	for case in fixture["cases"].as_array().unwrap() {
		let error = expected_error(case);
		let failure = match case["family"].as_str().unwrap() {
			"invalid-json" => file_failure(
				FileReadError::InvalidJson {
					message: error["details"]["content_issues"][0]["message"]
						.as_str()
						.unwrap()
						.to_owned(),
					user_message: None,
				},
				error["details"]["path"].as_str().unwrap(),
			),
			"invalid-bundle" => source_failure(
				ImportSourceError::Source(SourceError::InvalidBundle {
					message: error["message"].as_str().unwrap().to_owned(),
				}),
				case["arguments"]["path"].as_str().unwrap(),
			),
			family => panic!("unobserved fixture family {family}"),
		};
		let previous = failure.clone().wire();
		let actual = error_result(failure);
		assert_eq!(actual.is_error, Some(true), "{}", case["id"]);
		assert!(actual.structured_content.is_none(), "{}", case["id"]);
		assert_eq!(
			serde_json::to_value(&actual).unwrap(),
			case["response"]["result"],
			"{}",
			case["id"]
		);
		let old_text = &previous.content[0].as_text().unwrap().text;
		let text = &actual.content[0].as_text().unwrap().text;
		assert_ne!(old_text, text, "fixture must catch the prior key-order gap");
		assert_eq!(
			serde_json::from_str::<Value>(old_text).unwrap(),
			serde_json::from_str::<Value>(text).unwrap(),
			"the change is presentation-only: {}",
			case["id"]
		);
	}
}

#[test]
fn unobserved_import_error_families_keep_their_previous_complete_projection() {
	prior_projection(Failure::input(
		OP,
		vec![
			json!({"path":["path"],"reason":"invalid_type","message":"required","expected":"string"}),
		],
	));
	prior_projection(profile_gap(
		"unpaired surrogate",
		json!({"boundary":"JSON-string"}),
	));
	prior_projection(Failure::output(OP, "independent native failure"));
	prior_projection(file_failure(
		FileReadError::File {
			reason: FileReason::Io,
			errno: Some(13),
		},
		"/owned/record.json",
	));
	prior_projection(Failure::integrity("unobserved integrity reason"));
	let fixture = original();
	prior_projection(Failure(expected_error(&fixture["cases"][0])).partial(json!({"z":1,"a":2})));
}

#[test]
fn extra_members_and_unobserved_issue_shapes_are_not_dropped_or_reordered() {
	let fixture = original();
	let observed = expected_error(&fixture["cases"][0]);
	let mut root_extra = observed.clone();
	root_extra["unobserved"] = json!({"z":1,"a":2});
	prior_projection(Failure(root_extra));
	let mut details_extra = observed.clone();
	details_extra["details"]["native_profile"] = json!({"z":1,"a":2});
	prior_projection(Failure(details_extra));
	let mut issue_extra = observed.clone();
	issue_extra["details"]["content_issues"][0]["extra"] = json!({"z":1,"a":2});
	prior_projection(Failure(issue_extra));
	let mut other_path = observed;
	other_path["details"]["content_issues"][0]["path"] = json!(["different"]);
	prior_projection(Failure(other_path));
}

#[test]
fn plain_sdk_schema_exception_text_and_presence_are_unchanged() {
	let result = error_result(Failure::schema_exception(
		"Cannot convert undefined or null to object",
	));
	assert_eq!(result.is_error, Some(true));
	assert!(result.structured_content.is_none());
	assert_eq!(
		result.content[0].as_text().unwrap().text,
		"Cannot convert undefined or null to object"
	);
	assert_eq!(
		serde_json::to_value(result).unwrap(),
		serde_json::to_value(
			Failure::schema_exception("Cannot convert undefined or null to object").wire()
		)
		.unwrap()
	);
}

const ORIGINAL_118: &[u8] = include_bytes!(
	"../../tests/fixtures/rea_evidence_file/import-error-text-original-118-rea-6_8_0-679ccf.json"
);

fn original_118() -> Value {
	assert_eq!(
		format!("{:x}", Sha256::digest(ORIGINAL_118)),
		"d15eb3fcc59d06c47e06f8efcc92978a7ef29aa679f808dda005fa078c434317"
	);
	serde_json::from_slice(ORIGINAL_118).unwrap()
}

fn original_response(case: &Value) -> Value {
	serde_json::from_slice(&unhex(case["response_wire_hex"].as_str().unwrap())).unwrap()
}

fn original_input_order(case: &Value) -> Vec<String> {
	case["argument_root_order"]
		.as_array()
		.unwrap()
		.iter()
		.map(|key| key.as_str().unwrap().to_owned())
		.collect()
}

fn observed_118_failure(case: &Value, expected: &Value) -> Failure {
	let path = case["arguments"]["path"]
		.as_str()
		.unwrap_or("/unused-schema-path");
	if case["id"] == "exception/exception-path" {
		return super::super::rea_mcp_input::import_ordered(
			&case["arguments"],
			Some(&original_input_order(case)),
		)
		.unwrap_err();
	}
	if case["kind"] == "plain" {
		assert_eq!(
			expected["result"]["content"][0]["text"],
			"Cannot convert object to primitive value"
		);
		return source_failure(
			ImportSourceError::Source(SourceError::SchemaException {
				message: "Cannot convert object to primitive value",
			}),
			path,
		);
	}
	let text = expected["result"]["content"][0]["text"].as_str().unwrap();
	let payload: Value = serde_json::from_str(text).unwrap();
	let error = &payload["error"];
	if error.get("recovery").is_some() {
		return super::super::rea_mcp_input::import_ordered(
			&case["arguments"],
			Some(&original_input_order(case)),
		)
		.unwrap_err();
	}
	match error["details"]["reason"].as_str().unwrap() {
		"invalid-json" => {
			let public = error["message"].as_str().unwrap();
			file_failure(
				FileReadError::InvalidJson {
					message: error["details"]["content_issues"][0]["message"]
						.as_str()
						.unwrap()
						.to_owned(),
					user_message: (public != "Evidence file is not valid JSON. Repair or recreate the file and try again.")
						.then(|| public.to_owned()),
				},
				path,
			)
		}
		"Evidence bundle validation failed" => source_failure(
			ImportSourceError::Source(SourceError::InvalidBundle {
				message: error["message"].as_str().unwrap().to_owned(),
			}),
			path,
		),
		reason @ ("Conflicting unknown revision" | "Evidence bundle unknown registry failed") => {
			Failure::integrity(reason)
		}
		"wrong-kind" => source_failure(
			ImportSourceError::SingleRecord {
				evidence_id: case["single_record_evidence_id"]
					.as_str()
					.unwrap()
					.to_owned(),
			},
			path,
		),
		reason @ ("missing" | "not-file") => file_failure(
			FileReadError::File {
				reason: if reason == "missing" {
					FileReason::Missing
				} else {
					FileReason::NotFile
				},
				errno: None,
			},
			path,
		),
		reason => panic!("unobserved original error reason {reason}"),
	}
}

#[test]
fn original_118_error_fixture_binds_all_42_requests_and_responses() {
	let fixture = original_118();
	assert_eq!(fixture["qualified"], false);
	assert_eq!(
		fixture["provenance"]["qualification"]["sha256"],
		"37054a6411d39221d7a31a1ef1a90696c90100f4d0bb21ccf55737d27e90b42d"
	);
	let cases = fixture["cases"].as_array().unwrap();
	assert_eq!(cases.len(), 42);
	let mut kinds = (0, 0);
	for case in cases {
		assert_eq!(case["operation"], "import_evidence_bundle");
		let request_bytes = unhex(case["request_wire_hex"].as_str().unwrap());
		let response_bytes = unhex(case["response_wire_hex"].as_str().unwrap());
		let request: Value = serde_json::from_slice(&request_bytes).unwrap();
		let response: Value = serde_json::from_slice(&response_bytes).unwrap();
		assert_eq!(request["method"], "tools/call");
		assert_eq!(request["params"]["name"], case["operation"]);
		assert_eq!(request["params"]["arguments"], case["arguments"]);
		assert_eq!(request["id"], response["id"]);
		assert_eq!(response["result"]["isError"], true);
		assert_eq!(
			format!("{:x}", Sha256::digest(&request_bytes)),
			case["request_wire_record"]["raw_sha256"].as_str().unwrap()
		);
		assert_eq!(
			format!("{:x}", Sha256::digest(&response_bytes)),
			case["source_wire_record"]["raw_sha256"].as_str().unwrap()
		);
		match case["kind"].as_str().unwrap() {
			"json" => kinds.0 += 1,
			"plain" => kinds.1 += 1,
			kind => panic!("unexpected original error representation {kind}"),
		}
	}
	assert_eq!(kinds, (38, 4));
}

#[test]
fn all_38_original_json_errors_and_four_sdk_exceptions_match_complete_text() {
	let fixture = original_118();
	for case in fixture["cases"].as_array().unwrap() {
		let expected = original_response(case);
		let failure = observed_118_failure(case, &expected);
		let previous = failure.clone().wire();
		let actual = error_result(failure);
		let text = &actual.content[0].as_text().unwrap().text;
		let expected_text = expected["result"]["content"][0]["text"].as_str().unwrap();
		assert_eq!(text.as_bytes(), expected_text.as_bytes(), "{}", case["id"]);
		assert_eq!(
			serde_json::to_value(&actual).unwrap(),
			expected["result"],
			"{}",
			case["id"]
		);
		assert_eq!(actual.is_error, Some(true));
		assert!(actual.structured_content.is_none());
		let old_text = &previous.content[0].as_text().unwrap().text;
		if case["kind"] == "json" {
			assert_ne!(
				old_text, text,
				"original must catch prior text order: {}",
				case["id"]
			);
			assert_eq!(
				serde_json::from_str::<Value>(old_text).unwrap(),
				serde_json::from_str::<Value>(text).unwrap()
			);
		} else {
			assert_eq!(old_text, text);
		}
	}
}

#[test]
fn input_order_remains_import_only_and_rejects_unobserved_issue_members() {
	let fixture = original_118();
	let case = fixture["cases"]
		.as_array()
		.unwrap()
		.iter()
		.find(|case| case["id"] == "main/input-0")
		.unwrap();
	let response = original_response(case);
	let text = response["result"]["content"][0]["text"].as_str().unwrap();
	let observed = serde_json::from_str::<Value>(text).unwrap()["error"].clone();
	let mut other_operation = observed.clone();
	other_operation["details"]["operation"] = json!("get_evidence_bundle");
	other_operation["recovery"]["operation"] = json!("get_evidence_bundle");
	prior_projection(Failure(other_operation));
	let mut richer_issue = observed.clone();
	richer_issue["details"]["issues"][0]["expected"] = json!("string");
	prior_projection(Failure(richer_issue));
	let mut extra_recovery = observed.clone();
	extra_recovery["recovery"]["extra"] = json!(true);
	prior_projection(Failure(extra_recovery));
	prior_projection(Failure(observed).partial(json!({"z":1,"a":2})));
}
