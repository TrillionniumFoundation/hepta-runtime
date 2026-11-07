// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Boundary regressions for the registered HIA application contract.

use super::*;

fn reference() -> Value {
	json!({"id":"item", "sha256":"a".repeat(64), "uri":"hia://artifacts/issued-item"})
}
fn profile() -> Value {
	json!({"id":"profile", "sha256":"b".repeat(64)})
}
fn verify_request() -> Value {
	json!({"catalog_sha256":"a".repeat(64), "context":profile(), "request_key":"verify-1",
		"candidate":reference(), "base_program":null, "validation_profile":profile(),
		"subject":{"kind":"core"}, "claims":["core_admission"]})
}

#[test]
fn all_tools_expose_the_exact_reviewed_schemas() {
	let source: Value = serde_json::from_slice(CATALOG_BYTES).unwrap();
	assert_eq!(source["tools"].as_array().unwrap().len(), TOOLS.len());
	for tool in source["tools"].as_array().unwrap() {
		let name = tool["name"].as_str().unwrap();
		assert_eq!(
			&*input_schema(name),
			tool["inputSchema"].as_object().unwrap()
		);
		assert_eq!(
			&*output_schema(name),
			tool["outputSchema"].as_object().unwrap()
		);
		assert_eq!(tool["inputSchema"]["additionalProperties"], false);
	}
}

#[test]
fn arbitrary_executables_and_unknown_nested_authority_are_not_tool_arguments() {
	let mut request = json!({"section":"manifest"});
	validate_input("hia_describe", &request).unwrap();
	request["executable"] = json!("/bin/sh");
	assert!(validate_input("hia_describe", &request).is_err());
	let mut request = verify_request();
	validate_input("hia_verify", &request).unwrap();
	request["context"]["authority"] = json!(true);
	assert!(validate_input("hia_verify", &request).is_err());
	assert!(validate_input("hia_unregistered", &json!({})).is_err());
}

#[test]
fn equivalence_and_refinement_cannot_omit_their_actual_subjects() {
	let mut request = verify_request();
	request["claims"] = json!(["behavior_equivalence"]);
	assert!(validate_input("hia_verify", &request).is_err());
	request["base_program"] = reference();
	validate_input("hia_verify", &request).unwrap();
	request["claims"] = json!(["lowering_refinement"]);
	assert!(validate_input("hia_verify", &request).is_err());
	request["subject"] = json!({"kind":"canonical_lowering", "backend_profile":profile(), "lowering_profile":profile()});
	validate_input("hia_verify", &request).unwrap();
	request["claims"] = json!(["encoding_check"]);
	assert!(validate_input("hia_verify", &request).is_err());
}

#[test]
fn version_numbers_remain_lossless_and_bounded() {
	let mut request = json!({"catalog_sha256":"a".repeat(64), "context":profile(), "request_key":"adopt-1",
		"target_slot":"main", "expected_current":{"generation":"18446744073709551615", "epoch":"0"},
		"candidate_artifact":reference(), "evaluation_receipt":reference(), "verification_receipts":[reference()]});
	validate_input("hia_adopt", &request).unwrap();
	request["expected_current"]["generation"] = json!("18446744073709551616");
	assert!(validate_input("hia_adopt", &request).is_err());
	request["expected_current"]["generation"] = json!(9007199254740992_u64);
	assert!(validate_input("hia_adopt", &request).is_err());
	request["expected_current"]["generation"] = json!("01");
	assert!(validate_input("hia_adopt", &request).is_err());
}

#[test]
fn accepted_operations_cannot_claim_a_completed_result() {
	let mut response = json!({"contract_version":CONTRACT_VERSION, "request_id":"req-1", "status":"accepted",
		"operation":{"host":"test", "job_id":"job-1", "request_sha256":"a".repeat(64), "report_artifact":null}});
	validate_output("hia_emit", &response).unwrap();
	response["result"] = json!({});
	assert!(validate_output("hia_emit", &response).is_err());
	response.as_object_mut().unwrap().remove("result");
	response["status"] = json!("completed");
	assert!(validate_output("hia_emit", &response).is_err());
}

#[test]
fn emission_cannot_claim_execution_adoption_or_a_hidden_compiler() {
	let result = json!({"candidate":reference(), "native_artifact":reference(), "build_receipt":reference(),
		"backend_profile":profile(), "target_profile":profile(), "codegen_backend":"hia-direct",
		"llvm_codegen_used":false, "external_assembler_used":false, "linker_used":false,
		"native_execution_observed":false, "adopted":false});
	let response = json!({"contract_version":CONTRACT_VERSION, "request_id":"emit-1", "status":"completed", "result":result});
	validate_output("hia_emit", &response).unwrap();
	for field in [
		"llvm_codegen_used",
		"external_assembler_used",
		"native_execution_observed",
		"adopted",
	] {
		let mut changed = response.clone();
		changed["result"][field] = json!(true);
		assert!(validate_output("hia_emit", &changed).is_err(), "{field}");
	}
}

#[test]
fn resource_uris_are_exact_opaque_names_and_pages_are_bounded() {
	validate_input(
		"hia_resource_read",
		&json!({"uri":"hia://artifacts/issued~item", "max_bytes":512}),
	)
	.unwrap();
	for uri in [
		"hia://artifacts/../escape",
		"hia://artifacts/a?hash=x",
		"hia://artifacts/",
		"file:///tmp/a",
		"hia://artifacts/a/b",
	] {
		assert!(
			validate_input("hia_resource_read", &json!({"uri":uri})).is_err(),
			"{uri}"
		);
	}
	assert!(validate_input(
		"hia_resource_read",
		&json!({"uri":"hia://artifacts/a", "max_bytes":65537})
	)
	.is_err());
	assert!(validate_input(
		"hia_resource_read",
		&json!({"uri":"hia://artifacts/a", "authority":true})
	)
	.is_err());
}

#[test]
fn a_new_schema_constraint_cannot_be_silently_ignored() {
	assert!(validate_vocabulary(
		&json!({"type":"string", "unimplemented_constraint":true}),
		&mut BTreeMap::new()
	)
	.is_err());
}

#[test]
fn maximum_escaped_read_page_fits_the_actual_dual_content_wire_limit() {
	let response = json!({"contract_version":CONTRACT_VERSION, "request_id":"page-1", "status":"completed",
		"result":{"artifact":reference(), "encoding":"utf8", "content":"\0".repeat(65536), "next_cursor":null}});
	validate_output("hia_read", &response).unwrap();
	assert!(serde_json::to_vec(&response).unwrap().len() < MAX_WORKER_BYTES);
	let result = wire(response).unwrap();
	assert!(
		serde_json::to_vec(&result).unwrap().len() < crate::utils::truncation::MAX_RESULT_BYTES
	);
	validate_input(
		"hia_describe",
		&json!({"section":"manifest", "max_bytes":512.0}),
	)
	.unwrap();
}
