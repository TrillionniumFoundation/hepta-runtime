// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
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

//! Envelope, independent readout and worker-ownership controls for semantic replay.

use super::*;
use serde_json::{json, Value};
use std::time::Duration;

pub(crate) fn envelope(request_json: String) -> SemanticReplayParams {
	SemanticReplayParams {
		expected_request_sha256: sha(request_json.as_bytes()),
		expected_core_source_sha256: sha(include_bytes!("weight_semantic/lib.rs")),
		expected_target_contract_sha256: sha(TARGET_CONTRACT),
		request_json,
	}
}

pub(crate) fn fixture() -> SemanticReplayParams {
	envelope(serde_json::to_string(&core_tests::base()).unwrap())
}

#[tokio::test]
#[serial_test::serial(weight_semantic_worker)]
async fn replay_binds_raw_envelope_and_retains_readonly_scope() {
	let mut params = fixture();
	params.request_json.push_str("\n ");
	params.expected_request_sha256 = sha(params.request_json.as_bytes());
	let text = replay(params.clone()).await.unwrap();
	let value: Value = serde_json::from_str(&text).unwrap();
	assert_eq!(value["schema"], "hepta.weight-semantic-replay.result.v1");
	assert_eq!(
		value["adapter_schema"],
		"hepta.weight-semantic-replay.mcp.v1"
	);
	assert_eq!(value["request_sha256"], params.expected_request_sha256);
	assert_eq!(value["request_bytes"], params.request_json.len());
	assert_eq!(
		value["implementation_sha256"],
		params.expected_core_source_sha256
	);
	assert_eq!(
		value["core_source_sha256"],
		params.expected_core_source_sha256
	);
	assert_eq!(
		value["target_contract_sha256"],
		params.expected_target_contract_sha256
	);
	assert_eq!(
		value["adapter_source_sha256"],
		sha(include_bytes!("weight_semantic.rs"))
	);
	assert_eq!(value["maximum_concurrent_workers"], 1);
	for name in [
		"hidden_program_reexecuted",
		"teacher_program_reexecuted",
		"states_reconstructed_from_causal_traces",
		"supplied_checkpoint_law_only",
		"rounded_binary64_not_interval_proof",
	] {
		assert_eq!(value[name], true, "{name}");
	}
	for name in [
		"external_source_authenticated",
		"weights_modified",
		"independent_holdout_verified",
		"task_value_improvement_qualified",
		"production_eligible",
	] {
		assert_eq!(value[name], false, "{name}");
	}
	assert!(text.len() <= MAX_RESULT_BYTES);
	assert_eq!(value["rows"][0]["source_row"], 0);
	assert_eq!(value["rows"][0]["hidden"].as_array().unwrap().len(), 49);
}

#[test]
fn every_envelope_identity_is_checked_before_request_parsing() {
	for (field, message) in [
		("expected_request_sha256", "request SHA256 mismatch"),
		("expected_core_source_sha256", "core source SHA256 mismatch"),
		(
			"expected_target_contract_sha256",
			"target contract SHA256 mismatch",
		),
	] {
		let mut value = serde_json::to_value(envelope("{".into())).unwrap();
		value[field] = json!("0".repeat(64));
		let params = serde_json::from_value(value).unwrap();
		assert!(
			execute(&params).unwrap_err().to_string().contains(message),
			"{field}"
		);
	}
	for value in ["F".repeat(64), "a".repeat(63), "g".repeat(64)] {
		let mut params = fixture();
		params.expected_target_contract_sha256 = value;
		assert!(execute(&params)
			.unwrap_err()
			.to_string()
			.contains("lowercase hexadecimal"));
	}
}

#[test]
fn raw_whitespace_changes_require_a_new_request_commitment() {
	let mut params = fixture();
	params.request_json.push('\n');
	assert!(execute(&params)
		.unwrap_err()
		.to_string()
		.contains("request SHA256 mismatch"));
	params.expected_request_sha256 = sha(params.request_json.as_bytes());
	assert!(execute(&params).is_ok());
}

#[test]
fn strict_envelope_and_nested_request_reject_extra_or_duplicate_fields() {
	let mut outer = serde_json::to_value(fixture()).unwrap();
	outer["teacher_q"] = json!(vec![0.; 6]);
	assert!(serde_json::from_value::<SemanticReplayParams>(outer).is_err());
	let mut request: Value = serde_json::from_str(&fixture().request_json).unwrap();
	request["teacher_q"] = json!(vec![0.; 6]);
	assert!(execute(&envelope(request.to_string())).is_err());
	let request = fixture().request_json;
	let duplicate = format!(
		"{},\"profile\":\"{}\"}}",
		&request[..request.len() - 1],
		core::PROFILE
	);
	assert!(execute(&envelope(duplicate)).is_err());
	assert!(execute(&envelope(format!("{request} true"))).is_err());
}

#[test]
fn request_budget_counts_utf8_bytes_and_accepts_exact_boundary() {
	for request in [String::new(), "é".repeat(core::MAX_REQUEST_BYTES / 2 + 1)] {
		assert!(execute(&envelope(request))
			.unwrap_err()
			.to_string()
			.contains("UTF-8 bytes"));
	}
	let mut request = fixture().request_json;
	request.push_str(&" ".repeat(core::MAX_REQUEST_BYTES - request.len()));
	assert_eq!(request.len(), core::MAX_REQUEST_BYTES);
	assert!(execute(&envelope(request)).is_ok());
}

#[test]
fn oversized_results_fail_without_returning_partial_json() {
	let error = encode_result(&json!({"quoted": "\"".repeat(MAX_RESULT_BYTES)})).unwrap_err();
	assert!(format!("{error:#}").contains("result byte budget exceeded"));
	let mut bounded = BoundedResult {
		bytes: Vec::new(),
		limit: 3,
	};
	bounded.write_all(b"abc").unwrap();
	assert!(bounded.write_all(b"d").is_err());
	assert_eq!(bounded.bytes, b"abc");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_waiter_does_not_release_a_running_worker_permit() {
	let workers = Arc::new(Semaphore::new(1));
	let (started_tx, started_rx) = tokio::sync::oneshot::channel();
	let (release_tx, release_rx) = std::sync::mpsc::channel();
	let waiter = tokio::spawn(run_worker(workers.clone(), move || {
		started_tx.send(()).unwrap();
		release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
		Ok("finished".into())
	}));
	tokio::time::timeout(Duration::from_secs(5), started_rx)
		.await
		.unwrap()
		.unwrap();
	assert_eq!(workers.available_permits(), 0);
	waiter.abort();
	assert!(waiter.await.unwrap_err().is_cancelled());
	let error = run_worker(workers.clone(), || panic!("busy worker must not be queued"))
		.await
		.unwrap_err();
	assert!(error.to_string().contains("busy"));
	assert_eq!(workers.available_permits(), 0);
	release_tx.send(()).unwrap();
	let released = tokio::time::timeout(Duration::from_secs(5), workers.clone().acquire_owned())
		.await
		.unwrap()
		.unwrap();
	drop(released);
	assert_eq!(
		run_worker(workers, || Ok("next".into())).await.unwrap(),
		"next"
	);
}

#[tokio::test]
async fn failed_parse_releases_capacity_without_admitting_unbounded_work() {
	let workers = Arc::new(Semaphore::new(1));
	let invalid = envelope("{".into());
	assert!(run_worker(workers.clone(), move || execute(&invalid))
		.await
		.is_err());
	assert_eq!(workers.available_permits(), 1);
	let valid = fixture();
	assert!(run_worker(workers.clone(), move || execute(&valid))
		.await
		.is_ok());
	assert_eq!(workers.available_permits(), 1);
}

#[test]
fn asymmetric_head_matches_independent_high_precision_readout_reference() {
	let mut request = core_tests::base();
	let mut model: Value = serde_json::from_str(&request.checkpoint_json).unwrap();
	model["network"]["b1"][0] = json!(0.5);
	model["network"]["b1"][1] = json!(-0.5);
	for (row, first, second, bias) in [
		(0, 2., 0.5, 0.125),
		(1, -3., 0.25, -0.25),
		(2, 0.75, -2., 0.5),
		(3, 1., -1., 0.2),
	] {
		model["network"]["w2"][row][0] = json!(first);
		model["network"]["w2"][row][1] = json!(second);
		model["network"]["b2"][row] = json!(bias);
	}
	request.checkpoint_json = model.to_string();
	request.expected_checkpoint_sha256 = sha(request.checkpoint_json.as_bytes());
	request.traces[0].steps = vec![
		core::Step {
			action: 1,
			completion: None
		};
		6
	];
	let result: Value = serde_json::from_str(
		&execute(&envelope(serde_json::to_string(&request).unwrap())).unwrap(),
	)
	.unwrap();
	let row = &result["rows"][0];
	// Decimal precision 70: h=(exp(1)-1)/(exp(1)+1), logit=2*h+0.2.
	// These constants were calculated independently of the Rust dot/exp/tanh.
	let expected_scores = [
		0.,
		0.8181757358900147,
		-1.7518807610950318,
		1.7708221824650268,
		-0.5095465867088502,
		0.5095465867088502,
	];
	for (actual, expected) in row["network_scores"]
		.as_array()
		.unwrap()
		.iter()
		.zip(expected_scores)
	{
		assert!((actual.as_f64().unwrap() - expected).abs() < 2e-14);
	}
	assert!((row["hidden"][0].as_f64().unwrap() - 0.46211715726000974).abs() < 2e-14);
	assert!((row["hidden"][1].as_f64().unwrap() + 0.46211715726000974).abs() < 2e-14);
	assert!((row["learned_belief"].as_f64().unwrap() - 0.7547732933544251).abs() < 2e-14);
	assert_eq!(row["analytic_endpoint_belief"], 0.5);
}

#[test]
fn compiled_contract_declares_the_supported_profile_and_limitations() {
	let contract: Value = serde_json::from_slice(TARGET_CONTRACT).unwrap();
	assert_eq!(contract["profile"], core::PROFILE);
	assert_eq!(
		contract["checkpoint"]["head_dimensions"],
		json!([85, 48, 4])
	);
	assert_eq!(contract["target"]["event"], "X_deadline6 > 0");
	assert_eq!(contract["bank"]["event"], "X_horizon > threshold");
	assert_eq!(contract["coordinates"].as_array().unwrap().len(), 33);
	assert_eq!(contract["limits"]["concurrent_workers"], 1);
	assert_eq!(
		contract["scope"]["first_passage_or_latent_reset_implemented"],
		false
	);
	assert_eq!(contract["scope"]["external_source_authenticated"], false);
	assert_eq!(contract["scope"]["production_eligible"], false);
}
