// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Synthetic semantic provenance, exact arithmetic and shared admission controls.

use super::*;
use crate::mcp::weight_semantic::weight_semantic_tests::{envelope, fixture as replay_fixture};
use serde_json::Value;

pub(crate) fn fixture() -> SemanticCertificateParams {
	let mut replay = replay_fixture();
	let mut request: Value = serde_json::from_str(&replay.request_json).unwrap();
	let mut model: Value =
		serde_json::from_str(request["checkpoint_json"].as_str().unwrap()).unwrap();
	model["network"]["b2"] = json!([1., -1., 0., 0.]);
	let model = model.to_string();
	request["expected_checkpoint_sha256"] = json!(sha(model.as_bytes()));
	request["checkpoint_json"] = json!(model);
	let mut public: Value = serde_json::from_str(request["public_json"].as_str().unwrap()).unwrap();
	// Identity latent law and stationary sensor: waiting only adds a positive
	// latency fee, so the useful READ is the unique best initial continuation.
	public["latency_price"] = json!(0.025);
	let public = public.to_string();
	request["expected_public_sha256"] = json!(sha(public.as_bytes()));
	request["public_json"] = json!(public);
	replay = envelope(request.to_string());
	SemanticCertificateParams {
		replay,
		expected_join_source_sha256: sha(include_bytes!("weight_semantic_certificate.rs")),
		expected_semantic_adapter_source_sha256: sha(include_bytes!("weight_semantic.rs")),
		expected_certificate_source_sha256: sha(include_bytes!("weight_certificate.rs")),
		expected_arithmetic_source_sha256: sha(include_bytes!("weight_certificate_exact.rs")),
		witnesses: vec![SemanticWitness {
			source_row: 0,
			competitor_action: 1,
			multiplier_f64_le_hex: hex(1f64.to_le_bytes()),
		}],
	}
}

fn execute(params: &SemanticCertificateParams) -> Result<Value> {
	serde_json::from_str(&execute_until(
		params,
		Instant::now() + Duration::from_secs(30),
	)?)
	.map_err(Into::into)
}

fn change_request(params: &mut SemanticCertificateParams, edit: impl FnOnce(&mut Value)) {
	let mut value: Value = serde_json::from_str(&params.replay.request_json).unwrap();
	edit(&mut value);
	params.replay = envelope(value.to_string());
}

#[test]
fn native_join_proves_the_synthetic_separation_without_source_or_efficacy_claims() {
	let params = fixture();
	let value = execute(&params).unwrap();
	let proof = &value["certificate"]["proof"];
	assert_eq!(proof["verdict"], "F64_NECESSARY_SYSTEM_INFEASIBLE");
	// Hidden is (0,...,0,1), center biases are (+1,-1,0). The READ>WAIT
	// witness has d=2 and R^2=1/2, independently of the semantic implementation.
	assert_eq!(
		proof["radius_squared"],
		json!({"numerator_hex":"1","binary_exponent":-1,"denominator_hex":"1"})
	);
	assert_eq!(
		proof["ideal_real"]["d"],
		json!({"numerator_hex":"1","binary_exponent":1,"denominator_hex":"1"})
	);
	let row = &value["generated_witness_rows"][0];
	assert_eq!(row["target_action"], 2);
	assert_eq!(row["competitor_action"], 1);
	assert_eq!(row["source_row"], 0);
	assert_eq!(
		row["hidden_f64_le_hex"],
		hex([vec![0.; 48], vec![1.]]
			.concat()
			.iter()
			.flat_map(|x: &f64| x.to_le_bytes())
			.collect::<Vec<_>>())
	);
	assert_eq!(value["witness_semantics_reexecuted_and_joined"], true);
	assert_eq!(
		value["caller_hidden_q_state_mask_or_target_accepted"],
		false
	);
	assert_eq!(value["worker_shared_with_semantic_replay"], true);
	assert_eq!(value["maximum_concurrent_workers"], 1);
	for name in [
		"external_source_authenticated",
		"hardware_arithmetic_semantics_verified",
		"independent_holdout_verified",
		"task_value_improvement_qualified",
		"whole_network_impossibility_qualified",
		"production_eligible",
		"weights_modified",
	] {
		assert_eq!(value[name], false, "{name}");
	}
	assert_eq!(value["gradient_steps"], 0);
	// The nested checker retains its truthful supplied-row-only declaration;
	// semantic execution is established by the enclosing native operation.
	assert_eq!(
		value["certificate"]["hidden_or_teacher_program_reexecuted"],
		false
	);
}

#[test]
fn zero_witness_and_reversed_center_remain_not_certified() {
	let mut params = fixture();
	params.witnesses[0].multiplier_f64_le_hex = hex((-0f64).to_le_bytes());
	assert_eq!(
		execute(&params).unwrap()["certificate"]["proof"]["verdict"],
		"NOT_CERTIFIED"
	);
	let mut params = fixture();
	change_request(&mut params, |request| {
		let mut model: Value =
			serde_json::from_str(request["checkpoint_json"].as_str().unwrap()).unwrap();
		model["network"]["b2"] = json!([-1., 1., 0., 0.]);
		let model = model.to_string();
		request["expected_checkpoint_sha256"] = json!(sha(model.as_bytes()));
		request["checkpoint_json"] = json!(model);
	});
	assert_eq!(
		execute(&params).unwrap()["certificate"]["proof"]["verdict"],
		"NOT_CERTIFIED"
	);
}

#[test]
fn generated_rows_can_be_independently_passed_through_the_unchanged_exact_check() {
	let params = fixture();
	let result = execute(&params).unwrap();
	let request = weight_semantic::admit_request(&params.replay).unwrap();
	let direct = CertificateParams {
		semantics: SEMANTICS.into(),
		checkpoint_json: request.checkpoint_json,
		expected_checkpoint_sha256: request.expected_checkpoint_sha256,
		expected_witness_sha256: result["certificate"]["witness_sha256"]
			.as_str()
			.unwrap()
			.into(),
		source: serde_json::from_value(result["certificate"]["source"].clone()).unwrap(),
		rows: serde_json::from_value(result["generated_witness_rows"].clone()).unwrap(),
	};
	let checked =
		weight_certificate::solve_until(&direct, Instant::now() + Duration::from_secs(30)).unwrap();
	assert_eq!(checked["proof"], result["certificate"]["proof"]);
	let second = execute(&params).unwrap();
	for name in [
		"request_sha256",
		"checkpoint_sha256",
		"public_sha256",
		"generated_witness_rows",
	] {
		assert_eq!(second[name], result[name], "{name}");
	}
}

#[test]
fn all_compiled_source_pins_are_checked_before_malformed_replay_parsing() {
	for field in [
		"expected_join_source_sha256",
		"expected_semantic_adapter_source_sha256",
		"expected_certificate_source_sha256",
		"expected_arithmetic_source_sha256",
	] {
		let mut value = serde_json::to_value(fixture()).unwrap();
		value[field] = json!("0".repeat(64));
		value["replay"] = serde_json::to_value(envelope("{".into())).unwrap();
		let params = serde_json::from_value(value).unwrap();
		assert!(
			execute(&params)
				.unwrap_err()
				.to_string()
				.contains("source SHA256 mismatch"),
			"{field}"
		);
	}
	for field in [
		"expected_request_sha256",
		"expected_core_source_sha256",
		"expected_target_contract_sha256",
	] {
		let mut value = serde_json::to_value(fixture()).unwrap();
		value["replay"][field] = json!("0".repeat(64));
		assert!(
			execute(&serde_json::from_value(value).unwrap()).is_err(),
			"{field}"
		);
	}
	for field in ["expected_checkpoint_sha256", "expected_public_sha256"] {
		let mut params = fixture();
		change_request(&mut params, |request| {
			request[field] = json!("0".repeat(64))
		});
		assert!(execute(&params).is_err(), "{field}");
	}
}

#[test]
fn caller_hidden_q_masks_states_targets_and_duplicate_schema_fields_are_rejected() {
	for field in [
		"hidden",
		"hidden_f64_le_hex",
		"teacher_q",
		"state",
		"legal",
		"target_action",
	] {
		let mut value = serde_json::to_value(fixture()).unwrap();
		value[field] = json!(null);
		assert!(
			serde_json::from_value::<SemanticCertificateParams>(value).is_err(),
			"outer {field}"
		);
		let mut value = serde_json::to_value(fixture()).unwrap();
		value["witnesses"][0][field] = json!(null);
		assert!(
			serde_json::from_value::<SemanticCertificateParams>(value).is_err(),
			"witness {field}"
		);
		let mut params = fixture();
		change_request(&mut params, |request| request[field] = json!(null));
		assert!(execute(&params).is_err(), "inner {field}");
	}
	let value = serde_json::to_string(&fixture()).unwrap();
	let duplicate = format!("{},\"witnesses\":[]}}", &value[..value.len() - 1]);
	assert!(serde_json::from_str::<SemanticCertificateParams>(&duplicate).is_err());
	let duplicate = "{\"source_row\":0,\"source_row\":1,\"competitor_action\":1,\"multiplier_f64_le_hex\":\"000000000000f03f\"}";
	assert!(serde_json::from_str::<SemanticWitness>(duplicate).is_err());
}

#[test]
fn exact_trace_witness_coverage_and_comparison_uniqueness_are_required() {
	let mut params = fixture();
	params.witnesses[0].source_row = 7;
	assert!(execute(&params).unwrap_err().to_string().contains("absent"));
	let mut params = fixture();
	params.witnesses.push(params.witnesses[0].clone());
	assert!(execute(&params)
		.unwrap_err()
		.to_string()
		.contains("duplicate"));
	for duplicate in [true, false] {
		let mut params = fixture();
		change_request(&mut params, |request| {
			let mut extra = request["traces"][0].clone();
			if !duplicate {
				extra["source_row"] = json!(1);
			}
			request["traces"].as_array_mut().unwrap().push(extra);
		});
		let error = execute(&params).unwrap_err().to_string();
		assert!(
			error.contains(if duplicate {
				"duplicate replay"
			} else {
				"cover every"
			}),
			"{error}"
		);
	}
	for count in [0, MAX_WITNESSES + 1] {
		let mut params = fixture();
		params.witnesses = vec![params.witnesses[0].clone(); count];
		assert!(execute(&params).is_err());
	}
}

#[test]
fn terminal_illegal_and_same_target_comparisons_are_rejected() {
	for competitor in [0, 2, 3, 4, 5, 255] {
		let mut params = fixture();
		params.witnesses[0].competitor_action = competitor;
		assert!(execute(&params).is_err(), "{competitor}");
	}
	let mut params = fixture();
	change_request(&mut params, |request| {
		request["traces"][0]["steps"] = json!(vec![json!({"action":1,"completion":null}); 6]);
	});
	assert!(execute(&params)
		.unwrap_err()
		.to_string()
		.contains("distinct legal continuations"));
}

#[test]
fn malformed_nonfinite_or_negative_exact_multipliers_are_rejected_before_replay() {
	for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.] {
		let mut params = fixture();
		params.witnesses[0].multiplier_f64_le_hex = hex(value.to_le_bytes());
		assert!(execute(&params)
			.unwrap_err()
			.to_string()
			.contains("finite and nonnegative"));
	}
	for value in [
		"0".repeat(15),
		"F".repeat(16),
		"g".repeat(16),
		"0".repeat(18),
	] {
		let mut params = fixture();
		params.witnesses[0].multiplier_f64_le_hex = value;
		assert!(execute(&params).is_err());
	}
}

#[test]
fn outer_deadline_and_canonical_byte_budget_cannot_be_extended() {
	assert!(execute_until(&fixture(), Instant::now())
		.unwrap_err()
		.to_string()
		.contains("outer result deadline"));
	let mut request = weight_semantic::admit_request(&fixture().replay).unwrap();
	request.profile = "invalid-profile-after-expired-cutoff".into();
	assert!(core::replay_until(&request, Instant::now())
		.unwrap_err()
		.to_string()
		.contains("deadline expired before admission"));
	let mut writer = Commitment {
		hash: Sha256::new(),
		bytes: 0,
		end: Instant::now() + Duration::from_secs(30),
	};
	writer.write_all(&vec![b'x'; MAX_REQUEST_BYTES]).unwrap();
	assert_eq!(writer.bytes, MAX_REQUEST_BYTES);
	assert!(writer.write_all(b"x").is_err());
	let params = fixture();
	let end = Instant::now() + Duration::from_secs(30);
	let (request, request_sha, _) = admit(&params, end).unwrap();
	let replay = core::replay(&request).unwrap();
	let generated = join(&params, &request, &replay, &request_sha, end).unwrap();
	assert!(weight_certificate::solve_until(&generated, Instant::now()).is_err());
}

#[test]
fn mismatched_native_result_identity_cannot_be_joined() {
	let params = fixture();
	let end = Instant::now() + Duration::from_secs(30);
	let (request, request_sha, _) = admit(&params, end).unwrap();
	let replay = core::replay(&request).unwrap();
	for field in [
		"checkpoint_sha256",
		"public_sha256",
		"implementation_sha256",
	] {
		let mut value = serde_json::to_value(&replay).unwrap();
		value[field] = json!("0".repeat(64));
		let changed = serde_json::from_value(value).unwrap();
		assert!(
			join(&params, &request, &changed, &request_sha, end).is_err(),
			"{field}"
		);
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial(weight_semantic_worker)]
async fn cancelled_shared_worker_blocks_both_tools_until_actual_completion() {
	let (started_tx, started_rx) = tokio::sync::oneshot::channel();
	let (release_tx, release_rx) = std::sync::mpsc::channel();
	let task = tokio::spawn(weight_semantic::run_shared_worker(move || {
		started_tx.send(()).unwrap();
		release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
		Ok("done".into())
	}));
	tokio::time::timeout(Duration::from_secs(5), started_rx)
		.await
		.unwrap()
		.unwrap();
	task.abort();
	assert!(task.await.unwrap_err().is_cancelled());
	assert!(verify(fixture())
		.await
		.unwrap_err()
		.to_string()
		.contains("busy"));
	assert!(weight_semantic::replay(replay_fixture())
		.await
		.unwrap_err()
		.to_string()
		.contains("busy"));
	release_tx.send(()).unwrap();
	tokio::time::timeout(Duration::from_secs(5), async {
		loop {
			match verify(fixture()).await {
				Ok(text) => break serde_json::from_str::<Value>(&text).unwrap(),
				Err(error) if error.to_string().contains("busy") => {
					tokio::time::sleep(Duration::from_millis(1)).await
				}
				Err(error) => panic!("{error:#}"),
			}
		}
	})
	.await
	.unwrap();
}
