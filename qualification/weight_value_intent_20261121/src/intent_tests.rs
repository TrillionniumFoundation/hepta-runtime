// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Synthetic adversarial controls; these carry no independent financial labels.

use super::*;
use crate::evidence::{Contract, Dataset, Evidence, Role};
use hepta_continuation_runtime_study::source::{ARITHMETIC_SHA256, TASK_SHA256};

fn binding() -> Binding {
	Binding {
		compressed_sha256: "1".repeat(64),
		decoded_sha256: "2".repeat(64),
		profile_sha256: "3".repeat(64),
		protected_law_task_sha256: "4".repeat(64),
	}
}
fn contract(mask: u8) -> Contract {
	Contract {
		candidate_id: "synthetic".into(),
		row_mask: mask,
		binding: binding(),
		protocol_sha256: "5".repeat(64),
		producer_sha256: "6".repeat(64),
		evaluator_sha256: "7".repeat(64),
		evidence_pin: SourcePin {
			source_id: "synthetic".into(),
			sha256: "8".repeat(64),
			size_bytes: 1,
		},
		dataset: Dataset {
			role: Role::ExposedTrainAudit,
			full_state_manifest_sha256: "9".repeat(64),
			finalist_seal_sha256: None,
			postfreeze_sample_seal_sha256: None,
		},
		maximum_work_units: 1000,
		maximum_cpu_seconds: 1.0,
		owner_revision: MAIN_OWNER.into(),
	}
}
fn intent(before: &[f64; 196], after: &[f64; 196], mask: u8) -> Intent {
	let norm = exact::check(before, after).unwrap();
	Intent {
		schema: "hepta.readout196-intent.v1".into(),
		candidate_id: "synthetic".into(),
		layout: LAYOUT.into(),
		binding: binding(),
		protocol_sha256: "5".repeat(64),
		producer_sha256: "6".repeat(64),
		row_mask: mask,
		edits: before
			.iter()
			.zip(after)
			.map(|(a, b)| Edit {
				old_bits: format!("{:016x}", a.to_bits()),
				new_bits: format!("{:016x}", b.to_bits()),
			})
			.collect(),
		expected_readout_sha256: readout_sha256(after),
		delta_squared_units_hex: norm.delta_squared_units_hex,
		anchor_q147_squared_units_hex: norm.anchor_q147_squared_units_hex,
	}
}
fn base() -> [f64; 196] {
	let mut value = [0.0; 196];
	value[0] = 1.0;
	value
}
fn evidence(intent: &Intent, contract: &Contract) -> Evidence {
	Evidence {
		schema: "hepta.own-law-evaluator-record.v1".into(),
		candidate_id: intent.candidate_id.clone(),
		readout_sha256: intent.expected_readout_sha256.clone(),
		binding: intent.binding.clone(),
		protocol_sha256: contract.protocol_sha256.clone(),
		evaluator_sha256: contract.evaluator_sha256.clone(),
		task_sha256: TASK_SHA256.into(),
		arithmetic_sha256: ARITHMETIC_SHA256.into(),
		target: "fixed_deadline6_binary_endpoint".into(),
		metric: "full_state_own_law_dag_expected_task_utility".into(),
		role: contract.dataset.role,
		dataset: contract.dataset.clone(),
		resource_receipt_sha256: "a".repeat(64),
		work_units: 100,
		cpu_seconds: 0.01,
		complete: true,
		original_value: 0.1,
		candidate_value: 0.2,
	}
}

#[test]
fn exact_ball_accepts_equality_rejects_one_ulp_outside() {
	let before = base();
	let mut after = before;
	after[0] = 1.5;
	assert!(exact::check(&before, &after).unwrap().within_shared_ball);
	after[0] = 1.5_f64.next_up();
	assert!(!exact::check(&before, &after).unwrap().within_shared_ball);
}

#[test]
fn cross_sign_and_shared_q_b_budget_are_exact() {
	let mut before = base();
	before[1] = 4.0;
	let mut after = before;
	after[0] = -1.0;
	assert!(exact::check(&before, &after).unwrap().within_shared_ball);
	after[0] = -1.1;
	assert!(!exact::check(&before, &after).unwrap().within_shared_ball);
	let before = base();
	let mut after = before;
	after[0] += 0.4;
	assert!(exact::check(&before, &after).unwrap().within_shared_ball);
	after[195] = 0.4;
	assert!(!exact::check(&before, &after).unwrap().within_shared_ball);
}

#[test]
fn subnormal_and_maximum_finite_values_do_not_underflow_or_overflow() {
	let mut before = [0.0; 196];
	before[0] = f64::from_bits(1);
	let mut after = before;
	after[0] = 0.0;
	let tiny = exact::check(&before, &after).unwrap();
	assert_eq!(tiny.delta_squared_units_hex, "1");
	assert_eq!(tiny.anchor_q147_squared_units_hex, "1");
	assert!(!tiny.within_shared_ball);
	before[0] = f64::MAX;
	after[0] = f64::MAX * 0.5;
	assert!(exact::check(&before, &after).unwrap().within_shared_ball);
	after[0] = (f64::MAX * 0.5).next_down();
	assert!(!exact::check(&before, &after).unwrap().within_shared_ball);
	after[0] = -f64::MAX;
	assert!(!exact::check(&before, &after).unwrap().within_shared_ball);
}

#[test]
fn zero_radius_and_belief_anchor_cannot_fund_q_edits() {
	let mut before = [0.0; 196];
	before[195] = f64::MAX;
	assert!(exact::check(&before, &before).unwrap().within_shared_ball);
	let mut after = before;
	after[0] = f64::from_bits(1);
	assert!(!exact::check(&before, &after).unwrap().within_shared_ball);
}

#[test]
fn exact_old_bits_preserve_positive_and_negative_zero_identity() {
	let before = base();
	let valid = intent(&before, &before, 15);
	let mut modified = valid.clone();
	modified.edits[195].old_bits = "8000000000000000".into();
	assert!(prepare_readout(&before, &modified, &contract(15)).is_err());
	let mut after = before;
	after[195] = -0.0;
	let signed = intent(&before, &after, 15);
	let (preview, _) = prepare_readout(&before, &signed, &contract(15)).unwrap();
	assert_eq!(preview[195].to_bits(), (-0.0_f64).to_bits());
	assert_eq!(before[195].to_bits(), 0.0_f64.to_bits());
}

#[test]
fn row_mask_covers_weights_and_biases_in_the_declared_layout() {
	let before = base();
	for (mask, index, allowed) in [
		(7, 143, true),
		(7, 194, true),
		(7, 144, false),
		(7, 195, false),
		(8, 144, true),
		(8, 195, true),
		(8, 143, false),
		(8, 194, false),
	] {
		let mut after = before;
		after[index] += 0.01;
		assert_eq!(
			prepare_readout(&before, &intent(&before, &after, mask), &contract(mask)).is_ok(),
			allowed
		);
	}
}

#[test]
fn altered_source_layout_mask_dimension_and_integer_witness_fail_closed() {
	let before = base();
	let good = intent(&before, &before, 15);
	for field in 0..8 {
		let mut bad = good.clone();
		match field {
			0 => bad.binding.protected_law_task_sha256 = "f".repeat(64),
			1 => bad.layout = "4x49".into(),
			2 => bad.row_mask = 0,
			3 => {
				bad.edits.pop();
			}
			4 => bad.delta_squared_units_hex = "1".into(),
			5 => bad.anchor_q147_squared_units_hex = "0".into(),
			6 => bad.expected_readout_sha256 = "e".repeat(64),
			_ => bad.producer_sha256 = "d".repeat(64),
		}
		assert!(
			prepare_readout(&before, &bad, &contract(15)).is_err(),
			"field {field}"
		);
	}
}

#[test]
fn nonfinite_malformed_and_duplicate_bits_records_are_rejected() {
	for value in [
		"7ff0000000000000",
		"fff0000000000000",
		"7ff8000000000000",
		"000000000000000",
		"3FF0000000000000",
		"gg00000000000000",
	] {
		assert!(bits(value).is_err());
	}
	assert!(unique_json(br#"{"old_bits":"a","old_bits":"b"}"#).is_err());
	let before = base();
	let mut after = before;
	after[0] = f64::INFINITY;
	assert!(exact::check(&before, &after).is_err());
}

#[test]
fn evaluator_rejects_current_tick_financial_and_mismatched_identity_claims() {
	let before = base();
	let intent = intent(&before, &before, 15);
	let contract = contract(15);
	let good = evidence(&intent, &contract);
	contract.check_evidence(&intent, &good).unwrap();
	for field in 0..8 {
		let mut bad = good.clone();
		match field {
			0 => bad.target = "current_tick_endpoint".into(),
			1 => bad.metric = "financial_pnl".into(),
			2 => bad.task_sha256 = "b".repeat(64),
			3 => bad.arithmetic_sha256 = "c".repeat(64),
			4 => bad.readout_sha256 = "d".repeat(64),
			5 => bad.dataset.full_state_manifest_sha256 = "e".repeat(64),
			6 => bad.complete = false,
			_ => bad.evaluator_sha256 = "f".repeat(64),
		}
		assert!(
			contract.check_evidence(&intent, &bad).is_err(),
			"field {field}"
		);
	}
}

#[test]
fn exposed_audit_cannot_be_relabelled_confirmation_without_bound_seals() {
	let before = base();
	let intent = intent(&before, &before, 15);
	let mut contract = contract(15);
	contract.dataset.role = Role::SealedOwnLawConfirmation;
	assert!(contract.check_intent(&intent).is_err());
	contract.dataset.finalist_seal_sha256 = Some("b".repeat(64));
	contract.dataset.postfreeze_sample_seal_sha256 = Some("b".repeat(64));
	assert!(contract.check_intent(&intent).is_err());
	contract.dataset.postfreeze_sample_seal_sha256 = Some("c".repeat(64));
	contract.check_intent(&intent).unwrap();
	contract.dataset.role = Role::ExposedTrainAudit;
	assert!(contract.check_intent(&intent).is_err());
}

#[test]
fn evaluator_work_cpu_finiteness_and_completeness_are_bounded() {
	let before = base();
	let intent = intent(&before, &before, 15);
	let contract = contract(15);
	let good = evidence(&intent, &contract);
	for field in 0..7 {
		let mut bad = good.clone();
		match field {
			0 => bad.work_units = 1001,
			1 => bad.work_units = 0,
			2 => bad.cpu_seconds = 1.1,
			3 => bad.cpu_seconds = -0.1,
			4 => bad.cpu_seconds = f64::NAN,
			5 => bad.candidate_value = f64::INFINITY,
			_ => {
				bad.candidate_value = f64::MAX;
				bad.original_value = -f64::MAX;
			}
		}
		assert!(
			contract.check_evidence(&intent, &bad).is_err(),
			"field {field}"
		);
	}
}

#[test]
fn isolated_preview_and_owner_refusal_leave_anchor_bits_unchanged() {
	let before = base();
	let frozen = before.map(f64::to_bits);
	let mut after = before;
	after[0] = 1.25;
	let (preview, _) =
		prepare_readout(&before, &intent(&before, &after, 15), &contract(15)).unwrap();
	assert_ne!(preview[0].to_bits(), before[0].to_bits());
	assert_eq!(owner_reason(MAIN_OWNER), "UNSUPPORTED_JSON_F64");
	assert_eq!(owner_reason("unrecognized"), "UNREVIEWED_OWNER_REVISION");
	after[0] = -f64::MAX;
	assert!(prepare_readout(&before, &intent(&before, &after, 15), &contract(15)).is_err());
	assert_eq!(before.map(f64::to_bits), frozen);
}
